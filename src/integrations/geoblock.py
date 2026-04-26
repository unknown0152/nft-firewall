"""
src/integrations/geoblock.py — Per-country CIDR geo-blocking.

Downloads per-country IPv4 CIDR lists from ipdeny.com, blocks/unblocks
them via the nftables blocked_ips set, and persists state so blocks
survive ruleset reloads.

Public API
----------
    from integrations.geoblock import (
        block_country,
        unblock_country,
        list_blocked,
        reblock_from_config,
    )
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_STATE_FILE   = _PROJECT_ROOT / "state" / "geoblock_state.json"


# ── Internal state management ─────────────────────────────────────────────────

def _load_state() -> Dict[str, List[str]]:
    """Read the geoblock state file from disk."""
    if not _STATE_FILE.exists():
        return {}
    try:
        return json.loads(_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_state(state: Dict[str, List[str]]) -> None:
    """Write the geoblock state file atomically."""
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        os.replace(tmp, _STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)


# ── Network helpers ───────────────────────────────────────────────────────────

def _fetch_country(cc: str) -> List[str]:
    """Fetch CIDR list for country *cc* from ipdeny.com with local caching."""
    cc = cc.lower()
    cache_dir = Path("/var/lib/nft-firewall/geoip-cache")
    cache_file = cache_dir / f"{cc}.zone"
    
    # Use cache if it's less than 7 days old
    if cache_file.exists():
        age_days = (time.time() - cache_file.stat().st_mtime) / 86400
        if age_days < 7:
            try:
                return cache_file.read_text().splitlines()
            except Exception: pass

    url = f"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            content = resp.read().decode("utf-8")
            # Update cache
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(content)
            except Exception: pass
            return content.splitlines()
    except Exception as exc:
        # Fallback to expired cache if available
        if cache_file.exists():
            try:
                return cache_file.read_text().splitlines()
            except Exception: pass
        return []


def _apply_block_guard(cidr: str) -> bool:
    """Ensure we don't accidentally block massive ranges or LAN."""
    from utils.validation import validate_block_target
    result = validate_block_target(cidr)
    if result.ok:
        return True
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def block_country(cc: str, force: bool = False) -> "tuple[int, int]":
    """Download and block all CIDRs for country *cc* using optimized aggregation."""
    import ipaddress
    from core.state import set_add_bulk, SET_BLOCKED
    from utils.validation import get_connection_info

    cc = cc.upper()
    
    # ── SAFETY CHECK ──────────────────────────────────────────────────────────
    if not force:
        my_ip, my_cc = get_connection_info()
        if cc == my_cc:
            print(f"  \033[33m!\033[0m \033[1mBlocked Prevented:\033[0m {cc} is your current country.")
            print(f"    To prevent lockout, you cannot block your own region ({my_ip}).")
            return (0, 0)
    
    print(f"  \033[34m→\033[0m Fetching CIDR list for {cc}...")
    cidrs = _fetch_country(cc)
    if not cidrs:
        print(f"  \033[31m!\033[0m No CIDRs fetched for {cc} (network or cache failure)")
        return (0, 0)

    state = _load_state()
    existing = set(state.get(cc, []))

    # ── AGGREGATION PASS ──────────────────────────────────────────────────────
    # Many countries have thousands of small /24 ranges that are contiguous.
    # collapsing them into supernets (e.g. /16) makes the kernel MUCH faster.
    print(f"  \033[34m→\033[0m Aggregating {len(cidrs)} CIDRs into supernets...")
    try:
        networks = [ipaddress.ip_network(c.strip()) for c in cidrs if c.strip()]
        collapsed = [str(n) for n in ipaddress.collapse_addresses(networks)]
        print(f"  \033[32m✓\033[0m Collapsed {len(cidrs)} ranges into {len(collapsed)} optimized supernets.")
        cidrs = collapsed
    except Exception as e:
        print(f"  \033[33m!\033[0m Aggregation failed (using raw ranges): {e}")

    to_add = []
    skipped_count = 0

    print(f"  \033[34m→\033[0m Filtering against existing blocks...")
    for cidr in cidrs:
        if cidr in existing:
            skipped_count += 1
            continue
        if not _apply_block_guard(cidr):
            skipped_count += 1
            continue
        to_add.append(cidr)

    if not to_add:
        print(f"  \033[32m✓\033[0m {cc} is already up to date.")
        return (0, skipped_count)

    print(f"  \033[34m→\033[0m Syncing {len(to_add)} elements to live firewall...")
    blocked_count = set_add_bulk(SET_BLOCKED, to_add)
    
    if blocked_count > 0:
        state[cc] = sorted(existing | set(to_add[:blocked_count]))
        _save_state(state)
        print(f"  \033[32m✓\033[0m {cc}: {blocked_count} blocked, {skipped_count} skipped")
    else:
        print(f"  \033[31m!\033[0m Failed to block {cc} (nft error)")

    return (blocked_count, skipped_count)


def unblock_country(cc: str) -> int:
    """Remove all CIDRs previously blocked for country *cc*."""
    from core.state import set_del_bulk, SET_BLOCKED

    cc = cc.upper()
    state = _load_state()
    if cc not in state:
        print(f"  \033[33m!\033[0m {cc} is not in the geo-block list.")
        return 0

    to_remove = state[cc]
    print(f"  \033[34m→\033[0m Removing {len(to_remove)} elements from firewall...")
    removed = set_del_bulk(SET_BLOCKED, to_remove)

    if removed > 0:
        del state[cc]
        _save_state(state)
        print(f"  \033[32m✓\033[0m {cc}: {removed} unblocked")
    else:
        print(f"  \033[31m!\033[0m Failed to unblock {cc} (nft error)")
        
    return removed


def whitelist_country(cc: str) -> "tuple[int, int]":
    """Download and whitelist all CIDRs for country *cc* (Lockdown Mode)."""
    import ipaddress
    from core.state import set_add_bulk, SET_WHITELIST

    cc = cc.upper()
    print(f"  \033[34m→\033[0m Fetching CIDR list for {cc}...")
    cidrs = _fetch_country(cc)
    if not cidrs:
        return (0, 0)

    # Aggregation
    networks = [ipaddress.ip_network(c.strip()) for c in cidrs if c.strip()]
    to_add = [str(n) for n in ipaddress.collapse_addresses(networks)]
    
    print(f"  \033[34m→\033[0m Activating Lockdown for {cc} ({len(to_add)} supernets)...")
    added = set_add_bulk(SET_WHITELIST, to_add)
    
    if added > 0:
        print(f"  \033[32m✓\033[0m {cc} is now WHITELISTED. Lockdown active.")
    return (added, 0)


def clear_geowhitelist() -> None:
    """Disable Lockdown Mode by clearing the whitelist set."""
    from core.state import set_del_bulk, SET_WHITELIST, load_persistent_sets, save_persistent_sets
    import subprocess

    print(f"  \033[34m→\033[0m Disabling Lockdown Mode...")
    subprocess.run(["nft", "flush", "set", "ip", "firewall", SET_WHITELIST], capture_output=True)
    
    sets = load_persistent_sets()
    if SET_WHITELIST in sets:
        sets[SET_WHITELIST] = []
        save_persistent_sets(sets)
    print(f"  \033[32m✓\033[0m Lockdown Mode disabled.")


def list_blocked() -> "dict[str, int]":
    """Return a summary of currently blocked countries and their CIDR counts."""
    state = _load_state()
    return {cc: len(cidrs) for cc, cidrs in state.items()}


def geotest() -> None:
    """Validate that blocked countries are actually being filtered by the live ruleset."""
    import ipaddress
    import subprocess
    from core.state import SET_BLOCKED

    state = _load_state()
    if not state:
        print("  \033[33m!\033[0m No countries are currently geo-blocked.")
        return

    print("  \033[1mGeo-Block Validation Test\033[0m")
    print("  " + "─" * 40)

    for cc, cidrs in state.items():
        if not cidrs: continue
        
        # Pick the first IP from the first range as a probe
        try:
            net = ipaddress.ip_network(cidrs[0])
            probe_ip = str(next(net.hosts()))
        except Exception:
            probe_ip = cidrs[0].split('/')[0]

        # Use 'nft --check' simulation to see if it's in the set
        # 'nft get element ip firewall blocked_ips { IP }' returns 0 if found
        cmd = ["nft", "get", "element", "ip", "firewall", SET_BLOCKED, "{", probe_ip, "}"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        
        if proc.returncode == 0:
            status = "\033[32m🟢 BLOCKED\033[0m"
            detail = f"(Probe: {probe_ip})"
        else:
            status = "\033[31m🔴 LEAKING\033[0m"
            detail = f"(IP {probe_ip} not found in live set)"

        print(f"  {cc:<4} {status:<20} {detail}")

    print("  " + "─" * 40)
    print("  \033[34m→\033[0m Verification complete.")
