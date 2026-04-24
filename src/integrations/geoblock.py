"""
src/integrations/geoblock.py — Per-country CIDR geo-blocking.

Downloads per-country IPv4 CIDR lists from ipdeny.com, blocks/unblocks
them via the nftables blocked_ips set, and persists state so blocks
survive ruleset reloads.

Public API
----------
    from integrations.geoblock import block_country, unblock_country, list_blocked
    blocked, skipped = block_country("CN")
    removed = unblock_country("CN")
    counts  = list_blocked()          # {"CN": 9823, "RU": 5412}
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

# ── Paths & constants ─────────────────────────────────────────────────────────

_STATE_FILE = Path("/var/lib/nft-firewall/geoblock-state.json")
_IPDENY_URL = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"


# ── State persistence ─────────────────────────────────────────────────────────

def _load_state() -> "dict[str, list[str]]":
    """Read the persisted country→CIDR mapping from ``_STATE_FILE``.

    Returns
    -------
    dict[str, list[str]]
        Dict keyed by uppercase country code mapping to lists of CIDR strings,
        or an empty dict if the file does not exist or cannot be parsed.
    """
    if not _STATE_FILE.exists():
        return {}
    try:
        data = json.loads(_STATE_FILE.read_text())
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _save_state(state: dict) -> None:
    """Atomically persist *state* to ``_STATE_FILE``.

    Writes to a ``.tmp`` sibling file, fsyncs, then replaces the target so
    that a crash mid-write never leaves a corrupt state file.

    Parameters
    ----------
    state:
        Dict keyed by uppercase country code mapping to lists of CIDR strings.
    """
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _STATE_FILE.with_suffix(".tmp")
    with tmp.open("w") as fh:
        json.dump(state, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _STATE_FILE)


# ── Feed fetching ─────────────────────────────────────────────────────────────

def _fetch_country(cc: str) -> "list[str]":
    """Fetch the CIDR list for country code *cc* from ipdeny.com.

    Downloads the zone file and validates each line as a CIDR prefix.

    Parameters
    ----------
    cc:
        Two-letter country code (case-insensitive).  Lowercased before use.

    Returns
    -------
    list[str]
        List of valid CIDR strings.  Returns ``[]`` on any network or parse
        error, and prints a warning.
    """
    url = _IPDENY_URL.format(cc=cc.lower())
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError, Exception) as exc:
        print(f"[geoblock] WARNING: fetch failed for {cc.upper()}: {exc}")
        return []

    result = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            result.append(str(net))
        except ValueError:
            continue

    return result


# ── /8 guard ──────────────────────────────────────────────────────────────────

def _apply_8_guard(cidr: str) -> bool:
    """Return ``True`` if *cidr* covers no more than a /8 worth of addresses.

    Prints a warning and returns ``False`` for supernets larger than a /8 to
    prevent accidentally black-holing large swaths of the internet.

    Parameters
    ----------
    cidr:
        IPv4 CIDR prefix to evaluate.

    Returns
    -------
    bool
        ``True`` if the prefix is /8 or more specific, ``False`` otherwise.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        print(f"[geoblock] WARNING: invalid CIDR, skipping: {cidr!r}")
        return False

    if net.num_addresses <= 2 ** 24:
        return True

    print(
        f"[geoblock] WARNING: refusing to block {cidr} — prefix covers "
        f"{net.num_addresses:,} addresses (larger than /8)"
    )
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def block_country(cc: str) -> "tuple[int, int]":
    """Download and block all CIDRs for country *cc*.

    Idempotent: CIDRs already in state for this country are skipped.

    Parameters
    ----------
    cc:
        Two-letter country code (case-insensitive).  Uppercased internally.

    Returns
    -------
    tuple[int, int]
        ``(blocked_count, skipped_count)``.  Returns ``(0, 0)`` if the
        country zone file could not be fetched or was empty.
    """
    from core.state import block_ip  # lazy import — avoids nft at import time

    cc = cc.upper()
    cidrs = _fetch_country(cc)
    if not cidrs:
        print(f"[geoblock] WARNING: no CIDRs fetched for {cc}, nothing blocked")
        return (0, 0)

    state = _load_state()
    existing = set(state.get(cc, []))

    blocked_count = 0
    skipped_count = 0
    new_cidrs = list(existing)

    for cidr in cidrs:
        if cidr in existing:
            skipped_count += 1
            continue
        if not _apply_8_guard(cidr):
            skipped_count += 1
            continue
        if block_ip(cidr):
            blocked_count += 1
            new_cidrs.append(cidr)
        else:
            skipped_count += 1

    state[cc] = new_cidrs
    _save_state(state)

    print(f"[geoblock] {cc}: +{blocked_count} blocked, {skipped_count} skipped")
    return (blocked_count, skipped_count)


def unblock_country(cc: str) -> int:
    """Remove all CIDRs previously blocked for country *cc*.

    Parameters
    ----------
    cc:
        Two-letter country code (case-insensitive).  Uppercased internally.

    Returns
    -------
    int
        Number of CIDRs successfully removed.  Returns ``0`` if the country
        was not in state.
    """
    from core.state import unblock_ip  # lazy import — avoids nft at import time

    cc = cc.upper()
    state = _load_state()
    if cc not in state:
        return 0

    removed = 0
    for cidr in state[cc]:
        if unblock_ip(cidr):
            removed += 1

    del state[cc]
    _save_state(state)

    print(f"[geoblock] {cc}: -{removed} unblocked")
    return removed


def list_blocked() -> "dict[str, int]":
    """Return a summary of currently blocked countries and their CIDR counts.

    Returns
    -------
    dict[str, int]
        Dict mapping country code to number of blocked CIDRs.
        Returns ``{}`` if the state file is absent or empty.
    """
    state = _load_state()
    return {cc: len(cidrs) for cc, cidrs in state.items()}


def get_total_cidr_count() -> int:
    """Return the total number of CIDRs currently tracked across all countries.

    Returns
    -------
    int
        Sum of all per-country CIDR counts, or ``0`` on any error.
    """
    try:
        return sum(list_blocked().values())
    except Exception:
        return 0


def reblock_from_config(blocked_countries: "list[str]") -> None:
    """Re-apply geo-blocks for countries listed in *blocked_countries*.

    Only blocks countries not already present in state (idempotent with
    respect to the state file).  Used by ``_cmd_apply()`` to restore
    geo-blocks after a full ruleset reload.

    Parameters
    ----------
    blocked_countries:
        List of two-letter country codes to ensure are blocked.
    """
    state = _load_state()
    for cc in blocked_countries:
        cc = cc.upper()
        if cc in state:
            print(f"[geoblock] {cc}: already in state, skipping re-block")
            continue
        print(f"[geoblock] {cc}: re-blocking from config ...")
        block_country(cc)
