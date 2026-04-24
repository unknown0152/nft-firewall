# Setup Script Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `setup.py` — an interactive, Rich-powered wizard that auto-detects network config, validates it with `nft --check`, then applies the ruleset and starts all 3 systemd services with one confirmation.

**Architecture:** Single file `setup.py` in the project root. Pure detection functions (subprocess/file reads) are separated from Rich UI helpers and orchestration phases so they can be unit-tested independently. Phases flow strictly: detect → review → write config + simulate → apply.

**Tech Stack:** Python 3.10+, [Rich](https://github.com/Textualize/rich) (already installed), subprocess, configparser, pathlib.

**Spec:** `docs/superpowers/specs/2026-03-19-setup-script-design.md`

---

## Chunk 1: Scaffold, root check, Rich bootstrap, detection functions

---

### Task 1: Scaffold + root check + Rich bootstrap

**Files:**
- Create: `setup.py`
- Create: `tests/test_setup.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_setup.py
# NOTE: all imports consolidated here — do not add bare imports in later append blocks
import configparser
import importlib
import os
import pwd
import subprocess
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# -- Root check --
def test_exits_when_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    import setup
    with pytest.raises(SystemExit) as exc:
        setup._require_root()
    assert exc.value.code == 1

def test_passes_when_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    import setup
    setup._require_root()   # must not raise
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /home/nuc/nft-firewall
python3 -m pytest tests/test_setup.py::test_exits_when_not_root -v
```
Expected: `ModuleNotFoundError: No module named 'setup'`

- [ ] **Step 3: Create `setup.py` scaffold**

```python
#!/usr/bin/env python3
"""
setup.py — NFT Firewall interactive setup wizard.

Run with: sudo python3 setup.py
"""
from __future__ import annotations

import configparser
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Paths ─────────────────────────────────────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent
_CONFIG_DIR   = _PROJECT_ROOT / "config"
_CONFIG_FILE  = _CONFIG_DIR   / "firewall.ini"
_MAIN_PY      = _PROJECT_ROOT / "src" / "main.py"
_SERVICES_DIR = Path("/etc/systemd/system")
_SERVICE_FILES = ["nft-watchdog.service", "nft-listener.service", "nft-ssh-alert.service"]

VERSION = "10.0"

# ── Status tags ───────────────────────────────────────────────────────────────
DETECTED = "detected"
GUESSED  = "guessed"
MISSING  = "missing"


def _require_root() -> None:
    """Exit immediately if not running as root."""
    if os.geteuid() != 0:
        print("[error] This script must be run as root: sudo python3 setup.py",
              file=sys.stderr)
        sys.exit(1)


def _ensure_rich() -> None:
    """Install rich if not already available."""
    try:
        import rich  # noqa: F401
    except ImportError:
        print("Installing rich...", flush=True)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", "rich"],
            check=True,
        )


if __name__ == "__main__":
    _require_root()
    _ensure_rich()
    # phases imported after rich is guaranteed present
    from rich.console import Console
    console = Console()
    console.print("[green]Setup scaffold OK[/green]")
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /home/nuc/nft-firewall
python3 -m pytest tests/test_setup.py -v
```
Expected: 2 PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): scaffold, root check, rich bootstrap"
```

---

### Task 2: Network detection functions

**Files:**
- Modify: `setup.py` — add detection functions after the constants block
- Modify: `tests/test_setup.py` — add detection tests

Each detection function returns `(value: str, tag: str)` where tag is one of `DETECTED`, `GUESSED`, `MISSING`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_setup.py  (no new imports needed — all at top of file)

# ── _detect_phy_if ─────────────────────────────────────────────────────────
def test_detect_phy_if_from_route(monkeypatch):
    import setup
    mock = MagicMock()
    mock.returncode = 0
    mock.stdout = "1.1.1.1 via 192.168.50.1 dev enp88s0 src 192.168.50.10\n"
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_phy_if()
    assert val == "enp88s0"
    assert tag == setup.DETECTED

def test_detect_phy_if_fallback_on_failure(monkeypatch):
    import setup
    mock = MagicMock(returncode=1, stdout="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_phy_if()
    # fallback returns MISSING so user picks from list
    assert tag == setup.MISSING

# ── _detect_lan_net ────────────────────────────────────────────────────────
def test_detect_lan_net(monkeypatch):
    import setup
    mock = MagicMock(returncode=0,
        stdout="2: enp88s0: ...\n    inet 192.168.50.10/24 brd ...\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_lan_net("enp88s0")
    assert val == "192.168.50.0/24"
    assert tag == setup.DETECTED

def test_detect_lan_net_missing_when_no_inet(monkeypatch):
    import setup
    mock = MagicMock(returncode=0, stdout="2: enp88s0: <UP>\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_lan_net("enp88s0")
    assert tag == setup.MISSING

# ── _detect_vpn_interface ─────────────────────────────────────────────────
def test_detect_vpn_interface(monkeypatch):
    import setup
    mock = MagicMock(returncode=0,
        stdout="1: lo: ...\n4: wg0: <POINTOPOINT,UP> ...\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_vpn_interface()
    assert val == "wg0"
    assert tag == setup.DETECTED

def test_detect_vpn_interface_defaults_to_wg0(monkeypatch):
    import setup
    mock = MagicMock(returncode=0, stdout="1: lo: ...\n2: eth0: ...\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    val, tag = setup._detect_vpn_interface()
    assert val == "wg0"
    assert tag == setup.GUESSED

# ── _detect_vpn_endpoint ──────────────────────────────────────────────────
def test_detect_vpn_endpoint(tmp_path):
    import setup
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Peer]\nEndpoint = 185.236.203.98:9930\n")
    ip, port, tag = setup._detect_vpn_endpoint("wg0", wg_conf_dir=tmp_path)
    assert ip == "185.236.203.98"
    assert port == "9930"
    assert tag == setup.DETECTED

def test_detect_vpn_endpoint_missing(tmp_path):
    import setup
    ip, port, tag = setup._detect_vpn_endpoint("wg0", wg_conf_dir=tmp_path)
    assert tag == setup.MISSING

# ── _detect_ssh_port ──────────────────────────────────────────────────────
def test_detect_ssh_port_from_sshd_config(tmp_path):
    import setup
    sshd = tmp_path / "sshd_config"
    sshd.write_text("Port 2222\nPermitRootLogin no\n")
    val, tag = setup._detect_ssh_port(sshd_config=sshd)
    assert val == "2222"
    assert tag == setup.DETECTED

def test_detect_ssh_port_default(tmp_path):
    import setup
    val, tag = setup._detect_ssh_port(sshd_config=tmp_path / "missing")
    assert val == "22"
    assert tag == setup.GUESSED

# ── _detect_linux_user ────────────────────────────────────────────────────
def test_detect_linux_user(tmp_path, monkeypatch):
    import setup, pwd as _pwd
    fake_home = tmp_path / "alice"
    (fake_home / ".config" / "keybase").mkdir(parents=True)
    entry = MagicMock()
    entry.pw_uid = 1001
    entry.pw_name = "alice"
    entry.pw_dir = str(fake_home)
    monkeypatch.setattr(_pwd, "getpwall", lambda: [entry])
    val, tag = setup._detect_linux_user()
    assert val == "alice"
    assert tag == setup.DETECTED

def test_detect_linux_user_missing(tmp_path, monkeypatch):
    import setup, pwd as _pwd
    monkeypatch.setattr(_pwd, "getpwall", lambda: [])
    val, tag = setup._detect_linux_user()
    assert tag == setup.MISSING

# ── _has_ipv6 ──────────────────────────────────────────────────────────────
def test_has_ipv6_detects_global_address(monkeypatch):
    import setup
    mock = MagicMock(returncode=0,
        stdout="2: eth0:\n    inet 192.168.1.1/24\n    inet6 2a01::1/64 scope global\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    assert setup._has_ipv6("eth0") is True

def test_has_ipv6_ignores_link_local(monkeypatch):
    import setup
    mock = MagicMock(returncode=0,
        stdout="2: eth0:\n    inet 192.168.1.1/24\n    inet6 fe80::1/64 scope link\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    assert setup._has_ipv6("eth0") is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "detect" -v
```
Expected: all FAIL with AttributeError

- [ ] **Step 3: Implement detection functions in `setup.py`**

Add after the constants block:

```python
# ── Detection helpers ─────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 5) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _detect_phy_if() -> Tuple[str, str]:
    """Return (interface_name, tag) via the default route."""
    try:
        r = _run(["ip", "route", "get", "1.1.1.1"])
        if r.returncode == 0:
            m = re.search(r"\bdev\s+(\S+)", r.stdout)
            if m:
                return m.group(1), DETECTED
    except Exception:
        pass
    return "", MISSING


def _list_non_vpn_interfaces() -> List[str]:
    """Return non-loopback, non-WireGuard interface names."""
    try:
        r = _run(["ip", "link", "show"])
        return re.findall(r"^\d+:\s+([^:@\s]+)", r.stdout, re.MULTILINE)
    except Exception:
        return []


def _detect_lan_net(phy_if: str) -> Tuple[str, str]:
    """Return (CIDR network, tag) for the IPv4 address on phy_if."""
    import ipaddress
    try:
        r = _run(["ip", "addr", "show", phy_if])
        m = re.search(r"inet\s+([\d.]+/\d+)", r.stdout)
        if m:
            net = str(ipaddress.IPv4Interface(m.group(1)).network)
            return net, DETECTED
    except Exception:
        pass
    return "", MISSING


def _detect_vpn_interface() -> Tuple[str, str]:
    """Return (wg interface name, tag) from ip link show."""
    try:
        r = _run(["ip", "link", "show"])
        m = re.search(r"^\d+:\s+(wg\S+):", r.stdout, re.MULTILINE)
        if m:
            return m.group(1), DETECTED
    except Exception:
        pass
    return "wg0", GUESSED


def _detect_vpn_endpoint(
    vpn_interface: str,
    wg_conf_dir: Path = Path("/etc/wireguard"),
) -> Tuple[str, str, str]:
    """Return (vpn_server_ip, vpn_server_port, tag) from the wg config file."""
    conf = wg_conf_dir / f"{vpn_interface}.conf"
    try:
        text = conf.read_text()
        m = re.search(r"Endpoint\s*=\s*([\d.]+):(\d+)", text)
        if m:
            return m.group(1), m.group(2), DETECTED
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return "", "", MISSING


def _detect_ssh_port(
    sshd_config: Path = Path("/etc/ssh/sshd_config"),
) -> Tuple[str, str]:
    """Return (port, tag) from sshd_config, defaulting to 22."""
    try:
        text = sshd_config.read_text()
        m = re.search(r"^\s*Port\s+(\d+)", text, re.MULTILINE)
        if m:
            return m.group(1), DETECTED
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return "22", GUESSED


def _detect_linux_user() -> Tuple[str, str]:
    """Return (username, tag) for the first uid≥1000 with ~/.config/keybase."""
    for pw in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
        if pw.pw_uid >= 1000:
            if Path(pw.pw_dir, ".config", "keybase").exists():
                return pw.pw_name, DETECTED
    return "", MISSING


def _has_ipv6(phy_if: str) -> bool:
    """Return True if phy_if has a non-link-local IPv6 address (dual-stack signal)."""
    try:
        r = _run(["ip", "addr", "show", phy_if])
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6") and "fe80::" not in line:
                return True
    except Exception:
        pass
    return False
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "detect" -v
```
Expected: all PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): network detection functions with full test coverage"
```

---

### Task 3: Config writer

**Files:**
- Modify: `setup.py` — add `write_firewall_ini()`
- Modify: `tests/test_setup.py` — add writer tests

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_setup.py  (no new imports needed — all at top of file)

def test_write_firewall_ini_writes_all_keys(tmp_path):
    import setup
    values = {
        "phy_if": "enp88s0",
        "vpn_interface": "wg0",
        "lan_net": "192.168.50.0/24",
        "vpn_server_ip": "185.236.203.98",
        "vpn_server_port": "9930",
        "ssh_port": "22",
        "target_user": "ukendt52",
        "linux_user": "nuc",
        "team": "nuc_firewall_bot",
        "channel": "general",
    }
    out = tmp_path / "firewall.ini"
    setup.write_firewall_ini(values, out)

    cfg = configparser.ConfigParser()
    cfg.read(out)
    # All 6 network keys
    assert cfg.get("network", "phy_if")          == "enp88s0"
    assert cfg.get("network", "vpn_interface")   == "wg0"
    assert cfg.get("network", "lan_net")         == "192.168.50.0/24"
    assert cfg.get("network", "vpn_server_ip")   == "185.236.203.98"
    assert cfg.get("network", "vpn_server_port") == "9930"
    assert cfg.get("network", "ssh_port")        == "22"
    # All 4 keybase keys
    assert cfg.get("keybase", "target_user") == "ukendt52"
    assert cfg.get("keybase", "linux_user")  == "nuc"
    assert cfg.get("keybase", "team")        == "nuc_firewall_bot"
    assert cfg.get("keybase", "channel")     == "general"

def test_write_firewall_ini_creates_parent_dir(tmp_path):
    import setup
    values = {
        "phy_if": "eth0", "vpn_interface": "wg0", "lan_net": "10.0.0.0/24",
        "vpn_server_ip": "1.2.3.4", "vpn_server_port": "51820",
        "ssh_port": "22", "target_user": "bob", "linux_user": "bob",
        "team": "myteam", "channel": "general",
    }
    out = tmp_path / "subdir" / "firewall.ini"
    setup.write_firewall_ini(values, out)
    assert out.exists()
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "write_firewall" -v
```
Expected: FAIL with AttributeError

- [ ] **Step 3: Implement `write_firewall_ini()` in `setup.py`**

```python
def write_firewall_ini(values: Dict[str, str], path: Path = _CONFIG_FILE) -> None:
    """Write all 10 config keys to *path* as a firewall.ini file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    cfg["network"] = {
        "phy_if"         : values["phy_if"],
        "vpn_interface"  : values["vpn_interface"],
        "lan_net"        : values["lan_net"],
        "vpn_server_ip"  : values["vpn_server_ip"],
        "vpn_server_port": values["vpn_server_port"],
        "ssh_port"       : values["ssh_port"],
    }
    cfg["keybase"] = {
        "target_user": values["target_user"],
        "linux_user" : values["linux_user"],
        "team"       : values["team"],
        "channel"    : values["channel"],
    }
    with path.open("w") as f:
        cfg.write(f)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "write_firewall" -v
```
Expected: 2 PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): config writer — all 10 keys, creates parent dir"
```

---

## Chunk 2: Rich UI, phase orchestration, main()

---

### Task 4: Rich UI helpers

**Files:**
- Modify: `setup.py` — add `_ui_*` helpers using Rich

These are display functions — test them by confirming they don't raise, not by asserting output.

- [ ] **Step 1: Write smoke tests**

```python
# append to tests/test_setup.py
def test_ui_helpers_do_not_raise():
    import setup
    # Should not raise even with no terminal attached
    setup._ui_header()
    setup._ui_step(1, 4, "Test step")
    setup._ui_detection_table({
        "phy_if":          ("enp88s0",          "detected"),
        "lan_net":         ("192.168.50.0/24",   "detected"),
        "vpn_interface":   ("wg0",               "detected"),
        "vpn_server_ip":   ("185.236.203.98",    "detected"),
        "vpn_server_port": ("9930",              "detected"),
        "ssh_port":        ("22",                "guessed"),
        "linux_user":      ("nuc",               "detected"),
    })
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "ui_helpers" -v
```
Expected: FAIL with AttributeError

- [ ] **Step 3: Implement Rich UI helpers in `setup.py`**

Add after the detection functions:

```python
# ── Rich UI helpers ───────────────────────────────────────────────────────────
# Imported at function call time so tests can import setup.py without rich

def _console():
    from rich.console import Console
    return Console()


def _ui_header() -> None:
    from rich.panel import Panel
    from rich.text import Text
    c = _console()
    t = Text(f"🛡️  NFT FIREWALL  SETUP  v{VERSION}", justify="center", style="bold cyan")
    c.print(Panel(t, border_style="cyan", padding=(0, 4)))
    c.print()


def _ui_step(n: int, total: int, label: str) -> None:
    from rich.rule import Rule
    _console().print(Rule(f"[bold cyan]Step {n}/{total} — {label}[/bold cyan]"))
    _console().print()


def _ui_detection_table(candidates: Dict[str, Tuple[str, str]]) -> None:
    from rich.table import Table
    from rich.panel import Panel

    ICONS = {DETECTED: "[green]✓[/green]", GUESSED: "[yellow]?[/yellow]", MISSING: "[red]✗[/red]"}
    COLORS = {DETECTED: "green", GUESSED: "yellow", MISSING: "red"}

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim", width=18)
    table.add_column()
    for key, (val, tag) in candidates.items():
        icon  = ICONS.get(tag, "")
        color = COLORS.get(tag, "white")
        display = f"{icon}  [{color}]{val or '(not found)'}[/{color}]"
        table.add_row(key, display)

    _console().print(Panel(table, title="[bold]Detected Configuration[/bold]",
                           border_style="cyan"))
    _console().print()


def _ui_success(msg: str) -> None:
    from rich.panel import Panel
    _console().print(Panel(f"[bold green]✓  {msg}[/bold green]", border_style="green"))
    _console().print()


def _ui_error(msg: str) -> None:
    from rich.panel import Panel
    _console().print(Panel(f"[bold red]✗  {msg}[/bold red]", border_style="red"))
    _console().print()


def _ui_warning(msg: str) -> None:
    _console().print(f"[bold yellow]⚠  {msg}[/bold yellow]")
    _console().print()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "ui_helpers" -v
```
Expected: PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): Rich UI helpers — header, step, detection table, alerts"
```

---

### Task 5: Phase 1 + Phase 2 (detect → review)

**Files:**
- Modify: `setup.py` — add `phase1_detect()` and `phase2_review()`
- Modify: `tests/test_setup.py` — add orchestration tests

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_setup.py
def test_phase1_detect_returns_all_keys(monkeypatch):
    import setup
    # Patch all individual detectors to return known values
    monkeypatch.setattr(setup, "_detect_phy_if",        lambda: ("eth0", setup.DETECTED))
    monkeypatch.setattr(setup, "_detect_lan_net",       lambda iface: ("10.0.0.0/24", setup.DETECTED))
    monkeypatch.setattr(setup, "_detect_vpn_interface", lambda: ("wg0", setup.DETECTED))
    monkeypatch.setattr(setup, "_detect_vpn_endpoint",  lambda iface: ("1.2.3.4", "51820", setup.DETECTED))
    monkeypatch.setattr(setup, "_detect_ssh_port",      lambda: ("22", setup.GUESSED))
    monkeypatch.setattr(setup, "_detect_linux_user",    lambda: ("alice", setup.DETECTED))
    monkeypatch.setattr(setup, "_has_ipv6",             lambda iface: False)
    result = setup.phase1_detect()
    assert result["phy_if"] == ("eth0", setup.DETECTED)
    assert result["ssh_port"] == ("22", setup.GUESSED)
    assert result["vpn_server_ip"] == ("1.2.3.4", setup.DETECTED)
    # All 8 keys present (7 network + has_ipv6)
    for key in ("phy_if","lan_net","vpn_interface","vpn_server_ip",
                "vpn_server_port","ssh_port","linux_user","has_ipv6"):
        assert key in result
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "phase1" -v
```
Expected: FAIL with AttributeError

- [ ] **Step 3: Implement `phase1_detect()` and `phase2_review()` in `setup.py`**

```python
# ── Phase 1 — Auto-detect ─────────────────────────────────────────────────────

def phase1_detect() -> Dict[str, Tuple[str, str]]:
    """Run all detectors. Returns dict of key → (value, tag)."""
    phy_if, phy_tag          = _detect_phy_if()
    lan_net, lan_tag          = _detect_lan_net(phy_if) if phy_if else ("", MISSING)
    vpn_if, vpn_if_tag        = _detect_vpn_interface()
    vpn_ip, vpn_port, ep_tag  = _detect_vpn_endpoint(vpn_if)
    ssh_port, ssh_tag         = _detect_ssh_port()
    linux_user, lu_tag        = _detect_linux_user()
    ipv6_present              = _has_ipv6(phy_if) if phy_if else False

    return {
        "phy_if"         : (phy_if,          phy_tag),
        "lan_net"        : (lan_net,          lan_tag),
        "vpn_interface"  : (vpn_if,           vpn_if_tag),
        "vpn_server_ip"  : (vpn_ip,           ep_tag),
        "vpn_server_port": (vpn_port,         ep_tag),
        "ssh_port"       : (ssh_port,         ssh_tag),
        "linux_user"     : (linux_user,       lu_tag),
        "has_ipv6"       : (str(ipv6_present), DETECTED),
    }


# ── Phase 2 — Review & fill gaps ──────────────────────────────────────────────

def _prompt(label: str, default: str, tag: str) -> str:
    """Prompt user to confirm or replace a value.
    Pressing Enter keeps the default for both detected and guessed values.
    """
    from rich.prompt import Prompt
    if tag == DETECTED:
        return Prompt.ask(f"  [cyan]{label}[/cyan]", default=default, console=_console())
    elif tag == GUESSED:
        return Prompt.ask(f"  [yellow]{label}[/yellow] (guessed)", default=default, console=_console())
    else:
        return Prompt.ask(f"  [red]{label}[/red] (not found)", default="", console=_console())


def _pick_from_list(label: str, options: List[str]) -> str:
    """Show a numbered list and return the user's choice."""
    c = _console()
    c.print(f"\n  [yellow]Multiple options found for {label}:[/yellow]")
    for i, opt in enumerate(options, 1):
        c.print(f"    [cyan]{i}[/cyan]. {opt}")
    from rich.prompt import IntPrompt
    idx = IntPrompt.ask("  Choose", default=1, console=c)
    return options[max(0, min(idx - 1, len(options) - 1))]


def _select_profile() -> str:
    """Show profile list and return chosen profile name."""
    profiles = ["cosmos-vpn-secure", "vpn-only", "media-vpn"]
    descriptions = {
        "cosmos-vpn-secure": "Cosmos Cloud + full-tunnel VPN killswitch (recommended)",
        "vpn-only":          "Pure VPN killswitch — no Cosmos, nothing extra",
        "media-vpn":         "Media stack + VPN killswitch + Cosmos proxy",
    }
    c = _console()
    c.print("\n  [bold]Select a firewall profile:[/bold]")
    for i, name in enumerate(profiles, 1):
        marker = "[cyan](default)[/cyan] " if i == 1 else ""
        c.print(f"    [cyan]{i}[/cyan]. {name} — {descriptions[name]} {marker}")
    from rich.prompt import IntPrompt
    idx = IntPrompt.ask("  Profile", default=1, console=c)
    return profiles[max(0, min(idx - 1, len(profiles) - 1))]


def phase2_review(candidates: Dict[str, Tuple[str, str]]) -> Dict[str, str]:
    """Show detected values and prompt user to confirm/correct.
    Returns a flat dict of confirmed string values + keybase fields.
    """
    c = _console()
    _ui_detection_table(candidates)

    # Warn if no IPv4 found OR if dual-stack (IPv6 also present)
    lan_missing  = candidates.get("lan_net",   ("", MISSING))[1] == MISSING
    has_ipv6     = candidates.get("has_ipv6",  ("False", DETECTED))[0] == "True"
    if lan_missing or has_ipv6:
        _ui_warning(
            "No IPv4 address found on the detected interface.\n"
            "  This setup enforces IPv4-only operation — ALL IPv6 traffic will be dropped."
            if lan_missing else
            "IPv6 detected on this interface.\n"
            "  This setup enforces IPv4-only operation — ALL IPv6 traffic will be dropped."
        )

    # phy_if: may need list if missing
    phy_val, phy_tag = candidates["phy_if"]
    if not phy_val:
        ifaces = [i for i in _list_non_vpn_interfaces()
                  if i != "lo" and not i.startswith("wg")]
        if ifaces:
            phy_val = _pick_from_list("phy_if", ifaces)
            phy_tag = DETECTED
        else:
            phy_val = _prompt("phy_if", "", MISSING)

    c.print("\n  [bold]Confirm or correct detected values[/bold] (Enter to accept):\n")

    confirmed: Dict[str, str] = {}
    confirmed["phy_if"]          = _prompt("phy_if",          phy_val,                            phy_tag)
    confirmed["lan_net"]         = _prompt("lan_net",         candidates["lan_net"][0],           candidates["lan_net"][1])
    confirmed["vpn_interface"]   = _prompt("vpn_interface",   candidates["vpn_interface"][0],     candidates["vpn_interface"][1])
    confirmed["vpn_server_ip"]   = _prompt("vpn_server_ip",   candidates["vpn_server_ip"][0],     candidates["vpn_server_ip"][1])
    confirmed["vpn_server_port"] = _prompt("vpn_server_port", candidates["vpn_server_port"][0],   candidates["vpn_server_port"][1])
    confirmed["ssh_port"]        = _prompt("ssh_port",        candidates["ssh_port"][0],          candidates["ssh_port"][1])

    c.print("\n  [bold]Keybase configuration:[/bold]\n")
    confirmed["target_user"] = _prompt("target_user (authorized Keybase username)", "", MISSING)
    confirmed["linux_user"]  = _prompt("linux_user  (Linux user with Keybase session)",
                                       candidates["linux_user"][0], candidates["linux_user"][1])
    confirmed["team"]        = _prompt("team        (Keybase team name)", "", MISSING)
    confirmed["channel"]     = _prompt("channel     (Keybase channel)", "general", GUESSED)

    confirmed["profile"] = _select_profile()
    return confirmed
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "phase1" -v
```
Expected: PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): phase1 detect + phase2 review with rich prompts"
```

---

### Task 6: Phase 3 — Write config + simulate

**Files:**
- Modify: `setup.py` — add `phase3_simulate()`
- Modify: `tests/test_setup.py` — add simulate tests

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_setup.py
def test_phase3_simulate_writes_config_and_returns_true(tmp_path, monkeypatch):
    import setup
    values = {
        "phy_if": "eth0", "vpn_interface": "wg0", "lan_net": "10.0.0.0/24",
        "vpn_server_ip": "1.2.3.4", "vpn_server_port": "51820", "ssh_port": "22",
        "target_user": "bob", "linux_user": "bob", "team": "myteam",
        "channel": "general", "profile": "cosmos-vpn-secure",
    }
    mock_ok = MagicMock(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_ok)

    config_path = tmp_path / "firewall.ini"
    result = setup.phase3_simulate(values, config_path=config_path)
    assert result is True
    assert config_path.exists()

def test_phase3_simulate_returns_false_on_nft_error(tmp_path, monkeypatch):
    import setup
    values = {
        "phy_if": "eth0", "vpn_interface": "wg0", "lan_net": "10.0.0.0/24",
        "vpn_server_ip": "1.2.3.4", "vpn_server_port": "51820", "ssh_port": "22",
        "target_user": "bob", "linux_user": "bob", "team": "myteam",
        "channel": "general", "profile": "cosmos-vpn-secure",
    }
    mock_fail = MagicMock(returncode=1, stdout="", stderr="syntax error")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_fail)

    result = setup.phase3_simulate(values, config_path=tmp_path / "firewall.ini")
    assert result is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "phase3" -v
```
Expected: FAIL

- [ ] **Step 3: Implement `phase3_simulate()` in `setup.py`**

```python
# ── Phase 3 — Write config + simulate ────────────────────────────────────────

def phase3_simulate(
    values: Dict[str, str],
    config_path: Path = _CONFIG_FILE,
) -> bool:
    """Write firewall.ini then validate with 'main.py simulate <profile>'.
    Returns True on success, False on failure (prints error, does not exit).
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn

    write_firewall_ini(values, config_path)

    profile = values.get("profile", "cosmos-vpn-secure")
    cmd = [sys.executable, str(_MAIN_PY), "simulate", profile]

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  transient=True) as prog:
        prog.add_task("Validating ruleset with nft --check ...", total=None)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            _ui_error("Ruleset simulation timed out after 30s.")
            return False

    if r.returncode == 0:
        _ui_success("Ruleset is valid — nft --check passed.")
        return True
    else:
        _ui_error(f"Ruleset validation failed:\n\n{r.stderr or r.stdout}")
        return False
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "phase3" -v
```
Expected: 2 PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): phase3 — write config + simulate with spinner"
```

---

### Task 7: Phase 4 — Apply & start services

**Files:**
- Modify: `setup.py` — add `phase4_apply()`

This phase has side effects (apt, nft, systemctl) — test it with mocked subprocess only.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_setup.py
def test_phase4_apply_runs_all_steps(tmp_path, monkeypatch):
    import setup
    calls = []
    def mock_run(cmd, **kw):
        calls.append(cmd)
        return MagicMock(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(subprocess, "run", mock_run)
    # Patch service file copy (needs root in real run)
    monkeypatch.setattr(setup, "_install_service_files", lambda: None)

    values = {
        "phy_if": "eth0", "vpn_interface": "wg0", "lan_net": "10.0.0.0/24",
        "vpn_server_ip": "1.2.3.4", "vpn_server_port": "51820", "ssh_port": "22",
        "target_user": "bob", "linux_user": "bob", "team": "myteam",
        "channel": "general", "profile": "cosmos-vpn-secure",
    }
    setup.phase4_apply(values)
    # apply and systemctl enable must have been called
    flat = [" ".join(c) for c in calls]
    assert any("apply" in s for s in flat)
    assert any("enable" in s for s in flat)
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "phase4" -v
```
Expected: FAIL

- [ ] **Step 3: Implement `phase4_apply()` and helpers in `setup.py`**

```python
# ── Phase 4 — Apply & start services ─────────────────────────────────────────

def _apt_check_missing(packages: List[str]) -> List[str]:
    """Return packages from *packages* that are not currently installed."""
    missing = []
    for pkg in packages:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True,
        )
        if "install ok installed" not in r.stdout:
            missing.append(pkg)
    return missing


def _install_service_files() -> None:
    """Copy the 3 service files from the project root to /etc/systemd/system/."""
    import shutil
    for name in _SERVICE_FILES:
        src = _PROJECT_ROOT / name
        dst = _SERVICES_DIR / name
        if not src.exists():
            _ui_error(f"Service file not found: {src}")
            sys.exit(1)
        shutil.copy2(src, dst)


def _spinner(label: str, cmd: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    """Run *cmd* with an animated Rich spinner. Returns CompletedProcess.
    Callers must check returncode — this helper never raises on non-zero exit.
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn
    with Progress(SpinnerColumn(), TextColumn(label), transient=True) as prog:
        prog.add_task(label, total=None)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r


def phase4_apply(values: Dict[str, str]) -> None:
    """Install deps, apply ruleset, install services, start all 3 daemons."""
    from rich.prompt import Confirm
    from rich.panel import Panel

    c = _console()
    profile = values.get("profile", "cosmos-vpn-secure")

    # ── Confirmation panel ────────────────────────────────────────────────────
    summary = (
        f"  Profile  : [cyan]{profile}[/cyan]\n"
        f"  Services : nft-watchdog, nft-listener, nft-ssh-alert\n"
        f"  Config   : {_CONFIG_FILE}"
    )
    c.print(Panel(summary, title="[bold]About to apply[/bold]", border_style="yellow"))

    if not Confirm.ask("\n  [bold yellow]Apply ruleset and start all 3 services?[/bold yellow]",
                       default=False, console=c):
        c.print("\n[dim]Setup cancelled.[/dim]")
        sys.exit(0)

    # ── Step 1: Install missing packages ─────────────────────────────────────
    required = ["nftables", "python3", "python3-pip", "wireguard-tools"]
    missing  = _apt_check_missing(required)
    if missing:
        c.print(f"\n  Installing: {', '.join(missing)}")
        r = _spinner(f"apt-get install {' '.join(missing)} ...",
                     ["apt-get", "install", "-y"] + missing)
        if r.returncode != 0:
            _ui_error(f"apt-get failed:\n{r.stderr}")
            sys.exit(1)

    # Install rich if not already present (may have just gotten python3-pip above)
    try:
        import rich  # noqa: F401
    except ImportError:
        r = _spinner("pip3 install rich ...",
                     [sys.executable, "-m", "pip", "install", "--quiet", "rich"])
        if r.returncode != 0:
            _ui_error(f"pip install rich failed:\n{r.stderr}")
            sys.exit(1)

    # ── Step 2: Apply ruleset ────────────────────────────────────────────────
    r = _spinner(f"Applying profile '{profile}' ...",
                 [sys.executable, str(_MAIN_PY), "apply", profile])
    if r.returncode != 0:
        _ui_error(f"Ruleset apply failed:\n{r.stderr or r.stdout}")
        sys.exit(1)

    # ── Step 3: Install service files ────────────────────────────────────────
    from rich.progress import Progress, SpinnerColumn, TextColumn
    with Progress(SpinnerColumn(), TextColumn("Installing service files ..."),
                  transient=True) as prog:
        prog.add_task("", total=None)
        _install_service_files()

    # ── Step 4: Enable and start services ────────────────────────────────────
    r = _spinner("Reloading systemd ...", ["systemctl", "daemon-reload"])
    if r.returncode != 0:
        _ui_error(f"daemon-reload failed:\n{r.stderr}")
        sys.exit(1)

    svc_names = [s.replace(".service", "") for s in _SERVICE_FILES]
    r = _spinner("Enabling and starting services ...",
                 ["systemctl", "enable", "--now"] + svc_names)
    if r.returncode != 0:
        # Show journal tail for diagnosis
        for svc in svc_names:
            jctl = subprocess.run(
                ["journalctl", "-u", svc, "-n", "20", "--no-pager"],
                capture_output=True, text=True,
            )
            if jctl.stdout.strip():
                _ui_error(f"Journal for {svc}:\n{jctl.stdout}")
        sys.exit(1)

    # ── Step 5: Show live status dashboard ───────────────────────────────────
    from rich.panel import Panel
    c.print()
    r = subprocess.run(
        [sys.executable, str(_MAIN_PY), "status"],
        capture_output=True, text=True,
    )
    c.print(Panel(r.stdout.strip(), title="[bold green]🛡️  Live Status[/bold green]",
                  border_style="green"))
    _ui_success("Setup complete! All services are running.")
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python3 -m pytest tests/test_setup.py -k "phase4" -v
```
Expected: PASSED

- [ ] **Step 5: Commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): phase4 — apt, apply, service install, start, status panel"
```

---

### Task 8: Wire `main()`, full run + final test

**Files:**
- Modify: `setup.py` — add `main()` and `__main__` block
- Modify: `tests/test_setup.py` — add full-flow smoke test

- [ ] **Step 1: Write the smoke test**

```python
# append to tests/test_setup.py  (no new imports needed — all at top of file)

# NOTE: import setup at module level so monkeypatch.setattr works on the
# cached module object rather than a fresh one per test.
import setup as _setup_mod   # alias to avoid shadowing local names

def test_main_calls_all_phases(monkeypatch):
    calls = []
    monkeypatch.setattr(os,         "geteuid",        lambda: 0)
    monkeypatch.setattr(_setup_mod, "_ensure_rich",   lambda: calls.append("rich"))
    monkeypatch.setattr(_setup_mod, "_ui_header",     lambda: calls.append("header"))
    monkeypatch.setattr(_setup_mod, "_ui_step",       lambda *a: None)   # suppress Rich output
    monkeypatch.setattr(_setup_mod, "phase1_detect",  lambda: calls.append("p1") or {})
    monkeypatch.setattr(_setup_mod, "phase2_review",  lambda c: calls.append("p2") or {"profile": "vpn-only"})
    monkeypatch.setattr(_setup_mod, "phase3_simulate", lambda v, **kw: calls.append("p3") or True)
    monkeypatch.setattr(_setup_mod, "phase4_apply",   lambda v: calls.append("p4"))
    _setup_mod.main()
    assert calls == ["rich", "header", "p1", "p2", "p3", "p4"]

def test_main_exits_if_simulate_fails(monkeypatch):
    monkeypatch.setattr(os,         "geteuid",        lambda: 0)
    monkeypatch.setattr(_setup_mod, "_ensure_rich",   lambda: None)
    monkeypatch.setattr(_setup_mod, "_ui_header",     lambda: None)
    monkeypatch.setattr(_setup_mod, "_ui_step",       lambda *a: None)
    monkeypatch.setattr(_setup_mod, "phase1_detect",  lambda: {})
    monkeypatch.setattr(_setup_mod, "phase2_review",  lambda c: {"profile": "vpn-only"})
    monkeypatch.setattr(_setup_mod, "phase3_simulate", lambda v, **kw: False)
    p4_called = []
    monkeypatch.setattr(_setup_mod, "phase4_apply",   lambda v: p4_called.append(True))
    with pytest.raises(SystemExit) as exc:
        _setup_mod.main()
    assert exc.value.code == 1
    assert not p4_called   # phase4 must NOT run if simulate fails
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest tests/test_setup.py -k "test_main" -v
```
Expected: FAIL

- [ ] **Step 3: Implement `main()` in `setup.py`**

Replace the `if __name__ == "__main__":` block:

```python
# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    _require_root()
    _ensure_rich()

    _ui_header()

    _ui_step(1, 4, "Network Detection")
    candidates = phase1_detect()

    _ui_step(2, 4, "Configuration Review")
    confirmed = phase2_review(candidates)

    _ui_step(3, 4, "Simulate Ruleset")
    if not phase3_simulate(confirmed):
        sys.exit(1)

    _ui_step(4, 4, "Apply & Start Services")
    phase4_apply(confirmed)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the full test suite**

```bash
python3 -m pytest tests/test_setup.py -v
```
Expected: ALL PASSED

- [ ] **Step 5: Verify the script is syntactically valid and the help screen works**

```bash
python3 -c "import py_compile; py_compile.compile('setup.py'); print('syntax OK')"
# Verify it exits cleanly when not root (don't actually run as root)
python3 setup.py 2>&1 | head -3
```
Expected first line: `[error] This script must be run as root: sudo python3 setup.py`

- [ ] **Step 6: Final commit**

```bash
git add setup.py tests/test_setup.py
git commit -m "feat(setup): main() wiring + full test suite — setup wizard complete"
```

---

## Validation

After all tasks complete, run the full test suite one final time:

```bash
cd /home/nuc/nft-firewall
python3 -m pytest tests/test_setup.py -v --tb=short
```

Expected: **all tests PASSED**, zero failures.

Then do a live dry run (non-root exits cleanly with a styled error panel — confirms Rich is working):

```bash
python3 setup.py
```
Expected: red error panel "This script must be run as root".
