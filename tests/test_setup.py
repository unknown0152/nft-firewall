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
def test_exits_when_not_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    import setup
    with pytest.raises(SystemExit) as exc:
        setup._require_root()
    assert exc.value.code == 1

def test_passes_when_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    import setup
    setup._require_root()   # must not raise

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

def test_detect_phy_if_skips_wg_interface(monkeypatch):
    import setup
    # Simulate VPN-active: route goes via wg0, but enp88s0 has an IPv4 addr
    call_count = [0]
    def mock_run(cmd, *a, **kw):
        call_count[0] += 1
        m = MagicMock()
        if "route" in cmd:
            m.returncode = 0
            m.stdout = "1.1.1.1 dev wg0 src 10.0.0.2\n"
        elif "link" in cmd:
            m.returncode = 0
            m.stdout = "1: lo:\n2: enp88s0:\n"
        elif "addr" in cmd and "enp88s0" in cmd:
            m.returncode = 0
            m.stdout = "2: enp88s0:\n    inet 192.168.50.10/24\n"
        else:
            m.returncode = 1
            m.stdout = ""
        return m
    monkeypatch.setattr(subprocess, "run", mock_run)
    val, tag = setup._detect_phy_if()
    assert val == "enp88s0"
    assert tag == setup.DETECTED

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

# ── _list_non_vpn_interfaces ────────────────────────────────────────────────
def test_list_non_vpn_interfaces_excludes_lo_and_wg(monkeypatch):
    import setup
    mock = MagicMock(returncode=0,
        stdout="1: lo: <LOOPBACK,UP>\n2: enp88s0: <UP>\n3: wg0: <UP>\n4: eth1: <UP>\n")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock)
    result = setup._list_non_vpn_interfaces()
    assert "lo" not in result
    assert "wg0" not in result
    assert "enp88s0" in result
    assert "eth1" in result

def test_list_non_vpn_interfaces_returns_empty_on_failure(monkeypatch):
    import setup
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(Exception("fail")))
    result = setup._list_non_vpn_interfaces()
    assert result == []

# ── write_firewall_ini ──────────────────────────────────────────────────────
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

# ── Rich UI helpers smoke tests ─────────────────────────────────────────────
def test_ui_helpers_do_not_raise(monkeypatch):
    import setup
    # Patch _ui_step and _ui_detection_table to use a no-op _console
    # so they don't need a real terminal
    monkeypatch.setattr(setup, "_console", lambda: __import__("rich.console", fromlist=["Console"]).Console(force_terminal=False))
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
    setup._ui_success("All good")
    setup._ui_error("Something failed")
    setup._ui_warning("Check this")

# ── Phase 1 ────────────────────────────────────────────────────────────────────
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

# ── Phase 3 ────────────────────────────────────────────────────────────────────
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

# ── Phase 4 ────────────────────────────────────────────────────────────────────
def test_phase4_apply_runs_all_steps(tmp_path, monkeypatch):
    import setup
    calls = []
    def mock_run(cmd, **kw):
        calls.append(cmd)
        return MagicMock(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(subprocess, "run", mock_run)
    # Patch service file copy (needs root in real run)
    monkeypatch.setattr(setup, "_install_service_files", lambda: None)
    # Patch Confirm.ask to always return True
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **kw: True)

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

# ── main() smoke tests ─────────────────────────────────────────────────────────
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
