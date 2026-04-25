import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_setup_install_sequence_does_not_apply_live_rules(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
        "step2_5_nft_preflight",
        "step3_scaffold_dirs",
        "step4_install_sudoers",
        "step5_deploy_services",
        "step6_reload_and_restart",
        "step7_apply_ruleset",
    ):
        monkeypatch.setattr(setup, name, lambda name=name, **_kw: calls.append(name))

    setup.cmd_install()

    assert "step7_apply_ruleset" not in calls


def test_fw_wrapper_blocks_plain_apply():
    script = Path(__file__).resolve().parent.parent.parent / "scripts" / "fw"
    text = script.read_text()
    assert "safe-apply" in text
    assert "use 'fw safe-apply <profile>'" in text


def test_firewall_threatfeed_service_uses_real_cli_command():
    service = (
        Path(__file__).resolve().parent.parent.parent
        / "systemd"
        / "nft-firewall-threatfeed.service"
    )
    text = service.read_text()

    assert "ExecStart=/usr/local/bin/fw threat-update" in text
    assert "threatfeed update" not in text


def test_uninstall_flushes_live_ruleset(monkeypatch):
    import setup

    calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "shutil", type("S", (), {"rmtree": lambda *a: None})())

    import pathlib
    monkeypatch.setattr(setup, "INSTALL_DIR",  type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(setup, "SUDOERS_FILE", type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(pathlib.Path, "exists", lambda s: False)

    setup.cmd_uninstall()

    flush_call = ("/usr/sbin/nft", "flush", "ruleset")
    assert flush_call in calls, f"nft flush ruleset not called; calls={calls}"


def test_uninstall_flushes_before_stopping_services(monkeypatch):
    import setup

    calls = []
    monkeypatch.setattr(setup, "_run", lambda cmd, **kw: calls.append(tuple(cmd)))
    monkeypatch.setattr(setup, "_ok",   lambda *a, **kw: None)
    monkeypatch.setattr(setup, "_info", lambda *a, **kw: None)
    monkeypatch.setattr(setup, "shutil", type("S", (), {"rmtree": lambda *a: None})())

    import pathlib
    monkeypatch.setattr(setup, "INSTALL_DIR",  type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(setup, "SUDOERS_FILE", type("P", (), {"exists": lambda s: False})())
    monkeypatch.setattr(pathlib.Path, "exists", lambda s: False)

    setup.cmd_uninstall()

    flush_idx = next(i for i, c in enumerate(calls) if c == ("/usr/sbin/nft", "flush", "ruleset"))
    systemctl_indices = [i for i, c in enumerate(calls) if c[0] == "systemctl"]
    assert all(flush_idx < s for s in systemctl_indices), (
        f"flush (idx={flush_idx}) must precede all systemctl calls (idx={systemctl_indices})"
    )


def test_install_sequence_calls_nft_preflight(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
        "step2_5_nft_preflight",
        "step3_scaffold_dirs",
        "step4_install_sudoers",
        "step5_deploy_services",
        "step6_reload_and_restart",
    ):
        monkeypatch.setattr(setup, name, lambda name=name, **_kw: calls.append(name))

    setup.cmd_install()

    assert "step2_5_nft_preflight" in calls
    assert calls.index("step2_5_nft_preflight") > calls.index("step2_install_code")
    assert calls.index("step2_5_nft_preflight") < calls.index("step3_scaffold_dirs")


def test_preflight_exits_on_nft_syntax_error(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\nphy_if = eth0\nvpn_server_ip = 1.2.3.4\n"
        "vpn_server_port = 51820\nlan_net = 192.168.1.0/24\nssh_port = 22\n"
    )
    monkeypatch.setattr(setup, "_CONF_FILE", ini)

    real_src = str(Path(__file__).resolve().parent.parent.parent / "src")
    monkeypatch.syspath_prepend(real_src)

    monkeypatch.setattr(
        _subprocess, "run",
        lambda *a, **kw: _subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Error: syntax error at line 42"
        ),
    )

    with pytest.raises(SystemExit):
        setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")


def test_preflight_passes_on_valid_ruleset(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    ini = tmp_path / "firewall.ini"
    ini.write_text(
        "[network]\nphy_if = eth0\nvpn_server_ip = 1.2.3.4\n"
        "vpn_server_port = 51820\nlan_net = 192.168.1.0/24\nssh_port = 22\n"
    )
    monkeypatch.setattr(setup, "_CONF_FILE", ini)

    monkeypatch.setattr(
        _subprocess, "run",
        lambda *a, **kw: _subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        ),
    )

    # Should complete without raising
    setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")


def test_preflight_skips_if_ini_missing(monkeypatch, tmp_path):
    import setup
    import subprocess as _subprocess

    monkeypatch.setattr(setup, "_CONF_FILE", tmp_path / "missing.ini")
    run_calls = []
    monkeypatch.setattr(_subprocess, "run", lambda *a, **kw: run_calls.append(a))

    setup.step2_5_nft_preflight(src_path=Path(__file__).resolve().parent.parent.parent / "src")

    assert run_calls == [], "nft should not be called when firewall.ini is missing"
