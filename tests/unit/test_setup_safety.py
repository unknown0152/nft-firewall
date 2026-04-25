import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))


def test_setup_install_sequence_does_not_apply_live_rules(monkeypatch):
    import setup

    calls = []
    for name in (
        "step0_configure",
        "step1_create_system_user",
        "step2_install_code",
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
