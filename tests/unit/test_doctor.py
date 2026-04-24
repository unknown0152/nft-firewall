import configparser
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))


def _patch_doctor_common(monkeypatch, ruleset=None):
    import core.rules
    import core.state
    import integrations.docker
    import main

    cfg = configparser.ConfigParser()
    cfg["install"] = {"profile": "cosmos-vpn-secure"}

    monkeypatch.setattr(main, "_load_config", lambda: cfg)
    monkeypatch.setattr(
        main,
        "_build_ruleset_config",
        lambda _cfg, _profile: types.SimpleNamespace(phy_if="eth0", vpn_interface="wg0"),
    )
    monkeypatch.setattr(integrations.docker, "load_registry", lambda: [])
    monkeypatch.setattr(
        core.rules,
        "generate_ruleset",
        lambda _cfg, exposed_ports=None: ruleset
        or 'table ip6 killswitch { chain input { priority -300; } }\n'
        'table ip firewall { chain output { oifname "wg0" accept } }\n',
    )
    monkeypatch.setattr(core.state, "load_persistent_sets", lambda: {})
    return main, core.state


def test_doctor_uses_installed_privileged_nft_wrapper(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)
    seen = {}

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        main.Path,
        "exists",
        lambda self: str(self) == "/usr/local/lib/nft-firewall/fw-nft",
    )

    def fake_simulate(_ruleset, nft_cmd=None):
        seen["nft_cmd"] = nft_cmd
        return True, ""

    monkeypatch.setattr(state, "simulate_apply", fake_simulate)

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    assert exc.value.code == 0
    assert seen["nft_cmd"] == ["sudo", "/usr/local/lib/nft-firewall/fw-nft"]
    assert "[ok] nft --check: ruleset syntax valid" in capsys.readouterr().out


def test_doctor_warns_when_privileged_nft_wrapper_missing(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(main.Path, "exists", lambda _self: False)
    monkeypatch.setattr(
        state,
        "simulate_apply",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[warn] nft --check: nft --check requires installed sudo wrapper; run setup.py install or run doctor as root" in out


def test_doctor_warns_when_sudo_wrapper_permission_missing(monkeypatch, capsys):
    main, state = _patch_doctor_common(monkeypatch)

    monkeypatch.setattr(main.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        main.Path,
        "exists",
        lambda self: str(self) == "/usr/local/lib/nft-firewall/fw-nft",
    )
    monkeypatch.setattr(
        state,
        "simulate_apply",
        lambda _ruleset, nft_cmd=None: (False, "sudo: a password is required"),
    )

    with pytest.raises(SystemExit) as exc:
        main._cmd_doctor(types.SimpleNamespace(profile="cosmos-vpn-secure"))

    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "[warn] nft --check: nft --check requires installed sudo wrapper; run setup.py install or run doctor as root" in out
