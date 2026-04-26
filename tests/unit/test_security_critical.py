"""
tests/unit/test_security_critical.py
"""
import os
import pytest
from core.rules import RulesetConfig, generate_ruleset, _check_invariants
from daemons.knockd import PortKnockDaemon

def test_ruleset_invariant_catches_alias_0_slash_0():
    cfg = RulesetConfig(phy_if="eth0", vpn_interface="wg0")
    ruleset = 'table ip firewall { chain input { ip saddr 0/0 accept comment "nft-killswitch-output" } } policy drop'
    with pytest.raises(ValueError, match="/0 network found"):
        _check_invariants(cfg, ruleset)

def test_ruleset_invariant_catches_multiline_exposure():
    cfg = RulesetConfig(phy_if="eth0", vpn_interface="wg0")
    ruleset = (
        'table ip firewall {\n'
        '  chain input {\n'
        '    iifname "eth0"\n'
        '    tcp dport 80\n'
        '    accept\n'
        '  }\n'
        '}\n'
        'comment "nft-killswitch-output"\n'
        'policy drop'
    )
    with pytest.raises(ValueError, match="Public port exposure detected on eth0"):
        _check_invariants(cfg, ruleset)

def test_knockd_rejects_physical_iface(tmp_path):
    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = eth0\n")
    daemon = PortKnockDaemon(str(conf))
    with pytest.raises(RuntimeError, match="matches physical interface"):
        daemon._add_rule("1.2.3.4")

def test_knockd_rejects_non_wg_iface(tmp_path):
    conf = tmp_path / "firewall.ini"
    conf.write_text("[network]\nphy_if = eth0\nvpn_interface = enp1s0\n")
    daemon = PortKnockDaemon(str(conf))
    with pytest.raises(RuntimeError, match="not a trusted tunnel type"):
        daemon._add_rule("1.2.3.4")
