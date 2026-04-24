import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core.rules import RulesetConfig, generate_ruleset


def test_generate_ruleset_preloads_persistent_dynamic_sets():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        blocked_ips=["203.0.113.4/32"],
        trusted_ips=["198.51.100.7/32"],
        dk_ips=["193.163.0.0/16"],
    )
    ruleset = generate_ruleset(cfg)

    assert "set blocked_ips" in ruleset
    assert "elements = { 203.0.113.4/32 }" in ruleset
    assert "elements = { 198.51.100.7/32 }" in ruleset
    assert "elements = { 193.163.0.0/16 }" in ruleset
