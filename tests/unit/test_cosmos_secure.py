import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from core.profiles import get_profile
from core.rules import RulesetConfig, generate_ruleset


def _rules(public_ports=None):
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
        docker_networks=["172.18.0.0/16", "172.19.0.0/16"],
        cosmos_public_ports=public_ports or [],
    )
    return generate_ruleset(cfg)


def test_cosmos_secure_profile_does_not_open_cosmos_vpn_port():
    profile = get_profile("cosmos-secure")
    ruleset = _rules([80, 443])

    assert profile.cosmos_udp == []
    assert "4242" not in ruleset
    assert "udp dport 4242" not in ruleset


def test_cosmos_public_ports_are_configurable():
    ruleset = _rules([8080])

    assert 'iifname "eth0" tcp dport { 8080 } accept' in ruleset
    assert "tcp dport { 80, 443 }" not in ruleset


def test_docker_forwarding_is_limited_to_configured_public_ports():
    ruleset = _rules([80, 443])

    assert "set docker_nets" in ruleset
    assert "elements = { 172.18.0.0/15 }" in ruleset
    assert 'iifname "eth0" tcp dport { 80, 443 } ip daddr @docker_nets accept' in ruleset
    assert 'meta iifkind "bridge" meta oifkind "bridge" accept' not in ruleset


def test_overlapping_docker_networks_are_collapsed_for_interval_set():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.16.0.0/12", "172.17.0.0/16", "172.18.0.0/16"],
        cosmos_public_ports=[80, 443],
    )
    ruleset = generate_ruleset(cfg)

    assert "elements = { 172.16.0.0/12 }" in ruleset
    assert "172.17.0.0/16" not in ruleset
    assert "172.18.0.0/16" not in ruleset


def test_generated_interval_sets_are_collapsed():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        blocked_ips=["203.0.113.0/24", "203.0.113.7/32"],
        trusted_ips=["198.51.100.0/24", "198.51.100.4/32"],
        dk_ips=["193.163.0.0/16", "193.163.10.0/24"],
    )
    ruleset = generate_ruleset(cfg)

    assert "elements = { 203.0.113.0/24 }" in ruleset
    assert "203.0.113.7/32" not in ruleset
    assert "elements = { 198.51.100.0/24 }" in ruleset
    assert "198.51.100.4/32" not in ruleset
    assert "elements = { 193.163.0.0/16 }" in ruleset
    assert "193.163.10.0/24" not in ruleset


def test_random_published_container_port_is_not_allowed_without_config_port():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.18.0.0/16"],
        cosmos_public_ports=[80, 443],
    )
    exposed = [{
        "host_port": 9999,
        "container_ip": "172.18.0.5",
        "container_port": 9999,
        "proto": "tcp",
    }]
    ruleset = generate_ruleset(cfg, exposed_ports=exposed)

    assert "tcp dport 9999 dnat" not in ruleset
    assert "tcp dport 9999 ip daddr 172.18.0.5 accept" not in ruleset
    assert 'iifname "eth0" tcp dport 9999 accept' not in ruleset


def test_published_container_port_is_allowed_when_listed_in_firewall_config():
    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="198.51.100.10",
        vpn_server_port="51820",
        docker_networks=["172.18.0.0/16"],
        cosmos_public_ports=[8080],
    )
    exposed = [{
        "host_port": 8080,
        "container_ip": "172.18.0.5",
        "container_port": 80,
        "proto": "tcp",
    }]
    ruleset = generate_ruleset(cfg, exposed_ports=exposed)

    assert "tcp dport 8080 dnat to 172.18.0.5:80" in ruleset
    assert "tcp dport 80 ip daddr 172.18.0.5 accept" in ruleset


def test_container_killswitch_remains_enforced_for_forwarding():
    ruleset = _rules([80, 443])

    assert 'ip saddr @docker_nets oifname "eth0" ct state new drop' in ruleset
    assert 'ip saddr @docker_nets oifname "wg0" accept' in ruleset
    assert '        oifname "wg0" accept  # container internet ONLY via VPN' not in ruleset


def test_ssh_rules_remain_protected():
    ruleset = _rules([80, 443])

    assert 'iifname "eth0" ip saddr 192.168.1.0/24 tcp dport 22 accept' in ruleset
    assert 'iifname "eth0" tcp dport 22 drop' in ruleset
    assert 'iifname "wg0" tcp dport 22 drop' in ruleset
