NFT Firewall AI Context

This is a security-critical nftables + WireGuard + Docker killswitch project.

Core invariants:
1. No internet egress except via wg0.
2. Physical interface enp88s0 must never expose public ports 80/443/6881/etc.
3. Docker iptables/ip6tables are disabled; nftables is authoritative.
4. Docker/container egress must never escape via enp88s0.
5. If wg0 is down, host and containers must fail closed.
6. /0 CIDRs must always be rejected.
7. fw-admin must only mutate firewall through strict wrappers.
8. doctor must inspect BOTH generated rules and live nft rules.
9. Tests must prove every security invariant.
10. Do not add broad accept rules unless explicitly justified and tested.

Known safe output rules:
- loopback
- WireGuard bootstrap to configured VPN endpoint
- DHCP client rule: oifname phy_if udp sport 68 dport 67 accept
- LAN destination allow: oifname phy_if ip daddr lan_net accept
- Docker bridge-local destination: meta oifkind "bridge" ip daddr @docker_nets accept
- VPN egress: oifname wg0 accept

Rules for AI changes:
- Small diffs only.
- No broad refactors.
- Do not change firewall behavior unless requested.
- Every fix needs a failing test first.
- After every fix run:
  pytest tests/unit -q
  sudo fw simulate cosmos-vpn-secure
  sudo fw doctor
- If changing wrappers, reinstall with sudo python3 setup.py install before live testing.
- If changing rules, use sudo fw safe-apply cosmos-vpn-secure and confirm.
