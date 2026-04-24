"""
src/core/rules.py — Pure nftables ruleset generator.

This module is intentionally side-effect-free.  It only builds strings.
No subprocess calls, no file I/O, no imports from state.py.

Usage
-----
    from core.rules import RulesetConfig, generate_ruleset

    cfg = RulesetConfig(
        phy_if="eth0",
        vpn_interface="wg0",
        vpn_server_ip="1.2.3.4",
        vpn_server_port="51820",
        lan_net="192.168.1.0/24",
        ssh_port=22,
        cosmos_tcp=[80, 443],
        cosmos_udp=[4242],
    )
    ruleset_str = generate_ruleset(cfg, exposed_ports=[...])

The returned string can be passed directly to ``state.apply_ruleset()``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# ── Data contract ─────────────────────────────────────────────────────────────

@dataclass
class RulesetConfig:
    """All inputs needed to generate a complete nftables ruleset.

    Only ``phy_if`` is required; every other field has a safe default.

    Attributes
    ----------
    phy_if:
        Physical (WAN-facing) network interface, e.g. ``"eth0"``.
    vpn_interface:
        WireGuard tunnel interface name.  Default ``"wg0"``.
    vpn_server_ip:
        Remote WireGuard endpoint IP.  Used in the OUTPUT bootstrap rule.
    vpn_server_port:
        Remote WireGuard endpoint UDP port.
    lan_net:
        Local LAN subnet in CIDR notation, e.g. ``"192.168.1.0/24"``.
    container_supernet:
        Docker container IP supernet (covers all bridge /28 networks).
        Default ``"172.16.0.0/12"``.
    docker_networks:
        Docker bridge network CIDRs treated as internal container networks.
    ssh_port:
        SSH port to protect with LAN + GeoIP restrictions.  Default ``22``.
    torrent_port:
        Optional torrent TCP+UDP port to open on the VPN interface.
    extra_ports:
        Additional TCP ports to open on the VPN interface.
    cosmos_tcp:
        TCP ports used by Cosmos (``--network host``, no DNAT needed).
    cosmos_udp:
        UDP ports used by Cosmos Constellation VPN.
        This project does not enable Cosmos VPN; keep empty unless explicitly
        implementing unrelated custom UDP exposure.
    cosmos_public_ports:
        TCP ports exposed for Cosmos Cloud reverse-proxy ingress.
    allow_plex_lan:
        When ``True``, open port 32400 for LAN-only Plex direct play.
    blocked_ips/trusted_ips/dk_ips:
        Persisted dynamic set members to preload after a ruleset reload.
    """

    # Required
    phy_if: str

    # Network topology
    vpn_interface:      str           = "wg0"
    vpn_server_ip:      str           = ""
    vpn_server_port:    str           = ""
    lan_net:            str           = "192.168.1.0/24"
    container_supernet: str           = "172.16.0.0/12"
    docker_networks:    List[str]     = field(default_factory=list)

    # WireGuard fwmark — wg-quick marks its encrypted UDP packets with this value
    # so the kernel routing policy can exempt them from the tunnel (avoiding loops).
    # The same mark is used here to lock the bootstrap OUTPUT rule to the WG process.
    # Default 0xca6c = 51820 — the standard wg-quick value for wg0.
    vpn_fwmark: str = "0xca6c"

    # Ports
    ssh_port:     int            = 22
    torrent_port: Optional[int]  = None
    extra_ports:  List[int]      = field(default_factory=list)

    # Profile flags
    cosmos_tcp:     List[int] = field(default_factory=list)
    cosmos_udp:     List[int] = field(default_factory=list)
    cosmos_public_ports: List[int] = field(default_factory=list)
    allow_plex_lan: bool      = False

    # Persisted dynamic sets
    blocked_ips: List[str] = field(default_factory=list)
    trusted_ips: List[str] = field(default_factory=list)
    dk_ips:      List[str] = field(default_factory=list)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _iface_vars(cfg: RulesetConfig) -> Dict[str, str]:
    """Return the nftables interface-match expression strings.

    Keys: PHY, OPH, VPN, OVPN — positive matches only.
    Negative-match variants (NPHY, NOPH, NVPN, NOVP) have been removed:
    every accept rule must name the interface it permits, never 'not X'.
    """
    phy = cfg.phy_if
    vpn = cfg.vpn_interface
    return {
        "PHY" : f'iifname "{phy}"',
        "OPH" : f'oifname "{phy}"',
        "VPN" : f'iifname "{vpn}"',
        "OVPN": f'oifname "{vpn}"',
    }


def _pset(ports) -> str:
    """Format a collection of ports as an nftables set literal, e.g. ``{ 22, 80 }``."""
    return "{ " + ", ".join(str(p) for p in sorted(ports)) + " }"


def _normalize_intervals(elements: List[str]) -> List[str]:
    """Return sorted non-overlapping CIDR/IP intervals for nft interval sets."""
    networks = []
    passthrough = []
    for element in elements:
        raw = str(element).strip()
        if not raw:
            continue
        try:
            networks.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            passthrough.append(raw)
    collapsed = [str(net) for net in ipaddress.collapse_addresses(networks)]
    return sorted(set(collapsed + passthrough))


def _nexpr(networks: List[str]) -> str:
    """Format one or more CIDRs as an nftables network expression."""
    unique = _normalize_intervals(networks)
    if len(unique) == 1:
        return unique[0]
    return "{ " + ", ".join(unique) + " }"


def _emit_dynamic_set(lines: List[str], name: str, comment: str, elements: List[str]) -> None:
    """Append an interval ipv4_addr set with optional persisted elements."""
    a = lines.append
    a(f"    # {comment}")
    a(f"    set {name} {{")
    a("        type ipv4_addr; flags interval")
    if elements:
        a("        elements = { " + ", ".join(_normalize_intervals(elements)) + " }")
    a("    }")
    a("")


def _allowed_exposed_ports(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[Dict]:
    """Return exposed entries whose host port is explicitly allowed by config."""
    allowed_tcp = set(cfg.cosmos_public_ports)
    return [
        e for e in exposed_ports
        if e.get("proto", "tcp") == "tcp" and int(e["host_port"]) in allowed_tcp
    ]


def _build_header(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the comment header lines and ``flush ruleset`` directive."""
    L: List[str] = []
    a = L.append

    a("#!/usr/sbin/nft -f")
    a("")
    a("# +===================================================================+")
    a("# | NFT Firewall & VPN Killswitch — Modular Architecture             |")
    a("# | Full-tunnel | iptables:false | Dynamic sets | Watchdog-aware     |")
    a("# +===================================================================+")
    a(f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    a(f"# VPN       : {cfg.vpn_server_ip}:{cfg.vpn_server_port} -> {cfg.vpn_interface}")
    a(f"# Physical  : {cfg.phy_if} | LAN: {cfg.lan_net}")
    a(f"# SSH       : {cfg.ssh_port}")
    if cfg.torrent_port:
        a(f"# Torrent   : {cfg.torrent_port}")
    if cfg.extra_ports:
        a(f"# Extra     : {', '.join(map(str, cfg.extra_ports))}")
    if cfg.cosmos_tcp:
        a(f"# Cosmos-TCP: {', '.join(map(str, cfg.cosmos_tcp))}")
    if cfg.cosmos_udp:
        a(f"# Cosmos-UDP: {', '.join(map(str, cfg.cosmos_udp))}")
    a(f"# Plex      : {'yes' if cfg.allow_plex_lan else 'no'}")
    a(f"# Container supernet: {cfg.container_supernet}")
    docker_nets = _normalize_intervals(cfg.docker_networks or [cfg.container_supernet])
    a(f"# Docker networks: {', '.join(docker_nets)}")
    if cfg.cosmos_public_ports:
        a(f"# Cosmos public TCP: {', '.join(map(str, cfg.cosmos_public_ports))}")
    a(f"# Exposed ports ({len(exposed_ports)}):")
    for e in exposed_ports:
        a(f"#   host:{e['host_port']}/{e.get('proto', 'tcp')} "
          f"-> {e['container_ip']}:{e['container_port']}")
    if not exposed_ports:
        a("#   none")
    a("")
    a("# Docker has iptables:false — it NEVER touches these tables.")
    a("# Dynamic sets (blocked_ips, trusted_ips) survive nftables reload.")
    a("")
    a("flush ruleset")
    a("")
    return L


def _build_ipv6_killswitch() -> List[str]:
    """Return the ``table ip6 killswitch`` block that drops all IPv6 at priority -300.

    Priority -300 is more aggressive than -200 — it undercuts any hidden OS-default
    'allow' hooks that might be inserted at -200 by the kernel or other tools.
    """
    return [
        "# ===================================================================",
        "# IPv6 kill — priority -300, undercuts all other hooks.",
        "# Any IPv6 packet is silently dropped before any other rule can fire.",
        "# ===================================================================",
        "table ip6 killswitch {",
        "    chain input   { type filter hook input   priority -300; policy drop; }",
        "    chain output  { type filter hook output  priority -300; policy drop; }",
        "    chain forward { type filter hook forward priority -300; policy drop; }",
        "}",
        "",
    ]


def _build_nat_table(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the ``table ip nat`` block (prerouting DNAT + postrouting masquerade)."""
    iv = _iface_vars(cfg)
    OVPN = iv["OVPN"]
    docker_nets = cfg.docker_networks or [cfg.container_supernet]
    allowed_exposed = _allowed_exposed_ports(cfg, exposed_ports)

    L: List[str] = []
    a = L.append

    a("# ===================================================================")
    a("# NAT — we own this entirely (Docker has iptables:false).")
    a("# MASQUERADE only via wg0 — enforces VPN killswitch at NAT layer.")
    a("# ===================================================================")
    a("table ip nat {")
    a("")
    a("    chain prerouting {")
    a("        type nat hook prerouting priority dstnat; policy accept;")
    a("")

    if allowed_exposed:
        a("        # Explicitly allowed public container ingress only.")
        a("        # Docker published ports are ignored unless listed in firewall config.")
        for e in allowed_exposed:
            hp  = e["host_port"]
            cip = e["container_ip"]
            cp  = e["container_port"]
            pr  = e.get("proto", "tcp")
            src = e.get("src")
            if src:
                a(f"        {pr} dport {hp} ip saddr {src} dnat to {cip}:{cp}"
                  f"   # host:{hp} LAN-only -> {cip}:{cp}")
            else:
                a(f"        {pr} dport {hp} dnat to {cip}:{cp}"
                  f"   # host:{hp} -> {cip}:{cp}")
    else:
        a("        # No explicitly allowed public container ingress.")

    a("    }")
    a("")
    a("    chain postrouting {")
    a("        type nat hook postrouting priority srcnat; policy accept;")
    a("")
    a("        # Single supernet rule replaces 40+ Docker per-/28 rules.")
    a("        # Masquerade ONLY via wg0 — containers cannot leak via phy.")
    a(f"        ip saddr {_nexpr(docker_nets)} {OVPN} masquerade")
    a("    }")
    a("")
    a("}")
    a("")
    return L


def _build_filter_table(cfg: RulesetConfig, exposed_ports: List[Dict]) -> List[str]:
    """Return the ``table ip firewall`` block with sets and all three chains."""
    iv   = _iface_vars(cfg)
    PHY  = iv["PHY"]
    OPH  = iv["OPH"]
    VPN  = iv["VPN"]
    OVPN = iv["OVPN"]

    ssh = cfg.ssh_port

    vpn_tcp_in = {ssh}
    vpn_udp_in: set = set()
    if cfg.torrent_port:
        vpn_tcp_in.add(cfg.torrent_port)
        vpn_udp_in.add(cfg.torrent_port)
    for p in cfg.extra_ports:
        vpn_tcp_in.add(p)

    allowed_exposed = _allowed_exposed_ports(cfg, exposed_ports)

    exp_tcp_ports = sorted({e["host_port"] for e in allowed_exposed
                            if e.get("proto", "tcp") == "tcp"})
    exp_udp_ports = sorted({e["host_port"] for e in allowed_exposed
                            if e.get("proto", "tcp") == "udp"})
    lan_only_hp   = {e["host_port"] for e in allowed_exposed if e.get("src")}
    open_tcp      = [p for p in exp_tcp_ports if p not in lan_only_hp]
    open_udp      = [p for p in exp_udp_ports if p not in lan_only_hp]
    docker_nets   = cfg.docker_networks or [cfg.container_supernet]

    L: List[str] = []
    a = L.append

    a("# ===================================================================")
    a("# Main filter — INPUT / OUTPUT / FORWARD: policy drop on all three.")
    a("# Dynamic sets: blocked_ips and trusted_ips are runtime-editable.")
    a("# ===================================================================")
    a("table ip firewall {")
    a("")
    _emit_dynamic_set(
        L,
        "blocked_ips",
        "Runtime IP block list — persisted and preloaded after reload.",
        cfg.blocked_ips,
    )
    _emit_dynamic_set(
        L,
        "trusted_ips",
        "Trusted public admin IPs — SSH override from non-LAN addresses.",
        cfg.trusted_ips,
    )
    _emit_dynamic_set(
        L,
        "dk_ips",
        "DK GeoIP set — SSH allowed from Danish IPs.",
        cfg.dk_ips,
    )
    _emit_dynamic_set(
        L,
        "docker_nets",
        "Docker bridge networks — internal container networks.",
        docker_nets,
    )
    a("    # Bogon set — RFC-1918 ranges for anti-spoofing.")
    a("    set bogons {")
    a("        type ipv4_addr; flags interval")
    a("        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }")
    a("    }")
    a("")

    # ── INPUT ────────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # INPUT — default DROP.")
    a("    # ---------------------------------------------------------------")
    a("    chain input {")
    a("        type filter hook input priority filter; policy drop;")
    a("")
    a('        iifname "lo" accept')
    a("        ct state established,related accept")
    a("        ct state invalid drop")
    a("")
    a("        # Global block list (highest priority after connection tracking)")
    a("        ip saddr @blocked_ips drop")
    a("")
    a("        # Trusted admin IPs — SSH override (before LAN/VPN restriction)")
    a(f"        {PHY} ip saddr @trusted_ips tcp dport {ssh} accept"
      "   # admin SSH override")
    a("")
    a(f"        {PHY} ip saddr @bogons ip saddr != {cfg.lan_net} drop"
      "   # anti-spoofing (LAN excluded)")
    a("")
    a("        tcp flags == 0x0         drop  # NULL scan")
    a("        tcp flags == fin|psh|urg drop  # XMAS scan")
    a("        tcp flags == fin|syn     drop")
    a("        tcp flags == syn|rst     drop")
    a("")
    a("        ip protocol icmp icmp type echo-request \\")
    a("            limit rate 5/second burst 10 packets accept")
    a("        ip protocol icmp icmp type echo-request drop")
    a("        ip protocol icmp accept")
    a("")
    a(f"        # SSH: LAN + DK GeoIP on physical; DK GeoIP + trusted on VPN")
    a(f"        {PHY} ip saddr {cfg.lan_net} tcp dport {ssh} accept")
    a(f"        {PHY} ip saddr @dk_ips tcp dport {ssh} accept   # DK GeoIP")
    a(f"        {PHY} tcp dport {ssh} drop")
    a(f"        {VPN} ip saddr @trusted_ips tcp dport {ssh} accept   # trusted override")
    a(f"        {VPN} ip saddr @dk_ips tcp dport {ssh} accept   # DK GeoIP")
    a(f"        {VPN} tcp dport {ssh} drop")

    vpn_tcp_no_ssh = vpn_tcp_in - {ssh}
    if vpn_tcp_no_ssh:
        a(f"        {VPN} tcp dport {_pset(vpn_tcp_no_ssh)} accept")
    if vpn_udp_in:
        a(f"        {VPN} udp dport {_pset(vpn_udp_in)} accept")
    a("")

    if cfg.cosmos_tcp or cfg.cosmos_udp:
        a("        # Legacy host-bound Cosmos ports (--network host, no DNAT needed)")
        if cfg.cosmos_tcp:
            a(f"        tcp dport {_pset(cfg.cosmos_tcp)} accept"
              "   # Cosmos reverse proxy")
        if cfg.cosmos_udp:
            a(f"        udp dport {_pset(cfg.cosmos_udp)} accept"
              "   # Legacy UDP exposure")
        a("")

    if cfg.cosmos_public_ports:
        a("        # Cosmos Cloud reverse-proxy ingress (configured public TCP ports)")
        a(f"        {PHY} tcp dport {_pset(cfg.cosmos_public_ports)} accept")
        a("")

    if cfg.allow_plex_lan:
        a("        # Plex: direct LAN access (also via Cosmos proxy).")
        a("        # MUST be before the general LAN catch-all — otherwise the LAN")
        a("        # accept above would shadow this rule and the drop would never fire.")
        a(f"        {PHY} ip saddr {cfg.lan_net} tcp dport 32400 accept")
        a("        tcp dport 32400 drop   # block from internet/VPN")
        a("")

    a(f"        {PHY} ip saddr {cfg.lan_net} accept   # general LAN access (last positive rule)")
    a("")

    if open_tcp or open_udp:
        a("        # Published container ports (no src restriction)")
        if open_tcp:
            a(f"        tcp dport {_pset(open_tcp)} accept")
        if open_udp:
            a(f"        udp dport {_pset(open_udp)} accept")
        a("")

    a('        counter log prefix "[nft-in-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")

    # ── OUTPUT ───────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # OUTPUT — default DROP. Full-tunnel VPN killswitch.")
    a("    # Accept paths (ALL interface-pinned — no bare ct established,")
    a("    # no negative-match rules — every accept names its interface):")
    a('    #   1. oifname "lo"')
    a(f"    #   2. {OPH} udp dport 67              (DHCP broadcast + renewal)")
    a(f"    #   3. {OPH} meta mark {cfg.vpn_fwmark} ip daddr {cfg.vpn_server_ip}:{cfg.vpn_server_port}")
    a(f"    #      WG bootstrap — fwmark-locked: only the WireGuard kernel process")
    a(f"    #      marks packets with {cfg.vpn_fwmark}; no other process can use this hole.")
    a(f"    #   4. {OPH} ip daddr {cfg.lan_net}     (LAN stays local)")
    a("    #   5. meta oifkind \"bridge\" ip daddr @docker_nets  (host → containers via bridge only)")
    a(f"    #   6. oifname \"{cfg.vpn_interface}\"   (THE KILLSWITCH — sole internet path)")
    a("    # wg0 down → rule 6 never matches → total drop, no leak.")
    a("    # No ct established,related: stale conntrack cannot bypass the killswitch.")
    a("    # ---------------------------------------------------------------")
    a("    chain output {")
    a("        type filter hook output priority filter; policy drop;")
    a("")
    a('        oifname "lo" accept')
    a(f"        {OPH} udp dport 67 accept                              # DHCP broadcast + renewal")
    a("        ct state invalid drop")
    a("")
    a("        # Block outbound to blocked IPs (even if they were trusted)")
    a("        ip daddr @blocked_ips drop")
    a("")
    a(f"        {OPH} meta mark {cfg.vpn_fwmark} ip daddr {cfg.vpn_server_ip} udp dport {cfg.vpn_server_port} accept  # WG bootstrap — fwmark-locked")
    a(f"        {OPH} ip daddr {cfg.lan_net} accept                         # LAN stays local")
    a('        meta oifkind "bridge" ip daddr @docker_nets accept'
      "               # host → containers via bridge only")
    a(f"        {OVPN} accept                                        # KILLSWITCH")
    a("")
    a('        counter log prefix "[nft-out-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")

    # ── FORWARD ──────────────────────────────────────────────────────────────
    a("    # ---------------------------------------------------------------")
    a("    # FORWARD — default DROP.")
    a(f"    # 0. DROP ct new: container_supernet → {cfg.phy_if} (before conntrack).")
    a("    #    Scoped to ct state new so DNAT return traffic (established) still works.")
    a("    #    Prevents containers initiating connections to PHY; reply packets pass.")
    a("    # 1. ct established (covers DNAT return paths and all other legit flows)")
    a("    # 2. LAN-to-LAN (Plex discovery, local routing)")
    a("    # 3. Inter-container bridges (Cosmos /28 link networks)")
    a("    # 4. Container internet egress via wg0 only (killswitch)")
    a("    # 5. Inbound to published containers (post-DNAT)")
    a("    # ---------------------------------------------------------------")
    a("    chain forward {")
    a("        type filter hook forward priority filter; policy drop;")
    a("")
    a("        ct state invalid drop")
    a("")
    a(f"        # Prevents containers from initiating NEW connections via PHY.")
    a(f"        # Scoped to ct state new only — DNAT return traffic (established)")
    a(f"        # must be allowed through for inbound container services (e.g. Plex).")
    a(f"        # Without ct state new: reply packets from 172.16.x.x → enp88s0")
    a(f"        # are dropped before the ct established rule can accept them.")
    a(f"        ip saddr @docker_nets {OPH} ct state new drop"
      "  # containers cannot initiate PHY connections")
    a("")
    a("        ct state established,related accept")
    a("")
    a(f"        {PHY} {OPH} ip saddr {cfg.lan_net} ip daddr {cfg.lan_net} accept"
      "  # LAN-to-LAN")
    a("")
    a("        # Docker internal bridge traffic only between known container networks.")
    a('        meta iifkind "bridge" meta oifkind "bridge" '
      "ip saddr @docker_nets ip daddr @docker_nets accept")
    a("")
    a(f"        ip saddr @docker_nets {OVPN} accept  # container internet ONLY via VPN (killswitch)")
    a("")

    if cfg.cosmos_public_ports:
        a("        # Cosmos Cloud public reverse-proxy forwarding.")
        a(f"        {PHY} tcp dport {_pset(cfg.cosmos_public_ports)} "
          "ip daddr @docker_nets accept")
        a("")

    if allowed_exposed:
        a("        # Inbound to published containers (post-DNAT forwarding)")
        for e in allowed_exposed:
            cip = e["container_ip"]
            cp  = e["container_port"]
            pr  = e.get("proto", "tcp")
            src = e.get("src")
            if src:
                a(f"        ip saddr {src} {pr} dport {cp} ip daddr {cip} accept"
                  f"   # {e['host_port']}/{pr} [LAN-only] -> {cip}:{cp}")
            else:
                a(f"        {pr} dport {cp} ip daddr {cip} accept"
                  f"   # {e['host_port']}/{pr} -> {cip}:{cp}")
        a("")

    a('        counter log prefix "[nft-fwd-drop] " flags all limit rate 5/minute')
    a("    }")
    a("")
    a("}")
    return L


# ── Public API ────────────────────────────────────────────────────────────────

def generate_ruleset(cfg: RulesetConfig, exposed_ports: Optional[List[Dict]] = None) -> str:
    """Build the complete nftables ruleset as a single string.

    This function is pure — it performs no I/O and executes no subprocesses.
    The returned string is ready to be written to a file and loaded with
    ``nft -f``, or validated with ``nft -c -f``.

    Tables generated
    ----------------
    ``ip6 killswitch``
        Drops all IPv6 at priority -300, undercutting all other hooks.
    ``ip nat``
        Masquerade (VPN-only killswitch at NAT layer) + DNAT for exposed
        container ports.
    ``ip firewall``
        Default-drop INPUT/OUTPUT/FORWARD with dynamic ``blocked_ips``,
        ``trusted_ips``, ``dk_ips``, and ``bogons`` sets.

    Parameters
    ----------
    cfg:
        A :class:`RulesetConfig` describing the network topology, ports, and
        profile flags.
    exposed_ports:
        List of expose-registry dicts (as returned by
        ``integrations.docker.load_registry()``).  Defaults to ``[]``.

    Returns
    -------
    str
        The complete nftables ruleset, newline-terminated.
    """
    if exposed_ports is None:
        exposed_ports = []

    sections: List[List[str]] = [
        _build_header(cfg, exposed_ports),
        _build_ipv6_killswitch(),
        _build_nat_table(cfg, exposed_ports),
        _build_filter_table(cfg, exposed_ports),
    ]

    lines: List[str] = []
    for section in sections:
        lines.extend(section)

    return "\n".join(lines) + "\n"
