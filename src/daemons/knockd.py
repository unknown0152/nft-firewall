"""
src/daemons/knockd.py — Port-knock daemon for stealth SSH access.

Listens on a raw AF_PACKET socket for a configurable knock sequence.
When the correct sequence is received from an IP within the time window,
a temporary nftables rule is added to allow that IP to reach SSH.
The rule is automatically removed after open_ttl_seconds.

Only one rule is open at a time — a new successful knock immediately
revokes the previous rule before adding the new one.

Config ([knockd] section in firewall.ini):
    sequence          = 7000,8000,9000   # comma-separated UDP (or TCP) ports
    protocol          = udp              # udp or tcp
    window_seconds    = 10               # knock window
    open_ttl_seconds  = 30              # how long SSH stays open
"""
from __future__ import annotations

import configparser
import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class PortKnockDaemon:
    """Listens for a port-knock sequence and opens SSH temporarily."""

    def __init__(self, config_path: str) -> None:
        cfg = configparser.ConfigParser()
        cfg.read(config_path)

        # ── knockd defaults ──────────────────────────────────────────────
        seq_str = cfg.get("knockd", "sequence", fallback="7000,8000,9000")
        self._sequence: list[int] = [
            int(p.strip()) for p in seq_str.split(",")
        ]

        self._proto: str = cfg.get("knockd", "protocol", fallback="udp").lower()
        self._window: int = cfg.getint("knockd", "window_seconds", fallback=10)
        self._ttl: int = cfg.getint("knockd", "open_ttl_seconds", fallback=30)

        # ssh_port: knockd section first, then [network] ssh_port, then 22
        if cfg.has_option("knockd", "ssh_port"):
            self._ssh_port: int = cfg.getint("knockd", "ssh_port")
        elif cfg.has_option("network", "ssh_port"):
            self._ssh_port = cfg.getint("network", "ssh_port")
        else:
            self._ssh_port = 22

        # ── state ────────────────────────────────────────────────────────
        self._knock_state: Dict[str, List[Tuple[int, float]]] = {}
        self._active_rule: Optional[Tuple[str, str]] = None
        self._lock = threading.Lock()
        self._ttl_timer: Optional[threading.Timer] = None

        # ── logging ──────────────────────────────────────────────────────
        self._logger = logging.getLogger("nft-knockd")

    # ── public entry point ───────────────────────────────────────────────

    def run_daemon(self) -> None:
        """Main loop: sniff packets on a raw socket and process knocks."""
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)
        )
        sock.settimeout(1.0)
        self._log("Port-knock daemon started")
        try:
            while True:
                try:
                    raw = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                data = raw[0]
                # Ethernet frame: skip 14-byte header -> IP packet
                ip_data = data[14:]
                if len(ip_data) < 20:
                    continue

                # IP header
                ihl = (ip_data[0] & 0x0F) * 4
                proto = ip_data[9]  # 6=TCP, 17=UDP
                src_ip = socket.inet_ntoa(ip_data[12:16])

                # Protocol filter
                if self._proto == "udp" and proto != 17:
                    continue
                if self._proto == "tcp" and proto != 6:
                    continue

                transport = ip_data[ihl:]
                if len(transport) < 4:
                    continue
                dst_port = struct.unpack("!H", transport[2:4])[0]

                self._handle_knock(src_ip, dst_port)

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()
            self._log("Port-knock daemon stopped")

    # ── knock processing ─────────────────────────────────────────────────

    def _handle_knock(self, src_ip: str, dst_port: int) -> None:
        """Record a knock and check for sequence completion."""
        with self._lock:
            now = time.time()
            self._knock_state.setdefault(src_ip, [])

            # Prune entries older than the knock window
            cutoff = now - self._window
            self._knock_state[src_ip] = [
                (p, t) for p, t in self._knock_state[src_ip] if t >= cutoff
            ]

            # Record this knock
            self._knock_state[src_ip].append((dst_port, now))

            # Check if the last N ports match the sequence
            ports = [p for p, _ in self._knock_state[src_ip]]
            seq_len = len(self._sequence)
            if len(ports) >= seq_len and ports[-seq_len:] == self._sequence:
                self._open_for_ip(src_ip)
                self._knock_state[src_ip] = []

    # ── rule management ──────────────────────────────────────────────────

    def _open_for_ip(self, ip: str) -> None:
        """Open SSH for *ip*, revoking any previously active rule first."""
        # Revoke existing rule (only one open at a time)
        if self._active_rule is not None:
            if self._ttl_timer is not None:
                self._ttl_timer.cancel()
                self._ttl_timer = None
            self._revoke_rule(self._active_rule[1])
            self._active_rule = None

        # Add new rule
        try:
            handle = self._add_rule(ip)
        except RuntimeError as exc:
            self._log(f"ERROR: failed to add rule for {ip}: {exc}")
            return

        self._active_rule = (ip, handle)

        # Start TTL timer (daemon thread so it won't block exit)
        timer = threading.Timer(self._ttl, self._expire_rule, args=[ip, handle])
        timer.daemon = True
        timer.start()
        self._ttl_timer = timer

        self._log(f"Port-knock: opened SSH for {ip} (TTL={self._ttl}s, handle={handle})")

    def _add_rule(self, ip: str) -> str:
        """Add an nftables rule allowing *ip* to reach SSH; return rule handle."""
        cmd = [
            "nft", "--echo", "--json", "add", "rule", "ip", "firewall", "input",
            "ip", "saddr", ip, "tcp", "dport", str(self._ssh_port), "accept",
        ]
        cmd = self._privileged_nft(cmd)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError(f"nft add rule failed: {r.stderr.strip()}")
        data = json.loads(r.stdout)
        for entry in data.get("nftables", []):
            if "rule" in entry:
                return str(entry["rule"]["handle"])
        raise RuntimeError(f"Could not parse rule handle from nft output: {r.stdout!r}")

    def _revoke_rule(self, handle: str) -> None:
        """Best-effort deletion of an nftables rule by handle."""
        cmd = ["nft", "delete", "rule", "ip", "firewall", "input", "handle", handle]
        cmd = self._privileged_nft(cmd)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            self._log(f"WARN: revoke rule handle={handle} failed: {r.stderr.strip()}")
        else:
            self._log(f"Port-knock: revoked SSH rule handle={handle}")

    def _expire_rule(self, ip: str, handle: str) -> None:
        """TTL timer callback — revoke the rule if it is still the active one."""
        with self._lock:
            if self._active_rule == (ip, handle):
                self._revoke_rule(handle)
                self._active_rule = None
                self._log(f"Port-knock: TTL expired for {ip}, rule revoked")

    # ── helpers ──────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        print(f"[knockd] {msg}", flush=True)

    def _privileged_nft(self, cmd: List[str]) -> List[str]:
        """Route nft mutations through the installed sudo wrapper when needed."""
        if os.geteuid() == 0:
            return cmd
        wrapper = Path("/usr/local/lib/nft-firewall/fw-nft")
        if wrapper.exists():
            return ["sudo", str(wrapper)] + cmd[1:]
        return ["sudo"] + cmd
