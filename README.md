# 🔥 NFT Firewall

![Linux](https://img.shields.io/badge/Linux-Debian%2012%20%7C%2013-blue)
![Firewall](https://img.shields.io/badge/Firewall-nftables-green)
![VPN](https://img.shields.io/badge/VPN-WireGuard-purple)
![Docker](https://img.shields.io/badge/Docker-iptables%20disabled-blue)
![Cosmos](https://img.shields.io/badge/Cosmos%20Cloud-hardened-orange)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![Release](https://img.shields.io/github/v/release/unknown0152/nft-firewall?include_prereleases&label=release)
![License](https://img.shields.io/github/license/unknown0152/nft-firewall)

Secure-by-default nftables firewall for Debian servers with WireGuard, Docker, and optional Cosmos Cloud hardening.

## Features

- nftables-only firewall
- WireGuard VPN killswitch
- Strict LAN mode by default
- Docker cannot open firewall holes
- Cosmos Cloud runs as non-root user `media`
- Public 80/443 ingress can be pinned to `wg0`
- Safe apply with rollback confirmation
- Runtime user separation: `fw-admin`, `media`, `backup`, `deploy`

## Warning

This installer changes firewall rules, Docker networking, systemd services, users, groups, and permissions.

Use on a fresh Debian server first. Keep SSH console access available.

## One-command install

```bash
curl -sSL https://raw.githubusercontent.com/unknown0152/nft-firewall/main/install.sh | sudo bash
