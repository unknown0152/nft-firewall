# NFT Firewall

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
