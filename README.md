# NFT Firewall — V11.0 'Battle-Hardened'

> **Security Briefing — For Trusted Eyes Only**
>
> This is a production-grade Linux host firewall built on nftables.
> It enforces a full-tunnel WireGuard VPN killswitch, actively defends SSH,
> and sends real-time intelligence to your phone via Keybase.
> Everything is driven from a single Python CLI with zero external
> Python dependencies beyond the standard library.

---

## Table of Contents

1. [What This Is and Why It Exists](#1-what-this-is-and-why-it-exists)
2. [V11.0 — What's New (Battle-Hardened)](#2-v110--whats-new-battle-hardened)
3. [Installation on a New Server](#3-installation-on-a-new-server)
4. [Architecture Map](#4-architecture-map)
5. [Firewall Profiles](#5-firewall-profiles)
6. [Command Reference](#6-command-reference)
7. [Keybase ChatOps](#7-keybase-chatops)
8. [Active Defense — Two-Stage Auto-Block](#8-active-defense--two-stage-auto-block)
9. [Wall of Shame — `!top`](#9-wall-of-shame----top)
10. [Daily Report & Maintenance](#10-daily-report--maintenance)
11. [Emergency Procedures](#11-emergency-procedures)
12. [Backup & Recovery](#12-backup--recovery)
13. [Configuration Reference](#13-configuration-reference)

---

## 1. What This Is and Why It Exists

A standard Linux server with WireGuard installed can still leak traffic:
if the VPN tunnel goes down, the kernel's default routing will happily
send packets straight out the physical NIC.  This project fixes that at
the kernel level, not in userspace.

The core idea: set the OUTPUT chain policy to **DROP**.  The only way
a packet leaves the machine is through an explicit `accept` rule.  The
only rule that accepts general internet traffic names `wg0` (the WireGuard
interface).  If `wg0` is not up, that rule never matches, so everything
drops.  There is no race, no daemon to crash, no edge case.

Everything else — SSH defence, Keybase alerts, Docker NAT, WireGuard
health monitoring — is built on top of that hard guarantee.

### Core Capabilities

| Capability | Description |
|---|---|
| **VPN Killswitch** | nftables OUTPUT policy DROP — all internet traffic must exit via WireGuard or be dropped at the kernel level |
| **IPv6 Blackhole** | Separate `table ip6 killswitch` at priority −300 drops all IPv6 before it can reach any other hook |
| **Active Defense** | Two-stage SSH auto-block: fast attack (3 fails / 5 min) and slow-roll (10 fails / 1 hour) — both trigger an instant nftables ban and a phone alert |
| **Wall of Shame** | `!top` command shows attacking country leaderboard, most persistent IPs, and killswitch packet counters |
| **WireGuard Monitor** | Watchdog daemon detects stalls and dead handshakes — four escalating recovery levels, Keybase alert on every state change |
| **Keybase ChatOps** | Full two-way bot: send `!status`, `!block`, `!unblock`, `!top`, `!help` from your phone |
| **SSH Alerter** | Real-time notifications for logins, bans, unbans, and brute-force bursts |
| **Daily Report** | Morning dashboard pushed to Keybase at 08:00 with network, security, Docker, daemon, and system vitals |
| **Docker NAT** | nftables owns all DNAT/MASQUERADE — Docker runs with `iptables: false` and cannot poke holes in the firewall |
| **Self-Maintenance** | Auto-prunes state backups older than 30 days and rotated log files every morning |

---

## 2. V11.0 — What's New (Battle-Hardened)

### The Bootstrap Hole Is Now Identity-Locked

The hardest problem in a full-tunnel killswitch is the chicken-and-egg
moment at startup: WireGuard needs to send its UDP handshake packets to
the VPN server *before* the tunnel is up, but the OUTPUT chain blocks all
outbound traffic that does not go through `wg0`.

The V11.0 solution uses the kernel's `fwmark` mechanism.  When `wg-quick`
sets up the WireGuard interface, it instructs the kernel to mark every
encrypted WireGuard UDP packet with the value `0xca6c` (decimal 51820 —
the standard WireGuard port, used as the mark by convention).  This mark
is set *inside the kernel*, by the WireGuard module, after the packet is
already encrypted.  No userspace process can forge it.

The OUTPUT bootstrap rule therefore reads:

```
oifname "eth0"  meta mark 0xca6c  ip daddr <vpn-server>  udp dport <vpn-port>  accept
```

Breaking that down:
- `oifname "eth0"` — must be going out the physical NIC (not a loop or VPN)
- `meta mark 0xca6c` — **must carry the WireGuard kernel mark** — closes the hole to all other processes
- `ip daddr <vpn-server>` — must be addressed to exactly your VPN endpoint
- `udp dport <vpn-port>` — must be the correct UDP port

All four conditions must match simultaneously.  A rogue process trying to
use this hole to bypass the killswitch cannot set `meta mark 0xca6c` —
only the WireGuard kernel module can do that.  The bootstrap hole is
identity-locked to the WireGuard process itself.

### Two-Stage Active Defense

Previous versions had one auto-block trigger (fast attack only).
V11.0 adds a **second, independent slow-roll window**:

| Window | Threshold | Trigger |
|---|---|---|
| **Short** | 3 failures in 5 minutes | Fast brute-force detected |
| **Long** | 10 failures in 1 hour | Patient slow-roll attacker |

Both windows run simultaneously in the SSH alerter.  Either one can
trigger an immediate `block <IP>` command and a 🚨 AUTO-BANNED phone alert
naming which window fired.  IPs blocked via the long window are also
written to `state/persistent_ips.json` and appear in the Wall of Shame.

### Wall of Shame (`!top`)

New `!top` command available from your Keybase chat:

```
🏆 Wall of Shame
━━━━━━━━━━━━━━━━━━━━

🚩 Top Attacking Countries  _47 IP(s) in block list_
    1.  🇨🇳 China — 19 IPs
    2.  🇷🇺 Russia — 8 IPs
    3.  🇺🇸 United States — 6 IPs
    4.  🇳🇱 Netherlands — 4 IPs
    5.  🇩🇪 Germany — 3 IPs

🕐 Most Persistent Attackers  _(slow-roll: 10+ hits in 1h)_
    1.  `1.2.3.4`  Shanghai, CN  — 14 hits  _2026-03-15 03:17_
    2.  `5.6.7.8`  Moscow, RU    — 11 hits  _2026-03-14 22:44_

🛑 Killswitch Packets Denied
    Total: 1,284,991 packets
    Input:   892,445
    Output:   201,038
    Forward:  191,508

📊 Weekly Auto-Blocks  📈
    This week:  12
    Last week:  7
```

### Positive-Match-Only Interface Rules

All interface rules throughout the ruleset now use **positive matches
only** (`iifname "eth0"`, `oifname "wg0"`) — never negative matches
(`iifname != "eth0"`).  Negative interface rules are dangerous because
adding a new interface (e.g. another Docker bridge or a second VPN)
can silently make a negative rule match more traffic than intended.
Every `accept` rule in V11.0 names exactly which interface it trusts.

### IPv6 Kill at Priority −300

The IPv6 killswitch table runs at hook priority `−300`, more aggressive
than the `−200` used in V10.x.  This undercuts any kernel or tool-inserted
accept hooks that might fire at `−200`, ensuring IPv6 is dropped before
any other rule can fire.

### Packet Counters on All Drop Rules

Every `log prefix ... drop` rule in INPUT, OUTPUT, and FORWARD now
includes a `counter` statement.  This is what feeds the killswitch packet
statistics in `!top` and the daily dashboard.

---

## 3. Installation on a New Server

### Step 1 — Prepare users and copy the project

```bash
# Optional base user bootstrap on the NEW server
sudo bash setup.sh

# Copy or clone nft-firewall as the human admin/dev user
sudo -u nuc git clone <repo-url> /home/nuc/nft-firewall
cd /home/nuc/nft-firewall

# Or, from an old server, create and transfer a portable archive as nuc
sudo -u nuc bash /home/nuc/nft-firewall/backup_firewall.sh
scp /home/nuc/backups/nft-firewall-*.tar.gz user@NEW_SERVER:/tmp/
```

### Step 2 — Install the firewall

```bash
cd /home/nuc/nft-firewall
sudo python3 setup.py install
```

The installer keeps a strict user model:

| User | Purpose |
|---|---|
| `nuc` | Human admin/dev user; owns the working copy and may be in `docker` for convenience |
| `fw-admin` | nft-firewall runtime/systemd user; owns `/opt/nft-firewall`, `/var/lib/nft-firewall`, `/var/log/nft-firewall`, and `/etc/nft-firewall`; not in `docker` |
| `media` | Docker/Cosmos/compose runtime user; owns `/home/media/compose` |
| `backup` | Backup user |
| `deploy` | rsync/deploy user |

The installer writes least-privilege sudo wrappers for `fw-admin`. It does
not grant broad wildcard sudo and does not put `fw-admin` in the Docker group.

### Step 3 — Run Cosmos compose as media

```bash
sudo -u media mkdir -p /home/media/compose/cosmos
cd /home/media/compose/cosmos
sudo -u media docker compose up -d
```

Cosmos/Docker files belong under `/home/media/compose/cosmos`, not under
`/home/nuc` and not under `/opt/nft-firewall`.

### Step 4 — Enable the daily report timer

```bash
sudo systemctl enable --now nft-daily-report.timer
systemctl status nft-daily-report.timer
```

### What you do NOT need to change

If your new server uses the same WireGuard config and Keybase account, the
wizard detects everything automatically.  The only values that differ
between machines are `phy_if` (NIC name) and `lan_net` (subnet) — both
are auto-detected.

---

## 4. Architecture Map

```
nft-firewall/
├── src/
│   ├── main.py                   ← Single CLI entry point for all commands
│   │
│   ├── core/
│   │   ├── rules.py              ← Pure ruleset generator (returns nft text, no side-effects)
│   │   ├── state.py              ← Apply / backup / restore / block / allow live set operations
│   │   └── profiles.py           ← Named firewall profiles (cosmos-vpn-secure, media-vpn, vpn-only)
│   │
│   ├── daemons/
│   │   ├── watchdog.py           ← WireGuard health monitor + 4-level VPN recovery daemon
│   │   ├── listener.py           ← Keybase ChatOps bot (listens for !commands)
│   │   └── ssh_alert.py          ← SSH intrusion alerter + two-stage Active Defense
│   │
│   ├── integrations/
│   │   └── docker.py             ← Container port expose registry + nftables DNAT management
│   │
│   └── utils/
│       ├── formatter.py          ← Builds the mobile-friendly vertical status dashboard
│       ├── keybase.py            ← Shared Keybase notification helper (team + DM routing)
│       └── analytics.py          ← Wall of Shame data: GeoIP leaderboard, packet counters, persistent IPs
│
├── config/
│   ├── firewall.ini              ← (gitignored) your real config with actual IPs and ports
│   └── firewall.ini.example      ← sanitised template — safe to commit
│
├── state/                        ← (gitignored) live ruleset backups + daemon state
│
├── tests/                        ← Unit test suite
├── setup.py                      ← Interactive setup wizard
├── backup_firewall.sh            ← Full project archive script
└── README.md                     ← This file
```

### Module Roles

| File | Role |
|---|---|
| `core/rules.py` | Pure function: `RulesetConfig` + exposed ports → nft ruleset string.  No system calls, no I/O. |
| `core/state.py` | All system mutations: `nft -f`, `nft set add`, backups, restores, conntrack flush. |
| `core/profiles.py` | Defines which Cosmos TCP/UDP ports and Plex LAN access each named profile opens. |
| `daemons/watchdog.py` | Polls WireGuard handshake age every 30 s.  Four escalating recovery levels.  Keybase alert on every state change. |
| `daemons/listener.py` | Long-polls Keybase API.  Dispatches `!status`, `!block`, `!unblock`, `!ip-list`, `!top`, `!help`. |
| `daemons/ssh_alert.py` | Tails `fail2ban.log` and `auth.log` with logrotate-safe stateful tailers.  Two-stage auto-block. |
| `integrations/docker.py` | Maintains a JSON registry of exposed ports.  `apply` reads it to generate DNAT rules. |
| `utils/formatter.py` | Builds the dashboard string: Network → Security → Docker → Daemons → System vitals. |
| `utils/keybase.py` | Routes notifications to a team channel or DM.  Handles `sudo -u` escalation and retries. |
| `utils/analytics.py` | GeoIP batch resolver, country leaderboard, persistent attacker log, packet counter reader. |

---

## 5. Firewall Profiles

| Profile | Description | Use Case |
|---|---|---|
| `cosmos-vpn-secure` | Cosmos Cloud + full-tunnel VPN killswitch | **Primary profile** — all internet via WireGuard |
| `media-vpn` | Media stack + VPN killswitch + Cosmos proxy | Media server with VPN protection |
| `vpn-only` | Pure VPN killswitch — no Cosmos, nothing extra | Minimal / testing |

```bash
# Validate syntax first (no root required)
python3 src/main.py simulate cosmos-vpn-secure

# Apply with a 60-second rollback window
sudo python3 src/main.py apply cosmos-vpn-secure --safe
# Type CONFIRM to keep, or wait 60s to auto-rollback

# Apply immediately
sudo python3 src/main.py apply cosmos-vpn-secure
```

---

## 6. Command Reference

All commands: `sudo python3 src/main.py <command>`
(`simulate`, `profiles`, `status` do not require root)

### Ruleset Management

| Command | Root | Description |
|---|---|---|
| `apply <profile>` | ✓ | Generate and apply a firewall profile |
| `apply <profile> --dry-run` | ✓ | Print the generated nft ruleset without applying |
| `apply <profile> --safe` | ✓ | Apply with 60s rollback window — type `CONFIRM` to keep |
| `simulate <profile>` | — | Validate syntax with `nft --check` (never applies) |
| `backup` | ✓ | Snapshot current live ruleset to `state/` |
| `restore [FILE]` | ✓ | Restore from `state/` — latest if no file given |
| `rules` | ✓ | Print the full live nftables ruleset |
| `profiles` | — | List all available profiles |

### IP Set Management

| Command | Root | Description |
|---|---|---|
| `block <ip/cidr>` | ✓ | Add to `blocked_ips` — drops all traffic from this IP immediately |
| `unblock <ip/cidr>` | ✓ | Remove from `blocked_ips` |
| `allow <ip>` | ✓ | Add to `trusted_ips` — permits SSH from non-LAN addresses |
| `disallow <ip>` | ✓ | Remove from `trusted_ips` |
| `ip-list` | ✓ | Show all blocked and trusted IPs |

### Docker Port Exposure

| Command | Root | Description |
|---|---|---|
| `docker-expose <host_port> <container_ip> <container_port> [proto] [--src CIDR]` | ✓ | Register a DNAT rule (persists across `apply`) |
| `docker-unexpose <host_port> [proto]` | ✓ | Remove a DNAT rule |
| `list-exposed` | — | Show the full port exposure registry |

### Monitoring & Health

| Command | Root | Description |
|---|---|---|
| `status` | — | Print the vertical mobile dashboard to stdout |
| `health` | — | JSON health report — exit 0 healthy, exit 1 degraded |
| `firewall-report` | ✓ | Build dashboard and push to Keybase |
| `maintenance` | ✓ | Prune state backups >30 days and rotated log files |
| `keybase-test` | ✓ | Send a test notification to verify Keybase config |

### Daemon Control

| Command | Root | Description |
|---|---|---|
| `watchdog daemon` | ✓ | Start the WireGuard health monitor (systemd ExecStart) |
| `watchdog status` | ✓ | One-shot human-readable watchdog status |
| `watchdog health` | ✓ | One-shot JSON health report |
| `listener daemon` | ✓ | Start the Keybase ChatOps bot (systemd ExecStart) |
| `ssh-alert daemon` | ✓ | Start the SSH intrusion alerter (systemd ExecStart) |

---

## 7. Keybase ChatOps

The listener daemon watches your configured team channel for commands.
Send these from your phone to control the firewall remotely:

| Command | What it does |
|---|---|
| `!status` | Pushes the full vertical dashboard to the channel |
| `!block 1.2.3.4` | Immediately blocks an IP in nftables |
| `!unblock 1.2.3.4` | Removes an IP from the block list |
| `!ip-list` | Shows all blocked and trusted IPs |
| `!top` | Wall of Shame: attacking countries, persistent IPs, packet counters |
| `!help` | Lists all available commands |

### Automatic Notifications

| Alert | Trigger |
|---|---|
| 🚨 **AUTO-BANNED (5-min)** | 3 SSH failures from one IP within 5 minutes |
| 🚨 **AUTO-BANNED (1-hour)** | 10 SSH failures from one IP within 1 hour |
| ⚠️ **SSH Brute-force** | 5+ failures from one IP (30-min throttle) |
| 🔑 **SSH Login** | Successful SSH authentication |
| 🚫 **SSH Ban** | fail2ban bans an IP |
| 🔓 **SSH Unban** | fail2ban unbans an IP |
| 🔴 **VPN Down** | WireGuard handshake lost / tunnel dead |
| 🟢 **VPN Recovered** | Tunnel restored after an outage |
| ⚠️ **VPN Stall** | Handshake stale >5.5 min without full loss |
| ☀️ **Daily Report** | Full dashboard at 08:00 every morning |

---

## 8. Active Defense — Two-Stage Auto-Block

The SSH alerter implements two independent sliding-window block triggers,
completely separate from fail2ban:

```
Failed SSH attempts from a non-private IP
   │
   ├─ SHORT WINDOW: 3 failures in any 5-minute window
   │       └─ IP not already blocked this session
   │              ↓
   │      python3 src/main.py block <IP>     ← instant nftables drop
   │      🚨 AUTO-BANNED (5-min) → Keybase   ← phone alert
   │
   └─ LONG WINDOW: 10 failures in any 1-hour window
           └─ IP not already blocked this session
                  ↓
          python3 src/main.py block <IP>     ← instant nftables drop
          🚨 AUTO-BANNED (1-hour) → Keybase  ← phone alert
          log_persistent_ip() → state/       ← recorded in Wall of Shame
```

**Thresholds** (in `src/daemons/ssh_alert.py`):

| Constant | Default | Meaning |
|---|---|---|
| `AUTO_BLOCK_THRESHOLD` | `3` | Failures to trigger the short-window block |
| `AUTO_BLOCK_WINDOW` | `300` | Short sliding window in seconds (5 min) |
| `LONG_BLOCK_THRESHOLD` | `10` | Failures to trigger the long-window block |
| `LONG_BLOCK_WINDOW` | `3600` | Long sliding window in seconds (1 hour) |
| `ATTEMPT_THRESHOLD` | `5` | Failures for a ⚠️ brute-force notification |
| `ATTEMPT_THROTTLE` | `1800` | Minimum seconds between brute-force alerts per IP |

**Private IPs are never auto-blocked** — RFC-1918 ranges (`10.x`,
`172.16–31.x`, `192.168.x`) and loopback are always exempt.

**Daemon restart safety** — at startup, the daemon reads the live
`nft list set ip firewall blocked_ips` and pre-populates its internal
`_auto_blocked` set.  A daemon restart cannot re-issue a `block` command
for an IP the firewall already knows about.

---

## 9. Wall of Shame — `!top`

Send `!top` from Keybase to get a full threat intelligence snapshot:

- **Top Attacking Countries** — GeoIP leaderboard of all IPs currently in
  the `blocked_ips` set, resolved in batch via ip-api.com, cached for 24 h.
- **Most Persistent Attackers** — IPs that triggered the 1-hour slow-roll
  window, sorted by hit count, stored in `state/persistent_ips.json`.
- **Killswitch Packets Denied** — live `counter packets` values from the
  log/drop rules in INPUT, OUTPUT, and FORWARD (requires V11.0 ruleset).
- **Weekly Auto-Blocks** — this week vs. last week, with trend arrow.

---

## 10. Daily Report & Maintenance

### Morning Report

Sent to Keybase at **08:00** every day:

```
☀️ Good Morning  Sat, 21 Mar · 08:00
━━━━━━━━━━━━━━━━━━━━
🟢 HEALTHY
━━━━━━━━━━━━━━━━━━━━

🌐  Network
    📡  VPN  🟢 203.0.113.x
    🤝  Handshake  🟢 22s ago

🔒  Security
    🛡️  Killswitch  🟢 Active
    📋  NFT Rules  🟢 Intact
    🚫  Blocked IPs  47
    🏆  Top Attacker  🇨🇳 CN (19)
    🛑  Dropped pkts  1,284,991

🐳  Docker  🟢 6 running
    📦  Exposed
    🏠  32400/tcp  LAN
    🌍  9653/tcp   public

⚙️  Daemons
    🟢  Watchdog
    🟢  Listener
    🟢  SSH Alert

🖥️  System
    ⚡  CPU  0.48, 0.42, 0.46
    🧠  RAM  5.0GB / 62.5GB
    💾  Disk  / is 13% full
```

### Systemd Units

| Unit | Type | Schedule |
|---|---|---|
| `nft-watchdog.service` | daemon | always running |
| `nft-listener.service` | daemon | always running |
| `nft-ssh-alert.service` | daemon | always running |
| `nft-daily-report.timer` | timer | fires at 08:00 daily |
| `nft-daily-report.service` | oneshot | triggered by the timer |

The daily service runs two commands in sequence:

```ini
ExecStart     = python3 src/main.py firewall-report   # send morning report
ExecStartPost = python3 src/main.py maintenance        # then prune old files
```

### Self-Maintenance

`maintenance` removes:
- `state/nftables_*.conf` backups older than **30 days**
- `*.log.1`, `*.log.2`, `*.log.gz`, `*.log.*.gz` rotated log files

---

## 11. Emergency Procedures

### Stop All Daemons

```bash
sudo systemctl stop nft-watchdog nft-listener nft-ssh-alert
```

### Flush All Firewall Rules (Open Mode)

> **Warning:** This removes all nftables rules and leaves the machine fully open.
> Use only if you are locked out or need to debug connectivity.

```bash
sudo nft flush ruleset
```

### Restore Last Known-Good Ruleset

```bash
# Restore the most recent backup automatically
sudo python3 src/main.py restore

# Restore a specific snapshot
sudo python3 src/main.py restore state/nftables_20260321_080000.conf
```

### Re-Apply from Scratch

```bash
sudo python3 src/main.py apply cosmos-vpn-secure
```

### Unblock a Locked-Out IP

```bash
# From the server console
sudo python3 src/main.py unblock 1.2.3.4

# From Keybase on your phone
!unblock 1.2.3.4
```

### Bring WireGuard Back Up Manually

```bash
sudo wg-quick up wg0
# The watchdog detects recovery and sends a 🟢 VPN Recovered alert
```

### View Live Daemon Logs

```bash
sudo journalctl -u nft-watchdog  -f
sudo journalctl -u nft-ssh-alert -f
sudo journalctl -u nft-listener  -f
sudo journalctl -u nft-daily-report -n 50
```

---

## 12. Backup & Recovery

### Full Project Archive

```bash
sudo bash backup_firewall.sh
# → /home/nuc/backups/nft-firewall-YYYY-MM-DD_HHMMSS.tar.gz
```

The archive excludes `.git`, `__pycache__`, `state/`, `.backups/`, and `dist/`.

### Snapshot the Live Ruleset

```bash
sudo python3 src/main.py backup
# → state/nftables_YYYYMMDD_HHMMSS.conf
```

### Validate Before Applying

```bash
python3 src/main.py simulate cosmos-vpn-secure
# [ok] Ruleset for profile 'cosmos-vpn-secure' is valid (nft --check passed).
```

---

## 13. Configuration Reference

`config/firewall.ini` — single source of truth for network topology.
See `config/firewall.ini.example` for a fully documented template.

```ini
[network]
phy_if          = <your-nic>          # Physical NIC (run: ip link show)
vpn_interface   = wg0                 # WireGuard tunnel interface
lan_net         = <your-lan-cidr>     # e.g. 192.168.1.0/24
vpn_server_ip   = <vpn-endpoint-ip>   # WireGuard server public IP
vpn_server_port = <vpn-port>          # WireGuard UDP port
ssh_port        = <ssh-port>          # Must match sshd_config Port
extra_ports     = <port>[,<port>]     # Extra TCP ports on VPN interface
torrent_port    = <port>              # BitTorrent TCP+UDP (optional)

[keybase]
target_user     = <keybase-username>  # DM fallback
linux_user      = <linux-username>    # User running Keybase daemon
team            = <team-name>         # Keybase team for alerts
channel         = general             # Channel within the team
```

### Changing the SSH Port

Edit `ssh_port` in `firewall.ini`, then re-apply:

```bash
sudo python3 src/main.py apply cosmos-vpn-secure
```

### Adding an Extra Open Port

Append to `extra_ports` (comma-separated), then re-apply:

```ini
extra_ports = 8096, 9090
```

### Adding a Docker Port Exposure

```bash
# Expose host port 8096 → container 172.17.0.5:8096, LAN-only
sudo python3 src/main.py docker-expose 8096 172.17.0.5 8096 tcp --src 192.168.1.0/24

# Re-apply to load the new DNAT rule into the live ruleset
sudo python3 src/main.py apply cosmos-vpn-secure
```

---

> **V11.0 'Battle-Hardened'** — identity-locked bootstrap hole, two-stage
> active defence, Wall of Shame intelligence, and positive-match-only
> interface rules throughout.  Killswitch proven leak-proof under live
> test — zero packets via physical NIC when the tunnel is down.
