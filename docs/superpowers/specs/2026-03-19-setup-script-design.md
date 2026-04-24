# Setup Script Design
**Date:** 2026-03-19
**Project:** nft-firewall v10.0

## Goal

A single `setup.py` script that gets nft-firewall fully running on a new server with minimal user input. Auto-detects all network values, prompts only for what it can't find, simulates before touching anything live, and ends with all 3 services running and the status dashboard on screen.

## Constraints

- Requires `sudo` (root) to apply ruleset and install services
- Assumes Keybase is already installed and logged in on the server
- Assumes the server has an IPv4 address (the ruleset enforces an IPv6 killswitch — a warning is shown on dual-stack / IPv6-only systems before the confirmation gate)
- `linux_user` detection assumes `~/.config/keybase` is under the standard `$HOME` path; `XDG_CONFIG_HOME` overrides are not handled — user can correct the detected value
- Uses [Rich](https://github.com/Textualize/rich) for terminal UI — installed automatically by the script if absent

---

## Phases

### Phase 1 — Auto-detect (silent)

Probes the system and builds a candidate config dict. No output during this phase. Each value is tagged `detected` (confident), `guessed` (best-effort default), or `missing` (not found).

| Config key | Detection method |
|---|---|
| `phy_if` | `ip route get 1.1.1.1` → `dev` field. **Fallback:** if command fails (no default route), enumerate all non-loopback, non-`wg*` interfaces from `ip link show` and present as numbered list in Phase 2. |
| `lan_net` | IPv4 address + prefix of `phy_if` via `ip addr show <phy_if>` |
| `vpn_interface` | First `wg*` device from `ip link show`, default `wg0` |
| `vpn_server_ip` | `Endpoint` line in `/etc/wireguard/<vpn_interface>.conf` (uses detected interface name, not hardcoded `wg0`) |
| `vpn_server_port` | Same `Endpoint` line, port after `:` |
| `ssh_port` | `Port` line in `/etc/ssh/sshd_config`, default `22` |
| `linux_user` | First uid ≥ 1000 with `~/.config/keybase` present |

If `phy_if` has multiple candidates → numbered list in Phase 2.
If no IPv4 address is found on `phy_if` → tag `lan_net` as `missing` and display a yellow warning in Phase 2: "No IPv4 address found — this setup enforces IPv4-only operation and ALL IPv6 traffic will be dropped."

### Phase 2 — Review & fill gaps

Displays a Rich `Table` inside a `Panel` showing all detected values with color-coded status icons:
- `green ✓` — `detected`
- `yellow ?` — `guessed` (user should verify)
- `red ✗` — `missing` (must be provided)

If a value has multiple candidates, show a numbered list and user picks.

User presses Enter to accept a detected value or types a replacement. For guessed values, pressing Enter without input retains the displayed default. Prompts appear for `guessed` and `missing` values. The following fields always prompt (with detected value as default where available):

- `target_user` — authorized Keybase username for ChatOps (always manual)
- `linux_user` — confirm or override detected value
- `team` — Keybase team name (always manual)
- `channel` — Keybase channel, default `general` (always prompted with default)

Profile selector: numbered list, `cosmos-vpn-secure` pre-selected as default.

### Phase 3 — Write config & simulate

Writes the full `config/firewall.ini` to its real path (not a temp file — `src/main.py` has no alternate config path flag):

```ini
[network]
phy_if          = <value>
vpn_interface   = <value>
lan_net         = <value>
vpn_server_ip   = <value>
vpn_server_port = <value>
ssh_port        = <value>

[keybase]
target_user = <value>
linux_user  = <value>
team        = <value>
channel     = <value>
```

All 6 `[network]` keys and all 4 `[keybase]` keys are written explicitly.

Then runs with an animated Rich spinner:
```
python3 src/main.py simulate <profile>
```

Shows `✓ Ruleset valid` or prints the nft error in a red panel and exits cleanly. The `apply` command in Phase 4 also runs its own internal `nft --check` gate (`state.simulate_apply()`), providing a second safety net.

### Phase 4 — Apply (one confirmation)

Shows a Rich `Panel` summarising what is about to happen:
- Profile being applied
- Services being installed
- Packages to install (if any missing)
- IPv6 killswitch warning (if dual-stack detected in Phase 1)

Then a single prompt:
```
Apply ruleset and start all 3 services? [y/N]
```

If confirmed, runs these steps in order, each with a Rich spinner:

1. Install any missing packages: `apt-get install -y nftables python3 python3-pip wireguard-tools` then `pip3 install rich` if not already present
2. `python3 src/main.py apply <profile>`
3. Copy 3 service files → `/etc/systemd/system/`
4. `systemctl daemon-reload && systemctl enable --now nft-watchdog nft-listener nft-ssh-alert`
5. Print live output of `python3 src/main.py status` inside a Rich `Panel` titled `🛡️ Live Status`

---

## Visual Design

### Header (shown once at start)
Rich `Panel` with double border, cyan, bold:
```
╔══════════════════════════════════════╗
║   🛡️  NFT FIREWALL  SETUP  v10.0    ║
╚══════════════════════════════════════╝
```

### Step indicators
Rich `Rule` with step label at the start of each phase:
```
──────────────── Step 1/4 — Network Detection ────────────────
──────────────── Step 2/4 — Configuration Review ─────────────
──────────────── Step 3/4 — Simulate Ruleset ─────────────────
──────────────── Step 4/4 — Apply & Start Services ───────────
```

### Detection table (Phase 2)
Rich `Table` inside a `Panel`, two columns: key and `[color]icon  value`:
```
┌─ Detected Configuration ───────────────────┐
│  phy_if          │ ✓  enp88s0              │
│  lan_net         │ ✓  192.168.50.0/24      │
│  vpn_server_ip   │ ✓  185.236.203.98       │
│  vpn_server_port │ ✓  51820                │
│  ssh_port        │ ?  22  (default)        │
│  linux_user      │ ✓  nuc                  │
└────────────────────────────────────────────┘
```

### Spinners
Rich `Progress` with spinner column + task description for:
- simulate, apt install, pip install, ruleset apply, service install, systemctl enable

### Color coding
- `green` — detected / success
- `yellow` — guessed / warning
- `red` — error / missing
- `cyan` — section headers, banner
- `bold` — prompts, final result

### Final screen
Live output of `python3 src/main.py status` wrapped in a Rich `Panel` titled `🛡️ Live Status`. This is the last thing the user sees.

---

## Error handling

| Scenario | Behaviour |
|---|---|
| Script not run as root | Print red error panel and `sys.exit(1)` immediately |
| `config/` directory absent | Create it silently |
| `ip route get` fails (no default route) | Fall back to numbered interface list |
| No IPv4 on `phy_if` | Yellow warning, allow user to proceed or abort |
| `nft --check` fails in Phase 3 | Red error panel with full nft output, exit 1, `config/firewall.ini` left in place for debugging |
| `apt-get` fails | Red error panel, suggest manual install, exit 1 |
| `systemctl` fails | Print last 20 lines of `journalctl -u <service>` and exit 1 |
| User hits Ctrl-C | Clean exit with "Setup cancelled." message |

---

## File

**`setup.py`** — project root, next to `build.py`. Single file, ~350 lines.
