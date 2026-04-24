# Security Invariants — nft-firewall

These are the properties that **must hold at all times** in the live ruleset.
Every change to `src/core/rules.py`, `src/daemons/ssh_alert.py`, or any systemd
unit file must be reviewed against this list.

Start every review from `sudo nft list ruleset` — not just the generator code.
The generator can produce a syntactically valid ruleset that silently violates an
invariant through rule ordering alone.

---

## I-1 — Killswitch: internet exits via wg0 only

**Rule:** OUTPUT policy DROP. The sole internet-bound accept is `oifname "wg0" accept`.

**Supporting constraints:**
- No `ct state established,related accept` in OUTPUT — stale conntrack cannot bypass the killswitch.
- The only PHY accept in OUTPUT is DHCP (`udp dport 67`) and the WireGuard bootstrap,
  which is fwmark-locked to `0xca6c` (set by the WireGuard kernel module; no userland
  process can set this mark without a raw socket and root — see I-1a below).

**I-1a — Bootstrap fwmark scope:** The bootstrap rule
`oifname "enp88s0" meta mark 0xca6c ip daddr <vpn_ip> udp dport <vpn_port> accept`
is intentionally root-only exploitable. If the host is fully compromised (root), all
bets are off. This is an accepted and documented residual risk.

**Breaks if:**
- Any `oifname "enp88s0" accept` is added to OUTPUT without fwmark + dst pinning.
- `ct state established,related accept` is inserted in OUTPUT for "convenience".
- A second MASQUERADE rule targeting enp88s0 is added to NAT postrouting.

---

## I-2 — Container PHY isolation: 172.16.0.0/12 never exits via enp88s0

**Rule:** FORWARD chain contains
`ip saddr 172.16.0.0/12 oifname "enp88s0" drop`
and this drop fires **before** `ct state established,related accept`.

**Why order matters:** If the drop comes after `ct established`, a container→PHY
flow established during a temporary rule-order mistake persists in conntrack until
timeout (~5 days for TCP ESTABLISHED), even after the mistake is corrected.

**Supporting constraints:**
- NAT postrouting MASQUERADE is on wg0 only — containers have no NAT path via enp88s0.
- The drop covers all of 172.16.0.0/12 regardless of which /28 bridge Docker creates.

**Critical scoping note:** The drop is `ct state new` only.
DNAT return traffic (e.g. Plex reply packets: `172.16.0.2 → LAN client via enp88s0`)
is `ct state established` and must reach the `ct established accept` rule below.
Removing `ct state new` makes the drop unconditional and silently breaks all
inbound DNAT container services (Plex, torrent, etc.) for LAN clients.

**Breaks if:**
- `ct state new` is removed from the drop, making it unconditional — DNAT return
  traffic is dropped and container services stop responding to LAN clients.
- Any rule is inserted above the container→PHY drop that accepts NEW traffic
  matching `ip saddr 172.16.0.0/12 oifname "enp88s0"`.
- A container is started on a subnet outside 172.16.0.0/12 (e.g. 10.x.x.x via kind/k3s) —
  that subnet is not covered and bypasses the drop entirely.

---

## I-3 — SSH access: LAN + DK GeoIP + trusted IPs only

**Rule:** Every accept path for the SSH port has an explicit `tcp dport {ssh} drop`
immediately after it.  The order on enp88s0 is:

1. `trusted_ips` accept  ← SSH override (before bogon check — see note)
2. bogon anti-spoof drop
3. LAN (`192.168.50.0/24`) accept
4. DK GeoIP accept
5. **explicit drop**

**Note on trusted_ips ordering:** The trusted_ips accept fires before the bogon
anti-spoof rule. This is intentional (admin override must work even during an attack)
but means `trusted_ips` must only ever contain routable WAN IPs.  Adding an RFC1918
address to `trusted_ips` would bypass anti-spoofing for that range.

**Breaks if:**
- A bare `tcp dport {ssh} accept` is added without interface or source pinning.
- The explicit drop after each accept group is removed or moved below a later accept.
- An RFC1918 address is added to `trusted_ips`.

---

## I-4 — Plex LAN-only: port 32400 unreachable from internet

**Rule:** In INPUT, the Plex LAN accept
`iifname "enp88s0" ip saddr 192.168.50.0/24 tcp dport 32400 accept`
must appear **before** the general LAN catch-all
`iifname "enp88s0" ip saddr 192.168.50.0/24 accept`.

The hard block `tcp dport 32400 drop` then denies all non-LAN sources.

**Why order matters (the bug we fixed 2026-03-21):** nftables first-match stops
evaluation at the LAN catch-all. If the Plex accept is below it, the specific rule
is dead code — the drop still works for internet sources, but the intent is broken
and any future refactor that re-orders around the drop would silently open port 32400
to the internet.

**Breaks if:**
- The Plex block is generated after the general LAN catch-all in `rules.py`.
- Any new rule `tcp dport 32400 accept` is added below the drop without LAN pinning.
- `allow_plex_lan` is set True but `cosmos_tcp` also includes 32400 (the Cosmos
  global accept fires before any port-specific logic and has no source restriction).

---

## I-5 — IPv6 total blackout

**Rule:** `table ip6 killswitch` with all three chains at priority `-300`, policy drop.
No IPv6 exceptions exist anywhere in the ruleset.

Priority -300 undercuts the kernel's default hooks and any OS-inserted ip6 rules.

**Breaks if:**
- Any tool (NetworkManager, Docker, a future kernel feature) inserts an ip6 table
  at priority higher than -300 with an accept policy.
- The priority is changed to -200 or lower (which some OS default hooks also use).

---

## I-6 — SSH alert cannot be permanently silenced by manual unblock

**Rule:** `SshAlertDaemon._auto_blocked` is a full-replace resync from the live
nftables `blocked_ips` set every `RESYNC_INTERVAL` seconds (default 300).

**Why this matters:** `!unblock <ip>` removes an IP from nftables but does not touch
the daemon's in-memory set. Without the resync, that IP is immune to auto-block for
the rest of the daemon's lifetime.

**Breaks if:**
- `RESYNC_INTERVAL` is set to 0 or a very large value.
- `_resync_loop` is changed from set-replace to set-update (update never removes IPs).
- The resync thread is removed from `run_daemon()`.

---

## Verification checklist (run after every ruleset change)

```bash
# 1. Validate syntax
sudo python3 src/main.py simulate cosmos-vpn-secure

# 2. Apply
sudo python3 src/main.py apply cosmos-vpn-secure

# 3. Confirm killswitch (wg0 down → curl must time out)
sudo wg-quick down wg0
curl --max-time 5 https://icanhazip.com && echo "LEAK" || echo "ok — blocked"
sudo wg-quick up wg0

# 4. Confirm container→PHY drop is before ct established
sudo nft list chain ip firewall forward | head -10
# Expected: "ip saddr 172.16.0.0/12 oifname ... drop" BEFORE "ct state established"

# 5. Confirm Plex rule order
sudo nft list chain ip firewall input | grep -A1 "32400"
# Expected: LAN accept for 32400 BEFORE "ip saddr 192.168.50.0/24 accept"

# 6. Confirm IPv6 blackout
sudo nft list table ip6 killswitch | grep "priority -300"
```
