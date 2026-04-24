## What does this change do?

<!-- One paragraph summary -->

## Does this touch firewall or SSH alert code?

<!-- If NO: delete the invariant section below and merge.
     If YES: fill in every field — PR will not be merged without it. -->

Files changed that require invariant review:
- [ ] `src/core/rules.py`
- [ ] `src/daemons/ssh_alert.py`
- [ ] `src/core/profiles.py`
- [ ] `src/core/state.py`
- [ ] systemd unit files

---

## Invariant checklist (required for firewall/ssh_alert changes)

See [`SECURITY_INVARIANTS.md`](../SECURITY_INVARIANTS.md) for full definitions.

### Which invariants does this change touch?

<!-- Tick every invariant your change affects, even if only to confirm it is preserved. -->

- [ ] **I-1** — Killswitch: internet exits via wg0 only
- [ ] **I-2** — Container PHY isolation: 172.16.0.0/12 never exits via enp88s0
- [ ] **I-3** — SSH access: LAN + DK GeoIP + trusted IPs only
- [ ] **I-4** — Plex LAN-only: port 32400 unreachable from internet
- [ ] **I-5** — IPv6 total blackout
- [ ] **I-6** — SSH alert cannot be permanently silenced by manual unblock

### For each ticked invariant, answer:

**Invariant:** <!-- e.g. I-2 -->
**How this change affects it:** <!-- e.g. "adds a new FORWARD rule above the container→PHY drop" -->
**Concrete failure if someone later mis-orders rules here:**
<!-- e.g. "inserting any accept rule for 172.16.0.0/12 above the drop would let containers
     reach enp88s0; stale conntrack would keep the flow alive for up to 5 days" -->

---

## Verification

Paste the output of the relevant checks from `SECURITY_INVARIANTS.md §Verification checklist`:

```
# paste nft list output or test results here
```

- [ ] `simulate` passed (`python3 src/main.py simulate cosmos-vpn-secure`)
- [ ] `apply` succeeded on a live box
- [ ] Killswitch test passed (curl timed out with wg0 down) ← required for I-1 changes
- [ ] FORWARD chain order confirmed (container→PHY drop before ct established) ← required for I-2 changes
