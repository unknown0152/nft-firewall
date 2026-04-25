# Hardening Pass — Design Spec
**Date:** 2026-04-25
**Scope:** Make nft-firewall safe to share with sysadmin friends (first public share)

---

## Goal

Three gaps block a confident first share:
1. Uninstall leaves live DROP rules in kernel memory — SSH lockout after uninstall.
2. `setup.py install` never validates the generated ruleset — syntax errors surface later at `fw safe-apply` with no context.
3. The `cosmos.enabled = false` ruleset path has not been audited against nftables v1.1.3.

This pass fixes all three, plus commits the DHCP `udp dport 67` syntax fix already made in dev.

---

## Change 1 — Commit and sync the DHCP fix

**What:** `src/core/rules.py:542` was changed from `udp sport 68 dport 67` to `udp sport 68 udp dport 67`. The matching test in `tests/unit/test_cosmos_secure.py` was updated. Both are staged in the dev tree but not committed or synced to `/opt/nft-firewall`.

**Action:** Commit the two changed files, push, then sync the installed copy so `fw safe-apply` works immediately.

---

## Change 2 — Fix uninstall lockout

**File:** `setup.py` → `cmd_uninstall()`

**Problem:** `cmd_uninstall()` stops systemd services and deletes files but never touches the live nftables ruleset. Kernel memory retains the DROP-policy tables indefinitely. After uninstall the box is unreachable via SSH.

**Fix:** At the very top of `cmd_uninstall()`, before any `systemctl stop`, flush the live ruleset:

```python
_run(["/usr/sbin/nft", "flush", "ruleset"], check=False)
_ok("nft flush ruleset — live rules cleared")
```

`check=False` so a failure (e.g. nft not running) doesn't abort the uninstall. The flush must come first so even a partially interrupted uninstall leaves the kernel in a safe (open) state.

**No fallback table needed:** flushing removes all tables and chains; kernel default is ACCEPT for all hooks with no tables loaded.

---

## Change 3 — `nft --check` pre-flight in `setup.py install`

**File:** `setup.py` → `cmd_install()`

**Problem:** Install syncs code and config but never validates the generated ruleset. Friends get a clean install then a confusing `[error] Ruleset syntax error` when they first run `fw safe-apply`.

**Fix:** Add a Step 2.5 after code sync, before systemd setup:

1. Import `generate_ruleset` and `_build_ruleset_config` from the freshly-installed `/opt/nft-firewall/src`.
2. Generate the ruleset for the configured profile.
3. Write it to a temp file and run `/usr/sbin/nft --check -f <tmpfile>`.
4. On failure: print the nft error, print the offending line, and `sys.exit(1)` — no systemd units are touched.
5. On success: print `✓ nft --check passed` and continue.

**Ordering dependency:** Step 0 (config wizard) runs before Step 2, so `firewall.ini` exists when the check runs. No ordering changes needed.

**Failure message** should include: the nft error text, the line number, and the suggestion to run `sudo python3 setup.py install --reconfigure` if the config looks wrong.

---

## Change 4 — Ruleset audit: `cosmos.enabled = false` path

**File:** `src/core/rules.py` (fixes if found), `tests/unit/` (new tests if gaps found)

**Method:**
1. Generate the ruleset for `cosmos.enabled = false` (no DNAT, no container ingress rules) using a representative `RulesetConfig`.
2. Write to a temp file and run `sudo nft --check -f` against the live nftables v1.1.3.
3. Fix any syntax errors found in `rules.py`.
4. Add a unit test for each fix so it cannot regress.

**Success criterion:** Both `cosmos-vpn-secure` (Cosmos enabled) and the no-Cosmos profile pass `nft --check` on nftables v1.1.3.

---

## Out of scope

- New `fw` subcommands or UX changes.
- nftables version detection in doctor.
- Full install → safe-apply → uninstall smoke test (no test machine available).
- Changes to data directories, users, or sudoers.

---

## Test coverage

- `test_output_dhcp_is_restricted_to_sport_68` — already updated, covers Change 1.
- New test: `test_no_cosmos_ruleset_has_no_dnat_rules` — covers Change 4 no-Cosmos path structurally.
- `nft --check` validation in Changes 3 and 4 runs against the live binary; unit tests cover structural properties, not binary syntax.
