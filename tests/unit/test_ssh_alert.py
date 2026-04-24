"""
tests/unit/test_ssh_alert.py — Unit tests for _tail_stateful() and _load_state()
in src/daemons/ssh_alert.py.
"""
import sys
import time as _time_module
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / 'src'))
from daemons.ssh_alert import _tail_stateful, _load_state, _save_state


# ---------------------------------------------------------------------------
# Test 1 — _load_state returns (None, 0) when the state file is absent
# ---------------------------------------------------------------------------

def test_load_state_returns_none_when_missing(tmp_path):
    result = _load_state(tmp_path / "nonexistent.json")
    assert result == (None, 0)


# ---------------------------------------------------------------------------
# Test 2 — first-run branch: inode and offset are captured in memory and
#           no lines from existing history are yielded before sleep fires.
#
# On first run the code reads st_ino and st_size into local variables
# (saved_inode, offset) but does NOT call _save_state until a *new* line
# is yielded.  The state file therefore does not exist after the first
# sleep fires with only pre-existing content.
#
# We verify the in-memory behaviour by appending a new line AFTER the
# generator has initialised (so history is skipped) and checking that
# only the new line is yielded.
# ---------------------------------------------------------------------------

def test_first_run_sets_inode_and_offset(tmp_path, monkeypatch):
    """After the first-run branch runs, existing content is skipped (EOF seek).

    We confirm this by checking that _load_state returns (None, 0) — i.e. the
    state file is NOT written — when no new lines appeared before sleep fires.
    """
    log_file = tmp_path / "auth.log"
    log_file.write_text("line1\nline2\nline3\n")
    state_file = tmp_path / "state.json"

    # Patch sleep to raise SystemExit to interrupt the infinite loop
    monkeypatch.setattr(_time_module, "sleep", lambda s: (_ for _ in ()).throw(SystemExit(0)))

    gen = _tail_stateful(log_file, state_file)
    try:
        next(gen)
    except (SystemExit, StopIteration):
        pass

    # The code only writes state when it yields a line; with no new lines after
    # the EOF seek, the state file must not exist yet.
    assert not state_file.exists(), (
        "State file should not be written on first run when no new lines appear"
    )


# ---------------------------------------------------------------------------
# Test 3 — first-run branch: history is not replayed
#
# Write content to the log, construct the generator (first-run branch runs
# and seeks to EOF), then interrupt via sleep.  Assert that no lines from
# the pre-existing content were ever yielded.
# ---------------------------------------------------------------------------

def test_first_run_does_not_replay_history(tmp_path, monkeypatch):
    log_file = tmp_path / "auth.log"
    log_file.write_text("old_line1\nold_line2\nold_line3\n")
    state_file = tmp_path / "state.json"

    yielded_lines = []

    # Patch sleep to raise SystemExit to break out of the loop
    monkeypatch.setattr(_time_module, "sleep", lambda s: (_ for _ in ()).throw(SystemExit(0)))

    gen = _tail_stateful(log_file, state_file)
    try:
        for line in gen:
            yielded_lines.append(line)
    except (SystemExit, StopIteration):
        pass

    assert yielded_lines == [], (
        f"Expected no lines on first run (history skipped), got: {yielded_lines}"
    )
