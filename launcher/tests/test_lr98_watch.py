"""LR-98: the launcher's read-only watch (`xtl_launcher.py watch --minutes M`, probe 2 of amendments 1 and 2): what the
old rules and the new rules would flag, and the unjudged processes with their image names and times. Written before
the code; marked LR-98 and LR-97. A "minute" is shortened by the module's own constant; records are stand-ins."""

from __future__ import annotations

import os
import re

import pytest

from operator_kit import (OP_SID, ORPHAN_PID, StandInWitness, list_extra, orphan, stand_in_alive,
                          stand_in_end)

windows_only = pytest.mark.skipif(os.name != "nt", reason="the process list and the clock exist on Windows only")
ANY_SID = re.compile(r"S-1-\d+(-\d+)+")
SUMMARY = re.compile(r"WATCH DONE: flagged by the old rules (\d+), by the new rules (\d+), unjudged (\d+), "
                     r"passed as the operator's (\d+)")


@pytest.mark.lr(98)
@pytest.mark.lr(97)
@windows_only
def test_lr98_the_watch_reports_old_and_new_flags_and_the_unjudged_and_ends_nothing(world, launcher, monkeypatch,
                                                                                   tmp_path):
    world.seams.session_sid = OP_SID
    path = tmp_path / "witness" / "witness.json"
    world.set_config(witness_file=str(path))
    witness = StandInWitness(path, launcher.now_filetime).start()
    monkeypatch.setattr(launcher, "WATCH_MINUTE_SECONDS", 1.5)
    made: dict = {}

    def extra():  # the three appear after the watch has started, so they are new to it
        if not made:
            start = launcher.now_filetime()
            made["listed"] = orphan(ORPHAN_PID, start + 1, image="bash.exe")      # the operator's: old flags it
            made["alive"] = orphan(ORPHAN_PID + 4, start + 2, image="evil.exe")   # not listed, alive: both flag it
            made["gone"] = orphan(ORPHAN_PID + 8, start + 3, image="sleep.exe")   # not listed, gone: unjudged
            witness.pairs.add((made["listed"]["pid"], made["listed"]["created"]))
            return [made["listed"], made["alive"], made["gone"]]
        return [made["listed"], made["alive"]]

    list_extra(monkeypatch, launcher, extra)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True, ORPHAN_PID + 4: True, ORPHAN_PID + 8: False})
    ended = stand_in_end(monkeypatch, launcher, True)
    try:
        res = world.run("watch", "--minutes", "2")
    finally:
        witness.stop()
    assert res.code == 0, res.describe()
    found = SUMMARY.findall(res.stdout)
    assert found and tuple(int(x) for x in found[-1]) == (3, 1, 1, 1), res.describe()
    lines = res.stdout.splitlines()
    assert any("evil.exe" in ln and "old and new" in ln for ln in lines), res.describe()
    assert any("bash.exe" in ln and "operator" in ln and "old" in ln for ln in lines), res.describe()
    assert any("sleep.exe" in ln and "unjudged" in ln and re.search(r"\d{2}:\d{2}:\d{2}", ln) for ln in lines)
    assert ended == [], "the watch ended a process"
    assert res.requests == [], "the watch used the network"
    assert not world.ledger_file.exists(), "the watch wrote the ledger"
    assert not ANY_SID.search(res.stdout) and not ANY_SID.search(res.log_text)


@pytest.mark.lr(98)
def test_lr98_the_watch_needs_its_minutes(world):
    res = world.run("watch")
    assert res.code == 2 and res.last.startswith("CONFIG: "), res.describe()
