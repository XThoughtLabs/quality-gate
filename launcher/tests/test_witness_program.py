"""The operator's witness, `xtl_witness.py` (LR-97, amendment 1 section 2 rule 1; LR-98 rule 5): its own tests on a
stand-in process table and a stand-in clock, written before the program. Each test is marked LR-97 or LR-98.

The stand-in table maps a process id to its creation time; `sid_of` gives each process's owner, None for one the
witness cannot read. Every SID here is a stand-in."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import launcher_world as W

OWN = "S-1-5-21-1111111111-2222222222-3333333333-1021"
EXEC = "S-1-5-21-1111111111-2222222222-3333333333-1007"
SECOND = 10_000_000
ANY_SID = re.compile(r"S-1-\d+(-\d+)+")
windows_only = pytest.mark.skipif(os.name != "nt", reason="the real process list exists on Windows only")


@pytest.fixture(scope="module")
def xw():
    import xtl_witness
    return xtl_witness


class Machine:
    """A stand-in process table, owners and clock."""

    def __init__(self):
        self.now = 1_000 * SECOND
        self.table: dict[int, int] = {}
        self.owners: dict[tuple[int, int], str | None] = {}
        self.calls: list[str] = []

    def add(self, pid, created, owner):
        self.table[pid] = created
        self.owners[(pid, created)] = owner

    def drop(self, pid):
        self.table.pop(pid, None)

    def clock(self):
        self.calls.append("clock")
        return self.now

    def processes(self):
        self.calls.append("table")
        return dict(self.table)

    def sid_of(self, pid, created):
        return self.owners.get((pid, created))


def make(xw, tmp_path, machine, **more):
    path = tmp_path / "w" / "witness.json"
    path.parent.mkdir(exist_ok=True)
    options = {"lifetime_seconds": 3600}
    options.update(more)
    return xw.Witness(str(path), OWN, table=machine.processes, sid_of=machine.sid_of, clock=machine.clock,
                      **options), path


def content(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.lr(97)
def test_witness_m_lists_only_its_own_users_processes(xw, tmp_path):
    m = Machine()
    m.add(100, 10 * SECOND, OWN)
    m.add(104, 11 * SECOND, EXEC)       # another user's: never
    m.add(108, 12 * SECOND, None)       # cannot be read: never
    m.add(112, 13 * SECOND, "S-1-5-18")
    w, path = make(xw, tmp_path, m)
    assert w.tick() is True
    assert content(path)["pairs"] == [[100, 10 * SECOND]]


@pytest.mark.lr(97)
def test_witness_m_a_process_it_could_not_read_is_listed_only_once_it_reads_it_as_its_own(xw, tmp_path):
    m = Machine()
    m.add(108, 12 * SECOND, None)
    m.add(116, 14 * SECOND, None)
    w, path = make(xw, tmp_path, m)
    w.tick()
    m.owners[(108, 12 * SECOND)] = OWN       # readable now
    m.owners[(116, 14 * SECOND)] = EXEC
    w.tick()
    assert content(path)["pairs"] == [[108, 12 * SECOND]]


@pytest.mark.lr(97)
def test_witness_keeps_the_history_of_exited_processes_and_tells_reused_ids_apart(xw, tmp_path):
    m = Machine()
    m.add(100, 10 * SECOND, OWN)
    w, path = make(xw, tmp_path, m)
    w.tick()
    m.drop(100)
    m.add(100, 20 * SECOND, EXEC)            # the id reused by another user
    m.now += SECOND
    w.tick()
    m.drop(100)
    m.add(100, 30 * SECOND, OWN)             # and again by the operator
    m.now += SECOND
    w.tick()
    assert content(path)["pairs"] == [[100, 10 * SECOND], [100, 30 * SECOND]]


@pytest.mark.lr(97)
def test_witness_n_the_file_holds_no_name_or_sid_only_its_four_fields(xw, tmp_path):
    m = Machine()
    m.add(100, 10 * SECOND, OWN)
    w, path = make(xw, tmp_path, m)
    w.tick()
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    assert set(data) == {"format", "started", "written", "pairs"}
    assert data["format"] == "xtl-witness/1"
    assert not ANY_SID.search(text)
    assert all(isinstance(x, int) for pair in data["pairs"] for x in pair)


@pytest.mark.lr(97)
def test_witness_the_write_time_is_read_before_the_list_is_taken(xw, tmp_path):
    m = Machine()
    w, path = make(xw, tmp_path, m)
    m.calls.clear()
    w.tick()
    assert m.calls.index("clock") < m.calls.index("table")
    assert content(path)["written"] == m.now


@pytest.mark.lr(97)
def test_witness_replaces_its_file_whole_and_leaves_no_temporary_file(xw, tmp_path):
    m = Machine()
    m.add(100, 10 * SECOND, OWN)
    w, path = make(xw, tmp_path, m)
    for i in range(5):
        m.now += SECOND
        w.tick()
    assert sorted(p.name for p in path.parent.iterdir()) == ["witness.json"]
    assert content(path)["written"] == m.now


@pytest.mark.lr(98)
def test_witness_s_stops_at_its_lifetime(xw, tmp_path):
    m = Machine()
    w, path = make(xw, tmp_path, m, lifetime_seconds=10)
    assert w.tick() is True
    m.now += 11 * SECOND
    assert w.tick() is False


@pytest.mark.lr(98)
def test_witness_stops_when_its_parent_is_gone(xw, tmp_path):
    m = Machine()
    m.add(500, 5 * SECOND, OWN)
    w, path = make(xw, tmp_path, m, parent=(500, 5 * SECOND))
    assert w.tick() is True
    m.drop(500)
    m.add(500, 6 * SECOND, OWN)              # the parent's id reused: still gone
    assert w.tick() is False


@pytest.mark.lr(97)
def test_witness_stops_rather_than_grow_past_its_bound(xw, tmp_path):
    m = Machine()
    for i in range(5):
        m.add(100 + 4 * i, (10 + i) * SECOND, OWN)
    w, path = make(xw, tmp_path, m, max_pairs=3)
    assert w.tick() is False


@pytest.mark.lr(97)
def test_witness_writes_at_most_every_quarter_second(xw, tmp_path):
    m = Machine()
    w, path = make(xw, tmp_path, m, lifetime_seconds=1)
    waits: list[float] = []

    def sleep(seconds):
        waits.append(seconds)
        m.now += int(seconds * SECOND)

    assert xw.run(w, sleep=sleep) == 0
    assert waits and min(waits) >= 0.25 and len(waits) <= 5


@pytest.mark.lr(97)
@windows_only
def test_witness_on_the_real_machine_lists_its_own_process_and_no_sid(xw, tmp_path):
    path = tmp_path / "real" / "witness.json"
    path.parent.mkdir()
    python = getattr(sys, "_base_executable", sys.executable)
    with W.quiet_audit():
        child = subprocess.Popen([python, "-I", str(Path(xw.__file__)), "--file", str(path),
                                  "--lifetime-seconds", "20"])
    try:
        deadline = time.time() + 15
        data = None
        while time.time() < deadline:
            try:
                data = content(path)
                if any(pair[0] == child.pid for pair in data["pairs"]):
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        assert data is not None and any(pair[0] == child.pid for pair in data["pairs"]), data
        assert any(pair[0] == os.getpid() for pair in data["pairs"]), "the witness did not list its own user's test"
        assert not ANY_SID.search(path.read_text(encoding="utf-8"))
    finally:
        child.kill()
        child.wait(timeout=10)

@pytest.mark.lr(97)
def test_witness_replaces_its_file_through_a_temporary_file_and_one_rename(xw, tmp_path, monkeypatch):
    m = Machine()
    m.add(100, 10 * SECOND, OWN)
    w, path = make(xw, tmp_path, m)
    calls = []
    real = xw.os.replace

    def replace(src, dst):
        calls.append((Path(src).name, Path(dst).name))
        return real(src, dst)

    monkeypatch.setattr(xw.os, "replace", replace)
    w.tick()
    assert len(calls) == 1 and calls[0][1] == "witness.json" and calls[0][0].endswith(".tmp")


@pytest.mark.lr(97)
@windows_only
def test_witness_on_the_real_machine_reads_an_owner_only_for_the_right_creation_time(xw):
    own, table, sid_of, clock = xw._windows()
    created = table()[os.getpid()]
    assert sid_of(os.getpid(), created) == own
    assert sid_of(os.getpid(), created + 1) is None  # the id reused by another process: not read as its own