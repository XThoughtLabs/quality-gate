"""LR-97: the launcher knows its operator (the user of its own session) and trusts the operator's witness only after
its checks (HQ-TASK-M1-C2S section 4, tests a to g, with rule 2 replaced by amendment 1: tests h to n on the launcher's
side). Written from the tasks before the code; each test is marked LR-97.

The witness here is a stand-in thread that writes the file of amendment 1 section 2 rule 1; its security is the
world's seam `witness_security`, and the operator is the seam `session_user_sid`. Processes of unknown owner are
stand-in records (run 1's orphaned sleep.exe); `end_process` and `process_alive` are stand-ins for them."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
import os
import re
import time

import pytest

import launcher_world as W
from operator_kit import (ADMINS_SID, FULL, OP_SID, ORPHAN_PID, OWN_STRAY_PID, READ_EXECUTE, SECOND, SYSTEM_SID,
                          WITNESS_FORMAT, StandInWitness, list_extra, once, orphan, own_stray, right_acl,
                          stand_in_alive, stand_in_end, watch_model)
from stage_a_kit import msg, spec

windows_only = pytest.mark.skipif(os.name != "nt", reason="the process list and the clock exist on Windows only")
STAY = {"op": "pause", "seconds": 60}
NO_OPERATOR = "operator not identified: the old rules apply"
COUNTS = re.compile(r"operator rule: (\d+) of the operator passed, (\d+) of other users passed, (\d+) unjudged")
ANY_SID = re.compile(r"S-1-\d+(-\d+)+")


def counts(res) -> tuple[int, int, int]:
    found = COUNTS.findall(res.log_text)
    assert found, f"no count line in the log\n{res.describe()}"
    return tuple(int(x) for x in found[-1])


@pytest.fixture
def witness(world, launcher, tmp_path):
    """An operator and a running stand-in witness, configured in the world."""
    world.seams.session_sid = OP_SID
    path = tmp_path / "witness" / "witness.json"
    world.set_config(witness_file=str(path))
    stand_in = StandInWitness(path, launcher.now_filetime).start()
    yield stand_in
    stand_in.stop()


def appears_during_the_run(monkeypatch, launcher, seen, make, *, persistent=True, ended=()):
    """The record `make()` (made once) is listed from the model's first message on, until it is ended."""
    made: dict = {}

    def record():
        if "record" not in made:
            made["record"] = make()
        return made["record"]

    def condition():
        return ("run" in seen and seen["run"].count >= 1
                and ("record" not in made or made["record"]["pid"] not in ended))
    if persistent:
        list_extra(monkeypatch, launcher, lambda: [record()] if condition() else [])
    else:
        list_extra(monkeypatch, launcher, once(condition, record))
    return made


# ---------------------------------------------------------------- a: the operator's orphan passes
@pytest.mark.lr(97)
@windows_only
def test_lr97_a_an_orphaned_process_of_the_operator_listed_by_the_witness_does_not_stop_the_run(
        world, check, launcher, monkeypatch, witness):
    seen = watch_model(monkeypatch, launcher)

    def make():
        created = launcher.now_filetime()
        witness.pairs.add((ORPHAN_PID, created))
        return orphan(ORPHAN_PID, created)

    appears_during_the_run(monkeypatch, launcher, seen, make)
    ended = stand_in_end(monkeypatch, launcher, False)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), {"op": "pause", "seconds": 2}, msg("m2")])
    check.success(res)
    assert ORPHAN_PID not in ended, "the operator's process was given to end_process"
    assert counts(res)[0] == 1, res.describe()
    assert "operator identified: yes" in res.log_text


# ---------------------------------------------------------------- b: no witness, today's LR-82
@pytest.mark.lr(97)
@windows_only
def test_lr97_b_the_same_orphan_without_a_witness_stops_the_run_as_today(world, check, launcher, monkeypatch,
                                                                         tmp_path):
    world.seams.session_sid = OP_SID
    world.set_config(witness_file=str(tmp_path / "witness" / "witness.json"))  # configured, but nobody writes it
    seen = watch_model(monkeypatch, launcher)
    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, lambda: orphan(ORPHAN_PID, launcher.now_filetime()), ended=ended)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert ORPHAN_PID in ended


# ---------------------------------------------------------------- c: the launcher's own user is never passed
@pytest.mark.lr(97)
@windows_only
def test_lr97_c_a_process_of_the_launchers_own_user_listed_by_the_witness_still_stops_the_run(
        world, check, launcher, monkeypatch, witness):
    seen = watch_model(monkeypatch, launcher)

    def make():
        created = launcher.now_filetime()
        witness.pairs.add((OWN_STRAY_PID, created))  # a forged listing must not pass the executor's own process
        return own_stray(OWN_STRAY_PID, created)

    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, make, ended=ended)
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert OWN_STRAY_PID in ended


# ---------------------------------------------------------------- d: no operator, the old rules and one line
@pytest.mark.lr(97)
@windows_only
@pytest.mark.parametrize("session", ["unreadable", "the launcher's own user"])
def test_lr97_d_without_an_operator_the_old_rules_apply_and_the_log_says_so(world, check, launcher, monkeypatch,
                                                                            witness, session):
    world.seams.session_sid = None if session == "unreadable" else W.EXEC_SID
    seen = watch_model(monkeypatch, launcher)

    def make():
        created = launcher.now_filetime()
        witness.pairs.add((ORPHAN_PID, created))
        return orphan(ORPHAN_PID, created)

    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, make, ended=ended)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert ORPHAN_PID in ended
    assert res.log_text.count(NO_OPERATOR) == 1, res.describe()
    assert NO_OPERATOR in res.stdout


# ---------------------------------------------------------------- e: the operator comes from the session
@pytest.mark.lr(97)
@windows_only
def test_lr97_e_a_forged_username_or_userdomain_does_not_change_the_operator(launcher, monkeypatch):
    real = launcher.session_user_sid()
    assert real is not None and ANY_SID.fullmatch(real), "the session's user could not be read on this machine"
    monkeypatch.setenv("USERNAME", "xtl-forged-user")
    monkeypatch.setenv("USERDOMAIN", "XTL-FORGED-DOMAIN")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\xtl-forged-user")
    assert launcher.session_user_sid() == real
    # The tests run as the session's own user, so the session's user is the process's own user.
    p = launcher._proc()
    assert real == launcher._token_sid(p["k32"].GetCurrentProcess())


@pytest.mark.lr(97)
def test_lr97_e_the_session_reading_never_reads_the_environment(launcher):
    source = inspect.getsource(launcher.session_user_sid)
    assert "environ" not in source and "getenv" not in source


# ---------------------------------------------------------------- f: nothing personal is written
@pytest.mark.lr(97)
@windows_only
def test_lr97_f_no_sid_or_user_name_in_the_log_the_ledger_or_the_output(world, check, launcher, monkeypatch,
                                                                        witness):
    seen = watch_model(monkeypatch, launcher)

    def make():
        created = launcher.now_filetime()
        witness.pairs.add((ORPHAN_PID, created))
        return orphan(ORPHAN_PID, created)

    appears_during_the_run(monkeypatch, launcher, seen, make)
    stand_in_end(monkeypatch, launcher, False)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), {"op": "pause", "seconds": 2}, msg("m2")])
    check.success(res)
    ledger = world.ledger_file.read_text(encoding="utf-8")
    for where, text in (("log", res.log_text), ("ledger", ledger), ("stdout", res.stdout), ("stderr", res.stderr)):
        # LR-49 keeps the launcher's own (the executor's service user's) SID in the log: the CEO's decision of
        # 2026-11-14. No other SID (the operator's, the CEO's, anyone's) and no user name may appear.
        others = [m.group(0) for m in ANY_SID.finditer(text) if m.group(0) != W.EXEC_SID]
        assert not others, f"a SID other than the executor's in the {where}"
        assert OP_SID not in text and W.CEO_SID not in text
        assert world.app["executor_user"] not in text, f"the executor's user name in the {where}"
    assert ANY_SID.findall(ledger) == [] and W.EXEC_SID not in res.stdout
    assert counts(res) == (1, counts(res)[1], 0)


# ---------------------------------------------------------------- g: the start check is unchanged
@pytest.mark.lr(97)
@pytest.mark.lr(84)
@windows_only
def test_lr97_g_the_start_check_still_refuses_a_process_of_the_launchers_own_user(world, check, launcher, witness):
    import subprocess
    import sys
    with W.quiet_audit():
        stray = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        entry = launcher._system_processes()[stray.pid]
        witness.pairs.add((stray.pid, entry["created"]))  # even listed, it is the executor's own process
        world.foreign_file.write_text(f"{stray.pid}\n", encoding="utf-8")
        res = spec(world, [msg("m1")])
        check.preflight_stop(res, "PROCESS_AT_START")
    finally:
        world.foreign_file.write_text("", encoding="utf-8")
        stray.kill()
        stray.wait(timeout=10)


# ---------------------------------------------------------------- h, i: a witness that cannot be trusted
@pytest.mark.lr(97)
@windows_only
@pytest.mark.parametrize("flaw", ["owned by the executor", "stale"])
def test_lr97_h_i_an_untrusted_witness_is_ignored_and_the_old_rules_stop_the_run(world, check, launcher, monkeypatch,
                                                                                witness, tmp_path, flaw):
    if flaw == "owned by the executor":
        world.seams.witness_acl[W.norm(witness.path)] = (W.EXEC_SID, right_acl(OP_SID, W.EXEC_SID), False)
    else:
        witness.age = 5 * SECOND
    seen = watch_model(monkeypatch, launcher)

    def make():
        created = launcher.now_filetime()
        witness.pairs.add((ORPHAN_PID, created))
        return orphan(ORPHAN_PID, created)

    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, make, ended=ended)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert ORPHAN_PID in ended
    assert "the old rules apply" in res.log_text, res.describe()


# ---------------------------------------------------------------- k, l: not listed after the wait
@pytest.mark.lr(97)
@windows_only
def test_lr97_k_an_unknown_process_not_listed_and_alive_after_the_wait_stops_the_run(world, check, launcher,
                                                                                   monkeypatch, witness):
    seen = watch_model(monkeypatch, launcher)
    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, lambda: orphan(ORPHAN_PID, launcher.now_filetime()), ended=ended)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: True})
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert ORPHAN_PID in ended
    assert res.duration < 40, f"the attempt ran {res.duration:.0f} s"


@pytest.mark.lr(97)
@windows_only
def test_lr97_l_an_unknown_process_not_listed_and_gone_is_unjudged_counted_and_does_not_stop(
        world, check, launcher, monkeypatch, witness):
    world.set_config(witness_file=str(witness.path), max_unjudged=1)  # within the limit (review round 1, F1)
    seen = watch_model(monkeypatch, launcher)
    ended = stand_in_end(monkeypatch, launcher, True)
    appears_during_the_run(monkeypatch, launcher, seen, lambda: orphan(ORPHAN_PID, launcher.now_filetime()),
                           persistent=False, ended=ended)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: False})
    res = spec(world, [msg("m1"), {"op": "pause", "seconds": 2}, msg("m2")])
    check.success(res)
    assert ORPHAN_PID not in ended
    assert counts(res)[2] == 1, res.describe()
    assert "unjudged" in res.log_text and "sleep.exe" in res.log_text


# ---------------------------------------------------------------- the preflight names the operator and the witness
@pytest.mark.lr(97)
@pytest.mark.lr(98)
@windows_only
def test_lr97_the_preflight_says_operator_identified_and_witness_found(world, witness):
    res = world.run("check")
    lines = [ln.strip() for ln in res.stdout.splitlines()]
    assert res.code == 0 and lines[-1] == "PREFLIGHT OK", res.describe()
    assert "operator identified: yes" in lines and "witness: found" in lines, res.describe()


# ---------------------------------------------------------------- the witness's checks, one by one (h, i, j)
def write_file(path, launcher, *, written=None, pairs=(), **override):
    data = {"format": WITNESS_FORMAT, "started": launcher.now_filetime() - SECOND,
            "written": launcher.now_filetime() if written is None else written,
            "pairs": [list(p) for p in pairs]}
    data.update(override)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def security(monkeypatch, launcher):
    """The witness's file and folder security, settable per path; the default is right."""
    table: dict = {}

    def witness_security(path):
        return table.get(W.norm(path), (OP_SID, right_acl(OP_SID, W.EXEC_SID), False))

    def witness_file(path):  # the file's security and bytes from one open (review round 1, F2)
        try:
            data = Path(path).read_bytes()
        except OSError:
            return None
        return witness_security(path), data

    monkeypatch.setattr(launcher, "witness_security", witness_security, raising=False)
    monkeypatch.setattr(launcher, "witness_file", witness_file, raising=False)
    return table


FLAWS = {
    "file owned by the executor": ("file", (W.EXEC_SID, right_acl(OP_SID, W.EXEC_SID), False)),
    "file owned by Administrators": ("file", (ADMINS_SID, right_acl(OP_SID, W.EXEC_SID), False)),
    "file writable by the executor": ("file", (OP_SID, right_acl(OP_SID, W.EXEC_SID)[:3] + [(W.EXEC_SID, 0x2, "Allow")], False)),
    "file deletable by the executor": ("file", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [(W.EXEC_SID, 0x10000, "Allow")], False)),
    "file's permissions changeable by the executor": ("file", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [(W.EXEC_SID, 0x40000, "Allow")], False)),
    "file's owner changeable by everyone": ("file", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [("S-1-1-0", 0x80000, "Allow")], False)),
    "file with a null DACL": ("file", (OP_SID, None, False)),
    "file is a link": ("file", (OP_SID, right_acl(OP_SID, W.EXEC_SID), True)),
    "folder lets the executor add a file": ("folder", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [(W.EXEC_SID, 0x2, "Allow")], False)),
    "folder lets the executor delete a child": ("folder", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [(W.EXEC_SID, 0x40, "Allow")], False)),
    "folder gives Users generic write": ("folder", (OP_SID, right_acl(OP_SID, W.EXEC_SID) + [("S-1-5-32-545", 0x40000000, "Allow")], False)),
    "folder owned by the executor": ("folder", (W.EXEC_SID, right_acl(OP_SID, W.EXEC_SID), False)),
    "folder with a null DACL": ("folder", (OP_SID, None, False)),
    "folder is a junction": ("folder", (OP_SID, right_acl(OP_SID, W.EXEC_SID), True)),
    "security unreadable": ("file", None),
}


@pytest.mark.lr(97)
@pytest.mark.parametrize("flaw", sorted(FLAWS))
def test_lr97_h_a_witness_the_executor_could_forge_or_replace_is_not_trusted(launcher, tmp_path, security, flaw):
    path = tmp_path / "w" / "witness.json"
    write_file(path, launcher, pairs=[(ORPHAN_PID, 5)])
    where, value = FLAWS[flaw]
    security[W.norm(path if where == "file" else path.parent)] = value
    witness = launcher.Witness(str(path), OP_SID, W.EXEC_SID)
    assert witness.read() is None
    assert witness.reason


@pytest.mark.lr(97)
def test_lr97_h_the_right_witness_is_trusted_with_system_and_administrators_writing(launcher, tmp_path, security):
    path = tmp_path / "w" / "witness.json"
    write_file(path, launcher, pairs=[(ORPHAN_PID, 5), (8, 9)])
    security[W.norm(path.parent)] = (ADMINS_SID, right_acl(OP_SID, W.EXEC_SID) + [(W.EXEC_SID, FULL, "Deny")], False)
    state = launcher.Witness(str(path), OP_SID, W.EXEC_SID).read()
    assert state is not None
    written, pairs = state
    assert pairs == {(ORPHAN_PID, 5), (8, 9)}


@pytest.mark.lr(97)
@pytest.mark.parametrize("age", [2.6, -1.0])
def test_lr97_i_a_stale_or_future_witness_is_not_trusted(launcher, tmp_path, security, age):
    path = tmp_path / "w" / "witness.json"
    write_file(path, launcher, written=launcher.now_filetime() - int(age * SECOND))
    witness = launcher.Witness(str(path), OP_SID, W.EXEC_SID)
    assert witness.read() is None and witness.reason


@pytest.mark.lr(97)
def test_lr97_i_a_witness_written_one_second_ago_is_fresh(launcher, tmp_path, security):
    path = tmp_path / "w" / "witness.json"
    write_file(path, launcher, written=launcher.now_filetime() - SECOND)
    assert launcher.Witness(str(path), OP_SID, W.EXEC_SID).read() is not None


MALFORMED = {
    "not JSON": b"{not json",
    "not an object": b"[1, 2]",
    "another format": None,
    "a pair of three": None,
    "a bool for a pid": None,
    "a negative time": None,
    "an extra field": None,
    "a name field": None,
}


@pytest.mark.lr(97)
@pytest.mark.parametrize("kind", sorted(MALFORMED))
def test_lr97_a_malformed_witness_file_is_not_trusted(launcher, tmp_path, security, kind):
    path = tmp_path / "w" / "witness.json"
    if MALFORMED[kind] is not None:
        path.parent.mkdir(parents=True)
        path.write_bytes(MALFORMED[kind])
    else:
        override = {"another format": {"format": "xtl-witness/0"},
                    "a pair of three": {"pairs": [[1, 2, 3]]},
                    "a bool for a pid": {"pairs": [[True, 2]]},
                    "a negative time": {"pairs": [[1, -2]]},
                    "an extra field": {"note": "x"},
                    "a name field": {"user": "someone"}}[kind]
        write_file(path, launcher, **override)
    witness = launcher.Witness(str(path), OP_SID, W.EXEC_SID)
    assert witness.read() is None and witness.reason


@pytest.mark.lr(97)
def test_lr97_without_an_operator_or_a_path_there_is_no_witness(launcher, tmp_path, security):
    path = tmp_path / "w" / "witness.json"
    write_file(path, launcher)
    assert launcher.Witness(None, OP_SID, W.EXEC_SID).read() is None
    assert launcher.Witness(str(path), None, W.EXEC_SID).read() is None
    # a file and a folder the launcher's own user owns and only it may write: still no witness for its own user
    security[W.norm(path)] = (W.EXEC_SID, right_acl(W.EXEC_SID, W.EXEC_SID), False)
    security[W.norm(path.parent)] = (W.EXEC_SID, right_acl(W.EXEC_SID, W.EXEC_SID), False)
    for ancestor in path.parent.parents:  # the folders above pass, so only the operator's check can refuse
        security[W.norm(ancestor)] = (SYSTEM_SID, [(SYSTEM_SID, FULL, "Allow")], False)
    assert launcher.Witness(str(path), W.EXEC_SID, W.EXEC_SID).read() is None


# ---------------------------------------------------------------- j and the wait: the judgement on stand-ins
class FakeWitness:
    """read() gives the next of `states` (the last one repeats); None is an untrusted reading."""

    def __init__(self, *states):
        self.states = list(states)
        self.reads = 0
        self.reason = ""

    def read(self):
        self.reads += 1
        state = self.states[min(self.reads - 1, len(self.states) - 1)]
        if state is None:
            self.reason = "stand-in: not trusted"
        return state


class FakeLog:
    def __init__(self):
        self.lines: list[str] = []

    def write(self, text):
        self.lines.append(text)


def rule(launcher, monkeypatch, witness, alive=True):
    monkeypatch.setattr(launcher, "process_alive", lambda pid, created: alive)
    return launcher.OperatorRule(witness, FakeLog())


@pytest.mark.lr(97)
def test_lr97_j_a_listed_pair_passes_and_is_counted(launcher, monkeypatch):
    r = rule(launcher, monkeypatch, FakeWitness((100 * SECOND, frozenset({(ORPHAN_PID, 50 * SECOND)}))))
    assert r.sort([orphan(ORPHAN_PID, 50 * SECOND)]) == []
    assert r.passed == {(ORPHAN_PID, 50 * SECOND)} and r.unjudged == set()
    assert not any(ANY_SID.search(line) for line in r.log.lines)


@pytest.mark.lr(97)
def test_lr97_j_the_same_id_with_another_creation_time_is_not_passed(launcher, monkeypatch):
    r = rule(launcher, monkeypatch, FakeWitness((100 * SECOND, frozenset({(ORPHAN_PID, 50 * SECOND)}))))
    record = orphan(ORPHAN_PID, 51 * SECOND)
    assert r.sort([record]) == [record]
    assert r.passed == set()


@pytest.mark.lr(97)
def test_lr97_j_a_record_without_a_creation_time_is_not_passed(launcher, monkeypatch):
    r = rule(launcher, monkeypatch, FakeWitness((100 * SECOND, frozenset({(ORPHAN_PID, 50 * SECOND)}))))
    record = orphan(ORPHAN_PID, 50 * SECOND)
    record["created"] = None
    assert r.sort([record]) == [record]


@pytest.mark.lr(97)
def test_lr97_the_rule_touches_only_unknown_owners(launcher, monkeypatch):
    pairs = frozenset({(OWN_STRAY_PID, 50 * SECOND)})
    r = rule(launcher, monkeypatch, FakeWitness((100 * SECOND, pairs)))
    record = own_stray(OWN_STRAY_PID, 50 * SECOND)
    assert r.sort([record]) == [record]


@pytest.mark.lr(97)
def test_lr97_the_judgement_waits_for_a_write_half_a_second_after_the_creation(launcher, monkeypatch):
    created = 100 * SECOND
    early = (created + SECOND // 4, frozenset())                       # too early to judge
    late = (created + SECOND, frozenset({(ORPHAN_PID, created)}))      # listed by then
    witness = FakeWitness(early, early, late)
    r = rule(launcher, monkeypatch, witness)
    assert r.sort([orphan(ORPHAN_PID, created)]) == []
    assert witness.reads == 3 and r.passed == {(ORPHAN_PID, created)}


@pytest.mark.lr(97)
@pytest.mark.parametrize("alive, foreign", [(True, True), (False, False)])
def test_lr97_k_l_not_listed_after_the_wait_alive_is_foreign_gone_is_unjudged(launcher, monkeypatch, alive, foreign):
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset())), alive=alive)
    record = orphan(ORPHAN_PID, created)
    assert r.sort([record]) == ([record] if foreign else [])
    assert r.unjudged == (set() if foreign else {(ORPHAN_PID, created)})


@pytest.mark.lr(97)
def test_lr97_the_wait_is_bounded_at_two_seconds(launcher, monkeypatch):
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created, frozenset())))  # never half a second after the creation
    record = orphan(ORPHAN_PID, created)
    started = time.monotonic()
    assert r.sort([record, orphan(ORPHAN_PID + 4, created)]) == [record, orphan(ORPHAN_PID + 4, created)]
    took = time.monotonic() - started
    assert 1.5 <= took <= 3.0, f"the wait took {took:.2f} s"


@pytest.mark.lr(97)
def test_lr97_an_untrusted_reading_applies_the_old_rules_at_once(launcher, monkeypatch):
    r = rule(launcher, monkeypatch, FakeWitness(None))
    record = orphan(ORPHAN_PID, 100 * SECOND)
    started = time.monotonic()
    assert r.sort([record]) == [record]
    assert time.monotonic() - started < 1.0
    assert any("the old rules apply" in line for line in r.log.lines)


@pytest.mark.lr(97)
def test_lr97_no_witness_object_means_the_old_rules(launcher, monkeypatch):
    r = rule(launcher, monkeypatch, None)
    record = orphan(ORPHAN_PID, 100 * SECOND)
    assert r.sort([record]) == [record]


# ---------------------------------------------------------------- the real security reading
@pytest.mark.lr(97)
@windows_only
def test_lr97_the_real_security_reading_gives_the_owner_and_the_rules_of_a_file(launcher, tmp_path):
    path = tmp_path / "w" / "witness.json"
    path.parent.mkdir()
    path.write_text("{}", encoding="utf-8")
    p = launcher._proc()
    me = launcher._token_sid(p["k32"].GetCurrentProcess())
    owner, aces, reparse = launcher.witness_security(str(path))
    assert reparse is False and isinstance(aces, list) and aces
    assert owner in (me, ADMINS_SID)  # an elevated test window owns new files through Administrators
    assert all(kind in ("Allow", "Deny") and isinstance(mask, int) for _, mask, kind in aces)
    # pytest's folders are made with mode 0o700, which Python 3.13 turns into rules for the owner, SYSTEM and
    # Administrators only: someone of these may write it.
    assert any(sid in (me, "S-1-3-4", SYSTEM_SID, ADMINS_SID) and mask & 0x2 and kind == "Allow"
               for sid, mask, kind in aces), [(sid == me, hex(mask), kind) for sid, mask, kind in aces]
    assert launcher.witness_security(str(tmp_path / "absent" / "x.json")) is None


@pytest.mark.lr(97)
def test_lr97_the_constants_of_amendment_1(launcher):
    assert launcher.WITNESS_FORMAT == WITNESS_FORMAT
    assert launcher.WITNESS_FRESH_SECONDS == 2
    assert launcher.WITNESS_AFTER_SECONDS == 0.5
    assert launcher.WITNESS_WAIT_SECONDS == 2
    assert {SYSTEM_SID, ADMINS_SID} <= set(launcher.WITNESS_WRITERS)
    assert FULL & launcher.WITNESS_WRITE_BITS and not READ_EXECUTE & launcher.WITNESS_WRITE_BITS

@pytest.mark.lr(97)
def test_lr97_a_process_whose_end_cannot_be_read_stays_foreign(launcher, monkeypatch):
    """Fail closed: when the process list cannot be read during the judgement, the record is not unjudged."""
    created = 100 * SECOND

    def broken(pid, created):
        raise OSError("the process list cannot be read")

    monkeypatch.setattr(launcher, "process_alive", broken)
    r = launcher.OperatorRule(FakeWitness((created + SECOND, frozenset())), FakeLog())
    record = orphan(ORPHAN_PID, created)
    assert r.sort([record]) == [record]
    assert r.unjudged == set()

@pytest.mark.lr(97)
def test_lr97_an_untrusted_reading_during_the_wait_ends_it_with_the_old_rules(launcher, monkeypatch):
    created = 100 * SECOND
    witness = FakeWitness((created + SECOND // 4, frozenset()), None)
    r = rule(launcher, monkeypatch, witness, alive=False)
    record = orphan(ORPHAN_PID, created)
    assert r.sort([record]) == [record]
    assert r.unjudged == set() and witness.reads == 2
