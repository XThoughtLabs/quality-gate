"""The repairs of review round 1 of LR-96 to LR-99 (evidence-local s-repair\\review\\review1-FINDINGS.md), by the CEO's
decisions of 2026-11-14: F1 ("unjudged" only for a process whose only mark is a dead parent, and a per-run limit
max_unjudged), F2 (the witness file read through one open; every folder above it checked), F3 (the must_not_open
entry's number, not its path, in the log and the stop message), and the lows F4, F5, F9, F11 and the stand-in race.
Written before the repairs; each test names the finding it closes."""

from __future__ import annotations

import io
import os
import re
import sys
from pathlib import Path

import pytest

import launcher_world as W
from operator_kit import (ADMINS_SID, FULL, OP_SID, ORPHAN_PID, SECOND, SYSTEM_SID, StandInWitness, list_extra,
                          once, orphan, right_acl, stand_in_alive, stand_in_end, watch_model)
from stage_a_kit import msg, spec
from test_lr97_witness import FakeLog, FakeWitness, counts, write_file

windows_only = pytest.mark.skipif(os.name != "nt", reason="the process list and the security API exist on Windows only")
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
AUTHENTICATED_USERS = "S-1-5-11"
LAUNCHER_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- F1: "unjudged" only for a plain orphan, and a limit
MARKS = {
    "a child of the launcher": {"ppid": 999, "parent_alive": True, "parent_owner": "self"},
    "a child of a process in the job": {"parent_in_job": True, "parent_alive": True, "parent_owner": "self"},
    "a child of the executor's process": {"parent_alive": True, "parent_owner": "self"},
    "started by WMI": {"broker": "wmi", "parent_alive": True, "parent_owner": "unknown", "parent_image": "WmiPrvSE.exe"},
    "started by the scheduler in this session": {"broker": "schedule", "parent_alive": True, "parent_owner": "unknown"},
}


def marked(kind: str, created: int) -> dict:
    record = orphan(ORPHAN_PID, created)
    record.update(MARKS[kind])
    return record


def rule(launcher, monkeypatch, witness, alive=False, limit=10):
    monkeypatch.setattr(launcher, "process_alive", lambda pid, created: alive)
    return launcher.OperatorRule(witness, FakeLog(), limit)


@pytest.mark.lr(97)
@pytest.mark.parametrize("kind", sorted(MARKS))
def test_f1_a_marked_process_not_listed_and_gone_stays_foreign(launcher, monkeypatch, kind):
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset())))
    record = marked(kind, created)
    assert r.sort([record], exclude={999}) == [record]
    assert r.unjudged == set() and not r.over


@pytest.mark.lr(97)
@pytest.mark.parametrize("kind", sorted(MARKS))
def test_f1_a_marked_process_listed_by_the_witness_is_the_operators(launcher, monkeypatch, kind):
    """The witness reads the owner from the token: a listed pair is the operator's whatever its parent."""
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset({(ORPHAN_PID, created)}))))
    assert r.sort([marked(kind, created)], exclude={999}) == []
    assert r.passed == {(ORPHAN_PID, created)}


DEAD_PARENT_MARKS = {  # a dead parent whose id now names another process, or a record the lister would not make
    "the parent's id is the launcher's": {"ppid": 999},
    "the parent's id is a process in the job": {"parent_in_job": True},
    "the parent's owner is the executor": {"parent_owner": "self"},
    "a broker": {"broker": "wmi"},
}


@pytest.mark.lr(97)
@pytest.mark.parametrize("kind", sorted(DEAD_PARENT_MARKS))
def test_f1_a_dead_parent_record_with_a_mark_stays_foreign(launcher, monkeypatch, kind):
    """plain_orphan checks every mark itself, not only the dead parent (it is a pure function of the record)."""
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset())))
    record = orphan(ORPHAN_PID, created)
    record.update(DEAD_PARENT_MARKS[kind])
    assert r.sort([record], exclude={999}) == [record]
    assert r.unjudged == set()


@pytest.mark.lr(97)
def test_f1_a_plain_orphan_not_listed_and_gone_is_unjudged_within_the_limit(launcher, monkeypatch):
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset())), limit=1)
    assert r.sort([orphan(ORPHAN_PID, created)], exclude={999}) == []
    assert r.unjudged == {(ORPHAN_PID, created)} and not r.over


@pytest.mark.lr(97)
@pytest.mark.parametrize("limit", [0, 1, 3])
def test_f1_one_unjudged_more_than_the_limit_is_over(launcher, monkeypatch, limit):
    created = 100 * SECOND
    r = rule(launcher, monkeypatch, FakeWitness((created + SECOND, frozenset())), limit=limit)
    for i in range(limit):
        r.sort([orphan(ORPHAN_PID + 4 * i, created)], exclude=set())
        assert not r.over, f"over after {i + 1} of {limit}"
    r.sort([orphan(ORPHAN_PID + 4 * limit, created)], exclude=set())
    assert r.over and len(r.unjudged) == limit + 1


@pytest.mark.lr(97)
def test_f1_the_limit_is_read_from_the_configuration_and_defaults_to_0(launcher, tmp_path):
    def config(extra=""):
        path = tmp_path / "c.toml"
        key = tmp_path / "k.pem"
        key.write_text("x", encoding="utf-8")
        path.write_text("[launcher]\n" + "\n".join(
            f"{k} = {v}" for k, v in {
                "key_file": f"'{key}'", "app_file": f"'{tmp_path / 'a.json'}'", "runs_dir": f"'{tmp_path}'",
                "app_python": "'C:\\p.exe'", "claude_command": "['C:\\c.exe']", "deny_read_paths": "[]",
                "must_not_open": "[]", "ledger_file": f"'{tmp_path / 'l.jsonl'}'", "max_messages_attempt": 80,
                "max_messages_task": 240, "max_runs_task": 3}.items()) + "\n" + extra, encoding="utf-8")
        return path
    assert launcher.load_config(config()).get("max_unjudged", 0) == 0
    assert launcher.load_config(config("max_unjudged = 4\n"))["max_unjudged"] == 4
    for bad in ("max_unjudged = -1\n", "max_unjudged = true\n", "max_unjudged = '2'\n"):
        with pytest.raises(launcher.ConfigError):
            launcher.load_config(config(bad))


@pytest.fixture
def witness(world, launcher, tmp_path):
    world.seams.session_sid = OP_SID
    path = tmp_path / "witness" / "witness.json"
    world.set_config(witness_file=str(path))
    stand_in = StandInWitness(path, launcher.now_filetime).start()
    yield stand_in
    stand_in.stop()


def appears_once(monkeypatch, launcher, seen, make):
    list_extra(monkeypatch, launcher, once(lambda: "run" in seen and seen["run"].count >= 1, make))


@pytest.mark.lr(97)
@windows_only
def test_f1_with_the_default_limit_an_unjudged_process_stops_the_run(world, check, launcher, monkeypatch, witness):
    seen = watch_model(monkeypatch, launcher)
    appears_once(monkeypatch, launcher, seen, lambda: orphan(ORPHAN_PID, launcher.now_filetime()))
    ended = stand_in_end(monkeypatch, launcher, True)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: False})
    res = spec(world, [msg("m1"), {"op": "pause", "seconds": 3}, msg("m2")])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert ORPHAN_PID not in ended, "a process that is gone was given to end_process"
    assert "max_unjudged" in res.log_text, res.describe()
    assert counts(res)[2] == 1


@pytest.mark.lr(97)
@windows_only
def test_f1_the_reviewers_relay_a_hidden_wmi_child_gone_at_once_stops_the_run(world, check, launcher, monkeypatch,
                                                                            witness):
    world.set_config(witness_file=str(witness.path), max_unjudged=5)
    seen = watch_model(monkeypatch, launcher)
    appears_once(monkeypatch, launcher, seen, lambda: marked("started by WMI", launcher.now_filetime()))
    stand_in_end(monkeypatch, launcher, True)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: False})
    res = spec(world, [msg("m1"), {"op": "pause", "seconds": 3}, msg("m2")])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert counts(res)[2] == 0


@pytest.mark.lr(97)
@windows_only
def test_f1_over_the_limit_at_the_search_before_the_push_stops_the_push(world, check, launcher, monkeypatch, witness):
    seen = watch_model(monkeypatch, launcher)
    shown = {"done": False}

    def extra():  # only after the attempt has ended (its exit code is read last), so at the search before the push
        if "run" in seen and seen["run"].exit_code is not None and not shown["done"]:
            shown["done"] = True
            return [orphan(ORPHAN_PID, launcher.now_filetime())]
        return []

    list_extra(monkeypatch, launcher, extra)
    stand_in_end(monkeypatch, launcher, True)
    stand_in_alive(monkeypatch, launcher, {ORPHAN_PID: False})
    res = spec(world, [msg("m1")])
    check.post_model_stop(res, "PROCESS_BEFORE_PUSH")


# ---------------------------------------------------------------- F2: one open of the file; the folders above
@pytest.fixture
def security(monkeypatch, launcher):
    table: dict = {}

    def witness_security(path):
        return table.get(W.norm(path), (OP_SID, right_acl(OP_SID, W.EXEC_SID), False))

    def witness_file(path):
        try:
            data = Path(path).read_bytes()
        except OSError:
            return None
        return witness_security(path), data

    monkeypatch.setattr(launcher, "witness_security", witness_security, raising=False)
    monkeypatch.setattr(launcher, "witness_file", witness_file, raising=False)
    return table


ROOT_LIKE = (TRUSTED_INSTALLER, [(AUTHENTICATED_USERS, 0x4, "Allow"), (SYSTEM_SID, FULL, "Allow"),
                                 (ADMINS_SID, FULL, "Allow"), ("S-1-5-32-545", 0x1200A9, "Allow")], False)
ANCESTOR_FLAWS = {
    "the executor may delete children of the grandparent": (W.EXEC_SID, 0x40),
    "Users may delete the grandparent": ("S-1-5-32-545", 0x10000),
    "the executor may change the grandparent's rules": (W.EXEC_SID, 0x40000),
    "everyone may take the grandparent": ("S-1-1-0", 0x80000),
    "the executor has generic all on the grandparent": (W.EXEC_SID, 0x10000000),
}


@pytest.mark.lr(97)
@pytest.mark.parametrize("flaw", sorted(ANCESTOR_FLAWS) + ["owned by the executor", "a junction", "unreadable",
                                                           "a null access list"])
def test_f2_a_folder_above_the_witness_that_others_can_move_or_change_is_not_trusted(launcher, tmp_path, security,
                                                                                   flaw):
    path = tmp_path / "a" / "w" / "witness.json"
    write_file(path, launcher)
    grandparent = path.parent.parent
    if flaw in ANCESTOR_FLAWS:
        sid, mask = ANCESTOR_FLAWS[flaw]
        security[W.norm(grandparent)] = (SYSTEM_SID, ROOT_LIKE[1] + [(sid, mask, "Allow")], False)
    else:
        security[W.norm(grandparent)] = {"owned by the executor": (W.EXEC_SID, ROOT_LIKE[1], False),
                                         "a junction": (SYSTEM_SID, ROOT_LIKE[1], True),
                                         "unreadable": None,
                                         "a null access list": (SYSTEM_SID, None, False)}[flaw]
    witness = launcher.Witness(str(path), OP_SID, W.EXEC_SID)
    assert witness.read() is None and "above" in witness.reason


@pytest.mark.lr(97)
def test_f2_a_drive_root_like_folder_above_is_trusted(launcher, tmp_path, security):
    """Authenticated Users may add folders to the drive's root and TrustedInstaller owns it: neither lets anyone
    move or replace a folder that exists."""
    path = tmp_path / "a" / "w" / "witness.json"
    write_file(path, launcher)
    for ancestor in path.parent.parents:
        security[W.norm(ancestor)] = ROOT_LIKE
    assert launcher.Witness(str(path), OP_SID, W.EXEC_SID).read() is not None


@pytest.mark.lr(97)
def test_f2_the_files_owner_and_rules_come_from_the_open_that_reads_it(launcher, tmp_path, security, monkeypatch):
    """Owner and bytes from one open: a file checked by its path and then read through another open is refused."""
    path = tmp_path / "a" / "w" / "witness.json"
    write_file(path, launcher)
    monkeypatch.setattr(launcher, "witness_file",
                        lambda p: ((W.EXEC_SID, right_acl(OP_SID, W.EXEC_SID), False), Path(p).read_bytes()))
    witness = launcher.Witness(str(path), OP_SID, W.EXEC_SID)
    assert witness.read() is None, "the file's security was not taken from its own open"


@pytest.mark.lr(97)
@windows_only
def test_f2_the_real_open_gives_the_same_owner_and_rules_as_the_path_and_the_bytes(launcher, tmp_path):
    path = tmp_path / "real" / "witness.json"
    path.parent.mkdir()
    path.write_bytes(b'{"x": 1}')
    security, data = launcher.witness_file(str(path))
    assert data == b'{"x": 1}'
    assert security[0] == launcher.witness_security(str(path))[0]
    assert sorted(security[1]) == sorted(launcher.witness_security(str(path))[1]) and security[2] is False
    assert launcher.witness_file(str(tmp_path / "absent.json")) is None


@pytest.mark.lr(97)
@windows_only
def test_f2_the_real_reading_leaves_out_rules_that_only_children_inherit(launcher):
    """C:\\ gives Authenticated Users a Modify rule for its children only; it must not read as a right on C:\\."""
    owner, rules, reparse = launcher.witness_security("C:\\")
    assert not any(sid == AUTHENTICATED_USERS and mask & 0x10000 for sid, mask, kind in rules), rules


@pytest.mark.lr(97)
@windows_only
def test_f2_the_real_reading_sees_a_junction_above_the_file(launcher, tmp_path):
    import subprocess
    target = tmp_path / "target"
    target.mkdir()
    (target / "witness.json").write_text("{}", encoding="utf-8")
    link = tmp_path / "link"
    with W.quiet_audit():
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    assert made.returncode == 0, made.stdout
    assert launcher.witness_security(str(link))[2] is True
    witness = launcher.Witness(str(link / "witness.json"), OP_SID, W.EXEC_SID)
    assert witness.read() is None


@pytest.mark.lr(98)
@pytest.mark.parametrize("flaw", ["the executor may delete children", "a junction", "owned by the executor",
                                  "unreadable"])
def test_f2_the_operators_command_refuses_a_folder_above_the_witness_others_can_move(xo, tmp_path, flaw):
    from test_lr98_operator import EXEC_SID, FakeWindows, run
    win = FakeWindows(tmp_path)
    win.ancestor_states[str(tmp_path)] = {
        "the executor may delete children": (SYSTEM_SID, ROOT_LIKE[1] + [(EXEC_SID, 0x40, "Allow")], False, False, True),
        "a junction": (SYSTEM_SID, ROOT_LIKE[1], False, True, True),
        "owned by the executor": (EXEC_SID, ROOT_LIKE[1], False, False, True),
        "unreadable": None}[flaw]
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1, out
    assert not any(e.startswith(("make_folder", "set_acl")) for e in win.events)
    assert "witness started" not in win.events and "runas" not in win.events


# ---------------------------------------------------------------- F3: the entry's number, not its path
@pytest.mark.lr(97)
@pytest.mark.lr(11)
def test_f3_no_must_not_open_path_reaches_the_log_or_the_output(world):
    world.set_config(must_not_open=[str(world.candidate_folder), r"C:\Users\xtl-ceo-zz-profile\keys"])
    res = world.run("check")
    assert res.code == 0, res.describe()
    for text in (res.log_text, res.stdout):
        assert "xtl-ceo-zz-profile" not in text and str(world.candidate_folder) not in text
    assert "must_not_open entry 1: denied" in res.log_text and "must_not_open entry 2: denied" in res.log_text


@pytest.mark.lr(97)
@pytest.mark.lr(11)
def test_f3_the_folder_open_stop_names_the_entrys_number(world, check):
    world.seams.folders[W.norm(world.absent_folder)] = "open"
    res = world.run("check")
    check.preflight_stop(res, "FOLDER_OPEN")
    assert "must_not_open entry 2" in res.last and str(world.absent_folder) not in res.last + res.log_text


# ---------------------------------------------------------------- the lows
@pytest.fixture(scope="module")
def xo():
    import xtl_operator
    return xtl_operator


@pytest.mark.lr(98)
def test_f4_an_unexpected_error_stops_without_a_traceback_and_stops_the_witness(xo, tmp_path):
    from test_lr98_operator import FakeWindows, run
    win = FakeWindows(tmp_path)

    def broken():
        raise OSError("C:\\Users\\xtl-ceo-zz-profile\\secret path")

    win.processes = broken
    code, out = run(xo, win, tmp_path, "task", "--issue", "1")
    assert code == 1 and win.witness_proc.stopped, out
    assert "Traceback" not in out and "xtl-ceo-zz-profile" not in out
    assert "an unexpected OSError" in out


@pytest.mark.lr(98)
def test_f5_the_witness_starts_with_the_base_interpreter_not_a_venv_redirector(xo, tmp_path):
    from test_lr98_operator import FakeWindows, run
    win = FakeWindows(tmp_path)
    run(xo, win, tmp_path, "task", "--issue", "1")
    assert win.witness_proc.argv[0] == getattr(sys, "_base_executable", sys.executable)


@pytest.mark.lr(97)
@pytest.mark.lr(98)
@windows_only
def test_f9_the_watch_without_its_own_sid_identifies_no_operator(world, launcher, monkeypatch):
    world.seams.session_sid = OP_SID
    world.seams.sid = None
    monkeypatch.setattr(launcher, "WATCH_MINUTE_SECONDS", 0.5)
    res = world.run("watch", "--minutes", "1")
    assert res.code == 0, res.describe()
    assert "operator not identified: the old rules apply" in res.stdout


@pytest.mark.lr(98)
@windows_only
def test_f11_the_executor_must_be_a_user_account(xo):
    machine = xo.Machine()
    assert machine.account_sid("Users") is None and machine.account_sid("Everyone") is None
    own = os.environ.get("USERNAME", "")
    if own:
        assert machine.account_sid(own) == machine.own_sid()


@pytest.mark.lr(98)
@pytest.mark.parametrize("name, ok", [("exec zz user", True), ("PC-ZZ\\exec-zz", True), ("exéc", True),
                                      ('a"b', False), ("a/b", False), ("a:b", False), ("", False),
                                      ("a" * 21, False)])
def test_f11_the_user_name_rule_takes_windows_names_and_refuses_cmd_characters(xo, name, ok):
    assert bool(xo.USER_NAME.fullmatch(name)) is ok

@pytest.mark.lr(98)
@windows_only
def test_f2_the_operators_real_folder_reading_leaves_out_rules_only_children_inherit(xo):
    owner, rules, protected, reparse, is_dir = xo.Machine().folder("C:\\")
    assert is_dir and not reparse
    assert not any(sid == AUTHENTICATED_USERS and mask & 0x10000 for sid, mask, kind in rules), rules