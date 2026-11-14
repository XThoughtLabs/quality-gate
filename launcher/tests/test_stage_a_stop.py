"""Stage A: the stop at the limit (LR-57), ending the model's processes (LR-58, LR-64), subagents
(LR-59) and the timeout (LR-61).

Written from LAUNCHER-CONTRACT.md section 12. Each test is named and marked by its rule. The tests
of the job object run on Windows only; they are the regression tests HQ asked for in its answer to
the stop-and-ask on M-6 (amendment A13)."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import time

import pytest

import launcher_world as W
from stage_a_kit import (COMMIT, GRACE, SLUG, argv_value, kill_all, logged_pid, msg, one_attempt, read_json, result,
                         spec, wait_dead)

windows_only = pytest.mark.skipif(os.name != "nt", reason="LR-58's job object exists on Windows only")
STAY = {"op": "pause", "seconds": 120}


def over_flags(messages):
    return [m["over_limit"] for m in sorted(messages, key=lambda m: m["ordinal"])]


# ---------------------------------------------------------------- LR-57
@pytest.mark.lr(57)
def test_lr57_the_stop_waits_for_the_last_messages_tool_results(world, check, tmp_path):
    before, after, late = tmp_path / "before", tmp_path / "after", tmp_path / "late"
    steps = [msg("a1", tools=["t1"]), result("t1"), msg("a2", tools=["t2"]), result("t2"),
             msg("a3", tools=["t3a", "t3b"]), {"op": "marker", "file": str(before)},
             {"op": "pause", "seconds": 1.5}, result("t3a"), {"op": "pause", "seconds": 1.5}, result("t3b"),
             {"op": "marker", "file": str(after)}, {"op": "pause", "seconds": 5},
             {"op": "marker", "file": str(late)}, STAY]
    res = spec(world, steps, "--max-messages", "3")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert before.exists() and after.exists(), "the stop did not wait for the third message's tool results"
    assert not late.exists(), "the model kept running long after its results"
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 3 and over_flags(messages) == [False] * 3
    assert finished["outcome"] == "MESSAGE_LIMIT"
    assert res.duration < 60


@pytest.mark.lr(57)
def test_lr57_a_tool_use_in_a_later_fragment_is_waited_for(world, check, tmp_path):
    after = tmp_path / "after"
    steps = [msg("a1", tools=["t1"]), msg("a1", tools=["t1b"], text=None), {"op": "pause", "seconds": 1},
             result("t1"), {"op": "pause", "seconds": 1.5}, result("t1b"), {"op": "marker", "file": str(after)},
             STAY]
    res = spec(world, steps, "--max-messages", "1")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert after.exists(), "the stop came before the fragment's tool result"


@pytest.mark.lr(57)
def test_lr57_without_tool_use_the_stop_is_at_once(world, check, tmp_path):
    late = tmp_path / "late"
    res = spec(world, [msg("a1"), msg("a2"), {"op": "pause", "seconds": 8}, {"op": "marker", "file": str(late)},
                       STAY], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert not late.exists(), "the stop waited although the last message had no tool use"
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 2


@pytest.mark.lr(57)
def test_lr57_messages_beyond_the_limit_are_counted_and_marked(world, check):
    res = spec(world, [{"op": "burst", "count": 5, "prefix": "b"}, STAY], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 5
    assert over_flags(messages) == [False, False, True, True, True]
    assert "3 over the limit" in res.log_text, "the log does not name the messages over the limit"


@pytest.mark.lr(57)
def test_lr57_a_model_that_never_stops_by_itself(world, check):
    res = spec(world, [{"op": "forever", "interval": 0.02, "prefix": "f"}], "--max-messages", "4")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    _, messages, finished = one_attempt(world, res)
    flags = over_flags(messages)
    assert len(flags) >= 4 and flags[:4] == [False] * 4 and all(flags[4:])
    assert finished["messages"] == len(flags)
    assert res.duration < 60


@pytest.mark.lr(57)
def test_lr57_a_message_beyond_the_limit_stops_while_results_are_awaited(world, check, tmp_path):
    """The L-th message's tool result never comes, but another message does: the stop begins at once."""
    late = tmp_path / "late"
    steps = [msg("a1"), msg("a2", tools=["t2"]), msg("a3"), {"op": "pause", "seconds": 8},
             {"op": "marker", "file": str(late)}, STAY]
    res = spec(world, steps, "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert not late.exists(), "the stop waited for a result although a message beyond the limit came"
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 3 and over_flags(messages) == [False, False, True]


@pytest.mark.lr(57)
def test_lr57_reaching_the_limit_is_message_limit_however_the_model_ends(world, check):
    res = spec(world, [msg("a1"), msg("a2")], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")


@pytest.mark.lr(57)
def test_lr57_the_limit_reached_while_results_are_awaited_is_message_limit_when_the_model_ends(world, check):
    """The L-th message's tool result never comes and the model ends by itself, exit 0 with a result event:
    the stop never began, yet the count reached the limit, so the attempt is MESSAGE_LIMIT and nothing is pushed."""
    res = spec(world, [msg("a1"), msg("a2", tools=["t2"])], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    _, _, finished = one_attempt(world, res)
    assert finished["outcome"] == "MESSAGE_LIMIT" and finished["messages"] == 2 and finished["exit_code"] == 0


@pytest.mark.lr(57)
def test_lr57_below_the_limit_the_run_goes_on(world, check):
    """A control for the test above: one message less than the limit is a normal end."""
    res = spec(world, [msg("a1"), msg("a2")], "--max-messages", "3")
    check.success(res)
    assert res.pushed


@pytest.mark.lr(57)
def test_lr57_subagent_messages_reach_the_limit(world, check):
    steps = [msg("main-1", tools=["tu-task"]), msg("sub-1", parent="tu-task"), msg("sub-2", parent="tu-task"),
             {"op": "pause", "seconds": 8}, msg("sub-3", parent="tu-task"), result("tu-task"), STAY]
    res = spec(world, steps, "--max-messages", "3")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 3
    assert [m["subagent"] for m in sorted(messages, key=lambda m: m["ordinal"])] == [False, True, True]


@pytest.mark.lr(57)
@windows_only
def test_lr57_lr58_a_model_that_ignores_the_break_is_ended_after_the_grace(world, check):
    res = spec(world, [{"op": "ignore_break"}, {"op": "burst", "count": 2, "prefix": "b"}, STAY],
               "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert GRACE - 1 <= res.duration < GRACE + 40, f"the attempt took {res.duration:.0f} s"
    assert wait_dead([res.model["pid"]]) == [], "the model is still running"


# ---------------------------------------------------------------- LR-58 and LR-64: the job object
def _family_steps(pids_file):
    return [{"op": "ignore_break"}, {"op": "spawn_family", "pids": str(pids_file)}]


@pytest.mark.lr(58)
@windows_only
def test_lr58_a_hidden_child_and_an_orphaned_grandchild_end_at_the_message_limit(world, check, tmp_path):
    pids_file = tmp_path / "family.json"
    pids = []
    try:
        res = spec(world, _family_steps(pids_file) + [{"op": "burst", "count": 2, "prefix": "b"}, STAY],
                   "--max-messages", "2")
        family = read_json(pids_file)
        pids = list(family.values())
        check.post_model_stop(res, "MESSAGE_LIMIT")
        alive = wait_dead([family["model"], family["hidden_child"], family["grandchild"]], seconds=5)
        assert alive == [], f"still running after MESSAGE_LIMIT: {alive} of {family}"
    finally:
        kill_all(pids)


@pytest.mark.lr(58)
@pytest.mark.lr(61)
@windows_only
def test_lr58_lr61_a_hidden_child_and_an_orphaned_grandchild_end_at_the_timeout(world, check, tmp_path):
    pids_file = tmp_path / "family.json"
    pids = []
    try:
        # A message every 25 s: three before the one-minute timeout, far below the limit of 7.
        res = spec(world, _family_steps(pids_file) + [{"op": "forever", "interval": 25, "prefix": "slow"}])
        family = read_json(pids_file)
        pids = list(family.values())
        check.post_model_stop(res, "TIMEOUT")
        assert res.duration < 60 + GRACE + 40, f"the attempt took {res.duration:.0f} s with timeout_minutes = 1"
        alive = wait_dead([family["model"], family["hidden_child"], family["grandchild"]], seconds=5)
        assert alive == [], f"still running after TIMEOUT: {alive} of {family}"
        _, messages, finished = one_attempt(world, res)
        assert finished["outcome"] == "TIMEOUT"
        assert 1 <= finished["messages"] < 80, "the timeout is not a separate bound"
    finally:
        kill_all(pids)


@pytest.mark.lr(58)
@windows_only
def test_lr58_children_left_by_a_model_that_ended_by_itself_are_ended(world, check, tmp_path):
    pids_file = tmp_path / "family.json"
    pids = []
    try:
        res = spec(world, [{"op": "spawn_family", "pids": str(pids_file)}, msg("m1")])
        family = read_json(pids_file)
        pids = list(family.values())
        check.success(res)
        assert wait_dead([family["hidden_child"], family["grandchild"]], seconds=5) == []
    finally:
        kill_all(pids)


@pytest.mark.lr(58)
@pytest.mark.lr(64)
@windows_only
def test_lr58_the_model_is_suspended_until_it_is_in_the_job(world, check, launcher, monkeypatch, tmp_path):
    early = tmp_path / "early"  # the fake writes it first of all, before it reads the prompt
    seen = {}
    real_add = launcher.job_add

    def watching_add(job, process):
        time.sleep(2.0)  # a model that was not suspended would have started by now
        seen["model_ran_before_assign"] = early.exists()
        seen["calls"] = seen.get("calls", 0) + 1
        return real_add(job, process)

    monkeypatch.setattr(launcher, "job_add", watching_add)
    res = world.run("spec", "--slug", SLUG, steps=[COMMIT, msg("m1")], extra_env={"FAKE_CLAUDE_EARLY": str(early)})
    check.success(res)
    assert early.exists(), "the harness wrote no early mark"
    assert seen == {"model_ran_before_assign": False, "calls": 1}


@pytest.mark.lr(58)
@pytest.mark.lr(64)
@windows_only
@pytest.mark.parametrize("seam", ["job_open", "job_add", "resume_process"])
def test_lr58_a_failed_job_setup_starts_nothing(world, check, launcher, monkeypatch, seam, tmp_path):
    def fail(*args, **kwargs):
        raise OSError("the job could not be set up")

    early = tmp_path / "early"  # the fake writes it first of all: absent means it never ran (amendment A2, R10)
    monkeypatch.setattr(launcher, seam, fail)
    res = world.run("spec", "--slug", SLUG, steps=[COMMIT, msg("m1")], extra_env={"FAKE_CLAUDE_EARLY": str(early)})
    check.stopped(res, "JOB_SETUP_FAILED")
    assert res.model is None and not early.exists(), "the model ran"
    assert not res.pushed
    reserved, messages, finished = one_attempt(world, res)
    assert finished["outcome"] == "JOB_SETUP_FAILED" and finished["messages"] == 0 and messages == []
    assert finished["exit_code"] is None, "LR-75: the model never ran, so its exit code is null"
    if seam != "job_open":
        assert wait_dead([logged_pid(res)], seconds=5) == [], "the suspended process was not terminated"
    second = spec(world, [msg("n1")])  # the seam still fails: a second reservation, a second failure
    check.stopped(second, "JOB_SETUP_FAILED")
    reserved2 = [r for r in world.ledger_records() if r["record"] == "attempt_reserved"][-1]
    assert reserved2["runs_before"] == 1, "the reserved run was given back"


@pytest.mark.lr(58)
@pytest.mark.lr(64)
@windows_only
@pytest.mark.parametrize("steps, extra", [
    ([msg("m1")], []),
    ([{"op": "burst", "count": 3, "prefix": "b"}, STAY], ["--max-messages", "2"]),
], ids=["ended-by-itself", "message-limit"])
def test_lr58_a_survivor_stops_the_run(world, check, launcher, monkeypatch, steps, extra):
    real_end = launcher.job_end

    def one_left(job):
        real_end(job)
        return 1

    monkeypatch.setattr(launcher, "job_end", one_left)
    res = spec(world, steps, *extra)
    check.post_model_stop(res, "PROCESS_SURVIVED")
    _, _, finished = one_attempt(world, res)
    assert finished["outcome"] == "PROCESS_SURVIVED"


@pytest.mark.lr(64)
@windows_only
def test_lr64_job_open_sets_kill_on_close_and_no_breakaway(launcher):
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [("a", ctypes.c_int64), ("b", ctypes.c_int64), ("LimitFlags", wintypes.DWORD),
                    ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", wintypes.DWORD),
                    ("f", ctypes.c_size_t), ("g", wintypes.DWORD), ("h", wintypes.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", ctypes.c_uint64 * 6), ("m", ctypes.c_size_t * 4)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                              ctypes.c_void_p]
    job = launcher.job_open()
    try:
        info = Extended()
        assert k32.QueryInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info), None)
        flags = info.basic.LimitFlags
        assert flags & 0x2000, "no JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE"
        assert not flags & 0x800, "JOB_OBJECT_LIMIT_BREAKAWAY_OK is set"
        assert not flags & 0x1000, "JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK is set"
    finally:
        launcher.job_close(job)


@pytest.mark.lr(64)
@windows_only
def test_lr64_the_job_kills_its_processes_when_closed(launcher):
    """KILL_ON_JOB_CLOSE: the model's tree dies with the launcher's handle."""
    job = launcher.job_open()
    with W.quiet_audit():
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x4)
    try:
        launcher.job_add(job, process)
        launcher.resume_process(process.pid)
        time.sleep(0.5)
        assert W.process_alive(process.pid)
        launcher.job_close(job)
        assert wait_dead([process.pid], seconds=10) == []
    finally:
        kill_all([process.pid])


@pytest.mark.lr(64)
@windows_only
def test_lr64_job_end_reports_zero_when_all_are_ended(launcher):
    job = launcher.job_open()
    with W.quiet_audit():
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x4)
    try:
        launcher.job_add(job, process)
        launcher.resume_process(process.pid)
        assert launcher.job_end(job) == 0
        assert wait_dead([process.pid], seconds=5) == []
    finally:
        launcher.job_close(job)
        kill_all([process.pid])


@pytest.mark.lr(64)
@windows_only
def test_lr64_a_killed_launcher_takes_the_model_with_it(tmp_path):
    """A launcher process that dies (here: killed) closes its job handle, and the job kills the model's
    tree (LR-58). The child imports the launcher and uses only the seams of LR-64."""
    pid_file = tmp_path / "sleeper.pid"
    script = (
        "import subprocess, sys, time\n"
        f"sys.path.insert(0, {str(W.LAUNCHER_DIR)!r})\n"
        "import xtl_launcher as L\n"
        "job = L.job_open()\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],"
        " creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x4)\n"
        "L.job_add(job, p)\n"
        "L.resume_process(p.pid)\n"
        f"open({str(pid_file)!r}, 'w').write(str(p.pid))\n"
        "time.sleep(120)\n")
    with W.quiet_audit():
        holder = subprocess.Popen([sys.executable, "-c", script])
    sleeper = None
    try:
        deadline = time.time() + 30
        while time.time() < deadline and not (pid_file.exists() and pid_file.read_text().strip()):
            time.sleep(0.1)
        sleeper = int(pid_file.read_text().strip())
        assert W.process_alive(sleeper)
        with W.quiet_audit():
            subprocess.run(["taskkill", "/F", "/PID", str(holder.pid)], capture_output=True)
        assert wait_dead([sleeper], seconds=10) == [], "the model outlived the launcher"
    finally:
        kill_all([p for p in (sleeper, holder.pid) if p])


# ---------------------------------------------------------------- LR-59
@pytest.mark.lr(59)
def test_lr59_agent_and_task_are_always_denied(world, check):
    res = spec(world, [msg("m1")])
    check.success(res)
    deny = json.loads(res.model["settings"])["permissions"]["deny"]
    assert "Agent" in deny and "Task" in deny
    assert deny.index("Agent") > deny.index("WebSearch") and deny.index("Task") > deny.index("WebSearch")


@pytest.mark.lr(59)
def test_lr59_task_and_fix_runs_deny_them_too(world, check):
    res = world.run("task", "--issue", str(W.ISSUE_NUMBER), steps=[{"op": "commit", "path": "app/thing.py"},
                                                                 msg("m1")])
    check.success(res)
    deny = json.loads(res.model["settings"])["permissions"]["deny"]
    assert {"Agent", "Task"} <= set(deny)
    assert argv_value(res, "--allowedTools").count("Agent") == 0
