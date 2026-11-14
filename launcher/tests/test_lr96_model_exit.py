"""LR-96: the model's own exited process, still listed outside the job, does not discard a finished run (HQ-TASK-M1-C2R
section 4, tests a to e). Written from the task and the contract before the repair; each test is marked LR-96.

The world lists, besides what the launcher sees, a record of the model's own process (its pid and its creation time)
outside the job, at the searches the test names, as run 2 of M1-C2 showed it (pid 27556 at the last search).
`end_process` is a stand-in here: no real process is opened or ended by these tests."""

from __future__ import annotations

import os
import sys

import pytest

from operator_kit import list_extra, once, stand_in_end, watch_model
from stage_a_kit import msg, of_kind, spec

windows_only = pytest.mark.skipif(os.name != "nt", reason="the job object and the process list exist on Windows only")
STAY = {"op": "pause", "seconds": 60}
OWN_LINE = "the model's own exited process was still listed"


def own_record(seen: dict, created: int | None = None) -> dict:
    run = seen["run"]
    return {"pid": run.process.pid, "ppid": os.getpid(), "image": "python.exe", "path": sys.executable,
            "parent_image": "python.exe", "parent_path": None,
            "created": seen["created"] if created is None else created, "in_job": False, "broker": None,
            "owner": "self", "session": 1, "same_session": True, "parent_owner": "self", "parent_in_job": False,
            "parent_alive": True}


def stream_ended(seen: dict) -> bool:
    return "run" in seen and not seen["run"].open_stream


def unended(world) -> list:
    return of_kind(world.ledger_records(), "process_unended")


# ---------------------------------------------------------------- a: the regression of run 2
@pytest.mark.lr(96)
@windows_only
def test_lr96_a_the_models_own_exited_process_at_the_last_search_does_not_stop_a_finished_run(
        world, check, launcher, monkeypatch):
    seen = watch_model(monkeypatch, launcher)
    list_extra(monkeypatch, launcher, lambda: [own_record(seen)] if stream_ended(seen) else [])
    ended = stand_in_end(monkeypatch, launcher, False)
    res = spec(world, [msg("m1")])
    check.success(res)
    pid = seen["run"].process.pid
    assert "PROCESS_OUTSIDE_JOB" not in res.log_text and "PROCESS_BEFORE_PUSH" not in res.log_text, res.describe()
    assert pid not in ended, "the model's own exited process was given to end_process"
    assert unended(world) == [], unended(world)
    lines = [ln for ln in res.log_text.splitlines() if OWN_LINE in ln]
    assert lines and f"pid {pid}" in lines[0], res.describe()


# ---------------------------------------------------------------- b: the grace after a stop, and the search after the end
@pytest.mark.lr(96)
@windows_only
def test_lr96_b_the_models_own_exited_process_during_the_grace_after_a_stop(world, check, launcher, monkeypatch):
    seen = watch_model(monkeypatch, launcher)
    list_extra(monkeypatch, launcher,
               lambda: [own_record(seen)] if "run" in seen and seen["run"].stop_began is not None else [])
    ended = stand_in_end(monkeypatch, launcher, False)
    res = spec(world, [msg("m1"), msg("m2"), msg("m3"), STAY], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    assert "PROCESS_OUTSIDE_JOB" not in res.log_text, res.describe()
    assert seen["run"].process.pid not in ended
    assert unended(world) == []
    assert OWN_LINE in res.log_text, res.describe()


@pytest.mark.lr(96)
@windows_only
def test_lr96_b_the_models_own_exited_process_in_the_search_after_the_end(world, check, launcher, monkeypatch):
    seen = watch_model(monkeypatch, launcher)
    state = {"ended": False}
    real_end = launcher.job_end

    def job_end(job):
        state["ended"] = True
        return real_end(job)

    monkeypatch.setattr(launcher, "job_end", job_end)
    list_extra(monkeypatch, launcher, lambda: [own_record(seen)] if state["ended"] else [])
    ended = stand_in_end(monkeypatch, launcher, False)
    res = spec(world, [msg("m1")])
    check.success(res)
    assert "PROCESS_SURVIVED" not in res.log_text, res.describe()
    assert seen["run"].process.pid not in ended
    assert unended(world) == []
    assert OWN_LINE in res.log_text, res.describe()


# ---------------------------------------------------------------- c: paired with a, the handle shows it still running
@pytest.mark.lr(96)
@windows_only
def test_lr96_c_the_models_own_process_outside_the_job_while_its_handle_shows_it_running_stops_the_run(
        world, check, launcher, monkeypatch):
    seen = watch_model(monkeypatch, launcher)
    list_extra(monkeypatch, launcher,
               lambda: [own_record(seen)] if ("run" in seen and seen["run"].count >= 1 and seen["run"].open_stream
                                              and seen["run"].stop_began is None) else [])
    ended = stand_in_end(monkeypatch, launcher, True)
    res = spec(world, [msg("m1"), STAY])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert seen["run"].process.pid in ended
    assert OWN_LINE not in res.log_text, res.describe()


# ---------------------------------------------------------------- d: the same pid with another creation time
@pytest.mark.lr(96)
@windows_only
def test_lr96_d_the_models_pid_with_another_creation_time_is_judged_as_today(world, check, launcher, monkeypatch):
    seen = watch_model(monkeypatch, launcher)
    list_extra(monkeypatch, launcher, once(lambda: stream_ended(seen), lambda: own_record(seen, created=seen["created"] + 1)))
    ended = stand_in_end(monkeypatch, launcher, False)
    res = spec(world, [msg("m1")])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert seen["run"].process.pid in ended
    assert OWN_LINE not in res.log_text, res.describe()
    assert len(unended(world)) == 1


# ---------------------------------------------------------------- e: no readable creation time, no rule
@pytest.mark.lr(96)
@windows_only
def test_lr96_e_without_the_models_creation_time_the_rule_does_not_apply(world, check, launcher, monkeypatch):
    monkeypatch.setattr(launcher, "process_created", lambda process: None, raising=False)
    seen = watch_model(monkeypatch, launcher)
    list_extra(monkeypatch, launcher, once(lambda: stream_ended(seen), lambda: own_record(seen)))
    stand_in_end(monkeypatch, launcher, False)
    res = spec(world, [msg("m1")])
    check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
    assert OWN_LINE not in res.log_text, res.describe()


@pytest.mark.lr(96)
@windows_only
def test_lr96_the_models_creation_time_comes_from_the_launchers_own_handle(launcher):
    """The handle's creation time equals the one the process list gives for the same process."""
    import subprocess

    import launcher_world as W
    with W.quiet_audit():
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
    try:
        entry = launcher._system_processes()[process.pid]
        assert launcher.process_created(process) == entry["created"]
    finally:
        process.kill()
        process.wait(timeout=10)
