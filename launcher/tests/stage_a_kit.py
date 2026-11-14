"""Shared helpers for the stage A tests (LR-51 to LR-66), written from the contract."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import launcher_world as W

SLUG = "s1"
TASK = f"spec-{SLUG}"
GRACE = 10  # LR-58: the fixed grace period, in seconds
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
COMMIT = {"op": "commit", "path": "acceptance/test_stage_a.py", "text": "def test_a():\n    assert True\n"}
RESERVED_FIELDS = {"record", "task", "attempt", "role", "time", "limit", "max_messages_task", "max_runs_task",
                   "messages_before", "runs_before"}
MESSAGE_FIELDS = {"record", "attempt", "message_id", "generated", "ordinal", "time", "over_limit", "subagent"}
FINISHED_FIELDS = {"record", "attempt", "messages", "outcome", "result", "exit_code", "time", "count_complete"}  # LR-71
RESULT_FIELDS = {"num_turns": 13, "is_error": False, "subtype": "success", "total_cost_usd": 0.4321,
                 "duration_ms": 98765}


def spec(world, steps, *extra, commit=True):
    """A spec run (no venv, so it is quick) whose model commits first, then runs `steps`."""
    return world.run("spec", "--slug", SLUG, *extra, steps=([COMMIT] if commit else []) + list(steps))


def msg(mid=None, tools=(), parent=None, **more):
    step = {"op": "assistant", "tools": list(tools), "parent": parent, **more}
    if mid is not None:
        step["id"] = mid
    return step


def result(*ids):
    return {"op": "tool_result", "ids": list(ids)}


def of_kind(records, kind, attempt=None):
    return [r for r in records if r.get("record") == kind and (attempt is None or r.get("attempt") == attempt)]


def attempt_of(res) -> str:
    """The run id of LR-17, which LR-55 makes the attempt id."""
    return res.run_dir.name


def one_attempt(world, res):
    """The ledger records of the run's own attempt: (reserved, messages, finished)."""
    records = world.ledger_records()
    attempt = attempt_of(res)
    reserved = of_kind(records, "attempt_reserved", attempt)
    finished = of_kind(records, "attempt_finished", attempt)
    assert len(reserved) == 1, (attempt, records)
    assert len(finished) <= 1, (attempt, records)
    return reserved[0], of_kind(records, "message", attempt), (finished[0] if finished else None)


def reserved_record(task, attempt, limit, *, role="spec", messages_before=0, runs_before=0, max_task=240,
                    max_runs=3):
    return {"record": "attempt_reserved", "task": task, "attempt": attempt, "role": role,
            "time": "2026-11-13T00:00:00Z", "limit": limit, "max_messages_task": max_task,
            "max_runs_task": max_runs, "messages_before": messages_before, "runs_before": runs_before}


def message_record(attempt, ordinal, *, over=False):
    return {"record": "message", "attempt": attempt, "message_id": f"m-{attempt}-{ordinal}", "generated": False,
            "ordinal": ordinal, "time": "2026-11-13T00:00:01Z", "over_limit": over, "subagent": False}


def finished_record(attempt, messages, outcome="DONE"):
    return {"record": "attempt_finished", "attempt": attempt, "messages": messages, "outcome": outcome,
            "result": None, "exit_code": 0, "time": "2026-11-13T00:00:02Z"}


def argv_value(res, flag):
    argv = res.model["argv"]
    return argv[argv.index(flag) + 1]


def wait_dead(pids, seconds=10.0):
    deadline = time.time() + seconds
    while time.time() < deadline and any(W.process_alive(p) for p in pids):
        time.sleep(0.2)
    return [p for p in pids if W.process_alive(p)]


def kill_all(pids):
    for pid in pids:
        if W.process_alive(pid):
            W.kill_pid(pid)


def logged_pid(res) -> int:
    """LR-62: the log names the model's process id."""
    found = re.findall(r"model pid (\d+)", res.log_text)
    assert found, res.describe()
    return int(found[-1])


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


IS_WINDOWS = os.name == "nt"
