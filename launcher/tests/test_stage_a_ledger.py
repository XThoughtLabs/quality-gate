"""Stage A: limits (LR-53), the task (LR-54), the ledger (LR-55) and task totals (LR-56).

Written from LAUNCHER-CONTRACT.md section 12. Each test is named and marked by its rule."""

from __future__ import annotations

import _thread
import json
import os
import threading
import time

import pytest

import launcher_world as W
from conftest import secrets_of
from stage_a_kit import (FINISHED_FIELDS, RESERVED_FIELDS, SLUG, TASK, TIME_RE, argv_value, attempt_of,
                         finished_record, message_record, msg, of_kind, one_attempt, reserved_record, spec)


def assert_stopped_before_anything(res, check, code):
    """LR-56: for task and spec, the budget check runs right after the preflight."""
    check.stopped(res, code)
    assert res.requests == [], [f"{r['method']} {r['path']}" for r in res.requests]
    assert res.run_dirs == []
    assert res.model is None
    assert not any("clone" in (e.get("argv") or []) for e in res.events)


# ---------------------------------------------------------------- LR-53
@pytest.mark.lr(53)
@pytest.mark.parametrize("key", ["max_messages_attempt", "max_messages_task", "max_runs_task", "ledger_file"])
def test_lr53_lr55_new_keys_are_required(world, check, key):
    del world.config[key]
    world.write_files()
    check.config_error(world.run("check"))


@pytest.mark.lr(53)
@pytest.mark.parametrize("value", [0, -1, True, "80", 1.5])
@pytest.mark.parametrize("key", ["max_messages_attempt", "max_messages_task", "max_runs_task"])
def test_lr53_limits_must_be_positive_integers(world, check, key, value):
    world.set_config(**{key: value})
    check.config_error(world.run("check"))


@pytest.mark.lr(55)
@pytest.mark.parametrize("value", ["ledger.jsonl", "", "\\\\server\\share\\ledger.jsonl", 5])
def test_lr55_ledger_file_must_be_a_full_drive_path(world, check, value):
    world.set_config(ledger_file=value)
    check.config_error(world.run("check"))


@pytest.mark.lr(53)
@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", "3\n", ""])
def test_lr53_max_messages_must_be_a_positive_integer(world, check, value):
    check.config_error(world.run("spec", "--slug", SLUG, "--max-messages", value))


@pytest.mark.lr(53)
@pytest.mark.parametrize("command", [["task", "--issue", "5"], ["spec", "--slug", SLUG], ["fix", "--pr", "7"]])
def test_lr53_every_run_command_takes_max_messages(world, command):
    world.api.issues.clear()  # the cheapest way to a stop that is not a usage error
    res = world.run(*command, "--max-messages", "4")
    assert res.code in (0, 1), res.describe()
    assert not res.last.startswith("CONFIG:"), res.describe()


@pytest.mark.lr(53)
@pytest.mark.parametrize("config_limit, extra, expected", [
    (3, [], 3),                        # the configuration is the smallest
    (80, ["--max-messages", "2"], 2),  # the command line lowers it
    (80, ["--max-messages", "100"], W.MAX_TURNS),  # but never raises it: quality.toml's max_turns stays
    (5, ["--max-messages", "6"], 5),   # nor above the configuration
])
def test_lr53_the_effective_limit_is_the_smallest(world, check, config_limit, extra, expected):
    world.set_config(max_messages_attempt=config_limit)
    res = spec(world, [msg("m1")], *extra)
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["limit"] == expected
    assert argv_value(res, "--max-turns") == str(expected)


@pytest.mark.lr(53)
def test_lr53_the_task_remainder_lowers_the_limit(world, check):
    world.seed_ledger([reserved_record(TASK, "old-1", 7), finished_record("old-1", 237)])
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["limit"] == 3 and reserved["messages_before"] == 237
    assert argv_value(res, "--max-turns") == "3"


# ---------------------------------------------------------------- LR-54
@pytest.mark.lr(54)
def test_lr54_tasks_by_command(world, check):
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["task"] == TASK and reserved["role"] == "spec"


@pytest.mark.lr(54)
def test_lr54_a_task_run_belongs_to_its_issue(world, check):
    res = world.run("task", "--issue", str(W.ISSUE_NUMBER), steps=[
        {"op": "commit", "path": "app/thing.py"}, msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["task"] == f"issue-{W.ISSUE_NUMBER}" and reserved["role"] == "task"


@pytest.mark.lr(54)
def test_lr54_a_fix_round_is_charged_to_its_issue(world, check):
    world.set_up_fix(comments=False)
    world.seed_ledger([reserved_record("issue-7", "old-1", 80, role="task"), finished_record("old-1", 240)])
    res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[{"op": "commit", "path": "app/thing.py"}, msg("m1")])
    check.stopped(res, "BUDGET_EXHAUSTED")
    assert res.model is None, "the model ran"
    assert world.api.requests_to("GET", rf"/pulls/{W.PR_NUMBER}$"), "the PR was not read"
    assert of_kind(world.ledger_records(), "attempt_reserved") == [reserved_record("issue-7", "old-1", 80,
                                                                                   role="task")]


@pytest.mark.lr(54)
def test_lr54_a_fix_round_of_another_issue_is_not_charged(world, check):
    """A control for the test above: issue 5's budget does not stop PR 7's round."""
    world.set_up_fix(comments=False)
    world.seed_ledger([reserved_record("issue-5", "old-1", 80, role="task"), finished_record("old-1", 240)])
    res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[{"op": "commit", "path": "app/thing.py"}, msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["task"] == "issue-7" and reserved["role"] == "fix"


@pytest.mark.lr(54)
def test_lr54_the_fix_task_is_the_branchs_issue_not_the_prs_number(world, check):
    """PR 7's branch names issue 12: the round is charged to issue-12, not to issue-7."""
    world.set_up_fix(comments=False)
    with W.quiet_audit():
        W.git("--git-dir", str(world.remote), "update-ref", "refs/heads/ai/12-fix-the-thing", world.facts.pr_head)
    world.set_up_pr(head__ref="ai/12-fix-the-thing")
    world.seed_ledger([reserved_record("issue-12", "old-1", 80, role="task"), finished_record("old-1", 240)])
    res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[{"op": "commit", "path": "app/thing.py"}, msg("m1")])
    check.stopped(res, "BUDGET_EXHAUSTED")
    assert res.model is None


@pytest.mark.lr(54)
@pytest.mark.parametrize("ref", ["ai/thing", "ai/-7-thing", "ai/07-thing", "ai/7"])
def test_lr54_a_fix_head_without_the_issue_number_is_refused(world, check, ref):
    world.set_up_fix(comments=False)
    world.set_up_pr(head__ref=ref)
    res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[{"op": "commit", "path": "app/thing.py"}, msg("m1")])
    check.stopped(res, "NOT_A_FIX_TARGET")
    assert res.model is None


# ---------------------------------------------------------------- LR-55
@pytest.mark.lr(55)
def test_lr55_the_records_of_one_attempt(world, check):
    res = spec(world, [msg("m1"), msg("m2")])
    check.success(res)
    records = world.ledger_records()
    attempt = attempt_of(res)
    assert [r["record"] for r in records] == ["attempt_reserved", "message", "message", "attempt_finished"]
    reserved, m1, m2, finished = records
    assert set(reserved) == RESERVED_FIELDS and set(finished) == FINISHED_FIELDS
    assert reserved == {**reserved, "task": TASK, "attempt": attempt, "role": "spec", "limit": W.MAX_TURNS,
                        "max_messages_task": 240, "max_runs_task": 3, "messages_before": 0, "runs_before": 0}
    assert [m1["ordinal"], m2["ordinal"]] == [1, 2] and m1["attempt"] == m2["attempt"] == attempt
    assert finished["attempt"] == attempt and finished["messages"] == 2 and finished["outcome"] == "DONE"
    for record in records:
        assert TIME_RE.fullmatch(record["time"]), record
    raw = world.ledger_file.read_bytes()
    assert raw.endswith(b"\n") and b"\r" not in raw
    assert all(isinstance(json.loads(line), dict) for line in raw.split(b"\n") if line)


@pytest.mark.lr(55)
def test_lr55_the_reservation_is_on_disk_before_the_model_starts(world, check, tmp_path):
    copy = tmp_path / "ledger-at-start.jsonl"
    res = spec(world, [{"op": "snapshot", "src": str(world.ledger_file), "dst": str(copy)}, msg("m1")])
    check.success(res)
    seen = [json.loads(line) for line in copy.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["record"] for r in seen] == ["attempt_reserved"]
    assert seen[0]["attempt"] == attempt_of(res)


@pytest.mark.lr(55)
def test_lr55_the_ledger_appends_and_never_rewrites(world, check):
    world.seed_ledger([reserved_record("spec-other", "old-1", 7), message_record("old-1", 1),
                       finished_record("old-1", 1)])
    before = world.ledger_file.read_bytes()
    res = spec(world, [msg("m1")])
    check.success(res)
    after = world.ledger_file.read_bytes()
    assert after.startswith(before) and len(after) > len(before)


@pytest.mark.lr(55)
def test_lr55_no_secret_and_no_prompt_text_in_the_ledger(world, check, test_key):
    res = world.run("task", "--issue", str(W.ISSUE_NUMBER), steps=[
        {"op": "commit", "path": "app/thing.py"}, msg("m1", text="MODEL-TEXT-MARK"),
        {"op": "result", "text": "RESULT-TEXT-MARK"}])
    check.success(res)
    text = world.ledger_file.read_text(encoding="utf-8")
    for secret in secrets_of(res, test_key):
        assert secret not in text
    for mark in ("ISSUE-BODY-MARK", "EXECUTOR-TEMPLATE-START", W.ISSUE_TITLE, "MODEL-TEXT-MARK",
                 "RESULT-TEXT-MARK"):
        assert mark not in text, mark


@pytest.mark.lr(55)
def test_lr55_the_ledger_and_its_lock_are_denied_to_the_model(world, check):
    res = spec(world, [msg("m1")])
    check.success(res)
    deny = set(json.loads(res.model["settings"])["permissions"]["deny"])
    for path in (str(world.ledger_file), str(world.ledger_file) + ".lock"):
        ref = W.claude_path_ref(path)
        for tool in ("Read", "Grep", "Glob", "Edit", "Write"):
            assert f"{tool}({ref})" in deny, (tool, ref)


@pytest.mark.lr(55)
def test_lr55_the_ledger_folder_is_created(world, check, tmp_path):
    world.set_config(ledger_file=str(tmp_path / "new" / "deeper" / "ledger.jsonl"))
    world.ledger_file = tmp_path / "new" / "deeper" / "ledger.jsonl"
    res = spec(world, [msg("m1")])
    check.success(res)
    assert [r["record"] for r in world.ledger_records()] == ["attempt_reserved", "message", "attempt_finished"]


GOOD = json.dumps(reserved_record("spec-other", "old-1", 7), sort_keys=True).encode()


@pytest.mark.lr(55)
@pytest.mark.parametrize("raw", [
    b"garbage\n",
    b'{"record": "attempt_reserved"}\n',
    b"[1, 2]\n",
    GOOD,  # a last line without its newline
    GOOD + b"\n" + GOOD + b"\n",  # one attempt reserved twice
    json.dumps(finished_record("never-reserved", 1)).encode() + b"\n",
    json.dumps(message_record("never-reserved", 1)).encode() + b"\n",
    json.dumps({"record": "something_else", "attempt": "x"}).encode() + b"\n",
    json.dumps({**reserved_record("spec-other", "old-1", 7), "limit": "7"}).encode() + b"\n",
], ids=["garbage", "missing-fields", "not-an-object", "no-final-newline", "reserved-twice",
        "finished-unreserved", "message-unreserved", "unknown-record", "ill-typed-limit"])
def test_lr55_an_unreadable_ledger_stops_before_anything(world, check, raw):
    world.seed_ledger([], raw=raw)
    res = spec(world, [msg("m1")])
    assert_stopped_before_anything(res, check, "LEDGER_FAILED")
    assert world.ledger_file.read_bytes() == raw, "the ledger was changed"


@pytest.mark.lr(55)
def test_lr55_a_ledger_that_cannot_be_written_stops_before_the_model(world, check, tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")
    world.set_config(ledger_file=str(blocker / "ledger.jsonl"))  # its folder is a file
    res = spec(world, [msg("m1")])
    check.stopped(res, "LEDGER_FAILED")
    assert res.model is None


@pytest.mark.lr(55)
@pytest.mark.skipif(os.name != "nt", reason="the lock of LR-55 is taken with msvcrt on Windows; fcntl elsewhere")
def test_lr55_a_lock_held_by_another_launcher_stops_the_run(world, check):
    import msvcrt

    world.ledger_file.parent.mkdir(parents=True, exist_ok=True)
    lock = open(str(world.ledger_file) + ".lock", "a+b")
    try:
        os.lseek(lock.fileno(), 0, 0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        res = spec(world, [msg("m1")])
    finally:
        os.lseek(lock.fileno(), 0, 0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        lock.close()
    assert_stopped_before_anything(res, check, "LEDGER_FAILED")
    assert world.ledger_records() == []


# ---------------------------------------------------------------- LR-56
@pytest.mark.lr(56)
def test_lr56_used_up_messages_stop_before_anything(world, check):
    world.seed_ledger([reserved_record(TASK, "old-1", 80), finished_record("old-1", 240)])
    before = world.ledger_file.read_bytes()
    res = spec(world, [msg("m1")])
    assert_stopped_before_anything(res, check, "BUDGET_EXHAUSTED")
    assert world.ledger_file.read_bytes() == before, "an attempt was reserved"


@pytest.mark.lr(56)
def test_lr56_one_message_left_runs_with_limit_one(world, check):
    world.seed_ledger([reserved_record(TASK, "old-1", 80), finished_record("old-1", 239)])
    res = spec(world, [msg("m1")])
    check.stopped(res, "MESSAGE_LIMIT")  # its one message reaches the limit (LR-57)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["limit"] == 1 and reserved["messages_before"] == 239 and reserved["runs_before"] == 1


@pytest.mark.lr(56)
def test_lr56_used_up_runs_stop_before_anything(world, check):
    seed = []
    for n in range(3):
        seed += [reserved_record(TASK, f"old-{n}", 7), finished_record(f"old-{n}", 0)]
    world.seed_ledger(seed)
    res = spec(world, [msg("m1")])
    assert_stopped_before_anything(res, check, "BUDGET_EXHAUSTED")


@pytest.mark.lr(56)
def test_lr56_two_runs_used_leave_one(world, check):
    seed = []
    for n in range(2):
        seed += [reserved_record(TASK, f"old-{n}", 7), finished_record(f"old-{n}", 0)]
    world.seed_ledger(seed)
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["runs_before"] == 2


@pytest.mark.lr(56)
def test_lr56_other_tasks_are_not_counted(world, check):
    world.seed_ledger([reserved_record("spec-other", "old-1", 80), finished_record("old-1", 240),
                       reserved_record("issue-5", "old-2", 80, role="task")])
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["messages_before"] == 0 and reserved["runs_before"] == 0


@pytest.mark.lr(56)
def test_lr56_an_unfinished_attempt_is_charged_its_limit(world, check):
    world.set_config(max_messages_task=55)
    world.seed_ledger([reserved_record(TASK, "old-1", 50), message_record("old-1", 1)])
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["messages_before"] == 50 and reserved["runs_before"] == 1
    assert reserved["limit"] == 5


@pytest.mark.lr(56)
def test_lr56_an_unfinished_attempt_with_more_records_is_charged_them(world, check):
    world.seed_ledger([reserved_record(TASK, "old-1", 2)] +
                      [message_record("old-1", n, over=n > 2) for n in range(1, 5)])
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["messages_before"] == 4


@pytest.mark.lr(56)
def test_lr56_a_finished_attempt_is_charged_the_larger_count(world, check):
    world.seed_ledger([reserved_record(TASK, "old-1", 7)] + [message_record("old-1", n) for n in (1, 2, 3)] +
                      [finished_record("old-1", 1), reserved_record(TASK, "old-2", 7), finished_record("old-2", 2)])
    res = spec(world, [msg("m1")])
    check.success(res)
    reserved, _, _ = one_attempt(world, res)
    assert reserved["messages_before"] == 3 + 2


@pytest.mark.lr(56)
def test_lr56_a_failed_attempt_keeps_its_charge(world, check):
    first = spec(world, [msg("m1"), msg("m2"), {"op": "crash", "code": 4}])
    check.post_model_stop(first, "MODEL_FAILED")
    second = spec(world, [msg("n1")])
    check.success(second)
    reserved, _, _ = one_attempt(world, second)
    assert reserved["messages_before"] == 2 and reserved["runs_before"] == 1


@pytest.mark.lr(56)
def test_lr56_an_interrupted_attempt_is_counted_for_its_continuation(world, check, tmp_path):
    """Ctrl+C arrives as KeyboardInterrupt in the launcher's own thread while the model runs."""
    marker = tmp_path / "three-sent"

    def interrupt_when_ready():
        deadline = time.time() + 120
        while time.time() < deadline and not marker.exists():
            time.sleep(0.05)
        time.sleep(1.0)
        _thread.interrupt_main()

    helper = threading.Thread(target=interrupt_when_ready, daemon=True)
    helper.start()
    first = spec(world, [msg("m1"), msg("m2"), msg("m3"), {"op": "marker", "file": str(marker)},
                         {"op": "pause", "seconds": 90}])
    helper.join(timeout=5)
    check.stopped(first, "INTERRUPTED")
    assert not first.pushed
    _, messages, finished = one_attempt(world, first)
    assert len(messages) == 3 and finished["messages"] == 3 and finished["outcome"] == "INTERRUPTED"
    second = spec(world, [msg("n1")])
    check.success(second)
    reserved, _, _ = one_attempt(world, second)
    assert reserved["messages_before"] == 3 and reserved["runs_before"] == 1
