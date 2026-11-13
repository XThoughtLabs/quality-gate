"""Stage A: the stream and the unit (LR-51, LR-52), a broken stream (LR-60) and the log (LR-62).

Written from LAUNCHER-CONTRACT.md section 12. Each test is named and marked by its rule."""

from __future__ import annotations

import pytest

import launcher_world as W
from stage_a_kit import (COMMIT, MESSAGE_FIELDS, RESULT_FIELDS, argv_value, msg, of_kind, one_attempt, result,
                         spec)


def counted_ids(messages):
    return [m["message_id"] for m in sorted(messages, key=lambda m: m["ordinal"])]


# ---------------------------------------------------------------- LR-51
@pytest.mark.lr(51)
def test_lr51_model_reads_the_stream_with_the_attempt_limit(world, check):
    res = spec(world, [msg("a1")])
    check.success(res)
    argv = res.model["argv"]
    assert argv[-3:] == ["--output-format", "stream-json", "--verbose"], argv
    assert argv.count("--output-format") == 1
    assert argv_value(res, "--max-turns") == str(W.MAX_TURNS)


@pytest.mark.lr(51)
def test_lr51_max_turns_is_the_effective_limit(world, check):
    res = spec(world, [msg("a1")], "--max-messages", "3")
    check.success(res)
    assert argv_value(res, "--max-turns") == "3"


# ---------------------------------------------------------------- LR-52
@pytest.mark.lr(52)
def test_lr52_fragments_with_one_id_count_once(world, check):
    steps = [msg("m1", text="first part"), msg("m1", tools=["t1"], text=None), result("t1"),
             msg("m1", text="a late fragment"), msg("m2")]
    res = spec(world, steps)
    check.success(res)
    _, messages, finished = one_attempt(world, res)
    assert counted_ids(messages) == ["m1", "m2"]
    assert [m["ordinal"] for m in sorted(messages, key=lambda m: m["ordinal"])] == [1, 2]
    assert finished["messages"] == 2 and finished["outcome"] == "DONE"
    assert all(set(m) == MESSAGE_FIELDS for m in messages), messages
    assert all(m["generated"] is False and m["over_limit"] is False for m in messages)


@pytest.mark.lr(52)
def test_lr52_events_without_a_usable_id_count_each(world, check):
    steps = [msg(None), msg(None), msg(raw_id=123), msg(raw_id=""), msg(raw_id="x" * 257), msg(raw_id=None)]
    res = spec(world, steps)
    check.success(res)
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 6
    ordered = sorted(messages, key=lambda m: m["ordinal"])
    assert [m["message_id"] for m in ordered] == [f"gen-{n}" for n in range(1, 7)]
    assert all(m["generated"] is True for m in ordered)


@pytest.mark.lr(52)
def test_lr52_an_id_of_256_characters_is_an_id(world, check):
    long_id = "y" * 256
    res = spec(world, [msg(raw_id=long_id), msg(raw_id=long_id)])
    check.success(res)
    _, messages, _ = one_attempt(world, res)
    assert counted_ids(messages) == [long_id]
    assert messages[0]["generated"] is False


@pytest.mark.lr(52)
def test_lr52_subagent_messages_count_like_any_other(world, check):
    steps = [msg("main-1", tools=["tu-task"]), msg("sub-1", parent="tu-task"), msg("sub-2", parent="tu-task"),
             msg("sub-2", parent="tu-task", text="its second fragment"), result("tu-task"), msg("main-2")]
    res = spec(world, steps)
    check.success(res)
    _, messages, finished = one_attempt(world, res)
    ordered = sorted(messages, key=lambda m: m["ordinal"])
    assert [m["message_id"] for m in ordered] == ["main-1", "sub-1", "sub-2", "main-2"]
    assert [m["subagent"] for m in ordered] == [False, True, True, False]
    assert finished["messages"] == 4


@pytest.mark.lr(52)
def test_lr52_other_events_never_count(world, check):
    steps = [{"op": "event", "event": {"type": "user", "message": {"role": "user", "content": "hi"}}},
             {"op": "api_retry", "error": "rate_limit"},
             {"op": "event", "event": {"type": "system", "subtype": "init"}},
             {"op": "event", "event": {"type": "stream_event", "event": {"type": "message_start"}}},
             {"op": "event", "event": {"type": "result", "subtype": "success", "num_turns": 2}},
             {"op": "event", "event": {"message": {"id": "no-type"}}},
             msg("only-one")]
    res = spec(world, steps)
    check.success(res)
    _, messages, finished = one_attempt(world, res)
    assert counted_ids(messages) == ["only-one"] and finished["messages"] == 1


# ---------------------------------------------------------------- LR-60
@pytest.mark.lr(60)
def test_lr60_lines_that_are_not_json_objects_do_not_count(world, check):
    token_shape = "ghp_" + "A" * 30
    long_bad = f"NOT-JSON-MARK {token_shape} " + "z" * 500
    steps = [{"op": "line", "text": long_bad}, {"op": "line", "text": "[1, 2, 3]"},
             {"op": "line", "text": '"just a string"'}, {"op": "line", "hex": "fffe7b7d"},
             {"op": "line", "text": "   "}, msg("m1")]
    res = spec(world, steps)
    check.success(res)
    _, messages, finished = one_attempt(world, res)
    assert counted_ids(messages) == ["m1"] and finished["messages"] == 1
    assert "NOT-JSON-MARK" in res.log_text, "the bad line is not logged"
    assert "z" * 250 not in res.log_text, "the bad line is not cut to 200 characters"
    assert token_shape not in res.log_text, "the bad line is not scrubbed"


@pytest.mark.lr(60)
def test_lr60_ten_bad_lines_are_tolerated(world, check):
    res = spec(world, [{"op": "line", "text": f"bad {n}"} for n in range(10)] + [msg("m1")])
    check.success(res)


@pytest.mark.lr(60)
def test_lr60_more_than_ten_bad_lines_stop_the_attempt(world, check):
    steps = [{"op": "line", "text": f"bad {n}"} for n in range(11)] + [{"op": "pause", "seconds": 60}]
    res = spec(world, steps)
    check.post_model_stop(res, "STREAM_UNREADABLE")
    assert res.duration < 45, f"the attempt ran {res.duration:.0f} s"
    _, _, finished = one_attempt(world, res)
    assert finished["outcome"] == "STREAM_UNREADABLE"


@pytest.mark.lr(60)
def test_lr60_a_line_over_32_mib_stops_the_attempt(world, check):
    steps = [{"op": "big_line", "bytes": 32 * 1024 * 1024 + 1}, {"op": "pause", "seconds": 60}]
    res = spec(world, steps)
    check.post_model_stop(res, "STREAM_UNREADABLE")
    _, _, finished = one_attempt(world, res)
    assert finished["outcome"] == "STREAM_UNREADABLE"


@pytest.mark.lr(60)
def test_lr60_a_long_line_under_the_cap_is_only_a_bad_line(world, check):
    res = spec(world, [{"op": "big_line", "bytes": 1024 * 1024}, msg("m1")])
    check.success(res)


@pytest.mark.lr(60)
def test_lr60_no_result_event_and_exit_0_stops(world, check):
    res = spec(world, [msg("m1"), {"op": "no_result"}])
    check.post_model_stop(res, "STREAM_UNREADABLE")
    assert "model stream: no result event" in res.log_text
    _, messages, finished = one_attempt(world, res)
    assert finished["result"] is None and finished["messages"] == 1 and finished["exit_code"] == 0
    assert finished["outcome"] == "STREAM_UNREADABLE"


@pytest.mark.lr(60)
def test_lr60_a_crash_in_the_middle_of_the_stream(world, check):
    res = spec(world, [msg("m1"), msg("m2"), {"op": "crash", "code": 3}])
    check.post_model_stop(res, "MODEL_FAILED")
    assert "model stream: no result event" in res.log_text
    _, messages, finished = one_attempt(world, res)
    assert counted_ids(messages) == ["m1", "m2"]
    assert finished["messages"] == 2 and finished["result"] is None and finished["exit_code"] == 3
    assert finished["outcome"] == "MODEL_FAILED"


# ---------------------------------------------------------------- LR-62
@pytest.mark.lr(62)
def test_lr62_result_fields_come_from_the_result_event(world, check):
    res = spec(world, [msg("m1"), {"op": "result", "text": "RESULT-MARK " + "r" * 2500}])
    check.success(res)
    _, _, finished = one_attempt(world, res)
    assert finished["result"] == RESULT_FIELDS
    assert finished["exit_code"] == 0
    for field, value in RESULT_FIELDS.items():
        assert f"model {field}: {value}" in res.log_text, field
    assert "RESULT-MARK" in res.log_text and "r" * 2001 not in res.log_text
    assert "RESULT-MARK" not in world.ledger_file.read_text(encoding="utf-8"), "result text in the ledger"


@pytest.mark.lr(62)
def test_lr62_api_retry_is_logged_and_not_counted(world, check):
    res = spec(world, [{"op": "api_retry", "error": "rate_limit"}, msg("m1")])
    check.success(res)
    assert "api_retry" in res.log_text and "rate_limit" in res.log_text
    _, messages, _ = one_attempt(world, res)
    assert len(messages) == 1


@pytest.mark.lr(62)
def test_lr62_log_names_each_message_without_its_content(world, check):
    res = spec(world, [msg("m1", text="CONTENT-MARK-1"), msg(None, text="CONTENT-MARK-2")])
    check.success(res)
    assert "CONTENT-MARK" not in res.log_text
    assert "message 1" in res.log_text and "message 2" in res.log_text
    assert "limit 7" in res.log_text, "the effective limit is not logged"


@pytest.mark.lr(62)
def test_lr62_the_commit_steps_still_reach_the_remote(world, check):
    """A control: the stream changes nothing in what a finished run pushes (LR-39)."""
    res = spec(world, [msg("m1")])
    check.success(res)
    assert res.pushed
    assert of_kind(world.ledger_records(), "attempt_finished")[0]["outcome"] == "DONE"
    assert COMMIT["path"] in W.tree_files(world.remote, f"refs/heads/spec/{'s1'}")
