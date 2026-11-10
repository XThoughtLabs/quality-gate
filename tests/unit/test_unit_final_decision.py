"""The one decision of round 2, called directly: gate.report.final_decision (CONTRACTS.md section 8.5).

Each case changes one fact of an otherwise ready world, so that each rule of the order can be seen on its own.
"""

from __future__ import annotations

import copy

import pytest

pytestmark = pytest.mark.req("FN-1", "FN-2", "FN-4", "FN-5", "FN-8")

HEAD = "1" * 40
OTHER = "2" * 40
REVIEWER = {"login": "example-reviewer[bot]", "id": 9001}
SIX = ["gate/env", "gate/tests", "gate/acceptance", "gate/guard", "gate/security", "gate/report"]
SEVEN = SIX + ["gate/archive"]


def creator(kind="reviewer"):
    return {
        "reviewer": {"login": "example-reviewer[bot]", "id": 9001, "type": "Bot"},
        "ceo": {"login": "example-owner", "id": 501, "type": "User"},
        "executor": {"login": "example-executor[bot]", "id": 9002, "type": "Bot"},
        "other-id": {"login": "example-reviewer[bot]", "id": 4242, "type": "Bot"},
        "not-a-bot": {"login": "example-reviewer[bot]", "id": 9001, "type": "User"},
        "other-login": {"login": "someone-else[bot]", "id": 9001, "type": "Bot"},
    }[kind]


def review(state, who="reviewer", context="independent-review"):
    return {"context": context, "state": state, "creator": creator(who)}


def run(name, conclusion="success", status="completed", app=15368, head=HEAD, run_id=1):
    return {"id": run_id, "name": name, "head_sha": head, "status": status, "conclusion": conclusion, "app": {"id": app}}


def world(mode="finalize", **change):
    facts = {
        "mode": mode,
        "head_sha": HEAD,
        "gate_verdict": "ready-for-human",
        "gate_reasons": [],
        "archive_ok": True,
        "check_runs": [run(n, run_id=i + 1) for i, n in enumerate(SEVEN if mode == "finalize" else SIX)],
        "statuses": [review("success")],
        "reviewer": dict(REVIEWER),
        "own_checks": {"gate/archive": "success"} if mode == "archive" else None,
    }
    facts.update(change)
    return facts


def decide(**facts):
    from gate.report import final_decision

    return final_decision(**copy.deepcopy(facts))


def codes(decision):
    return [item["code"] for item in decision["reasons"]]


@pytest.mark.parametrize("mode", ["archive", "finalize"])
def test_everything_right_is_ready_for_human_completed_success(mode):
    d = decide(**world(mode))
    assert (d["post"], d["status"], d["conclusion"], d["verdict"]) == (True, "completed", "success", "ready-for-human")


@pytest.mark.parametrize("mode", ["archive", "finalize"])
@pytest.mark.parametrize("statuses,code", [
    ([], "REVIEW_MISSING"),
    (None, "REVIEW_UNREADABLE"),
    ([review("success", context="ci/other")], "REVIEW_MISSING"),
    ([review("success", who="ceo")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("success", who="executor")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("success", who="other-id")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("success", who="not-a-bot")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("success", who="other-login")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("success", who="ceo"), review("success")], "REVIEW_NOT_BY_REVIEWER"),
    ([review("weird")], "REVIEW_UNREADABLE"),
    (["not-a-status"], "REVIEW_MISSING"),
], ids=["none", "unreadable", "other-context", "ceo", "executor", "other-id", "not-a-bot", "other-login", "newest-by-another",
        "unknown-state", "junk"])
def test_no_valid_review_keeps_gate_final_in_progress(mode, statuses, code):
    d = decide(**world(mode, statuses=statuses))
    assert (d["post"], d["status"], d["conclusion"], d["verdict"]) == (True, "in_progress", None, "awaiting-review")
    assert code in codes(d)


def test_the_reviewer_unreadable_is_never_success():
    d = decide(**world(reviewer=None))
    assert d["status"] == "in_progress" and "REVIEW_UNREADABLE" in codes(d)


def test_a_pending_review_in_the_archive_job_waits():
    d = decide(**world("archive", statuses=[review("pending")]))
    assert (d["post"], d["status"], d["verdict"]) == (True, "in_progress", "awaiting-review")
    assert "REVIEW_PENDING" in codes(d)


def test_a_pending_review_in_finalize_posts_nothing():
    d = decide(**world("finalize", statuses=[review("pending")]))
    assert d["post"] is False and d["status"] is None and d["conclusion"] is None


@pytest.mark.parametrize("mode", ["archive", "finalize"])
@pytest.mark.parametrize("state", ["failure", "error"])
def test_a_failed_review_is_blocked_review_failed(mode, state):
    d = decide(**world(mode, statuses=[review(state)]))
    assert (d["status"], d["conclusion"], d["verdict"]) == ("completed", "failure", "blocked")
    assert "REVIEW_FAILED" in codes(d)


@pytest.mark.parametrize("verdict", ["blocked", "incomplete", "needs-human"])
@pytest.mark.parametrize("state", ["success", "failure", "pending"])
def test_a_gate_verdict_that_is_not_ready_stays_in_the_archive_job(verdict, state):
    d = decide(**world("archive", gate_verdict=verdict, statuses=[review(state)]))
    assert (d["post"], d["status"], d["conclusion"], d["verdict"]) == (True, "completed", "failure", verdict)
    assert ("REVIEW_FAILED" in codes(d)) == (state == "failure")


@pytest.mark.parametrize("verdict", [None, "something-else"])
def test_no_record_or_an_unknown_gate_verdict_is_incomplete(verdict):
    d = decide(**world(gate_verdict=verdict))
    assert (d["status"], d["conclusion"], d["verdict"]) == ("completed", "failure", "incomplete")


def test_a_ready_gate_verdict_with_an_archive_that_is_not_complete_is_never_success():
    d = decide(**world(archive_ok=False))
    assert d["conclusion"] == "failure" and d["verdict"] == "incomplete"


@pytest.mark.parametrize("name", SEVEN)
def test_one_mandatory_check_failed_on_the_head_is_blocked(name):
    runs = [run(n, "failure" if n == name else "success", run_id=i + 1) for i, n in enumerate(SEVEN)]
    d = decide(**world(check_runs=runs))
    assert (d["conclusion"], d["verdict"]) == ("failure", "blocked") and "FAILED_CHECK" in codes(d)


@pytest.mark.parametrize("name", SEVEN)
def test_one_mandatory_check_missing_on_the_head_is_incomplete(name):
    runs = [run(n, run_id=i + 1) for i, n in enumerate(SEVEN) if n != name]
    d = decide(**world(check_runs=runs))
    assert (d["conclusion"], d["verdict"]) == ("failure", "incomplete") and "MISSING_CHECK" in codes(d)


def test_unreadable_check_runs_are_incomplete():
    d = decide(**world(check_runs=None))
    assert (d["conclusion"], d["verdict"]) == ("failure", "incomplete") and "CHECKS_UNREADABLE" in codes(d)


@pytest.mark.parametrize("bad", [
    run("gate/tests", app=999, run_id=50),
    run("gate/tests", head=OTHER, run_id=50),
    run("gate/tests", status="in_progress", conclusion=None, run_id=50),
    run("gate/tests", conclusion="neutral", run_id=50),
], ids=["another-app", "another-commit", "in-progress", "neutral"])
def test_only_a_completed_success_of_the_actions_app_on_the_head_counts(bad):
    runs = [run(n, run_id=i + 1) for i, n in enumerate(SEVEN) if n != "gate/tests"] + [bad]
    d = decide(**world(check_runs=runs))
    assert d["conclusion"] == "failure"


@pytest.mark.parametrize("status", ["in_progress", "queued"])
def test_a_mandatory_check_not_yet_completed_on_the_head_counts_as_missing_never_as_passed(status):
    runs = [run(n, run_id=i + 1) for i, n in enumerate(SEVEN) if n != "gate/tests"]
    runs.append(run("gate/tests", status=status, conclusion=None, run_id=50))
    d = decide(**world(check_runs=runs))
    assert (d["conclusion"], d["verdict"]) == ("failure", "incomplete") and "MISSING_CHECK" in codes(d)


def test_the_newest_run_of_a_name_counts_by_its_id():
    runs = [run(n, run_id=i + 1) for i, n in enumerate(SEVEN)] + [run("gate/tests", "failure", run_id=99)]
    assert decide(**world(check_runs=runs))["verdict"] == "blocked"
    runs = [run(n, run_id=i + 10) for i, n in enumerate(SEVEN)] + [run("gate/tests", "failure", run_id=1)]
    assert decide(**world(check_runs=runs))["verdict"] == "ready-for-human"


def test_the_archive_jobs_own_gate_archive_stands_for_the_check_run_it_has_not_posted_yet():
    assert decide(**world("archive"))["verdict"] == "ready-for-human"
    d = decide(**world("archive", own_checks={"gate/archive": "failure"}))
    assert d["verdict"] == "blocked"


def test_the_gates_own_reasons_are_kept():
    reason = {"code": "SOMETHING", "detail": "kept"}
    d = decide(**world(gate_verdict="blocked", gate_reasons=[reason]))
    assert reason in d["reasons"]


def test_the_decision_reports_the_review_it_read():
    d = decide(**world(statuses=[review("failure")]))
    assert d["review"]["state"] == "failed"
    d = decide(**world(statuses=[]))
    assert d["review"] == {"state": "missing", "code": "REVIEW_MISSING"}
