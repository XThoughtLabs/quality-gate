"""CR-5 (the gate's checks and its stored report), CR-6 (the review), and the waiting outcome."""

from __future__ import annotations

import pytest

import fake_github as F


def refused(world, result, rule, code):
    assert result.code == 1, result.out
    assert result.stop.startswith("CONTROLLER REFUSED"), result.out
    assert world.rule(rule).get("code") == code, world.last_record()
    assert "merge" not in world.gh.routes()
    assert [r["conclusion"] for r in world.gh.policy_runs()] == ["failure"]


def waiting(world, result, rule, code):
    assert result.code == 3, result.out
    assert result.stop.startswith("CONTROLLER WAITING"), result.out
    assert world.rule(rule).get("code") == code, world.last_record()
    assert "merge" not in world.gh.routes()
    assert [r["conclusion"] for r in world.gh.policy_runs()] == ["failure"]


def gate_run(world, name):
    return next(r for r in world.gh.check_runs if r["name"] == name)


# ---------------------------------------------------------------- the checks
@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("name", F.GATE_CHECKS)
def test_each_gate_check_is_required(world, name):
    world.gh.check_runs = [r for r in world.gh.check_runs if r["name"] != name]
    waiting(world, world.run(), "CR-5", "GATE_CHECK_MISSING")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("conclusion", ["failure", "neutral", "skipped", "cancelled", "timed_out", "action_required"])
def test_a_gate_check_that_did_not_succeed(world, conclusion):
    gate_run(world, "gate/tests")["conclusion"] = conclusion
    refused(world, world.run(), "CR-5", "GATE_CHECK_FAILED")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("status", ["queued", "in_progress"])
def test_a_gate_check_still_running(world, status):
    run = gate_run(world, "gate/final")
    run["status"], run["conclusion"] = status, None
    waiting(world, world.run(), "CR-5", "GATE_CHECK_PENDING")


@pytest.mark.cr("CR-5")
def test_a_success_from_another_app_does_not_count(world):
    world.gh.check_runs = [r for r in world.gh.check_runs if r["name"] != "gate/guard"]
    world.gh.check_runs.append(F.check_run(500, "gate/guard", app=F.EXECUTOR_APP))
    waiting(world, world.run(), "CR-5", "GATE_CHECK_MISSING")


@pytest.mark.cr("CR-5")
def test_the_newest_run_of_a_name_decides(world):
    world.gh.check_runs.append(F.check_run(900, "gate/final", conclusion="failure"))
    refused(world, world.run(), "CR-5", "GATE_CHECK_FAILED")


@pytest.mark.cr("CR-5")
def test_an_older_failure_is_replaced_by_a_newer_success(world):
    world.gh.check_runs.append(F.check_run(5, "gate/final", conclusion="failure"))
    assert world.run().code == 0


@pytest.mark.cr("CR-5")
def test_check_runs_are_read_on_every_page(world):
    fillers = [F.check_run(1000 + i, f"diag/x{i}", conclusion="neutral") for i in range(120)]
    world.gh.check_runs = fillers + world.gh.check_runs
    world.gh.check_runs.append(F.check_run(5000, "gate/env", conclusion="failure"))
    refused(world, world.run(), "CR-5", "GATE_CHECK_FAILED")


# ---------------------------------------------------------------- the stored report
@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("change", [
    lambda c: c.update(author={"login": "acme-executor[bot]"}),
    lambda c: c.update(author=None),
    lambda c: c["commit"]["verification"].update(verified=False),
])
def test_a_foreign_commit_on_the_reports_branch(world, change):
    change(world.gh.reports_commits[1])
    refused(world, world.run(), "CR-5", "REPORTS_UNTRUSTED")


@pytest.mark.cr("CR-5")
def test_reports_commits_are_read_on_every_page(world):
    good = world.gh.reports_commits[1]
    world.gh.reports_commits = [world.gh.reports_commits[0]] + [dict(good, sha=f"{i:040x}") for i in range(1, 130)]
    world.gh.reports_commits[120] = {"sha": "7" * 40, "author": {"login": "mallory"},
                                     "commit": {"verification": {"verified": True}}}
    refused(world, world.run(), "CR-5", "REPORTS_UNTRUSTED")


@pytest.mark.cr("CR-5")
def test_no_reports_branch(world):
    world.gh.reports_exists = False
    waiting(world, world.run(), "CR-5", "REPORT_MISSING")


@pytest.mark.cr("CR-5")
def test_no_record_for_this_head(world):
    world.gh.records = {f"{F.PR}/1000-1": F.good_record(head="9" * 40)}
    waiting(world, world.run(), "CR-5", "REPORT_MISSING")


@pytest.mark.cr("CR-5")
def test_a_record_of_another_pr_does_not_count(world):
    world.gh.records = {f"{F.PR + 1}/1000-1": F.good_record(pr=F.PR + 1)}
    waiting(world, world.run(), "CR-5", "REPORT_MISSING")


@pytest.mark.cr("CR-5")
def test_truncated_reports_tree_is_unreadable(world):
    world.gh.reports_tree_truncated = True
    refused(world, world.run(), "CR-5", "UNREADABLE")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("newer", ["1001-1", "1000-2", "999-9"])
def test_the_newest_record_decides(world, newer):
    marked = F.good_record()
    marked["report.json"]["marked_tests"] = [{"path": "tests/test_api.py", "name": "test_create"}]
    world.gh.records[f"{F.PR}/{newer}"] = marked
    result = world.run()
    if newer == "999-9":
        assert result.code == 0, result.out
    else:
        refused(world, result, "CR-5", "MARKED_TESTS")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("field, code", [
    ("marked_tests", "MARKED_TESTS"),
    ("needs_code_owner", "NEEDS_CODE_OWNER"),
    ("dependency_changes", "DEPENDENCY_CHANGES"),
    ("security_review_changes", "SECURITY_CHANGES"),
])
def test_a_mark_in_the_report_refuses(world, field, code):
    value = {"marked_tests": {"path": "tests/test_api.py", "name": "test_x"}}.get(field, "tests/test_api.py")
    world.gh.records[f"{F.PR}/1000-1"]["report.json"][field] = [value]
    refused(world, world.run(), "CR-5", code)


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("field", ["marked_tests", "needs_code_owner", "dependency_changes", "security_review_changes"])
def test_a_mark_list_that_is_not_a_list_refuses(world, field):
    world.gh.records[f"{F.PR}/1000-1"]["report.json"][field] = "unknown"
    result = world.run()
    assert result.code == 1, result.out
    assert world.rule("CR-5").get("ok") is False


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("change", [
    lambda r: r["report.json"]["verification"].update(head_sha="9" * 40),
    lambda r: r["report.json"]["verification"].update(pr=F.PR + 1),
])
def test_report_for_another_commit_or_pr(world, change):
    change(world.gh.records[f"{F.PR}/1000-1"])
    refused(world, world.run(), "CR-5", "REPORT_MISMATCH")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("change", [
    lambda r: r["final.json"].update(gate_verdict="blocked"),
    lambda r: r["final.json"].update(gate_verdict="needs-human"),
    lambda r: r["final.json"]["conclusions"].update({"gate/archive": "failure"}),
    lambda r: r["verdict.json"].update(verdict="incomplete"),
    lambda r: r["verdict.json"]["checks"].update({"gate/guard": "failure"}),
])
def test_gate_not_ready_in_the_record(world, change):
    change(world.gh.records[f"{F.PR}/1000-1"])
    refused(world, world.run(), "CR-5", "GATE_NOT_READY")


@pytest.mark.cr("CR-5")
@pytest.mark.parametrize("name", ["final.json", "verdict.json", "report.json"])
def test_a_missing_record_file(world, name):
    del world.gh.records[f"{F.PR}/1000-1"][name]
    result = world.run()
    assert result.code in (1, 3), result.out
    assert world.rule("CR-5").get("code") == "REPORT_MISSING"
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-5")
def test_an_unreadable_record_file(world):
    world.gh.records[f"{F.PR}/1000-1"]["report.json"] = b"{not json"
    refused(world, world.run(), "CR-5", "UNREADABLE")


# ---------------------------------------------------------------- the review
@pytest.mark.cr("CR-6")
def test_no_review(world):
    world.gh.statuses = []
    waiting(world, world.run(), "CR-6", "REVIEW_MISSING")


@pytest.mark.cr("CR-6")
def test_a_status_of_another_context_is_no_review(world):
    world.gh.statuses = [F.review_status(50, context="independent-review-2")]
    waiting(world, world.run(), "CR-6", "REVIEW_MISSING")


@pytest.mark.cr("CR-6")
def test_review_pending(world):
    world.gh.statuses = [F.review_status(50, state="pending")]
    waiting(world, world.run(), "CR-6", "REVIEW_PENDING")


@pytest.mark.cr("CR-6")
@pytest.mark.parametrize("state", ["failure", "error"])
def test_review_failed(world, state):
    world.gh.statuses = [F.review_status(50, state=state)]
    refused(world, world.run(), "CR-6", "REVIEW_FAILED")


@pytest.mark.cr("CR-6")
@pytest.mark.parametrize("creator", [
    {"login": "acme-executor[bot]", "user_id": F.EXECUTOR_BOT},
    {"login": "acme-reviewer[bot]", "user_id": F.REVIEWER_BOT + 1},
    {"login": "acme-reviewer", "user_id": F.REVIEWER_BOT},
    {"kind": "User"},
])
def test_review_not_by_the_reviewer(world, creator):
    world.gh.statuses = [F.review_status(50, **creator)]
    refused(world, world.run(), "CR-6", "REVIEW_NOT_BY_REVIEWER")


@pytest.mark.cr("CR-6")
def test_the_newest_review_decides(world):
    world.gh.statuses = [F.review_status(50), F.review_status(60, state="failure")]
    refused(world, world.run(), "CR-6", "REVIEW_FAILED")


@pytest.mark.cr("CR-6")
def test_a_newer_status_by_someone_else_hides_an_older_success(world):
    world.gh.statuses = [F.review_status(50), F.review_status(60, login="mallory", user_id=1, kind="User")]
    refused(world, world.run(), "CR-6", "REVIEW_NOT_BY_REVIEWER")


@pytest.mark.cr("CR-6")
def test_an_older_failure_is_replaced_by_a_newer_success(world):
    world.gh.statuses = [F.review_status(50, state="failure"), F.review_status(60)]
    assert world.run().code == 0


@pytest.mark.cr("CR-6")
def test_statuses_are_read_on_every_page(world):
    others = [F.review_status(1000 + i, context="ci/other") for i in range(150)]
    world.gh.statuses = others + [F.review_status(10, state="failure")]
    refused(world, world.run(), "CR-6", "REVIEW_FAILED")


# ---------------------------------------------------------------- waiting against refused
@pytest.mark.cr("CR-5")
def test_waiting_and_refused_together_is_refused(world):
    world.gh.statuses = []
    gate_run(world, "gate/tests")["conclusion"] = "failure"
    result = world.run()
    assert result.code == 1, result.out
    assert "CR-5 GATE_CHECK_FAILED" in result.stop
