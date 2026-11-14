"""CR-7 (the policy check), CR-8 (the merge), CR-9 (running twice), CR-10 (the record), CR-12 (exit codes)."""

from __future__ import annotations

import json

import pytest

import fake_github as F


def policy_writes(world):
    return [c for c in world.gh.calls if c.route in ("post_check", "patch_check")]


# ---------------------------------------------------------------- CR-7
@pytest.mark.cr("CR-7")
def test_success_is_posted_once_then_merged(world):
    result = world.run()
    assert result.code == 0, result.out
    posts = policy_writes(world)
    assert [c.route for c in posts] == ["post_check"]
    body = posts[0].body
    assert body["name"] == F.POLICY and body["head_sha"] == F.HEAD
    assert body["status"] == "completed" and body["conclusion"] == "success"
    summary = body["output"]["summary"]
    for word in ("SA1-T1", "workflow/service.py", "tests/test_overdue_today.py", "reports/7/1000-1",
                 F.REVIEWER_SLUG + "[bot]"):
        assert word in summary, summary
    assert "success" in body["output"]["title"]
    assert world.gh.routes().index("post_check") < world.gh.routes().index("merge")


@pytest.mark.cr("CR-7")
def test_failure_names_the_first_failing_rule(world):
    world.gh.pr["user"]["id"] = 1
    world.gh.statuses = [F.review_status(50, state="failure")]
    world.run()
    body = policy_writes(world)[0].body
    assert body["conclusion"] == "failure" and body["status"] == "completed"
    assert "CR-2 PR_NOT_BY_EXECUTOR" in body["output"]["title"]
    summary = body["output"]["summary"]
    assert summary.index("CR-2 PR_NOT_BY_EXECUTOR") < summary.index("REVIEW_FAILED")


@pytest.mark.cr("CR-7")
def test_an_existing_own_check_is_updated_in_place(world):
    world.gh.check_runs.append({"id": 777, "name": F.POLICY, "head_sha": F.HEAD, "status": "completed",
                                "conclusion": "failure", "app": {"id": F.APP_ID}})
    result = world.run()
    assert result.code == 0, result.out
    posts = policy_writes(world)
    assert [c.route for c in posts] == ["patch_check"]
    assert posts[0].path.endswith("/check-runs/777")
    assert posts[0].body["conclusion"] == "success"
    assert len(world.gh.policy_runs()) == 1


@pytest.mark.cr("CR-7")
def test_the_newest_own_check_is_updated(world):
    for run_id in (701, 702):
        world.gh.check_runs.append({"id": run_id, "name": F.POLICY, "head_sha": F.HEAD, "status": "completed",
                                    "conclusion": "failure", "app": {"id": F.APP_ID}})
    world.run()
    assert policy_writes(world)[0].path.endswith("/check-runs/702")


@pytest.mark.cr("CR-7")
def test_a_check_of_that_name_from_another_app_is_not_touched(world):
    world.gh.check_runs.append({"id": 778, "name": F.POLICY, "head_sha": F.HEAD, "status": "completed",
                                "conclusion": "success", "app": {"id": F.EXECUTOR_APP}})
    world.run()
    assert [c.route for c in policy_writes(world)] == ["post_check"]


@pytest.mark.cr("CR-7")
def test_check_post_refused_is_a_github_error(world):
    world.gh.fail["post_check"] = (403, {"message": "Resource not accessible by integration"})
    result = world.run()
    assert result.code == 6, result.out
    assert result.stop.startswith("CONTROLLER GITHUB_ERROR")
    assert "merge" not in world.gh.routes()


# ---------------------------------------------------------------- CR-8
@pytest.mark.cr("CR-8")
def test_merge_carries_the_head_and_the_method(world):
    result = world.run()
    merges = [c for c in world.gh.calls if c.route == "merge"]
    assert len(merges) == 1
    assert merges[0].body.get("sha") == F.HEAD and merges[0].body.get("merge_method") == "merge"
    assert world.last_record()["merge_sha"] == F.MERGE_SHA
    assert result.stop == f"CONTROLLER MERGED: PR {F.PR} at {F.HEAD} merged as {F.MERGE_SHA}"


@pytest.mark.cr("CR-8")
def test_everything_is_read_again_before_the_merge(world):
    world.run()
    routes = world.gh.routes()
    post = routes.index("post_check")
    after = routes[post + 1:routes.index("merge")]
    for needed in ("pr", "compare", "check_runs", "reports_commits", "statuses"):
        assert needed in after, (needed, after)


@pytest.mark.cr("CR-8")
def test_head_moved_after_the_post_refuses_without_merge(world):
    def move(gh):
        gh.pr["head"]["sha"] = "9" * 40
    world.gh.after["post_check"] = move
    result = world.run()
    assert result.code == 1, result.out
    assert "HEAD_MOVED" in result.stop
    assert "merge" not in world.gh.routes()
    assert [c.route for c in policy_writes(world)] == ["post_check"]


@pytest.mark.cr("CR-8")
def test_a_rule_failing_on_the_second_read_updates_the_check_to_failure(world):
    def review_withdrawn(gh):
        gh.statuses.append(F.review_status(99, state="failure"))
    world.gh.after["post_check"] = review_withdrawn
    result = world.run()
    assert result.code == 1, result.out
    assert "CR-6 REVIEW_FAILED" in result.stop
    writes = policy_writes(world)
    assert [c.route for c in writes] == ["post_check", "patch_check"]
    assert writes[1].body["conclusion"] == "failure"
    assert "merge" not in world.gh.routes()
    assert len(world.gh.policy_runs()) == 1


@pytest.mark.cr("CR-8")
def test_mergeable_null_is_read_once_more_after_five_seconds(world):
    world.gh.mergeable = [True, None, True]
    result = world.run()
    assert result.code == 0, result.out
    assert world.sleeps == [5]


@pytest.mark.cr("CR-8")
def test_mergeable_null_twice_is_not_mergeable(world):
    world.gh.mergeable = [True, None, None]
    result = world.run()
    assert result.code == 4, result.out
    assert "NOT_MERGEABLE" in result.stop
    assert world.sleeps == [5]
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-8")
def test_mergeable_false_is_not_mergeable(world):
    world.gh.mergeable = [True, False]
    result = world.run()
    assert result.code == 4, result.out
    assert "NOT_MERGEABLE" in result.stop
    assert world.sleeps == []
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-8")
@pytest.mark.parametrize("status, message", [
    (405, "Repository rule violations found"),
    (409, "Head branch was modified. Review and try the merge again."),
    (422, "Validation Failed"),
    (403, "Resource not accessible by integration"),
])
def test_github_refuses_the_merge_once_without_retry(world, status, message):
    world.gh.merge_answer = (status, {"message": message})
    result = world.run()
    assert result.code == 4, result.out
    assert result.stop.startswith("CONTROLLER MERGE_REFUSED")
    assert str(status) in result.stop and message in result.stop
    assert world.gh.routes().count("merge") == 1
    assert world.last_record()["message"].startswith(str(status))
    assert [r["conclusion"] for r in world.gh.policy_runs()] == ["success"]


@pytest.mark.cr("CR-8")
def test_a_200_without_merged_is_refused(world):
    world.gh.merge_answer = (200, {"merged": False, "sha": F.MERGE_SHA, "message": "odd"})
    result = world.run()
    assert result.code == 4, result.out
    assert world.last_record()["merge_sha"] is None


@pytest.mark.cr("CR-8")
def test_only_routes_of_the_contract_are_used(world):
    world.run()
    assert "UNKNOWN" not in world.gh.routes()
    assert all(c.url.startswith(F.API + "/") for c in world.gh.calls)


# ---------------------------------------------------------------- CR-9
@pytest.mark.cr("CR-9")
def test_an_already_merged_pr_gets_nothing(world):
    world.gh.pr.update(state="closed", merged=True)
    result = world.run()
    assert result.code == 5, result.out
    assert result.stop.startswith("CONTROLLER ALREADY_MERGED")
    assert world.gh.writes() == []
    assert world.last_record()["outcome"] == "ALREADY_MERGED"


@pytest.mark.cr("CR-9")
def test_a_second_run_after_a_merge_does_nothing(world):
    assert world.run().code == 0
    calls = len(world.gh.writes())
    result = world.run()
    assert result.code == 5, result.out
    assert len(world.gh.writes()) == calls
    assert world.gh.routes().count("merge") == 1


@pytest.mark.cr("CR-9")
def test_two_runs_on_one_head_leave_one_result(world):
    world.gh.statuses = []
    assert world.run().code == 3
    world.gh.statuses = [F.review_status(50)]
    assert world.run().code == 0
    runs = world.gh.policy_runs()
    assert len(runs) == 1 and runs[0]["conclusion"] == "success"
    assert [c.route for c in policy_writes(world)] == ["post_check", "patch_check"]


@pytest.mark.cr("CR-9")
def test_a_held_lock_stops_the_run(world):
    world.log_file.parent.mkdir(parents=True, exist_ok=True)
    lock = world.log_file.with_name(world.log_file.name + ".lock")
    lock.write_text("held", encoding="utf-8")
    result = world.run()
    assert result.code == 7, result.out
    assert result.stop.startswith("CONTROLLER LOCKED")
    assert world.gh.calls == []
    assert lock.read_text(encoding="utf-8") == "held"


@pytest.mark.cr("CR-9")
@pytest.mark.parametrize("make_world", ["merged", "refused", "github_error"])
def test_the_lock_is_removed_at_the_end(world, make_world):
    if make_world == "refused":
        world.gh.pr["draft"] = True
    if make_world == "github_error":
        world.gh.fail["token"] = (401, {"message": "bad"})
    world.run()
    assert not world.log_file.with_name(world.log_file.name + ".lock").exists()


# ---------------------------------------------------------------- CR-10
@pytest.mark.cr("CR-10")
def test_one_line_per_run_with_every_field(world):
    world.run()
    world.gh.pr.update(state="closed", merged=True)
    world.run()
    lines = world.log_lines()
    assert len(lines) == 2
    first = lines[0]
    for key in ("time", "repository", "pr", "head_sha", "base_tip", "task_id", "queue_sha256", "rules", "outcome",
                "policy_check_id", "merge_sha"):
        assert key in first, key
    assert first["repository"] == F.REPO and first["pr"] == F.PR and first["head_sha"] == F.HEAD
    assert first["task_id"] == "SA1-T1" and first["queue_sha256"] == world.queue_sha
    assert first["outcome"] == "MERGED" and first["merge_sha"] == F.MERGE_SHA
    assert set(first["rules"]) == {"CR-2", "CR-3", "CR-4", "CR-5", "CR-6"}
    assert all(rule["ok"] is True for rule in first["rules"].values())
    assert first["time"].endswith("Z") or first["time"].endswith("+00:00")


@pytest.mark.cr("CR-10")
def test_a_refused_run_records_each_rule(world):
    world.gh.pr["draft"] = True
    world.gh.statuses = []
    world.run()
    rules = world.last_record()["rules"]
    assert rules["CR-2"].get("ok") is False and rules["CR-2"].get("code") == "PR_DRAFT"
    assert set(rules["CR-2"]) == {"ok", "code", "detail"} and "draft" in rules["CR-2"]["detail"]
    assert rules["CR-6"]["code"] == "REVIEW_MISSING"
    assert rules["CR-4"]["ok"] is True
    assert world.last_record()["outcome"] == "REFUSED"


@pytest.mark.cr("CR-10")
def test_usage_errors_write_no_record(world):
    world.run(world.argv(**{"--pr": "0"}))
    assert world.log_lines() == []


# ---------------------------------------------------------------- CR-12
@pytest.mark.cr("CR-12")
@pytest.mark.parametrize("setup, code, word", [
    (lambda w: None, 0, "MERGED"),
    (lambda w: w.gh.pr.update(draft=True), 1, "REFUSED"),
    (lambda w: w.gh.statuses.clear(), 3, "WAITING"),
    (lambda w: setattr(w.gh, "merge_answer", (405, {"message": "no"})), 4, "MERGE_REFUSED"),
    (lambda w: w.gh.pr.update(merged=True, state="closed"), 5, "ALREADY_MERGED"),
    (lambda w: w.gh.fail.update(token=(401, {"message": "bad"})), 6, "GITHUB_ERROR"),
])
def test_exit_code_and_exactly_one_stop_line(world, setup, code, word):
    setup(world)
    result = world.run()
    assert result.code == code, result.out
    assert len(result.stop_lines) == 1, result.out
    assert result.stop_lines[0].startswith(f"CONTROLLER {word}:")


@pytest.mark.cr("CR-12")
def test_pr_unreadable_is_a_github_error_with_nothing_posted(world):
    world.gh.fail["pr"] = (500, {"message": "boom"})
    result = world.run()
    assert result.code == 6, result.out
    assert world.gh.writes() == []


@pytest.mark.cr("CR-12")
def test_stop_line_detail_names_the_first_failing_rule(world):
    world.gh.compare["files"].append({"filename": "tests/test_api.py", "status": "modified", "patch": "@@ x\n+a\n"})
    result = world.run()
    assert result.stop.startswith("CONTROLLER REFUSED: CR-4 TEST_CHANGED"), result.out


@pytest.mark.cr("CR-10")
def test_log_holds_no_secret(world, rsa_key):
    world.gh.merge_answer = (405, {"message": "no " + F.TOKEN})
    world.run()
    text = world.log_file.read_text(encoding="utf-8")
    assert F.TOKEN not in text
    assert "BEGIN" not in text and "PRIVATE" not in text
    assert json.loads(text.splitlines()[-1])["outcome"] == "MERGE_REFUSED"
