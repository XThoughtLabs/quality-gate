"""CR-2 (the PR) and CR-3 (the task)."""

from __future__ import annotations

import importlib.util
import json

import pytest

import fake_github as F
from conftest import REPO_ROOT


def refused(world, result, rule, code):
    assert result.code == 1, result.out
    assert result.stop.startswith("CONTROLLER REFUSED"), result.out
    assert f"{rule} {code}" in result.stop, result.out
    assert "merge" not in world.gh.routes()
    assert world.rule(rule).get("code") == code
    runs = world.gh.policy_runs()
    assert len(runs) == 1 and runs[0]["conclusion"] == "failure" and runs[0]["head_sha"] == F.HEAD


@pytest.mark.cr("CR-2")
@pytest.mark.parametrize("change, code", [
    (lambda pr: pr.update(state="closed"), "PR_NOT_OPEN"),
    (lambda pr: pr.update(draft=True), "PR_DRAFT"),
    (lambda pr: pr["base"].update(ref="main"), "PR_WRONG_BASE"),
    (lambda pr: pr["base"]["repo"].update(full_name="acme/other"), "PR_WRONG_BASE"),
    (lambda pr: pr["head"]["repo"].update(full_name="mallory/demo-stand"), "PR_FROM_FORK"),
    (lambda pr: pr["head"].update(repo=None), "PR_FROM_FORK"),
    (lambda pr: pr["user"].update(login="acme-reviewer[bot]"), "PR_NOT_BY_EXECUTOR"),
    (lambda pr: pr["user"].update(id=F.EXECUTOR_BOT + 1), "PR_NOT_BY_EXECUTOR"),
    (lambda pr: pr["user"].update(type="User"), "PR_NOT_BY_EXECUTOR"),
    (lambda pr: pr["user"].update(login="acme-executor"), "PR_NOT_BY_EXECUTOR"),
])
def test_pr_rule(world, change, code):
    change(world.gh.pr)
    refused(world, world.run(), "CR-2", code)


@pytest.mark.cr("CR-2")
def test_pr_unreadable_fails_closed(world):
    world.gh.fail["pr"] = (500, {"message": "boom"})
    result = world.run()
    assert result.code in (1, 6), result.out
    assert "merge" not in world.gh.routes()
    assert not any(r.get("conclusion") == "success" for r in world.gh.policy_runs())


@pytest.mark.cr("CR-3")
@pytest.mark.parametrize("ref", [
    "ai/12-sa1-t9-unknown-task",
    "ai/12-sa1-t1-overdue-misses-today-x",
    "feature/sa1-t1-overdue-misses-today",
    "ai/0-sa1-t1-overdue-misses-today",
    "ai/x-sa1-t1-overdue-misses-today",
    "ai/12345678901-sa1-t1-overdue-misses-today",
    "AI/12-sa1-t1-overdue-misses-today",
])
def test_branch_that_maps_to_no_task(world, ref):
    world.gh.pr["head"]["ref"] = ref
    refused(world, world.run(), "CR-3", "NO_TASK")


@pytest.mark.cr("CR-3")
def test_branch_maps_to_the_second_task(world):
    world.gh.pr["head"]["ref"] = F.T2_REF
    result = world.run()
    assert result.code == 0, result.out
    assert world.last_record()["task_id"] == "SA1-T2"


@pytest.mark.cr("CR-3")
def test_task_done_by_an_earlier_merged_pr(world):
    world.gh.closed_prs = [{"number": 3, "merged_at": "2026-11-14T08:00:00Z", "head": {"ref": "ai/9-sa1-t1-overdue-misses-today"}}]
    refused(world, world.run(), "CR-3", "TASK_DONE")


@pytest.mark.cr("CR-3")
def test_a_closed_unmerged_pr_does_not_make_the_task_done(world):
    world.gh.closed_prs = [{"number": 3, "merged_at": None, "head": {"ref": "ai/9-sa1-t1-overdue-misses-today"}}]
    assert world.run().code == 0


@pytest.mark.cr("CR-3")
def test_a_merged_pr_of_another_task_does_not_count(world):
    world.gh.closed_prs = [{"number": 3, "merged_at": "2026-11-14T08:00:00Z", "head": {"ref": F.T2_REF}}]
    assert world.run().code == 0


@pytest.mark.cr("CR-3")
def test_closed_prs_are_read_on_every_page(world):
    filler = [{"number": 1000 + i, "merged_at": None, "head": {"ref": f"other/{i}"}} for i in range(100)]
    world.gh.closed_prs = filler + [{"number": 3, "merged_at": "2026-11-14T08:00:00Z",
                                     "head": {"ref": "ai/9-sa1-t1-overdue-misses-today"}}]
    refused(world, world.run(), "CR-3", "TASK_DONE")


@pytest.mark.cr("CR-3")
def test_task_done_by_the_run_log(world):
    world.log_file.parent.mkdir(parents=True, exist_ok=True)
    line = {"repository": F.REPO, "task_id": "SA1-T1", "outcome": "MERGED", "pr": 5, "head_sha": "9" * 40}
    world.log_file.write_text(json.dumps(line) + "\n", encoding="utf-8")
    refused(world, world.run(), "CR-3", "TASK_DONE")


@pytest.mark.cr("CR-3")
def test_a_refused_run_in_the_log_does_not_make_the_task_done(world):
    world.log_file.parent.mkdir(parents=True, exist_ok=True)
    line = {"repository": F.REPO, "task_id": "SA1-T1", "outcome": "REFUSED", "pr": 5, "head_sha": "9" * 40}
    world.log_file.write_text(json.dumps(line) + "\n", encoding="utf-8")
    assert world.run().code == 0


def launcher_branch_slug():
    spec = importlib.util.spec_from_file_location("launcher_for_slug", REPO_ROOT / "launcher" / "xtl_launcher.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.branch_slug


@pytest.mark.cr("CR-3")
@pytest.mark.parametrize("title", [
    "SA1-T1 Overdue misses today",
    "SA1-T2 A very long title that is longer than forty characters for sure",
    "SA1-T3 Search: Ünïcode & symbols!!",
    "SA1-T1 ---",
    "",
    "SA1-T1 abcdefghij-abcdefghij-abcdefghij-abcdefghij",
    "SA1-T1 abcdefghijabcdefghijabcdefghijabcdefghijabcdefghij",
])
def test_branch_slug_is_the_launchers(controller, title):
    assert controller.branch_slug(title) == launcher_branch_slug()(title)
