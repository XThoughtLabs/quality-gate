"""`fix --pr N` end to end: the PR (LR-42), the stored reports (LR-43 to
LR-45), the decisions (LR-46, LR-47), the PR's head (LR-48), HEAD_MOVED
(LR-38), and what fix shares with task (LR-18, LR-25, LR-26, LR-29, LR-39,
LR-40).

PR 7's head commit changes quality.toml (99 turns, one round), the prompt
and the pin: a launcher that read them from the PR's branch is caught."""

from __future__ import annotations

import json
import os
import time

import pytest

import launcher_world as W
from conftest import shared_run

PROPOSAL_TEXT = "| bandit | B105 | app/fix.py | FIX-PROPOSAL-MARK-2718 a test constant |\n"
FIX_STEPS = [
    {"op": "commit", "path": "app/fix.py", "text": "def fix():\n    return 3\n",
     "message": "Fix the thing"},
    {"op": "proposal", "text": PROPOSAL_TEXT},
]
JUDGE_EVENT = {"workflow_run": {"id": 100, "run_attempt": 10,
                                "path": ".github/workflows/judge.yml",
                                "event": "pull_request_target", "conclusion": "completed"}}


def prepare_fix(w, mp):
    w.set_up_fix(comments=False)


@pytest.fixture(scope="module")
def fix_run(tmp_path_factory, launcher, test_key, template):
    return shared_run(tmp_path_factory, "fix", launcher, test_key, template, prepare_fix,
                      ["fix", "--pr", str(W.PR_NUMBER)], FIX_STEPS)


def decide_calls(res, event_name):
    calls = []
    for e in W.gate_commands(res, "decide"):
        argv = e["argv"]
        if "gate.feedback" in argv and argv[argv.index("--event-name") + 1] == event_name:
            calls.append(e)
    return calls


# ---------------------------------------------------------------- the shared run
def test_lr39_fix_succeeds_and_fast_forwards_the_pr_branch(fix_run, check):
    check.success(fix_run)
    facts = fix_run.world.facts
    tip = fix_run.refs_after[f"refs/heads/{W.PR_BRANCH}"]
    commits = W.commits_between(fix_run.world.remote, facts.pr_head, tip)
    assert [c["subject"] for c in commits] == ["Fix the thing"]
    assert W.is_ancestor(fix_run.world.remote, facts.pr_head, tip)
    for c in commits:
        assert (c["author_name"], c["author_email"]) == (W.BOT_LOGIN, W.BOT_EMAIL)


def test_lr39_fix_push_without_force(fix_run):
    pushes = fix_run.git_commands("push")
    assert len(pushes) == 1
    argv = pushes[0]["argv"]
    assert f"HEAD:refs/heads/{W.PR_BRANCH}" in argv and "origin" in argv
    assert not any(a.startswith("+") or a.startswith("--force") or a == "-f" for a in argv), argv


def test_lr40_fix_opens_no_pr_and_posts_the_proposal(fix_run):
    api = fix_run.world.api
    assert api.requests_to("POST", rf"^/repos/{W.REPOSITORY}/pulls$") == []
    assert W.gate_commands(fix_run, "create-pull-request") == []
    cmds = W.gate_commands(fix_run, "post-proposal")
    assert len(cmds) == 1
    argv = cmds[0]["argv"]
    assert argv[argv.index("--branch") + 1] == W.PR_BRANCH
    assert W.same_path(argv[argv.index("--file") + 1], fix_run.run_dir / "repo" / W.PROPOSAL_FILE)
    assert W.effective_env(cmds[0]).get("GATE_TOKEN") == api.tokens_issued[0]
    assert any("FIX-PROPOSAL-MARK-2718" in c["body"] for c in api.comments[W.PR_NUMBER])


def test_lr48_model_works_on_the_pr_head(fix_run):
    g = fix_run.model["git"]
    assert g["branch"] == W.PR_BRANCH
    assert g["head"] == fix_run.world.facts.pr_head


def test_lr18_fix_reads_config_prompt_and_pin_from_the_integration_branch(fix_run):
    text = W.norm_text(fix_run.model["stdin"])
    assert text.lstrip().startswith(W.EXECUTOR_TEMPLATE.rstrip("\n"))
    assert "PR-BRANCH-TEMPLATE" not in text
    argv = fix_run.model["argv"]
    assert argv[argv.index("--max-turns") + 1] == str(W.MAX_TURNS)
    for e in W.gate_commands(fix_run, "gate.feedback"):
        a = e["argv"]
        assert W.same_path(a[a.index("--config") + 1], fix_run.run_dir / "repo" / "quality.toml")


def test_lr25_fix_venv_without_a_lock(fix_run):
    env = {k.upper(): v for k, v in fix_run.model["env"].items()}
    assert W.same_path(env["VIRTUAL_ENV"], fix_run.run_dir / "venv")
    assert W.same_path(env["PATH"].split(os.pathsep)[0], fix_run.run_dir / "venv" / "Scripts")
    assert not [e for e in fix_run.events if e.get("argv") and "pip" in e["argv"]
                and "install" in e["argv"]]


def test_lr26_fix_allowed_tools(fix_run):
    argv = fix_run.model["argv"]
    assert argv[argv.index("--allowedTools") + 1] == W.TASK_TOOLS


def test_lr43_check_actors_run_by_the_pinned_gate(fix_run):
    cmds = W.gate_commands(fix_run, "check-actors")
    assert len(cmds) == 1
    e = cmds[0]
    argv = e["argv"]
    assert "gate.archive" in argv
    assert argv[argv.index("--api-repo") + 1] == W.REPOSITORY
    assert argv[argv.index("--branch") + 1] == "reports"
    assert W.same_path(argv[argv.index("--config") + 1], fix_run.run_dir / "repo" / "quality.toml")
    assert W.same_path(argv[argv.index("--out") + 1], fix_run.run_dir / "actors.json")
    assert W.same_path(e["cwd"], fix_run.run_dir / "gate")
    env = W.effective_env(e)
    assert env.get("GATE_TOKEN") == fix_run.world.api.tokens_issued[0]
    assert env.get("GITHUB_API_URL") == fix_run.world.api.url


def test_lr44_ls_remote_then_stored_reports_detached(fix_run):
    ls = fix_run.git_commands("ls-remote")
    assert ls, "git ls-remote was not run"
    argv = ls[0]["argv"]
    for part in ("--exit-code", "--heads", "origin", "reports"):
        assert part in argv, argv
    stored = fix_run.run_dir / "stored"
    if stored.exists():
        reports_tip = fix_run.refs_after["refs/heads/reports"]
        assert W.git("-C", str(stored), "rev-parse", "HEAD") == reports_tip
        assert W.git("-C", str(stored), "symbolic-ref", "-q", "HEAD", check=False) == ""
        assert (stored / "reports" / "7" / "100-10" / "context.json").exists()


def test_lr46_judge_event_is_the_newest_record_for_the_head(fix_run):
    calls = decide_calls(fix_run, "workflow_run")
    assert len(calls) == 1
    e = calls[0]
    argv = e["argv"]
    assert json.loads(e["files"]["--event"]) == JUDGE_EVENT
    assert json.loads(e["files"]["--pulls"]) == W.pulls_entry(fix_run.world.facts)
    assert W.same_path(argv[argv.index("--reports-dir") + 1], fix_run.run_dir / "stored" / "reports")
    assert W.same_path(argv[argv.index("--actors") + 1], fix_run.run_dir / "actors.json")
    assert argv[argv.index("--integration-branch") + 1] == W.INTEGRATION
    assert "--out" in argv
    assert W.same_path(e["cwd"], fix_run.run_dir / "gate")


def test_lr46_no_reviewer_comment_means_no_review_decision(fix_run):
    assert decide_calls(fix_run, "issue_comment") == []
    reads = fix_run.world.api.requests_to("GET", rf"^/repos/{W.REPOSITORY}/issues/7/comments")
    assert reads, "the PR's comments were not read"


def test_lr47_note_is_the_judges_comment(fix_run, gate_at_pin, tmp_path):
    facts = fix_run.world.facts
    reports = W.stored_reports(fix_run.world.remote, tmp_path / "stored")
    judge = W.run_decide(gate_at_pin, tmp_path / "judge", "workflow_run", JUDGE_EVENT,
                       W.pulls_entry(facts), reports)
    assert judge["reason_code"] is None and W.JUDGE_MARK in judge["comment"]
    text = W.norm_text(fix_run.model["stdin"])
    fix_line = W.FIX_LINE.format(n=W.PR_NUMBER)
    assert fix_line in text
    after = text[text.index(fix_line) + len(fix_line):]
    assert W.norm_text(judge["comment"]) in after
    assert after.index(W.norm_text(judge["comment"])) < after.index(W.PROPOSAL_LINE)
    assert text.index(W.BRANCH_LINE.format(branch=W.PR_BRANCH)) < text.index(fix_line)


def test_lr38_head_reread_just_before_the_push(fix_run):
    push = fix_run.git_commands("push")[0]
    reads = [r for r in fix_run.world.api.requests_to("GET", rf"^/repos/{W.REPOSITORY}/pulls/7$")
             if fix_run.model["started"] < r["time"] < push["time"]]
    assert reads, "the PR's head was not read again between the model and the push"


def test_lr49_fix_log(fix_run):
    log = fix_run.log_text
    assert "fix" in log and W.PR_BRANCH in log
    assert fix_run.refs_after[f"refs/heads/{W.PR_BRANCH}"] in log
    assert "token revoked" in log


# ---------------------------------------------------------------- the reviewer (LR-46, LR-46a)
def review_event(world, body):
    """LR-46 with amendment 1 (A1, LR-46a): `pull_request` holds the PR's
    API URL, never an empty object."""
    return {"action": "created",
            "issue": {"number": W.PR_NUMBER,
                      "pull_request": {"url": f"{world.api.url}/repos/{W.REPOSITORY}"
                                              f"/pulls/{W.PR_NUMBER}"}},
            "comment": {"body": body, "user": {"login": W.REVIEWER_BOT}},
            "sender": {"login": W.REVIEWER_BOT}}


def gates_own_decisions(world, gate_at_pin, folder, review_body):
    """The pinned gate's answers on the same inputs, to compare the
    launcher's note with (the gate's text is not written into the tests)."""
    reports = W.stored_reports(world.remote, folder / "stored")
    judge = W.run_decide(gate_at_pin, folder / "judge", "workflow_run", JUDGE_EVENT,
                         W.pulls_entry(world.facts), reports)
    review = W.run_decide(gate_at_pin, folder / "review", "issue_comment",
                          review_event(world, review_body), W.pulls_entry(world.facts),
                          reports, statuses=W.review_statuses())
    return judge, review


def note_in_prompt(res) -> str:
    text = W.norm_text(res.model["stdin"])
    fix_line = W.FIX_LINE.format(n=W.PR_NUMBER)
    assert fix_line in text, text[:500]
    after = text[text.index(fix_line) + len(fix_line):]
    return after[:after.index(W.PROPOSAL_LINE)] if W.PROPOSAL_LINE in after else after


def test_lr46a_review_event_statuses_and_both_notes(world, check, gate_at_pin, tmp_path):
    """The reviewer's newest marked comment for the head, read over every
    page (number 103: on the second page even at 100 per page), with the
    head's statuses; the judge acts too, so the note is both comments, the
    judge's first, joined by a blank line (LR-47)."""
    world.set_up_fix(comments=True)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    calls = decide_calls(res, "issue_comment")
    assert len(calls) == 1, res.describe()
    e = calls[0]
    body = world.api.comments[W.PR_NUMBER][102]["body"]
    assert W.REVIEW_MARK in body
    assert json.loads(e["files"]["--event"]) == review_event(world, body)
    statuses = json.loads(e["files"]["--statuses"])
    projected = [{"context": s["context"], "state": s["state"],
                  "creator": {"login": s["creator"]["login"]}} for s in statuses]
    assert projected == [{"context": s["context"], "state": s["state"],
                          "creator": {"login": s["creator"]["login"]}}
                         for s in W.review_statuses()]
    assert world.api.requests_to("GET", rf"/commits/{world.facts.pr_head}/statuses")
    assert json.loads(e["files"]["--pulls"]) == W.pulls_entry(world.facts)
    assert decide_calls(res, "workflow_run"), "the judge's decision was not asked"
    check.success(res)
    judge, review = gates_own_decisions(world, gate_at_pin, tmp_path, body)
    assert judge["reason_code"] is None and review["reason_code"] is None, (judge, review)
    expected = W.norm_text(judge["comment"]) + "\n\n" + W.norm_text(review["comment"])
    assert expected in note_in_prompt(res)


def test_lr46a_reviewer_alone_makes_the_round_act(world, check, gate_at_pin, tmp_path):
    """The judge's newest record is ready (NOT_A_FAILURE adds nothing); the
    reviewer's `changes_requested`, with a `failure` status by the reviewer's
    bot, makes the round act, and its findings reach the prompt."""
    world.set_up_fix(comments=True, newest_verdict="ready-for-human")
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.success(res)
    body = world.api.comments[W.PR_NUMBER][102]["body"]
    judge, review = gates_own_decisions(world, gate_at_pin, tmp_path, body)
    assert judge["reason_code"] == "NOT_A_FAILURE" and review["reason_code"] is None, (judge, review)
    note = note_in_prompt(res)
    assert W.norm_text(review["comment"]) in note
    assert W.REVIEW_MARK in note and "app/thing.py does not check input" in note
    for absent in (W.JUDGE_MARK, "MALLORY-MARK", "IMPOSTOR-MARK", "Old review."):
        assert absent not in note, absent
    tip = res.refs_after[f"refs/heads/{W.PR_BRANCH}"]
    assert [c["subject"] for c in W.commits_between(world.remote, world.facts.pr_head, tip)] == \
        ["Fix the thing"]


def test_lr46a_control_pass_marker_gives_nothing_to_fix(world, check):
    """The same world with the marker's verdict `pass`: the review adds
    nothing, the judge adds nothing, so no model runs."""
    world.set_up_fix(comments=True, newest_verdict="ready-for-human", review_verdict="pass")
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NOTHING_TO_FIX")
    assert res.model is None and not res.pushed
    assert len(decide_calls(res, "issue_comment")) == 1, "the review's decision was not asked"


# ---------------------------------------------------------------- refusals
def test_lr47_nothing_to_fix(world, check):
    world.set_up_fix(comments=False, newest_verdict="ready-for-human")
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NOTHING_TO_FIX")
    assert res.model is None and not res.pushed


def test_lr47_gate_reason_stops_the_round(world, check):
    world.set_up_fix(comments=False, newest_repeated=True)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "REPEATED_FIX")
    assert res.model is None and not res.pushed


@pytest.mark.parametrize("override", [
    {"state": "closed"},
    {"base__ref": "main"},
    {"head__repo__full_name": "Evil/gate-practice-app"},
    {"head__ref": "feature/thing"},
    {"head__ref": "spec/thing"},
    {"user__login": "someone"},
    {"user__login": W.SLUG},
], ids=["closed", "base", "fork", "head_ref", "spec_ref", "author", "author_without_bot"])
def test_lr42_not_a_fix_target(world, check, override):
    world.set_up_fix(comments=False)
    world.set_up_pr(**override)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NOT_A_FIX_TARGET")
    assert res.model is None and not res.pushed
    assert W.gate_commands(res, "decide") == []


def test_lr42_missing_pr(world, check):
    world.set_up_fix(comments=False)
    del world.api.pulls[W.PR_NUMBER]
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NOT_A_FIX_TARGET")
    assert res.model is None and not res.pushed


def test_lr43_reports_untrusted(world, check):
    world.set_up_fix(comments=False)
    shas = W.git("--git-dir", str(world.remote), "rev-list", "reports").split()
    world.api.foreign_report_commits.add(shas[1])
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "REPORTS_UNTRUSTED")
    assert res.model is None and not res.pushed
    assert W.gate_commands(res, "decide") == []


def test_lr44_reports_unreadable(world, check):
    """LR-44 names `REPORTS_UNREADABLE` for `ls-remote ... reports` giving
    neither 0 nor 2. Amendment 1, A8 also lists `REMOTE_UNREADABLE` with the
    same words; LR-44's own code is expected here (reported as an overlap)."""
    world.set_up_fix(comments=False)
    gone = world.remote.with_name("remote-gone.git")

    def break_remote():
        for _ in range(25):
            try:
                os.rename(world.remote, gone)
                break
            except OSError:
                time.sleep(0.2)
        world.remote = gone
        world.api.bare_repo = str(gone)

    world.api.after("GET", rf"^/repos/{W.REPOSITORY}/commits\?", break_remote)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    assert gone.exists(), "the test could not make the remote unreadable"
    check.stopped(res, "REPORTS_UNREADABLE")
    assert res.model is None
    assert W.gate_commands(res, "decide") == []


def test_lr44_lr45_no_reports_branch_gives_an_empty_folder_and_no_record(world, check):
    world.set_up_fix(records=False, comments=False)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NO_RECORD")
    assert res.model is None and not res.pushed
    stored = res.run_dir / "stored" / "reports"
    assert stored.is_dir() and list(stored.iterdir()) == []


def test_lr45_no_record_for_this_head(world, check):
    world.set_up_fix(comments=False, include_head=False)
    res = world.run("fix", "--pr", "7", steps=FIX_STEPS)
    check.stopped(res, "NO_RECORD")
    assert res.model is None and not res.pushed


def test_lr38_head_moved(world, check, tmp_path):
    world.set_up_fix(comments=False)
    flag = tmp_path / "moved.flag"
    world.api.moved_head_flag = str(flag)
    world.api.moved_head_sha = "f" * 40
    world.api.moved_pr = W.PR_NUMBER
    steps = FIX_STEPS + [{"op": "touch", "file": str(flag)}]
    res = world.run("fix", "--pr", "7", steps=steps)
    check.post_model_stop(res, "HEAD_MOVED")


def test_lr38_lr48_branch_moved_during_the_model_is_head_moved(world, check, tmp_path):
    """Someone force-pushes the PR's branch while the model works. The fake
    API's PR head follows the branch, so LR-38's re-read before the push
    sees it: HEAD_MOVED, and the launcher pushes nothing."""
    world.set_up_fix(comments=False)
    record = tmp_path / "race.txt"
    steps = FIX_STEPS + [{"op": "push_race", "remote": str(world.remote), "force": True,
                          "ref": f"refs/heads/{W.PR_BRANCH}", "record": str(record)}]
    res = world.run("fix", "--pr", "7", steps=steps)
    check.stopped(res, "HEAD_MOVED")
    assert res.model is not None
    assert res.git_commands("push") == [], "the launcher started git push"
    racing = record.read_text(encoding="utf-8").strip()
    assert world.remote_refs()[f"refs/heads/{W.PR_BRANCH}"] == racing


def test_lr39_lr48_branch_moved_after_the_reread_is_push_failed(world, check, tmp_path):
    """The branch moves (forced) right after the fake API answered the
    re-read of LR-38 with the old head: the push, never forced, is refused
    (PUSH_FAILED) and the other writer's commit stays."""
    world.set_up_fix(comments=False)
    racing = W.make_racing_commit(world, {"app/other.py": "x = 9\n"})
    done = tmp_path / "model-done.flag"

    def move_branch():
        W.git("--git-dir", str(world.remote), "update-ref", f"refs/heads/{W.PR_BRANCH}", racing)

    world.api.after("GET", rf"^/repos/{W.REPOSITORY}/pulls/{W.PR_NUMBER}(\?|$)", move_branch,
                    when=done.exists)
    steps = FIX_STEPS + [{"op": "touch", "file": str(done)}]
    res = world.run("fix", "--pr", "7", steps=steps)
    assert world.api.after_hooks[0][3], "no GET /pulls/7 came after the model: no re-read"
    check.stopped(res, "PUSH_FAILED")
    assert res.git_commands("push"), "the launcher did not try to push"
    assert world.remote_refs()[f"refs/heads/{W.PR_BRANCH}"] == racing, "the push overwrote the branch"
