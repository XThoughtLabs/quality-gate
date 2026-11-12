"""FN-10: a success re-reads every condition of the decision, not only the review (CONTRACTS.md section 8.5; round 2b).

The customer's finding A2 of the re-acceptance of round 2 (2026-11-12): after FN-9 the success post re-read only the
newest review, so a newer `gate/tests` with failure on the same SHA, which came after the decision's read, did not stop
`gate/final` success and `ready-for-human`, in the archive job and in finalize alike. These tests change the check runs
at named moments, never by time: between the decision's own read and the post, just after the success post, and at a
success post that fails. Black box, through `python -P -m gate.<name>` against the GitHub stand-in of
test_final_after_review, with one more seam: a test may change the check runs once a check-run read is answered.

In the archive job, `gate/archive` is the job's own (FN-8): the decision, and the decision made again, keep the archive
job's own `gate/archive` as the decision found it (FN-10), so the API's `gate/archive` is an input of finalize only.
"""
from __future__ import annotations

import pytest

from gatekit import assert_no_traceback
from test_final_after_review import (CUT_201, HEAD, SEVEN, SIX, TOKEN, Hub, Lost, Ready, check_run, ran, status,
                                     text_of)

PATHS = ["archive", "finalize"]
FAILED = ["failure", "cancelled", "neutral", "skipped"]      # completed with anything but success (FN-1)
NOT_COMPLETED = ["in_progress", "queued"]
UNREADABLE = "unreadable"                                    # every later read of the check runs answers 500
NAMES = {"archive": SIX, "finalize": SEVEN}                  # the mandatory checks each path reads from the API


class Hub10(Hub):
    """The stand-in of FN-9, with a seam on the check runs: after_runs_read is called with the read's number once its
    answer is fixed, before it is sent."""

    def __init__(self, stub):
        super().__init__(stub)
        self.run_reads = 0
        self.after_runs_read = None

    def _runs(self, req):
        if "runs" in self.broken:
            return 500, {"message": "boom"}
        sha = req.path.split("/commits/", 1)[1].split("/", 1)[0]
        runs = list(self.runs.get(sha, [])) if (req.q("page") or "1") == "1" else []
        self.run_reads += 1
        if self.after_runs_read is not None:
            self.after_runs_read(self.run_reads)
        return 200, {"total_count": len(runs), "check_runs": runs}


@pytest.fixture
def hub(stub):
    return Hub10(stub)


def newer_run(hub, name, kind):
    """A newer check run of `name` on the head, with a larger id (FN-1: the newest run counts), or for UNREADABLE every
    later read of the check runs fails."""
    if kind == UNREADABLE:
        hub.broken.add("runs")
        return None
    run = check_run(name, state=kind) if kind in NOT_COMPLETED else check_run(name, conclusion=kind)
    hub.runs[HEAD].append(run)
    return run


def run_path(world, path):
    return world.archive_post(world.archive_read()) if path == "archive" else world.finalize(world.first, "A")


def expected_conclusion(kind):
    return None if kind in NOT_COMPLETED else "failure"


def assert_newest_follows(hub, kind, name, why):
    """The newest gate/final follows the newer check run: blocked for a failed one, waiting for the mandatory checks for
    one not completed, incomplete for check runs that cannot be read (FN-10, FN-4); never success."""
    posted = hub.posted()
    seen = [(b.get("status"), b.get("conclusion")) for b in posted]
    assert posted, f"gate/final was posted ({why})"
    last = posted[-1]
    assert not (last.get("status") == "completed" and last.get("conclusion") == "success"), (
        f"FN-10: the newest gate/final is success while the newest {name} is {kind} ({why}); gate/final posts in order: {seen}")
    summary = last["output"]["summary"]
    if kind in FAILED:
        assert (last["status"], last.get("conclusion")) == ("completed", "failure"), seen
        assert summary.startswith("Final verdict: blocked"), last["output"]
        assert f"FAILED_CHECK: {name} did not succeed on {HEAD}" in summary, last["output"]
    elif kind in NOT_COMPLETED:
        assert last["status"] == "in_progress" and last.get("conclusion") is None, seen
        assert last["output"]["title"] == f"gate/final: waiting for the mandatory checks on {HEAD}", last["output"]
        assert f"CHECK_NOT_COMPLETED: {name} is not completed on {HEAD}" in summary, last["output"]
        assert "checks passed" not in summary, f"a check not completed: the summary must not say the checks passed\n{summary}"
    else:
        assert (last["status"], last.get("conclusion")) == ("completed", "failure"), seen
        assert summary.startswith("Final verdict: incomplete"), last["output"]
        assert "CHECKS_UNREADABLE" in summary, last["output"]
    assert last["head_sha"] == HEAD
    assert "ready-for-human" not in text_of(last)


def change_between_read_and_post(world, hub, name, kind):
    """The decision's own read of the check runs (read 1: final-facts in the archive job, finalize's own read) is
    answered; then the newer run comes, before the success would be posted."""
    came = []

    def between(number):
        if number == 1 and not came:
            came.append(newer_run(hub, name, kind) or kind)

    hub.after_runs_read = between
    return came


def change_at_the_success_post(world, hub, name, kind):
    """The newer run comes as the success post arrives (its own decision has nothing to do with it), so only a read
    after the post can see it."""
    came = []

    def as_posted(body):
        if body.get("name") == "gate/final" and body.get("conclusion") == "success" and not came:
            came.append(newer_run(hub, name, kind) or kind)
        return None

    hub.on_post = as_posted
    return came


# ----------------------------------------------------------------------------- b) before the post


@pytest.mark.req("FN-10", "FN-1")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("kind", [*NOT_COMPLETED, UNREADABLE])
def test_fn10_b_a_newer_mandatory_run_not_completed_between_the_read_and_the_post_is_never_success(tmp_path, hub, path, kind):
    """A newer gate/tests that is queued or in progress (or check runs that can no longer be read) between the decision's
    read and its post: no success at all, not even for a moment that a read after the post would correct."""
    world = Ready(tmp_path, hub)
    came = change_between_read_and_post(world, hub, "gate/tests", kind)
    res = run_path(world, path)
    hub.after_runs_read = None
    ran(res)
    assert came, "precondition: the decision's own read of the check runs was answered before the change"
    assert all(b.get("conclusion") != "success" for b in hub.posted()), (
        f"FN-10: a success was posted though the newest gate/tests was {kind} just before the post: {hub.posted()}")
    assert_newest_follows(hub, kind, "gate/tests", f"a {kind} gate/tests between the read and the post ({path})")


# ----------------------------------------------------------------------------- c) after the post


@pytest.mark.req("FN-10", "FN-1", "FN-4")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("kind", [*FAILED, *NOT_COMPLETED, UNREADABLE])
def test_fn10_c_a_newer_failed_or_unfinished_mandatory_run_just_after_the_success_post_is_followed(tmp_path, hub, path, kind):
    """The read after the post: the newer gate/tests came just after the success was posted. Nothing else will post for
    it (a check run starts no workflow), so the run that posted the success must follow it."""
    world = Ready(tmp_path, hub)
    came = change_at_the_success_post(world, hub, "gate/tests", kind)
    res = run_path(world, path)
    hub.on_post = None
    ran(res)
    assert came, "precondition: a success was posted while every condition held"
    assert_newest_follows(hub, kind, "gate/tests", f"a {kind} gate/tests just after the success post ({path})")


# ----------------------------------------------------------------------------- d) every mandatory check


@pytest.mark.req("FN-10", "FN-1")
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("kind", ["failure", "in_progress"])
@pytest.mark.parametrize("path,name", [(p, n) for p in PATHS for n in NAMES[p]])
def test_fn10_d_every_mandatory_check_is_read_again_not_only_gate_tests(tmp_path, hub, path, name, kind, when):
    """The same for each mandatory check of Q-2 (but gate/final): gate/env, gate/tests, gate/acceptance, gate/guard,
    gate/security, gate/report, and gate/archive in finalize (in the archive job it is the job's own, FN-8)."""
    world = Ready(tmp_path, hub)
    change = change_between_read_and_post if when == "before" else change_at_the_success_post
    came = change(world, hub, name, kind)
    res = run_path(world, path)
    hub.after_runs_read = hub.on_post = None
    ran(res)
    assert came, f"precondition: the newer {name} came {when} the post"
    if when == "before":
        assert all(b.get("conclusion") != "success" for b in hub.posted()), hub.posted()
    assert_newest_follows(hub, kind, name, f"a {kind} {name} {when} the success post ({path})")


# ----------------------------------------------------------------------------- e) a success post that fails


@pytest.mark.req("FN-10", "FN-9")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("kind", ["failure", "in_progress"])
@pytest.mark.parametrize("answer", ["lost", "refused"])
def test_fn10_e_a_newer_mandatory_run_at_a_failed_success_post_is_followed_instead_of_a_second_try(tmp_path, hub, path, kind, answer):
    """The first success post fails (GitHub stored it and the answer was lost, or GitHub refused it) while a newer
    gate/tests comes. The decision is made again before a second try: no second success, its post instead (L75)."""
    world = Ready(tmp_path, hub)
    seen = []

    def as_posted(body):
        if body.get("name") != "gate/final":
            return None
        seen.append(body)
        if body.get("conclusion") == "success" and len(seen) == 1:
            newer_run(hub, "gate/tests", kind)
            return Lost(CUT_201) if answer == "lost" else (500, {"message": "boom"})
        return None

    hub.on_post = as_posted
    res = run_path(world, path)
    hub.on_post = None
    ran(res)
    assert [b.get("conclusion") for b in seen] == ["success", expected_conclusion(kind)], (
        f"FN-10: the success must not be tried again once the newest gate/tests is {kind}: {seen}")
    assert_newest_follows(hub, kind, "gate/tests", f"a {kind} gate/tests at a {answer} success post ({path})")


@pytest.mark.req("FN-10", "FN-9")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("kind", ["failure", "in_progress"])
def test_fn10_e_a_success_lost_twice_is_followed_by_a_newer_mandatory_run_then_exit_1(tmp_path, hub, path, kind):
    """Both success posts are stored with their answers lost, and a newer gate/tests comes at the second (L67): the
    decision made again is followed by its post, then the run exits 1."""
    world = Ready(tmp_path, hub)
    seen = []

    def as_posted(body):
        if body.get("name") != "gate/final":
            return None
        seen.append(body)
        if body.get("conclusion") != "success":
            return None
        if len(seen) == 2:
            newer_run(hub, "gate/tests", kind)
        return Lost(CUT_201)

    hub.on_post = as_posted
    res = run_path(world, path)
    hub.on_post = None
    assert_no_traceback(res)
    assert TOKEN not in res.both
    assert res.rc == 1, res.describe()
    assert [b.get("conclusion") for b in seen] == ["success", "success", expected_conclusion(kind)], seen
    assert_newest_follows(hub, kind, "gate/tests", f"a {kind} gate/tests at the second lost success ({path})")


# ----------------------------------------------------------------------------- the decision itself: a run not completed


@pytest.mark.req("FN-10", "FN-4", "FN-8")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("kind", NOT_COMPLETED)
def test_fn10_a_mandatory_run_not_completed_at_the_decisions_own_read_waits_for_the_checks(tmp_path, hub, path, kind):
    """One decision: the first decision of the archive job and of finalize gives a newest mandatory run that is queued
    or in progress what the decision made again gives it, gate/final in progress, never success nor a failure."""
    world = Ready(tmp_path, hub)
    newer_run(hub, "gate/tests", kind)
    res = world.finalize(world.first, "A") if path == "finalize" else world.archive_post(archive_read_any(world))
    ran(res)
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("in_progress", None)], posted
    assert_newest_follows(hub, kind, "gate/tests", f"a {kind} gate/tests at the decision's own read ({path})")


def archive_read_any(world):
    """The archive job up to its post, whatever its decision (Ready.archive_read requires ready-for-human)."""
    from gatekit import load_out, run_gate, write_json
    from test_final_after_review import ARCH_OK, verdict_obj

    folder = world.tmp / "archive"
    verdict = write_json(folder / "verdict.json", verdict_obj())
    archive = write_json(folder / "archive.json", ARCH_OK)
    facts, out = folder / "facts.json", folder / "final" / "final.json"
    res = run_gate("publish", "final-facts", "--head-sha", HEAD, "--config", world.cfg, "--out", facts, env=world.hub.env())
    assert res.rc == 0, res.describe()
    res = run_gate("report", "final", "--verdict", verdict, "--archive", archive, "--facts", facts, "--out", out)
    assert res.rc == 0, res.describe()
    load_out(res, out)
    return out


# ----------------------------------------------------------------------------- f) controls: pass on both codes


@pytest.mark.req("FN-10", "FN-9")
@pytest.mark.parametrize("path", PATHS)
def test_fn10_f_control_no_change_gives_one_success_and_nothing_after(tmp_path, hub, path):
    world = Ready(tmp_path, hub)
    ran(run_path(world, path))
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("completed", "success")], posted
    assert posted[0]["output"]["summary"].startswith("Final verdict: ready-for-human"), posted[0]["output"]


@pytest.mark.req("FN-10", "FN-1")
@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("when", ["before", "after"])
def test_fn10_f_control_a_newer_success_run_of_the_same_check_gives_one_success_and_nothing_after(tmp_path, hub, path, when):
    world = Ready(tmp_path, hub)
    change = change_between_read_and_post if when == "before" else change_at_the_success_post
    came = change(world, hub, "gate/tests", "success")
    ran(run_path(world, path))
    hub.after_runs_read = hub.on_post = None
    assert came, f"precondition: a newer successful gate/tests came {when} the post"
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("completed", "success")], posted


# ----------------------------------------------------------------------------- reruns (step 1's research): controls


@pytest.mark.req("FN-10", "FN-8")
def test_fn10_control_a_rerun_of_the_archive_job_after_a_newer_failed_check_ends_blocked(tmp_path, hub):
    """P3: after the archive job's success, a newer failed gate/tests; a rerun of the archive job decides on the newest
    check runs and posts last."""
    world = Ready(tmp_path, hub)
    ran(world.archive_post(world.archive_read()))
    assert [b.get("conclusion") for b in hub.posted()] == ["success"], "precondition: attempt 1 posted success"
    newer_run(hub, "gate/tests", "failure")
    ran(world.archive_post(archive_read_any(world)))
    assert_newest_follows(hub, "failure", "gate/tests", "a rerun of the archive job after a newer failed gate/tests")


@pytest.mark.req("FN-10", "FN-4")
def test_fn10_control_a_rerun_of_finalize_after_a_newer_failed_check_ends_blocked(tmp_path, hub):
    """P5: after finalize's success, a newer failed gate/tests; a rerun of that finalize run (the same event) decides on
    the newest check runs."""
    world = Ready(tmp_path, hub)
    ran(world.finalize(world.first, "A"))
    assert [b.get("conclusion") for b in hub.posted()] == ["success"], "precondition: run A posted success"
    newer_run(hub, "gate/tests", "failure")
    ran(world.finalize(world.first, "A-rerun"))
    assert_newest_follows(hub, "failure", "gate/tests", "a rerun of finalize after a newer failed gate/tests")


@pytest.mark.req("FN-10", "FN-9")
@pytest.mark.parametrize("path", PATHS)
def test_fn10_control_a_review_and_a_check_that_change_together_follow_the_decisions_order(tmp_path, hub, path):
    """A control (FN-9 already followed the review): just after the success post both the review (the reviewer's
    pending) and gate/tests (failure) change. The decision's order holds, a review that is not the reviewer's success
    decides first, never success."""
    world = Ready(tmp_path, hub)
    came = []

    def as_posted(body):
        if body.get("name") == "gate/final" and body.get("conclusion") == "success" and not came:
            hub.statuses[HEAD].insert(0, status("pending"))
            came.append(newer_run(hub, "gate/tests", "failure"))
        return None

    hub.on_post = as_posted
    res = run_path(world, path)
    hub.on_post = None
    ran(res)
    assert came, "precondition: a success was posted"
    last = hub.posted()[-1]
    assert last["status"] == "in_progress" and last.get("conclusion") is None, hub.posted()
    assert last["output"]["title"] == f"gate/final: waiting for the independent review on {HEAD}", last["output"]
    assert "REVIEW_PENDING" in last["output"]["summary"], last["output"]


# ----------------------------------------------------------------------------- the decision made again: its inputs


@pytest.mark.req("FN-10", "FN-1")
@pytest.mark.parametrize("path", PATHS)
def test_fn10_a_the_customers_schedule_gives_no_success_at_all(tmp_path, hub, path):
    """The customer's schedule (a newer failed gate/tests while the review is read again before the post), asserted
    more strictly than the customer's own test: the decision made again reads the statuses and then the check runs, so
    the failure is seen before the post and no success is posted at all."""
    world = Ready(tmp_path, hub)

    def after_status_read(number):
        if number == 2:   # read 1 is the decision's own; read 2 is the read again before the post
            newer_run(hub, "gate/tests", "failure")

    hub.after_read = after_status_read
    ran(run_path(world, path))
    hub.after_read = None
    assert all(b.get("conclusion") != "success" for b in hub.posted()), hub.posted()
    assert_newest_follows(hub, "failure", "gate/tests", f"the customer's schedule, strictly ({path})")


def final_file(tmp_path, *, verdict="ready-for-human", check=("completed", "success"), gate_verdict="ready-for-human",
               archive="success"):
    from gatekit import write_json
    from test_final_after_review import CREATORS

    content = {"verdict": verdict, "reasons": [], "gate_reasons": [],
               "final_check": {"status": check[0], "conclusion": check[1]},
               "conclusions": {"gate/archive": archive, "gate/final": check[1]},
               "reviewer": {"login": CREATORS["reviewer"]["login"], "id": CREATORS["reviewer"]["id"]}}
    if gate_verdict is not None:
        content["gate_verdict"] = gate_verdict
    return write_json(tmp_path / "final.json", content)


def post_final(hub, final):
    from gatekit import run_gate

    return run_gate("publish", "post-final", "--final", final, "--head-sha", HEAD, env=hub.env())


@pytest.mark.req("FN-10", "FN-1", "F-1")
@pytest.mark.parametrize("gate_verdict,archive,shown,code", [
    ("blocked", "success", "blocked", None),
    (None, "success", "incomplete", "NO_RECORD"),
    ("ready-for-human", "failure", "incomplete", "EVIDENCE_NOT_STORED"),
], ids=["gate-verdict-blocked", "no-gate-verdict", "archive-failed"])
def test_fn10_post_final_makes_the_decision_again_on_the_files_own_record(tmp_path, hub, gate_verdict, archive, shown, code):
    """post-final's decision made again takes the gate's own verdict and the archive's state from final.json as the
    decision found them: a file whose final_check says success while its own record does not allow it never posts
    success, though every check run and the review on the head would."""
    # Strengthened after the code, for the mutants FN10-inputs-verdict and FN10-inputs-archive (round 2b, step 5): the
    # final verdict and its reason, not only a failure. It still fails on 76ab28b's code, where a success is posted.
    Ready(tmp_path, hub)
    ran(post_final(hub, final_file(tmp_path, gate_verdict=gate_verdict, archive=archive)))
    posted = hub.posted()
    assert posted and all(b.get("conclusion") != "success" for b in posted), posted
    assert (posted[-1]["status"], posted[-1].get("conclusion")) == ("completed", "failure"), posted
    assert posted[-1]["output"]["summary"].startswith(f"Final verdict: {shown}"), posted[-1]["output"]
    if code:
        assert code in posted[-1]["output"]["summary"], posted[-1]["output"]


@pytest.mark.req("FN-10", "FN-1", "F-3")
@pytest.mark.parametrize("verdict,check", [("blocked", ("completed", "success")), ("ready-for-human", ("in_progress", "success"))],
                         ids=["success-but-blocked", "success-but-in-progress"])
def test_fn10_control_post_final_success_only_for_a_file_whose_final_check_and_verdict_agree(tmp_path, hub, verdict, check):
    """The file's own consistency (mutant FIN-post-success): its record, every check run and the review would allow a
    success, so only final_check and verdict keep it away."""
    Ready(tmp_path, hub)
    ran(post_final(hub, final_file(tmp_path, verdict=verdict, check=check)))
    posted = hub.posted()
    assert posted and all(b.get("conclusion") != "success" for b in posted), posted


@pytest.mark.req("FN-10", "FN-8")
def test_fn10_control_the_archive_jobs_own_gate_archive_stands_in_its_decision_made_again(tmp_path, hub):
    """In the archive job, gate/archive is the job's own (FN-8), as the decision found it (FN-10): the job posted it just
    before gate/final. A newer gate/archive of another run does not change this job's decision; that run posts its own
    gate/final right after its gate/archive, in the same step (LIMITATIONS.md L77)."""
    world = Ready(tmp_path, hub)
    change_between_read_and_post(world, hub, "gate/archive", "failure")
    ran(world.archive_post(world.archive_read()))
    hub.after_runs_read = None
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("completed", "success")], posted
