"""The final verdict after the independent review (CONTRACTS.md section 8.5, FN-1 to FN-8; round 2).

The customer's finding of 2026-11-10: in run 42751543290 `gate/final` became success before the mandatory independent
review. These tests show that a missing, pending, failed, other-commit or other-creator review never gives a green
`gate/final`, through the archive job's commands (`gate.publish final-facts`, `gate.report final --facts`,
`gate.publish post-final`) and through finalize (`gate.publish finalize`). Black box: every script is reached through
`python -P -m gate.<name>`, and GitHub is a local stand-in whose routes are the ones section 8.5 names.
"""
from __future__ import annotations

import copy
import json
import re

import pytest

from gatekit import RawResponse, assert_no_traceback, base_env, load_out, make_config, run_gate, write_json
from reportkit import World

REPO = "example-org/example-app"
HEAD = "1" * 40          # the PR's head, the commit the judge ran on
OTHER = "2" * 40         # another commit of the same PR (an earlier head)
NEWER = "3" * 40         # the PR's head after a new push
PR = 7
TOKEN = "SENTINEL-VALUE-1234-GATE_TOKEN"
ACTIONS_APP = 15368
REVIEW = "independent-review"
SIX = ["gate/env", "gate/tests", "gate/acceptance", "gate/guard", "gate/security", "gate/report"]
SEVEN = SIX + ["gate/archive"]
ARCH_OK = {"stored": True, "sha256sums_match": True, "path": "reports/7/1001-1", "commit": "a" * 40, "reason": None,
           "artifact_present": True, "skipped_unsafe": [], "actors_ok": True}

CREATORS = {
    "reviewer": {"login": "example-reviewer[bot]", "id": 9001, "type": "Bot"},
    "ceo": {"login": "example-owner", "id": 501, "type": "User"},
    "executor": {"login": "example-executor[bot]", "id": 9002, "type": "Bot"},
    "same-login-other-id": {"login": "example-reviewer[bot]", "id": 4242, "type": "Bot"},
    "same-login-not-a-bot": {"login": "example-reviewer[bot]", "id": 9001, "type": "User"},
    "same-id-other-login": {"login": "someone-else[bot]", "id": 9001, "type": "Bot"},
}
NOT_THE_REVIEWER = ["ceo", "executor", "same-login-other-id", "same-login-not-a-bot", "same-id-other-login"]

_ids = iter(range(70_000, 10**9))


def status(state, who="reviewer", context=REVIEW):
    return {"id": next(_ids), "state": state, "context": context, "description": "Codex: pass",
            "creator": copy.deepcopy(CREATORS[who]), "created_at": "2026-11-10T03:59:45Z"}


def check_run(name, conclusion="success", state="completed", app=ACTIONS_APP, head=HEAD):
    return {"id": next(_ids), "name": name, "head_sha": head, "status": state,
            "conclusion": conclusion if state == "completed" else None,
            "app": {"id": app, "slug": "github-actions" if app == ACTIONS_APP else "another-app"}}


def green_runs(names=SIX, head=HEAD):
    return [check_run(name, head=head) for name in names]


def pull(number=PR, head=HEAD, base="candidate/a", state="open"):
    return {"number": number, "state": state, "head": {"sha": head, "ref": "ai/7-example", "repo": {"full_name": REPO}},
            "base": {"ref": base, "repo": {"full_name": REPO}}}


class Hub:
    """The GitHub stand-in: statuses and check runs per commit, the open PRs, the reviewer's account, and check-run posts."""

    def __init__(self, stub):
        self.stub = stub
        self.statuses: dict[str, list] = {}
        self.runs: dict[str, list] = {}
        self.pulls = [pull()]
        self.users = {c["login"]: c for c in (CREATORS["reviewer"], CREATORS["executor"], CREATORS["ceo"])}
        self.broken: set[str] = set()      # reads that answer 500: statuses, runs, users, pulls
        # The seams of FN-9's interleaving tests: a test changes the stand-in's state at a named moment, never by time.
        self.reads = 0                     # statuses reads answered so far
        self.after_read = None             # called with the read's number once its answer is fixed, before it is sent
        self.on_post = None                # called with a check-run post's body as it arrives; may return a refusal
        self.garbled = None                # bytes every statuses read answers with, as sent (FN-9: a failure is never silence)
        self.refused: list = []            # posts answered with a refusal: never counted as posted
        repo = re.escape(REPO)
        stub.route("GET", r"/users/(.+)", self._user)
        stub.route("GET", rf"/repos/{repo}/commits/([^/]+)/statuses", self._statuses)
        stub.route("GET", rf"/repos/{repo}/commits/([^/]+)/check-runs", self._runs)
        stub.route("GET", rf"/repos/{repo}/pulls", self._pulls)
        stub.route("POST", rf"/repos/{repo}/check-runs", self._post)

    def _user(self, req):
        if "users" in self.broken:
            return 500, {"message": "boom"}
        login = req.path.split("/users/", 1)[1]
        return (200, self.users[login]) if login in self.users else (404, {"message": "Not Found"})

    def _statuses(self, req):
        if "statuses" in self.broken:
            return 500, {"message": "boom"}
        if self.garbled is not None:
            return RawResponse(self.garbled)
        sha = req.path.split("/commits/", 1)[1].split("/", 1)[0]
        answer = list(self.statuses.get(sha, [])) if (req.q("page") or "1") == "1" else []
        self.reads += 1
        if self.after_read is not None:
            self.after_read(self.reads)
        return 200, answer

    def _post(self, req):
        refusal = self.on_post(req.json()) if self.on_post is not None else None
        if refusal is not None:
            if not isinstance(refusal, Lost):   # a Lost answer: GitHub stored the post, only its answer is lost
                self.refused.append(req)
            return refusal
        return 201, {"id": 1}

    def _runs(self, req):
        if "runs" in self.broken:
            return 500, {"message": "boom"}
        sha = req.path.split("/commits/", 1)[1].split("/", 1)[0]
        runs = self.runs.get(sha, []) if (req.q("page") or "1") == "1" else []
        return 200, {"total_count": len(runs), "check_runs": runs}

    def _pulls(self, req):
        if "pulls" in self.broken:
            return 500, {"message": "boom"}
        return 200, ([p for p in self.pulls if p["state"] == "open"] if (req.q("page") or "1") == "1" else [])

    def writes(self):
        return [r for r in self.stub.requests if r.method not in ("GET", "HEAD")]

    def posted(self, name="gate/final"):
        return [r.json() for r in self.writes()
                if r.path.endswith("/check-runs") and r.json().get("name") == name and not any(r is x for x in self.refused)]

    def env(self):
        return base_env({"GATE_TOKEN": TOKEN, "GITHUB_API_URL": self.stub.url, "GITHUB_REPOSITORY": REPO})


@pytest.fixture
def hub(stub):
    return Hub(stub)


def config(tmp_path):
    return make_config(tmp_path / "quality.toml")


def verdict_obj(verdict="ready-for-human"):
    checks = {c: "success" for c in SIX}
    reasons = []
    if verdict == "blocked":
        checks["gate/tests"] = "failure"
        reasons = [{"code": "FAILED_CHECK", "detail": "gate/tests failed"}]
    elif verdict == "needs-human":
        reasons = [{"code": "REPEATED_FIX", "detail": "same diff as an earlier round"}]
    elif verdict == "incomplete":
        reasons = [{"code": "MISSING_OUTPUT", "detail": "meta.json is missing"}]
    return {"verdict": verdict, "reasons": reasons, "checks": checks}


def text_of(body) -> str:
    return json.dumps(body, sort_keys=True)


def codes(d) -> list[str]:
    return [r.get("code") for r in d.get("reasons", [])]


# ----------------------------------------------------------------------------- the archive job's chain


def archive_chain(tmp_path, hub, *, prelim="ready-for-human", archive=ARCH_OK, facts=True, head=HEAD):
    """final-facts (when facts) -> report final -> post-final, as judge.yml's archive job runs them (Y-24)."""
    cfg = config(tmp_path)
    v = write_json(tmp_path / "verdict.json", verdict_obj(prelim))
    a = write_json(tmp_path / "archive.json", archive)
    out = tmp_path / "final" / "final.json"
    extra = []
    if facts:
        facts_path = tmp_path / "facts.json"
        res = run_gate("publish", "final-facts", "--head-sha", head, "--config", cfg, "--out", facts_path, env=hub.env())
        assert res.rc == 0, f"precondition: gate.publish final-facts reads the facts (section 8.5)\n{res.describe()}"
        extra = ["--facts", facts_path]
    res = run_gate("report", "final", "--verdict", v, "--archive", a, "--out", out, *extra)
    assert res.rc == 0, f"gate.report final must write the final verdict\n{res.describe()}"
    final = load_out(res, out)
    res = run_gate("publish", "post-final", "--final", out, "--head-sha", head, env=hub.env())
    assert res.rc == 0, f"gate.publish post-final must post the two checks\n{res.describe()}"
    assert TOKEN not in res.both
    return final, hub.posted("gate/final"), hub.posted("gate/archive")


def assert_waiting(final, posted, head=HEAD):
    assert len(posted) == 1, f"exactly one gate/final is posted, got {posted}"
    body = posted[0]
    assert body.get("status") == "in_progress" and body.get("conclusion") is None, (
        f"without a successful review by the reviewer, gate/final must stay in progress, never completed (FN-2)\n{body}")
    assert body["head_sha"] == head
    assert body["output"]["title"] == f"gate/final: waiting for the independent review on {head}", body["output"]
    assert "ready-for-human" not in text_of(body), "nothing waiting may say ready-for-human (FN-1, FN-7)"
    assert final["verdict"] == "awaiting-review" and final["gate_verdict"] == "ready-for-human"
    assert final["final_check"] == {"status": "in_progress", "conclusion": None}


def assert_completed(posted, conclusion, head=HEAD):
    assert len(posted) == 1, f"exactly one gate/final is posted, got {posted}"
    body = posted[0]
    assert body.get("status") == "completed" and body.get("conclusion") == conclusion, body
    assert body["head_sha"] == head
    return body


@pytest.mark.req("FN-2", "FN-1")
def test_fn2_a_ready_run_with_no_review_leaves_gate_final_in_progress_never_success(tmp_path, hub):
    """The customer's finding: the archive job made gate/final success before any review existed."""
    final, posted, archive = archive_chain(tmp_path, hub, facts=False)
    assert_waiting(final, posted)
    assert [b.get("conclusion") for b in archive] == ["success"], "gate/archive itself is completed as before"


@pytest.mark.req("FN-2")
def test_fn2_a_ready_run_whose_head_has_no_review_status_waits(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)
    assert "REVIEW_MISSING" in codes(final)


@pytest.mark.req("FN-2")
def test_fn2_a_pending_review_waits(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("pending")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)
    assert "REVIEW_PENDING" in codes(final)


@pytest.mark.req("FN-2", "FN-4")
@pytest.mark.parametrize("broken", ["statuses", "users"])
def test_fn2_an_unreadable_review_or_reviewer_account_waits(tmp_path, hub, broken):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success")]
    hub.broken.add(broken)
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)
    assert "REVIEW_UNREADABLE" in codes(final)


@pytest.mark.req("FN-2", "F-3")
@pytest.mark.parametrize("prelim", ["blocked", "incomplete", "needs-human"])
def test_fn2_control_a_verdict_that_is_not_ready_is_completed_failure_as_before(tmp_path, hub, prelim):
    """A control: passes with and without round 2, when no review facts are given."""
    final, posted, _ = archive_chain(tmp_path, hub, prelim=prelim, facts=False)
    body = assert_completed(posted, "failure")
    assert final["verdict"] == prelim
    assert prelim in body["output"]["summary"]


@pytest.mark.req("FN-2", "FN-8")
@pytest.mark.parametrize("prelim", ["blocked", "incomplete", "needs-human"])
def test_fn2_a_verdict_that_is_not_ready_stays_even_after_a_successful_review(tmp_path, hub, prelim):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub, prelim=prelim)
    assert_completed(posted, "failure")
    assert final["verdict"] == prelim and final["gate_verdict"] == prelim


@pytest.mark.req("FN-2", "FN-1", "F-2")
@pytest.mark.parametrize("archive", [dict(ARCH_OK, stored=False, reason="TOO_LARGE"), dict(ARCH_OK, sha256sums_match=False),
                                     dict(ARCH_OK, actors_ok=False)], ids=["not-stored", "sums-differ", "another-actor"])
def test_fn1_a_successful_review_never_makes_up_for_an_archive_that_is_not_complete(tmp_path, hub, archive):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub, archive=archive)
    assert_completed(posted, "failure")
    assert final["verdict"] != "ready-for-human"


# ----------------------------------------------------------------------------- FN-8: a review already there


@pytest.mark.req("FN-8", "FN-1")
def test_fn8_a_successful_review_already_on_the_head_gives_ready_for_human_from_the_archive_job(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    body = assert_completed(posted, "success")
    assert body["output"]["summary"].startswith("Final verdict: ready-for-human"), body["output"]
    assert final["verdict"] == "ready-for-human" and final["final_check"] == {"status": "completed", "conclusion": "success"}


@pytest.mark.req("FN-8", "FN-4")
@pytest.mark.parametrize("state", ["failure", "error"])
def test_fn8_a_failed_review_already_on_the_head_gives_blocked_review_failed(tmp_path, hub, state):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status(state)]
    final, posted, _ = archive_chain(tmp_path, hub)
    body = assert_completed(posted, "failure")
    assert final["verdict"] == "blocked" and "REVIEW_FAILED" in codes(final)
    assert "REVIEW_FAILED" in body["output"]["summary"]


@pytest.mark.req("FN-5", "FN-1")
@pytest.mark.parametrize("who", NOT_THE_REVIEWER)
def test_fn5_a_successful_review_by_anyone_but_the_reviewer_counts_as_no_review(tmp_path, hub, who):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success", who=who)]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)
    assert "REVIEW_NOT_BY_REVIEWER" in codes(final)


@pytest.mark.req("FN-1", "FN-5")
def test_fn1_the_newest_review_decides_a_later_success_by_another_creator_hides_the_reviewers(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success", who="ceo"), status("success")]   # newest first
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)


@pytest.mark.req("FN-1")
def test_fn1_the_newest_review_decides_a_later_failure_beats_an_earlier_success(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("failure"), status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")
    assert "REVIEW_FAILED" in codes(final)


@pytest.mark.req("FN-1")
def test_fn1_control_a_later_success_by_the_reviewer_beats_an_earlier_failure(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success"), status("failure")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "success")


@pytest.mark.req("FN-1")
def test_fn1_statuses_of_other_contexts_are_not_a_review(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success", context="ci/other"), status("success", context="gate/final")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)


@pytest.mark.req("FN-5", "FN-1")
def test_fn5_a_successful_review_of_another_commit_is_never_seen_for_the_head(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[OTHER] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_waiting(final, posted)


@pytest.mark.req("FN-1")
@pytest.mark.parametrize("name", SIX)
def test_fn1_a_successful_review_with_one_mandatory_check_failed_on_the_head_is_blocked(tmp_path, hub, name):
    hub.runs[HEAD] = [check_run(n, "failure" if n == name else "success") for n in SIX]
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")
    assert final["verdict"] == "blocked" and "FAILED_CHECK" in codes(final)


@pytest.mark.req("FN-1")
@pytest.mark.parametrize("name", SIX)
def test_fn1_a_successful_review_with_one_mandatory_check_missing_on_the_head_is_incomplete(tmp_path, hub, name):
    hub.runs[HEAD] = [check_run(n) for n in SIX if n != name]
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")
    assert final["verdict"] == "incomplete" and "MISSING_CHECK" in codes(final)


@pytest.mark.req("FN-1")
def test_fn1_unreadable_check_runs_are_never_success(tmp_path, hub):
    hub.runs[HEAD] = green_runs()
    hub.statuses[HEAD] = [status("success")]
    hub.broken.add("runs")
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")
    assert final["verdict"] == "incomplete" and "CHECKS_UNREADABLE" in codes(final)


@pytest.mark.req("FN-1")
@pytest.mark.parametrize("bad", ["another-app", "another-commit", "neutral", "skipped"])
def test_fn1_only_a_completed_success_of_the_actions_app_on_the_head_counts(tmp_path, hub, bad):
    # Changed by FN-10 (round 2b, the CEO's decision of 2026-11-12): the case "in-progress" asserted a completed
    # failure; FN-10 makes a mandatory run not completed wait (gate/final in progress, CHECK_NOT_COMPLETED). That case
    # is now test_fn10_a_mandatory_run_not_completed_at_the_decisions_own_read_waits_for_the_checks.
    runs = [check_run(n) for n in SIX if n != "gate/tests"]
    runs.append({
        "another-app": lambda: check_run("gate/tests", app=999),
        "another-commit": lambda: check_run("gate/tests", head=OTHER),
        "neutral": lambda: check_run("gate/tests", "neutral"),
        "skipped": lambda: check_run("gate/tests", "skipped"),
    }[bad]())
    hub.runs[HEAD] = runs
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")
    assert final["verdict"] != "ready-for-human"


@pytest.mark.req("FN-1")
def test_fn1_the_newest_run_of_a_check_counts_an_older_success_does_not_hide_a_newer_failure(tmp_path, hub):
    older = check_run("gate/tests")
    newer = check_run("gate/tests", "failure")
    hub.runs[HEAD] = [check_run(n) for n in SIX if n != "gate/tests"] + [newer, older]
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "failure")


@pytest.mark.req("FN-1")
def test_fn1_control_a_newer_success_of_a_check_replaces_an_older_failure(tmp_path, hub):
    older = check_run("gate/tests", "failure")
    newer = check_run("gate/tests")
    hub.runs[HEAD] = [check_run(n) for n in SIX if n != "gate/tests"] + [older, newer]
    hub.statuses[HEAD] = [status("success")]
    final, posted, _ = archive_chain(tmp_path, hub)
    assert_completed(posted, "success")


# ----------------------------------------------------------------------------- final-facts


@pytest.mark.req("FN-1", "FN-8")
def test_final_facts_writes_the_heads_statuses_check_runs_and_the_reviewers_account(tmp_path, hub):
    hub.statuses[HEAD] = [status("success")]
    hub.statuses[OTHER] = [status("failure")]
    hub.runs[HEAD] = green_runs()
    out = tmp_path / "facts.json"
    res = run_gate("publish", "final-facts", "--head-sha", HEAD, "--config", config(tmp_path), "--out", out, env=hub.env())
    assert res.rc == 0, res.describe()
    facts = load_out(res, out)
    assert facts["head_sha"] == HEAD
    assert [s["id"] for s in facts["statuses"]] == [s["id"] for s in hub.statuses[HEAD]]
    assert [r["id"] for r in facts["check_runs"]] == [r["id"] for r in hub.runs[HEAD]]
    assert facts["reviewer"] == {"login": "example-reviewer[bot]", "id": 9001}
    assert TOKEN not in res.both


@pytest.mark.req("FN-1")
@pytest.mark.parametrize("broken,part", [("statuses", "statuses"), ("runs", "check_runs"), ("users", "reviewer")])
def test_final_facts_a_failed_read_is_null_never_an_empty_list(tmp_path, hub, broken, part):
    hub.broken.add(broken)
    out = tmp_path / "facts.json"
    res = run_gate("publish", "final-facts", "--head-sha", HEAD, "--config", config(tmp_path), "--out", out, env=hub.env())
    assert res.rc == 0, res.describe()
    assert load_out(res, out)[part] is None


@pytest.mark.req("FN-1")
@pytest.mark.parametrize("answer", [{"login": "example-reviewer[bot]", "id": 9001, "type": "User"},
                                    {"login": "someone-else[bot]", "id": 9001, "type": "Bot"},
                                    {"login": "example-reviewer[bot]", "id": "9001", "type": "Bot"},
                                    {"login": "example-reviewer[bot]", "id": True, "type": "Bot"}],
                         ids=["not-a-bot", "another-login", "id-as-text", "id-as-bool"])
def test_final_facts_an_account_that_is_not_the_reviewers_bot_is_null(tmp_path, hub, answer):
    hub.users["example-reviewer[bot]"] = answer
    out = tmp_path / "facts.json"
    res = run_gate("publish", "final-facts", "--head-sha", HEAD, "--config", config(tmp_path), "--out", out, env=hub.env())
    assert res.rc == 0, res.describe()
    assert load_out(res, out)["reviewer"] is None


@pytest.mark.req("FN-3")
@pytest.mark.parametrize("sha", ["1" * 39, "G" * 40, "A" * 40, "1" * 40 + "\n", ""])
def test_final_facts_a_head_that_is_not_40_lowercase_hex_exits_2(tmp_path, hub, sha):
    out = tmp_path / "facts.json"
    res = run_gate("publish", "final-facts", "--head-sha", sha, "--config", config(tmp_path), "--out", out, env=hub.env())
    assert "invalid choice" not in res.err, f"precondition: gate.publish has final-facts, so exit 2 is its own refusal\n{res.describe()}"
    assert res.rc == 2, res.describe()
    assert_no_traceback(res)
    assert not hub.stub.requests, "nothing is read for a malformed SHA"


# ----------------------------------------------------------------------------- post-final


@pytest.mark.req("FN-1", "FN-2")
@pytest.mark.parametrize("content", [{"verdict": "ready-for-human", "reasons": [], "conclusions": {"gate/archive": "success", "gate/final": "success"}},
                                     {"verdict": "ready-for-human", "conclusions": {"gate/archive": "success", "gate/final": "success"},
                                      "final_check": "completed"}],
                         ids=["no-final-check", "final-check-not-an-object"])
def test_post_final_a_file_without_a_readable_final_check_never_posts_success(tmp_path, hub, content):
    final = write_json(tmp_path / "final.json", content)
    res = run_gate("publish", "post-final", "--final", final, "--head-sha", HEAD, env=hub.env())
    assert res.rc == 0, res.describe()
    assert_completed(hub.posted("gate/final"), "failure")


@pytest.mark.req("FN-1", "F-3")
@pytest.mark.parametrize("verdict,check", [
    ("blocked", {"status": "completed", "conclusion": "success"}),
    ("awaiting-review", {"status": "completed", "conclusion": "success"}),
    ("ready-for-human", {"status": "in_progress", "conclusion": "success"}),
    ("ready-for-human", {"status": "queued", "conclusion": "success"}),
], ids=["success-but-blocked", "success-but-awaiting", "success-but-in-progress", "success-but-queued"])
def test_post_final_success_only_for_a_completed_success_whose_final_verdict_is_ready(tmp_path, hub, verdict, check):
    # FN-9 (M-1 repair): the reviewer's success is on the head and the file names the reviewer, so FN-9's re-read would
    # confirm a success; only the file's own consistency may keep it away (mutant FIN-post-success).
    hub.statuses[HEAD] = [status("success")]
    final = write_json(tmp_path / "final.json", {"verdict": verdict, "reasons": [], "final_check": check,
                                                 "conclusions": {"gate/archive": "success", "gate/final": "success"},
                                                 "reviewer": {"login": CREATORS["reviewer"]["login"], "id": CREATORS["reviewer"]["id"]}})
    res = run_gate("publish", "post-final", "--final", final, "--head-sha", HEAD, env=hub.env())
    assert res.rc == 0, res.describe()
    assert all(b.get("conclusion") != "success" for b in hub.posted("gate/final")), hub.posted("gate/final")
    assert hub.posted("gate/final"), "gate/final is still posted"


# ----------------------------------------------------------------------------- finalize (FN-3, FN-4, FN-5)


def store_record(reports, *, pr=PR, run=1001, attempt=1, head=HEAD, gate_verdict="ready-for-human", archive="success",
                 prelim="ready-for-human", final_verdict="awaiting-review"):
    folder = reports / str(pr) / f"{run}-{attempt}"
    write_json(folder / "context.json", {"pr": pr, "head_sha": head, "run_id": str(run), "run_attempt": str(attempt),
                                         "repository": REPO, "head_repository": REPO})
    write_json(folder / "verdict.json", verdict_obj(prelim))
    final_check = {"status": "in_progress", "conclusion": None} if final_verdict == "awaiting-review" else \
        {"status": "completed", "conclusion": "success" if final_verdict == "ready-for-human" else "failure"}
    write_json(folder / "final.json", {"verdict": final_verdict, "gate_verdict": gate_verdict, "reasons": [],
                                       "conclusions": {"gate/archive": archive, "gate/final": final_check["conclusion"]},
                                       "final_check": final_check, "review": {"state": "missing", "code": "REVIEW_MISSING"}})
    return folder


def status_event(st, sha=HEAD, **override):
    event = {"id": st["id"], "sha": sha, "name": REPO, "context": st["context"], "state": st["state"],
             "description": st["description"], "target_url": None, "sender": copy.deepcopy(st["creator"]),
             "branches": [], "commit": {"sha": sha}}
    event.update(override)
    return event


def finalize(tmp_path, hub, event, *, record=True, actors_ok=True, reports=None):
    cfg = config(tmp_path)
    stored = tmp_path / "stored" / "reports"
    stored.mkdir(parents=True, exist_ok=True)
    if record:
        store_record(stored)
    actors = write_json(tmp_path / "actors.json", {"actors_ok": actors_ok, "foreign_commits": [], "accepted_commits": [],
                                                    "reason": None if actors_ok else "reports written by another actor"})
    ev = write_json(tmp_path / "event.json", event)
    out = tmp_path / "finalize.json"
    res = run_gate("publish", "finalize", "--event", ev, "--config", cfg, "--reports-dir", reports or stored,
                   "--actors", actors, "--out", out, env=hub.env())
    assert "invalid choice" not in res.err, f"precondition: gate.publish has the finalize command (FN-3)\n{res.describe()}"
    assert_no_traceback(res)
    assert TOKEN not in res.both
    for w in hub.writes():
        assert w.method == "POST" and w.path == f"/repos/{REPO}/check-runs", f"finalize writes only check runs (FN-6): {w}"
        assert w.json().get("name") == "gate/final", f"finalize posts gate/final only: {w.json()}"
    return res, load_out(res, out)


def reviewed(hub, state="success", runs=None, head=HEAD):
    st = status(state)
    hub.statuses.setdefault(head, []).insert(0, st)
    hub.runs[head] = green_runs(SEVEN, head=head) if runs is None else runs
    return st


@pytest.mark.req("FN-4", "FN-1", "FN-3")
def test_fn4_everything_right_gives_gate_final_success_and_ready_for_human(tmp_path, hub):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    body = assert_completed(hub.posted(), "success")
    assert body["output"]["summary"].startswith("Final verdict: ready-for-human"), body["output"]
    assert out["acted"] is True and out["code"] is None and out["pr"] == PR and out["sha"] == HEAD


@pytest.mark.req("FN-4")
@pytest.mark.parametrize("state", ["failure", "error"])
def test_fn4_a_failed_review_gives_blocked_review_failed(tmp_path, hub, state):
    st = reviewed(hub, state)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    body = assert_completed(hub.posted(), "failure")
    assert "blocked" in body["output"]["summary"] and "REVIEW_FAILED" in body["output"]["summary"]
    assert out["decision"]["verdict"] == "blocked"


@pytest.mark.req("FN-9", "FN-4")
def test_fn9_a_pending_review_keeps_gate_final_in_progress_in_finalize(tmp_path, hub):
    # Changed by FN-9 (M-1 repair, 2026-11-11): FN-4 said a pending review posts nothing, which let an earlier success
    # stay the newest gate/final. Was test_fn4_a_pending_review_changes_nothing (asserted no write at all).
    st = reviewed(hub, "pending")
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    posted = hub.posted()
    assert len(posted) == 1 and posted[0]["status"] == "in_progress" and posted[0].get("conclusion") is None, posted
    assert posted[0]["output"]["title"] == f"gate/final: waiting for the independent review on {HEAD}", posted[0]
    assert "REVIEW_PENDING" in posted[0]["output"]["summary"] and "ready-for-human" not in text_of(posted[0])
    assert out["decision"]["verdict"] == "awaiting-review"


@pytest.mark.req("FN-4", "FN-5", "FN-1")
def test_fn4_a_newer_review_by_another_creator_keeps_gate_final_in_progress(tmp_path, hub):
    st = reviewed(hub)
    hub.statuses[HEAD].insert(0, status("success", who="ceo"))
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    posted = hub.posted()
    assert len(posted) == 1 and posted[0]["status"] == "in_progress" and posted[0].get("conclusion") is None, posted
    assert "ready-for-human" not in text_of(posted[0])
    # FN-9 (L63): the decision itself is for the newest review, not only the post that FN-9's re-read corrects.
    assert out["decision"]["verdict"] == "awaiting-review" and "REVIEW_NOT_BY_REVIEWER" in codes(out["decision"]), out


@pytest.mark.req("FN-9", "FN-5", "FN-3")
@pytest.mark.parametrize("who", NOT_THE_REVIEWER)
def test_fn9_a_status_created_by_anyone_but_the_reviewer_gets_the_decision_for_the_newest_review_never_success(
        tmp_path, hub, who):
    # Changed by FN-9 (M-1 repair, 2026-11-11): FN-5 said such a status posts nothing (IGNORED_CREATOR), so a run it
    # started could not correct an earlier success. Now finalize decides on the newest review, here that very status,
    # which is no valid review. Was test_fn5_a_status_created_by_anyone_but_the_reviewer_posts_nothing.
    hub.runs[HEAD] = green_runs(SEVEN)
    st = status("success", who=who)
    hub.statuses[HEAD] = [st]
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    posted = hub.posted()
    assert len(posted) == 1 and posted[0]["status"] == "in_progress" and posted[0].get("conclusion") is None, posted
    assert "REVIEW_NOT_BY_REVIEWER" in posted[0]["output"]["summary"] and "ready-for-human" not in text_of(posted[0])
    assert out["acted"] is True and out["code"] is None


@pytest.mark.req("FN-3", "FN-5", "FN-9")
def test_fn3_the_events_sender_is_not_believed_the_creator_comes_from_the_api(tmp_path, hub):
    # Changed by FN-9 (M-1 repair, 2026-11-11): the run now decides instead of stopping with IGNORED_CREATOR; the API's
    # creator still decides, so the payload's claim of the reviewer never makes gate/final success.
    hub.runs[HEAD] = green_runs(SEVEN)
    st = status("success", who="ceo")
    hub.statuses[HEAD] = [st]
    event = status_event(st, sender=copy.deepcopy(CREATORS["reviewer"]))   # the payload claims the reviewer
    res, out = finalize(tmp_path, hub, event)
    posted = hub.posted()
    assert posted and all(b.get("conclusion") != "success" for b in posted), posted
    assert "REVIEW_NOT_BY_REVIEWER" in posted[-1]["output"]["summary"], posted[-1]


@pytest.mark.req("FN-3")
@pytest.mark.parametrize("change,code", [
    ({"context": "ci/other"}, "IGNORED_CONTEXT"),
    ({"context": "gate/final"}, "IGNORED_CONTEXT"),
    ({"context": None}, "IGNORED_CONTEXT"),
    ({"sha": "1" * 39}, "IGNORED_SHA"),
    ({"sha": "A" * 40}, "IGNORED_SHA"),
    ({"sha": "1" * 40 + "\n"}, "IGNORED_SHA"),
    ({"sha": 1}, "IGNORED_SHA"),
    ({"id": None}, "IGNORED_EVENT"),
    ({"id": "77"}, "IGNORED_EVENT"),
    ({"id": True}, "IGNORED_EVENT"),
    ({"id": 0}, "IGNORED_EVENT"),
], ids=lambda value: re.sub(r"\W+", "-", str(value))[:30])
def test_fn3_every_event_field_is_untrusted_and_checked_before_anything_is_posted(tmp_path, hub, change, code):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st, **change))
    assert res.rc == 0, res.describe()
    assert hub.writes() == []
    assert out["acted"] is False and out["code"] == code


@pytest.mark.req("FN-3")
def test_fn3_an_event_whose_status_id_is_a_status_of_another_context_posts_nothing(tmp_path, hub):
    """The event says independent-review; the API's status with that id is of another context: the API decides."""
    reviewed(hub)
    other = status("success", context="ci/other")
    hub.statuses[HEAD].insert(0, other)
    res, out = finalize(tmp_path, hub, status_event(other, context=REVIEW))
    assert hub.writes() == []
    assert out["acted"] is False and out["code"] == "IGNORED_EVENT"


@pytest.mark.req("FN-3")
def test_fn3_a_status_id_that_is_not_among_the_shas_statuses_posts_nothing(tmp_path, hub):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st, id=st["id"] + 1_000_000))
    assert hub.writes() == []
    assert out["acted"] is False and out["code"] == "IGNORED_EVENT"


@pytest.mark.req("FN-5", "FN-3")
def test_fn5_a_review_of_an_earlier_head_after_a_new_push_posts_nothing(tmp_path, hub):
    """The race between a new push and a late review: the review names a commit that is no longer the head."""
    hub.pulls = [pull(head=NEWER)]
    st = reviewed(hub, head=HEAD)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    assert hub.writes() == []
    assert out["code"] == "NOT_A_PR_HEAD"


@pytest.mark.req("FN-3", "FN-5")
@pytest.mark.parametrize("pulls", [[], [pull(base="main")], [pull(state="closed")]], ids=["no-pr", "pr-into-another-base", "closed-pr"])
def test_fn3_a_sha_that_is_not_the_head_of_an_open_pr_into_the_integration_branch_posts_nothing(tmp_path, hub, pulls):
    hub.pulls = pulls
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert hub.writes() == []
    assert out["code"] == "NOT_A_PR_HEAD"


@pytest.mark.req("FN-4")
def test_fn4_no_stored_record_for_the_head_is_never_success(tmp_path, hub):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st), record=False)
    body = assert_completed(hub.posted(), "failure")
    assert "incomplete" in body["output"]["summary"] and "NO_RECORD" in body["output"]["summary"]


@pytest.mark.req("FN-4")
def test_fn4_a_record_of_another_commit_does_not_count(tmp_path, hub):
    st = reviewed(hub)
    stored = tmp_path / "stored" / "reports"
    store_record(stored, head=OTHER)
    res, out = finalize(tmp_path, hub, status_event(st), record=False)
    assert_completed(hub.posted(), "failure")


@pytest.mark.req("FN-4")
def test_fn4_the_newest_stored_run_for_the_head_counts(tmp_path, hub):
    st = reviewed(hub)
    stored = tmp_path / "stored" / "reports"
    store_record(stored, run=1001, attempt=1)
    store_record(stored, run=1001, attempt=2, gate_verdict="blocked", prelim="blocked", final_verdict="blocked")
    res, out = finalize(tmp_path, hub, status_event(st), record=False)
    body = assert_completed(hub.posted(), "failure")
    assert "blocked" in body["output"]["summary"]


@pytest.mark.req("FN-4")
def test_fn4_control_an_older_run_that_was_blocked_does_not_hide_a_newer_ready_one(tmp_path, hub):
    st = reviewed(hub)
    stored = tmp_path / "stored" / "reports"
    store_record(stored, run=999, attempt=3, gate_verdict="blocked", prelim="blocked", final_verdict="blocked")
    store_record(stored, run=1001, attempt=1)
    res, out = finalize(tmp_path, hub, status_event(st), record=False)
    assert_completed(hub.posted(), "success")


@pytest.mark.req("FN-4", "FN-1")
@pytest.mark.parametrize("record", [
    {"archive": "failure"},
    {"gate_verdict": "incomplete", "final_verdict": "incomplete"},
    {"prelim": "blocked"},
], ids=["archive-failed", "archive-not-stored", "preliminary-not-ready"])
def test_fn4_a_successful_review_with_the_archive_or_the_preliminary_not_ready_is_never_success(tmp_path, hub, record):
    st = reviewed(hub)
    stored = tmp_path / "stored" / "reports"
    store_record(stored, **record)
    res, out = finalize(tmp_path, hub, status_event(st), record=False)
    assert_completed(hub.posted(), "failure")


@pytest.mark.req("FN-4", "D-0")
def test_fn4_untrusted_reports_are_never_success(tmp_path, hub):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st), actors_ok=False)
    body = assert_completed(hub.posted(), "failure")
    assert "REPORTS_UNTRUSTED" in body["output"]["summary"]


@pytest.mark.req("FN-4")
def test_fn4_a_missing_reports_folder_is_never_success(tmp_path, hub):
    st = reviewed(hub)
    res, out = finalize(tmp_path, hub, status_event(st), record=False, reports=tmp_path / "no-such-folder")
    assert all(b.get("conclusion") != "success" for b in hub.posted())
    assert hub.posted(), "a lost read of the reports must say so on gate/final, not keep silent"


@pytest.mark.req("FN-4", "FN-1")
@pytest.mark.parametrize("name", SEVEN)
def test_fn4_a_successful_review_with_one_mandatory_check_failed_is_blocked(tmp_path, hub, name):
    st = reviewed(hub, runs=[check_run(n, "failure" if n == name else "success") for n in SEVEN])
    res, out = finalize(tmp_path, hub, status_event(st))
    body = assert_completed(hub.posted(), "failure")
    assert "FAILED_CHECK" in body["output"]["summary"]


@pytest.mark.req("FN-4", "FN-1")
@pytest.mark.parametrize("name", SEVEN)
def test_fn4_a_successful_review_with_one_mandatory_check_missing_is_incomplete(tmp_path, hub, name):
    st = reviewed(hub, runs=[check_run(n) for n in SEVEN if n != name])
    res, out = finalize(tmp_path, hub, status_event(st))
    body = assert_completed(hub.posted(), "failure")
    assert "MISSING_CHECK" in body["output"]["summary"]


@pytest.mark.req("FN-9", "FN-4")
@pytest.mark.parametrize("broken", ["users", "statuses", "pulls", "users-not-a-bot"])
def test_fn9_a_read_needed_before_deciding_that_fails_posts_gate_final_in_progress_and_exits_1(tmp_path, hub, broken):
    # Changed by FN-9's "a failure is never silence" (L65, the CEO's decision of 2026-11-11): such a run posted nothing,
    # so an earlier success stayed newest over the review it could not read. Was
    # test_fn4_a_read_needed_before_deciding_that_fails_posts_nothing_and_exits_1 (asserted no write at all); the case
    # "users-not-a-bot" (a 200 answer that is not the reviewer's bot, L58) is new.
    st = reviewed(hub)
    if broken == "users-not-a-bot":
        hub.users[CREATORS["reviewer"]["login"]] = dict(CREATORS["reviewer"], type="User")
    else:
        hub.broken.add(broken)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 1, res.describe()
    assert out["code"] == "READ_FAILED", out
    posted = hub.posted()
    assert len(posted) == 1 and posted[0]["status"] == "in_progress" and posted[0].get("conclusion") is None, posted
    assert "REVIEW_UNREADABLE" in posted[0]["output"]["summary"] and "ready-for-human" not in text_of(posted[0])


@pytest.mark.req("FN-4")
def test_fn4_unreadable_check_runs_are_never_success(tmp_path, hub):
    st = reviewed(hub)
    hub.broken.add("runs")
    res, out = finalize(tmp_path, hub, status_event(st))
    body = assert_completed(hub.posted(), "failure")
    assert "CHECKS_UNREADABLE" in body["output"]["summary"]


# ----------------------------------------------------------------------------- FN-7: the preliminary texts


@pytest.mark.req("FN-7", "M-1")
def test_fn7_the_comment_of_a_ready_run_says_the_checks_passed_and_waits_for_the_review(tmp_path):
    o = World(tmp_path).run().need()
    assert o.verdict["verdict"] == "ready-for-human", "precondition: a green run"
    assert "ready-for-human" not in o.md, "the PR comment must not say ready-for-human before the review (FN-7)"
    lowered = o.md.lower()
    assert "checks passed" in lowered and "waits for the independent review" in lowered, o.md[:600]


@pytest.mark.req("FN-7", "M-1")
def test_fn7_control_a_blocked_run_is_still_named_blocked_in_the_comment(tmp_path):
    w = World(tmp_path)
    w.fail("gate/tests")
    o = w.run().need()
    assert "**Preliminary verdict: blocked**" in o.md


@pytest.mark.req("FN-7")
def test_fn7_post_checks_of_a_ready_run_never_says_ready_for_human(tmp_path, hub):
    v = write_json(tmp_path / "verdict.json", verdict_obj("ready-for-human"))
    res = run_gate("publish", "post-checks", "--verdict", v, "--head-sha", HEAD, env=hub.env())
    assert res.rc == 0, res.describe()
    posted = [r.json() for r in hub.writes()]
    assert {b["name"] for b in posted} == set(SIX), "gate/report among the six"
    for body in posted:
        assert "ready-for-human" not in text_of(body), body
        summary = body["output"]["summary"].lower()
        assert "checks passed" in summary and "waits for the independent review" in summary, body["output"]


@pytest.mark.req("FN-7")
def test_fn7_control_post_checks_of_a_blocked_run_names_blocked(tmp_path, hub):
    v = write_json(tmp_path / "verdict.json", verdict_obj("blocked"))
    res = run_gate("publish", "post-checks", "--verdict", v, "--head-sha", HEAD, env=hub.env())
    assert res.rc == 0, res.describe()
    assert all("Preliminary verdict: blocked" in r.json()["output"]["summary"] for r in hub.writes())


# ----------------------------------------------------------------------------- feedback reads awaiting-review


@pytest.mark.req("FN-2", "D-6")
def test_feedback_reads_a_stored_awaiting_review_as_not_a_failure(tmp_path):
    reports = tmp_path / "stored" / "reports"
    store_record(reports, run=1001, attempt=1)
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True, "foreign_commits": [], "accepted_commits": [], "reason": None})
    pulls = write_json(tmp_path / "pulls.json", [{"number": PR, "head_sha": HEAD, "base_ref": "candidate/a", "head_ref": "ai/7-example",
                                                  "head_repository": REPO, "repository": REPO}])
    event = write_json(tmp_path / "event.json", {"workflow_run": {"id": 1001, "run_attempt": 1, "path": ".github/workflows/judge.yml",
                                                                  "event": "pull_request_target", "conclusion": "success"}})
    out = tmp_path / "decision.json"
    res = run_gate("feedback", "decide", "--event-name", "workflow_run", "--event", event, "--pulls", pulls, "--reports-dir", reports,
                   "--actors", actors, "--config", config(tmp_path), "--out", out)
    assert res.rc == 0, res.describe()
    decision = load_out(res, out)
    assert decision["reason_code"] == "NOT_A_FAILURE" and decision["act"] is False and decision["post"] is False


# ----------------------------------------------------------------------------- FN-9: the newest review decides last (M-1)
#
# Finding M-1 of round 2's review round 1. Each interleaving is fixed by the stand-in's seams (Hub.after_read and
# Hub.on_post), never by time: a status is added or a read is broken at a named moment, or a second finalize process is
# run from inside the stand-in while the first one waits for its answer (the stand-in serves each request on its own
# thread). A run whose status GitHub's concurrency rule replaced (L18) is simply never run.


EXPECT = {   # the newest review -> what the newest gate/final must be (FN-9)
    ("failure", "reviewer"): ("blocked", "REVIEW_FAILED"),
    ("error", "reviewer"): ("blocked", "REVIEW_FAILED"),
    ("pending", "reviewer"): ("waiting", "REVIEW_PENDING"),
    ("success", "ceo"): ("waiting", "REVIEW_NOT_BY_REVIEWER"),
    ("success", "executor"): ("waiting", "REVIEW_NOT_BY_REVIEWER"),
}
NEWER_STATUSES = [("failure", "reviewer"), ("error", "reviewer"), ("pending", "reviewer"), ("success", "ceo")]
NEWER_IDS = ["failure", "error", "pending", "ceo-success"]


class Ready:
    """A ready head: one stored ready record, every mandatory check green, the reviewer's success the newest review."""

    def __init__(self, tmp_path, hub):
        self.tmp, self.hub = tmp_path, hub
        self.cfg = config(tmp_path)
        self.stored = tmp_path / "stored" / "reports"
        store_record(self.stored)
        hub.runs[HEAD] = green_runs(SEVEN)
        self.first = status("success")
        hub.statuses[HEAD] = [self.first]

    def add(self, state, who="reviewer"):
        """A new independent-review status on the head: the newest review from now on."""
        st = status(state, who=who)
        self.hub.statuses[HEAD].insert(0, st)
        return st

    def finalize(self, st, name):
        """One run of finalize for the event of `st`, in its own folder, as one run of the workflow."""
        folder = self.tmp / f"finalize-{name}"
        actors = write_json(folder / "actors.json", {"actors_ok": True, "foreign_commits": [], "accepted_commits": [],
                                                     "reason": None})
        event = write_json(folder / "event.json", status_event(st))
        return run_gate("publish", "finalize", "--event", event, "--config", self.cfg, "--reports-dir", self.stored,
                        "--actors", actors, "--out", folder / "finalize.json", env=self.hub.env())

    def archive_read(self):
        """The archive job up to its post (Y-24): final-facts, then report final, with the review already there (FN-8)."""
        folder = self.tmp / "archive"
        verdict = write_json(folder / "verdict.json", verdict_obj())
        archive = write_json(folder / "archive.json", ARCH_OK)
        facts, out = folder / "facts.json", folder / "final" / "final.json"
        res = run_gate("publish", "final-facts", "--head-sha", HEAD, "--config", self.cfg, "--out", facts, env=self.hub.env())
        assert res.rc == 0, res.describe()
        res = run_gate("report", "final", "--verdict", verdict, "--archive", archive, "--facts", facts, "--out", out)
        assert res.rc == 0, res.describe()
        assert load_out(res, out)["verdict"] == "ready-for-human", "precondition: the archive job read the reviewer's success"
        return out

    def archive_post(self, out):
        """The archive job's post, as judge.yml runs it."""
        return run_gate("publish", "post-final", "--final", out, "--head-sha", HEAD, env=self.hub.env())


def ran(res):
    """A run that ends as a workflow run must: exit 0, no traceback, no token."""
    assert "invalid choice" not in res.err, res.describe()
    assert_no_traceback(res)
    assert TOKEN not in res.both
    assert res.rc == 0, res.describe()


def assert_newest_final(hub, expect, code, why):
    posted = hub.posted()
    seen = [(b.get("status"), b.get("conclusion")) for b in posted]
    assert posted, f"gate/final was posted ({why})"
    last = posted[-1]
    assert not (last.get("status") == "completed" and last.get("conclusion") == "success"), (
        f"FN-9: the newest gate/final is success while the newest review is not the reviewer's success ({why}); "
        f"gate/final posts in order: {seen}")
    if expect == "blocked":
        assert (last["status"], last.get("conclusion")) == ("completed", "failure"), seen
        assert last["output"]["summary"].startswith("Final verdict: blocked"), last["output"]
    else:
        assert last["status"] == "in_progress" and last.get("conclusion") is None, seen
        assert last["output"]["title"] == f"gate/final: waiting for the independent review on {HEAD}", last["output"]
    assert code in last["output"]["summary"], last["output"]
    assert last["head_sha"] == HEAD
    assert "ready-for-human" not in text_of(last)


@pytest.mark.req("FN-9", "FN-8")
@pytest.mark.parametrize("state,who", NEWER_STATUSES, ids=NEWER_IDS)
def test_fn9_b_a_review_that_changes_between_the_archive_jobs_read_and_its_post_is_not_overtaken(tmp_path, hub, state, who):
    """M-1 (b): the archive job read the reviewer's success; a newer status came and its finalize run acted on it; only
    then did the archive job post. The archive job's success must not become the newest gate/final."""
    world = Ready(tmp_path, hub)
    out = world.archive_read()
    newer = world.add(state, who)
    ran(world.finalize(newer, "B"))
    ran(world.archive_post(out))
    # FN-9 (L63): before the post, never success - not even for a moment that the after-read would correct.
    assert all(b.get("conclusion") != "success" for b in hub.posted()), hub.posted()
    expect, code = EXPECT[(state, who)]
    assert_newest_final(hub, expect, code, f"a {who} {state} status between the archive job's read and its post")


@pytest.mark.req("FN-9", "FN-4")
@pytest.mark.parametrize("state,who", [NEWER_STATUSES[0], NEWER_STATUSES[2], NEWER_STATUSES[3]],
                         ids=["failure", "pending", "ceo-success"])
def test_fn9_a_a_success_posted_after_a_newer_reviews_run_read_and_posted_is_not_the_newest(tmp_path, hub, state, who):
    """M-1 (a): run A read the reviewer's success; before A posted, a newer status came, and its run B read it and
    posted. Run A's success must not become the newest gate/final."""
    world = Ready(tmp_path, hub)
    second = {}

    def between(number):
        if number == 1:   # run A's read is answered with the success alone; then the newer status and run B
            second["status"] = world.add(state, who)
            try:
                second["res"] = world.finalize(second["status"], "B")
            except BaseException as error:   # kept for the test: an error here would be lost in the stand-in's thread
                second["error"] = error

    hub.after_read = between
    first = world.finalize(world.first, "A")
    hub.after_read = None
    assert "error" not in second, second.get("error")
    ran(second["res"])
    ran(first)
    # FN-9 (L63): before the post, never success - not even for a moment that the after-read would correct.
    assert all(b.get("conclusion") != "success" for b in hub.posted()), hub.posted()
    expect, code = EXPECT[(state, who)]
    assert_newest_final(hub, expect, code, f"run A posted after run B read a {who} {state} status")


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("state,who", NEWER_STATUSES, ids=NEWER_IDS)
def test_fn9_a_review_that_changes_right_after_a_success_post_is_followed_by_its_decision(tmp_path, hub, path, state, who):
    """The re-read after the post: the newer status came just after the success was posted, and its own finalize run was
    replaced while it waited (L18), so no queued run will correct the success."""
    world = Ready(tmp_path, hub)
    came = []

    def as_posted(body):
        if body.get("name") == "gate/final" and body.get("conclusion") == "success" and not came:
            came.append(world.add(state, who))

    hub.on_post = as_posted
    if path == "archive":
        ran(world.archive_post(world.archive_read()))
    else:
        ran(world.finalize(world.first, "A"))
    hub.on_post = None
    assert came, "precondition: a success was posted while the reviewer's success was the newest review"
    expect, code = EXPECT[(state, who)]
    assert_newest_final(hub, expect, code, f"a {who} {state} status just after the success post ({path})")


@pytest.mark.req("FN-9", "FN-5", "FN-6")
@pytest.mark.parametrize("state,who", [("success", "ceo"), ("success", "executor"), ("pending", "reviewer")],
                         ids=["ceo-success", "executor-success", "reviewer-pending"])
def test_fn9_a_a_run_that_replaced_the_waiting_run_decides_on_the_newest_review(tmp_path, hub, state, who):
    """M-1 (a): run A posted success; the reviewer's failure came next and its run B waited; a third independent-review
    status made GitHub replace B by C (L18). C, whoever created its status, posts the decision for the newest review."""
    world = Ready(tmp_path, hub)
    ran(world.finalize(world.first, "A"))
    assert [b.get("conclusion") for b in hub.posted()] == ["success"], "precondition: run A posted success"
    world.add("failure")   # run B of this status never runs: replaced while it waited
    third = world.add(state, who)
    ran(world.finalize(third, "C"))
    expect, code = EXPECT[(state, who)]
    assert_newest_final(hub, expect, code, f"run C for a {who} {state} status, after run B was replaced")


@pytest.mark.req("FN-9", "FN-6")
def test_fn9_control_a_run_that_replaced_the_waiting_run_posts_success_for_a_newer_success_by_the_reviewer(tmp_path, hub):
    world = Ready(tmp_path, hub)
    ran(world.finalize(world.first, "A"))
    world.add("failure")
    third = world.add("success")
    ran(world.finalize(third, "C"))
    assert [(b["status"], b.get("conclusion")) for b in hub.posted()] == [("completed", "success")] * 2, hub.posted()


@pytest.mark.req("FN-9", "FN-8", "FN-4")
@pytest.mark.parametrize("path", ["archive", "finalize"])
def test_fn9_control_a_review_unchanged_around_the_post_gives_one_success_and_nothing_after(tmp_path, hub, path):
    world = Ready(tmp_path, hub)
    if path == "archive":
        ran(world.archive_post(world.archive_read()))
    else:
        ran(world.finalize(world.first, "A"))
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("completed", "success")], posted
    assert posted[0]["output"]["summary"].startswith("Final verdict: ready-for-human"), posted[0]["output"]


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_fn9_a_re_read_that_fails_is_never_success(tmp_path, hub, path, when):
    """Every read of the statuses after the decision's own read answers 500: before the post, or once success is posted."""
    world = Ready(tmp_path, hub)
    if when == "before":
        hub.after_read = lambda number: hub.broken.add("statuses")
    else:
        hub.on_post = lambda body: (hub.broken.add("statuses")
                                    if body.get("name") == "gate/final" and body.get("conclusion") == "success" else None)
    if path == "archive":
        ran(world.archive_post(world.archive_read()))
    else:
        ran(world.finalize(world.first, "A"))
    hub.after_read = hub.on_post = None
    posted = hub.posted()
    if when == "before":
        assert all(b.get("conclusion") != "success" for b in posted), f"no success without a re-read that confirms it: {posted}"
    else:
        assert any(b.get("conclusion") == "success" for b in posted), "precondition: the re-read before the post confirmed it"
    assert_newest_final(hub, "waiting", "REVIEW_UNREADABLE", f"the re-read {when} the post failed ({path})")


@pytest.mark.req("FN-9", "FN-4")
def test_fn9_finalize_decides_on_the_newest_review_not_on_the_older_status_that_started_it(tmp_path, hub):
    """L63 (M1 b): a late run for an older failed review. The newest review is the reviewer's success, so the decision is
    success, made on the API's list, not on the status that started the run."""
    world = Ready(tmp_path, hub)
    older = world.add("failure")
    world.add("success")
    ran(world.finalize(older, "late"))
    posted = hub.posted()
    assert [(b["status"], b.get("conclusion")) for b in posted] == [("completed", "success")], posted
    assert posted[0]["output"]["summary"].startswith("Final verdict: ready-for-human"), posted[0]["output"]


# ----------------------------------------------------------------------------- FN-9: a failure is never silence (L65)


GARBLED = {   # answers that http.client cannot parse: they raise IncompleteRead and BadStatusLine, not OSError
    "incomplete-read": b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n[",
    "bad-status-line": b"NOT-AN-HTTP-ANSWER\r\n\r\n",
}


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("when", ["before", "after"])
@pytest.mark.parametrize("kind", sorted(GARBLED))
def test_fn9_a_re_read_that_the_http_client_cannot_parse_is_never_success_and_never_a_crash(tmp_path, hub, path, when, kind):
    world = Ready(tmp_path, hub)
    if when == "before":
        hub.after_read = lambda number: setattr(hub, "garbled", GARBLED[kind])
    else:
        hub.on_post = lambda body: (setattr(hub, "garbled", GARBLED[kind])
                                    if body.get("name") == "gate/final" and body.get("conclusion") == "success" else None)
    if path == "archive":
        res = world.archive_post(world.archive_read())
    else:
        res = world.finalize(world.first, "A")
    hub.after_read = hub.on_post = None
    ran(res)
    posted = hub.posted()
    if when == "before":
        assert all(b.get("conclusion") != "success" for b in posted), f"no success without a re-read that confirms it: {posted}"
    else:
        assert any(b.get("conclusion") == "success" for b in posted), "precondition: the re-read before the post confirmed it"
    assert_newest_final(hub, "waiting", "REVIEW_UNREADABLE", f"the {kind} re-read {when} the post ({path})")


def lose_corrections(world, hub, refusal, lost):
    """After the first success post, the reviewer's failure comes (its own run replaced, L18) and the next `lost` posts
    of gate/final are refused."""
    seen = []

    def as_posted(body):
        if body.get("name") != "gate/final":
            return None
        seen.append(body)
        if len(seen) == 1 and body.get("conclusion") == "success":
            world.add("failure")
            return None
        if 2 <= len(seen) <= 1 + lost:
            return (500, {"message": "boom"}) if refusal == "500" else RawResponse(GARBLED["bad-status-line"])
        return None

    hub.on_post = as_posted
    return seen


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("refusal", ["500", "bad-status-line"])
def test_fn9_a_correction_after_a_success_that_fails_once_is_tried_again(tmp_path, hub, path, refusal):
    world = Ready(tmp_path, hub)
    seen = lose_corrections(world, hub, refusal, lost=1)
    if path == "archive":
        res = world.archive_post(world.archive_read())
    else:
        res = world.finalize(world.first, "A")
    hub.on_post = None
    ran(res)
    assert len(hub.refused) == 1 and len(seen) == 3, f"precondition: one correction was lost and one more was sent: {seen}"
    assert_newest_final(hub, "blocked", "REVIEW_FAILED", f"a lost correction ({refusal}, {path})")


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("refusal", ["500", "bad-status-line"])
def test_fn9_a_correction_that_fails_twice_ends_the_run_with_exit_1_and_no_traceback(tmp_path, hub, refusal):
    """When GitHub refuses the correction twice the run cannot do more: it must fail visibly (exit 1), not crash."""
    world = Ready(tmp_path, hub)
    seen = lose_corrections(world, hub, refusal, lost=2)
    res = world.finalize(world.first, "A")
    hub.on_post = None
    assert len(hub.refused) == 2 and len(seen) == 3, f"precondition: two corrections were sent and lost: {seen}"
    assert_no_traceback(res)
    assert TOKEN not in res.both
    assert res.rc == 1, res.describe()


# ----------------------------------------------------------------------------- FN-9 amended: L67 to L69


class Lost(RawResponse):
    """The answer to a post that GitHub stored, cut on the way back: the post counts as posted."""


CUT_201 = b"HTTP/1.0 201 Created\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"


def refuse(kind):
    return (500, {"message": "boom"}) if kind == "500" else RawResponse(GARBLED["bad-status-line"])


def break_read(hub, broken):
    if broken == "users-not-a-bot":
        hub.users[CREATORS["reviewer"]["login"]] = dict(CREATORS["reviewer"], type="User")
    else:
        hub.broken.add(broken)


NOT_JSON_201 = b"HTTP/1.0 201 Created\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\nnot-json!"
UNREADABLE = "unreadable"
EXPECT[UNREADABLE] = ("waiting", "REVIEW_UNREADABLE")
LATER = NEWER_STATUSES + [UNREADABLE]
LATER_IDS = NEWER_IDS + ["re-read-fails"]


def on_success_posts(world, hub, *, lost, arrive_at, newer, answer=CUT_201):
    """The answers of the first `lost` success posts are lost after GitHub stored them (`answer`: a cut body, or a body
    that is not JSON). As success post number `arrive_at` arrives, the newer status `newer` comes (its own run replaced,
    L18), or, for UNREADABLE, every later read of the statuses fails."""
    seen = []

    def as_posted(body):
        if body.get("name") != "gate/final":
            return None
        seen.append(body)
        if body.get("conclusion") != "success":
            return None
        number = sum(b.get("conclusion") == "success" for b in seen)
        if number == arrive_at:
            if newer == UNREADABLE:
                hub.broken.add("statuses")
            else:
                world.add(*newer)
        return Lost(answer) if number <= lost else None

    hub.on_post = as_posted
    return seen


def expected_conclusion(newer):
    return "failure" if EXPECT[newer if newer == UNREADABLE else tuple(newer)][0] == "blocked" else None


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("newer", NEWER_STATUSES, ids=NEWER_IDS)
def test_fn9_a_success_post_whose_answer_is_lost_is_not_tried_again_once_the_newest_review_no_longer_allows_it(
        tmp_path, hub, path, newer):
    # Changed by FN-9's amendment for L75 (the CEO's decision of 2026-11-11): the success was tried again without a
    # re-read, and only the after-read corrected it. Was test_fn9_a_success_post_whose_answer_is_lost_once_is_tried_
    # again_and_then_followed (failure only; it asserted the posts [success, success, failure]).
    world = Ready(tmp_path, hub)
    seen = on_success_posts(world, hub, lost=1, arrive_at=1, newer=newer)
    res = world.archive_post(world.archive_read()) if path == "archive" else world.finalize(world.first, "A")
    hub.on_post = None
    ran(res)
    assert [b.get("conclusion") for b in seen] == ["success", expected_conclusion(newer)], seen
    expect, code = EXPECT[tuple(newer)]
    assert_newest_final(hub, expect, code, f"a success answer lost, then a {newer} status ({path})")


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
def test_fn9_control_a_success_post_whose_answer_is_lost_once_is_tried_again_while_the_review_allows_it(tmp_path, hub, path):
    world = Ready(tmp_path, hub)
    seen = on_success_posts(world, hub, lost=1, arrive_at=0, newer=UNREADABLE)
    res = world.archive_post(world.archive_read()) if path == "archive" else world.finalize(world.first, "A")
    hub.on_post = None
    ran(res)
    assert [b.get("conclusion") for b in seen] == ["success", "success"], seen


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
@pytest.mark.parametrize("newer", LATER, ids=LATER_IDS)
def test_fn9_a_success_post_whose_answer_is_lost_twice_is_followed_by_the_newest_review_then_exit_1(tmp_path, hub, path, newer):
    # Changed by L72 (the third check's medium, the CEO's decision of 2026-11-11): the test had only a failed review, so
    # a follow-up for a failed review only (mutant C8) or one that ignores a failed re-read (C9) passed. Now every kind
    # of newer status and a failed re-read, arriving at the second success post.
    world = Ready(tmp_path, hub)
    seen = on_success_posts(world, hub, lost=2, arrive_at=2, newer=newer)
    res = world.archive_post(world.archive_read()) if path == "archive" else world.finalize(world.first, "A")
    hub.on_post = None
    assert_no_traceback(res)
    assert TOKEN not in res.both
    assert res.rc == 1, res.describe()
    assert [b.get("conclusion") for b in seen] == ["success", "success", expected_conclusion(newer)], seen
    expect, code = EXPECT[newer if newer == UNREADABLE else tuple(newer)]
    assert_newest_final(hub, expect, code, f"a success answer lost twice, then {newer} ({path})")


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("path", ["archive", "finalize"])
def test_fn9_a_success_post_whose_answer_is_not_json_counts_as_a_failed_post(tmp_path, hub, path):
    """L73: GitHub stored the success and answered with a body that is not JSON while the reviewer's failure came."""
    world = Ready(tmp_path, hub)
    seen = on_success_posts(world, hub, lost=1, arrive_at=1, newer=("failure", "reviewer"), answer=NOT_JSON_201)
    res = world.archive_post(world.archive_read()) if path == "archive" else world.finalize(world.first, "A")
    hub.on_post = None
    ran(res)
    assert [b.get("conclusion") for b in seen] == ["success", "failure"], seen
    assert_newest_final(hub, "blocked", "REVIEW_FAILED", f"a success answer that is not JSON ({path})")


@pytest.mark.req("FN-9", "FN-2")
def test_fn9_a_waiting_post_whose_answer_is_not_json_is_tried_once_more(tmp_path, hub):
    """L73: the archive job's in-progress gate/final, with no review yet, is answered with a body that is not JSON."""
    hub.runs[HEAD] = green_runs(SIX)
    hub.on_post = lambda body: RawResponse(NOT_JSON_201) if body.get("name") == "gate/final" and not hub.refused else None
    final, posted, _archive = archive_chain(tmp_path, hub)
    hub.on_post = None
    assert len(hub.refused) == 1, "precondition: the first gate/final post had an answer that is not JSON"
    assert_waiting(final, posted)


@pytest.mark.req("FN-9")
@pytest.mark.parametrize("refusal", ["500", "bad-status-line"])
def test_fn9_finalize_tries_its_decision_post_once_more(tmp_path, hub, refusal):
    """L68: run A posted success; the reviewer's failure came; run B's blocked post is refused once."""
    world = Ready(tmp_path, hub)
    ran(world.finalize(world.first, "A"))
    failed = world.add("failure")
    hub.on_post = lambda body: refuse(refusal) if body.get("name") == "gate/final" and not hub.refused else None
    res = world.finalize(failed, "B")
    hub.on_post = None
    ran(res)
    assert len(hub.refused) == 1, "precondition: run B's first post was refused"
    assert_newest_final(hub, "blocked", "REVIEW_FAILED", f"run B's decision post refused once ({refusal})")


@pytest.mark.req("FN-9")
def test_fn9_a_run_that_cannot_read_tries_its_in_progress_post_once_more(tmp_path, hub):
    """L68: run A posted success; a newer review came; run B cannot read the reviewer's account and its in-progress post
    is refused once."""
    world = Ready(tmp_path, hub)
    ran(world.finalize(world.first, "A"))
    newer = world.add("failure")
    hub.broken.add("users")
    hub.on_post = lambda body: refuse("500") if body.get("name") == "gate/final" and not hub.refused else None
    res = world.finalize(newer, "B")
    hub.on_post = None
    assert_no_traceback(res)
    assert res.rc == 1, res.describe()
    assert len(hub.refused) == 1, "precondition: run B's first post was refused"
    assert_newest_final(hub, "waiting", "REVIEW_UNREADABLE", "run B's in-progress post refused once")


@pytest.mark.req("FN-9", "FN-2")
def test_fn9_the_archive_jobs_waiting_post_is_tried_once_more(tmp_path, hub):
    """L68: the archive job's in-progress gate/final, with no review yet, is refused once."""
    hub.runs[HEAD] = green_runs(SIX)
    hub.on_post = lambda body: refuse("500") if body.get("name") == "gate/final" and not hub.refused else None
    final, posted, _archive = archive_chain(tmp_path, hub)
    hub.on_post = None
    assert len(hub.refused) == 1, "precondition: the first gate/final post was refused"
    assert_waiting(final, posted)


@pytest.mark.req("FN-9", "FN-5", "FN-3")
@pytest.mark.parametrize("broken", ["users", "statuses", "users-not-a-bot"])
def test_fn9_a_status_on_a_sha_that_is_no_open_pr_head_posts_nothing_even_when_a_read_fails(tmp_path, hub, broken):
    """L69: the head of an already merged PR gets no gate/final, so no later report reads its merge as a bypass."""
    hub.pulls = [pull(state="closed")]
    st = reviewed(hub)
    break_read(hub, broken)
    res, out = finalize(tmp_path, hub, status_event(st))
    assert res.rc == 0, res.describe()
    assert hub.writes() == [], hub.writes()
    assert out["code"] == "NOT_A_PR_HEAD", out


@pytest.mark.req("FN-9", "FN-3")
@pytest.mark.parametrize("broken", ["users", "users-not-a-bot"])
def test_fn9_an_event_whose_status_the_api_does_not_hold_posts_nothing_even_when_the_account_read_fails(tmp_path, hub, broken):
    """L69: the event's status is checked against the API before the reviewer's account is read."""
    st = reviewed(hub)
    break_read(hub, broken)
    res, out = finalize(tmp_path, hub, status_event(st, id=st["id"] + 1_000_000))
    assert res.rc == 0, res.describe()
    assert hub.writes() == [], hub.writes()
    assert out["code"] == "IGNORED_EVENT", out
