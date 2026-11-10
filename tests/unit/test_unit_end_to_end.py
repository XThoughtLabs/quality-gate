"""The judge's whole path on a real local repository, without GitHub.

Each scenario runs what the three jobs run, in order: the checks, the seal, the
report, the store with a read-back, and the final verdict. GitHub's own behaviour
(rulesets, app permissions, real runs) is tested in the real proofs, not here.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.req("V-1", "V-2", "V-4", "V-5", "X-2")

HEAD_RUN = "1001"
RUN_STEPS = ("gate/env", "gate/guard", "gate/tests", "gate/acceptance", "gate/security")
DIAGNOSTIC_STEPS = ("diag/coverage", "diag/mypy", "diag/ruff", "diag/semgrep", "diag/schemathesis", "diag/mutation", "diag/benchmark")
PASSING_TEST = "def test_ok():\n    assert 1 + 1 == 2\n"
FAILING_TEST = "def test_ok():\n    assert 1 + 1 == 2\n\n\ndef test_new():\n    assert 1 + 1 == 3\n"


def toml_list(items: list[str]) -> str:
    return json.dumps(items)


def write_config(path: Path, reviewer: str = "example-reviewer") -> None:
    python = sys.executable
    security_tool = json.dumps(
        [python, "-c", "import json,os; [json.dump(v, open(os.path.join(os.environ['GATE_RAW'], k), 'w')) for k, v in {'bandit.json': {'results': []}, 'pip-audit.json': {'dependencies': []}, 'gitleaks.json': []}.items()]"]
    )
    tests = toml_list([python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--import-mode=importlib", "tests", "--junitxml={raw}/junit.xml"])
    acceptance = toml_list(
        [python, "-P", "-m", "gate.acceptance", "--junit", "{raw}/junit.xml", "--known-failing", "{env:GATE_KNOWN_FAILING}", "--mode", "{env:GATE_ACCEPTANCE_MODE}", "--out", "{raw}/acceptance.json", "--tests-dir", "acceptance", "--", python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--import-mode=importlib", "acceptance", "--junitxml={raw}/junit.xml"]
    )
    security = toml_list(
        [python, "-P", "-m", "gate.security_check", "--bandit", "{raw}/bandit.json", "--pip-audit", "{raw}/pip-audit.json", "--gitleaks", "{raw}/gitleaks.json", "--review", "security-review.md", "--repo", ".", "--base", "{env:GATE_BASE_SHA}", "--head", "{env:GATE_HEAD_SHA}", "--out", "{raw}/security.json", "--tool-command", security_tool]
    )
    path.write_text(
        f"""[project]
baseline_sha = "{'0' * 40}"
integration_branch = "candidate/a"

[limits]
max_turns = 5
timeout_minutes = 5
max_fix_rounds = 3

[feedback]
judge_workflow_path = ".github/workflows/judge.yml"
reviewer_app = "{reviewer}"

[checks."gate/tests"]
class = "mandatory"
commands = [{tests}]
junit = "junit.xml"
forbid_skips = true
expected_tests_from_base = true
required_outputs = ["junit.xml"]

[checks."gate/acceptance"]
class = "mandatory"
commands = [{acceptance}]
env = {{ PYTHONPATH = "{{env:GATE_HOME}}" }}
required_outputs = ["junit.xml", "acceptance.json"]

[checks."gate/security"]
class = "mandatory"
commands = [{security}]
env = {{ PYTHONPATH = "{{env:GATE_HOME}}", GATE_RAW = "{{raw}}" }}
required_outputs = ["security.json"]
""",
        encoding="utf-8",
        newline="\n",
    )


class World:
    def __init__(self, tmp: Path, gate, stub) -> None:
        self.tmp = tmp
        self.gate = gate
        self.stub = stub
        self.remote = tmp / "remote.git"
        self.repo = tmp / "repo"
        self.out = tmp / "out"
        self.publish = tmp / "publish"
        self.config = tmp / "repo" / "quality.toml"
        (tmp / "no-reports").mkdir()
        # env_check reads the PR number for the pull-requests write probe from the event, as the
        # judge's run job does (GITHUB_EVENT_PATH). GATE_PR is "7", so the event names PR 7.
        self.event = tmp / "event.json"
        self.event.write_text(json.dumps({"pull_request": {"number": 7}}), encoding="utf-8")

        self.remote.mkdir()
        gate.git(self.remote, "init", "--quiet", "--bare", "--initial-branch=candidate/a")
        self.repo.mkdir()
        gate.git(self.repo, "init", "--quiet", "--initial-branch=candidate/a")
        gate.git(self.repo, "remote", "add", "origin", str(self.remote))
        (self.repo / "src").mkdir()
        (self.repo / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "test_app.py").write_text(PASSING_TEST, encoding="utf-8")
        (self.repo / "acceptance").mkdir()
        (self.repo / "acceptance" / "test_spec.py").write_text("def test_spec():\n    assert True is True\n", encoding="utf-8")
        write_config(self.config)
        gate.git(self.repo, "add", "-A")
        gate.git(self.repo, "commit", "--quiet", "-m", "baseline")
        self.base = gate.git(self.repo, "rev-parse", "HEAD")
        gate.git(self.repo, "push", "--quiet", "origin", "candidate/a")
        gate.git(self.repo, "checkout", "--quiet", "-b", "ai/1-change")

    def change(self, test_source: str = PASSING_TEST) -> str:
        (self.repo / "src" / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
        (self.repo / "tests" / "test_app.py").write_text(test_source, encoding="utf-8")
        self.gate.git(self.repo, "add", "-A")
        self.gate.git(self.repo, "commit", "--quiet", "-m", "the executor's change")
        self.head = self.gate.git(self.repo, "rev-parse", "HEAD")
        self.gate.git(self.repo, "push", "--quiet", "origin", "ai/1-change")
        return self.head

    def env(self) -> dict[str, str]:
        return self.gate.env(
            GATE_HOME=str(self.gate.root),
            GATE_PY=sys.executable,
            GATE_CONFIG=str(self.config),
            GATE_PR_DIR=str(self.repo),
            GATE_BASE_SHA=self.base,
            GATE_HEAD_SHA=self.head,
            GATE_HEAD_REF="ai/1-change",
            GATE_PR_AUTHOR="example-executor[bot]",
            GATE_PR="7",
            GATE_REPORTS_DIR=str(self.tmp / "no-reports"),
            GATE_KNOWN_FAILING=str(self.repo / "acceptance" / "known-failing.txt"),
            GATE_ACCEPTANCE_MODE="subset",
            GATE_ENV_ROLE="run",
            GATE_PROBE_TOKEN="SENTINEL-VALUE-PROBE",
            GITHUB_API_URL=self.stub.url,
            GITHUB_REPOSITORY="example/app",
            GITHUB_EVENT_PATH=str(self.event),
        )

    def run_job(self, stop_after: str | None = None) -> dict:
        """Run the run job's steps. Returns the jobs record the API would give."""
        builtin = self.gate.root / "gate" / "builtin_checks.toml"
        steps = []
        finished = True
        for number, check in enumerate(RUN_STEPS, start=1):
            if not finished:
                steps.append({"name": check, "status": "completed", "conclusion": "cancelled", "number": number})
                continue
            config = builtin if check in ("gate/env", "gate/guard") else self.config
            process = self.gate.run("run_checks", "--config", config, "--check", check, "--out", self.out, "--workdir", self.repo, env=self.env())
            steps.append({"name": check, "status": "completed", "conclusion": "success" if process.returncode == 0 else "failure", "number": number})
            if check == stop_after:
                finished = False
        if not stop_after:
            # As the judge does: every diagnostic step runs, configured or not.
            for check in DIAGNOSTIC_STEPS:
                process = self.gate.run("run_checks", "--config", self.config, "--check", check, "--if-configured", "--out", self.out, "--workdir", self.repo, env=self.env())
                steps.append({"name": check, "status": "completed", "conclusion": "success" if process.returncode == 0 else "failure", "number": len(steps) + 1})
        conclusion = "cancelled" if stop_after else ("success" if all(s["conclusion"] == "success" for s in steps) else "failure")
        return {"jobs": [{"name": "judge / run", "status": "completed", "conclusion": conclusion, "steps": steps}]}

    def claim_ready(self) -> None:
        """What a dishonest or mistaken run could write: its meta.json says ready, resealed."""
        meta = json.loads((self.out / "meta.json").read_text(encoding="utf-8"))
        meta["claimed_verdict"] = "ready-for-human"
        (self.out / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        lines = [
            line
            for line in (self.out / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
            if not line.endswith("  meta.json")
        ]
        digest = hashlib.sha256((self.out / "meta.json").read_bytes()).hexdigest()
        (self.out / "SHA256SUMS").write_text("\n".join([*lines, f"{digest}  meta.json"]) + "\n", encoding="utf-8")

    def judge(self, jobs: dict, remote: str | None = None, claim: bool = False) -> dict:
        """Run the seal, publish and archive, and return the final verdict."""
        assert self.gate.run("report", "seal", "--artifact", self.out, "--head-sha", self.head, "--run-id", HEAD_RUN, "--run-attempt", "1").returncode == 0
        if claim:
            self.claim_ready()
        context = {
            "repository": "example/app",
            "head_repository": "example/app",
            "pr": 7,
            "run_id": HEAD_RUN,
            "run_attempt": "1",
            "event": "pull_request_target",
            "baseline_sha": "0" * 40,
            "base_sha": self.base,
            "head_sha": self.head,
            "gate_sha": "1" * 40,
            "head_ref": "ai/1-change",
            "author": "example-executor[bot]",
            "config_hashes": {"quality.toml": "2" * 64},
        }
        context_path = self.tmp / "context.json"
        context_path.write_text(json.dumps(context), encoding="utf-8")
        jobs_path = self.tmp / "jobs.json"
        jobs_path.write_text(json.dumps(jobs), encoding="utf-8")
        generated = self.gate.run("report", "generate", "--context", context_path, "--jobs", jobs_path, "--artifact", self.out, "--config", self.config, "--out", self.publish)
        assert generated.returncode == 0, generated.stderr
        result = self.tmp / "archive-result.json"
        self.gate.run(
            "archive", "store", "--remote", remote or self.remote, "--branch", "reports", "--pr", 7, "--run-id", HEAD_RUN, "--attempt", 1,
            "--artifact", self.out, "--publish", self.publish, "--context", context_path, "--out", result,
        )
        final_path = self.tmp / "final" / "final.json"
        finished = self.gate.run("report", "final", "--verdict", self.publish / "verdict.json", "--archive", result, "--out", final_path)
        assert finished.returncode == 0, finished.stderr
        return json.loads(final_path.read_text(encoding="utf-8"))


@pytest.fixture
def world(short_tmp, gate, stub):
    return World(short_tmp, gate, stub)


def stored_files(world: World) -> list[str]:
    listing = world.gate.git(world.remote, "ls-tree", "-r", "--name-only", "reports")
    return listing.splitlines()


@pytest.mark.req("V-5", "F-1", "FN-2")
def test_a_clean_change_is_ready_for_a_person_and_stored(world):
    # Round 2 (FN-2): the gate's own verdict is ready, and the final verdict waits for the independent review
    # (before round 2 this test expected the final verdict ready-for-human and gate/final success).
    world.change()
    final = world.judge(world.run_job())
    assert final["gate_verdict"] == "ready-for-human", final["reasons"]
    assert final["verdict"] == "awaiting-review"
    assert final["conclusions"] == {"gate/archive": "success", "gate/final": None}
    assert "reports/7/1001-1/report.json" in stored_files(world)
    assert "reports/7/1001-1/artifact/exit-codes.tsv" in stored_files(world)


@pytest.mark.req("V-4", "V-6", "F-3")
def test_a_failing_test_blocks_even_when_the_artifact_claims_ready(world):
    world.change(FAILING_TEST)
    final = world.judge(world.run_job(), claim=True)
    assert final["verdict"] == "blocked"
    assert final["conclusions"]["gate/final"] == "failure"
    codes = {item["code"] for item in final["reasons"]}
    assert {"FAILED_CHECK", "CLAIM_MISMATCH"} <= codes


@pytest.mark.req("V-2", "W-2")
def test_a_run_cancelled_midway_is_incomplete_and_its_evidence_is_stored(world):
    world.change()
    final = world.judge(world.run_job(stop_after="gate/guard"))
    assert final["verdict"] == "incomplete"
    assert final["conclusions"]["gate/final"] == "failure"
    assert any(item["code"] == "UNFINISHED_STAGE" for item in final["reasons"])
    assert "reports/7/1001-1/artifact/raw/gate-guard/0.log" in stored_files(world)


@pytest.mark.req("F-2")
def test_evidence_that_cannot_be_stored_is_never_ready(world, short_tmp):
    world.change()
    final = world.judge(world.run_job(), remote=str(short_tmp / "no-such-remote.git"))
    assert final["verdict"] == "incomplete"
    assert final["conclusions"] == {"gate/archive": "failure", "gate/final": "failure"}
    assert any(item["code"] == "EVIDENCE_NOT_STORED" for item in final["reasons"])


@pytest.mark.req("G-1")
def test_the_guard_refuses_an_executor_change_to_the_configuration(world):
    (world.repo / "quality.toml").write_text(world.config.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    world.change()
    final = world.judge(world.run_job())
    assert final["verdict"] == "blocked"
    guard = json.loads((world.out / "guard.json").read_text(encoding="utf-8"))
    assert any(item["rule"] == "PROTECTED_PATH" for item in guard["violations"])


def reproduce_env(world: World) -> dict[str, str]:
    return world.gate.env(GATE_PY=sys.executable)


def test_reproduce_gives_the_stored_report_again(world, short_tmp):
    head = world.change()
    assert world.judge(world.run_job())["gate_verdict"] == "ready-for-human"  # round 2: was ["verdict"]; the final one waits (FN-2)
    out = short_tmp / "rerun"
    process = world.gate.run("reproduce", "--repo", world.remote, "--sha", head, "--out", out, env=reproduce_env(world))
    assert process.returncode == 0, process.stdout + process.stderr
    assert "reproduced" in process.stdout


def test_reproduce_notices_a_stored_report_that_was_changed(world, short_tmp, gate):
    head = world.change()
    world.judge(world.run_job())
    clone = short_tmp / "tamper"
    gate.git(short_tmp, "clone", "--quiet", "--branch", "reports", str(world.remote), str(clone))
    stored = clone / "reports" / "7" / "1001-1" / "report.json"
    report = json.loads(stored.read_text(encoding="utf-8"))
    report["checks"][2]["conclusion"] = "failure"
    stored.write_text(json.dumps(report), encoding="utf-8")
    gate.git(clone, "add", "-A")
    gate.git(clone, "commit", "--quiet", "-m", "a changed report")
    gate.git(clone, "push", "--quiet", "origin", "reports")
    out = short_tmp / "rerun"
    process = world.gate.run("reproduce", "--repo", world.remote, "--sha", head, "--out", out, env=reproduce_env(world))
    assert process.returncode == 1
    assert "differs: checks[2].conclusion" in process.stdout


def test_reproduce_refuses_a_commit_with_no_stored_evidence(world, short_tmp):
    head = world.change()
    world.judge(world.run_job())
    process = world.gate.run("reproduce", "--repo", world.remote, "--sha", world.base, "--out", short_tmp / "rerun", env=reproduce_env(world))
    assert process.returncode == 2
    assert head != world.base


@pytest.mark.req("X-0")
def test_reproduce_refuses_a_reports_branch_written_by_another_actor(world, short_tmp, stub):
    head = world.change()
    world.judge(world.run_job())
    stub.routes[("GET", "/repos/example/app/git/ref/heads/reports")] = (200, {"object": {"sha": "f" * 40}})
    stub.routes[("GET", "/repos/example/app/commits?sha=reports&per_page=100")] = (
        200,
        [{"sha": "f" * 40, "author": {"login": "someone-else[bot]"}, "commit": {"verification": {"verified": True}}}],
    )
    env = world.gate.env(GATE_PY=sys.executable, GITHUB_API_URL=stub.url)
    process = world.gate.run("reproduce", "--repo", world.remote, "--api-repo", "example/app", "--sha", head, "--out", short_tmp / "rerun", env=env)
    assert process.returncode == 1
    assert "REPORTS_UNTRUSTED" in process.stderr


@pytest.mark.req("X-0b")
def test_reproduce_refuses_to_start_with_a_secret_in_its_environment(world, short_tmp):
    """PR code would run under this user, and could read this process's environment."""
    head = world.change()
    assert world.judge(world.run_job())["gate_verdict"] == "ready-for-human"  # round 2: was ["verdict"]; the final one waits (FN-2)
    env = {**reproduce_env(world), "GATE_TOKEN": "FAKE-VALUE-NOT-A-TOKEN", "SOME_API_KEY": "FAKE-VALUE-TWO"}
    out = short_tmp / "rerun"
    process = world.gate.run("reproduce", "--repo", world.remote, "--sha", head, "--out", out, env=env)
    assert process.returncode == 2
    assert "GATE_TOKEN" in process.stderr and "SOME_API_KEY" in process.stderr
    assert "FAKE-VALUE" not in process.stdout + process.stderr
    assert not out.exists(), "nothing ran"


@pytest.mark.req("X-1")
def test_reproduce_finds_a_closed_prs_head_after_its_branch_is_gone(world, short_tmp):
    head = world.change()
    assert world.judge(world.run_job())["gate_verdict"] == "ready-for-human"  # round 2: was ["verdict"]; the final one waits (FN-2)
    world.gate.git(world.remote, "update-ref", "refs/pull/7/head", head)
    world.gate.git(world.remote, "update-ref", "-d", "refs/heads/ai/1-change")
    # Nothing else in the remote holds that commit now but refs/pull. Through file:// a clone
    # receives only what its refs reach, as from a real server; a plain path copies everything.
    process = world.gate.run("reproduce", "--repo", world.remote.as_uri(), "--sha", head, "--out", short_tmp / "rerun", env=reproduce_env(world))
    assert process.returncode == 0, process.stdout + process.stderr


@pytest.mark.req("X-1")
def test_reproduce_uses_the_default_branchs_security_review(world, short_tmp):
    """A PR's own copy must not decide the rerun any more than it decided the run."""
    review = "| tool | rule | path | reason |\n|---|---|---|---|\n"
    (world.repo / "security-review.md").write_text(review + "| bandit | B999 | x.py | the PR's own |\n", encoding="utf-8")
    head = world.change()
    assert world.judge(world.run_job())["verdict"] == "blocked", "the guard refuses the file"
    out = short_tmp / "rerun"
    world.gate.run("reproduce", "--repo", world.remote, "--sha", head, "--out", out, env=reproduce_env(world))
    assert not (out / "work" / "pr" / "security-review.md").exists()
