"""gate.reproduce (X-2, the one exit code that can be seen with a local repository and no container) and gate.publish.

Not covered, and why (see the report): X-1 and the exit codes 0 and 1 of X-2 need stored evidence from a real judge run and
the reruns of its checks; P-1 and P-2 need the GitHub API and arguments that CONTRACTS.md does not give.
"""
from __future__ import annotations

import shutil

import pytest

from gatekit import (Repo, SENTINEL_PREFIX, assert_no_traceback, assert_refused, base_env, closed_port_url, git,
                     run_gate, write_json)

SUBCOMMANDS = ["context", "jobs", "extras", "post-checks", "post-final", "comment", "pulls", "limits", "hide-paths"]


def repo_with_commit(tmp_path):
    repo = Repo(tmp_path / "app")
    repo.write("src/app.py", "x = 1\n")
    return repo, repo.commit("app")


@pytest.mark.req("X-2")
def test_x2_no_reports_branch_at_all_means_no_evidence_exits_2(tmp_path):
    repo, sha = repo_with_commit(tmp_path)
    out = tmp_path / "rerun"
    res = run_gate("reproduce", "--repo", repo.path, "--sha", sha, "--out", out, cwd=tmp_path, timeout=120)
    assert_refused(res, 2)
    assert res.both.strip(), "a refusal prints a short message"


@pytest.mark.req("X-2")
def test_x2_evidence_that_is_stored_only_for_another_sha_is_no_evidence_for_this_one(tmp_path):
    repo, sha = repo_with_commit(tmp_path)
    repo.git("checkout", "-q", "--orphan", "reports")
    repo.git("rm", "-rq", "--cached", ".")
    shutil.rmtree(repo.path / "src")
    write_json(repo.path / "reports" / "7" / "1001-1" / "context.json",
               {"pr": 7, "run_id": 1001, "run_attempt": 1, "head_sha": "9" * 40, "trusted_sha": "8" * 40})
    repo.commit("evidence for another sha")
    repo.checkout("main")
    assert git(repo.path, "rev-parse", "--verify", "refs/heads/reports")
    res = run_gate("reproduce", "--repo", repo.path, "--sha", sha, "--out", tmp_path / "rerun", cwd=tmp_path, timeout=120)
    assert_refused(res, 2)


@pytest.mark.req("X-2", "C-2")
def test_x2_usage_error_exits_2(tmp_path):
    assert_refused(run_gate("reproduce", "--sha", "3" * 40, cwd=tmp_path), 2)


@pytest.mark.req("C-3")
@pytest.mark.parametrize("sub", SUBCOMMANDS)
def test_publish_never_prints_its_token_whatever_fails(tmp_path, sub):
    env = base_env({"GATE_TOKEN": f"{SENTINEL_PREFIX}-PUBLISH-TOKEN", "GITHUB_API_URL": closed_port_url(),
                    "GITHUB_REPOSITORY": "example-org/example-app"})
    res = run_gate("publish", sub, env=env, cwd=tmp_path, timeout=120)
    assert "No module named" not in res.err, "precondition: gate.publish exists and runs with python -P -m"
    assert SENTINEL_PREFIX not in res.both, f"gate.publish {sub} printed its token"
    assert_no_traceback(res)
