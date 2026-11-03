"""The gate's own tests of what the contract's entrances add to the workflows."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.req("P-1", "P-2", "Q-1a", "R-9", "R-10", "A-9", "D-8", "E-4a", "F-2a", "Z-1", "C-1")

SECRET = "SENTINEL-VALUE-1234"


def write_json(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# gate.publish


@pytest.mark.req("V-1")
def test_post_checks_posts_each_conclusion_on_the_exact_sha(gate, stub, tmp_path):
    stub.default_post = 201
    verdict = write_json(tmp_path / "verdict.json", {"verdict": "blocked", "reasons": [{"code": "FAILED_CHECK", "detail": "x"}], "checks": {"gate/tests": "failure", "gate/env": "success"}})
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    process = gate.run("publish", "post-checks", "--verdict", verdict, "--head-sha", "a" * 40, env=env)
    assert process.returncode == 0, process.stderr
    posted = {r["body"]["name"]: r["body"] for r in stub.requests if r["path"] == "/repos/example/app/check-runs"}
    assert posted["gate/tests"]["conclusion"] == "failure"
    assert posted["gate/env"]["conclusion"] == "success"
    assert {body["head_sha"] for body in posted.values()} == {"a" * 40}
    assert SECRET not in process.stdout + process.stderr


def test_post_final_posts_archive_and_final(gate, stub, tmp_path):
    stub.default_post = 201
    final = write_json(tmp_path / "final.json", {"verdict": "incomplete", "reasons": [], "conclusions": {"gate/archive": "failure", "gate/final": "failure"}})
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    assert gate.run("publish", "post-final", "--final", final, "--head-sha", "b" * 40, env=env).returncode == 0
    names = {r["body"]["name"]: r["body"]["conclusion"] for r in stub.requests}
    assert names == {"gate/archive": "failure", "gate/final": "failure"}


def test_an_api_failure_is_reported_without_the_token(gate, stub, tmp_path):
    stub.default_post = 500
    verdict = write_json(tmp_path / "verdict.json", {"verdict": "blocked", "reasons": [], "checks": {"gate/tests": "failure"}})
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    process = gate.run("publish", "post-checks", "--verdict", verdict, "--head-sha", "a" * 40, env=env)
    assert process.returncode == 1
    assert SECRET not in process.stdout + process.stderr


def test_context_holds_every_sha_and_config_hash(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text('[project]\nbaseline_sha = "' + "c" * 40 + '"\n', encoding="utf-8")
    out = tmp_path / "context.json"
    env = gate.env(
        GATE_REPOSITORY="example/app", GATE_HEAD_REPOSITORY="example/app", GATE_PR="3", GATE_RUN_ID="9", GATE_RUN_ATTEMPT="2",
        GATE_EVENT="pull_request_target", GATE_BASE_SHA="d" * 40, GATE_HEAD_SHA="e" * 40, GATE_SHA="f" * 40, GATE_HEAD_REF="ai/3-x",
        GATE_TRUSTED_SHA="1" * 40, ImageOS="ubuntu24", ImageVersion="20261101.1.0",
    )
    process = gate.run("publish", "context", "--config", config, "--hash", config, "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    context = json.loads(out.read_text(encoding="utf-8"))
    assert context["baseline_sha"] == "c" * 40
    assert context["base_sha"] == "d" * 40
    assert context["head_sha"] == "e" * 40
    assert context["gate_sha"] == "f" * 40
    assert context["trusted_sha"] == "1" * 40
    assert len(context["config_hashes"]["quality.toml"]) == 64
    assert context["execution_environment"] == {"image_os": "ubuntu24", "image_version": "20261101.1.0"}


def test_context_hashes_each_configuration_file_and_names_a_missing_one(gate, tmp_path):
    (tmp_path / "quality.toml").write_text("", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @example\n", encoding="utf-8")
    out = tmp_path / "context.json"
    env = gate.env(
        GATE_REPOSITORY="example/app", GATE_HEAD_REPOSITORY="example/app", GATE_PR="3", GATE_RUN_ID="9", GATE_RUN_ATTEMPT="2",
        GATE_EVENT="pull_request_target", GATE_BASE_SHA="d" * 40, GATE_HEAD_SHA="e" * 40, GATE_SHA="f" * 40, GATE_HEAD_REF="ai/3-x",
    )
    process = gate.run(
        "publish", "context", "--config", tmp_path / "quality.toml", "--hash-root", tmp_path,
        "--hash", "quality.toml", "--hash", "CODEOWNERS", "--hash", "prompts/executor.md", "--out", out, env=env,
    )
    assert process.returncode == 0, process.stderr
    hashes = json.loads(out.read_text(encoding="utf-8"))["config_hashes"]
    assert len(hashes["quality.toml"]) == 64
    assert len(hashes["CODEOWNERS"]) == 64
    assert hashes["prompts/executor.md"] == "missing"


def test_context_refuses_a_missing_trusted_value(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    assert gate.run("publish", "context", "--config", config, "--out", tmp_path / "c.json", env=gate.env()).returncode == 2


def test_extras_count_only_the_owners_time_comments(gate, stub, tmp_path):
    stub.routes[("GET", "/repos/example/app/issues/5/comments?per_page=100")] = (
        200,
        [
            {"author_association": "OWNER", "body": "/time 12"},
            {"author_association": "NONE", "body": "/time 500"},
            {"author_association": "OWNER", "body": "no time here"},
        ],
    )
    stub.routes[("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100")] = (200, [])
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app")
    out = tmp_path / "extras.json"
    (tmp_path / "r").mkdir()
    assert gate.run("publish", "extras", "--reports-dir", tmp_path / "r", "--pr", 5, "--integration", "candidate/a", "--out", out, env=env).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["human"] == [{"minutes": 12}]


@pytest.mark.req("B-1")
def test_extras_collect_merges_for_the_bypass_flag(gate, stub, tmp_path):
    head = "a" * 40
    stub.routes[("GET", "/repos/example/app/issues/5/comments?per_page=100")] = (200, [])
    stub.routes[("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100")] = (
        200,
        [
            {"number": 2, "merged_at": "2026-11-03T10:00:00Z", "merge_commit_sha": "m" * 40, "merged_by": {"login": "someone"}, "head": {"sha": head}},
            {"number": 3, "merged_at": None, "head": {"sha": "b" * 40}},
        ],
    )
    stub.routes[("GET", f"/repos/example/app/commits/{head}/check-runs?check_name=gate%2Ffinal")] = (200, {"check_runs": [{"conclusion": "failure"}]})
    stub.routes[("GET", "/repos/example/app/pulls/2/reviews?per_page=100")] = (
        200,
        [{"state": "APPROVED", "commit_id": head}, {"state": "APPROVED", "commit_id": "old"}],
    )
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app")
    out = tmp_path / "extras.json"
    (tmp_path / "r").mkdir()
    process = gate.run("publish", "extras", "--reports-dir", tmp_path / "r", "--pr", 5, "--integration", "candidate/a", "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    merges = json.loads(out.read_text(encoding="utf-8"))["merges"]
    assert merges == [
        {"pr": 2, "merge_sha": "m" * 40, "merged_by": "someone", "head_sha": head, "final_conclusion": "failure", "approvals": 1, "via_pr": True}
    ]


def test_limits_refuse_a_missing_turn_limit(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text("[limits]\ntimeout_minutes = 5\n", encoding="utf-8")
    assert gate.run("publish", "limits", "--config", config, "--output", tmp_path / "o.txt").returncode == 2


@pytest.mark.req("Y-11")
def test_limits_build_the_deny_rules_for_the_read_tools(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text('[limits]\nmax_turns = 7\ntimeout_minutes = 5\n[project]\nintegration_branch = "candidate/a"\n[spec_tests]\ndeny_read = ["src/**"]\n', encoding="utf-8")
    output = tmp_path / "o.txt"
    assert gate.run("publish", "limits", "--config", config, "--output", output).returncode == 0
    lines = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    assert lines["max-turns"] == "7"
    assert lines["integration-branch"] == "candidate/a"
    deny = json.loads(lines["spec-settings"])["permissions"]["deny"]
    for tool in ("Read", "Grep", "Glob"):
        assert f"{tool}(src/**)" in deny


@pytest.mark.req("Y-11")
def test_hide_paths_takes_code_out_without_marking_it_deleted(gate, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    gate.git(repo, "init", "--quiet")
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("X = 1\n", encoding="utf-8")
    (repo / "SPEC.md").write_text("the spec\n", encoding="utf-8")
    (repo / "quality.toml").write_text('[spec_tests]\ndeny_read = ["src/**"]\n', encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "x")
    assert gate.run("publish", "hide-paths", "--config", repo / "quality.toml", "--repo", repo).returncode == 0
    assert not (repo / "src" / "app.py").exists()
    assert (repo / "SPEC.md").exists()
    assert gate.git(repo, "status", "--porcelain") == ""


def test_hide_paths_refuses_an_empty_deny_list(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text("[spec_tests]\ndeny_read = []\n", encoding="utf-8")
    assert gate.run("publish", "hide-paths", "--config", config, "--repo", tmp_path).returncode == 2


# gate.report: what the workflow adds


@pytest.mark.req("F-2")
def test_final_treats_a_missing_preliminary_verdict_as_incomplete(gate, tmp_path):
    archive = write_json(tmp_path / "a.json", {"stored": True, "sha256sums_match": True})
    out = tmp_path / "final.json"
    assert gate.run("report", "final", "--verdict", tmp_path / "absent.json", "--archive", archive, "--out", out).returncode == 0
    final = json.loads(out.read_text(encoding="utf-8"))
    assert final["verdict"] == "incomplete"
    assert final["conclusions"]["gate/final"] == "failure"


@pytest.mark.parametrize("expected", ["0" * 64, ""])
def test_final_refuses_a_verdict_that_is_not_the_one_publish_computed(gate, tmp_path, expected):
    verdict = write_json(tmp_path / "v.json", {"verdict": "ready-for-human", "reasons": [], "checks": {}})
    archive = write_json(tmp_path / "a.json", {"stored": True, "sha256sums_match": True})
    out = tmp_path / "final.json"
    assert gate.run("report", "final", "--verdict", verdict, "--expect-verdict-sha256", expected, "--archive", archive, "--out", out).returncode == 0
    final = json.loads(out.read_text(encoding="utf-8"))
    assert final["verdict"] == "blocked"
    assert any(item["code"] == "PUBLISH_OUTPUT_MISMATCH" for item in final["reasons"])


def test_final_accepts_the_verdict_publish_computed(gate, tmp_path):
    import hashlib

    verdict = write_json(tmp_path / "v.json", {"verdict": "ready-for-human", "reasons": [], "checks": {}})
    digest = hashlib.sha256(verdict.read_bytes()).hexdigest()
    archive = write_json(tmp_path / "a.json", {"stored": True, "sha256sums_match": True})
    out = tmp_path / "final.json"
    assert gate.run("report", "final", "--verdict", verdict, "--expect-verdict-sha256", digest, "--archive", archive, "--out", out).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "ready-for-human"


def test_final_blocks_when_the_archive_jobs_environment_is_broken(gate, tmp_path):
    verdict = write_json(tmp_path / "v.json", {"verdict": "ready-for-human", "reasons": [], "checks": {}})
    archive = write_json(tmp_path / "a.json", {"stored": True, "sha256sums_match": True})
    env_result = write_json(tmp_path / "e.json", {"ok": False})
    out = tmp_path / "final.json"
    assert gate.run("report", "final", "--verdict", verdict, "--archive", archive, "--env-result", env_result, "--out", out).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["verdict"] == "blocked"


def test_seal_copies_the_records_and_hashes_every_file(gate, tmp_path):
    artifact = tmp_path / "out"
    guard = artifact / "raw" / "gate-guard" / "guard.json"
    write_json(guard, {"repeated_fix": False})
    nested = artifact / "raw" / "x" / "SHA256SUMS"
    nested.parent.mkdir(parents=True)
    nested.write_text("not the top one\n", encoding="utf-8")
    assert gate.run("report", "seal", "--artifact", artifact, "--head-sha", "a" * 40, "--run-id", "1", "--run-attempt", "1").returncode == 0
    assert (artifact / "guard.json").is_file()
    assert (artifact / "environment.json").is_file()
    names = [line.split("  ")[1] for line in (artifact / "SHA256SUMS").read_text(encoding="utf-8").splitlines()]
    assert "guard.json" in names
    assert "meta.json" in names
    assert "raw/x/SHA256SUMS" in names
    assert "SHA256SUMS" not in names


# gate.run_checks: what the workflow adds


def test_a_check_gets_its_env_table_and_not_the_gates_python_path(gate, tmp_path):
    config = tmp_path / "quality.toml"
    script = "import os; print('PATH=' + os.environ.get('PYTHONPATH', 'none')); print('OTHER=' + os.environ.get('OTHER', 'none'))"
    config.write_text(f'[checks."diag/benchmark"]\nclass = "diagnostic"\ncommands = [{json.dumps([sys.executable, "-c", script])}]\nenv = {{ OTHER = "{{env:FROM_JOB}}" }}\n', encoding="utf-8")
    out = tmp_path / "out"
    process = gate.run("run_checks", "--config", config, "--check", "diag/benchmark", "--out", out, env=gate.env(FROM_JOB="given"))
    assert process.returncode == 0, process.stderr
    log = (out / "raw" / "diag-benchmark" / "0.log").read_text(encoding="utf-8")
    assert "PATH=none" in log
    assert "OTHER=given" in log


def test_a_placeholder_for_a_missing_variable_exits_two(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text(f'[checks."gate/tests"]\ncommands = [{json.dumps([sys.executable, "{env:ABSENT_VARIABLE}"])}]\n', encoding="utf-8")
    assert gate.run("run_checks", "--config", config, "--check", "gate/tests", "--out", tmp_path / "o").returncode == 2


def test_if_configured_passes_only_for_a_check_not_configured(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "o"
    assert gate.run("run_checks", "--config", config, "--check", "diag/mypy", "--if-configured", "--out", out).returncode == 0
    assert not (out / "exit-codes.tsv").exists()
    assert gate.run("run_checks", "--config", config, "--check", "gate/tests", "--out", out).returncode == 2


def test_the_recorded_command_stays_as_configured(gate, tmp_path):
    config = tmp_path / "quality.toml"
    argv = [sys.executable, "-c", "pass", "{raw}/x"]
    config.write_text(f'[checks."diag/mypy"]\ncommands = [{json.dumps(argv)}]\n', encoding="utf-8")
    out = tmp_path / "o"
    assert gate.run("run_checks", "--config", config, "--check", "diag/mypy", "--out", out).returncode == 0
    row = (out / "exit-codes.tsv").read_text(encoding="utf-8").splitlines()[1].split("\t")
    assert json.loads(row[5]) == argv


# gate.acceptance and gate.security_check: the wrapped commands


@pytest.mark.req("A-1")
def test_acceptance_runs_the_command_and_a_listed_failure_exits_zero(gate, tmp_path):
    junit = tmp_path / "junit.xml"
    write = (
        "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("
        "'<testsuite><testcase classname=\"a\" name=\"t\"><failure/></testcase></testsuite>');sys.exit(1)"
    )
    known = tmp_path / "known.txt"
    known.write_text("a::t PUB-01\n", encoding="utf-8")
    out = tmp_path / "o.json"
    process = gate.run("acceptance", "--junit", junit, "--known-failing", known, "--out", out, "--", sys.executable, "-c", write, junit)
    assert process.returncode == 0, process.stderr
    assert json.loads(out.read_text(encoding="utf-8"))["test_command_exit_code"] == 1


def test_acceptance_fails_when_the_test_command_itself_breaks(gate, tmp_path):
    junit = tmp_path / "junit.xml"
    write = (
        "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("
        "'<testsuite><testcase classname=\"a\" name=\"t\"/></testsuite>');sys.exit(3)"
    )
    known = tmp_path / "known.txt"
    known.write_text("", encoding="utf-8")
    out = tmp_path / "o.json"
    process = gate.run("acceptance", "--junit", junit, "--known-failing", known, "--out", out, "--", sys.executable, "-c", write, junit)
    assert process.returncode == 1
    assert "TEST_COMMAND_ERROR" in json.loads(out.read_text(encoding="utf-8"))["reason_codes"]


@pytest.mark.req("A-6")
def test_the_final_prs_flag_can_come_from_the_trusted_environment(gate, tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite><testcase classname="a" name="t"><failure/></testcase></testsuite>', encoding="utf-8")
    known = tmp_path / "known.txt"
    known.write_text("a::t PUB-01\n", encoding="utf-8")
    out = tmp_path / "o.json"
    assert gate.run("acceptance", "--junit", junit, "--known-failing", known, "--out", out, env=gate.env(GATE_REQUIRE_EMPTY="1")).returncode == 1
    assert "LIST_NOT_EMPTY" in json.loads(out.read_text(encoding="utf-8"))["reason_codes"]
    assert gate.run("acceptance", "--junit", junit, "--known-failing", known, "--out", out, env=gate.env()).returncode == 0


# gate.feedback outputs


def test_outputs_refuse_a_branch_name_that_could_reach_an_expression(gate, tmp_path):
    decision = write_json(tmp_path / "d.json", {"act": True, "pr": 1, "head_ref": "ai/x$(touch y)", "comment": "c"})
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    process = gate.run("feedback", "outputs", "--decision", decision, "--config", config, "--output", tmp_path / "o.txt", "--note", tmp_path / "n" / "c.txt")
    assert process.returncode == 2
    assert not (tmp_path / "o.txt").exists()


def test_outputs_hand_on_a_decision(gate, tmp_path):
    decision = write_json(tmp_path / "d.json", {"act": True, "post": True, "pr": 4, "head_ref": "ai/4-x", "comment": "the note"})
    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nreviewer_app = "r-app"\nexecutor_app = "e-app"\n', encoding="utf-8")
    output = tmp_path / "o.txt"
    note = tmp_path / "n" / "c.txt"
    assert gate.run("feedback", "outputs", "--decision", decision, "--config", config, "--output", output, "--note", note).returncode == 0
    assert output.read_text(encoding="utf-8").splitlines() == ["act=true", "post=true", "pr=4", "head-ref=ai/4-x", "allowed-bots=r-app,e-app"]
    assert note.read_text(encoding="utf-8") == "the note\n"


# gate.env_check: the rerun's role


def test_the_reproduce_role_checks_no_secrets_and_ignores_the_runner_image(gate, tmp_path):
    config = tmp_path / "quality.toml"
    config.write_text('[environment]\nimage_os = "ubuntu24"\n', encoding="utf-8")
    assert gate.run("env_check", "--role", "reproduce", "--config", config, env=gate.env()).returncode == 0
    process = gate.run("env_check", "--role", "reproduce", "--config", config, env=gate.env(SOME_TOKEN=SECRET))
    assert process.returncode == 1
    assert "secret-present:SOME_TOKEN" in process.stdout
    assert SECRET not in process.stdout + process.stderr


# Nothing here is run from a judged repository's folder.


def test_a_judged_repository_cannot_shadow_the_gate(gate, tmp_path):
    fake = tmp_path / "gate"
    fake.mkdir()
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "env_check.py").write_text("import sys; print('SHADOWED'); sys.exit(0)\n", encoding="utf-8")
    process = gate.run("env_check", "--role", "executor", env=gate.env(), cwd=tmp_path)
    assert "SHADOWED" not in process.stdout
    assert process.returncode == 1


# A lost read of the stored runs must never look like "no earlier rounds".


def test_extras_refuse_a_missing_folder_of_stored_runs(gate, stub, tmp_path):
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app")
    process = gate.run("publish", "extras", "--reports-dir", tmp_path / "absent", "--pr", 5, "--integration", "candidate/a", "--out", tmp_path / "e.json", env=env)
    assert process.returncode == 2
    assert not (tmp_path / "e.json").exists()


def test_the_guard_refuses_a_missing_folder_of_stored_runs(gate, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    gate.git(repo, "init", "--quiet")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "x")
    sha = gate.git(repo, "rev-parse", "HEAD")
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "g.json"
    process = gate.run("guard", "--repo", repo, "--base", sha, "--head", sha, "--branch", "ai/1-x", "--config", config, "--out", out, "--reports-dir", tmp_path / "absent", "--pr", 1)
    assert process.returncode == 2
    assert not out.exists()


def test_feedback_refuses_a_missing_folder_of_stored_runs(gate, tmp_path):
    event = write_json(tmp_path / "event.json", {"context": "independent-review", "state": "failure", "sha": "a" * 40, "sender": {"login": "r[bot]"}})
    pulls = write_json(tmp_path / "pulls.json", [])
    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nreviewer_app = "r"\n', encoding="utf-8")
    out = tmp_path / "d.json"
    process = gate.run("feedback", "decide", "--event-name", "status", "--event", event, "--pulls", pulls, "--reports-dir", tmp_path / "absent", "--config", config, "--out", out)
    assert process.returncode == 2
    assert not out.exists()
