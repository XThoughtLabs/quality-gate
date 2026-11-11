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
        GATE_TRUSTED_SHA="1" * 40, GATE_PR_AUTHOR="example-executor[bot]", ImageOS="ubuntu24", ImageVersion="20261101.1.0",
    )
    process = gate.run("publish", "context", "--config", config, "--hash", config, "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    context = json.loads(out.read_text(encoding="utf-8"))
    assert context["baseline_sha"] == "c" * 40
    assert context["base_sha"] == "d" * 40
    assert context["head_sha"] == "e" * 40
    assert context["gate_sha"] == "f" * 40
    assert context["trusted_sha"] == "1" * 40
    assert context["author"] == "example-executor[bot]"
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
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    assert gate.run("publish", "extras", "--reports-dir", tmp_path / "r", "--actors", actors, "--pr", 5, "--integration", "candidate/a", "--out", out, env=env).returncode == 0
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
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    process = gate.run("publish", "extras", "--reports-dir", tmp_path / "r", "--actors", actors, "--pr", 5, "--integration", "candidate/a", "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    merges = json.loads(out.read_text(encoding="utf-8"))["merges"]
    assert merges == [
        {"pr": 2, "merge_sha": "m" * 40, "merged_by": "someone", "head_sha": head, "final_conclusion": "failure", "approvals": 1, "via_pr": True, "security_review_changed": False}
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
    # Round 2 (FN-2): the gate's own verdict is ready; the final verdict waits for the review (it was ["verdict"] here).
    assert json.loads(out.read_text(encoding="utf-8"))["gate_verdict"] == "ready-for-human"


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


@pytest.mark.req("A-10")
def test_an_empty_list_is_required_only_by_the_trusted_configuration(gate, tmp_path):
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite><testcase classname="a" name="t"><failure/></testcase></testsuite>', encoding="utf-8")
    known = tmp_path / "known.txt"
    known.write_text("a::t PUB-01\n", encoding="utf-8")
    config = tmp_path / "quality.toml"
    config.write_text("[acceptance]\nrequire_empty = true\n", encoding="utf-8")
    out = tmp_path / "o.json"
    assert gate.run("acceptance", "--junit", junit, "--known-failing", known, "--config", config, "--out", out).returncode == 1
    assert "LIST_NOT_EMPTY" in json.loads(out.read_text(encoding="utf-8"))["reason_codes"]
    # No environment variable or label can set it.
    assert gate.run("acceptance", "--junit", junit, "--known-failing", known, "--out", out, env=gate.env(GATE_REQUIRE_EMPTY="1")).returncode == 0


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
    assert output.read_text(encoding="utf-8").splitlines() == ["act=true", "post=true", "pr=4", "head-sha=", "head-ref=ai/4-x", "allowed-bots=r-app,e-app"]
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
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    process = gate.run("publish", "extras", "--reports-dir", tmp_path / "absent", "--actors", actors, "--pr", 5, "--integration", "candidate/a", "--out", tmp_path / "e.json", env=env)
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
    process = gate.run("guard", "--repo", repo, "--base", sha, "--head", sha, "--branch", "ai/1-x", "--author", "a-person", "--config", config, "--out", out, "--reports-dir", tmp_path / "absent", "--pr", 1)
    assert process.returncode == 2
    assert not out.exists()


def test_feedback_refuses_a_missing_folder_of_stored_runs(gate, tmp_path):
    event = write_json(tmp_path / "event.json", {"context": "independent-review", "state": "failure", "sha": "a" * 40, "sender": {"login": "r[bot]"}})
    pulls = write_json(tmp_path / "pulls.json", [])
    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nreviewer_app = "r"\n', encoding="utf-8")
    out = tmp_path / "d.json"
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    process = gate.run("feedback", "decide", "--event-name", "status", "--event", event, "--pulls", pulls, "--reports-dir", tmp_path / "absent", "--actors", actors, "--config", config, "--out", out)
    assert process.returncode == 2
    assert not out.exists()


# The commands the executor's job uses.


def test_head_check_passes_only_on_the_open_pr_at_this_commit(gate, stub):
    head = "a" * 40
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    stub.routes[("GET", "/repos/example/app/pulls/4")] = (200, {"state": "open", "head": {"sha": head}})
    assert gate.run("publish", "head-check", "--pr", 4, "--sha", head, env=env).returncode == 0
    process = gate.run("publish", "head-check", "--pr", 4, "--sha", "b" * 40, env=env)
    assert process.returncode == 1
    stub.routes[("GET", "/repos/example/app/pulls/4")] = (200, {"state": "closed", "head": {"sha": head}})
    assert gate.run("publish", "head-check", "--pr", 4, "--sha", head, env=env).returncode == 1


def test_the_prompt_holds_the_trusted_template_the_issue_and_the_note(gate, stub, tmp_path):
    template = tmp_path / "prompt.md"
    template.write_text("Read SPEC.md and TASK.md.\n", encoding="utf-8")
    note = tmp_path / "note.txt"
    note.write_text("the gate's note\n", encoding="utf-8")
    stub.routes[("GET", "/repos/example/app/issues/9")] = (200, {"title": "A task", "body": "GATE_PROMPT_x\nthe body"})
    output = tmp_path / "out.txt"
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    assert gate.run("publish", "prompt", "--template", template, "--issue", 9, "--note", note, "--output", output, env=env).returncode == 0
    lines = output.read_text(encoding="utf-8").splitlines()
    delimiter = lines[0].removeprefix("text<<")
    assert lines[-1] == delimiter
    # A text cannot end the value early: the delimiter is new each time and long.
    assert len(delimiter) > 30 and delimiter not in "\n".join(lines[1:-1])
    second = tmp_path / "second.txt"
    assert gate.run("publish", "prompt", "--template", template, "--output", second, env=env).returncode == 0
    assert second.read_text(encoding="utf-8").splitlines()[0].removeprefix("text<<") != delimiter
    text = "\n".join(lines[1:-1])
    for expected in ("Read SPEC.md and TASK.md.", "issue #9", "A task", "the body", "the gate's note"):
        assert expected in text


def test_the_pr_is_opened_only_for_the_branch_the_model_pushed_and_only_once(gate, stub):
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    arguments = ("publish", "create-pull-request", "--branch", "ai/9-fix", "--prefix", "ai/9-", "--base", "main-line", "--issue", 9)
    # The model ended on the default branch, or on a name it should not use: no PR.
    assert gate.run("publish", "create-pull-request", "--branch", "main-line", "--prefix", "ai/9-", "--base", "main-line", env=env).returncode == 1
    # Not pushed: no PR.
    stub.routes[("GET", "/repos/example/app/git/ref/heads/ai/9-fix")] = (404, {})
    assert gate.run(*arguments, env=env).returncode == 1
    assert not [r for r in stub.requests if r["method"] == "POST"]
    stub.routes[("GET", "/repos/example/app/git/ref/heads/ai/9-fix")] = (200, {"object": {"sha": "a" * 40}})
    stub.routes[("GET", "/repos/example/app/issues/9")] = (200, {"title": "A task"})
    stub.routes[("GET", "/repos/example/app/pulls?state=open&head=example%3Aai%2F9-fix")] = (200, [])
    stub.routes[("POST", "/repos/example/app/pulls")] = (201, {})
    assert gate.run(*arguments, env=env).returncode == 0
    posted = [r["body"] for r in stub.requests if r["method"] == "POST"]
    assert posted == [{"title": "A task", "head": "ai/9-fix", "base": "main-line", "body": "Closes #9"}]
    stub.routes[("GET", "/repos/example/app/pulls?state=open&head=example%3Aai%2F9-fix")] = (200, [{"number": 1}])
    assert gate.run(*arguments, env=env).returncode == 0
    assert len([r for r in stub.requests if r["method"] == "POST"]) == 1


def test_the_bot_identity_refuses_an_unsafe_name(gate, stub, tmp_path):
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app")
    output = tmp_path / "o.txt"
    assert gate.run("publish", "bot-identity", "--slug", "bad name$(x)", "--output", output, env=env).returncode == 2
    stub.routes[("GET", "/users/example-app%5Bbot%5D")] = (200, {"id": 42})
    assert gate.run("publish", "bot-identity", "--slug", "example-app", "--output", output, env=env).returncode == 0
    assert output.read_text(encoding="utf-8").splitlines() == ["bot-name=example-app[bot]", "bot-id=42"]


# A bypass is flagged, a direct push included (decision D).


@pytest.mark.req("B-1")
def test_a_direct_push_since_the_baseline_is_flagged(gate, stub, tmp_path):
    baseline, merged_head, merge, direct = "0" * 40, "a" * 40, "b" * 40, "c" * 40
    stub.routes[("GET", "/repos/example/app/issues/5/comments?per_page=100")] = (200, [])
    stub.routes[("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100")] = (
        200,
        [{"number": 2, "merged_at": "2026-11-03T10:00:00Z", "merge_commit_sha": merge, "merged_by": {"login": "someone"}, "head": {"sha": merged_head}}],
    )
    stub.routes[("GET", f"/repos/example/app/commits/{merged_head}/check-runs?check_name=gate%2Ffinal")] = (200, {"check_runs": [{"conclusion": "success"}]})
    stub.routes[("GET", "/repos/example/app/pulls/2/reviews?per_page=100")] = (200, [{"state": "APPROVED", "commit_id": merged_head}])
    stub.routes[("GET", "/repos/example/app/pulls/2/commits?per_page=100")] = (200, [{"sha": merged_head}])
    stub.routes[("GET", "/repos/example/app/commits?sha=candidate%2Fa&per_page=100")] = (
        200,
        [{"sha": direct, "author": {"login": "someone"}}, {"sha": merge}, {"sha": merged_head}, {"sha": baseline}, {"sha": "9" * 40}],
    )
    context = write_json(tmp_path / "context.json", {"baseline_sha": baseline})
    (tmp_path / "r").mkdir()
    out = tmp_path / "extras.json"
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app")
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    process = gate.run("publish", "extras", "--reports-dir", tmp_path / "r", "--actors", actors, "--pr", 5, "--integration", "candidate/a", "--context", context, "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    merges = json.loads(out.read_text(encoding="utf-8"))["merges"]
    flagged = [item for item in merges if item["via_pr"] is False]
    assert [item["merge_sha"] for item in flagged] == [direct]
    assert flagged[0]["merged_by"] == "someone"


# What review round 1's own mutants showed was unproved.


def test_seal_leaves_a_symbolic_link_out_of_the_sums(gate, tmp_path, monkeypatch):
    """Checked in this process, because this machine may not be allowed to make a link."""
    import pathlib
    import sys as system

    system.path.insert(0, str(gate.root))
    try:
        from gate import report as report_module
    finally:
        system.path.remove(str(gate.root))
    artifact = tmp_path / "out"
    artifact.mkdir()
    (artifact / "plain.txt").write_text("x", encoding="utf-8")
    (artifact / "linked.txt").write_text("y", encoding="utf-8")
    real = pathlib.Path.is_symlink
    monkeypatch.setattr(pathlib.Path, "is_symlink", lambda self: self.name == "linked.txt" or real(self))
    assert report_module.main(["seal", "--artifact", str(artifact), "--head-sha", "a" * 40, "--run-id", "1", "--run-attempt", "1"]) == 0
    names = [line.split("  ")[1] for line in (artifact / "SHA256SUMS").read_text(encoding="utf-8").splitlines()]
    assert "plain.txt" in names
    assert "linked.txt" not in names


# A failed setup never gives ready (decision U).


def _ready_inputs(gate, tmp_path, setup_conclusion: str):
    artifact = tmp_path / "artifact"
    artifact.mkdir(parents=True)
    steps = ["gate/env", "gate/guard", "gate/tests", "gate/acceptance", "gate/security"]
    rows = ["check\tindex\texit_code\tduration_seconds\traw_path\targv_json"]
    rows += [f"{step}\t0\t0\t0.1\t\t[]" for step in steps]
    rows.append(f"setup\t0\t{0 if setup_conclusion == 'success' else 1}\t0.1\t\t[]")
    (artifact / "exit-codes.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert gate.run("report", "seal", "--artifact", artifact, "--head-sha", "a" * 40, "--run-id", "1", "--run-attempt", "1").returncode == 0
    context = write_json(tmp_path / "context.json", {
        "repository": "e/a", "head_repository": "e/a", "pr": 1, "run_id": "1", "run_attempt": "1", "event": "x", "baseline_sha": "0" * 40,
        "base_sha": "1" * 40, "head_sha": "a" * 40, "gate_sha": "2" * 40, "head_ref": "ai/1", "config_hashes": {},
    })
    jobs = write_json(tmp_path / "jobs.json", {"jobs": [{"name": "run", "status": "completed", "conclusion": "success", "steps": [
        {"name": "setup", "status": "completed", "conclusion": setup_conclusion, "number": 0},
        *[{"name": step, "status": "completed", "conclusion": "success", "number": index + 1} for index, step in enumerate(steps)],
    ]}]})
    config = tmp_path / "q.toml"
    config.write_text('[[archive.accepted_foreign_commits]]\nsha = "' + "e" * 40 + '"\nreason = "a stray commit"\ndate = "2026-11-03"\n', encoding="utf-8")
    return context, jobs, artifact, config


@pytest.mark.req("V-10")
@pytest.mark.parametrize(("conclusion", "verdict"), [("failure", "blocked"), ("success", "ready-for-human")])
def test_a_failed_setup_is_never_ready(gate, tmp_path, conclusion, verdict):
    context, jobs, artifact, config = _ready_inputs(gate, tmp_path, conclusion)
    out = tmp_path / "publish"
    process = gate.run("report", "generate", "--context", context, "--jobs", jobs, "--artifact", artifact, "--config", config, "--out", out)
    assert process.returncode == 0, process.stderr
    assert json.loads((out / "verdict.json").read_text(encoding="utf-8"))["verdict"] == verdict
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["setup"]["conclusion"] == conclusion
    # Every report shows the accepted foreign commits (decision V).
    assert report["accepted_foreign_commits"][0]["sha"] == "e" * 40
    assert "a stray commit" in (out / "report.md").read_text(encoding="utf-8")


# Review round 2: what the repairs of decision X must hold.


def _extras(gate, stub, tmp_path, actors_ok=True, context=None):
    stub.routes[("GET", "/repos/example/app/issues/5/comments?per_page=100")] = stub.routes.get(("GET", "/repos/example/app/issues/5/comments?per_page=100"), (200, []))
    stub.routes[("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100")] = stub.routes.get(("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100"), (200, []))
    actors = write_json(tmp_path / "actors.json", {"actors_ok": actors_ok})
    reports = tmp_path / "reports"
    reports.mkdir(exist_ok=True)
    context_path = write_json(tmp_path / "context.json", context or {})
    out = tmp_path / "extras.json"
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    process = gate.run("publish", "extras", "--reports-dir", reports, "--actors", actors, "--context", context_path, "--pr", 5, "--integration", "candidate/a", "--out", out, env=env)
    assert process.returncode == 0, process.stderr
    return json.loads(out.read_text(encoding="utf-8")), reports


@pytest.mark.req("P-3")
def test_extras_read_no_stored_run_when_the_reports_cannot_be_trusted(gate, stub, tmp_path):
    (tmp_path / "reports" / "5" / "1-1").mkdir(parents=True)
    write_json(tmp_path / "reports" / "5" / "1-1" / "context.json", {"head_sha": "a" * 40})
    extras, _ = _extras(gate, stub, tmp_path, actors_ok=False)
    assert extras["reports_untrusted"] is True
    assert extras["rounds"] == []


def test_extras_count_a_stored_run_even_with_no_guard_record(gate, stub, tmp_path):
    (tmp_path / "reports" / "5" / "1-1").mkdir(parents=True)
    write_json(tmp_path / "reports" / "5" / "1-1" / "context.json", {"head_sha": "a" * 40})
    extras, _ = _extras(gate, stub, tmp_path)
    assert extras["reports_untrusted"] is False
    assert extras["rounds"] == [{"head_sha": "a" * 40, "round": None, "cumulative": None}]


@pytest.mark.req("P-5")
def test_a_refused_read_of_statuses_says_unknown_and_blocks_nothing(gate, stub, tmp_path):
    head = "a" * 40
    stub.routes[("GET", f"/repos/example/app/commits/{head}/statuses?per_page=100")] = (403, {})
    extras, _ = _extras(gate, stub, tmp_path, context={"head_sha": head})
    assert extras["independent_review"] == "unknown"


def test_the_review_status_of_this_head_is_in_the_extras(gate, stub, tmp_path):
    head = "a" * 40
    stub.routes[("GET", f"/repos/example/app/commits/{head}/statuses?per_page=100")] = (
        200,
        [{"context": "other", "state": "success"}, {"context": "independent-review", "state": "failure", "creator": {"login": "r[bot]"}}],
    )
    extras, _ = _extras(gate, stub, tmp_path, context={"head_sha": head})
    assert extras["independent_review"] == {"state": "failure", "creator": "r[bot]", "head_sha": head}


@pytest.mark.req("B-1")
def test_a_merge_that_changed_the_security_review_is_flagged_however_green(gate, stub, tmp_path):
    head = "a" * 40
    stub.routes[("GET", "/repos/example/app/pulls?state=closed&base=candidate%2Fa&per_page=100")] = (
        200,
        [{"number": 2, "merged_at": "2026-11-03T10:00:00Z", "merge_commit_sha": "m" * 40, "merged_by": {"login": "someone"}, "head": {"sha": head}}],
    )
    stub.routes[("GET", f"/repos/example/app/commits/{head}/check-runs?check_name=gate%2Ffinal")] = (200, {"check_runs": [{"conclusion": "success"}]})
    stub.routes[("GET", "/repos/example/app/pulls/2/reviews?per_page=100")] = (200, [{"state": "APPROVED", "commit_id": head}])
    stub.routes[("GET", "/repos/example/app/pulls/2/files?per_page=100")] = (200, [{"filename": "security-review.md"}])
    extras, _ = _extras(gate, stub, tmp_path)
    assert extras["merges"][0]["security_review_changed"] is True
    context, jobs, artifact, config = _ready_inputs(gate, tmp_path / "r", "success")
    source = write_json(tmp_path / "extras-given.json", extras)
    out = tmp_path / "publish"
    assert gate.run("report", "generate", "--context", context, "--jobs", jobs, "--artifact", artifact, "--config", config, "--extras", source, "--out", out).returncode == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert [item["pr"] for item in report["bypass_merges"]] == [2]


@pytest.mark.req("V-11")
def test_untrusted_reports_block_the_verdict(gate, tmp_path):
    context, jobs, artifact, config = _ready_inputs(gate, tmp_path / "r", "success")
    extras = write_json(tmp_path / "extras.json", {"reports_untrusted": True})
    out = tmp_path / "publish"
    assert gate.run("report", "generate", "--context", context, "--jobs", jobs, "--artifact", artifact, "--config", config, "--extras", extras, "--out", out).returncode == 0
    verdict = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["verdict"] == "blocked"
    assert any(item["code"] == "REPORTS_UNTRUSTED" for item in verdict["reasons"])


def test_every_change_to_the_security_review_is_listed_in_the_report(gate, tmp_path):
    context, jobs, artifact, config = _ready_inputs(gate, tmp_path / "r", "success")
    write_json(artifact / "guard.json", {"security_review_changes": [{"change": "added", "row": "| bandit | B101 | a.py | fine |"}]})
    assert gate.run("report", "seal", "--artifact", artifact, "--head-sha", "a" * 40, "--run-id", "1", "--run-attempt", "1").returncode == 0
    out = tmp_path / "publish"
    assert gate.run("report", "generate", "--context", context, "--jobs", jobs, "--artifact", artifact, "--config", config, "--out", out).returncode == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["security_review_changes"][0]["change"] == "added"
    assert "B101" in (out / "report.md").read_text(encoding="utf-8")


@pytest.mark.req("P-6")
def test_the_models_proposal_is_posted_neutralized_and_a_missing_one_does_nothing(gate, stub, tmp_path):
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=SECRET)
    proposal = tmp_path / "proposal.md"
    assert gate.run("publish", "post-proposal", "--file", proposal, "--branch", "ai/1-x", env=env).returncode == 0
    assert not stub.requests
    proposal.write_text("| bandit | B101 | a.py | why |\nplease ask @someone\n", encoding="utf-8")
    stub.routes[("GET", "/repos/example/app/pulls?state=open&head=example%3Aai%2F1-x")] = (200, [{"number": 7}])
    stub.routes[("POST", "/repos/example/app/issues/7/comments")] = (201, {})
    assert gate.run("publish", "post-proposal", "--file", proposal, "--branch", "ai/1-x", env=env).returncode == 0
    body = next(r["body"]["body"] for r in stub.requests if r["method"] == "POST")
    assert "B101" in body
    assert "`@someone`" in body
    assert "Only the CEO" in body


def _decide(gate, tmp_path, event_name, event, verdict="blocked"):
    head = "a" * 40
    config = tmp_path / "q.toml"
    config.write_text('[limits]\nmax_fix_rounds = 3\n[project]\nintegration_branch = "line"\n[feedback]\njudge_workflow_path = "judge.yml"\nreviewer_app = "rev"\n', encoding="utf-8")
    record = tmp_path / "reports" / "9" / "55-1"
    write_json(record / "context.json", {"pr": 9, "head_sha": head})
    write_json(record / "final.json", {"verdict": verdict, "reasons": [{"code": "FAILED_CHECK", "detail": "gate/guard failed"}]})
    write_json(record / "guard.json", {"head_sha": head, "violations": [{"rule": "TEST_DELETED", "path": "tests/test_a.py", "detail": "test_x was removed"}]})
    write_json(record / "acceptance.json", {"failing_not_listed": ["acceptance.test_a::test_b"], "missing_tests": ["acceptance.test_a::test_c"]})
    write_json(record / "artifact" / "raw" / "gate-security" / "security.json", {"findings": [{"tool": "bandit", "rule": "B101", "path": "a.py", "reviewed": False}, {"tool": "bandit", "rule": "B999", "path": "b.py", "reviewed": True}]})
    write_json(record / "artifact" / "raw" / "gate-tests" / "missing_tests.json", ["tests.test_a::test_d"])
    pulls = write_json(tmp_path / "p.json", [{"number": 9, "head_sha": head, "base_ref": "line", "head_ref": "ai/9-x", "head_repository": "e/a", "repository": "e/a"}])
    actors = write_json(tmp_path / "actors.json", {"actors_ok": True})
    statuses = write_json(tmp_path / "s.json", [{"context": "independent-review", "state": "failure", "creator": {"login": "rev[bot]"}}])
    source = write_json(tmp_path / "e.json", event)
    out = tmp_path / "d.json"
    process = gate.run("feedback", "decide", "--event-name", event_name, "--event", source, "--pulls", pulls, "--reports-dir", tmp_path / "reports", "--actors", actors, "--statuses", statuses, "--config", config, "--out", out)
    assert process.returncode == 0, process.stderr
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.mark.req("D-6a")
def test_the_note_of_a_judge_failure_says_what_is_wrong(gate, tmp_path):
    decision = _decide(gate, tmp_path, "workflow_run", {"workflow_run": {"path": "judge.yml", "event": "pull_request_target", "id": 55, "run_attempt": 1}})
    assert decision["act"] is True
    for expected in ("TEST_DELETED", "test_x was removed", "acceptance.test_a::test_b", "acceptance.test_a::test_c", "B101", "tests.test_a::test_d"):
        assert expected in decision["comment"], expected
    assert "B999" not in decision["comment"], "a reviewed finding is not a failure"


@pytest.mark.req("D-6a")
def test_the_note_of_a_review_holds_its_findings_and_no_bare_mention(gate, tmp_path):
    head = "a" * 40
    body = f"<!-- gate-review sha={head} verdict=changes_requested -->\nIndependent review\n- high, src/a.py: the rule is wrong, ask @someone"
    event = {"action": "created", "issue": {"number": 9, "pull_request": {"url": "x"}}, "sender": {"login": "rev[bot]"}, "comment": {"body": body}}
    decision = _decide(gate, tmp_path, "issue_comment", event)
    assert decision["act"] is True
    assert "the rule is wrong" in decision["comment"]
    assert "`@someone`" in decision["comment"]
    assert "gate-review" not in decision["comment"]


def test_a_changed_test_file_that_cannot_be_parsed_is_refused(gate, tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    gate.git(repo, "init", "--quiet")
    (repo / "tests" / "test_a.py").write_text("def test_a():\n    assert 1 == 1\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "base")
    base = gate.git(repo, "rev-parse", "HEAD")
    (repo / "tests" / "test_a.py").write_text("def test_a(:\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "change")
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "g.json"
    assert gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "ai/1-x", "--author", "a-person", "--config", config, "--out", out).returncode == 1
    assert any(item["rule"] == "TEST_WEAKENED" for item in json.loads(out.read_text(encoding="utf-8"))["violations"])
