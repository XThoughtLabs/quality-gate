"""Traps of GitHub Actions that the workflows must avoid. Checked from the YAML."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.req("Y-3", "Y-5", "Y-7", "Y-14", "Y-15")

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / f"{name}.yml").read_text(encoding="utf-8"))


def all_workflows() -> list[tuple[str, dict]]:
    return [(path.stem, load(path.stem)) for path in sorted(WORKFLOWS.glob("*.yml"))]


def test_the_job_context_is_used_only_where_github_allows_it():
    """job.* is available in a step's env and with, and not in a job's env."""
    for name, workflow in all_workflows():
        for job_name, job in workflow["jobs"].items():
            for key, value in (job.get("env") or {}).items():
                assert "job." not in str(value), f"{name}/{job_name} env {key}"


def test_steps_after_a_cancellation_still_run_in_publish_and_archive():
    """A step's default condition is success(), which is false once a run is cancelled."""
    jobs = load("judge")["jobs"]
    for job_name in ("publish", "archive"):
        for step in jobs[job_name]["steps"]:
            assert step.get("if") == "${{ always() }}", f"{job_name}: {step.get('name')}"


def test_the_run_job_uploads_what_it_has_after_a_cancellation():
    steps = load("judge")["jobs"]["run"]["steps"]
    names = [step.get("name") for step in steps]
    for name in ("Seal the evidence", "Upload the evidence"):
        assert steps[names.index(name)]["if"] == "${{ always() }}"
    assert names.index("Seal the evidence") < names.index("Upload the evidence")


def test_no_pr_code_runs_before_the_guard():
    steps = load("judge")["jobs"]["run"]["steps"]
    names = [step.get("name") for step in steps]
    guard = names.index("gate/guard")
    for name in ("setup", "gate/tests", "gate/acceptance", "gate/security"):
        assert names.index(name) > guard


def test_a_missing_secret_reaches_gate_env():
    """A required secret would stop the run before gate/env could name what is broken."""
    for name in ("executor", "spec-tests", "feedback"):
        secrets = load(name)[True]["workflow_call"]["secrets"]
        for secret, options in secrets.items():
            assert options["required"] is False, f"{name}: {secret}"


def test_the_verdict_cannot_be_replaced_by_another_jobs_artifact():
    jobs = load("judge")["jobs"]
    assert "verdict-sha256" in jobs["publish"]["outputs"]
    assert "needs.publish.outputs.verdict-sha256" in jobs["archive"]["env"]["GATE_EXPECT_VERDICT"]
    script = next(step["run"] for step in jobs["archive"]["steps"] if step.get("name") == "Store the evidence and post the final verdict")
    assert "--expect-verdict-sha256" in script


def test_the_archive_writes_to_github_only_through_the_api():
    """Only commits made through the API are signed by GitHub."""
    jobs = load("judge")["jobs"]
    script = next(step["run"] for step in jobs["archive"]["steps"] if step.get("name") == "Store the evidence and post the final verdict")
    assert script.count("gate.archive") == 2
    assert script.count("--api-repo") == 2
    # Each of them reads the recovery list.
    for line in script.splitlines():
        if "gate.archive" in line:
            assert '--config "$GATE_CONFIG"' in line, line
    assert "--remote" not in script


def test_a_fix_rounds_bots_are_named_exactly():
    fix = load("feedback")["jobs"]["fix"]
    assert fix["with"]["allowed-bots"] == "${{ needs.decide.outputs.allowed-bots }}"
    steps = load("executor")["jobs"]["executor"]["steps"]
    action = next(step for step in steps if str(step.get("uses", "")).startswith("anthropics/claude-code-action@"))
    assert action["with"]["allowed_bots"] == "${{ inputs.allowed-bots }}"


def test_the_archive_job_installs_nothing():
    """Nothing it installs can lose the evidence."""
    for step in load("judge")["jobs"]["archive"]["steps"]:
        assert "pip install" not in step.get("run", "")


def test_the_prompt_never_comes_from_the_prs_branch():
    for name, job_name in (("executor", "executor"), ("spec-tests", "author")):
        steps = load(name)["jobs"][job_name]["steps"]
        trusted = next(step for step in steps if step.get("with", {}).get("path") == ".trusted")
        assert trusted["with"]["ref"] == "${{ github.event.repository.default_branch }}"
        scripts = "\n".join(step.get("run", "") for step in load(name)["jobs"][job_name]["steps"])
        assert '--template "$RUNNER_TEMP/trusted/$GATE_PROMPT_FILE"' in scripts


def test_the_model_holds_no_github_cli_and_its_tools_lose_the_tokens():
    for name, job_name in (("executor", "executor"), ("spec-tests", "author")):
        steps = load(name)["jobs"][job_name]["steps"]
        action = next(step for step in steps if str(step.get("uses", "")).startswith("anthropics/claude-code-action@"))
        assert action["env"]["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
        assert "GH_TOKEN" not in action["env"]
        assert "Bash(gh" not in action["with"]["claude_args"]
        names = [step.get("name") for step in steps]
        assert names.index("Open the PR for what was pushed") > steps.index(action)


def test_a_fix_is_one_at_a_time_and_stops_when_the_head_moved():
    fix = load("feedback")["jobs"]["fix"]
    assert fix["concurrency"]["cancel-in-progress"] is False
    assert fix["with"]["expected-head"] == "${{ needs.decide.outputs.head-sha }}"
    steps = load("executor")["jobs"]["executor"]["steps"]
    names = [step.get("name") for step in steps]
    index = names.index("Stop if the PR has moved since the decision")
    assert index < names.index("Run the executor")
    # A refusal must stop the job: no condition that turns it off, nothing that swallows it.
    assert steps[index]["if"] == "${{ inputs.expected-head != '' }}"
    assert steps[index]["run"] == 'python -P -m gate.publish head-check --pr "$GATE_PR" --sha "$GATE_EXPECTED_HEAD"'
    assert not steps[index].get("continue-on-error")


def test_the_trusted_copy_leaves_the_working_folder_before_the_checkout_that_wipes_it():
    for name, job_name in (("executor", "executor"), ("spec-tests", "author")):
        steps = load(name)["jobs"][job_name]["steps"]
        names = [step.get("name") for step in steps]
        move = names.index("Move the gate and the prompt out of the working folder")
        assert 'mv .trusted "$RUNNER_TEMP/trusted"' in steps[move]["run"]
        assert 'mv .gate "$RUNNER_TEMP/gate"' in steps[move]["run"]
        assert move < names.index("Get the repository")


def test_the_spec_test_author_never_has_the_default_branchs_code_beside_it():
    steps = load("spec-tests")["jobs"]["author"]["steps"]
    names = [step.get("name") for step in steps]
    remove = names.index("Remove the default branch's copy")
    assert steps[remove]["run"] == 'rm -rf "$RUNNER_TEMP/trusted"'
    assert names.index("Build the prompt") < remove < names.index("Run the spec-test author")


def test_stored_runs_are_fetched_only_after_the_check():
    run_steps = load("judge")["jobs"]["run"]["steps"]
    script = next(step["run"] for step in run_steps if step.get("name") == "Get the stored runs")
    lines = [line.strip() for line in script.splitlines()]
    check = next(index for index, line in enumerate(lines) if "gate.archive check-actors" in line)
    fetch = next(index for index, line in enumerate(lines) if "get_stored_runs.sh" in line)
    # bash -e stops at a failed check, so the folder stays absent and gate/guard stops.
    assert check < fetch
    assert "|| true" not in script
    names = [step.get("name") for step in run_steps]
    assert names.index("Get the stored runs") < names.index("gate/guard")

    publish_steps = load("judge")["jobs"]["publish"]["steps"]
    script = next(step["run"] for step in publish_steps if step.get("name") == "Get the stored runs")
    assert re.search(r"if .*gate\.archive check-actors.*; then", script)
    generate = next(step["run"] for step in publish_steps if step.get("name") == "Generate the report")
    assert "--actors actors.json" in generate


def test_the_prs_branch_comes_from_the_working_tree():
    for name, job_name in (("executor", "executor"), ("spec-tests", "author")):
        steps = load(name)["jobs"][job_name]["steps"]
        script = next(step["run"] for step in steps if step.get("name") == "Open the PR for what was pushed")
        assert '--branch "$(git branch --show-current)"' in script


def run_the_review_step(tmp_path: Path, head_ref: str, trusted_review: str | None):
    """Run the workflow's own script, in a folder laid out as on the runner."""
    step = next(item for item in load("judge")["jobs"]["run"]["steps"] if item.get("name") == "Take the acceptance tests and the security review from the default branch")
    pr_dir = tmp_path / "pr"
    pr_dir.mkdir()
    (pr_dir / "security-review.md").write_text("the PR's own\n", encoding="utf-8")
    trusted = tmp_path / ".trusted"
    trusted.mkdir()
    if trusted_review is not None:
        (trusted / "security-review.md").write_text(trusted_review, encoding="utf-8")
    github_env = tmp_path / "github-env"
    env = {**os.environ, "GATE_PR_DIR": pr_dir.as_posix(), "GATE_HEAD_REF": head_ref, "GITHUB_ENV": github_env.as_posix()}
    process = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)
    assert process.returncode == 0, process.stderr
    return pr_dir / "security-review.md"


def test_the_security_review_used_is_the_default_branchs_copy(tmp_path):
    review = run_the_review_step(tmp_path, "ai/1-x", "the default branch's\n")
    assert review.read_text(encoding="utf-8") == "the default branch's\n"


def test_a_prs_own_security_review_is_removed_when_the_default_branch_has_none(tmp_path):
    assert not run_the_review_step(tmp_path, "ai/1-x", None).exists()


def test_the_security_review_is_the_default_branchs():
    steps = load("judge")["jobs"]["run"]["steps"]
    names = [step.get("name") for step in steps]
    index = names.index("Take the acceptance tests and the security review from the default branch")
    assert names.index("gate/guard") < index < names.index("setup")
    assert "security-review.md" in steps[index]["run"]


def test_status_is_no_longer_how_a_fix_round_starts():
    text = (WORKFLOWS / "feedback.yml").read_text(encoding="utf-8")
    assert "issue_comment" in text
    assert "statuses: write" not in text
    assert "repository_dispatch" not in text


def test_gate_scripts_are_run_safely():
    """Every call of the gate from a run step uses -P, so that a checkout cannot shadow it."""
    pattern = re.compile(r"-m gate\.")
    for name, workflow in all_workflows():
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                script = step.get("run", "")
                for line in script.splitlines():
                    if pattern.search(line):
                        assert "-P -m gate." in line, f"{name}/{job_name}: {line}"


def test_the_gate_is_taken_at_its_own_commit():
    for name, workflow in all_workflows():
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                if step.get("with", {}).get("path") == ".gate":
                    assert step["with"]["ref"] == "${{ job.workflow_sha }}", f"{name}/{job_name}"
                    assert step["with"]["repository"] == "${{ job.workflow_repository }}", f"{name}/{job_name}"
                    assert step["with"]["persist-credentials"] is False, f"{name}/{job_name}"
