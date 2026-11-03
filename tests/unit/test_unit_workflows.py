"""Traps of GitHub Actions that the workflows must avoid. Checked from the YAML."""

from __future__ import annotations

import re
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
    assert "--remote" not in script


def test_a_fix_rounds_bots_are_named_exactly():
    fix = load("feedback")["jobs"]["fix"]
    assert fix["with"]["allowed-bots"] == "${{ needs.decide.outputs.allowed-bots }}"
    steps = load("executor")["jobs"]["executor"]["steps"]
    action = next(step for step in steps if str(step.get("uses", "")).startswith("anthropics/claude-code-action@"))
    assert action["with"]["allowed_bots"] == "${{ inputs.allowed-bots }}"


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
