"""finalize.yml and the archive job's wiring (CONTRACTS.md FN-3, FN-6, Y-23, Y-24), read as YAML from GATE_ROOT."""
from __future__ import annotations

import re

import pytest
import yaml

from gatekit import GATE_ROOT

WORKFLOWS = GATE_ROOT / ".github" / "workflows"
SHA40 = re.compile(r"[0-9a-f]{40}")


def load(name: str) -> dict:
    path = WORKFLOWS / f"{name}.yml"
    assert path.exists(), f"{path} must exist (CONTRACTS.md FN-3, Y-23)"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} is not a YAML mapping"
    return data


def text(name: str) -> str:
    path = WORKFLOWS / f"{name}.yml"
    assert path.exists(), f"{path} must exist (CONTRACTS.md FN-3, Y-23)"
    return path.read_text(encoding="utf-8")


def triggers(wf: dict) -> dict:
    on = wf["on"] if "on" in wf else wf.get(True)   # PyYAML reads `on` as True
    assert on is not None, "no `on:`"
    return {on: None} if isinstance(on, str) else on


def the_job(wf: dict) -> tuple[str, dict]:
    jobs = wf.get("jobs") or {}
    assert len(jobs) == 1, f"finalize.yml has one job, found {list(jobs)}"
    return next(iter(jobs.items()))


def step_text(step: dict) -> str:
    return yaml.safe_dump(step, sort_keys=True)


def checkouts(job: dict) -> list[dict]:
    return [s for s in job.get("steps") or [] if str(s.get("uses", "")).startswith("actions/checkout@")]


# ----------------------------------------------------------------------------- FN-3 / Y-23


@pytest.mark.req("FN-3", "Y-23")
def test_fn3_finalize_is_a_reusable_workflow_only_with_a_config_path_input():
    on = triggers(load("finalize"))
    assert set(on) == {"workflow_call"}, f"finalize.yml must be `on: workflow_call` and nothing else, found {set(on)}"
    inputs = (on["workflow_call"] or {}).get("inputs") or {}
    assert "config-path" in inputs, f"a config-path input, found {list(inputs)}"


@pytest.mark.req("FN-3", "Y-23")
def test_fn3_the_job_runs_on_ubuntu_24_04_only_for_an_independent_review_status():
    job_id, job = the_job(load("finalize"))
    assert job.get("runs-on") == "ubuntu-24.04"
    condition = str(job.get("if", ""))
    assert "independent-review" in condition and "github.event.context" in condition, condition
    assert "status" in condition and "github.event_name" in condition, condition


@pytest.mark.req("FN-3", "Y-23")
def test_fn3_it_checks_out_only_the_gate_at_its_own_commit_and_the_default_branchs_configuration():
    job_id, job = the_job(load("finalize"))
    found = checkouts(job)
    assert len(found) == 2, f"two checkouts: the gate and the configuration, found {len(found)}"
    refs = []
    for step in found:
        with_ = step.get("with") or {}
        assert with_.get("persist-credentials") is False, f"persist-credentials: false on every checkout: {step}"
        refs.append(str(with_.get("ref", "")))
    assert any("job.workflow_sha" in ref for ref in refs), f"the gate at job.workflow_sha: {refs}"
    gate = next(s for s in found if "job.workflow_sha" in str((s.get("with") or {}).get("ref", "")))
    assert "job.workflow_repository" in str(gate["with"].get("repository", ""))
    config = next(s for s in found if s is not gate)
    assert "ref" not in (config.get("with") or {}), "the configuration is the default branch's: no ref"
    assert "repository" not in (config.get("with") or {}), "and from the calling repository itself"


@pytest.mark.req("FN-3", "Y-23")
def test_fn3_no_step_names_the_events_sha_or_a_pr_ref_and_none_runs_pr_code():
    job_id, job = the_job(load("finalize"))
    for step in job.get("steps") or []:
        body = step_text(step)
        for word in ("github.event.sha", "github.event.pull_request", "github.head_ref", "refs/pull", "head.sha"):
            assert word not in body, f"a step names {word}: {step.get('name')}"
    assert "pip install" not in text("finalize") and "pip3 install" not in text("finalize"), "finalize installs nothing"


@pytest.mark.req("FN-3", "FN-4", "Y-23")
def test_fn4_the_stored_runs_are_fetched_only_after_check_actors_then_finalize_runs():
    job_id, job = the_job(load("finalize"))
    scripts = [str(s.get("run", "")) for s in job.get("steps") or []]
    joined = "\n".join(scripts)
    actors = joined.find("gate.archive check-actors")
    stored = joined.find("get_stored_runs.sh")
    final = joined.find("gate.publish finalize")
    assert actors != -1 and stored != -1 and final != -1, "check-actors, get_stored_runs.sh and gate.publish finalize all run"
    assert actors < stored < final, "the check of W-12 and W-14 comes first (decision V.4), then the read, then finalize"
    line = next(s for s in scripts if "gate.publish finalize" in s)
    for option in ("--event", "--config", "--reports-dir", "--actors", "--out"):
        assert option in line, f"finalize is given {option}"
    assert "GITHUB_EVENT_PATH" in line, "the event comes from the runner's event file"
    block = next(s for s in scripts if "get_stored_runs.sh" in s)
    assert re.search(r"if\s+.*gate\.archive check-actors", block, re.S) or "&&" in block, \
        "the stored runs are fetched only when check-actors succeeded"


@pytest.mark.req("FN-3", "Y-8", "Y-23")
def test_fn3_no_run_script_holds_event_or_inputs_expressions():
    job_id, job = the_job(load("finalize"))
    for step in job.get("steps") or []:
        script = str(step.get("run", ""))
        assert "${{ github.event" not in script and "${{ inputs." not in script, f"{step.get('name')}: {script}"


@pytest.mark.req("Y-2", "Y-23")
def test_y23_every_action_in_finalize_is_pinned_and_listed_in_actions_lock():
    lock = (GATE_ROOT / "ACTIONS-LOCK.md").read_text(encoding="utf-8").splitlines()
    job_id, job = the_job(load("finalize"))
    uses = [str(s["uses"]) for s in job.get("steps") or [] if "uses" in s]
    assert uses, "finalize uses actions (checkout, setup-python)"
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), f"{ref} is not owner/name@<40 hex>"
        name, _, sha = ref.partition("@")
        assert any(sha in line and name in line for line in lock), f"{ref} is not in ACTIONS-LOCK.md"


# ----------------------------------------------------------------------------- FN-6


@pytest.mark.req("FN-6", "Y-23")
def test_fn6_the_job_has_exactly_checks_write_contents_read_pull_requests_read_and_the_workflow_nothing():
    wf = load("finalize")
    assert wf.get("permissions") == {}, f"the workflow's own block is empty, found {wf.get('permissions')!r}"
    job_id, job = the_job(wf)
    assert job.get("permissions") == {"checks": "write", "contents": "read", "pull-requests": "read"}, job.get("permissions")


@pytest.mark.req("FN-6", "Y-4")
def test_fn6_no_contents_write_no_actions_write_and_no_write_all_anywhere():
    body = text("finalize")
    assert not re.search(r"contents:\s*write", body)
    assert not re.search(r"actions:\s*write", body)
    assert "write-all" not in body


@pytest.mark.req("FN-6")
def test_fn6_no_secret_input_and_no_secret_reference():
    wf = load("finalize")
    call = triggers(wf)["workflow_call"] or {}
    assert "secrets" not in call, "finalize declares no secrets"
    assert "secrets." not in text("finalize"), "and references none"


@pytest.mark.req("FN-6")
def test_fn6_concurrency_per_sha_without_cancelling_a_run_in_progress():
    job_id, job = the_job(load("finalize"))
    conc = job.get("concurrency")
    assert isinstance(conc, dict), f"a concurrency block with a group and cancel-in-progress, found {conc!r}"
    assert "github.event.sha" in str(conc.get("group")), conc
    assert conc.get("cancel-in-progress") is False, conc


# ----------------------------------------------------------------------------- Y-24, the archive job's wiring (FN-2, FN-8)


def archive_script() -> str:
    steps = load("judge")["jobs"]["archive"]["steps"]
    found = [str(s.get("run", "")) for s in steps if "gate.report final" in str(s.get("run", ""))]
    assert found, "the archive job runs gate.report final"
    return found[0]


@pytest.mark.req("Y-24", "FN-2", "FN-8")
def test_y24_the_archive_job_reads_the_facts_for_the_head_after_the_store_and_before_the_final_verdict():
    script = archive_script()
    store = script.find("gate.archive store")
    facts = script.find("gate.publish final-facts")
    final = script.find("gate.report final")
    assert facts != -1, "gate.publish final-facts runs in the archive job"
    assert store < facts < final, "after the store, before the first final"
    line = next(l for l in script.splitlines() if "gate.publish final-facts" in l)
    assert '--head-sha "$GATE_HEAD_SHA"' in line and "--config" in line and "--out" in line, line


@pytest.mark.req("Y-24", "FN-2", "FN-8")
def test_y24_both_calls_of_gate_report_final_take_the_facts():
    lines = [l for l in archive_script().splitlines() if "gate.report final" in l]
    assert len(lines) == 2, f"two calls of gate.report final, found {len(lines)}"
    for line in lines:
        assert "--facts" in line, line
