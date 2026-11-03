"""Workflows (CONTRACTS.md section 12), read as YAML from GATE_ROOT/.github/workflows and ACTIONS-LOCK.md."""
from __future__ import annotations

import re

import pytest
import yaml

from gatekit import GATE_ROOT

WORKFLOWS = ["judge", "executor", "spec-tests", "feedback"]       # the four reusable workflows (Y-1)
ALL_WORKFLOWS = WORKFLOWS + ["self-test"]                           # self-test.yml is not workflow_call (Y-13)
MANDATORY_STEPS = ["gate/env", "gate/guard", "gate/tests", "gate/acceptance", "gate/security"]
SHA40 = re.compile(r"[0-9a-f]{40}")


def load(name: str) -> dict:
    path = GATE_ROOT / ".github" / "workflows" / f"{name}.yml"
    assert path.exists(), f"{path} must exist (CONTRACTS.md section 12)"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path} is not a YAML mapping"
    return data


def text_of(name: str) -> str:
    return (GATE_ROOT / ".github" / "workflows" / f"{name}.yml").read_text(encoding="utf-8")


def triggers(wf: dict):
    # PyYAML (YAML 1.1) reads the key `on` as the boolean True.
    on = wf["on"] if "on" in wf else wf.get(True)
    assert on is not None, "no `on:` in the workflow"
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {t: None for t in on}
    return on


def jobs(wf: dict) -> dict:
    assert isinstance(wf.get("jobs"), dict) and wf["jobs"], "a workflow needs jobs"
    return wf["jobs"]


def steps(job: dict) -> list:
    return job.get("steps") or []


def expr(value) -> str:
    s = str(value).strip()
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", s)
    return (m.group(1) if m else s).strip()


def walk(node):
    """Every value in a parsed YAML tree, with the mapping keys that lead to it."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield (k,), v
            for path, sub in walk(v):
                yield (k, *path), sub
    elif isinstance(node, list):
        for item in node:
            for path, sub in walk(item):
                yield path, sub


def all_uses():
    found = []
    for name in ALL_WORKFLOWS:
        for job_id, job in jobs(load(name)).items():
            if "uses" in job:
                found.append((name, job_id, str(job["uses"])))
            for st in steps(job):
                if "uses" in st:
                    found.append((name, job_id, str(st["uses"])))
    return found


def strings(node):
    for _, v in walk(node):
        if isinstance(v, str):
            yield v


def permission_blocks(wf: dict):
    blocks = []
    if "permissions" in wf:
        blocks.append(("workflow", wf["permissions"]))
    for job_id, job in jobs(wf).items():
        if "permissions" in job:
            blocks.append((job_id, job["permissions"]))
    return blocks


# ----------------------------------------------------------------------------- Y-1


@pytest.mark.req("Y-1")
@pytest.mark.parametrize("name", WORKFLOWS)
def test_y1_each_workflow_is_on_workflow_call_only(name):
    assert set(triggers(load(name))) == {"workflow_call"}, f"{name}.yml must be `on: workflow_call` and nothing else"


@pytest.mark.req("Y-1")
@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_y1_runners_are_exactly_ubuntu_24_04(name):
    found = 0
    for job_id, job in jobs(load(name)).items():
        if "uses" in job:
            continue  # a job that calls a reusable workflow has no runner of its own
        assert job.get("runs-on") == "ubuntu-24.04", f"{name}.yml job {job_id}: runs-on is {job.get('runs-on')!r}"
        found += 1
    assert found >= 1


# ----------------------------------------------------------------------------- Y-2


@pytest.mark.req("Y-2")
def test_y2_every_action_is_pinned_to_a_full_sha():
    uses = all_uses()
    actions = [u for u in uses if not u[2].startswith("./") and not u[2].startswith("docker://")]
    assert len(actions) >= 4, f"expected the workflows to use several actions, found {actions}"
    for name, job_id, ref in actions:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}", ref), f"{name}.yml {job_id}: {ref} is not owner/name@<40 hex>"


@pytest.mark.req("Y-2")
def test_y2_every_action_is_listed_in_actions_lock():
    lock = GATE_ROOT / "ACTIONS-LOCK.md"
    assert lock.exists(), "ACTIONS-LOCK.md must exist"
    lines = lock.read_text(encoding="utf-8").splitlines()
    actions = {u[2] for u in all_uses() if not u[2].startswith("./") and not u[2].startswith("docker://")}
    assert actions
    for ref in sorted(actions):
        name, _, sha = ref.partition("@")
        base = name  # owner/name or owner/name/path
        assert any(sha in line and base.split("/")[0] + "/" + base.split("/")[1] in line for line in lines), \
            f"{ref} is not in ACTIONS-LOCK.md (a line holding both the action and its SHA)"


# ----------------------------------------------------------------------------- Y-3 and Y-4


@pytest.mark.req("Y-3")
def test_y3_judge_permissions_are_exactly_the_documented_ones():
    js = jobs(load("judge"))
    assert {"run", "publish", "archive"} <= set(js)
    assert js["run"].get("permissions") == {"contents": "read"}
    assert js["publish"].get("permissions") == {"checks": "write", "pull-requests": "write", "actions": "read", "contents": "read"}
    assert js["archive"].get("permissions") == {"contents": "write", "checks": "write"}


@pytest.mark.req("Y-4")
@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_y4_no_actions_write_and_no_write_all(name):
    wf = load(name)
    for where, perms in permission_blocks(wf):
        assert perms != "write-all", f"{name}.yml {where}: permissions: write-all"
        if isinstance(perms, dict):
            assert perms.get("actions") != "write", f"{name}.yml {where}: actions: write"
    for path, value in walk(wf):
        if path and path[-1] == "permissions":
            assert value != "write-all"


@pytest.mark.req("Y-4")
def test_y4_control_the_judge_does_declare_permissions_so_the_check_is_not_vacuous():
    assert len(permission_blocks(load("judge"))) >= 3


# ----------------------------------------------------------------------------- Y-5


def always(value):
    return expr(value) == "always()"


@pytest.mark.req("Y-5")
def test_y5_publish_needs_run_and_always_runs():
    publish = jobs(load("judge"))["publish"]
    needs = publish.get("needs")
    assert (needs if isinstance(needs, list) else [needs]) == ["run"]
    assert always(publish.get("if")), f"publish: if is {publish.get('if')!r}"


@pytest.mark.req("Y-5")
def test_y5_archive_needs_run_and_publish_and_always_runs():
    archive = jobs(load("judge"))["archive"]
    needs = archive.get("needs")
    assert sorted(needs if isinstance(needs, list) else [needs]) == ["publish", "run"]
    assert always(archive.get("if")), f"archive: if is {archive.get('if')!r}"


# ----------------------------------------------------------------------------- Y-6


@pytest.mark.req("Y-6")
def test_y6_judge_uses_no_secrets_and_declares_no_secrets_input():
    wf = load("judge")
    call = triggers(wf)["workflow_call"] or {}
    assert "secrets" not in call, "judge.yml must not declare a secrets: input"
    for path, _ in walk(wf):
        assert path[-1] != "secrets", f"a `secrets` key at {'.'.join(map(str, path))}"
    for s in strings(wf):
        assert not re.search(r"\bsecrets\.", s), f"judge.yml refers to secrets.*: {s!r}"


# ----------------------------------------------------------------------------- Y-7


def run_steps(wf=None):
    return steps(jobs(wf or load("judge"))["run"])


def check_steps(wf=None):
    return [st for st in run_steps(wf) if str(st.get("name", "")).startswith(("gate/", "diag/"))]


@pytest.mark.req("Y-7")
def test_y7_the_pr_checkout_does_not_persist_credentials():
    checkouts = [st for st in run_steps() if str(st.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts, "the run job checks out the PR head with actions/checkout"
    for st in checkouts:
        assert st.get("with", {}).get("persist-credentials") in (False, "false"), f"checkout step: {st}"


@pytest.mark.req("Y-7")
def test_y7_every_mandatory_check_is_its_own_step_named_after_its_id():
    names = [st.get("name") for st in run_steps()]
    for cid in MANDATORY_STEPS:
        assert names.count(cid) == 1, f"the run job needs exactly one step named {cid!r}; step names: {names}"


@pytest.mark.req("Y-7")
def test_y7_every_check_step_runs_unless_cancelled_and_never_continues_on_error():
    cs = check_steps()
    assert len(cs) >= 5
    for st in cs:
        assert expr(st.get("if", "")) == "!cancelled()", f"step {st['name']}: if is {st.get('if')!r}"
        assert "continue-on-error" not in st, f"step {st['name']} must not have continue-on-error"


@pytest.mark.req("Y-7")
def test_y7_env_and_guard_come_before_any_step_that_runs_pr_code():
    names = [st.get("name") for st in run_steps()]
    first_pr_code = min(names.index(n) for n in names if n and str(n).startswith(("gate/", "diag/"))
                        and n not in ("gate/env", "gate/guard"))
    assert names.index("gate/env") < first_pr_code and names.index("gate/guard") < first_pr_code


@pytest.mark.req("Y-7")
def test_y7_the_run_job_does_not_run_for_a_fork():
    cond = str(jobs(load("judge"))["run"].get("if", ""))
    assert cond.strip(), "the run job needs an `if:` that keeps it from running for a fork"
    assert re.search(r"fork|head[._]repo|head_repo|full_name|repository", cond, re.I), \
        f"the condition does not look at where the head comes from: {cond!r}"


# ----------------------------------------------------------------------------- Y-8


@pytest.mark.req("Y-8")
@pytest.mark.parametrize("name", ALL_WORKFLOWS)
def test_y8_no_run_script_holds_event_or_inputs_expressions(name):
    wf = load(name)
    scripts = [st["run"] for job in jobs(wf).values() for st in steps(job) if "run" in st]
    for script in scripts:
        assert not re.search(r"\$\{\{\s*github\.event", script), f"{name}.yml: github.event in a run: script"
        assert not re.search(r"\$\{\{\s*inputs\.", script), f"{name}.yml: inputs.* in a run: script"


@pytest.mark.req("Y-8")
def test_y8_control_the_judge_does_have_run_scripts():
    assert [st for st in run_steps() if "run" in st]


# ----------------------------------------------------------------------------- Y-9


@pytest.mark.req("Y-9")
def test_y9_artifact_upload_keeps_30_days_and_runs_always():
    uploads = [st for job in jobs(load("judge")).values() for st in steps(job)
               if str(st.get("uses", "")).startswith("actions/upload-artifact@")]
    assert uploads, "the judge uploads the run's artifact"
    for st in uploads:
        assert st.get("with", {}).get("retention-days") == 30, st
        assert expr(st.get("if", "")) == "always()", st


# ----------------------------------------------------------------------------- Y-10


@pytest.mark.req("Y-10")
def test_y10_executor_token_comes_from_the_app_and_goes_to_claude_code_action():
    wf = load("executor")
    found = False
    for job_id, job in jobs(wf).items():
        ss = steps(job)
        mint = [s for s in ss if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]
        claude = [s for s in ss if "claude-code-action@" in str(s.get("uses", ""))]
        if not claude:
            continue
        found = True
        assert mint, "the app token must be minted by actions/create-github-app-token in the same job"
        token_id = mint[0].get("id")
        assert token_id, "the token step needs an id so that its output can be used"
        github_token = str(claude[0].get("with", {}).get("github_token", ""))
        assert f"steps.{token_id}.outputs.token" in github_token, f"github_token is {github_token!r}"
        assert "--max-turns" in str(claude[0].get("with", {}).get("claude_args", ""))
        assert job.get("timeout-minutes") is not None, "the executor job needs timeout-minutes"
    assert found, "executor.yml must run anthropics/claude-code-action"


# ----------------------------------------------------------------------------- Y-11


@pytest.mark.req("Y-11")
def test_y11_spec_tests_deny_reading_the_listed_paths_and_remove_them_before_the_model_starts():
    # Only the workflow's text can be checked from outside: the generated settings are built at run time.
    wf = load("spec-tests")
    txt = text_of("spec-tests")
    assert "deny_read" in txt, "the settings must be built from spec_tests.deny_read"
    assert "permissions" in txt and "deny" in txt, "the action's settings must hold permissions.deny"
    assert re.search(r"\bRead\b", txt), "the deny list must cover the Read tool"
    claude_jobs = [j for j in jobs(wf).values() if any("claude-code-action@" in str(s.get("uses", "")) for s in steps(j))]
    assert claude_jobs, "spec-tests.yml must run claude-code-action"
    ss = steps(claude_jobs[0])
    idx = next(i for i, s in enumerate(ss) if "claude-code-action@" in str(s.get("uses", "")))
    before = "\n".join(str(s.get("run", "")) + " " + str(s.get("with", "")) for s in ss[:idx])
    assert "deny_read" in before, "a step before the model starts must act on deny_read (remove the paths)"
    # That the paths are really removed cannot be seen from the YAML alone; see the report.


# ----------------------------------------------------------------------------- Y-12


def jobs_using_secrets(wf):
    found = {}
    for job_id, job in jobs(wf).items():
        hit = "secrets" in job or any(re.search(r"\bsecrets\.", s) for s in strings(job))
        if hit:
            found[job_id] = job
    return found


def executor_jobs(wf):
    out = {}
    for job_id, job in jobs(wf).items():
        blob = " ".join(strings(job))
        if "claude-code-action" in blob or "create-github-app-token" in blob or "executor.yml" in blob:
            out[job_id] = job
    return out


@pytest.mark.req("Y-12")
def test_y12_secrets_are_referenced_only_in_the_job_that_runs_the_executor():
    wf = load("feedback")
    executors = executor_jobs(wf)
    assert executors, "feedback.yml must run the executor"
    secret_jobs = jobs_using_secrets(wf)
    assert secret_jobs, "the executor job needs the secrets, so some job must reference them"
    assert set(secret_jobs) <= set(executors), f"secrets are referenced in {set(secret_jobs) - set(executors)} as well"


@pytest.mark.req("Y-12")
def test_y12_the_decision_job_comes_first_and_the_executor_runs_only_when_it_says_act():
    wf = load("feedback")
    decision = [jid for jid, job in jobs(wf).items()
                if any("gate.feedback" in str(s.get("run", "")) for s in steps(job))]
    assert decision, "a job must run `python -P -m gate.feedback decide`"
    decision_id = decision[0]
    order = list(jobs(wf))
    assert order[0] == decision_id, f"the decision job must come first; jobs are {order}"
    assert not jobs(wf)[decision_id].get("needs"), "the decision job waits for nothing"
    for jid, job in executor_jobs(wf).items():
        needs = job.get("needs")
        assert decision_id in (needs if isinstance(needs, list) else [needs]), f"{jid} must need {decision_id}"
        cond = str(job.get("if", ""))
        assert "act" in cond and decision_id in cond, f"{jid}: its `if:` must test the decision's `act` output: {cond!r}"
    assert jobs(wf)[decision_id].get("outputs"), "the decision job must publish its decision (`act`) as an output"


@pytest.mark.req("Y-1")
def test_y1_every_workflow_file_in_the_folder_runs_on_ubuntu_24_04_and_the_five_exist():
    folder = GATE_ROOT / ".github" / "workflows"
    files = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
    assert {f.stem for f in files} >= set(ALL_WORKFLOWS), f"expected at least {ALL_WORKFLOWS}, found {[f.name for f in files]}"
    for f in files:
        wf = yaml.safe_load(f.read_text(encoding="utf-8"))
        for job_id, job in jobs(wf).items():
            if "uses" not in job:
                assert job.get("runs-on") == "ubuntu-24.04", f"{f.name} job {job_id}: runs-on is {job.get('runs-on')!r}"


# ----------------------------------------------------------------------------- Y-12 permissions, Y-13, Y-14, Y-15


@pytest.mark.req("Y-12")
def test_y12_feedback_permissions_are_contents_read_and_pull_requests_write_and_nothing_more():
    wf = load("feedback")
    blocks = permission_blocks(wf)
    assert blocks, "feedback.yml must declare its permissions"
    if "permissions" not in wf:
        for job_id, job in jobs(wf).items():
            assert "permissions" in job, f"job {job_id} has no permissions of its own and no workflow-level block"
    allowed = {"contents": "read", "pull-requests": "write"}
    granted = {}
    for where, perms in blocks:
        assert isinstance(perms, dict), f"{where}: permissions must be a mapping, got {perms!r}"
        for key, value in perms.items():
            assert allowed.get(key) == value, f"{where}: {key}: {value} is more than contents: read and pull-requests: write"
            granted[key] = value
    assert granted == allowed, "both permissions are granted somewhere: the fix round comments on the PR and reads the code"


@pytest.mark.req("Y-13")
def test_y13_self_test_runs_on_push_and_pull_request_with_contents_read_and_no_secrets():
    wf = load("self-test")
    assert {"push", "pull_request"} <= set(triggers(wf)), f"triggers: {list(triggers(wf))}"
    blocks = permission_blocks(wf)
    assert blocks, "self-test.yml must declare its permissions"
    if "permissions" not in wf:
        for job_id, job in jobs(wf).items():
            assert "permissions" in job, f"job {job_id} has no permissions"
    for where, perms in blocks:
        assert perms == {"contents": "read"}, f"{where}: permissions are {perms!r}, not contents: read"
    for path, _ in walk(wf):
        assert path[-1] != "secrets", f"a `secrets` key at {'.'.join(map(str, path))}"
    for text in strings(wf):
        assert not re.search(r"\bsecrets\.", text), f"self-test.yml refers to secrets.*: {text!r}"


@pytest.mark.req("Y-13")
def test_y13_self_test_runs_make_check_and_actionlint_on_python_given_as_an_exact_version():
    wf = load("self-test")
    all_steps = [st for job in jobs(wf).values() for st in steps(job)]
    scripts = "\n".join(str(st.get("run", "")) for st in all_steps)
    assert re.search(r"\bmake check\b", scripts), "a step must run `make check`"
    assert "actionlint" in scripts or any("actionlint" in str(st.get("uses", "")) for st in all_steps), \
        "a step must run actionlint"
    setups = [st for st in all_steps if str(st.get("uses", "")).startswith("actions/setup-python@")]
    assert setups, "Python comes through actions/setup-python"
    for st in setups:
        assert re.fullmatch(r"actions/setup-python@[0-9a-f]{40}", str(st["uses"])), f"not a full SHA: {st['uses']}"
        version = (st.get("with") or {}).get("python-version")
        assert isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version), \
            f"python-version must be an exact version such as 3.13.7, got {version!r}"


@pytest.mark.req("Y-14")
def test_y14_judge_calls_gate_archive_with_api_repo_and_never_with_remote():
    wf = load("judge")
    scripts = [str(st["run"]) for job in jobs(wf).values() for st in steps(job) if "run" in st]
    archive = [t for t in scripts if "gate.archive" in t]
    assert archive, "the judge's archive job must call gate.archive"
    for t in archive:
        assert "--api-repo" in t, f"gate.archive is called without --api-repo:\n{t}"
        assert "--remote" not in t, f"gate.archive is called with --remote:\n{t}"
    assert "--remote" not in text_of("judge")


@pytest.mark.req("Y-15")
def test_y15_executor_passes_its_allowed_bots_input_to_the_action_and_never_allows_every_bot():
    wf = load("executor")
    call = triggers(wf)["workflow_call"] or {}
    inputs = call.get("inputs") or {}
    assert "allowed-bots" in inputs, f"executor.yml needs an `allowed-bots` input, has {list(inputs)}"
    default = inputs["allowed-bots"].get("default")
    assert default is None or "*" not in str(default), "the default must name apps, never *"
    claude = [st for job in jobs(wf).values() for st in steps(job) if "claude-code-action@" in str(st.get("uses", ""))]
    assert claude, "executor.yml must run claude-code-action"
    for st in claude:
        allowed = str((st.get("with") or {}).get("allowed_bots", ""))
        assert "inputs.allowed-bots" in allowed, f"allowed_bots is {allowed!r}"
        assert "*" not in allowed
