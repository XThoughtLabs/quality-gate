"""`spec --slug S` end to end, and the checks after the model (LR-30 to
LR-37, LR-39), which a spec run reaches fastest because it makes no venv.

One successful run is shared by several tests; each refusal has its own
world."""

from __future__ import annotations

import json
import time

import pytest

import launcher_world as W
from conftest import shared_run

SLUG = "login-flow"
BRANCH = f"spec/{SLUG}"
# Amendment 1, A5: each text is scrubbed as a whole before it is split into
# lines, so a PEM block over several lines is caught too.
PEM_BODY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA=="
SCRUB_RESULT = ("result with ghp_" + "K" * 30 + " and github_pat_" + "L" * 25
                + " RESULT-AFTER-TOKENS\n-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY
                + "\n-----END RSA PRIVATE KEY-----\nRESULT-AFTER-PEM")
SPEC_STEPS = [
    {"op": "commit", "path": "acceptance/test_login.py",
     "text": "def test_login():\n    assert True\n", "message": "Add a login test"},
    {"op": "result", "text": SCRUB_RESULT},
]
SPEC_RULES = {f"{tool}({p})" for p in ("workflow/**", "tests/**")
              for tool in ("Read", "Grep", "Glob", "Edit", "Write")}


@pytest.fixture(scope="module")
def spec_run(tmp_path_factory, launcher, test_key, template):
    return shared_run(tmp_path_factory, "spec", launcher, test_key, template, None,
                      ["spec", "--slug", SLUG], SPEC_STEPS)


def base_head(res):
    return res.refs_before[f"refs/heads/{W.INTEGRATION}"]


def spec(world, steps, slug=SLUG):
    return world.run("spec", "--slug", slug, steps=steps)


# ---------------------------------------------------------------- the shared run
def test_lr23_spec_succeeds_on_spec_branch(spec_run, check):
    check.success(spec_run)
    assert f"refs/heads/{BRANCH}" in spec_run.refs_after
    assert spec_run.model["git"]["branch"] == BRANCH
    assert spec_run.model["git"]["head"] == base_head(spec_run)


def test_lr18_spec_clone_is_shallow_depth_1(spec_run):
    g = spec_run.model["git"]
    assert g["shallow"] == "true"
    assert g["count"] == "1"


def test_lr23_deny_read_paths_hidden_without_showing_as_deleted(spec_run):
    files = spec_run.model["files"]
    assert not any(f.startswith(("workflow/", "tests/")) for f in files), files
    assert "app/core.py" in files and "acceptance/README.md" in files
    assert (spec_run.model["git"]["status"] or "") == ""
    cmds = W.gate_commands(spec_run, "hide-paths")
    assert len(cmds) == 1
    argv = cmds[0]["argv"]
    assert W.same_path(cmds[0]["cwd"], spec_run.run_dir / "gate")
    assert W.same_path(argv[argv.index("--repo") + 1], spec_run.run_dir / "repo")


def test_lr23_pushed_branch_deletes_nothing(spec_run):
    remote = spec_run.world.remote
    changed = W.changed_paths(remote, base_head(spec_run), f"refs/heads/{BRANCH}")
    assert changed == ["acceptance/test_login.py"], changed


def test_lr25_spec_makes_no_venv(spec_run):
    assert not (spec_run.run_dir / "venv").exists()
    assert not [e for e in spec_run.events if e.get("argv") and "venv" in e["argv"]]
    env = {k.upper() for k in spec_run.model["env"]}
    assert "VIRTUAL_ENV" not in env


def test_lr26_spec_allowed_tools(spec_run):
    argv = spec_run.model["argv"]
    assert argv[argv.index("--allowedTools") + 1] == W.SPEC_TOOLS
    assert argv[argv.index("--max-turns") + 1] == str(W.MAX_TURNS)
    assert argv[-2:] == ["--output-format", "json"]
    assert W.same_path(argv[argv.index("--settings") + 1], spec_run.run_dir / "claude-settings.json")


def test_lr27_spec_settings_add_the_gates_rules(spec_run):
    deny = set(json.loads(spec_run.model["settings"])["permissions"]["deny"])
    missing = (W.expected_deny(spec_run.world.config) | SPEC_RULES) - deny
    assert not missing, sorted(missing)


def test_lr28_spec_environment(spec_run):
    env = {k.upper(): v for k, v in spec_run.model["env"].items()}
    assert env.get("GIT_TERMINAL_PROMPT") == "0"
    assert env.get("GCM_INTERACTIVE") == "never"
    token = spec_run.world.api.tokens_issued[0]
    assert token not in json.dumps(spec_run.model)


def test_lr29_spec_prompt(spec_run):
    text = W.norm_text(spec_run.model["stdin"])
    template = W.SPEC_TEMPLATE.rstrip("\n")
    assert text.lstrip().startswith(template)
    assert text.find(W.BRANCH_LINE.format(branch=BRANCH)) > text.find(template)
    assert "The task is issue" not in text
    assert "This is a fix round" not in text
    assert "Never edit security-review.md" not in text


def test_lr40_spec_pr_with_the_spec_prefix(spec_run):
    cmds = W.gate_commands(spec_run, "create-pull-request")
    assert len(cmds) == 1
    argv = cmds[0]["argv"]
    assert argv[argv.index("--prefix") + 1] == "spec/"
    assert "--issue" not in argv
    assert argv[argv.index("--branch") + 1] == BRANCH
    assert W.same_path(cmds[0]["cwd"], spec_run.run_dir / "gate")
    env = W.effective_env(cmds[0])
    assert env.get("GATE_TOKEN") == spec_run.world.api.tokens_issued[0]
    posted = spec_run.world.api.requests_to("POST", rf"^/repos/{W.REPOSITORY}/pulls$")
    assert len(posted) == 1 and posted[0]["body"]["head"].split(":")[-1] == BRANCH


def test_lr41_spec_routes(spec_run, check):
    check.routes(spec_run)


def test_lr49_lr50_model_result_is_scrubbed_in_the_log(spec_run):
    log = spec_run.log_text
    assert "RESULT-AFTER-TOKENS" in log, "the model's result is not in the log"
    assert "RESULT-AFTER-PEM" in log
    assert "ghp_" + "K" * 30 not in log
    assert "github_pat_" + "L" * 25 not in log
    assert PEM_BODY not in log, "a PEM block over several lines reached the log (A5)"
    assert "[removed]" in log


def test_lr49_spec_log_names_the_command_and_slug(spec_run):
    log = spec_run.log_text
    assert "spec" in log and SLUG in log
    assert BRANCH in log
    assert spec_run.refs_after[f"refs/heads/{BRANCH}"] in log


# ---------------------------------------------------------------- LR-18 / LR-19 on the integration branch
def default_branch_main(world, good_pin_on_main: bool):
    pin = "" if good_pin_on_main else (
        f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{W.UNKNOWN_SHA}")
    world.new_branch("main", {"prompts/spec-tests.md": W.MAIN_TEMPLATE,
                              ".github/workflows/judge.yml": W.judge_yml(pin or None)},
                     message="The default branch differs")
    with W.quiet_audit():
        W.git("--git-dir", str(world.remote), "symbolic-ref", "HEAD", "refs/heads/main")


def test_lr18_prompt_and_pin_come_from_the_integration_branch(world, check):
    default_branch_main(world, good_pin_on_main=False)
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.success(res)
    text = W.norm_text(res.model["stdin"])
    assert text.lstrip().startswith(W.SPEC_TEMPLATE.rstrip("\n"))
    assert "MAIN-BRANCH-TEMPLATE" not in text
    assert res.model["git"]["head"] == res.refs_before[f"refs/heads/{W.INTEGRATION}"]


def test_lr19_pin_read_on_the_integration_branch_not_the_default(world, check):
    default_branch_main(world, good_pin_on_main=True)
    world.remote_commit(W.INTEGRATION, {".github/workflows/judge.yml": W.judge_yml(
        f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{W.UNKNOWN_SHA}")})
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "PIN_UNKNOWN")
    assert res.model is None and not res.pushed


# ---------------------------------------------------------------- LR-19
PIN_VARIANTS = {
    "no_uses": "    runs-on: ubuntu-24.04",
    "short_sha": "    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@fdc9918",
    "tag": "    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@v1",
    "unknown_sha": f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{W.UNKNOWN_SHA}",
    "other_owner": f"    uses: Evil/quality-gate/.github/workflows/judge.yml@{W.GATE_PIN}",
    "other_workflow": f"    uses: XThoughtLabs/quality-gate/.github/workflows/other.yml@{W.GATE_PIN}",
    "two_shas": (f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{W.GATE_PIN}\n"
                 "  second:\n"
                 f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{W.UNKNOWN_SHA}"),
}


@pytest.mark.parametrize("variant", sorted(PIN_VARIANTS) + ["missing_file"])
def test_lr19_pin_unknown(world, check, variant):
    if variant == "missing_file":
        world.remote_commit(W.INTEGRATION, {".github/workflows/judge.yml": None})
    else:
        world.remote_commit(W.INTEGRATION,
                            {".github/workflows/judge.yml": W.judge_yml(PIN_VARIANTS[variant])})
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "PIN_UNKNOWN")
    assert res.model is None and not res.pushed


# ---------------------------------------------------------------- LR-24
def test_lr24_spec_branch_exists(world, check):
    world.new_branch(BRANCH, {"acceptance/test_other.py": "x = 1\n"})
    before = world.remote_refs()
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "BRANCH_EXISTS")
    assert res.model is None
    assert world.remote_refs() == before


# ---------------------------------------------------------------- LR-30
def test_lr30_folder_open_just_before_the_model(world, check):
    world.seams.folder_hook = lambda path: "open" if world.api.tokens_issued else None
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "FOLDER_OPEN")
    assert res.model is None, "the model ran"
    assert not res.pushed
    assert "INNER-SECRET-NAME-0451" not in res.stdout + res.stderr + res.log_text


# ---------------------------------------------------------------- LR-31
def test_lr31_timeout_kills_the_model_and_its_children(world, check, tmp_path):
    pids_file = tmp_path / "pids.json"
    steps = [{"op": "commit", "path": "acceptance/test_a.py"},
             {"op": "sleep", "seconds": 150, "pids": str(pids_file)}]
    try:
        res = spec(world, steps)
        assert res.duration < 60 + 45, f"the model ran {res.duration:.0f} s with timeout_minutes = 1"
        check.post_model_stop(res, "TIMEOUT")
        pids = json.loads(pids_file.read_text(encoding="utf-8"))
        deadline = time.time() + 10
        while time.time() < deadline and any(W.process_alive(p) for p in pids.values()):
            time.sleep(0.2)
        assert not W.process_alive(pids["model"]), "the model is still running"
        assert not W.process_alive(pids["child"]), "the model's child is still running"
    finally:
        if pids_file.exists():
            for pid in json.loads(pids_file.read_text(encoding="utf-8")).values():
                if W.process_alive(pid):
                    W.kill_pid(pid)


# ---------------------------------------------------------------- LR-32
def test_lr32_model_failed(world, check):
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}, {"op": "exit", "code": 3}])
    check.post_model_stop(res, "MODEL_FAILED")


# ---------------------------------------------------------------- LR-33
@pytest.mark.parametrize("move", [
    [{"op": "switch", "branch": "spec/elsewhere"}, {"op": "commit", "path": "acceptance/test_a.py"}],
    [{"op": "detach"}, {"op": "commit", "path": "acceptance/test_a.py"}],
    [{"op": "commit", "path": "acceptance/test_a.py"}, {"op": "orphan_reset"}],
], ids=["other_branch", "detached", "unrelated_history"])
def test_lr33_branch_moved(world, check, move):
    res = spec(world, move)
    check.post_model_stop(res, "BRANCH_MOVED")


# ---------------------------------------------------------------- LR-34
def test_lr34_leftovers_committed_by_the_bot(world, check):
    steps = [{"op": "write", "path": "acceptance/test_left.py", "text": "def test_left():\n    pass\n"},
             {"op": "proposal", "text": "| bandit | B101 | x | y |\n"}]
    res = spec(world, steps)
    check.success(res)
    tip = f"refs/heads/{BRANCH}"
    commits = W.commits_between(world.remote, res.refs_before[f"refs/heads/{W.INTEGRATION}"], tip)
    assert [c["subject"] for c in commits] == [W.LEFTOVER_MESSAGE]
    c = commits[0]
    assert (c["author_name"], c["author_email"], c["committer_name"], c["committer_email"]) == \
        (W.BOT_LOGIN, W.BOT_EMAIL, W.BOT_LOGIN, W.BOT_EMAIL)
    files = W.tree_files(world.remote, tip)
    assert "acceptance/test_left.py" in files
    assert W.PROPOSAL_FILE not in files
    assert W.changed_paths(world.remote, res.refs_before[f"refs/heads/{W.INTEGRATION}"], tip) == \
        ["acceptance/test_left.py"]


def test_lr34_commit_plus_leftover_gives_two_commits(world, check):
    steps = [{"op": "commit", "path": "acceptance/test_a.py", "message": "Model commit"},
             {"op": "write", "path": "acceptance/test_a.py", "text": "# more\n"}]
    res = spec(world, steps)
    check.success(res)
    commits = W.commits_between(world.remote, res.refs_before[f"refs/heads/{W.INTEGRATION}"],
                                f"refs/heads/{BRANCH}")
    assert [c["subject"] for c in commits] == [W.LEFTOVER_MESSAGE, "Model commit"]


# ---------------------------------------------------------------- LR-35
@pytest.mark.parametrize("step", [
    {"op": "commit_as", "path": "acceptance/test_a.py", "name": "Mallory", "email": "m@example.com"},
    {"op": "commit_as", "path": "acceptance/test_a.py", "name": W.BOT_LOGIN, "email": "m@example.com"},
    {"op": "commit_as", "path": "acceptance/test_a.py", "name": "Mallory", "email": W.BOT_EMAIL},
    {"op": "commit_committer_as", "path": "acceptance/test_a.py", "name": "Mallory",
     "email": "m@example.com"},
], ids=["other_author", "bot_name_other_email", "other_name_bot_email", "other_committer"])
def test_lr35_identity(world, check, step):
    res = spec(world, [{"op": "commit", "path": "acceptance/test_ok.py"}, step])
    check.post_model_stop(res, "IDENTITY")


# ---------------------------------------------------------------- LR-36
@pytest.mark.parametrize("steps", [[], [{"op": "proposal", "text": "| a | b | c | d |\n"}]],
                         ids=["nothing", "proposal_only"])
def test_lr36_no_changes(world, check, steps):
    res = spec(world, steps)
    check.post_model_stop(res, "NO_CHANGES")


# ---------------------------------------------------------------- LR-37
@pytest.mark.parametrize("steps", [
    [{"op": "commit", "path": "app/x.py"}],
    [{"op": "commit", "path": "acceptance/test_a.py"}, {"op": "commit", "path": "README.md",
                                                        "text": "changed\n"}],
    [{"op": "commit", "path": "acceptance/test_a.py"}, {"op": "write", "path": "app/left.py"}],
    [{"op": "commit", "path": "acceptance.py"}],
], ids=["outside", "inside_and_outside", "leftover_outside", "prefix_without_folder"])
def test_lr37_spec_outside_acceptance(world, check, steps):
    res = spec(world, steps)
    check.post_model_stop(res, "SPEC_OUTSIDE_ACCEPTANCE")


# ---------------------------------------------------------------- LR-39
def test_lr39_refused_push(world, check):
    hook = world.remote / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'refused by the test' >&2\nexit 1\n", encoding="utf-8",
                    newline="\n")
    res = spec(world, [{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "PUSH_FAILED")
    assert not res.pushed
    assert world.api.requests_to("POST", r"/pulls$") == []


def test_lr39_never_forces_over_a_branch_that_appeared(world, check, tmp_path):
    record = tmp_path / "race.txt"
    steps = [{"op": "commit", "path": "acceptance/test_a.py"},
             {"op": "push_race", "remote": str(world.remote), "ref": f"refs/heads/{BRANCH}",
              "record": str(record)}]
    res = spec(world, steps)
    check.stopped(res, "PUSH_FAILED")
    racing = record.read_text(encoding="utf-8").strip()
    assert world.remote_refs()[f"refs/heads/{BRANCH}"] == racing, "the push overwrote the branch"
    assert world.api.requests_to("POST", r"/pulls$") == []
