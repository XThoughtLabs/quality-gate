"""`task --issue N` end to end: the work folder (LR-17 to LR-21), the branch
and the model (LR-22 to LR-29), after the model (LR-34, LR-35, LR-39 to
LR-41), the token's paths (LR-15) and the log (LR-49, LR-50).

One successful run is shared by most tests of this module (a venv costs
seconds); refusals get worlds of their own."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
from pathlib import Path

import pytest

import launcher_world as W
from conftest import shared_run

PROPOSAL_TEXT = "| bandit | B101 | app/feature.py | PROPOSAL-MARK-3141 asserts are fine here |\n"
RESULT_HEAD = "RSTART-Ωmega "
# Amendment 1, A5: the result is scrubbed first, then cut to 2,000 characters.
# The 40-character token becomes `[removed]` (9), so SCRUBFIRST-MARK, which
# starts at raw character 2,000, ends before character 2,000 once scrubbed;
# the tail starts past 2,000 either way.
RESULT_TOKEN = "ghp_" + "K" * 36
_RESULT_START = RESULT_HEAD + RESULT_TOKEN + " "
RESULT_TEXT = (_RESULT_START + "r" * (2000 - len(_RESULT_START)) + "SCRUBFIRST-MARK"
               + "y" * 100 + "ZZTAILMARKERZZ" * 20)
TASK_STEPS = [
    {"op": "commit", "path": "app/feature.py", "text": "def feature():\n    return 3\n",
     "message": "Add the feature"},
    {"op": "proposal", "text": PROPOSAL_TEXT},
    {"op": "result", "text": RESULT_TEXT},
]
REMOVED_VARS = ["XTL_SENTINEL_TOKEN", "XTL_MY_SECRET_X", "XTL_PASSWORD_Y", "XTL_PRIVATE_KEY_Z",
                "XTL_CREDENTIAL_W", "XTL_API_KEY_V", "xtl_lower_token_sentinel", "GH_SENTINEL",
                "GITHUB_SENTINEL", "GATE_SENTINEL", "GIT_CONFIG_XTL_SENTINEL"]
KEPT_VAR, KEPT_VALUE = "XTL_SENTINEL_KEEP", "kept-value-77"
REMOVED_WORDS = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL", "API_KEY")
REMOVED_PREFIXES = ("GH_", "GITHUB_", "GATE_", "GIT_CONFIG")


def prepare_task(w, mp):
    w.remote_commit(W.INTEGRATION, {"requirements.lock": "# no dependencies\n"},
                    message="Add an empty lock")
    for name in REMOVED_VARS:
        mp.setenv(name, "sentinel-value-0042")
    mp.setenv(KEPT_VAR, KEPT_VALUE)


@pytest.fixture(scope="module")
def task_run(tmp_path_factory, launcher, test_key, template):
    return shared_run(tmp_path_factory, "task", launcher, test_key, template, prepare_task,
                      ["task", "--issue", str(W.ISSUE_NUMBER)], TASK_STEPS)


def integration_head(res):
    return res.refs_before[f"refs/heads/{W.INTEGRATION}"]


def token_of(res):
    tokens = res.world.api.tokens_issued
    assert len(tokens) == 1, f"expected one token, found {len(tokens)}"
    return tokens[0]


# ---------------------------------------------------------------- the outcome
def test_lr22_task_succeeds_and_pushes_ai_branch(task_run, check):
    check.success(task_run)
    assert f"refs/heads/{W.ISSUE_BRANCH}" in task_run.refs_after
    assert task_run.world.api.requests_to("GET", rf"^/repos/{W.REPOSITORY}/issues/5$")


def test_lr14_success_revokes_the_token(task_run, check):
    check.revoked(task_run)
    last = task_run.requests[-1]
    assert (last["method"], last["path"]) == ("DELETE", "/installation/token")


def test_lr41_only_table_routes(task_run, check):
    check.routes(task_run)


def test_lr50_no_secret_in_output_or_log(task_run, check):
    check.no_leak(task_run)


# ---------------------------------------------------------------- LR-17
def test_lr17_run_folder_and_log_names(task_run):
    run_dir = task_run.run_dir
    name = run_dir.name
    assert run_dir.parent == task_run.world.runs_dir
    assert "task" in name and "5" in name, name
    assert any(re.fullmatch(r"[0-9a-f]{6}", c) for c in re.split(r"[-_.]", name)), name
    minutes = set()
    t = task_run.started - 60
    while t <= task_run.started + task_run.duration + 60:
        u = dt.datetime.fromtimestamp(t, dt.timezone.utc)
        minutes.add(u)
        t += 30
    pattern_ok = False
    for u in minutes:
        for fmt in (r"{Y}-?{m}-?{d}[T_-]?{H}-?{M}",):
            rx = fmt.format(Y=u.strftime("%Y"), m=u.strftime("%m"), d=u.strftime("%d"),
                            H=u.strftime("%H"), M=u.strftime("%M"))
            if re.search(rx, name):
                pattern_ok = True
    assert pattern_ok, f"no UTC date and time in the run id {name!r}"
    assert list(task_run.logs) == [f"{name}.log"]


# ---------------------------------------------------------------- LR-18
def test_lr18_clone_of_repo_url_in_run_repo(task_run):
    m = task_run.model
    assert m is not None
    assert W.same_path(m["cwd"], task_run.run_dir / "repo")
    assert W.same_path(m["git"]["remote_url"], task_run.world.config["repo_url"])


def test_lr18_clone_holds_no_credentials(task_run):
    cfg = task_run.model["git"]["local_config"] or ""
    assert "extraheader" not in cfg.lower()
    assert "@" not in (task_run.model["git"]["remote_url"] or "")
    token = token_of(task_run)
    assert token not in cfg


# ---------------------------------------------------------------- LR-19
def test_lr19_gate_cloned_and_checked_out_at_the_pin(task_run):
    gate_dir = task_run.run_dir / "gate"
    limits = W.gate_commands(task_run, "limits")
    assert limits and W.same_path(limits[0]["cwd"], gate_dir)
    if gate_dir.exists():
        assert W.git("-C", str(gate_dir), "rev-parse", "HEAD") == W.GATE_PIN
    else:
        assert any(W.GATE_PIN in " ".join(e.get("argv") or []) for e in task_run.events)


# ---------------------------------------------------------------- LR-20
def test_lr20_limits_from_the_pinned_gate(task_run):
    limits = W.gate_commands(task_run, "limits")
    assert len(limits) >= 1
    argv = limits[0]["argv"]
    assert "gate.publish" in argv
    i = argv.index("--config")
    assert W.same_path(argv[i + 1], task_run.run_dir / "repo" / "quality.toml")
    margv = task_run.model["argv"]
    assert margv[margv.index("--max-turns") + 1] == str(W.MAX_TURNS)


# ---------------------------------------------------------------- LR-21
def test_lr21_bot_identity_in_the_clone(task_run):
    api = task_run.world.api
    assert api.requests_to("GET", rf"^/users/{W.SLUG}%5Bbot%5D$")
    g = task_run.model["git"]
    assert g["user_name"] == W.BOT_LOGIN
    assert g["user_email"] == W.BOT_EMAIL
    assert g["credential_helpers"] is not None and g["credential_helpers"][-1] == ""
    assert W.PROPOSAL_FILE in [ln.strip() for ln in (g["exclude"] or "").splitlines()]


# ---------------------------------------------------------------- LR-24
def test_lr24_branch_created_from_the_integration_head(task_run):
    m = task_run.model["git"]
    assert m["branch"] == W.ISSUE_BRANCH
    assert m["head"] == integration_head(task_run)


# ---------------------------------------------------------------- LR-25
def test_lr25_venv_made_with_app_python_and_lock_installed(task_run):
    run_dir = task_run.run_dir
    app_python = task_run.world.config["app_python"]
    venv_cmds = [e for e in task_run.events if e.get("argv") and "venv" in e["argv"]
                 and "-m" in e["argv"]]
    assert venv_cmds, "no `-m venv` command"
    argv = venv_cmds[0]["argv"]
    assert W.same_path(argv[0], app_python) or W.same_path(venv_cmds[0]["executable"] or "", app_python)
    assert W.same_path(argv[argv.index("venv") + 1], run_dir / "venv")
    pip = [e for e in task_run.events if e.get("argv") and "pip" in e["argv"]
           and "install" in e["argv"]]
    assert pip, "requirements.lock was not installed"
    pargv = pip[0]["argv"]
    assert pargv[pargv.index("pip") - 1] == "-m"
    assert pargv[pargv.index("-r") + 1].replace("\\", "/").endswith("requirements.lock")
    assert W.norm(pargv[0]).startswith(W.norm(run_dir / "venv"))


def test_lr25_lr28_model_runs_in_the_venv(task_run):
    env = {k.upper(): v for k, v in task_run.model["env"].items()}
    venv = task_run.run_dir / "venv"
    assert W.same_path(env["VIRTUAL_ENV"], venv)
    first = env["PATH"].split(os.pathsep)[0]
    assert W.same_path(first, venv / "Scripts")


# ---------------------------------------------------------------- LR-26
def test_lr26_model_command_line_and_working_folder(task_run):
    m = task_run.model
    cmd = task_run.world.config["claude_command"]
    expected_tail = ["-p", "--max-turns", str(W.MAX_TURNS), "--allowedTools", W.TASK_TOOLS,
                     "--settings", None, "--output-format", "json"]
    argv = m["argv"]
    # argv[0] is the script the interpreter ran; the rest follows claude_command.
    assert W.same_path(argv[0], cmd[1])
    tail = argv[1:]
    assert len(tail) == len(expected_tail), tail
    for got, want in zip(tail, expected_tail):
        if want is not None:
            assert got == want, tail
    assert W.same_path(tail[6], task_run.run_dir / "claude-settings.json")
    assert W.same_path(m["cwd"], task_run.run_dir / "repo")
    ev = W.model_event(task_run)
    assert W.same_path(ev["argv"][0], cmd[0])


# ---------------------------------------------------------------- LR-27
def test_lr27_settings_deny_rules(task_run):
    settings = json.loads(task_run.model["settings"])
    deny = set(settings["permissions"]["deny"])
    missing = W.expected_deny(task_run.world.config) - deny
    assert not missing, sorted(missing)


# ---------------------------------------------------------------- LR-28
def test_lr28_model_environment(task_run):
    env = task_run.model["env"]
    names = {k.upper() for k in env}
    for name in names:
        assert not any(w in name for w in REMOVED_WORDS), name
        assert not name.startswith(REMOVED_PREFIXES), name
    for name in REMOVED_VARS:
        assert name.upper() not in names
    upper = {k.upper(): v for k, v in env.items()}
    assert upper.get(KEPT_VAR) == KEPT_VALUE
    assert upper.get("GIT_TERMINAL_PROMPT") == "0"
    assert upper.get("GCM_INTERACTIVE") == "never"


def test_lr28_rest_of_the_launchers_environment_is_kept(task_run):
    ev = W.model_event(task_run)
    parent = {k.upper(): v for k, v in ev["parent_env"].items()}
    child = {k.upper(): v for k, v in task_run.model["env"].items()}
    added = {"PATH", "VIRTUAL_ENV", "GIT_TERMINAL_PROMPT", "GCM_INTERACTIVE"}
    for name, value in parent.items():
        if name in added or any(w in name for w in REMOVED_WORDS) or name.startswith(REMOVED_PREFIXES):
            continue
        assert child.get(name) == value, name


# ---------------------------------------------------------------- LR-29
def test_lr29_prompt_on_stdin(task_run):
    text = W.norm_text(task_run.model["stdin"])
    template = W.EXECUTOR_TEMPLATE.rstrip("\n")
    assert text.lstrip().startswith(template), text[:200]
    issue = task_run.world.api.issues[W.ISSUE_NUMBER]
    parts = [template, W.BRANCH_LINE.format(branch=W.ISSUE_BRANCH),
             W.TASK_LINE.format(n=W.ISSUE_NUMBER), issue["title"], issue["body"],
             W.PROPOSAL_LINE]
    start = 0
    for part in parts:
        i = text.find(part, start)
        assert i >= 0, f"{part!r} missing or out of order"
        start = i + len(part)
    assert "This is a fix round" not in text
    assert task_run.model["stdin_is_utf8"]


# ---------------------------------------------------------------- LR-30
def test_lr30_folder_check_again_before_the_model(task_run):
    world = task_run.world
    token_time = min(r["time"] for r in world.api.requests
                     if r["path"].endswith("/access_tokens"))
    later = {W.norm(c[1]) for c in world.seams.calls
             if c[0] == "folder_openable" and token_time < c[2] < task_run.model["started"]}
    assert {W.norm(p) for p in world.config["must_not_open"]} <= later


# ---------------------------------------------------------------- LR-34 / LR-35
def test_lr34_proposal_never_committed(task_run):
    remote = task_run.world.remote
    files = W.tree_files(remote, f"refs/heads/{W.ISSUE_BRANCH}")
    assert W.PROPOSAL_FILE not in files
    assert "app/feature.py" in files


def test_lr35_every_new_commit_is_the_bots(task_run):
    commits = W.commits_between(task_run.world.remote, integration_head(task_run),
                                f"refs/heads/{W.ISSUE_BRANCH}")
    assert commits
    for c in commits:
        assert (c["author_name"], c["author_email"]) == (W.BOT_LOGIN, W.BOT_EMAIL), c
        assert (c["committer_name"], c["committer_email"]) == (W.BOT_LOGIN, W.BOT_EMAIL), c


# ---------------------------------------------------------------- LR-39
def test_lr39_push_without_force_with_the_header_in_its_environment(task_run):
    token = token_of(task_run)
    pushes = task_run.git_commands("push")
    assert len(pushes) == 1, [p["argv"] for p in pushes]
    argv = pushes[0]["argv"]
    assert "origin" in argv
    assert f"HEAD:refs/heads/{W.ISSUE_BRANCH}" in argv
    for a in argv:
        assert not a.startswith("+"), argv
        assert a not in ("-f", "--force", "--mirror", "--delete", "-d") and not a.startswith("--force"), argv
    env = W.effective_env(pushes[0])
    count = int(env["GIT_CONFIG_COUNT"])
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
    repo_url = task_run.world.config["repo_url"]
    assert pairs.get(f"http.{repo_url}.extraheader") == W.basic_header(token)
    assert pairs.get("credential.helper") == ""


def test_lr15_header_only_in_the_push(task_run):
    token = token_of(task_run)
    header = W.basic_header(token)
    for e in task_run.events:
        if not e.get("argv") or e in task_run.git_commands("push"):
            continue
        env = W.effective_env(e)
        assert header not in env.values(), e["argv"]


def test_lr39_remote_branch_is_the_pushed_head(task_run):
    tip = task_run.refs_after[f"refs/heads/{W.ISSUE_BRANCH}"]
    commits = W.commits_between(task_run.world.remote, integration_head(task_run), tip)
    assert [c["subject"] for c in commits] == ["Add the feature"]


# ---------------------------------------------------------------- LR-40
def test_lr40_pr_opened_by_the_pinned_gate(task_run):
    token = token_of(task_run)
    world = task_run.world
    cmds = W.gate_commands(task_run, "create-pull-request")
    assert len(cmds) == 1
    ev = cmds[0]
    argv = ev["argv"]
    assert W.same_path(ev["cwd"], task_run.run_dir / "gate")
    assert argv[argv.index("--prefix") + 1] == f"ai/{W.ISSUE_NUMBER}-"
    assert argv[argv.index("--issue") + 1] == str(W.ISSUE_NUMBER)
    assert argv[argv.index("--branch") + 1] == W.ISSUE_BRANCH
    assert argv[argv.index("--base") + 1] == W.INTEGRATION
    env = W.effective_env(ev)
    assert env.get("GATE_TOKEN") == token
    assert env.get("GITHUB_REPOSITORY") == W.REPOSITORY
    assert env.get("GITHUB_API_URL") == world.api.url
    posted = world.api.requests_to("POST", rf"^/repos/{W.REPOSITORY}/pulls$")
    assert len(posted) == 1
    assert posted[0]["body"]["head"].split(":")[-1] == W.ISSUE_BRANCH
    assert posted[0]["body"]["base"] == W.INTEGRATION


def test_lr40_proposal_posted_after_the_pr(task_run):
    token = token_of(task_run)
    world = task_run.world
    cmds = W.gate_commands(task_run, "post-proposal")
    assert len(cmds) == 1
    ev = cmds[0]
    argv = ev["argv"]
    assert W.same_path(ev["cwd"], task_run.run_dir / "gate")
    assert W.same_path(argv[argv.index("--file") + 1], task_run.run_dir / "repo" / W.PROPOSAL_FILE)
    assert argv[argv.index("--branch") + 1] == W.ISSUE_BRANCH
    env = W.effective_env(ev)
    assert env.get("GATE_TOKEN") == token
    assert env.get("GITHUB_REPOSITORY") == W.REPOSITORY
    assert env.get("GITHUB_API_URL") == world.api.url
    assert ev["time"] > W.gate_commands(task_run, "create-pull-request")[0]["time"]
    pr_number = min(world.api.pulls)
    comments = world.api.comments.get(pr_number, [])
    assert any("PROPOSAL-MARK-3141" in c["body"] for c in comments)


# ---------------------------------------------------------------- LR-15
def test_lr15_token_never_on_a_command_line(task_run):
    token = token_of(task_run)
    assert task_run.events, "no process was seen"
    for e in task_run.events:
        assert token not in " ".join(e.get("argv") or []), e.get("argv")


def test_lr15_token_never_in_a_file(task_run):
    token = token_of(task_run).encode()
    roots = [task_run.world.root]
    for root in roots:
        for p in Path(root).rglob("*"):
            if p.is_file():
                try:
                    data = p.read_bytes()
                except OSError:
                    continue
                assert token not in data, f"the token is in {p}"
    for cfg in (Path.home() / ".gitconfig", Path.home() / ".config" / "git" / "config"):
        if cfg.exists():
            assert token not in cfg.read_bytes(), cfg


def test_lr15_token_never_reaches_the_model(task_run):
    token = token_of(task_run)
    m = task_run.model
    assert token not in json.dumps(m["argv"])
    assert token not in m["stdin"]
    assert token not in json.dumps(m["env"])
    assert W.basic_header(token).split("basic ", 1)[1] not in json.dumps(m["env"])
    ev = W.model_event(task_run)
    assert token not in json.dumps(W.effective_env(ev))


def test_lr15_gate_commands_get_the_token_only_through_gate_token(task_run):
    token = token_of(task_run)
    cmds = W.gate_commands(task_run, "create-pull-request") + W.gate_commands(task_run, "post-proposal")
    assert cmds
    for ev in cmds:
        env = W.effective_env(ev)
        holders = sorted(k for k, v in env.items() if token in v)
        assert holders == ["GATE_TOKEN"], holders


# ---------------------------------------------------------------- LR-49
def test_lr49_log_contents(task_run):
    log = task_run.log_text
    world = task_run.world
    stamps = [s for s in W.utc_stamps(log)
              if task_run.started - 5 <= s <= task_run.started + task_run.duration + 5]
    assert len(stamps) >= 2, "the start and the end in UTC are not in the log"
    assert "task" in log
    assert W.EXEC_SID in log
    assert W.ISSUE_BRANCH in log
    tip = task_run.refs_after[f"refs/heads/{W.ISSUE_BRANCH}"]
    assert tip in log, "the pushed commit is not in the log"
    pr_number = min(world.api.pulls)
    assert world.api.html_pr(pr_number) in log
    assert re.search(rf"(?<!\d){pr_number}(?!\d)", log)
    assert "token revoked" in log
    for value in ("98765", "0.4321", "13", "success"):
        assert value in log, value
    assert re.search(r"is_error\W+false", log, re.IGNORECASE), "is_error is not logged"
    assert RESULT_HEAD.strip() in log
    assert RESULT_TOKEN not in log
    assert "ZZTAILMARKERZZ" not in log, "the result text is not cut to 2,000 characters"
    assert "SCRUBFIRST-MARK" in log, "the result was cut before it was scrubbed (A5)"
    for step in ("limits", "create-pull-request", "post-proposal", "push"):
        assert step in log, step


def test_lr49_log_is_utf8(task_run):
    raw = (task_run.world.runs_dir / "logs" / next(iter(task_run.logs))).read_bytes()
    raw.decode("utf-8")  # strict
    assert "Ωmega".encode("utf-8") in raw


# ---------------------------------------------------------------- refusals
def test_lr22_closed_issue(world, check):
    world.api.issues[W.ISSUE_NUMBER]["state"] = "closed"
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    assert res.model is None and not res.pushed


def test_lr22_pull_request_is_not_an_issue(world, check):
    world.api.issues[W.ISSUE_NUMBER]["pull_request"] = {"url": "x"}
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    assert res.model is None and not res.pushed


def test_lr22_missing_issue(world, check):
    res = world.run("task", "--issue", "99")
    check.stopped(res, "NOT_AN_ISSUE")
    assert res.model is None and not res.pushed


def test_lr24_task_branch_exists(world, check):
    world.new_branch(W.ISSUE_BRANCH, {"other.txt": "someone else's\n"})
    before = world.remote_refs()
    res = world.run("task", "--issue", "5", steps=[{"op": "commit", "path": "app/x.py"}])
    check.stopped(res, "BRANCH_EXISTS")
    assert res.model is None
    assert world.remote_refs() == before


def test_lr40_pr_failed(world, check):
    world.api.fail("POST", rf"^/repos/{W.REPOSITORY}/pulls$", 422, {"message": "Validation Failed"})
    res = world.run("task", "--issue", "5", steps=[{"op": "commit", "path": "app/x.py"}])
    check.stopped(res, "PR_FAILED")
    assert W.gate_commands(res, "create-pull-request")


def test_lr17_two_runs_get_two_folders_and_two_logs(world, check):
    world.api.issues.clear()
    first = world.run("task", "--issue", "5")
    second = world.run("task", "--issue", "5")
    check.stopped(first, "NOT_AN_ISSUE")
    check.stopped(second, "NOT_AN_ISSUE")
    assert len(first.run_dirs) == 1 and len(second.run_dirs) == 1
    assert first.run_dirs[0] != second.run_dirs[0]
    assert set(first.logs).isdisjoint(second.logs)
    assert len(list((world.runs_dir / "logs").glob("*.log"))) == 2
