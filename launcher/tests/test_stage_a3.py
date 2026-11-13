"""Stage A3: the launcher's own repository for git after the model, and the process list (LR-79 to LR-88),
written from LAUNCHER-CONTRACT.md section 14. Each test is named and marked by its rule; the tests of processes
run on Windows only."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import launcher_world as W
from stage_a_kit import SLUG, kill_all, msg, one_attempt, spec, wait_dead

windows_only = pytest.mark.skipif(os.name != "nt", reason="the job object and the process list exist on Windows only")
STAY = {"op": "pause", "seconds": 60}
GOOD_START = "0" * 40


def spec_tip(res):
    return res.refs_after.get(f"refs/heads/spec/{SLUG}")


def remote_paths(world, tip):
    return W.changed_paths(world.remote, world.facts.base_head, tip)


# ---------------------------------------------------------------- LR-79, LR-80: replace refs (S3)
@pytest.mark.lr(79)
@pytest.mark.lr(80)
def test_lr79_a_replace_ref_does_not_hide_a_commit_outside_acceptance(world, check):
    """The reviewer's S3 scenario: the checks must read the real commit, which touches outside.txt."""
    res = spec(world, [{"op": "replace_decoy", "bad": True}, msg("m1")])
    check.post_model_stop(res, "SPEC_OUTSIDE_ACCEPTANCE")


@pytest.mark.lr(79)
@pytest.mark.lr(80)
def test_lr79_the_commit_checked_and_pushed_is_the_real_one(world, check):
    """A decoy that touches outside.txt must not make the real commit, inside acceptance/, look wrong. A control: it
    passes on the code before stage A3 too (the clone's files are the real commit's there)."""
    res = spec(world, [{"op": "replace_decoy", "bad": False}, msg("m1")])
    check.success(res)
    tip = spec_tip(res)
    assert "acceptance/real.txt" in remote_paths(world, tip) and "outside.txt" not in remote_paths(world, tip)
    assert not any(ref.startswith("refs/replace/") for ref in res.refs_after), res.refs_after


# ---------------------------------------------------------------- LR-80: commondir (S2)
@pytest.mark.lr(80)
def test_lr80_a_commondir_with_fsmonitor_and_follow_tags_does_not_act(world, check, tmp_path):
    marker = tmp_path / "fsmonitor-ran"
    res = spec(world, [{"op": "commondir", "marker": str(marker)}, msg("m1")])
    check.success(res)
    assert not marker.exists(), "core.fsmonitor from the commondir's configuration ran"
    assert not any(ref.startswith("refs/tags/") for ref in res.refs_after), res.refs_after


# ---------------------------------------------------------------- LR-80: hooks everywhere (S1, S6)
HOOK_NAMES = ("pre-push", "pre-commit", "post-index-change", "reference-transaction", "post-checkout",
              "pre-auto-gc", "push-to-checkout", "post-rewrite", "post-update", "update", "pre-receive")


@pytest.mark.lr(80)
def test_lr80_hooks_in_every_folder_the_model_can_write_do_not_run(world, check, tmp_path):
    marker = tmp_path / "hook-ran"
    hook = f"#!/bin/sh\necho ran >> '{marker.as_posix()}'\nexit 0\n"
    steps = [{"op": "write", "path": f"{folder}/{name}", "text": hook}
             for folder in (".git/hooks", "../no-hooks", "../git-hooks", "..") for name in HOOK_NAMES]
    res = spec(world, [*steps, {"op": "write", "path": "acceptance/left.py", "text": "left = 1\n"}, msg("m1")])
    check.success(res)
    assert not marker.exists(), "a hook the model wrote ran during the launcher's git commands"
    assert W.LEFTOVER_MESSAGE in [c["subject"] for c in W.commits_between(world.remote, world.facts.base_head,
                                                                           spec_tip(res))]


@pytest.mark.lr(10)
@pytest.mark.lr(80)
@pytest.mark.parametrize("trouble", ["a-hook", "writable", "missing", "no-readme"])
def test_lr80_the_launchers_hooks_folder_must_be_read_only_and_hold_only_its_readme(world, check, launcher,
                                                                                   monkeypatch, tmp_path, trouble):
    hooks = tmp_path / "git-hooks"
    if trouble != "missing":
        hooks.mkdir()
        if trouble != "no-readme":
            (hooks / "README.md").write_text("x\n", encoding="utf-8")
    if trouble == "a-hook":
        (hooks / "pre-push").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    if trouble == "writable":
        world.seams.creatable.add(W.norm(hooks))
    monkeypatch.setattr(launcher, "hooks_folder", lambda: hooks, raising=False)
    res = spec(world, [msg("m1")])
    check.preflight_stop(res, "SELF_WRITABLE")


@pytest.mark.lr(80)
def test_lr80_every_git_command_uses_the_launchers_hooks_folder_and_nothing_lingers(world, check, launcher):
    res = spec(world, [msg("m1")])
    check.success(res)
    gits = [e for e in res.events if e.get("argv") and os.path.basename(e["argv"][0]).lower() in ("git", "git.exe")]
    assert gits, "no git command seen"
    for event in gits:
        argv = event["argv"]
        hooks = [a for a in argv if a.startswith("core.hooksPath=")]
        assert hooks and W.same_path(hooks[0].split("=", 1)[1], launcher.hooks_folder()), argv
        assert "gc.auto=0" in argv and "maintenance.auto=false" in argv, argv
        env = W.effective_env(event)
        assert env.get("GIT_CONFIG_NOSYSTEM") == "1" and env.get("GIT_NO_REPLACE_OBJECTS") == "1", argv
        assert W.same_path(env.get("GIT_GRAFT_FILE"), launcher.hooks_folder() / "no-grafts"), argv


@pytest.mark.lr(80)
def test_lr80_a_shallow_entry_of_the_model_reaching_the_own_repository_stops_the_run(world, check):
    res = spec(world, [{"op": "shallow_head"}, msg("m1")])
    check.post_model_stop(res, "GIT_REPO_UNSAFE")


@pytest.mark.lr(79)
@pytest.mark.lr(80)
def test_lr79_the_fetch_takes_no_tags_and_the_push_follows_none_and_runs_no_hook(world, check):
    res = spec(world, [msg("m1")])
    check.success(res)
    fetches, pushes = res.git_commands("fetch"), res.git_commands("push")
    after = [e for e in fetches if e["time"] > res.model["started"]]
    assert after and all("--no-tags" in e["argv"] for e in after), [e["argv"] for e in after]
    assert len(pushes) == 1 and {"--no-follow-tags", "--no-verify"} <= set(pushes[0]["argv"]), pushes[0]["argv"]


# ---------------------------------------------------------------- LR-79: no git with the clone as its repository
@pytest.mark.lr(79)
def test_lr79_no_git_command_after_the_model_runs_in_the_clone(world, check):
    res = spec(world, [msg("m1")])
    check.success(res)
    started = res.model["started"]
    clone = res.run_dir / "repo"
    after = [e for e in res.events if e.get("argv") and e["time"] > started
             and os.path.basename(e["argv"][0]).lower() in ("git", "git.exe")]
    assert after, "no git command after the model"
    for event in after:
        argv = event["argv"]
        repo = argv[argv.index("-C") + 1] if "-C" in argv else event.get("cwd")
        assert repo and not W.same_path(repo, clone), argv
        assert W.same_path(Path(repo).parent, res.run_dir) and Path(repo).name.startswith("post-"), argv
        assert len(Path(repo).name) == len("post-") + 32, argv


# ---------------------------------------------------------------- LR-80: the launcher's own repository is checked
@pytest.mark.lr(80)
def test_lr80_the_own_repository_is_refused_with_anything_that_changes_what_git_shows(launcher, tmp_path):
    start = "a" * 40
    for name in ("info/grafts", "objects/info/alternates", "objects/info/http-alternates", "commondir"):
        git_dir = tmp_path / name.replace("/", "-")
        (git_dir / name).parent.mkdir(parents=True, exist_ok=True)
        (git_dir / name).write_text("x\n", encoding="ascii")
        assert launcher.post_repo_problem(git_dir, start, "") == name
    clean = tmp_path / "clean"
    clean.mkdir()
    assert launcher.post_repo_problem(clean, start, "") is None
    assert launcher.post_repo_problem(clean, start, "refs/replace/" + "b" * 40 + "\n") == "refs/replace/"
    (clean / "shallow").write_text(start + "\n", encoding="ascii")
    assert launcher.post_repo_problem(clean, start, "") is None, "a spec run's own shallow start is allowed"
    (clean / "shallow").write_text(start + "\n" + "c" * 40 + "\n", encoding="ascii")
    assert launcher.post_repo_problem(clean, start, "") == "shallow"


# ---------------------------------------------------------------- LR-81: git's environment (S9)
INHERITED = {
    "GIT_EXEC_PATH": "C:\\xtl-planted\\exec-path",
    "GIT_ASKPASS": "C:\\xtl-planted\\askpass.exe",
    "GIT_SSL_NO_VERIFY": "1",
    "HTTPS_PROXY": "http://127.0.0.1:9",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "ALL_PROXY": "http://127.0.0.1:9",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES": "C:\\xtl-planted\\objects",
    "GIT_TEMPLATE_DIR": "C:\\xtl-planted\\templates",
}


@pytest.mark.lr(81)
@pytest.mark.parametrize("name", sorted(INHERITED))
def test_lr81_an_inherited_variable_never_reaches_git(world, check, monkeypatch, name):
    monkeypatch.setenv(name, INHERITED[name])
    res = spec(world, [msg("m1")])
    check.success(res)
    gits = [e for e in res.events if e.get("argv") and os.path.basename(e["argv"][0]).lower() in ("git", "git.exe")]
    assert gits
    for event in gits:
        assert name not in {k.upper() for k in W.effective_env(event)}, event["argv"]


@pytest.mark.lr(81)
@windows_only
def test_lr81_a_git_planted_early_on_path_is_not_used(world, check, monkeypatch, tmp_path):
    planted = tmp_path / "planted-bin"
    planted.mkdir()
    marker = tmp_path / "planted-git-ran"
    (planted / "git.bat").write_text(f"@echo ran > \"{marker}\"\r\n@exit /b 1\r\n", encoding="ascii")
    monkeypatch.setenv("PATH", str(planted) + os.pathsep + os.environ["PATH"])
    res = spec(world, [msg("m1")])
    check.success(res)
    assert not marker.exists(), "a git planted in an untrusted folder of PATH ran"


@pytest.mark.lr(81)
@pytest.mark.lr(67)
def test_lr81_the_filter_takes_windows_folders_from_the_system_not_the_environment(launcher, monkeypatch, tmp_path):
    planted = tmp_path / "Windows"
    monkeypatch.setenv("SystemRoot", str(planted))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    base = {"ppid": 1, "parent_image": "svchost.exe", "parent_path": None, "created": 10, "in_job": False,
            "broker": None}
    records = [
        {**base, "pid": 1, "image": "conhost.exe", "path": str(planted / "System32" / "conhost.exe")},
        {**base, "pid": 2, "image": "OpenConsole.exe", "path": str(
            tmp_path / "Program Files" / "WindowsApps" / "Microsoft.WindowsTerminal_1_x64__8wekyb3d8bbwe"
            / "OpenConsole.exe")},
    ]
    assert sorted(r["pid"] for r in launcher.outside_processes(records, since=0, exclude=set())) == [1, 2]


# ---------------------------------------------------------------- LR-82: an unknown owner is judged by its parent
@pytest.mark.lr(82)
def test_lr82_a_process_of_unknown_owner_is_judged_by_its_parent(launcher):
    base = {"ppid": 50, "image": "x.exe", "path": None, "parent_image": "svchost.exe", "parent_path": None,
            "created": 10, "in_job": False, "broker": None, "owner": "unknown", "session": 1, "same_session": True,
            "parent_owner": "unknown", "parent_in_job": False, "parent_alive": True}

    def rec(pid, **more):
        return {**base, "pid": pid, **more}

    records = [
        rec(1),                                                            # a live parent of another user: not foreign
        rec(2, parent_owner="other"),                                      # the operator's program: not foreign
        rec(3, ppid=999),                                                  # the launcher's child: foreign
        rec(4, parent_in_job=True),                                        # a job process's child: foreign
        rec(5, parent_owner="self"),                                       # a child of the user's process: foreign
        rec(6, parent_alive=False, parent_owner=None),                     # its parent is gone: foreign
        rec(7, broker="wmi", parent_image="WmiPrvSE.exe"),                 # WMI's child: foreign
        rec(8, broker="schedule"),                                         # the scheduler's, in this session: foreign
        rec(9, broker="schedule", same_session=False, session=0),          # the scheduler's, in session 0: not foreign
        rec(10, parent_alive=False, created=5),                            # older than the model: not counted
        rec(11, in_job=True, parent_alive=False),                          # in the job: not counted
    ]
    found = launcher.outside_processes(records, since=10, exclude={999})
    assert sorted(r["pid"] for r in found) == [3, 4, 5, 6, 7, 8]


@pytest.mark.lr(84)
def test_lr84_the_launchers_chain_is_its_ancestors_each_older_than_its_child(launcher):
    me = os.getpid()
    records = [{"pid": me, "ppid": 20, "created": 100}, {"pid": 20, "ppid": 30, "created": 90},
               {"pid": 30, "ppid": 40, "created": 80}, {"pid": 40, "ppid": 50, "created": 95},  # younger: not a parent
               {"pid": 50, "ppid": 0, "created": 1}, {"pid": 60, "ppid": me, "created": 110}]
    assert launcher.launcher_chain(records) == {me, 20, 30}


# ---------------------------------------------------------------- LR-82, LR-84: the reviewer's S4 child
def hidden_child(tmp_path, mode="dacl", seconds=40.0):
    """A child of the test (not of the launcher) that denies itself to OpenProcess, as the reviewer's did."""
    script = tmp_path / "hide.py"
    import fake_claude
    script.write_text(fake_claude.HIDE_SCRIPT, encoding="utf-8")
    flag = tmp_path / f"hidden-{mode}"
    python = getattr(sys, "_base_executable", sys.executable)  # not a venv's launcher, which starts a child
    with W.quiet_audit():
        process = subprocess.Popen([python, "-I", str(script), mode, str(flag), str(seconds)])
    deadline = time.time() + 30
    while time.time() < deadline and not flag.exists():
        time.sleep(0.05)
    assert flag.read_text(encoding="utf-8") == "0", "the child could not hide itself"
    return process


@pytest.mark.lr(82)
@pytest.mark.lr(67)
@windows_only
def test_lr82_the_s4_child_is_caught_while_the_model_runs_and_ended(world, check, tmp_path):
    pids_file = tmp_path / "hidden.pids"
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "wmi_hide", "mode": "dacl", "seconds": 40, "pids": str(pids_file)},
                           STAY])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
        assert res.duration < 45, f"the attempt ran {res.duration:.0f} s"
        assert wait_dead(pids, seconds=10) == [], "the hidden process outlived the attempt"
        assert str(pids[0]) in res.log_text
    finally:
        kill_all(pids)


@pytest.mark.lr(82)
@pytest.mark.lr(67)
@windows_only
def test_lr82_a_child_that_also_takes_away_its_owners_rights_is_caught_by_its_parent(world, check, tmp_path):
    pids_file = tmp_path / "hidden-ow.pids"
    res = spec(world, [msg("m1"), {"op": "wmi_hide", "mode": "owner-rights", "seconds": 25, "pids": str(pids_file)},
                       STAY])
    pid = int(pids_file.read_text(encoding="utf-8").split()[0])
    # Under the executor's standard user it cannot be opened (owner unknown, caught by its parent, WMI's provider host,
    # and it cannot be ended: PROCESS_SURVIVED). Under an administrator's user, as these tests run, WMI's child may
    # still be opened, and then it is ended: PROCESS_OUTSIDE_JOB. Either way it is caught and nothing is pushed.
    assert res.stop_code in ("PROCESS_SURVIVED", "PROCESS_OUTSIDE_JOB"), res.describe()
    check.post_model_stop(res, res.stop_code)
    assert str(pid) in res.log_text
    assert res.duration < 45, f"the attempt ran {res.duration:.0f} s"


@pytest.mark.lr(82)
@pytest.mark.lr(67)
@windows_only
def test_lr82_the_s4_child_is_caught_after_the_end(world, check, launcher, monkeypatch, tmp_path):
    pids_file = tmp_path / "hidden-late.pids"
    state = {"ended": False}
    listed, real_end = launcher.user_processes, launcher.job_end

    def job_end(job):
        state["ended"] = True
        return real_end(job)

    def scan(job):  # the hidden child is shown to the search only after the job has ended
        records = listed(job)
        return records if state["ended"] else []

    monkeypatch.setattr(launcher, "job_end", job_end)
    monkeypatch.setattr(launcher, "user_processes", scan)
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "wmi_hide", "mode": "dacl", "seconds": 40, "pids": str(pids_file)}])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_SURVIVED")
        assert wait_dead(pids, seconds=10) == [], "the hidden process found after the end was not ended"
        assert "search after the end" in res.log_text and str(pids[0]) in res.log_text
    finally:
        kill_all(pids)


@pytest.mark.lr(84)
@windows_only
def test_lr84_the_s4_child_left_from_an_earlier_run_stops_the_next_start(world, check, tmp_path):
    child = hidden_child(tmp_path, "dacl", seconds=30)
    try:
        world.foreign_file.write_text(f"{child.pid}\n", encoding="utf-8")
        res = spec(world, [msg("m1")])
        check.preflight_stop(res, "PROCESS_AT_START")
        assert str(child.pid) in res.log_text
    finally:
        world.foreign_file.write_text("", encoding="utf-8")
        kill_all([child.pid])


@pytest.mark.lr(84)
@windows_only
def test_lr84_a_plain_process_of_the_user_stops_the_start(world, check):
    with W.quiet_audit():
        stray = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        world.foreign_file.write_text(f"{stray.pid}\n", encoding="utf-8")
        res = spec(world, [msg("m1")])
        check.preflight_stop(res, "PROCESS_AT_START")
    finally:
        world.foreign_file.write_text("", encoding="utf-8")
        kill_all([stray.pid])


@pytest.mark.lr(84)
@pytest.mark.lr(67)
@windows_only
def test_lr84_a_process_started_between_the_start_check_and_the_model_is_caught(world, check):
    strays = []

    def start_stray():  # during the token's minting, after the preflight and before the model
        if strays:
            return
        with W.quiet_audit():
            stray = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        strays.append(stray.pid)
        world.foreign_file.write_text(f"{stray.pid}\n", encoding="utf-8")

    world.api.after("GET", r"^/app/installations", start_stray)
    try:
        res = spec(world, [msg("m1"), {"op": "pause", "seconds": 3}])
        check.stopped(res, "PROCESS_OUTSIDE_JOB")  # the first search can stop the model before it writes anything
        assert not res.pushed and res.git_commands("push") == []
        assert one_attempt(world, res)[2]["outcome"] == "PROCESS_OUTSIDE_JOB"
        assert strays and wait_dead(strays, seconds=10) == []
    finally:
        kill_all(strays)


# ---------------------------------------------------------------- LR-83: the search before the push (S5)
@pytest.mark.lr(83)
@pytest.mark.lr(82)
@windows_only
@pytest.mark.parametrize("kind", ["plain", "owner-rights"])
def test_lr83_a_process_started_after_the_last_search_stops_the_push(world, check, tmp_path, kind):
    """`owner-rights`: a child that takes away its owner's rights has an unknown owner; its parent is the launcher's
    own process (the tests run the launcher in this process), so it is foreign (LR-82)."""
    world.set_up_fix(comments=False)
    seen, strays = {"reads": 0}, []

    def second_read():
        seen["reads"] += 1
        return seen["reads"] == 2  # LR-38's re-read, after the search after the end and the checks

    def start_stray():
        if kind == "plain":
            with W.quiet_audit():
                stray = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        else:
            stray = hidden_child(tmp_path, "owner-rights", seconds=20)
        strays.append(stray.pid)
        with open(world.foreign_file, "a", encoding="utf-8") as fh:
            fh.write(f"{stray.pid}\n")

    world.api.after("GET", rf"^/repos/{W.REPOSITORY}/pulls/{W.PR_NUMBER}(\?|$)", start_stray, when=second_read)
    try:
        res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[
            {"op": "commit", "path": "app/fix.py", "text": "def fix():\n    return 3\n", "message": "Fix the thing"},
            msg("m1")])
        check.post_model_stop(res, "PROCESS_BEFORE_PUSH")
        assert strays and str(strays[0]) in res.log_text
        if kind == "plain":
            assert wait_dead(strays, seconds=10) == [], "the process found before the push was not ended"
        else:
            assert "owner unknown" in res.log_text and "it could not be ended" in res.log_text
    finally:
        kill_all(strays)


# ---------------------------------------------------------------- LR-85: the search in every wait (S7)
@pytest.mark.lr(85)
@windows_only
def test_lr85_a_process_started_during_the_grace_is_caught_in_the_grace(world, check, tmp_path):
    pids_file = tmp_path / "grace.pids"
    pids = []
    try:
        res = spec(world, [{"op": "ignore_break"}, {"op": "burst", "count": 3, "prefix": "b"},
                           {"op": "pause", "seconds": 1}, {"op": "wmi_spawn", "pids": str(pids_file)},
                           {"op": "pause", "seconds": 30}], "--max-messages", "2")
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
        assert one_attempt(world, res)[2]["outcome"] == "PROCESS_OUTSIDE_JOB"
        assert wait_dead(pids, seconds=10) == []
    finally:
        kill_all(pids)


@pytest.mark.lr(85)
@windows_only
def test_lr85_a_process_started_after_the_stream_ends_is_caught_in_the_wait(world, check, tmp_path):
    # The base interpreter: a virtual environment's launcher would keep a copy of the output open, so the stream
    # would not end before the model's process does.
    world.set_config(claude_command=[getattr(sys, "_base_executable", sys.executable), str(W.FAKE_CLAUDE)])
    pids_file = tmp_path / "wait.pids"
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "close_stdout"}, {"op": "wmi_spawn", "pids": str(pids_file)},
                           {"op": "pause", "seconds": 4}])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
        assert wait_dead(pids, seconds=10) == []
    finally:
        kill_all(pids)


# ---------------------------------------------------------------- LR-86: Claude Code's image (S8)
@pytest.mark.lr(86)
@windows_only
def test_lr86_an_image_without_exe_is_refused_at_the_start(world, check, tmp_path):
    command = tmp_path / "claude.cmd"
    command.write_text("@exit /b 0\r\n", encoding="ascii")
    world.config.pop("claude_image")
    world.set_config(claude_command=[str(command)])
    res = spec(world, [msg("m1")])
    check.preflight_stop(res, "CLAUDE_IMAGE")


@pytest.mark.lr(86)
@windows_only
def test_lr86_the_default_image_is_what_the_command_resolves_to(launcher, monkeypatch, tmp_path):
    (tmp_path / "xtlclaude.exe").write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    assert launcher.default_claude_image("xtlclaude").lower() == "xtlclaude.exe"
    assert launcher.default_claude_image("no-such-command-xtl") == "no-such-command-xtl"
