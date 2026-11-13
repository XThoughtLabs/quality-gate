"""Stage A2: the repairs after the review (LR-67 to LR-78), written from LAUNCHER-CONTRACT.md section 13.

Each test is named and marked by its rule. The tests of processes run on Windows only."""

from __future__ import annotations

import _thread
import json
import os
import subprocess
import sys
import threading
import time

import pytest

import launcher_world as W
from stage_a_kit import (COMMIT, SLUG, kill_all, logged_pid, msg, one_attempt, read_json, result, spec,
                         wait_dead)

windows_only = pytest.mark.skipif(os.name != "nt", reason="the job object and the process scan exist on Windows only")
STAY = {"op": "pause", "seconds": 60}
SYSTEMROOT = os.environ.get("SystemRoot", "C:\\Windows")


def finished_of(world, res):
    return one_attempt(world, res)[2]


# ---------------------------------------------------------------- LR-67: processes outside the job
@pytest.mark.lr(67)
@windows_only
def test_lr67_a_wmi_process_stops_the_attempt_and_is_ended(world, check, tmp_path):
    pids_file = tmp_path / "wmi.pids"
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "wmi_spawn", "pids": str(pids_file)}, STAY])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
        assert res.duration < 45, f"the attempt ran {res.duration:.0f} s"
        assert wait_dead(pids, seconds=10) == [], "the process WMI started outlived the attempt"
        assert finished_of(world, res)["outcome"] == "PROCESS_OUTSIDE_JOB"
        assert str(pids[0]) in res.log_text and "PING.EXE" in res.log_text.upper()
    finally:
        kill_all(pids)


@pytest.mark.lr(67)
@windows_only
def test_lr67_a_process_found_after_the_end_is_ended_and_the_run_is_process_survived(world, check, launcher,
                                                                                     monkeypatch):
    with W.quiet_audit():
        stray = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    calls = {"after": 0}

    def scan(job):
        if launcher.job_count(job) == 0:  # the job has ended: this is the search after the model
            calls["after"] += 1
            return [{"pid": stray.pid, "ppid": 0, "image": "python.exe", "path": sys.executable,
                     "parent_image": "WmiPrvSE.exe", "parent_path": None, "created": launcher.now_filetime(),
                     "in_job": False, "broker": "wmi"}]
        return []

    try:
        monkeypatch.setattr(launcher, "user_processes", scan)
        res = spec(world, [msg("m1")])
        check.post_model_stop(res, "PROCESS_SURVIVED")
        assert calls["after"] >= 1
        assert wait_dead([stray.pid], seconds=10) == [], "the process found after the end was not ended"
        assert str(stray.pid) in res.log_text
    finally:
        kill_all([stray.pid])


@pytest.mark.lr(67)
def test_lr67_the_filter(launcher):
    start = 1000
    # LR-90 (amendment Stage A4): an allowed image needs a live parent of another owner (here a service's svchost),
    # and conhost.exe a parent in the job; so record 1, a conhost under svchost, became foreign, and 16 passes.
    base = {"ppid": 1, "path": SYSTEMROOT + "\\System32\\conhost.exe", "parent_image": "svchost.exe",
            "parent_path": SYSTEMROOT + "\\System32\\svchost.exe", "created": start + 5, "in_job": False,
            "broker": None, "parent_owner": "other", "parent_alive": True}

    def rec(pid, image, **more):
        return {**base, "pid": pid, "image": image, **more}

    records = [
        rec(1, "conhost.exe"),                                                  # Windows' own: allowed
        rec(2, "PING.EXE", path=SYSTEMROOT + "\\System32\\PING.EXE"),          # not on the list: foreign
        rec(3, "conhost.exe", broker="wmi", parent_image="WmiPrvSE.exe"),      # WMI's child: always foreign
        rec(4, "conhost.exe", broker="schedule"),                               # the scheduler's: always foreign
        rec(5, "python.exe", in_job=True),                                      # the model's own: not counted
        rec(6, "python.exe", created=start - 1),                                # older than the model: not counted
        rec(7, "conhost.exe", path="C:\\Temp\\conhost.exe"),                   # a copy outside Windows: foreign
        rec(8, "python.exe"),                                                   # the launcher itself: excluded
        rec(9, "taskhostw.exe", path=SYSTEMROOT + "\\System32\\taskhostw.exe", broker="schedule"),
        rec(10, "backgroundTaskHost.exe", path=SYSTEMROOT + "\\System32\\backgroundTaskHost.exe"),  # Windows' own
        rec(11, "smartscreen.exe", path=SYSTEMROOT + "\\System32\\smartscreen.exe"),                # Windows' own
        rec(12, "dllhost.exe", path=SYSTEMROOT + "\\System32\\dllhost.exe"),                        # Windows' own
        rec(13, "RuntimeBroker.exe", path=SYSTEMROOT + "\\System32\\RuntimeBroker.exe"),            # Windows' own
        rec(14, "OpenConsole.exe", path=os.environ.get("ProgramFiles", "C:\\Program Files")
            + "\\WindowsApps\\Microsoft.WindowsTerminal_1.24.12741.0_x64__8wekyb3d8bbwe\\OpenConsole.exe"),
        rec(15, "powershell.exe", path=SYSTEMROOT + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        rec(16, "conhost.exe", parent_in_job=True, parent_owner="self"),             # a job process's console host
    ]
    found = launcher.outside_processes(records, since=start, exclude={8})
    assert sorted(p["pid"] for p in found) == [1, 2, 3, 4, 7, 9, 15]


@pytest.mark.lr(67)
@pytest.mark.lr(77)
@windows_only
def test_lr67_lr77_the_real_scan_sees_a_wmi_process_as_foreign(launcher):
    env = dict(os.environ, XTL_CMD=SYSTEMROOT + "\\System32\\PING.EXE -n 30 127.0.0.1")
    command = "(Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$env:XTL_CMD}).ProcessId"
    since = launcher.now_filetime()
    job = launcher.job_open()
    with W.quiet_audit():
        pid = int(subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                                 capture_output=True, text=True, env=env, check=True).stdout.strip())
    try:
        records = {p["pid"]: p for p in launcher.user_processes(job)}
        assert pid in records, "the scan does not list the WMI-created process"
        found = records[pid]
        assert found["image"].lower() == "ping.exe" and found["in_job"] is False
        assert found["parent_image"].lower() == "wmiprvse.exe" and found["broker"] == "wmi"
        assert found["created"] >= since
        assert pid in {p["pid"] for p in launcher.outside_processes(list(records.values()), since=since, exclude=set())}
        assert os.getpid() in records, "the scan does not see this user's own processes"
    finally:
        launcher.job_close(job)
        kill_all([pid])


@pytest.mark.lr(67)
@pytest.mark.lr(77)
@windows_only
def test_lr67_lr77_the_real_scan_sees_a_process_in_the_job_as_inside(launcher):
    since = launcher.now_filetime()
    job = launcher.job_open()
    with W.quiet_audit():
        process = subprocess.Popen([SYSTEMROOT + "\\System32\\PING.EXE", "-n", "30", "127.0.0.1"],
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | 0x4)
    try:
        launcher.job_add(job, process)
        launcher.resume_process(process.pid)
        records = {p["pid"]: p for p in launcher.user_processes(job)}
        assert records[process.pid]["in_job"] is True
        assert process.pid not in {p["pid"] for p in launcher.outside_processes(list(records.values()), since, set())}
    finally:
        launcher.job_close(job)
        kill_all([process.pid])


# ---------------------------------------------------------------- LR-68: a second Claude Code
@pytest.mark.lr(68)
@windows_only
def test_lr68_a_second_claude_code_stops_the_attempt_and_charges_its_limit(world, check, tmp_path):
    world.set_config(claude_image="PING.EXE")
    pids_file = tmp_path / "twin.pids"
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "spawn_listed", "pids": str(pids_file),
                                       "argv": [SYSTEMROOT + "\\System32\\PING.EXE", "-n", "30", "127.0.0.1"]}, STAY])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "SECOND_MODEL")
        assert res.duration < 45
        reserved, messages, finished = one_attempt(world, res)
        assert finished["outcome"] == "SECOND_MODEL" and finished["count_complete"] is False
        assert finished["messages"] == reserved["limit"] and len(messages) == 1
        assert wait_dead(pids, seconds=10) == []
    finally:
        kill_all(pids)


@pytest.mark.lr(68)
@windows_only
def test_lr68_the_model_itself_is_not_a_second_model(world, check):
    world.set_config(claude_image="python.exe")  # the image of the process the launcher starts here
    res = spec(world, [{"op": "list_parent"}, msg("m1"), {"op": "pause", "seconds": 2.5}])
    check.success(res)


@pytest.mark.lr(68)
def test_lr68_claude_image_must_be_a_file_name(world, check):
    world.set_config(claude_image="")
    check.config_error(world.run("check"))


# ---------------------------------------------------------------- LR-69: the verified commit
def _fix_steps():
    return [{"op": "commit", "path": "app/fix.py", "text": "def fix():\n    return 3\n", "message": "Fix the thing"},
            msg("m1")]


@pytest.mark.lr(69)
def test_lr69_a_commit_made_after_the_checks_is_not_pushed(world, check):
    world.set_up_fix(comments=False)
    seen = {"reads": 0}

    def second_read():
        seen["reads"] += 1
        return seen["reads"] == 2  # the first read is the round's start; the second is LR-38's, after the checks

    def add_commit():
        repo = next(p for p in world.runs_dir.iterdir() if p.is_dir() and p.name != "logs") / "repo"
        with W.quiet_audit():
            W.git("-C", str(repo), "-c", f"user.name={W.BOT_LOGIN}", "-c", f"user.email={W.BOT_EMAIL}",
                  "-c", f"core.hooksPath={repo / 'no-hooks-here'}", "commit", "-q", "--allow-empty",
                  "-m", "ADDED-AFTER-THE-CHECKS")

    world.api.after("GET", rf"^/repos/{W.REPOSITORY}/pulls/{W.PR_NUMBER}(\?|$)", add_commit, when=second_read)
    res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=_fix_steps())
    check.success(res)
    tip = res.refs_after[f"refs/heads/{W.PR_BRANCH}"]
    subjects = [c["subject"] for c in W.commits_between(world.remote, world.facts.pr_head, tip)]
    assert subjects == ["Fix the thing"], subjects
    push = res.git_commands("push")[0]["argv"]
    assert f"{tip}:refs/heads/{W.PR_BRANCH}" in push and "origin" not in push
    assert W.same_path(push[push.index("push") + 1], world.config["repo_url"])


# ---------------------------------------------------------------- LR-70: the model's git settings
CONFIG_TEXTS = {
    "url-insteadof": '[url "https://example.invalid/"]\n\tinsteadOf = https://github.com/\n',
    "credential-helper": "[credential]\n\thelper = !echo planted\n",
    "http-proxy": "[http]\n\tproxy = http://127.0.0.1:9\n\tsslVerify = false\n",
    "core-askpass": "[core]\n\taskPass = planted-askpass\n",
    "core-sshcommand": "[core]\n\tsshCommand = planted-ssh\n",
    "include-path": "[include]\n\tpath = ../planted.gitconfig\n",
    "core-fsmonitor": "[core]\n\tfsmonitor = planted-fsmonitor\n",
    "core-hookspath": "[core]\n\thooksPath = ../planted-hooks\n",
    "remote-pushurl": '[remote "origin"]\n\tpushurl = https://example.invalid/elsewhere.git\n',
}


@pytest.mark.lr(70)
@pytest.mark.parametrize("name", sorted(CONFIG_TEXTS))
def test_lr70_a_setting_written_into_the_clones_config_stops_the_run(world, check, name):
    res = spec(world, [{"op": "write", "path": ".git/config", "text": CONFIG_TEXTS[name]}, msg("m1")])
    check.post_model_stop(res, "GIT_CONFIG_CHANGED")


@pytest.mark.lr(70)
def test_lr70_a_git_file_in_place_of_the_folder_stops_the_run(world, check):
    res = spec(world, [{"op": "gitfile"}, msg("m1")])
    check.post_model_stop(res, "GIT_CONFIG_CHANGED")


@pytest.mark.lr(70)
def test_lr70_a_hook_the_model_wrote_does_not_run(world, check, tmp_path):
    marker = tmp_path / "hook-ran"
    hook = f"#!/bin/sh\necho ran > '{marker.as_posix()}'\nexit 0\n"
    res = spec(world, [{"op": "write", "path": ".git/hooks/pre-commit", "text": hook},
                       {"op": "write", "path": ".git/hooks/pre-push", "text": hook},
                       {"op": "write", "path": "acceptance/left.py", "text": "left = 1\n"}, msg("m1")])
    check.success(res)
    assert not marker.exists(), "a hook the model wrote ran during the launcher's git commands"
    assert "Changes left uncommitted by the executor" in [c["subject"] for c in W.commits_between(
        world.remote, world.facts.base_head, res.refs_after["refs/heads/spec/" + SLUG])]


@pytest.mark.lr(70)
@pytest.mark.lr(80)
def test_lr70_every_git_command_ignores_the_global_config_and_hooks(world, check, launcher):
    res = spec(world, [msg("m1")])
    check.success(res)
    gits = [e for e in res.events if e.get("argv") and os.path.basename(e["argv"][0]).lower() in ("git", "git.exe")]
    assert gits, "no git command seen"
    for event in gits:
        assert W.effective_env(event).get("GIT_CONFIG_GLOBAL") == os.devnull, event["argv"]
        hooks = [a for a in event["argv"] if a.startswith("core.hooksPath=")]
        # LR-80 (amendment Stage A3) replaced LR-70's <run>/no-hooks by the launcher's own read-only hooks folder.
        assert hooks and W.same_path(hooks[0].split("=", 1)[1], launcher.hooks_folder()), event["argv"]


@pytest.mark.lr(70)
@pytest.mark.lr(81)
def test_lr70_the_users_global_git_config_is_not_read(world, check, tmp_path, monkeypatch):
    # S6: a setting that the command line's -c does not override; the push would go elsewhere if it acted.
    home = tmp_path / "home"
    (home / ".config" / "git").mkdir(parents=True)
    repo_url = world.config["repo_url"].replace("\\", "\\\\")
    planted = f'[url "C:/xtl-nowhere/"]\n\tinsteadOf = {repo_url}\n[push]\n\tfollowTags = true\n'
    for config in (home / ".gitconfig", home / ".config" / "git" / "config"):
        config.write_text(planted, encoding="utf-8")
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(name, str(home) if name != "XDG_CONFIG_HOME" else str(home / ".config"))
    res = spec(world, [msg("m1")])
    check.success(res)  # with the planted url.insteadOf read, the push would fail


# ---------------------------------------------------------------- LR-71: reading the stream to its end
@pytest.mark.lr(71)
def test_lr71_on_ctrl_c_the_messages_already_written_are_counted(world, check, tmp_path):
    marker = tmp_path / "burst-written"

    def interrupt_when_ready():
        deadline = time.time() + 120
        while time.time() < deadline and not marker.exists():
            time.sleep(0.01)
        _thread.interrupt_main()

    world.remote_commit(W.INTEGRATION, {"quality.toml": W.quality_toml(max_turns=500)}, message="More turns")
    world.set_config(max_messages_attempt=500, max_messages_task=1000)
    helper = threading.Thread(target=interrupt_when_ready, daemon=True)
    helper.start()
    res = spec(world, [{"op": "burst", "count": 300, "prefix": "b"}, {"op": "marker", "file": str(marker)},
                       {"op": "pause", "seconds": 90}])
    helper.join(timeout=5)
    check.stopped(res, "INTERRUPTED")
    _, messages, finished = one_attempt(world, res)
    assert finished["outcome"] == "INTERRUPTED"
    assert finished["count_complete"] is True and finished["messages"] == 300
    # Ctrl+C can land inside one message's ledger append; that message is still counted, and the attempt's
    # charge is the larger of `messages` and the records (LR-56).
    assert 299 <= len(messages) <= 300


@pytest.mark.lr(71)
@windows_only
def test_lr71_an_unfinished_read_records_the_limit(world, check, launcher, monkeypatch):
    monkeypatch.setattr(launcher, "job_end", lambda job: 1)  # the job is not ended: the stream stays open
    bad = [{"op": "line", "text": f"bad {n}"} for n in range(11)]  # STREAM_UNREADABLE after one message
    res = spec(world, [{"op": "ignore_break"}, msg("m1"), *bad, STAY], "--max-messages", "5")
    check.stopped(res, "PROCESS_SURVIVED")
    reserved, messages, finished = one_attempt(world, res)
    assert finished["count_complete"] is False and finished["messages"] == 5 and len(messages) == 1


@pytest.mark.lr(71)
def test_lr71_a_finished_record_without_count_complete_is_still_read(world, check):
    from stage_a_kit import finished_record, reserved_record
    world.seed_ledger([reserved_record("spec-other", "old-1", 7), finished_record("old-1", 1)])
    res = spec(world, [msg("m1")])
    check.success(res)
    assert finished_of(world, res)["count_complete"] is True


# ---------------------------------------------------------------- LR-72: a line that cannot be parsed
@pytest.mark.lr(72)
def test_lr72_a_deeply_nested_assistant_event_counts_and_stops(world, check):
    res = spec(world, [msg("m1"), {"op": "deep_assistant", "depth": 20000}, STAY])
    check.post_model_stop(res, "STREAM_UNREADABLE")
    _, messages, finished = one_attempt(world, res)
    assert finished["messages"] == 2
    assert [m["generated"] for m in sorted(messages, key=lambda m: m["ordinal"])] == [False, True]


# ---------------------------------------------------------------- LR-73: the job's log
@pytest.mark.lr(73)
@windows_only
def test_lr73_the_log_names_each_step_of_the_end(world, check):
    res = spec(world, [{"op": "burst", "count": 3, "prefix": "b"}, STAY], "--max-messages", "2")
    check.post_model_stop(res, "MESSAGE_LIMIT")
    log = res.log_text
    for piece in ("processes alive before TerminateJobObject", "grace begins", "grace ends",
                  "TerminateJobObject called", "processes left after TerminateJobObject"):
        assert piece in log, piece


@pytest.mark.lr(73)
@windows_only
def test_lr73_children_still_running_after_a_model_that_ended_by_itself_are_logged(world, check, tmp_path):
    pids_file = tmp_path / "family.json"
    pids = []
    try:
        res = spec(world, [{"op": "spawn_family", "pids": str(pids_file)}, msg("m1")])
        pids = list(read_json(pids_file).values())
        check.success(res)
        assert "processes still running after the model ended by itself" in res.log_text
    finally:
        kill_all(pids)


# ---------------------------------------------------------------- LR-74: a started process outside the job
@pytest.mark.lr(74)
@windows_only
def test_lr74_a_process_started_but_not_put_into_the_job_is_killed(world, check, launcher, monkeypatch):
    def interrupted(job, process):
        raise KeyboardInterrupt

    monkeypatch.setattr(launcher, "job_add", interrupted)
    res = spec(world, [msg("m1")])
    check.stopped(res, "INTERRUPTED")
    assert wait_dead([logged_pid(res)], seconds=10) == [], "the suspended process outside the job was left alive"


# ---------------------------------------------------------------- LR-76: the timeout's ceiling
@pytest.mark.lr(76)
@pytest.mark.parametrize("minutes, code", [(60, "TIMEOUT_TOO_LONG"), (59, None)])
def test_lr76_a_timeout_above_59_minutes_is_refused(world, check, minutes, code):
    world.remote_commit(W.INTEGRATION, {"quality.toml": W.quality_toml(timeout_minutes=minutes)},
                        message="A longer timeout")
    res = spec(world, [msg("m1")])
    if code:
        check.stopped(res, code)
        assert res.model is None, "the model ran"
    else:
        check.success(res)
