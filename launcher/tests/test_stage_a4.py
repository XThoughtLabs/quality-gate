"""Stage A4: the third review's findings M1, M2 and L1 to L4 (LR-89 to LR-95), written from LAUNCHER-CONTRACT.md
section 15. Each test is named and marked by its rule; the tests of processes run on Windows only."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

import launcher_world as W
from stage_a_kit import COMMIT, SLUG, kill_all, msg, of_kind, spec, wait_dead

windows_only = pytest.mark.skipif(os.name != "nt", reason="the job object and the process list exist on Windows only")
SYSTEMROOT = os.environ.get("SystemRoot", "C:\\Windows")
DLLHOST = os.path.join(SYSTEMROOT, "System32", "dllhost.exe")


def hidden_child(tmp_path, seconds):
    """A child of the test (in the tests, the launcher's own process) that takes away even its owner's rights."""
    import fake_claude
    script = tmp_path / "hide.py"
    script.write_text(fake_claude.HIDE_SCRIPT, encoding="utf-8")
    flag = tmp_path / f"hidden-{time.monotonic_ns()}"
    python = getattr(sys, "_base_executable", sys.executable)  # not a venv's launcher, which starts a child
    with W.quiet_audit():
        process = subprocess.Popen([python, "-I", str(script), "owner-rights", str(flag), str(seconds)])
    deadline = time.time() + 30
    while time.time() < deadline and not flag.exists():
        time.sleep(0.05)
    assert flag.read_text(encoding="utf-8") == "0", "the child could not hide itself"
    return process


def unended(world, pid):
    return [r for r in of_kind(world.ledger_records(), "process_unended") if r["pid"] == pid]


# ---------------------------------------------------------------- LR-89: a process that cannot be ended (M1)
@pytest.mark.lr(89)
@windows_only
def test_lr89_an_unendable_process_is_reported_recorded_and_refused_until_it_is_gone(world, check, launcher, tmp_path):
    children = []

    def start_child():  # after the start check and before the model: the search while it runs finds it
        if not children:
            children.append(hidden_child(tmp_path, seconds=14))
            world.foreign_file.write_text(f"{children[0].pid}\n", encoding="utf-8")

    world.api.after("GET", r"^/app/installations", start_child)
    try:
        res = spec(world, [msg("m1"), {"op": "pause", "seconds": 3}])
        pid = children[0].pid
        assert res.stop_code in ("PROCESS_OUTSIDE_JOB", "PROCESS_SURVIVED"), res.describe()
        check.stopped(res, res.stop_code)
        assert not res.pushed
        assert "could not be ended" in res.log_text and "it is ended" not in res.log_text
        assert "restart Windows" in res.last and "was ended" not in res.last, res.last
        records = unended(world, pid)
        assert len(records) == 1, "recorded once"
        assert records[0]["created"] > 0 and records[0]["attempt"] == res.run_dir.name
        nxt = spec(world, [msg("m1")])
        # the preflight's refusal (check.preflight_stop counts the world's tokens of the first run too)
        assert nxt.code == 1 and nxt.stop_code == "PROCESS_UNENDED", nxt.describe()
        assert nxt.requests == [] and nxt.run_dirs == [] and nxt.model is None
        assert "Restart Windows" in nxt.last and str(pid) in nxt.log_text
        # wait_dead opens the process, which this child refuses: wait on the process list instead
        deadline = time.time() + 30
        while time.time() < deadline and launcher.process_alive(pid, records[0]["created"]):
            time.sleep(0.2)
        assert not launcher.process_alive(pid, records[0]["created"]), "the hidden child did not end by itself"
        world.foreign_file.write_text("", encoding="utf-8")
        after = spec(world, [msg("m1")])
        check.success(after)  # the refusal ends once the process is gone
    finally:
        kill_all([c.pid for c in children])


@pytest.mark.lr(89)
@windows_only
def test_lr89_the_search_after_the_end_says_could_not_be_ended_and_records_it(world, check, launcher, monkeypatch,
                                                                              tmp_path):
    children, state = [], {"ended": False}
    listed, real_end = launcher.user_processes, launcher.job_end

    def start_child():
        if not children:
            children.append(hidden_child(tmp_path, seconds=12))
            world.foreign_file.write_text(f"{children[0].pid}\n", encoding="utf-8")

    def job_end(job):
        state["ended"] = True
        return real_end(job)

    monkeypatch.setattr(launcher, "job_end", job_end)
    monkeypatch.setattr(launcher, "user_processes", lambda job: listed(job) if state["ended"] else [])
    world.api.after("GET", r"^/app/installations", start_child)
    try:
        res = spec(world, [msg("m1")])
        check.post_model_stop(res, "PROCESS_SURVIVED")
        assert "search after the end" in res.log_text and "could not be ended" in res.log_text
        assert "it is ended" not in res.log_text
        assert "restart Windows" in res.last
        assert len(unended(world, children[0].pid)) == 1
    finally:
        kill_all([c.pid for c in children])


@pytest.mark.lr(89)
@pytest.mark.lr(83)
@windows_only
def test_lr89_the_search_before_the_push_records_what_it_could_not_end(world, check, tmp_path):
    world.set_up_fix(comments=False)
    seen, children = {"reads": 0}, []

    def second_read():
        seen["reads"] += 1
        return seen["reads"] == 2

    def start_child():
        children.append(hidden_child(tmp_path, seconds=12))
        world.foreign_file.write_text(f"{children[0].pid}\n", encoding="utf-8")

    world.api.after("GET", rf"^/repos/{W.REPOSITORY}/pulls/{W.PR_NUMBER}(\?|$)", start_child, when=second_read)
    try:
        res = world.run("fix", "--pr", str(W.PR_NUMBER), steps=[
            {"op": "commit", "path": "app/fix.py", "text": "def fix():\n    return 3\n", "message": "Fix the thing"},
            msg("m1")])
        check.post_model_stop(res, "PROCESS_BEFORE_PUSH")
        assert "restart Windows" in res.last and "was ended" not in res.last
        assert len(unended(world, children[0].pid)) == 1
    finally:
        kill_all([c.pid for c in children])


@pytest.mark.lr(89)
def test_lr89_the_ledger_reads_a_process_record_after_its_attempt_has_finished(world, check):
    from stage_a_kit import finished_record, reserved_record
    record = {"record": "process_unended", "attempt": "old-1", "pid": 4, "created": 1, "image": "x.exe",
              "time": "2026-11-13T00:00:03Z"}
    world.seed_ledger([reserved_record("spec-other", "old-1", 7), finished_record("old-1", 1), record])
    res = spec(world, [msg("m1")])
    check.success(res)  # pid 4 with creation time 1 is no live process


# ---------------------------------------------------------------- LR-90: an allowed image and its parent (M2)
@pytest.mark.lr(90)
@windows_only
def test_lr90_the_reviewers_dllhost_under_the_launcher_is_flagged_while_the_model_runs(world, check, tmp_path):
    pids_file = tmp_path / "spoofed.pids"
    pids = []
    try:
        res = spec(world, [msg("m1"), {"op": "spoof_parent", "parent": os.getpid(), "image": DLLHOST,
                                       "pids": str(pids_file)}, {"op": "pause", "seconds": 60}])
        pids = [int(x) for x in pids_file.read_text(encoding="utf-8").split()]
        check.post_model_stop(res, "PROCESS_OUTSIDE_JOB")
        assert res.duration < 45, f"the attempt ran {res.duration:.0f} s"
        assert wait_dead(pids, seconds=10) == []
    finally:
        kill_all(pids)


@pytest.mark.lr(90)
@pytest.mark.lr(84)
@windows_only
def test_lr90_a_dllhost_of_the_users_own_process_stops_the_next_start(world, check):
    with W.quiet_audit():
        stray = subprocess.Popen([DLLHOST], creationflags=0x4 | 0x08000000)  # suspended, no window
    try:
        world.foreign_file.write_text(f"{stray.pid}\n", encoding="utf-8")
        res = spec(world, [msg("m1")])
        check.preflight_stop(res, "PROCESS_AT_START")
    finally:
        world.foreign_file.write_text("", encoding="utf-8")
        kill_all([stray.pid])


@pytest.mark.lr(90)
def test_lr90_each_allowed_image_passes_only_under_a_live_parent_of_another_user(launcher):
    sys32 = SYSTEMROOT + "\\System32\\"
    terminal = (os.environ.get("ProgramFiles", "C:\\Program Files")
                + "\\WindowsApps\\Microsoft.WindowsTerminal_1.24.12741.0_x64__8wekyb3d8bbwe\\OpenConsole.exe")
    service = {"ppid": 900, "parent_image": "svchost.exe", "parent_path": sys32 + "svchost.exe", "created": 10,
               "in_job": False, "broker": None, "owner": "self", "parent_owner": "other", "parent_alive": True,
               "parent_in_job": False}
    images = {"dllhost.exe": sys32 + "dllhost.exe", "RuntimeBroker.exe": sys32 + "RuntimeBroker.exe",
              "backgroundTaskHost.exe": sys32 + "backgroundTaskHost.exe", "smartscreen.exe": sys32 + "smartscreen.exe",
              "OpenConsole.exe": terminal}
    passing = [{**service, "pid": n, "image": image, "path": path} for n, (image, path) in enumerate(images.items(), 1)]
    passing += [{**service, "pid": 6, "image": "dllhost.exe", "path": sys32 + "dllhost.exe", "parent_owner": "unknown"},
                {**service, "pid": 7, "image": "conhost.exe", "path": sys32 + "conhost.exe", "parent_in_job": True,
                 "parent_owner": "self"}]
    assert launcher.outside_processes(passing, since=0, exclude={999}) == []
    failing = [
        {**service, "pid": 11, "image": "dllhost.exe", "path": sys32 + "dllhost.exe", "parent_owner": "self"},
        {**service, "pid": 12, "image": "dllhost.exe", "path": sys32 + "dllhost.exe", "ppid": 999},
        {**service, "pid": 13, "image": "dllhost.exe", "path": sys32 + "dllhost.exe", "parent_alive": False,
         "parent_owner": None},
        {**service, "pid": 14, "image": "conhost.exe", "path": sys32 + "conhost.exe"},
        {**service, "pid": 15, "image": "conhost.exe", "path": sys32 + "conhost.exe", "ppid": 999,
         "parent_owner": "self"},
        {**service, "pid": 16, "image": "OpenConsole.exe", "path": terminal, "parent_owner": "self"},
    ]
    assert sorted(r["pid"] for r in launcher.outside_processes(failing, since=0, exclude={999})) == \
        [11, 12, 13, 14, 15, 16]
    # at the start check, the chain's own console host passes (there is no job)
    assert launcher.outside_processes([failing[4]], since=0, exclude={999}, console_parents={999}) == []


# ---------------------------------------------------------------- LR-91: line endings (L1)
@pytest.mark.lr(91)
def test_lr91_a_crlf_file_the_model_committed_cleanly_gives_no_leftover_commit(world, check):
    res = spec(world, [{"op": "commit", "path": "acceptance/test_crlf.py", "text": "a = 1\r\nb = 2\r\n",
                        "message": "Add a CRLF file"}, msg("m1")])
    check.success(res)
    subjects = [c["subject"] for c in W.commits_between(world.remote, world.facts.base_head,
                                                         res.refs_after[f"refs/heads/spec/{SLUG}"])]
    assert W.LEFTOVER_MESSAGE not in subjects, subjects
    assert "autocrlf = false" in (res.model["git"]["local_config"] or ""), "the clone has no core.autocrlf=false"


# ---------------------------------------------------------------- LR-92: the start check's clock (L2)
@pytest.mark.lr(92)
@windows_only
def test_lr92_the_start_check_reads_its_clock_before_it_lists_the_processes(world, check, launcher, monkeypatch):
    calls = []
    listed, clock = launcher.user_processes, launcher.now_filetime

    def user_processes(job):
        calls.append("list")
        return listed(job)

    def now_filetime():
        calls.append("clock")
        return clock()

    monkeypatch.setattr(launcher, "user_processes", user_processes)
    monkeypatch.setattr(launcher, "now_filetime", now_filetime)
    res = world.run("check")
    assert res.code == 0, res.describe()
    assert calls[:2] == ["clock", "list"], calls


# ---------------------------------------------------------------- LR-93: every spec commit (L3)
@pytest.mark.lr(93)
def test_lr93_a_path_outside_acceptance_in_an_intermediate_commit_is_refused(world, check):
    res = spec(world, [{"op": "commit", "path": "outside.txt", "text": "x\n"}, {"op": "remove_commit",
                                                                                 "path": "outside.txt"}, msg("m1")])
    check.post_model_stop(res, "SPEC_OUTSIDE_ACCEPTANCE")


@pytest.mark.lr(93)
def test_lr93_a_merge_commit_is_refused(world, check):
    res = spec(world, [{"op": "merge_commit"}, msg("m1")])
    check.post_model_stop(res, "SPEC_MERGE_COMMIT")


# ---------------------------------------------------------------- LR-94: pip and the virtual environment (L4)
@pytest.mark.lr(94)
def test_lr94_venv_and_pip_run_isolated_with_nothing_of_the_launchers_environment(world, check, monkeypatch):
    world.remote_commit(W.INTEGRATION, {"requirements.lock": "# no dependencies\n"}, message="Add an empty lock")
    planted = {"PIP_INDEX_URL": "http://127.0.0.1:9/simple", "PIP_CONFIG_FILE": "C:\\xtl-planted\\pip.ini",
               "PYTHONPATH": "C:\\xtl-planted\\site", "HTTPS_PROXY": "http://127.0.0.1:9"}
    for name, value in planted.items():
        monkeypatch.setenv(name, value)
    res = world.run("task", "--issue", str(W.ISSUE_NUMBER), steps=[
        {"op": "commit", "path": "app/feature.py", "text": "x = 1\n", "message": "Add the feature"}, msg("m1")])
    check.success(res)
    venv = [e for e in res.events if e.get("argv") and "venv" in e["argv"] and "-m" in e["argv"]]
    pip = [e for e in res.events if e.get("argv") and "pip" in e["argv"] and "install" in e["argv"]]
    assert venv and pip
    assert "-I" in venv[0]["argv"] and "-I" in pip[0]["argv"] and "--isolated" in pip[0]["argv"], pip[0]["argv"]
    for event in (venv[0], pip[0]):
        names = {k.upper() for k in W.effective_env(event)}
        assert not names & set(planted), (event["argv"], names & set(planted))
