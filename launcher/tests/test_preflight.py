"""Section 3, the preflight (LR-3 to LR-11), run before any network use,
clone, token or run folder, in the contract's order, for every command."""

from __future__ import annotations

import itertools

import pytest

import launcher_world as W
from conftest import assert_only_the_log_under_runs_dir

ADMINISTRATORS = "S-1-5-32-544"
EVERYONE = "S-1-1-0"


def test_check_passes_prints_preflight_ok_and_touches_nothing(world, check):
    res = world.run("check")
    assert res.exc is None and res.code == 0, res.describe()
    assert "PREFLIGHT OK" in [ln.strip() for ln in res.stdout.splitlines()], res.describe()
    assert res.requests == []
    assert res.run_dirs == []
    assert res.model is None
    assert not any("clone" in (e.get("argv") or []) for e in res.events)
    assert_only_the_log_under_runs_dir(res)
    check.no_leak(res)


@pytest.mark.parametrize("command", [["check"], ["task", "--issue", "5"], ["spec", "--slug", "s"],
                                     ["fix", "--pr", "7"]])
def test_preflight_runs_for_every_command(world, check, command):
    world.seams.gh = True
    check.preflight_stop(world.run(*command), "GH_LOGIN")


# ---------------------------------------------------------------- LR-3
@pytest.mark.parametrize("name", ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"])
def test_lr3_ai_session(world, check, monkeypatch, name):
    monkeypatch.setenv(name, "1")
    check.preflight_stop(world.run("task", "--issue", "5"), "AI_SESSION")


@pytest.mark.parametrize("name", ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"])
def test_lr3_control_empty_value_passes(world, monkeypatch, name):
    monkeypatch.setenv(name, "")
    res = world.run("check")
    assert res.code == 0, res.describe()


# ---------------------------------------------------------------- LR-4
@pytest.mark.parametrize("how", ["raises", "none", "empty"])
def test_a8_identity_unknown_when_the_sid_cannot_be_read(world, check, monkeypatch, launcher, how):
    """Amendment 1, A8: `IDENTITY_UNKNOWN` when the SID cannot be read; it
    stops in the preflight like the rules around it. Section 1.1 does not say
    how `current_sid()` reports that, so the three plain ways are tried."""
    def no_sid():
        if how == "raises":
            raise OSError("the token cannot be opened")
        return None if how == "none" else ""
    monkeypatch.setattr(launcher, "current_sid", no_sid)
    check.preflight_stop(world.run("task", "--issue", "5"), "IDENTITY_UNKNOWN")


def test_lr4_ceo_sid(world, check):
    world.seams.sid = W.CEO_SID
    check.preflight_stop(world.run("task", "--issue", "5"), "CEO_USER")


def test_lr4_key_file_owned_by_the_current_user(world, check):
    world.seams.acl[W.norm(world.key_file)] = lambda s: (s.sid, True,
                                                         [(s.sid, W.READ_RIGHTS, "Allow", "False")])
    check.preflight_stop(world.run("task", "--issue", "5"), "CEO_USER")


# ---------------------------------------------------------------- LR-5
def test_lr5_admin(world, check):
    world.seams.admin = True
    check.preflight_stop(world.run("task", "--issue", "5"), "ADMIN")


# ---------------------------------------------------------------- LR-6
def test_lr6_not_the_executor_user(world, check):
    world.seams.sid = W.OTHER_SID
    check.preflight_stop(world.run("task", "--issue", "5"), "EXECUTOR_USER")


# ---------------------------------------------------------------- LR-7
def test_lr7_gh_login(world, check):
    world.seams.gh = True
    check.preflight_stop(world.run("task", "--issue", "5"), "GH_LOGIN")


@pytest.mark.parametrize("name", ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                                  "GITHUB_ENTERPRISE_TOKEN"])
def test_lr7_token_variable(world, check, monkeypatch, name):
    monkeypatch.setenv(name, "ghp_not_a_real_token_value_000")
    res = world.run("task", "--issue", "5")
    check.preflight_stop(res, "GH_LOGIN")
    assert "ghp_not_a_real_token_value_000" not in res.stdout + res.stderr + res.log_text


@pytest.mark.parametrize("name", ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN",
                                  "GITHUB_ENTERPRISE_TOKEN"])
def test_lr7_control_empty_token_variable_passes(world, monkeypatch, name):
    monkeypatch.setenv(name, "")
    res = world.run("check")
    assert res.code == 0, res.describe()


# ---------------------------------------------------------------- LR-8
def test_lr8_git_credential(world, check):
    world.seams.cred = True
    check.preflight_stop(world.run("task", "--issue", "5"), "GIT_CREDENTIAL")


# ---------------------------------------------------------------- LR-9
def acl_variant(name: str):
    def make(s):
        me = s.sid
        rule = (me, W.READ_RIGHTS, "Allow", "False")
        return {
            "unprotected": (W.CEO_SID, False, [rule]),
            "two_rules": (W.CEO_SID, True, [rule, (ADMINISTRATORS, 0x1F01FF, "Allow", "False")]),
            "everyone_too": (W.CEO_SID, True, [rule, (EVERYONE, W.READ_RIGHTS, "Allow", "False")]),
            "no_rules": (W.CEO_SID, True, []),
            "other_sid": (W.CEO_SID, True, [(W.OTHER_SID, W.READ_RIGHTS, "Allow", "False")]),
            "deny_kind": (W.CEO_SID, True, [(me, W.READ_RIGHTS, "Deny", "False")]),
            "inherited": (W.CEO_SID, True, [(me, W.READ_RIGHTS, "Allow", "True")]),
            "no_readdata": (W.CEO_SID, True, [(me, W.READ_RIGHTS & ~0x1, "Allow", "False")]),
            "writedata": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x2, "Allow", "False")]),
            "appenddata": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x4, "Allow", "False")]),
            "delete": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x10000, "Allow", "False")]),
            "writedac": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x40000, "Allow", "False")]),
            "writeowner": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x80000, "Allow", "False")]),
            "full_control": (W.CEO_SID, True, [(me, 0x1F01FF, "Allow", "False")]),
            # Amendment 1, A7: four more write bits refuse.
            "writeea": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x10, "Allow", "False")]),
            "writeattributes": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x100, "Allow", "False")]),
            "genericall": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x10000000, "Allow", "False")]),
            "genericwrite": (W.CEO_SID, True, [(me, W.READ_RIGHTS | 0x40000000, "Allow", "False")]),
        }[name]
    return make


ACL_BAD = ["unprotected", "two_rules", "everyone_too", "no_rules", "other_sid", "deny_kind",
           "inherited", "no_readdata", "writedata", "appenddata", "delete", "writedac",
           "writeowner", "full_control", "writeea", "writeattributes", "genericall",
           "genericwrite"]


@pytest.mark.parametrize("target", ["key", "app"])
@pytest.mark.parametrize("variant", ACL_BAD)
def test_lr9_key_access(world, check, target, variant):
    path = world.key_file if target == "key" else world.app_file
    world.seams.acl[W.norm(path)] = acl_variant(variant)
    check.preflight_stop(world.run("task", "--issue", "5"), "KEY_ACCESS")


# Controls: read (R), ReadData alone, and read and execute (RX), which holds
# no bit of LR-9 or A7.
@pytest.mark.parametrize("rights", [W.READ_RIGHTS, 0x1, 0x1200A9])
def test_lr9_control_exact_shape_passes_and_both_files_are_read(world, rights):
    for path in (world.key_file, world.app_file):
        world.seams.acl[W.norm(path)] = lambda s, r=rights: (W.CEO_SID, True,
                                                             [(s.sid, r, "Allow", "False")])
    res = world.run("check")
    assert res.code == 0, res.describe()
    asked = {W.norm(c[1]) for c in world.seams.calls if c[0] == "acl_of"}
    assert {W.norm(world.key_file), W.norm(world.app_file)} <= asked


# ---------------------------------------------------------------- LR-10
@pytest.mark.parametrize("which", ["launcher", "config"])
def test_lr10_self_writable(world, check, launcher, which):
    path = launcher.__file__ if which == "launcher" else world.config_path
    world.seams.writable.add(W.norm(path))
    check.preflight_stop(world.run("task", "--issue", "5"), "SELF_WRITABLE")


def test_lr10_control_both_files_are_checked(world, launcher):
    world.seams.writable.add(W.norm(world.runs_dir))
    res = world.run("check")
    assert res.code == 0, res.describe()
    asked = {W.norm(c[1]) for c in world.seams.calls if c[0] == "can_write"}
    assert W.norm(launcher.__file__) in asked
    assert W.norm(world.config_path) in asked


# ---------------------------------------------------------------- LR-11
def test_lr11_folder_open(world, check):
    world.seams.folders[W.norm(world.candidate_folder)] = "open"
    res = world.run("task", "--issue", "5")
    check.preflight_stop(res, "FOLDER_OPEN")
    # LR-97 rule 6 and review round 1's F3 (the CEO, 2026-11-14): the entry's number, never its path
    assert "must_not_open entry 1" in res.last, res.last
    for text in (res.stdout, res.stderr, res.log_text):
        assert "INNER-SECRET-NAME-0451" not in text


def test_lr11_second_path_open(world, check):
    """Any configured path: the second one, open, stops too."""
    world.seams.folders[W.norm(world.absent_folder)] = "open"
    res = world.run("check")
    check.preflight_stop(res, "FOLDER_OPEN")
    assert "must_not_open entry 2" in res.last, res.last


def test_lr11_control_absent_and_denied_pass_and_the_log_records_which(world):
    res = world.run("check")
    assert res.code == 0, res.describe()
    asked = {W.norm(c[1]) for c in world.seams.calls if c[0] == "folder_openable"}
    assert {W.norm(world.candidate_folder), W.norm(world.absent_folder)} <= asked
    log = res.log_text
    assert "denied" in log and "absent" in log, log
    assert "INNER-SECRET-NAME-0451" not in log + res.stdout + res.stderr


# ---------------------------------------------------------------- the order
def _break(world, mp, launcher, code):
    s = world.seams
    if code == "AI_SESSION":
        mp.setenv("CLAUDECODE", "1")
    elif code == "CEO_USER":
        s.acl[W.norm(world.key_file)] = lambda x: (x.sid, True, [(x.sid, W.READ_RIGHTS, "Allow", "False")])
    elif code == "ADMIN":
        s.admin = True
    elif code == "EXECUTOR_USER":
        s.sid = W.OTHER_SID
    elif code == "GH_LOGIN":
        s.gh = True
    elif code == "GIT_CREDENTIAL":
        s.cred = True
    elif code == "KEY_ACCESS":
        s.acl[W.norm(world.app_file)] = acl_variant("unprotected")
    elif code == "SELF_WRITABLE":
        s.writable.add(W.norm(launcher.__file__))
    elif code == "FOLDER_OPEN":
        s.folders[W.norm(world.candidate_folder)] = "open"


ORDER = ["AI_SESSION", "CEO_USER", "ADMIN", "EXECUTOR_USER", "GH_LOGIN", "GIT_CREDENTIAL",
         "KEY_ACCESS", "SELF_WRITABLE", "FOLDER_OPEN"]


@pytest.mark.parametrize("first, later", list(itertools.combinations(ORDER, 2)))
def test_preflight_order_first_failing_rule_wins(world, check, monkeypatch, launcher, first, later):
    _break(world, monkeypatch, launcher, later)
    _break(world, monkeypatch, launcher, first)
    check.preflight_stop(world.run("task", "--issue", "5"), first)


def test_preflight_order_all_broken_gives_ai_session(world, check, monkeypatch, launcher):
    for code in reversed(ORDER):
        _break(world, monkeypatch, launcher, code)
    check.preflight_stop(world.run("fix", "--pr", "7"), "AI_SESSION")


# ---------------------------------------------------------------- LR-49 for a stopped preflight
def test_lr49_preflight_stop_still_writes_its_log(world):
    world.seams.cred = True
    res = world.run("task", "--issue", "5")
    assert res.code == 1, res.describe()
    assert_only_the_log_under_runs_dir(res)
    log = res.log_text
    assert "GIT_CREDENTIAL" in log
    assert W.EXEC_SID in log
    assert "task" in log
