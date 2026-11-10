"""Section 1.1: the real seams, on files and folders the test owns, for
the shapes the preflight relies on. And the parts of the contract that
cannot be tested from outside, as skipped tests with their reasons, so no
gap is silent."""

from __future__ import annotations

import re
import subprocess

import pytest

import launcher_world as W

SID_RE = re.compile(r"S-1-\d+(-\d+)+")


def icacls(*args):
    with W.quiet_audit():
        return subprocess.run(["icacls", *map(str, args)], capture_output=True, text=True)


def test_seam_current_sid_is_a_sid(launcher):
    sid = launcher.current_sid()
    assert isinstance(sid, str) and SID_RE.fullmatch(sid), sid


def test_seam_is_admin_is_a_bool(launcher):
    assert type(launcher.is_admin()) is bool


def test_seam_acl_of_shape_and_an_exact_read_only_file(launcher, tmp_path):
    f = tmp_path / "key.pem"
    f.write_text("not a key", encoding="utf-8")
    owner, protected, rules = launcher.acl_of(str(f))
    assert SID_RE.fullmatch(owner)
    assert type(protected) is bool and protected is False  # a fresh file inherits
    assert rules
    for sid, rights, kind, inherited in rules:
        assert SID_RE.fullmatch(sid) and type(rights) is int
        assert kind in ("Allow", "Deny") and inherited in ("True", "False")
    me = launcher.current_sid()
    res = icacls(f, "/inheritance:r", "/grant:r", f"*{me}:(R)")
    assert res.returncode == 0, res.stdout + res.stderr
    owner, protected, rules = launcher.acl_of(str(f))
    assert protected is True
    assert len(rules) == 1
    sid, rights, kind, inherited = rules[0]
    assert (sid, kind, inherited) == (me, "Allow", "False")
    assert rights & 0x1 and not rights & (0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000)


def test_seam_can_write(launcher, tmp_path):
    f = tmp_path / "launcher.toml"
    f.write_text("x", encoding="utf-8")
    assert launcher.can_write(str(f)) is True
    me = launcher.current_sid()
    res = icacls(f, "/inheritance:r", "/grant:r", f"*{me}:(R)")
    assert res.returncode == 0, res.stdout + res.stderr
    assert launcher.can_write(str(f)) is False


def test_seam_folder_openable(launcher, tmp_path):
    folder = tmp_path / "codex-candidate"
    folder.mkdir()
    (folder / "inner.txt").write_text("x", encoding="utf-8")
    assert launcher.folder_openable(str(folder)) == "open"
    assert launcher.folder_openable(str(tmp_path / "missing")) == "absent"
    me = launcher.current_sid()
    res = icacls(folder, "/deny", f"*{me}:(RD)")
    assert res.returncode == 0, res.stdout + res.stderr
    try:
        assert launcher.folder_openable(str(folder)) == "denied"
    finally:
        icacls(folder, "/remove:d", f"*{me}")


@pytest.mark.skip(reason="gh_login_present() runs against the real GitHub CLI, which may reach "
                         "github.com; the suite makes no network use beyond 127.0.0.1")
def test_seam_gh_login_present_real():
    pass


@pytest.mark.skip(reason="git_credential_present() reads the real Windows credential store and "
                         "may start Git Credential Manager; not run against the real machine")
def test_seam_git_credential_present_real():
    pass


# ---------------------------------------------------------------- not testable from outside
@pytest.mark.skip(reason="LR-17 'an existing folder is never reused': the run id's 6 random hex "
                         "digits cannot be forced to collide without a seam beyond section 1.1; "
                         "only distinct folders for two runs are tested")
def test_lr17_existing_folder_is_never_reused():
    pass


@pytest.mark.skip(reason="LR-28 'in any case': Windows variable names are case-insensitive and "
                         "Python's os.environ upper-cases them, so a lower-case spelling cannot "
                         "reach the launcher as such; upper-case names are tested")
def test_lr28_lower_case_variable_names():
    pass


@pytest.mark.skip(reason="LR-14 Ctrl+C as a real console CTRL_C_EVENT would interrupt the test "
                         "process itself; it is tested as KeyboardInterrupt in the launcher's "
                         "thread (test_token.py::test_lr14_revoked_on_ctrl_c)")
def test_lr14_real_console_ctrl_c():
    pass


@pytest.mark.skip(reason="LR-5 'deny-only included': the real is_admin() needs a filtered token "
                         "of an Administrators member; the test user's token cannot be made so "
                         "from inside the test; the seam's verdict is tested through the fake")
def test_lr5_deny_only_administrators_token():
    pass


@pytest.mark.skip(reason="LR-11 / section 1.1 'it never lists it': opening a folder for listing "
                         "leaves no trace a test can read; the message and the log are checked "
                         "for the names inside the folder instead")
def test_lr11_folder_is_never_listed():
    pass


@pytest.mark.skip(reason="LR-15 'never in a file' covers every file of the run, the remote and "
                         "the user's git config, which are checked; files written by other "
                         "processes elsewhere on the machine cannot be enumerated")
def test_lr15_token_in_no_file_anywhere_on_the_machine():
    pass
