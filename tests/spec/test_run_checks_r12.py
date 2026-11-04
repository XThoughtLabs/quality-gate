"""gate.run_checks, R-12 (HQ-ANSWERS-07): a check with `junit` fails when the file records a failed test or an error, whatever
the commands exited with. `pytest.exit` with code 0 stops a run with an exit code of 0, and the failures recorded before it
stay in the JUnit file.

The commands here exit 0 on their own account. Some copy a prepared JUnit file into the raw folder; two run the real pytest of
this interpreter on a tiny test file, the way a project's `gate/tests` does.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from gatekit import assert_no_traceback, assert_rc, base_env, junit_xml, make_config, py_cmd, read_json, run_gate, write_script, write_text

HEADER = "check\tindex\texit_code\tduration_seconds\traw_path\targv_json"
SCRIPTS = {
    "copy.py": "import shutil, sys\nshutil.copyfile(sys.argv[1], sys.argv[2])",
    "exit.py": "import sys\nsys.exit(int(sys.argv[1]))",
}
STOPS_WITH_A_FAILURE = '''import pytest


def test_fails():
    assert 1 == 2


def test_stops_the_run():
    pytest.exit("stop here", returncode=0)
'''
STOPS_WITH_AN_ERROR = '''import pytest


@pytest.fixture
def broken():
    raise RuntimeError("fixture error")


def test_errors(broken):
    pass


def test_stops_the_run():
    pytest.exit("stop here", returncode=0)
'''
ALL_PASS = "def test_one():\n    assert 1 + 1 == 2\n\n\ndef test_two():\n    assert 2 + 2 == 4\n"


@pytest.fixture
def world(tmp_path):
    scripts = tmp_path / "scripts"
    for name, code in SCRIPTS.items():
        write_script(scripts / name, code)
    work = tmp_path / "work"
    work.mkdir()
    return type("W", (), {"tmp": tmp_path, "scripts": scripts, "work": work, "out": tmp_path / "out"})()


def run_check(world, commands, **check_keys):
    body = {"class": "mandatory", "commands": commands, "timeout_seconds": 120, **check_keys}
    cfg = make_config(world.tmp / "quality.toml", checks={"gate/tests": body})
    res = run_gate("run_checks", "--config", cfg, "--check", "gate/tests", "--out", world.out, cwd=world.work, env=base_env())
    assert "No module named" not in res.err, "precondition: gate.run_checks exists and runs with python -P -m"
    return res


def rows(world):
    tsv = Path(world.out) / "exit-codes.tsv"
    assert tsv.exists(), f"{tsv} was not written"
    lines = tsv.read_text(encoding="utf-8").splitlines()
    assert lines[0] == HEADER
    return [line.split("\t") for line in lines[1:] if line]


def copy_junit(world, cases):
    prepared = write_text(world.tmp / "prepared-junit.xml", junit_xml(cases))
    return py_cmd(world.scripts / "copy.py", prepared, "{raw}/junit.xml")


def counts(world):
    return read_json(world.out / "raw" / "gate-tests" / "counts.json")


def assert_failed_after_commands_that_exited_0(world, res):
    assert res.rc != 0, f"the check passed although its JUnit file records a failure\n{res.describe()}"
    assert_no_traceback(res)
    table = rows(world)
    assert [r[2] for r in table if r[1] == "0"] == ["0"], f"the command itself must have exited 0: {table}"
    post = [r for r in table if r[1] == "post"]
    assert post and all(r[0] == "gate/tests" and r[2] == "1" for r in post), f"a row `post` with exit code 1 is expected: {table}"


# ----------------------------------------------------------------------------- a failure or an error, with commands that exit 0


@pytest.mark.req("R-12")
@pytest.mark.parametrize("status,key", [("fail", "failures"), ("error", "errors")])
def test_r12_a_command_that_exits_0_and_a_junit_file_with_a_failure_or_an_error_fails(world, status, key):
    cmd = copy_junit(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", status), ("t.c", "test_c", "pass")])
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=False)
    assert_failed_after_commands_that_exited_0(world, res)
    assert counts(world)[key] == 1, "counts.json is still written (R-5)"


@pytest.mark.req("R-12")
def test_r12_a_failure_and_an_error_together_fail(world):
    cmd = copy_junit(world, [("t.c", "test_a", "fail"), ("t.c", "test_b", "error"), ("t.c", "test_c", "pass")])
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=True)
    assert_failed_after_commands_that_exited_0(world, res)
    assert (counts(world)["failures"], counts(world)["errors"]) == (1, 1)


@pytest.mark.req("R-12")
def test_r12_a_failure_in_the_junit_file_fails_when_a_later_command_also_exits_non_zero(world):
    cmds = [copy_junit(world, [("t.c", "test_a", "fail")]), py_cmd(world.scripts / "exit.py", 3)]
    res = run_check(world, cmds, junit="junit.xml")
    assert res.rc != 0
    assert_no_traceback(res)
    assert [r[2] for r in rows(world) if r[1] in ("0", "1")] == ["0", "3"], "every command runs (R-3)"


@pytest.mark.req("R-12")
def test_r12_the_real_pytest_stopped_by_pytest_exit_0_after_a_failure_still_fails_the_check(world):
    write_text(world.work / "test_stop.py", STOPS_WITH_A_FAILURE)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml={raw}/junit.xml", "test_stop.py"]
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=False)
    assert_failed_after_commands_that_exited_0(world, res)
    assert counts(world)["failures"] >= 1


@pytest.mark.req("R-12")
def test_r12_the_real_pytest_stopped_by_pytest_exit_0_after_an_error_still_fails_the_check(world):
    write_text(world.work / "test_stop.py", STOPS_WITH_AN_ERROR)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml={raw}/junit.xml", "test_stop.py"]
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=False)
    assert_failed_after_commands_that_exited_0(world, res)
    assert counts(world)["errors"] >= 1


# ----------------------------------------------------------------------------- controls: a skip, only passes, no junit key


@pytest.mark.req("R-12", "R-5")
def test_r12_control_a_skip_alone_is_not_a_failure_when_skips_are_allowed(world):
    cmd = copy_junit(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "skip")])
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=False)
    assert_rc(res, 0)
    assert "post" not in [r[1] for r in rows(world)]
    assert counts(world)["skipped"] == 1


@pytest.mark.req("R-12", "R-5")
def test_r12_control_only_passes_pass(world):
    cmd = copy_junit(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "pass")])
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=True)
    assert_rc(res, 0)
    assert "post" not in [r[1] for r in rows(world)]
    assert counts(world)["failures"] == 0 and counts(world)["errors"] == 0


@pytest.mark.req("R-12")
def test_r12_control_the_real_pytest_with_only_passing_tests_passes(world):
    write_text(world.work / "test_all_pass.py", ALL_PASS)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--junitxml={raw}/junit.xml", "test_all_pass.py"]
    res = run_check(world, [cmd], junit="junit.xml", forbid_skips=True)
    assert_rc(res, 0)
    assert "post" not in [r[1] for r in rows(world)]
    assert counts(world)["tests"] == 2


@pytest.mark.req("R-12")
def test_r12_control_a_check_without_a_junit_key_reads_no_junit_file(world):
    # "a check with `junit` fails when ...": without the key there is nothing to read, whatever a command left behind
    cmd = copy_junit(world, [("t.c", "test_a", "fail")])
    res = run_check(world, [cmd])
    assert_rc(res, 0)
    assert "post" not in [r[1] for r in rows(world)]
