"""gate.run_checks: rules R-1 to R-10, Q-1, Q-1a, Q-2."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from gatekit import (assert_no_traceback, assert_rc, assert_refused, base_env, junit_xml, make_config, py_cmd,
                     read_json, run_gate, write_script, write_text)

HEADER = "check\tindex\texit_code\tduration_seconds\traw_path\targv_json"

SCRIPTS = {
    "emit.py": "import sys\nsys.stdout.write(sys.argv[1] + '\\n'); sys.stderr.write(sys.argv[2] + '\\n'); sys.exit(int(sys.argv[3]))",
    "mark.py": "import sys\nopen(sys.argv[1], 'w').write('ran')",
    "cwdprint.py": "import os\nprint(os.getcwd())",
    "sleeper.py": "import time\ntime.sleep(60)",
    "copy.py": "import shutil, sys\nshutil.copyfile(sys.argv[1], sys.argv[2])",
    "argvprint.py": "import sys\nprint('ARG=' + sys.argv[1])",
    "touch.py": "import sys, pathlib\npathlib.Path(sys.argv[1]).write_text('x')",
    "envprint.py": "import json, os\nprint(json.dumps({k: os.environ.get(k) for k in ('MY_EXTRA', 'FROM_OUTER', 'PYTHONPATH')}))",
}


@pytest.fixture
def world(tmp_path):
    scripts = tmp_path / "scripts"
    for name, code in SCRIPTS.items():
        write_script(scripts / name, code)
    work = tmp_path / "work"
    work.mkdir()
    return type("W", (), {"tmp": tmp_path, "scripts": scripts, "work": work, "out": tmp_path / "out"})()


def script(world, name, *args):
    return py_cmd(world.scripts / name, *args)


def run_rc(world, checks, check_id, *, workdir=None, cwd=None, out=None, extra_toml="", env_extra=None, flags=(),
           setup=None):
    cfg = make_config(world.tmp / "quality.toml", checks=checks, raw_text=extra_toml, setup=setup)
    args = ["--config", cfg, "--check", check_id, "--out", out or world.out, *flags]
    if workdir:
        args += ["--workdir", workdir]
    return run_gate("run_checks", *args, cwd=cwd or world.work, env=base_env(env_extra))


def check(commands, **kw):
    body = {"class": "mandatory", "commands": commands, "timeout_seconds": 60}
    body.update(kw)
    return body


def rows(out_dir):
    tsv = Path(out_dir) / "exit-codes.tsv"
    assert tsv.exists(), f"{tsv} was not written"
    text = tsv.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == HEADER, f"header must be exactly {HEADER!r}, got {lines[0]!r}"
    return [line.split("\t") for line in lines[1:] if line]


# ----------------------------------------------------------------------------- R-1, R-2


@pytest.mark.req("R-1", "R-2")
def test_logs_and_rows_for_each_command(world):
    cmds = [script(world, "emit.py", "OUT-ZERO", "ERR-ZERO", 0), script(world, "emit.py", "OUT-ONE", "ERR-ONE", 3)]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests")
    assert_rc(res, 3)
    assert_no_traceback(res)
    log0 = (world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8")
    log1 = (world.out / "raw" / "gate-tests" / "1.log").read_text(encoding="utf-8")
    assert "OUT-ZERO" in log0 and "ERR-ZERO" in log0, "stdout and stderr both go to the log"
    assert "OUT-ONE" in log1 and "ERR-ONE" in log1
    assert "OUT-ONE" not in log0
    r = rows(world.out)
    assert [(x[0], x[1], x[2]) for x in r] == [("gate/tests", "0", "0"), ("gate/tests", "1", "3")]
    for i, row in enumerate(r):
        assert len(row) == 6
        assert float(row[3]) >= 0, "duration_seconds is a number"
        assert row[4].replace("\\", "/").endswith(f"raw/gate-tests/{i}.log")
        assert json.loads(row[5]) == cmds[i], "argv_json is the command as configured (R-9)"


@pytest.mark.req("R-1")
def test_slug_replaces_slash_with_dash(world):
    res = run_rc(world, {"diag/coverage": check([script(world, "emit.py", "COV", "e", 0)], **{"class": "diagnostic"})},
                 "diag/coverage")
    assert_rc(res, 0)
    assert "COV" in (world.out / "raw" / "diag-coverage" / "0.log").read_text(encoding="utf-8")
    assert [x[0] for x in rows(world.out)] == ["diag/coverage"]


@pytest.mark.req("R-2")
def test_row_exit_code_is_numeric_and_script_exit_zero_when_all_pass(world):
    cmds = [script(world, "emit.py", "a", "b", 0), script(world, "emit.py", "c", "d", 0)]
    res = run_rc(world, {"gate/env": check(cmds)}, "gate/env")
    assert_rc(res, 0)
    assert [x[2] for x in rows(world.out)] == ["0", "0"]


# ----------------------------------------------------------------------------- R-3


@pytest.mark.req("R-3")
def test_every_command_runs_after_a_failure_and_exit_code_is_the_first_nonzero(world):
    marker = world.tmp / "third-ran.txt"
    cmds = [script(world, "emit.py", "a", "b", 0), script(world, "emit.py", "c", "d", 3),
            script(world, "emit.py", "e", "f", 5), script(world, "mark.py", marker)]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests")
    assert_rc(res, 3)
    assert marker.exists(), "a later command must still run after a failed one"
    assert [x[2] for x in rows(world.out)] == ["0", "3", "5", "0"]


# ----------------------------------------------------------------------------- R-4


@pytest.mark.req("R-4")
def test_command_not_found_records_127_and_is_not_a_pass(world):
    marker = world.tmp / "after.txt"
    cmds = [["definitely-not-a-command-xyz", "--flag"], script(world, "mark.py", marker)]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests")
    assert_rc(res, 127)
    assert_no_traceback(res)
    assert [x[2] for x in rows(world.out)] == ["127", "0"]
    assert marker.exists()


@pytest.mark.req("R-4")
def test_command_past_timeout_is_killed_and_records_124(world):
    marker = world.tmp / "after-timeout.txt"
    cmds = [script(world, "sleeper.py"), script(world, "mark.py", marker)]
    res = run_rc(world, {"gate/tests": check(cmds, timeout_seconds=2)}, "gate/tests")
    assert_rc(res, 124)
    assert res.elapsed < 40, "the sleeping command must have been killed at the timeout"
    assert [x[2] for x in rows(world.out)] == ["124", "0"]
    assert marker.exists()


@pytest.mark.req("R-4")
def test_a_command_inside_the_timeout_is_not_killed(world):
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)], timeout_seconds=30)}, "gate/tests")
    assert_rc(res, 0)
    assert [x[2] for x in rows(world.out)] == ["0"]


# ----------------------------------------------------------------------------- R-5


def junit_command(world, cases):
    src = world.tmp / "prepared-junit.xml"
    write_text(src, junit_xml(cases))
    return script(world, "copy.py", src, "{raw}/junit.xml")


@pytest.mark.req("R-5")
def test_junit_counts_are_written_beside_the_logs(world):
    cmds = [junit_command(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "fail"),
                                  ("t.c", "test_c", "error"), ("t.c", "test_d", "skip")])]
    res = run_rc(world, {"gate/tests": check(cmds, junit="junit.xml", forbid_skips=False)}, "gate/tests")
    counts = read_json(world.out / "raw" / "gate-tests" / "counts.json")
    assert {k: counts[k] for k in ("tests", "failures", "errors", "skipped")} == {
        "tests": 4, "failures": 1, "errors": 1, "skipped": 1}
    assert_no_traceback(res)


@pytest.mark.req("R-5")
def test_junit_present_and_no_skips_passes(world):
    cmds = [junit_command(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "pass")])]
    res = run_rc(world, {"gate/tests": check(cmds, junit="junit.xml", forbid_skips=True)}, "gate/tests")
    assert_rc(res, 0)
    assert "post" not in [x[1] for x in rows(world.out)]
    counts = read_json(world.out / "raw" / "gate-tests" / "counts.json")
    assert counts["tests"] == 2 and counts["skipped"] == 0


@pytest.mark.req("R-5")
def test_skips_allowed_when_forbid_skips_is_false(world):
    cmds = [junit_command(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "skip"), ("t.c", "test_c", "skip")])]
    res = run_rc(world, {"gate/tests": check(cmds, junit="junit.xml", forbid_skips=False)}, "gate/tests")
    assert_rc(res, 0)
    assert "post" not in [x[1] for x in rows(world.out)]
    assert read_json(world.out / "raw" / "gate-tests" / "counts.json")["skipped"] == 2


@pytest.mark.req("R-5")
def test_forbid_skips_makes_a_skip_a_failure(world):
    cmds = [junit_command(world, [("t.c", "test_a", "pass"), ("t.c", "test_b", "skip")])]
    res = run_rc(world, {"gate/tests": check(cmds, junit="junit.xml", forbid_skips=True)}, "gate/tests")
    assert res.rc != 0, "skipped > 0 with forbid_skips is a failure"
    assert_no_traceback(res)
    post = [x for x in rows(world.out) if x[1] == "post"]
    assert len(post) == 1 and post[0][0] == "gate/tests" and post[0][2] == "1"


@pytest.mark.req("R-5")
def test_missing_junit_is_a_failure(world):
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)], junit="junit.xml")}, "gate/tests")
    assert res.rc != 0
    assert_no_traceback(res)
    post = [x for x in rows(world.out) if x[1] == "post"]
    assert len(post) == 1 and post[0][2] == "1"


@pytest.mark.req("R-5")
def test_unparsable_junit_is_a_failure(world):
    src = world.tmp / "garbage.xml"
    write_text(src, "<testsuites><testsuite")
    cmds = [script(world, "copy.py", src, "{raw}/junit.xml")]
    res = run_rc(world, {"gate/tests": check(cmds, junit="junit.xml")}, "gate/tests")
    assert res.rc != 0
    assert_no_traceback(res)
    post = [x for x in rows(world.out) if x[1] == "post"]
    assert len(post) == 1 and post[0][2] == "1"


# ----------------------------------------------------------------------------- R-6


@pytest.mark.req("R-6")
def test_required_output_present_is_fine(world):
    cmds = [script(world, "touch.py", "{raw}/summary.json")]
    res = run_rc(world, {"gate/tests": check(cmds, required_outputs=["summary.json"])}, "gate/tests")
    assert_rc(res, 0)
    assert "post" not in [x[1] for x in rows(world.out)]


@pytest.mark.req("R-6")
def test_required_output_missing_appends_a_post_row_and_fails(world):
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)],
                                             required_outputs=["summary.json"])}, "gate/tests")
    assert res.rc != 0
    assert_no_traceback(res)
    post = [x for x in rows(world.out) if x[1] == "post"]
    assert len(post) == 1 and post[0][0] == "gate/tests" and post[0][2] == "1"


# ----------------------------------------------------------------------------- R-7, Q-2


@pytest.mark.req("R-7")
def test_unknown_check_id_exits_2_and_runs_nothing(world):
    marker = world.tmp / "must-not-exist.txt"
    res = run_rc(world, {"gate/tests": check([script(world, "mark.py", marker)])}, "gate/other")
    assert_refused(res, 2, marker, world.out / "exit-codes.tsv")


@pytest.mark.req("R-7", "Q-2")
@pytest.mark.parametrize("cid,klass", [
    ("gate/tests", "diagnostic"), ("gate/final", "diagnostic"), ("gate/env", "optional"),
    ("diag/coverage", "mandatory"), ("diag/benchmark", "mandatory"),
])
def test_q2_reclassified_known_check_is_refused_with_exit_2(world, cid, klass):
    marker = world.tmp / "must-not-exist.txt"
    res = run_rc(world, {cid: check([script(world, "mark.py", marker)], **{"class": klass})}, cid)
    assert_refused(res, 2, marker, world.out / "exit-codes.tsv")


@pytest.mark.req("R-7", "Q-2")
@pytest.mark.parametrize("cid", ["gate/invented", "diag/invented", "lint/ruff"])
def test_q2_unknown_check_in_the_configuration_is_refused_with_exit_2(world, cid):
    marker = world.tmp / "must-not-exist.txt"
    checks = {"gate/tests": check([script(world, "mark.py", marker)]),
              cid: check([script(world, "mark.py", marker)])}
    res = run_rc(world, checks, "gate/tests")
    assert_refused(res, 2, marker, world.out / "exit-codes.tsv")


@pytest.mark.req("Q-2")
@pytest.mark.parametrize("cid,klass", [
    ("gate/env", "mandatory"), ("gate/tests", "mandatory"), ("gate/acceptance", "mandatory"),
    ("gate/guard", "mandatory"), ("gate/security", "mandatory"), ("gate/report", "mandatory"),
    ("gate/archive", "mandatory"), ("gate/final", "mandatory"),
    ("diag/coverage", "diagnostic"), ("diag/mypy", "diagnostic"), ("diag/ruff", "diagnostic"),
    ("diag/semgrep", "diagnostic"), ("diag/schemathesis", "diagnostic"), ("diag/mutation", "diagnostic"),
    ("diag/benchmark", "diagnostic"),
])
def test_q2_every_known_check_with_its_fixed_class_is_accepted(world, cid, klass):
    res = run_rc(world, {cid: check([script(world, "emit.py", "a", "b", 0)], **{"class": klass})}, cid)
    assert_rc(res, 0)


@pytest.mark.req("R-7", "C-2")
def test_broken_toml_is_a_configuration_error(world):
    bad = world.tmp / "quality.toml"
    write_text(bad, "[project\nthis is not toml")
    res = run_gate("run_checks", "--config", bad, "--check", "gate/tests", "--out", world.out, cwd=world.work)
    assert_refused(res, 2, world.out / "exit-codes.tsv")


@pytest.mark.req("C-2")
def test_missing_arguments_is_a_usage_error(world):
    res = run_gate("run_checks", "--check", "gate/tests", cwd=world.work)
    assert_refused(res, 2)


# ----------------------------------------------------------------------------- R-8


@pytest.mark.req("R-8")
def test_running_two_checks_leaves_both_and_never_rewrites(world):
    checks = {"gate/env": check([script(world, "emit.py", "a", "b", 0)]),
              "gate/tests": check([script(world, "emit.py", "c", "d", 2)])}
    r1 = run_rc(world, checks, "gate/env")
    assert_rc(r1, 0)
    first = (world.out / "exit-codes.tsv").read_bytes()
    r2 = run_rc(world, checks, "gate/tests")
    assert_rc(r2, 2)
    second = (world.out / "exit-codes.tsv").read_bytes()
    assert second.startswith(first), "rows are appended, earlier bytes are never rewritten"
    assert second.count(HEADER.encode()) == 1, "the header is written once"
    assert [(x[0], x[2]) for x in rows(world.out)] == [("gate/env", "0"), ("gate/tests", "2")]
    assert (world.out / "raw" / "gate-env" / "0.log").exists() and (world.out / "raw" / "gate-tests" / "0.log").exists()


# ----------------------------------------------------------------------------- Q-1 and the working directory


@pytest.mark.req("Q-1")
def test_raw_placeholder_is_the_absolute_raw_folder(world):
    cmds = [script(world, "argvprint.py", "{raw}"), script(world, "argvprint.py", "--x={raw}/junit.xml")]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests")
    assert_rc(res, 0)
    expected = (world.out / "raw" / "gate-tests").resolve()
    first = (world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8").strip()
    second = (world.out / "raw" / "gate-tests" / "1.log").read_text(encoding="utf-8").strip()
    assert first.startswith("ARG=")
    got = Path(first[len("ARG="):])
    assert got.is_absolute() and got.resolve() == expected, f"{{raw}} must become the absolute raw folder, got {got}"
    assert second.startswith("ARG=--x=")
    assert Path(second[len("ARG=--x="):]).resolve() == (expected / "junit.xml").resolve()
    assert "{raw}" not in first + second


@pytest.mark.req("R-0")
def test_commands_run_in_the_workdir_when_given_and_in_the_current_folder_otherwise(world):
    other = world.tmp / "other-folder"
    other.mkdir()
    cmds = [script(world, "cwdprint.py")]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests", workdir=other)
    assert_rc(res, 0)
    printed = (world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8").strip()
    assert Path(printed).resolve() == other.resolve()
    out2 = world.tmp / "out2"
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests", out=out2)
    assert_rc(res, 0)
    printed = (out2 / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8").strip()
    assert Path(printed).resolve() == world.work.resolve()


# ----------------------------------------------------------------------------- R-9


@pytest.mark.req("R-9", "Q-1")
def test_r9_argv_json_holds_the_command_as_configured_with_its_placeholders(world):
    cmds = [script(world, "argvprint.py", "{raw}/x.txt"), script(world, "argvprint.py", "--v={env:MY_TRUSTED_VAR}")]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests", env_extra={"MY_TRUSTED_VAR": "value-123"})
    assert_rc(res, 0)
    r = rows(world.out)
    assert [json.loads(x[5]) for x in r] == cmds, "the placeholders stay in argv_json so that a rerun records the same text"
    assert "{raw}" in r[0][5] and "{env:MY_TRUSTED_VAR}" in r[1][5]
    assert "value-123" not in r[1][5]
    log = (world.out / "raw" / "gate-tests" / "1.log").read_text(encoding="utf-8")
    assert "ARG=--v=value-123" in log, "while the command that really ran got the value"


# ----------------------------------------------------------------------------- Q-1 {env:NAME} and Q-1a


@pytest.mark.req("Q-1")
def test_q1_env_placeholder_is_replaced_by_the_variable_of_the_trusted_context(world):
    cmds = [script(world, "argvprint.py", "{env:MY_TRUSTED_VAR}/sub")]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests", env_extra={"MY_TRUSTED_VAR": "value-456"})
    assert_rc(res, 0)
    assert "ARG=value-456/sub" in (world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8")


@pytest.mark.req("Q-1")
def test_q1_a_variable_that_is_not_set_exits_2_and_runs_nothing(world):
    marker = world.tmp / "must-not-exist.txt"
    cmds = [script(world, "argvprint.py", "{env:SURELY_NOT_SET_VARIABLE_XYZ}"), script(world, "mark.py", marker)]
    res = run_rc(world, {"gate/tests": check(cmds)}, "gate/tests")
    assert_refused(res, 2, marker)
    assert "SURELY_NOT_SET_VARIABLE_XYZ" in res.both, "the message names the variable"


@pytest.mark.req("Q-1a")
def test_q1a_the_env_table_gives_a_checks_commands_more_variables_and_the_gates_pythonpath_never_reaches_them(world):
    body = check([script(world, "envprint.py")], env={"MY_EXTRA": "value-{raw}", "FROM_OUTER": "{env:OUTER_VAR}"})
    res = run_rc(world, {"gate/tests": body}, "gate/tests", env_extra={"OUTER_VAR": "outer-123"})
    assert_rc(res, 0)
    seen = json.loads((world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8").strip().splitlines()[-1])
    raw = (world.out / "raw" / "gate-tests").resolve()
    assert seen["MY_EXTRA"].startswith("value-") and Path(seen["MY_EXTRA"][len("value-"):]).resolve() == raw
    assert seen["FROM_OUTER"] == "outer-123"
    assert seen["PYTHONPATH"] is None, "the gate's own PYTHONPATH must not reach the checks' commands"


@pytest.mark.req("Q-1a")
def test_q1a_the_pythonpath_reaches_a_command_only_when_the_env_table_gives_it(world):
    body = check([script(world, "envprint.py")], env={"PYTHONPATH": "."})
    res = run_rc(world, {"gate/tests": body}, "gate/tests")
    assert_rc(res, 0)
    seen = json.loads((world.out / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8").strip().splitlines()[-1])
    assert seen["PYTHONPATH"] == "."


@pytest.mark.req("Q-1a")
def test_q1a_the_setup_table_is_run_as_the_check_setup_outside_the_fixed_classes(world):
    # Assumption: [setup] takes `commands` (and `timeout_seconds`) like a check does.
    setup = {"commands": [script(world, "emit.py", "SETUP-OUT", "SETUP-ERR", 0)], "timeout_seconds": 60}
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)])}, "setup", setup=setup)
    assert_rc(res, 0)
    assert "SETUP-OUT" in (world.out / "raw" / "setup" / "0.log").read_text(encoding="utf-8")
    assert [(x[0], x[1], x[2]) for x in rows(world.out)] == [("setup", "0", "0")]


@pytest.mark.req("Q-1a", "R-3")
def test_q1a_a_failing_setup_command_is_reported_like_any_other_check(world):
    setup = {"commands": [script(world, "emit.py", "a", "b", 4)], "timeout_seconds": 60}
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)])}, "setup", setup=setup)
    assert_rc(res, 4)
    assert [(x[0], x[2]) for x in rows(world.out)] == [("setup", "4")]


# ----------------------------------------------------------------------------- R-10


@pytest.mark.req("R-10")
@pytest.mark.parametrize("cid", ["diag/mypy", "gate/security", "setup"])
def test_r10_if_configured_a_check_that_is_not_configured_exits_0_and_records_nothing(world, cid):
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)])}, cid, flags=["--if-configured"])
    assert_rc(res, 0)
    assert_no_traceback(res)
    tsv = world.out / "exit-codes.tsv"
    assert not tsv.exists() or rows(world.out) == [], "nothing is recorded"
    assert not (world.out / "raw" / cid.replace("/", "-")).exists()


@pytest.mark.req("R-10")
def test_r10_control_without_the_flag_a_check_that_is_not_configured_is_not_a_success(world):
    # Assumption: without the flag, a known check with no configuration is an error, not an empty success.
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "a", "b", 0)])}, "diag/mypy")
    assert res.rc != 0
    assert_no_traceback(res)
    assert "diag/mypy" in res.both, "the refusal names the check that is not configured"


@pytest.mark.req("R-10")
def test_r10_control_a_configured_check_runs_normally_with_the_flag(world):
    res = run_rc(world, {"gate/tests": check([script(world, "emit.py", "OUT", "ERR", 3)])}, "gate/tests",
                 flags=["--if-configured"])
    assert_rc(res, 3)
    assert [(x[0], x[2]) for x in rows(world.out)] == [("gate/tests", "3")]


@pytest.mark.req("R-10", "Q-2")
def test_r10_the_flag_does_not_excuse_a_refused_configuration(world):
    marker = world.tmp / "must-not-exist.txt"
    res = run_rc(world, {"gate/tests": check([script(world, "mark.py", marker)], **{"class": "diagnostic"})},
                 "gate/tests", flags=["--if-configured"])
    assert_refused(res, 2, marker)
