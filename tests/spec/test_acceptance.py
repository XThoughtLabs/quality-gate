"""gate.acceptance: rules A-1 to A-10 (decision O)."""
from __future__ import annotations

import sys

import pytest

from gatekit import (assert_no_traceback, assert_rc, assert_refused, base_env, junit_xml, load_out, run_gate,
                     write_script, write_text)

T1 = "acceptance.test_status::test_history"
T2 = "acceptance.test_status::test_permissions"
T3 = "acceptance.test_search::test_find"
T4 = "acceptance.test_search::test_empty"

OUT_KEYS = {"ok", "mode", "list_size", "failing_not_listed", "listed_failing", "remove_from_list",
            "missing_listed", "passed", "reason_codes"}


def acc(tmp_path, cases, listed=None, *, mode=None, require_empty=False, list_missing=False, raw_junit=None,
        env_extra=None, command=None):
    junit = tmp_path / "junit.xml"
    if raw_junit is not None:
        write_text(junit, raw_junit)
    elif raw_junit is None and cases is not None:
        write_text(junit, junit_xml([(t.split("::")[0], t.split("::")[1], s) for t, s in cases]))
    known = tmp_path / "known-failing.txt"
    if not list_missing:
        write_text(known, "\n".join(listed or []) + ("\n" if listed else ""))
    out = tmp_path / "acceptance-out.json"
    args = ["--junit", junit, "--known-failing", known, "--out", out]
    if mode:
        args += ["--mode", mode]
    if require_empty:
        args.append("--require-empty")
    if command:
        args += ["--", *command]
    res = run_gate("acceptance", *args, cwd=tmp_path, env=base_env(env_extra))
    return res, load_out(res, out), out


# ----------------------------------------------------------------------------- A-1


@pytest.mark.req("A-1")
def test_listed_failing_test_does_not_fail_the_check(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "pass")], [f"{T1} PUB-01"])
    assert_rc(res, 0)
    assert d["ok"] is True
    assert d["listed_failing"] == [T1]
    assert d["failing_not_listed"] == [] and d["reason_codes"] == []
    assert d["passed"] == [T2]


@pytest.mark.req("A-1")
def test_listed_erroring_test_does_not_fail_the_check(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "error"), (T2, "pass")], [f"{T1} SPEC-6.1"])
    assert_rc(res, 0)
    assert d["listed_failing"] == [T1]


@pytest.mark.req("A-1")
@pytest.mark.parametrize("status", ["fail", "error"])
def test_failing_test_not_on_the_list_fails_the_check(tmp_path, status):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, status), (T3, "pass")], [f"{T1} PUB-01"])
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert res.both.strip(), "a failed rule prints a short message"
    assert d["ok"] is False
    assert d["failing_not_listed"] == [T2]
    assert d["listed_failing"] == [T1]
    assert "FAILING_NOT_LISTED" in d["reason_codes"]


@pytest.mark.req("A-1")
def test_empty_list_and_all_passing_is_ok(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass"), (T2, "pass")], [])
    assert_rc(res, 0)
    assert d["ok"] is True and d["reason_codes"] == [] and d["passed"] == [T1, T2]


# ----------------------------------------------------------------------------- A-2


@pytest.mark.req("A-2")
def test_skipped_test_not_on_the_list_counts_as_failing(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "skip"), (T2, "pass")], [])
    assert_rc(res, 1)
    assert d["failing_not_listed"] == [T1]
    assert "FAILING_NOT_LISTED" in d["reason_codes"]
    assert T1 not in d["passed"]


@pytest.mark.req("A-2")
def test_skipped_test_is_not_passed_even_when_other_tests_pass(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass"), (T2, "skip")], [])
    assert_rc(res, 1)
    assert d["passed"] == [T1]


# ----------------------------------------------------------------------------- A-3


@pytest.mark.req("A-3")
def test_listed_test_that_passes_goes_to_remove_from_list_without_failing_in_subset_mode(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass"), (T2, "fail")], [f"{T1} PUB-01", f"{T2} DEF-found-1"])
    assert_rc(res, 0)
    assert d["ok"] is True
    assert d["mode"] == "subset"
    assert d["remove_from_list"] == [T1]
    assert d["listed_failing"] == [T2]
    assert T1 in d["passed"]


@pytest.mark.req("A-3")
def test_subset_can_be_asked_for_explicitly(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass")], [f"{T1} PUB-01"], mode="subset")
    assert_rc(res, 0)
    assert d["mode"] == "subset" and d["remove_from_list"] == [T1]


# ----------------------------------------------------------------------------- A-4


@pytest.mark.req("A-4")
def test_listed_test_absent_from_junit_fails(tmp_path):
    res, d, _ = acc(tmp_path, [(T2, "pass")], [f"{T1} PUB-01"])
    assert_rc(res, 1)
    assert d["missing_listed"] == [T1]
    assert "MISSING_LISTED" in d["reason_codes"]
    assert d["ok"] is False


@pytest.mark.req("A-4")
def test_junit_without_test_cases_fails_with_no_tests(tmp_path):
    res, d, _ = acc(tmp_path, [], [])
    assert_rc(res, 1)
    assert "NO_TESTS" in d["reason_codes"]
    assert d["ok"] is False


# ----------------------------------------------------------------------------- A-5


@pytest.mark.req("A-5")
def test_exact_mode_ok_when_failing_set_equals_the_list(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "error"), (T3, "pass")], [f"{T1} PUB-01", f"{T2} PUB-02"], mode="exact")
    assert_rc(res, 0)
    assert d["ok"] is True and d["mode"] == "exact" and d["reason_codes"] == []


@pytest.mark.req("A-5")
def test_exact_mode_listed_test_that_passes_fails_the_check(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "pass")], [f"{T1} PUB-01", f"{T2} PUB-02"], mode="exact")
    assert_rc(res, 1)
    assert "LIST_NOT_EXACT" in d["reason_codes"]
    assert d["ok"] is False and d["mode"] == "exact"


@pytest.mark.req("A-5", "A-1")
def test_exact_mode_unlisted_failure_still_fails(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "fail")], [f"{T1} PUB-01"], mode="exact")
    assert_rc(res, 1)
    assert "FAILING_NOT_LISTED" in d["reason_codes"] and d["failing_not_listed"] == [T2]


# ----------------------------------------------------------------------------- A-6


@pytest.mark.req("A-6")
def test_require_empty_with_a_non_empty_list_fails_even_when_every_listed_test_fails(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "pass")], [f"{T1} PUB-01"], require_empty=True)
    assert_rc(res, 1)
    assert "LIST_NOT_EMPTY" in d["reason_codes"]
    assert d["ok"] is False


@pytest.mark.req("A-6")
def test_require_empty_with_an_empty_or_missing_list_passes(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass")], [], require_empty=True)
    assert_rc(res, 0)
    assert d["ok"] is True and d["list_size"] == 0
    again = tmp_path / "again"
    again.mkdir()
    res, d, _ = acc(again, [(T1, "pass")], None, require_empty=True, list_missing=True)
    assert_rc(res, 0)
    assert d["ok"] is True and d["list_size"] == 0


# ----------------------------------------------------------------------------- A-7


@pytest.mark.req("A-7")
@pytest.mark.parametrize("line", [
    "acceptance.test_status::test_history",            # no map id
    "acceptance.test_status::test_history PUB-1",      # one digit
    "acceptance.test_status::test_history PUB-123",    # three digits
    "acceptance.test_status::test_history SPEC-6.3",   # not a listed section
    "acceptance.test_status::test_history FOO-01",     # unknown prefix
    "acceptance.test_status::test_history DEF-bad_id",  # underscore is not a letter, digit or dash
])
def test_entry_without_a_valid_map_id_exits_2(tmp_path, line):
    res, _, out = acc(tmp_path, [(T1, "fail")], [line])
    assert_refused(res, 2, out)


@pytest.mark.req("A-7")
def test_duplicate_entry_exits_2(tmp_path):
    res, _, out = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01", f"{T1} PUB-01"])
    assert_refused(res, 2, out)


@pytest.mark.req("A-7")
def test_unreadable_junit_exits_2(tmp_path):
    res, _, out = acc(tmp_path, None, [f"{T1} PUB-01"], raw_junit="<testsuites><testsuite")
    assert_refused(res, 2, out)


@pytest.mark.req("A-7")
def test_missing_junit_file_exits_2(tmp_path):
    out = tmp_path / "o.json"
    known = write_text(tmp_path / "k.txt", "")
    res = run_gate("acceptance", "--junit", tmp_path / "no-such.xml", "--known-failing", known, "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out)


@pytest.mark.req("A-7")
@pytest.mark.parametrize("map_id", ["PUB-01", "PUB-99", "SPEC-6.1", "SPEC-6.2", "DEF-search-1", "DEF-A1-b2-c3"])
def test_valid_map_ids_are_accepted(tmp_path, map_id):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} {map_id}"])
    assert_rc(res, 0)
    assert d["listed_failing"] == [T1]


@pytest.mark.req("A-7")
def test_usage_error_without_arguments_exits_2(tmp_path):
    assert_refused(run_gate("acceptance", cwd=tmp_path), 2)


# ----------------------------------------------------------------------------- A-8 and the list file


@pytest.mark.req("A-8")
@pytest.mark.parametrize("name,cases,listed,kw", [
    ("ok", [(T1, "pass")], [], {}),
    ("failing", [(T1, "fail")], [], {}),
    ("no-tests", [], [], {}),
    ("missing", [(T2, "pass")], [f"{T1} PUB-01"], {}),
    ("exact", [(T1, "pass")], [f"{T1} PUB-01"], {"mode": "exact"}),
    ("require-empty", [(T1, "fail")], [f"{T1} PUB-01"], {"require_empty": True}),
])
def test_list_size_and_remove_from_list_are_always_written(tmp_path, name, cases, listed, kw):
    res, d, _ = acc(tmp_path, cases, listed, **kw)
    assert d is not None, f"--out must be written\n{res.describe()}"
    assert OUT_KEYS <= set(d), f"missing keys: {OUT_KEYS - set(d)}"
    assert d["list_size"] == len(listed)
    assert isinstance(d["remove_from_list"], list)


@pytest.mark.req("A-8", "A-3")
def test_all_lists_are_sorted(tmp_path):
    cases = [(T4, "fail"), (T2, "fail"), (T3, "pass"), (T1, "pass")]
    listed = [f"{T4} PUB-01", f"{T2} PUB-04", f"{T3} PUB-03", f"{T1} PUB-02"]
    res, d, _ = acc(tmp_path, cases, listed)
    assert_rc(res, 0)
    # The constants are not in lexical order (T4 and T3 sort before T1 and T2), so the expectation is sorted([...]).
    assert d["listed_failing"] == sorted([T2, T4]), "sorted, not in file or JUnit order"
    assert d["remove_from_list"] == sorted([T1, T3]) and d["passed"] == sorted([T1, T3])
    # a failing run, with several unlisted failures and several missing entries, also gives sorted lists
    other = tmp_path / "second"
    other.mkdir()
    res, d, _ = acc(other, [(T4, "fail"), (T2, "fail")], [f"{T3} PUB-03", f"{T1} PUB-02"])
    assert_rc(res, 1)
    assert d["failing_not_listed"] == sorted([T2, T4])
    assert d["missing_listed"] == sorted([T1, T3])
    for key in ("failing_not_listed", "listed_failing", "remove_from_list", "missing_listed", "passed"):
        assert d[key] == sorted(d[key]), f"{key} must be sorted"


@pytest.mark.req("A-8")
def test_blank_lines_and_comments_are_ignored_and_not_counted(tmp_path):
    listed = ["# a comment", "", f"{T1} PUB-01", "", "# another comment", f"{T2} SPEC-6.2"]
    res, d, _ = acc(tmp_path, [(T1, "fail"), (T2, "fail")], listed)
    assert_rc(res, 0)
    assert d["list_size"] == 2 and d["listed_failing"] == [T1, T2]


@pytest.mark.req("A-8")
def test_missing_list_file_is_an_empty_list(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass")], None, list_missing=True)
    assert_rc(res, 0)
    assert d["list_size"] == 0 and d["ok"] is True and d["remove_from_list"] == []


# ----------------------------------------------------------------------------- A-9 and A-10

MAKE_JUNIT = """
import shutil, sys
shutil.copyfile(sys.argv[1], sys.argv[2])
sys.exit(int(sys.argv[3]))
"""


def acc_with_command(tmp_path, cases, listed, code, **kw):
    """The JUnit file does not exist until the command after `--` has run and written it."""
    prepared = write_text(tmp_path / "prepared.xml", junit_xml([(t.split("::")[0], t.split("::")[1], s) for t, s in cases]))
    script = write_script(tmp_path / "make_junit.py", MAKE_JUNIT)
    junit = tmp_path / "junit.xml"
    assert not junit.exists()
    cmd = [sys.executable, script, prepared, junit, code]
    return acc(tmp_path, None, listed, raw_junit=None, command=cmd, **kw)


@pytest.mark.req("A-9")
def test_a9_the_command_runs_first_and_its_exit_code_is_recorded(tmp_path):
    res, d, _ = acc_with_command(tmp_path, [(T1, "pass")], [], 0)
    assert_rc(res, 0)
    assert d["test_command_exit_code"] == 0 and type(d["test_command_exit_code"]) is int
    assert d["ok"] is True


@pytest.mark.req("A-9", "A-1")
def test_a9_a_listed_failure_makes_pytest_exit_1_and_must_not_turn_the_check_red(tmp_path):
    res, d, _ = acc_with_command(tmp_path, [(T1, "fail"), (T2, "pass")], [f"{T1} PUB-01"], 1)
    assert_rc(res, 0)
    assert d["test_command_exit_code"] == 1
    assert d["ok"] is True and d["listed_failing"] == [T1] and d["reason_codes"] == []


@pytest.mark.req("A-9", "A-1")
def test_a9_an_unlisted_failure_still_fails_through_the_junit_not_through_the_exit_code(tmp_path):
    res, d, _ = acc_with_command(tmp_path, [(T1, "fail")], [], 1)
    assert_rc(res, 1)
    assert d["test_command_exit_code"] == 1
    assert "FAILING_NOT_LISTED" in d["reason_codes"] and "TEST_COMMAND_ERROR" not in d["reason_codes"]


@pytest.mark.req("A-9")
def test_a9_exit_code_5_no_tests_collected_is_accepted_as_the_commands_own_code(tmp_path):
    res, d, _ = acc_with_command(tmp_path, [(T1, "pass")], [], 5)
    assert_rc(res, 0)
    assert d["test_command_exit_code"] == 5 and "TEST_COMMAND_ERROR" not in d["reason_codes"]


@pytest.mark.req("A-9")
@pytest.mark.parametrize("code", [2, 3, 4, 6, 124, 127, 255])
def test_a9_any_other_exit_code_fails_the_check_even_when_the_junit_looks_fine(tmp_path, code):
    res, d, _ = acc_with_command(tmp_path, [(T1, "pass")], [], code)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["test_command_exit_code"] == code
    assert "TEST_COMMAND_ERROR" in d["reason_codes"] and d["ok"] is False


@pytest.mark.req("A-10")
def test_a10_gate_require_empty_acts_as_the_flag(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], env_extra={"GATE_REQUIRE_EMPTY": "1"})
    assert_rc(res, 1)
    assert "LIST_NOT_EMPTY" in d["reason_codes"] and d["ok"] is False


@pytest.mark.req("A-10")
@pytest.mark.parametrize("env_extra", [None, {"GATE_REQUIRE_EMPTY": "0"}, {"GATE_REQUIRE_EMPTY": ""}],
                         ids=["unset", "zero", "empty"])
def test_a10_control_without_the_variable_set_to_1_a_non_empty_list_is_allowed(tmp_path, env_extra):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], env_extra=env_extra)
    assert_rc(res, 0)
    assert d["ok"] is True


@pytest.mark.req("A-10")
def test_a10_gate_require_empty_with_an_empty_list_passes(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass")], [], env_extra={"GATE_REQUIRE_EMPTY": "1"})
    assert_rc(res, 0)
    assert d["ok"] is True
