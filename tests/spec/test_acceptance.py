"""gate.acceptance: rules A-1 to A-11 (decisions O and W)."""
from __future__ import annotations

import sys

import pytest

from gatekit import (assert_no_traceback, assert_rc, assert_refused, base_env, junit_xml, load_out, make_config,
                     run_gate, write_script, write_text)

T1 = "acceptance.test_status::test_history"
T2 = "acceptance.test_status::test_permissions"
T3 = "acceptance.test_search::test_find"
T4 = "acceptance.test_search::test_empty"

OUT_KEYS = {"ok", "mode", "list_size", "failing_not_listed", "listed_failing", "remove_from_list",
            "missing_listed", "missing_tests", "passed", "reason_codes"}


def acc(tmp_path, cases, listed=None, *, mode=None, require_empty=False, list_missing=False, raw_junit=None,
        env_extra=None, command=None, config=None, tests_dir=None):
    """config: None (no --config), a dict for the [acceptance] table, or "no-table" (a configuration without it)."""
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
    if config is not None:
        cfg = make_config(tmp_path / "quality.toml", acceptance=None if config == "no-table" else config)
        args += ["--config", cfg]
    if tests_dir is not None:
        args += ["--tests-dir", tests_dir]
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


# A parametrized acceptance test ID can hold a space (run 42361091565, PR #1). The map ID is
# the last whitespace field; the test ID is everything before it, its space kept (supersedes L17).
TSPACE1 = ("acceptance.test_spec_1_identity_and_visibility::"
           "test_spec_1_business_endpoints_require_a_valid_token[GET /tasks/{task_id}/history-invalid]")
TSPACE2 = ("acceptance.test_spec_1_identity_and_visibility::"
           "test_spec_1_business_endpoints_require_a_valid_token[GET /tasks/{task_id}/history-missing]")


@pytest.mark.req("A-7")
def test_a_test_id_with_a_space_is_listed_by_its_last_field_as_the_map_id(tmp_path):
    """The two real space-holding IDs of run 42361091565. Fails on the old split() parser,
    which made gate.acceptance exit 2 (a usage error) on such a line."""
    res, d, _ = acc(tmp_path, [(TSPACE1, "fail"), (TSPACE2, "fail")],
                    [f"{TSPACE1} DEF-SPEC-1", f"{TSPACE2} DEF-SPEC-1"])
    assert_rc(res, 0)
    assert d["listed_failing"] == sorted([TSPACE1, TSPACE2])
    assert d["failing_not_listed"] == []


@pytest.mark.req("A-7")
def test_a_space_test_id_still_needs_a_valid_map_id(tmp_path):
    """Control: the refusals hold even when the test ID holds a space. Passes both ways."""
    res, _, out = acc(tmp_path, [(TSPACE1, "fail")], [TSPACE1])  # no map ID at the end
    assert_refused(res, 2, out)


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
def test_a10_require_empty_true_in_the_configuration_acts_as_the_flag(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], config={"require_empty": True})
    assert_rc(res, 1)
    assert "LIST_NOT_EMPTY" in d["reason_codes"] and d["ok"] is False


@pytest.mark.req("A-10")
@pytest.mark.parametrize("config", [{"require_empty": False}, "no-table", {}], ids=["false", "no-table", "empty-table"])
def test_a10_control_without_true_in_the_configuration_a_non_empty_list_is_allowed(tmp_path, config):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], config=config)
    assert_rc(res, 0)
    assert d["ok"] is True


@pytest.mark.req("A-10")
def test_a10_with_an_empty_list_the_requirement_is_met(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "pass")], [], config={"require_empty": True})
    assert_rc(res, 0)
    assert d["ok"] is True


@pytest.mark.req("A-10")
@pytest.mark.parametrize("value", ["1", "true", "yes"])
@pytest.mark.parametrize("config", [None, {"require_empty": False}], ids=["no-config", "config-false"])
def test_a10_no_environment_variable_sets_it(tmp_path, config, value):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], config=config, env_extra={"GATE_REQUIRE_EMPTY": value})
    assert_rc(res, 0)
    assert d["ok"] is True and "LIST_NOT_EMPTY" not in d["reason_codes"]


@pytest.mark.req("A-10", "A-6")
def test_a10_the_flag_still_works_when_the_configuration_says_false(tmp_path):
    res, d, _ = acc(tmp_path, [(T1, "fail")], [f"{T1} PUB-01"], config={"require_empty": False}, require_empty=True)
    assert_rc(res, 1)
    assert "LIST_NOT_EMPTY" in d["reason_codes"]


# ----------------------------------------------------------------------------- A-11 (decision W)

TREE = {
    "acceptance/test_status.py": "def test_history():\n    assert 2 + 2 == 4\n\n\ndef test_permissions():\n    assert 3 + 3 == 6\n",
    "acceptance/test_search.py": (
        "import unittest\n\n\nclass TestSearch:\n    def test_find(self):\n        assert 1\n\n"
        "    def helper_empty(self):\n        pass\n\n\nclass Helper:\n    def test_not_a_test(self):\n        assert 1\n\n\n"
        "class CaseSearch(unittest.TestCase):\n    def testEmpty(self):\n        pass\n"),
    "acceptance/calc_test.py": "def test_calc():\n    assert 1\n",
    "acceptance/helpers.py": "def test_not_collected_from_a_helper_file():\n    assert 1\n",
}
EXPECTED = ["acceptance.test_status::test_history", "acceptance.test_status::test_permissions",
            "acceptance.test_search.TestSearch::test_find", "acceptance.test_search.CaseSearch::testEmpty",
            "acceptance.calc_test::test_calc"]
NOT_EXPECTED = "acceptance.test_search.Helper::test_not_a_test"


def a11(tmp_path, junit_ids, listed=None, *, tree=None, tests_dir="acceptance", **kw):
    for rel, text in (TREE if tree is None else tree).items():
        write_text(tmp_path / rel, text)
    cases = [(i, "pass") for i in junit_ids]
    return acc(tmp_path, cases, listed or [], tests_dir=tests_dir, **kw)


@pytest.mark.req("A-11")
def test_a11_every_test_of_the_folder_is_in_the_junit_file_so_the_check_is_ok(tmp_path):
    res, d, _ = a11(tmp_path, EXPECTED)
    assert_rc(res, 0)
    assert d["ok"] is True and d["missing_tests"] == [] and "MISSING_TEST" not in d["reason_codes"]


@pytest.mark.req("A-11")
@pytest.mark.parametrize("missing", EXPECTED)
def test_a11_a_test_absent_from_junit_and_not_on_the_list_fails(tmp_path, missing):
    res, d, _ = a11(tmp_path, [i for i in EXPECTED if i != missing])
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert "MISSING_TEST" in d["reason_codes"] and d["ok"] is False
    assert d["missing_tests"] == [missing]


@pytest.mark.req("A-11")
def test_a11_several_missing_tests_are_all_listed_sorted(tmp_path):
    res, d, _ = a11(tmp_path, [EXPECTED[0]])
    assert_rc(res, 1)
    assert d["missing_tests"] == sorted(EXPECTED[1:])


@pytest.mark.req("A-11")
def test_a11_a_parametrized_name_matches_the_test(tmp_path):
    ids = [i + "[case-1]" if i.endswith("test_history") else i for i in EXPECTED]
    res, d, _ = a11(tmp_path, ids)
    assert_rc(res, 0)
    assert d["missing_tests"] == []


@pytest.mark.req("A-11")
def test_a11_a_class_not_named_test_and_not_a_testcase_is_not_expected(tmp_path):
    assert NOT_EXPECTED not in EXPECTED
    res, d, _ = a11(tmp_path, EXPECTED)   # the junit file does not hold Helper::test_not_a_test
    assert_rc(res, 0)
    assert NOT_EXPECTED not in d["missing_tests"]


@pytest.mark.req("A-11")
def test_a11_only_files_named_test_star_or_star_test_are_read(tmp_path):
    res, d, _ = a11(tmp_path, [i for i in EXPECTED if "calc_test" not in i])
    assert_rc(res, 1)
    assert d["missing_tests"] == ["acceptance.calc_test::test_calc"], "calc_test.py is read, helpers.py is not"


@pytest.mark.req("A-11", "A-4")
def test_a11_a_listed_test_that_is_missing_stays_a_missing_listed_not_a_missing_test(tmp_path):
    listed = [f"{EXPECTED[0]} PUB-01"]
    res, d, _ = a11(tmp_path, EXPECTED[1:], listed)
    assert_rc(res, 1)
    assert "MISSING_LISTED" in d["reason_codes"] and d["missing_listed"] == [EXPECTED[0]]
    assert "MISSING_TEST" not in d["reason_codes"] and d["missing_tests"] == []


@pytest.mark.req("A-11")
def test_a11_without_tests_dir_nothing_is_required_and_missing_tests_is_empty(tmp_path):
    for rel, text in TREE.items():
        write_text(tmp_path / rel, text)
    res, d, _ = acc(tmp_path, [(EXPECTED[0], "pass")], [])
    assert_rc(res, 0)
    assert d["missing_tests"] == [] and "MISSING_TEST" not in d["reason_codes"]


@pytest.mark.req("A-11")
def test_a11_ids_take_their_paths_relative_to_the_working_folder(tmp_path):
    tree = {"suite/acceptance/test_deep.py": "def test_deep():\n    assert 1\n"}
    res, d, _ = a11(tmp_path, ["suite.acceptance.test_deep::test_deep"], tree=tree, tests_dir="suite/acceptance")
    assert_rc(res, 0)
    other = tmp_path / "second"
    other.mkdir()
    res, d, _ = a11(other, ["x.test_deep::test_deep"], tree=tree, tests_dir="suite/acceptance")
    assert_rc(res, 1)
    assert d["missing_tests"] == ["suite.acceptance.test_deep::test_deep"]


@pytest.mark.req("A-11")
def test_a11_the_test_files_are_parsed_and_never_run(tmp_path):
    marker = tmp_path / "ran.txt"
    tree = {"acceptance/test_boom.py": f"open({str(marker)!r}, 'w').write('ran')\n\n\ndef test_boom():\n    assert 1\n"}
    res, d, _ = a11(tmp_path, ["acceptance.test_boom::test_boom"], tree=tree)
    assert_rc(res, 0)
    assert not marker.exists()
