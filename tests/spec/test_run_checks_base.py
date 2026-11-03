"""gate.run_checks R-11 (decision W): each test of the base must appear in the JUnit file."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatekit import (Repo, assert_no_traceback, assert_rc, assert_refused, base_env, junit_xml, make_config, py_cmd,
                     run_gate, write_script, write_text)

BASE_FILES = {
    "tests/test_app.py": ("def test_add():\n    assert 1\n\n\ndef test_add_zero():\n    assert 1\n\n\n"
                          "def testlower():\n    assert 1\n\n\ndef helper_not_a_test():\n    pass\n"),
    "tests/test_cls.py": (
        "import unittest\nfrom unittest import TestCase\n\n\n"
        "class TestFoo:\n    def test_a(self):\n        assert 1\n\n    def helper_b(self):\n        pass\n\n\n"
        "class Helper:\n    def test_not_collected(self):\n        assert 1\n\n\n"
        "class AddCase(unittest.TestCase):\n    def testB(self):\n        pass\n\n\n"
        "class Other(TestCase):\n    def test_c(self):\n        pass\n\n\n"
        "class TestOuter:\n    class TestInner:\n        def test_deep(self):\n            assert 1\n"),
    "tests/calc_test.py": "def test_calc():\n    assert 1\n",
    "tests/helpers.py": "def test_ignored_in_a_helper_file():\n    assert 1\n",
    "pkg/tests/test_deep.py": "def test_deep_fn():\n    assert 1\n",
    "src/app.py": "x = 1\n",
}
EXPECTED = [
    "tests.test_app::test_add", "tests.test_app::test_add_zero", "tests.test_app::testlower",
    "tests.test_cls.TestFoo::test_a", "tests.test_cls.AddCase::testB", "tests.test_cls.Other::test_c",
    "tests.test_cls.TestOuter.TestInner::test_deep", "tests.calc_test::test_calc", "pkg.tests.test_deep::test_deep_fn",
]
NOT_EXPECTED = ["tests.test_cls.Helper::test_not_collected", "tests.test_app::helper_not_a_test",
                "tests.test_cls.TestFoo::helper_b", "tests.helpers::test_ignored_in_a_helper_file"]
COPY = "import shutil, sys\nshutil.copyfile(sys.argv[1], sys.argv[2])\n"


class Work:
    def __init__(self, tmp_path, files=None):
        self.tmp = Path(tmp_path)
        self.repo = Repo(self.tmp / "work")
        for rel, text in (BASE_FILES if files is None else files).items():
            self.repo.write(rel, text)
        self.base = self.repo.commit("base")
        self.copy = write_script(self.tmp / "scripts" / "copy.py", COPY)
        self.out = self.tmp / "out"

    def run(self, junit_ids, *, base="auto", flag=True, cwd=None):
        cases = [(i.split("::")[0], i.split("::")[1], "pass") for i in junit_ids]
        prepared = write_text(self.tmp / "prepared.xml", junit_xml(cases))
        body = {"class": "mandatory", "commands": [py_cmd(self.copy, prepared, "{raw}/junit.xml")], "junit": "junit.xml",
                "forbid_skips": False, "timeout_seconds": 60}
        if flag is not None:
            body["expected_tests_from_base"] = flag
        cfg = make_config(self.tmp / "quality.toml", checks={"gate/tests": body})
        env = {"GATE_BASE_SHA": self.base if base == "auto" else base}
        return run_gate("run_checks", "--config", cfg, "--check", "gate/tests", "--out", self.out,
                        cwd=cwd or self.repo.path, env=base_env(env))

    def rows(self):
        tsv = self.out / "exit-codes.tsv"
        assert tsv.exists(), f"{tsv} was not written"
        text = tsv.read_text(encoding="utf-8").splitlines()
        return [line.split("\t") for line in text[1:] if line]

    def missing(self):
        """The test IDs missing_tests.json lists (every string in it, whatever its shape)."""
        path = self.out / "raw" / "gate-tests" / "missing_tests.json"
        assert path.exists(), "missing_tests.json must be written to the raw folder"

        def leaves(node):
            if isinstance(node, str):
                yield node
            elif isinstance(node, dict):
                for value in node.values():
                    yield from leaves(value)
            elif isinstance(node, list):
                for value in node:
                    yield from leaves(value)

        return set(leaves(json.loads(path.read_text(encoding="utf-8"))))


@pytest.mark.req("R-11")
def test_r11_every_test_of_the_base_in_the_junit_file_passes(tmp_path):
    w = Work(tmp_path)
    res = w.run(EXPECTED)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert "post" not in [r[1] for r in w.rows()]


@pytest.mark.req("R-11")
@pytest.mark.parametrize("missing", EXPECTED)
def test_r11_a_test_of_the_base_absent_from_the_junit_file_fails_and_is_listed(tmp_path, missing):
    w = Work(tmp_path)
    res = w.run([i for i in EXPECTED if i != missing])
    assert res.rc != 0
    assert_no_traceback(res)
    post = [r for r in w.rows() if r[1] == "post"]
    assert len(post) == 1 and post[0][0] == "gate/tests" and post[0][2] == "1"
    listed = w.missing()
    assert missing in listed
    assert not [other for other in EXPECTED if other != missing and other in listed], "only the absent test is listed"


@pytest.mark.req("R-11")
def test_r11_the_id_is_the_dotted_path_the_class_chain_and_the_name(tmp_path):
    w = Work(tmp_path)
    res = w.run([])
    assert res.rc != 0
    listed = w.missing()
    for expected in EXPECTED:
        assert expected in listed, f"{expected} should be expected"
    for other in NOT_EXPECTED:
        assert other not in listed, f"{other} is not a test of the base"


@pytest.mark.req("R-11")
def test_r11_a_parametrized_name_matches_the_test(tmp_path):
    w = Work(tmp_path)
    ids = [i for i in EXPECTED if i != "tests.test_app::test_add"] + [
        "tests.test_app::test_add[1-2-3]", "tests.test_app::test_add[4-5-9]"]
    assert_rc(w.run(ids), 0)


@pytest.mark.req("R-11")
def test_r11_control_the_tests_that_are_not_expected_may_be_absent_or_present(tmp_path):
    w = Work(tmp_path)
    assert_rc(w.run(EXPECTED + NOT_EXPECTED + ["tests.test_other::test_surprise"]), 0)


@pytest.mark.req("R-11")
def test_r11_a_check_without_the_setting_does_not_require_the_tests(tmp_path):
    w = Work(tmp_path)
    for flag in (False, None):
        res = w.run(EXPECTED[:1], flag=flag)
        assert_rc(res, 0)


@pytest.mark.req("R-11")
def test_r11_a_test_that_the_head_removed_is_still_required_because_the_base_has_it(tmp_path):
    w = Work(tmp_path)
    w.repo.write("tests/test_app.py", "def test_add():\n    assert 1\n")   # the head drops two tests
    w.repo.commit("head removes tests")
    res = w.run([i for i in EXPECTED if i not in ("tests.test_app::test_add_zero", "tests.test_app::testlower")])
    assert res.rc != 0
    listed = w.missing()
    assert "tests.test_app::test_add_zero" in listed and "tests.test_app::testlower" in listed
    w2 = Work(tmp_path / "again")
    w2.repo.write("tests/test_app.py", "def test_add():\n    assert 1\n")
    w2.repo.commit("head removes tests")
    assert_rc(w2.run(EXPECTED), 0)


@pytest.mark.req("R-11")
def test_r11_the_base_is_the_merge_base_of_gate_base_sha_and_head(tmp_path):
    w = Work(tmp_path)
    w.repo.branch("pr")
    w.repo.write("src/app.py", "x = 2\n")
    w.repo.write("tests/test_on_the_pr.py", "def test_on_the_pr():\n    assert 1\n")
    w.repo.commit("pr work")
    w.repo.checkout("main")
    w.repo.write("tests/test_new_on_main.py", "def test_new_on_main():\n    assert 1\n")
    main_tip = w.repo.commit("main moves on")
    w.repo.checkout("pr")
    res = w.run(EXPECTED, base=main_tip)   # neither the new test of main nor the PR's own test is a test of the base
    assert_rc(res, 0)
    assert "post" not in [r[1] for r in w.rows()]


@pytest.mark.req("R-11")
def test_r11_the_files_are_parsed_and_never_run(tmp_path):
    marker = tmp_path / "ran.txt"
    files = dict(BASE_FILES)
    files["tests/test_boom.py"] = f"open({str(marker)!r}, 'w').write('ran')\n\n\ndef test_boom():\n    assert 1\n"
    w = Work(tmp_path, files)
    res = w.run(EXPECTED + ["tests.test_boom::test_boom"])
    assert_rc(res, 0)
    assert not marker.exists(), "a test file of the base must not be executed to find its tests"


@pytest.mark.req("R-11")
def test_r11_gate_base_sha_not_set_exits_2_and_runs_nothing(tmp_path):
    w = Work(tmp_path)
    res = w.run(EXPECTED, base=None)
    assert_refused(res, 2, w.out / "exit-codes.tsv")


@pytest.mark.req("R-11")
@pytest.mark.parametrize("base", ["f" * 40, "not-a-sha", "0" * 40])
def test_r11_a_base_that_cannot_be_read_exits_2(tmp_path, base):
    w = Work(tmp_path)
    res = w.run(EXPECTED, base=base)
    assert_refused(res, 2, w.out / "exit-codes.tsv")


@pytest.mark.req("R-11")
def test_r11_a_working_folder_that_is_not_a_git_repository_exits_2(tmp_path):
    w = Work(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    res = w.run(EXPECTED, cwd=plain)
    assert_refused(res, 2, w.out / "exit-codes.tsv")
