"""R-11, A-11 and the protected configuration files against real pytest, not a written JUnit file.

The first tests of these rules used synthetic JUnit, and that hid a fault: they could not
see what pytest really collects or names. Everything here runs the pinned pytest.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.req("R-11", "A-11", "G-1a", "G-1b")

# Each shape pytest treats in its own way, in one suite that passes.
SHAPES = {
    "tests/test_plain.py": "def test_plain():\n    assert 1 == 1\n",
    "tests/deep/er/test_folder.py": "def test_in_a_subfolder():\n    assert 1 == 1\n",
    "tests/test_classes.py": (
        "import unittest\n\n\n"
        "class TestPlain:\n    def test_method(self):\n        assert 1 == 1\n\n"
        "    class TestNested:\n        def test_inner(self):\n            assert 1 == 1\n\n\n"
        "class TestWithInit:\n    def __init__(self):\n        self.x = 1\n\n    def test_not_collected(self):\n        assert False\n\n\n"
        "class TestOff:\n    __test__ = False\n\n    def test_not_collected(self):\n        assert False\n\n\n"
        "class Helper:\n    def test_not_collected(self):\n        assert False\n\n\n"
        "class Case(unittest.TestCase):\n    def test_unittest(self):\n        self.assertEqual(1, 1)\n"
    ),
    "tests/test_shapes.py": (
        "import pytest\n\n\n"
        "@pytest.fixture\ndef test_client():\n    return 1\n\n\n"
        "def test_uses_the_fixture(test_client):\n    assert test_client == 1\n\n\n"
        '@pytest.mark.parametrize("value", [1, 2, "a b]c"])\ndef test_parametrized(value):\n    assert value\n\n\n'
        "def test_turned_off():\n    assert False\n\n\ntest_turned_off.__test__ = False\n"
    ),
    "tests/test_module_off.py": "__test__ = False\n\n\ndef test_not_collected():\n    assert False\n",
    "helpers/not_a_test_file.py": "def test_not_collected():\n    assert False\n",
    "acceptance/test_spec.py": "def test_spec():\n    assert 1 == 1\n",
}


def git(repo: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    return process.stdout.strip()


def write_files(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def make_repo(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main-line")
    write_files(repo, files)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    return repo, git(repo, "rev-parse", "HEAD")


def run_tests_check(gate, tmp_path: Path, repo: Path, base: str, extra: str = "", arguments: tuple[str, ...] = ()):
    config = tmp_path / "quality.toml"
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--ignore=acceptance", "--junitxml={raw}/junit.xml", *arguments]
    config.write_text(
        f'[checks."gate/tests"]\ncommands = [{json.dumps(command)}]\njunit = "junit.xml"\nforbid_skips = true\nexpected_tests_from_base = true\n{extra}\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    process = gate.run("run_checks", "--config", config, "--check", "gate/tests", "--out", out, "--workdir", repo, env=gate.env(GATE_BASE_SHA=base))
    missing = out / "raw" / "gate-tests" / "missing_tests.json"
    return process, json.loads(missing.read_text(encoding="utf-8")) if missing.exists() else None


def test_a_suite_of_every_shape_passes_with_nothing_missing(gate, tmp_path):
    repo, base = make_repo(tmp_path, SHAPES)
    process, missing = run_tests_check(gate, tmp_path, repo, base)
    log = (tmp_path / "out" / "raw" / "gate-tests" / "0.log").read_text(encoding="utf-8")
    assert process.returncode == 0, process.stderr + log
    assert missing == []


def test_merged_acceptance_tests_are_not_expected_of_gate_tests(gate, tmp_path):
    """The spec PR merges, and every later PR must still be able to pass."""
    repo, base = make_repo(tmp_path, {**SHAPES, "acceptance/test_more.py": "def test_more():\n    assert 1 == 1\n"})
    process, missing = run_tests_check(gate, tmp_path, repo, base)
    assert process.returncode == 0, process.stderr
    assert missing == []


@pytest.mark.parametrize(
    "narrowing",
    [("--ignore=tests/test_plain.py",), ("--deselect=tests/test_shapes.py::test_parametrized",), ("-k", "not test_method")],
    ids=["ignored-file", "deselected-test", "keyword"],
)
def test_a_test_of_the_base_that_did_not_run_fails_and_is_named(gate, tmp_path, narrowing):
    repo, base = make_repo(tmp_path, SHAPES)
    process, missing = run_tests_check(gate, tmp_path, repo, base, arguments=narrowing)
    assert process.returncode == 1, process.stdout
    assert missing, "the missing test is named"
    rows = (tmp_path / "out" / "exit-codes.tsv").read_text(encoding="utf-8").splitlines()
    assert any(row.startswith("gate/tests\tpost\t1") for row in rows)


def test_a_file_outside_the_run_is_named_in_the_trusted_ignore_list(gate, tmp_path):
    repo, base = make_repo(tmp_path, SHAPES)
    process, missing = run_tests_check(gate, tmp_path, repo, base, arguments=("--ignore=tests/test_plain.py",), extra='expected_tests_ignore = ["tests/test_plain.py"]')
    assert process.returncode == 0, process.stderr
    assert missing == []


def test_a_single_test_can_be_ignored_by_its_id(gate, tmp_path):
    repo, base = make_repo(tmp_path, SHAPES)
    process, missing = run_tests_check(gate, tmp_path, repo, base, arguments=("--deselect=tests/test_plain.py::test_plain",), extra='expected_tests_ignore = ["tests.test_plain::test_plain"]')
    assert process.returncode == 0, process.stderr
    assert missing == []


def test_a_configuration_file_in_a_subfolder_moves_pytests_root(gate, tmp_path):
    files = {"backend/pytest.ini": "[pytest]\n", "backend/tests/test_x.py": "def test_x():\n    assert 1 == 1\n"}
    repo, base = make_repo(tmp_path, files)
    process, missing = run_tests_check(gate, tmp_path, repo, base, extra='expected_tests_root = "backend"', arguments=("backend/tests",))
    assert process.returncode == 0, process.stderr
    assert missing == []
    # Without the setting the IDs differ, and the check fails rather than pass by accident.
    (tmp_path / "out" / "exit-codes.tsv").unlink()
    process, missing = run_tests_check(gate, tmp_path, repo, base, arguments=("backend/tests",))
    assert process.returncode == 1
    assert missing == ["backend.tests.test_x::test_x"]


def run_acceptance(gate, tmp_path: Path, repo: Path, listed: str = "", arguments: tuple[str, ...] = ()):
    known = repo / "acceptance" / "known-failing.txt"
    known.write_text(listed, encoding="utf-8")
    junit = tmp_path / "acceptance-junit.xml"
    out = tmp_path / "acceptance.json"
    process = gate.run(
        "acceptance", "--junit", junit, "--known-failing", known, "--tests-dir", "acceptance", "--out", out,
        "--", sys.executable, "-m", "pytest", "acceptance", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}", *arguments,
        cwd=repo,
    )
    return process, json.loads(out.read_text(encoding="utf-8"))


ACCEPTANCE = {
    "acceptance/test_a.py": (
        "import pytest\n\n\n"
        "def test_passes():\n    assert 1 == 1\n\n\n"
        "def test_fails():\n    assert 1 == 2\n\n\n"
        '@pytest.mark.parametrize("value", [1, 2])\ndef test_many(value):\n    assert value\n\n\n'
        "class TestOwn:\n    def __init__(self):\n        pass\n\n    def test_not_collected(self):\n        assert False\n"
    ),
}


def test_every_acceptance_test_ran_and_a_listed_failure_is_allowed(gate, tmp_path):
    repo, _ = make_repo(tmp_path, ACCEPTANCE)
    process, result = run_acceptance(gate, tmp_path, repo, "acceptance.test_a::test_fails PUB-01\n")
    assert process.returncode == 0, process.stderr
    assert result["missing_tests"] == []
    assert result["test_command_exit_code"] == 1


def test_an_acceptance_test_kept_from_running_fails(gate, tmp_path):
    """A conftest.py that narrows the run: unlisted tests that never ran are not a pass."""
    repo, _ = make_repo(tmp_path, {**ACCEPTANCE, "acceptance/test_b.py": "def test_hidden():\n    assert 1 == 2\n", "conftest.py": "collect_ignore_glob = ['acceptance/test_b*']\n"})
    process, result = run_acceptance(gate, tmp_path, repo, "acceptance.test_a::test_fails PUB-01\n")
    assert process.returncode == 1
    assert result["missing_tests"] == ["acceptance.test_b::test_hidden"]
    assert "MISSING_TEST" in result["reason_codes"]


CHEAT = (
    "import pytest\n\n\n@pytest.hookimpl(hookwrapper=True)\ndef pytest_runtest_makereport(item, call):\n"
    "    outcome = yield\n    outcome.get_result().outcome = 'passed'\n"
)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pytest.toml", '[pytest]\naddopts = ["-p", "cheat"]\npythonpath = ["."]\n'),
        (".pytest.toml", '[pytest]\naddopts = ["-p", "cheat"]\npythonpath = ["."]\n'),
        ("pytest.ini", "[pytest]\naddopts = -p cheat\npythonpath = .\n"),
        (".pytest.ini", "[pytest]\naddopts = -p cheat\npythonpath = .\n"),
        ("tests/pytest.toml", '[pytest]\naddopts = ["-p", "cheat"]\npythonpath = [".."]\n'),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-p cheat"\npythonpath = ["."]\n'),
        ("tests/pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-p cheat"\npythonpath = [".."]\n'),
        ("tox.ini", "[pytest]\naddopts = -p cheat\npythonpath = .\n"),
        ("setup.cfg", "[tool:pytest]\naddopts = -p cheat\npythonpath = .\n"),
        ("tests/setup.cfg", "[tool:pytest]\naddopts = -p cheat\npythonpath = ..\n"),
        # pytest's parser cuts this section line differently from configparser (review round 3).
        ("tox.ini", "[pytest] # ]\naddopts = -p cheat\npythonpath = .\n"),
    ],
)
def test_each_file_pytest_reads_as_configuration_is_refused(gate, tmp_path, name, text):
    """Each of them, in real pytest, turns a failing test green: so each must be refused."""
    repo, base = make_repo(tmp_path, {"tests/test_app.py": "def test_ok():\n    assert 1 == 1\n"})
    git(repo, "checkout", "-q", "-b", "ai/1-x")
    write_files(repo, {"tests/test_app.py": "def test_ok():\n    assert 1 == 2\n", name: text, "cheat.py": CHEAT})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the change")

    # The proof that the file matters: pytest really reads it and the failure disappears.
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    run = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], cwd=repo, capture_output=True, text=True, env=env, check=False)
    assert run.returncode == 0, f"this configuration did not change pytest: {run.stdout}"

    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nexecutor_app = "example-executor"\n', encoding="utf-8")
    out = tmp_path / "guard.json"
    process = gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "ai/1-x", "--author", "example-executor[bot]", "--config", config, "--out", out)
    assert process.returncode == 1
    rules = {(item["rule"], item["path"]) for item in json.loads(out.read_text(encoding="utf-8"))["violations"]}
    assert ("PROTECTED_PATH", name) in rules


def test_the_list_of_names_is_the_pinned_pytests_own():
    """When the pin moves and pytest reads a new file, this fails until the guard knows it."""
    from _pytest.config.findpaths import CONFIG_LOADERS_BY_NAME

    root = Path(__file__).resolve().parents[2]
    source = (root / "gate" / "guard.py").read_text(encoding="utf-8")
    for name in CONFIG_LOADERS_BY_NAME:
        assert f'"{name}"' in source, f"pytest reads {name}, and the guard does not name it"


APP = "def add(a, b):\n    return a + b\n"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("tox.ini", "[pytest] # ]\npythonpath = shim\n"),
        ("tox.ini", "[pytest]; a comment\npythonpath = shim\n"),
        ("setup.cfg", "[tool:pytest] # ]\npythonpath = shim\n"),
    ],
)
def test_a_broken_module_cannot_be_replaced_through_a_file_the_guard_reads_differently(gate, tmp_path, name, text):
    """Real pytest reads the file, and a broken module is swapped for a good one in a shim."""
    repo, base = make_repo(tmp_path, {"app.py": APP, "tests/test_add.py": "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"})
    git(repo, "checkout", "-q", "-b", "ai/1-x")
    write_files(repo, {"app.py": "def add(a, b):\n    return a - b\n", "shim/app.py": APP, name: text})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the change")
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=repo, capture_output=True, text=True, env=env, check=False)
    assert run.returncode == 0, f"this file did not change pytest: {run.stdout}"
    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nexecutor_app = "example-executor"\n', encoding="utf-8")
    out = tmp_path / "guard.json"
    process = gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "ai/1-x", "--author", "example-executor[bot]", "--config", config, "--out", out)
    assert process.returncode == 1
    assert ("PROTECTED_PATH", name) in {(item["rule"], item["path"]) for item in json.loads(out.read_text(encoding="utf-8"))["violations"]}


@pytest.mark.parametrize("name", ["pytest.py", "pytest/__init__.py", "_pytest/__init__.py"])
def test_a_module_standing_in_for_pytest_is_refused(gate, tmp_path, name):
    repo, base = make_repo(tmp_path, {"tests/test_app.py": "def test_ok():\n    assert 1 == 1\n"})
    git(repo, "checkout", "-q", "-b", "ai/1-x")
    write_files(repo, {name: "print('not pytest')\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the change")
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "guard.json"
    process = gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "ai/1-x", "--author", "a-person", "--config", config, "--out", out)
    assert process.returncode == 1
    assert any(item["rule"] == "PROTECTED_PATH" for item in json.loads(out.read_text(encoding="utf-8"))["violations"])


def test_a_pytest_plugin_entry_point_is_refused(gate, tmp_path):
    repo, base = make_repo(tmp_path, {"pyproject.toml": '[project]\nname = "x"\n', "tests/test_app.py": "def test_ok():\n    assert 1 == 1\n"})
    git(repo, "checkout", "-q", "-b", "ai/1-x")
    write_files(repo, {"pyproject.toml": '[project]\nname = "x"\n\n[project.entry-points.pytest11]\ncheat = "cheat"\n'})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the change")
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "guard.json"
    assert gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "ai/1-x", "--author", "a-person", "--config", config, "--out", out).returncode == 1


def test_a_change_to_the_security_review_is_listed_in_any_kind_of_pr(gate, tmp_path):
    """Decision X: listed and flagged, in a maintenance PR too."""
    row_old = "| bandit | B101 | a.py | fine |\n"
    row_new = "| bandit | B102 | b.py | also fine |\n"
    head_table = "| tool | rule | path | reason |\n|---|---|---|---|\n"
    repo, base = make_repo(tmp_path, {"security-review.md": head_table + row_old})
    git(repo, "checkout", "-q", "-b", "maintenance/1")
    write_files(repo, {"security-review.md": head_table + row_new})
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "the change")
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    out = tmp_path / "guard.json"
    process = gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", "maintenance/1", "--author", "a-person", "--config", config, "--out", out)
    assert process.returncode == 0, process.stderr
    guard = json.loads(out.read_text(encoding="utf-8"))
    assert guard["kind"] == "other"
    assert {"change": "added", "row": row_new.strip()} in guard["security_review_changes"]
    assert {"change": "removed", "row": row_old.strip()} in guard["security_review_changes"]
