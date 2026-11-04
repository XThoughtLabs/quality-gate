"""The synthetic baseline repository and the way to run gate.guard on a change to it (shared by the guard tests)."""
from __future__ import annotations

from pathlib import Path

from gatekit import (Repo, assert_no_traceback, assert_rc, git, load_out, make_config, run_gate, write_json)

EXECUTOR = "example-executor[bot]"     # the login of feedback.executor_app in the configurations below
REVIEWER = "example-reviewer[bot]"
PERSON = "some-person"


def lock_text(entries):
    out = []
    for name, ver, hs in entries:
        if not hs:
            out.append(f"{name}=={ver}\n")
        else:
            out.append(f"{name}=={ver} \\\n" + " \\\n".join(f"    --hash=sha256:{c * 64}" for c in hs) + "\n")
    return "".join(out)


def lines_file(a="VALUE = 1", b="OTHER = 'x'", top=0):
    ls = [f"# filler {i}" for i in range(1, 61)]
    ls[4] = a
    ls[49] = b
    return "\n".join([f"# extra {i}" for i in range(top)] + ls) + "\n"


TEST_APP = '''import pytest
from src.app import add


def _helper():
    return 1


def test_add():
    assert add(1, 2) == 3
    assert add(2, 2) == 4
    assert add(3, 3) == 6


def test_add_zero():
    assert add(0, 0) == 0


def test_raises():
    with pytest.raises(ValueError):
        add("x", 1)
'''

TEST_UNIT = '''import unittest


class AddTest(unittest.TestCase):
    def test_equal(self):
        self.assertEqual(1 + 1, 2)
        self.assertIn(1, [1, 2])
'''

# A richer test file for the methods, tautologies, parametrize and assert_* cases (G-2, G-4, G-4a)
TEST_EXTRA = '''import unittest

import pytest

from src.app import add


def assert_sum(a, b, expected):
    assert add(a, b) == expected


class TestMath:
    def test_one(self):
        assert add(1, 1) == 2
        assert add(2, 2) == 4

    def helper(self):
        return 1


class CaseTest(unittest.TestCase):
    def testFoo(self):
        self.assertEqual(add(1, 2), 3)
        self.assertEqual(add(2, 3), 5)


@pytest.mark.parametrize("x", [1, 2, 3])
def test_param(x):
    assert x > 0


def test_helpers():
    assert_sum(1, 2, 3)
    assert_sum(2, 2, 4)
    assert add(0, 0) == 0
'''

ACC_STATUS = '''def test_history():
    assert 2 + 2 == 4


def test_permissions():
    assert 3 + 3 == 6
'''

BASE_LOCK = lock_text([("examplelib", "1.0", "a"), ("otherlib", "2.0", "bc")])

PYPROJECT = '''[project]
name = "example"

[tool.coverage.report]
fail_under = 90

[tool.pytest.ini_options]
addopts = "--cov-fail-under=90"

[tool.example]
min_score = 50
other_limit = 70

[tool.ruff]
line-length = 100

[tool.poetry]
name = "example"
'''

# The same three kinds of file without the word pytest anywhere (decision X: G-1b looks at that word in setup.cfg and tox.ini)
FREE_PYPROJECT = '''[project]
name = "example"

[tool.ruff]
line-length = 100

[tool.poetry]
name = "example"
'''

FREE_SETUP_CFG = '''[metadata]
name = example

[options]
packages = find:

[flake8]
max-line-length = 100

[mypy]
strict = True

[coverage:run]
branch = True

[bandit]
skips = B101
'''

FREE_TOX_INI = '''[tox]
envlist = py313

[testenv]
commands = python -m unittest

[testenv:lint]
commands = flake8

[coverage:run]
branch = True

[bandit]
skips = B101

[flake8]
max-line-length = 100

[docs]
note = nothing
'''

SETUP_CFG = '''[metadata]
name = example

[options]
packages = find:

[tool:pytest]
addopts = -q

[coverage:run]
branch = True

[bandit]
skips = B101

[flake8]
max-line-length = 100

[mypy]
strict = True
'''

TOX_INI = '''[tox]
envlist = py313

[testenv]
commands = pytest

[testenv:lint]
commands = flake8

[pytest]
addopts = -q

[coverage:run]
branch = True

[bandit]
skips = B101

[flake8]
max-line-length = 100

[mypy]
strict = True

[docs]
note = nothing
'''

BASE = {
    "README.md": "# example\n",
    "src/app.py": lines_file(),
    "src/util.py": "def helper():\n    return 1\n",
    "src/testing_tools.py": "def tool():\n    return 1\n",
    "src/contest.py": "def contest():\n    return 1\n",
    "tests/test_app.py": TEST_APP,
    "tests/test_unit.py": TEST_UNIT,
    "tests/test_extra.py": TEST_EXTRA,
    "tests/helpers.py": "def make():\n    return 1\n",
    "acceptance/test_status.py": ACC_STATUS,
    "requirements.lock": BASE_LOCK,
    "requirements.in": "examplelib\notherlib\n",
    ".github/workflows/ci.yml": "name: ci\non: push\njobs: {}\n",
    "quality.toml": "[project]\nname = \"example\"\n",
    "CODEOWNERS": "* owner\n",
    "SPEC.md": "# spec\n",
    "TASK.md": "# task\n",
    "BASELINE.md": "# baseline\n",
    "OPEN-ISSUES.md": "# issues\n",
    "SOURCE-MANIFEST.json": "{}\n",
    "evidence/baseline.txt": "evidence\n",
    "prompts/executor.md": "prompt\n",
    "security-review.md": "| tool | rule | path | reason |\n|---|---|---|---|\n",
    "pyproject.toml": PYPROJECT,
    "setup.cfg": SETUP_CFG,
    "tox.ini": TOX_INI,
    # threshold-bearing files that no rule protects by itself, so that G-6 can be seen alone
    ".coveragerc": "[report]\nfail-under=90\n",
    "ci/limits.toml": "min_score = 50\nother_limit = 70\n",
    "Makefile": "test:\n\tpytest --cov-fail-under=90 -q\n",
    "ci/limits.yml": "fail_under: 90\n",
    "ci/args.py": 'ARGS = ["pytest", "--cov-fail-under", "90"]\n',
}

GUARD_CFG = {"extra_protected": ["prompts/"], "dependency_files": ["requirements.lock"],
             "dependency_sources": ["requirements.in"], "threshold_keys": ["min_score"]}


def build_baseline(tmp_path_factory):
    repo = Repo(tmp_path_factory.mktemp("guard-baseline") / "repo")
    for path, content in BASE.items():
        repo.write(path, content)
    repo.commit("baseline")
    return repo.path


class Case:
    """A baseline repository, a change on a branch, and a way to run the guard on it."""

    def __init__(self, tmp_path, baseline, *, branch="ai/12-example", base_edits=None, guard=None, author=None):
        self.tmp = Path(tmp_path)
        self.branch = branch
        # the PR's author comes from the trusted context; the default follows what the branch name suggests
        self.author = author or (EXECUTOR if branch.lower().startswith(("ai/", "spec/")) else PERSON)
        self.repo = Repo.clone(baseline, self.tmp / "repo")
        if base_edits:
            self._apply(base_edits)
            self.repo.commit("baseline tweaks")
        self.base = self.repo.sha()
        self.head = self.base
        self.repo.branch("pr-branch")  # a neutral git branch name; the guard is told the name through --branch
        self.cfg = make_config(self.tmp / "quality.toml", guard=GUARD_CFG if guard is None else guard)
        self._runs = 0

    def _apply(self, edits):
        for path, content in edits.items():
            if content is None:
                self.repo.remove(path)
            else:
                self.repo.write(path, content)

    def change(self, edits=None, *, renames=(), raw=None, msg="change", author_name=None, committer_name=None):
        for old, new in renames:
            self.repo.mv(old, new)
        self._apply(edits or {})
        self.repo.git("add", "-A")
        for path, content in (raw or {}).items():
            self.repo.raw_add(path, content)
        self.head = self.repo.commit(msg, stage_all=False, author_name=author_name, committer_name=committer_name)
        return self.head

    def run(self, *, base=None, head=None, branch=None, author=None, reports=None, pr=None, config=None, extra=()):
        self._runs += 1
        out = self.tmp / f"guard-{self._runs}.json"
        args = ["--repo", self.repo.path, "--base", base or self.base, "--head", head or self.head,
                "--branch", branch or self.branch, "--author", author or self.author,
                "--config", config or self.cfg, "--out", out]
        if reports is not None:
            Path(reports).mkdir(parents=True, exist_ok=True)
            args += ["--reports-dir", reports]
        if pr is not None:
            args += ["--pr", pr]
        args += list(extra)
        res = run_gate("guard", *args, cwd=self.tmp)
        return res, load_out(res, out)


def sub(text, old, new):
    assert old in text, f"test setup error: {old!r} not found"
    return text.replace(old, new, 1)


def rules(d):
    return [v["rule"] for v in d["violations"]]


def of(d, rule):
    return [v for v in d["violations"] if v["rule"] == rule]


def assert_clean(res, d):
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert d["violations"] == [], f"expected no violation, got {d['violations']}"


def assert_fires(res, d, rule, path=None):
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d is not None, "--out must be written even when the guard fails"
    for v in d["violations"]:
        assert {"rule", "path", "detail"} <= set(v), v
    got = of(d, rule)
    assert got, f"{rule} did not fire; violations: {d['violations']}"
    if path is not None:
        assert any(v["path"] == path for v in got), f"{rule} fired but not for {path}: {got}"


def store_guard(reports, pr, run_id, attempt, guard_json):
    write_json(Path(reports) / str(pr) / f"{run_id}-{attempt}" / "guard.json", guard_json)


def commit_app(case, a, b):
    return case.change({"src/app.py": lines_file(a, b)})


def run_store(case, head, reports, pr, run_id, attempt=1):
    res, d = case.run(head=head, reports=reports, pr=pr)
    store_guard(reports, pr, run_id, attempt, d)
    return res, d


def fp_between(case, a, b):
    res, d = case.run(base=a, head=b)
    return d["fingerprint"]["cumulative"]
