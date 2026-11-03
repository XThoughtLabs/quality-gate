"""gate.guard: rules G-1 to G-14 (decisions N and O). Real temporary git repositories, no repository code is run."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from gatekit import (Repo, assert_no_traceback, assert_rc, assert_refused, git, load_out, make_config, run_gate,
                     write_json, write_script, write_text)

# ----------------------------------------------------------------------------- the synthetic baseline


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

ACC_STATUS = '''def test_history():
    assert 2 + 2 == 4


def test_permissions():
    assert 3 + 3 == 6
'''

BASE_LOCK = lock_text([("examplelib", "1.0", "a"), ("otherlib", "2.0", "bc")])

PYPROJECT = '''[tool.coverage.report]
fail_under = 90

[tool.pytest.ini_options]
addopts = "--cov-fail-under=90"

[tool.example]
min_score = 50
other_limit = 70
'''

BASE = {
    "README.md": "# example\n",
    "src/app.py": lines_file(),
    "src/util.py": "def helper():\n    return 1\n",
    "src/testing_tools.py": "def tool():\n    return 1\n",
    "src/contest.py": "def contest():\n    return 1\n",
    "tests/test_app.py": TEST_APP,
    "tests/test_unit.py": TEST_UNIT,
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
    "pyproject.toml": PYPROJECT,
    ".coveragerc": "[report]\nfail-under=90\n",
}

GUARD_CFG = {"extra_protected": ["prompts/"], "dependency_files": ["requirements.lock"],
             "dependency_sources": ["requirements.in"], "threshold_keys": ["min_score"]}


@pytest.fixture(scope="session")
def baseline(tmp_path_factory):
    repo = Repo(tmp_path_factory.mktemp("guard-baseline") / "repo")
    for path, content in BASE.items():
        repo.write(path, content)
    repo.commit("baseline")
    return repo.path


class Case:
    """A baseline repository, a change on a branch, and a way to run the guard on it."""

    def __init__(self, tmp_path, baseline, *, branch="ai/12-example", base_edits=None, guard=None):
        self.tmp = Path(tmp_path)
        self.branch = branch
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

    def change(self, edits=None, *, renames=(), raw=None, msg="change"):
        for old, new in renames:
            self.repo.mv(old, new)
        self._apply(edits or {})
        self.repo.git("add", "-A")
        for path, content in (raw or {}).items():
            self.repo.raw_add(path, content)
        self.head = self.repo.commit(msg, stage_all=False)
        return self.head

    def run(self, *, base=None, head=None, branch=None, reports=None, pr=None, config=None, extra=()):
        self._runs += 1
        out = self.tmp / f"guard-{self._runs}.json"
        args = ["--repo", self.repo.path, "--base", base or self.base, "--head", head or self.head,
                "--branch", branch or self.branch, "--config", config or self.cfg, "--out", out]
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


# ----------------------------------------------------------------------------- output shape, kinds, exit codes


@pytest.mark.req("G-0")
def test_clean_change_exits_0_and_writes_the_documented_shape(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    head = case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert set(d) >= {"kind", "head_sha", "violations", "needs_code_owner", "dependency_changes", "fingerprint",
                      "repeated_fix"}
    assert d["kind"] == "ai" and d["head_sha"] == head
    assert d["needs_code_owner"] == [] and d["dependency_changes"] == [] and d["repeated_fix"] is False
    for key in ("round", "cumulative"):
        assert re.fullmatch(r"[0-9a-f]{64}", d["fingerprint"][key]), "a fingerprint is a SHA-256 hex digest"


@pytest.mark.req("G-0")
@pytest.mark.parametrize("branch,kind", [
    ("ai/12-example", "ai"), ("spec/tests-1", "spec"), ("candidate/a", "other"), ("main", "other"),
    ("feature/ai/x", "other"), ("ai-fix", "other"), ("aix/foo", "other"), ("spec", "other"),
])
def test_kind_follows_the_branch_prefix(tmp_path, baseline, branch, kind):
    case = Case(tmp_path, baseline, branch=branch)
    case.change({"README.md": "# changed\n"})
    res, d = case.run(branch=branch)
    assert d["kind"] == kind
    if kind == "spec":
        assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", "README.md")  # kind spec, README is outside acceptance/
    else:
        assert_clean(res, d)


@pytest.mark.req("G-0", "C-2")
def test_usage_error_exits_2_without_traceback(tmp_path):
    assert_refused(run_gate("guard", "--repo", tmp_path, cwd=tmp_path), 2)


@pytest.mark.req("Q-2", "C-2")
@pytest.mark.parametrize("raw", [
    '[checks."gate/tests"]\nclass = "diagnostic"\ncommands = [["x"]]\n',
    '[checks."gate/made-up"]\nclass = "mandatory"\ncommands = [["x"]]\n',
])
def test_q2_guard_refuses_a_bad_configuration(tmp_path, baseline, raw):
    case = Case(tmp_path, baseline)
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    cfg = make_config(tmp_path / "bad.toml", guard=GUARD_CFG, raw_text=raw)
    out = tmp_path / "guard-bad.json"
    res = run_gate("guard", "--repo", case.repo.path, "--base", case.base, "--head", case.head, "--branch", case.branch,
                   "--config", cfg, "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out)


@pytest.mark.req("G-0")
def test_reads_git_objects_only_not_the_working_tree(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    case.repo.checkout("main")  # the head commit is not checked out
    case.repo.write("SPEC.md", "# edited in the working tree, never committed\n")
    case.repo.write(".github/workflows/untracked.yml", "name: x\n")
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-0")
def test_compares_the_merge_base_not_the_base_tip(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    fork_point = case.base
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    pr_head = case.head
    case.repo.checkout("main")
    case.repo.write("SPEC.md", "# main moved on and changed a protected file\n")
    main_tip = case.repo.commit("main moves on")
    res, d = case.run(base=main_tip, head=pr_head)
    assert_clean(res, d)
    res2, d2 = case.run(base=fork_point, head=pr_head)
    assert_clean(res2, d2)


@pytest.mark.req("G-0")
def test_runs_no_code_from_the_repository(tmp_path, baseline):
    marker = tmp_path / "code-ran.txt"
    spy = write_script(tmp_path / "spy.py", "import sys\nopen(sys.argv[1], 'w').write('ran')\n")
    case = Case(tmp_path, baseline)
    # 1. module-level code in a test file of the head commit must not be executed to count test functions
    evil = (f"open({str(marker)!r}, 'w').write('ran')\n"
            + TEST_APP.replace("def test_add_zero():\n    assert add(0, 0) == 0\n", ""))
    case.change({"tests/test_app.py": evil, ".github/workflows/new.yml": "name: x\n"})
    # 2. external diff / textconv / fsmonitor commands configured for the repository must not be started
    spy_cmd = f'"{Path(sys.executable).as_posix()}" "{spy.as_posix()}" "{marker.as_posix()}"'
    case.repo.git("config", "diff.external", spy_cmd)
    case.repo.git("config", "diff.spy.textconv", spy_cmd)
    case.repo.git("config", "core.fsmonitor", spy_cmd)
    write_text(case.repo.path / ".git" / "info" / "attributes", "*.py diff=spy\n*.yml diff=spy\n*.md diff=spy\n")
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", ".github/workflows/new.yml")
    assert_fires(res, d, "TEST_DELETED", "tests/test_app.py")
    assert not marker.exists(), "the guard started code that comes from the repository"


# ----------------------------------------------------------------------------- G-1


PROTECTED_CASES = [
    (".github/workflows/ci.yml", "name: ci\non: pull_request\njobs: {}\n"),       # changed
    (".github/workflows/new.yml", "name: new\n"),                                  # added
    ("acceptance/test_status.py", ACC_STATUS + "\n# touched\n"),                   # changed
    ("acceptance/notes.txt", "added\n"),                                           # added
    ("quality.toml", "[project]\nname = \"changed\"\n"),
    ("CODEOWNERS", "* someone-else\n"),
    ("SPEC.md", "# changed\n"),
    ("TASK.md", None),                                                             # deleted
    ("BASELINE.md", "# changed\n"),
    ("OPEN-ISSUES.md", "# changed\n"),
    ("SOURCE-MANIFEST.json", "{\"changed\": true}\n"),
    ("evidence/baseline.txt", None),                                               # deleted
    ("evidence/new.txt", "added\n"),
    ("prompts/executor.md", "changed prompt\n"),                                   # guard.extra_protected
]


@pytest.mark.req("G-1")
@pytest.mark.parametrize("path,content", PROTECTED_CASES, ids=[p for p, _ in PROTECTED_CASES])
def test_g1_protected_path_fires(tmp_path, baseline, path, content):
    case = Case(tmp_path, baseline)
    case.change({path: content})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


CASE_VARIANTS = [".GitHub/workflows/x.yml", "ACCEPTANCE/extra.txt", "Quality.Toml", "codeowners", "Spec.MD",
                 "task.md", "baseline.md", "open-issues.md", "Source-Manifest.JSON", "EVIDENCE/y.txt"]


@pytest.mark.req("G-1")
@pytest.mark.parametrize("path", CASE_VARIANTS)
def test_g1_any_letter_case_fires(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change(raw={path: "added\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1")
@pytest.mark.parametrize("old,new,flagged", [
    ("src/util.py", "acceptance/util.py", "acceptance/util.py"),   # moved into a protected place
    ("evidence/baseline.txt", "docs/baseline.txt", "evidence/baseline.txt"),   # moved out of a protected place
    ("SPEC.md", "docs/SPEC-copy.md", "SPEC.md"),
])
def test_g1_rename_is_checked_under_both_names(tmp_path, baseline, old, new, flagged):
    case = Case(tmp_path, baseline)
    case.change(renames=[(old, new)])
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", flagged)


@pytest.mark.req("G-1")
@pytest.mark.parametrize("path", ["src/app.py", "src/acceptance_utils.py", "src/SPEC_notes.py", "docs/github-notes.md",
                                  "evidence_summary.txt", "README.md"])
def test_g1_control_ordinary_and_near_miss_paths_are_clean(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change({path: "changed\n" if path != "src/app.py" else lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1")
def test_g1_extra_protected_adds_to_the_fixed_list_and_never_replaces_it(tmp_path, baseline):
    case = Case(tmp_path, baseline, guard={"extra_protected": ["docs/private/"]})
    case.change({"SPEC.md": "# changed\n", "docs/private/a.md": "x\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "SPEC.md")
    assert_fires(res, d, "PROTECTED_PATH", "docs/private/a.md")


@pytest.mark.req("G-1", "G-0")
def test_g1_does_not_apply_to_other_prs(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="maint/fix")
    case.change({".github/workflows/ci.yml": "name: ci2\n", "SPEC.md": "# changed\n", "tests/test_app.py": None,
                 "src/util.py": "import os  # noqa\n"})
    res, d = case.run()
    assert d["kind"] == "other"
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-2


@pytest.mark.req("G-2")
@pytest.mark.parametrize("path", ["tests/test_app.py", "tests/helpers.py", "src/foo_test.py", "src/test_baz.py"])
def test_g2_deleted_test_file_fires(tmp_path, baseline, path):
    extra = {"src/foo_test.py": "def test_foo():\n    assert 1 == 1\n", "src/test_baz.py": "def test_baz():\n    assert 1 == 1\n"}
    case = Case(tmp_path, baseline, base_edits=extra)
    case.change({path: None})
    res, d = case.run()
    assert_fires(res, d, "TEST_DELETED", path)


@pytest.mark.req("G-2")
def test_g2_deleted_test_function_fires(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"tests/test_app.py": sub(TEST_APP, "def test_add_zero():\n    assert add(0, 0) == 0\n", "")})
    res, d = case.run()
    assert_fires(res, d, "TEST_DELETED", "tests/test_app.py")


@pytest.mark.req("G-2")
def test_g2_renamed_test_function_fires(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"tests/test_app.py": sub(TEST_APP, "def test_add_zero():", "def test_add_nothing():")})
    res, d = case.run()
    assert_fires(res, d, "TEST_DELETED", "tests/test_app.py")


@pytest.mark.req("G-2")
@pytest.mark.parametrize("what", ["non-test-file", "lookalike-names", "non-test-function", "new-test"])
def test_g2_control_nothing_test_related_is_removed(tmp_path, baseline, what):
    case = Case(tmp_path, baseline)
    if what == "non-test-file":
        case.change({"src/util.py": None})
    elif what == "lookalike-names":
        case.change({"src/testing_tools.py": None, "src/contest.py": None})
    elif what == "non-test-function":
        case.change({"tests/test_app.py": sub(TEST_APP, "def _helper():\n    return 1\n\n\n", "")})
    else:
        case.change({"tests/test_app.py": TEST_APP + "\n\ndef test_extra():\n    assert 1 + 1 == 2\n"})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-3

SKIPS = {
    "mark.skip": lambda t: sub(t, "def test_add():", "@pytest.mark.skip\ndef test_add():"),
    "mark.skip-with-reason": lambda t: sub(t, "def test_add():", '@pytest.mark.skip(reason="later")\ndef test_add():'),
    "mark.skipif": lambda t: sub(t, "def test_add():", '@pytest.mark.skipif(True, reason="later")\ndef test_add():'),
    "mark.xfail": lambda t: sub(t, "def test_add():", "@pytest.mark.xfail\ndef test_add():"),
    "unittest.skip": lambda t: sub(sub(t, "import pytest\n", "import pytest\nimport unittest\n"), "def test_add():",
                                   '@unittest.skip("later")\ndef test_add():'),
    "pytest.skip-call": lambda t: sub(t, "def test_add():\n", 'def test_add():\n    pytest.skip("later")\n'),
    "pytest.xfail-call": lambda t: sub(t, "def test_add():\n", 'def test_add():\n    pytest.xfail("later")\n'),
    "a-reason-line-does-not-excuse": lambda t: sub(t, "def test_add():", "# reason: flaky on CI\n@pytest.mark.skip\ndef test_add():"),
}


@pytest.mark.req("G-3")
@pytest.mark.parametrize("variant", list(SKIPS))
def test_g3_skip_added_to_an_existing_test_fires(tmp_path, baseline, variant):
    case = Case(tmp_path, baseline)
    case.change({"tests/test_app.py": SKIPS[variant](TEST_APP)})
    res, d = case.run()
    assert_fires(res, d, "TEST_SKIPPED", "tests/test_app.py")
    if variant.endswith("-call"):
        assert "SUPPRESSION_NO_REASON" not in rules(d), "pytest.skip( inside a base test is G-3's case, not G-5's"


@pytest.mark.req("G-3")
def test_g3_control_marker_that_is_not_a_skip_is_clean(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"tests/test_app.py": sub(TEST_APP, "def test_add():", "@pytest.mark.slow\ndef test_add():")})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-3")
def test_g3_control_a_skip_that_was_already_in_the_base_is_not_gained(tmp_path, baseline):
    skipped = SKIPS["mark.skip"](TEST_APP)
    case = Case(tmp_path, baseline, base_edits={"tests/test_app.py": skipped})
    case.change({"src/util.py": "def helper():\n    return 2\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-3")
def test_g3_control_a_new_test_is_not_a_test_present_in_the_base(tmp_path, baseline):
    new = TEST_APP + '\n\n@pytest.mark.skip(reason="later")\ndef test_brand_new():\n    assert 1 + 1 == 2\n'
    case = Case(tmp_path, baseline)
    case.change({"tests/test_app.py": new})
    res, d = case.run()
    assert "TEST_SKIPPED" not in rules(d)


# ----------------------------------------------------------------------------- G-4

WEAKEN = {
    "fewer-asserts": ("tests/test_app.py", lambda t: sub(t, "    assert add(3, 3) == 6\n", "")),
    "assert-True-swapped-in": ("tests/test_app.py", lambda t: sub(t, "assert add(3, 3) == 6", "assert True")),
    "assert-1-swapped-in": ("tests/test_app.py", lambda t: sub(t, "assert add(3, 3) == 6", "assert 1")),
    "assert-True-added": ("tests/test_app.py", lambda t: sub(t, "    assert add(3, 3) == 6\n", "    assert add(3, 3) == 6\n    assert True\n")),
    "raises-Exception": ("tests/test_app.py", lambda t: sub(t, "pytest.raises(ValueError)", "pytest.raises(Exception)")),
    "raises-removed": ("tests/test_app.py", lambda t: sub(t, '    with pytest.raises(ValueError):\n        add("x", 1)\n', '    add("x", 1)\n')),
    "self-assert-dropped": ("tests/test_unit.py", lambda t: sub(t, "        self.assertIn(1, [1, 2])\n", "")),
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("variant", list(WEAKEN))
def test_g4_weakened_test_fires(tmp_path, baseline, variant):
    path, edit = WEAKEN[variant]
    original = TEST_APP if path.endswith("test_app.py") else TEST_UNIT
    case = Case(tmp_path, baseline)
    case.change({path: edit(original)})
    res, d = case.run()
    assert_fires(res, d, "TEST_WEAKENED", path)


CONTROLS_G4 = {
    "adding-a-check": ("tests/test_app.py", lambda t: sub(t, "    assert add(3, 3) == 6\n", "    assert add(3, 3) == 6\n    assert add(4, 4) == 8\n")),
    "same-count-different-check": ("tests/test_app.py", lambda t: sub(t, "assert add(3, 3) == 6", "assert add(4, 4) == 8")),
    "narrower-raises-kept": ("tests/test_app.py", lambda t: sub(t, "pytest.raises(ValueError)", "pytest.raises(TypeError)")),
    "self-assert-added": ("tests/test_unit.py", lambda t: t + "        self.assertEqual(2, 2)\n"),
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("variant", list(CONTROLS_G4))
def test_g4_control_equal_or_stronger_tests_are_clean(tmp_path, baseline, variant):
    path, edit = CONTROLS_G4[variant]
    original = TEST_APP if path.endswith("test_app.py") else TEST_UNIT
    case = Case(tmp_path, baseline)
    case.change({path: edit(original)})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-5

TAIL = "\n\ndef helper():\n    return 1\n"
G5_FIRES = {
    "noqa": "import os  # noqa\n",
    "noqa-with-code": "import os  # noqa: F401\n",
    "type-ignore": "x: int = 'a'  # type: ignore\n",
    "type-ignore-with-code": "x: int = 'a'  # type: ignore[assignment]\n",
    "pytest.skip-in-new-code": "import pytest\n\n\ndef later():\n    pytest.skip('x')\n",
    "empty-reason": "import os  # noqa  # reason:\n",
    "reason-on-the-line-below": "import os  # noqa\n# reason: re-export\n",
    "reason-two-lines-above": "# reason: re-export\n\nimport os  # noqa\n",
}
G5_CLEAN = {
    "reason-same-line": "import os  # noqa  # reason: re-export\n",
    "reason-line-above": "# reason: re-export\nimport os  # noqa\n",
    "type-ignore-with-reason": "x: int = 'a'  # type: ignore  # reason: stub gap\n",
    "pytest.skip-with-reason": "import pytest\n\n\ndef later():\n    pytest.skip('x')  # reason: needs db\n",
    "plain-comment": "import os  # keep this import\n",
}


@pytest.mark.req("G-5")
@pytest.mark.parametrize("variant", list(G5_FIRES))
def test_g5_suppression_without_reason_fires(tmp_path, baseline, variant):
    case = Case(tmp_path, baseline)
    case.change({"src/util.py": G5_FIRES[variant] + TAIL})
    res, d = case.run()
    assert_fires(res, d, "SUPPRESSION_NO_REASON", "src/util.py")


@pytest.mark.req("G-5")
@pytest.mark.parametrize("variant", list(G5_CLEAN))
def test_g5_control_suppression_with_reason_is_clean(tmp_path, baseline, variant):
    case = Case(tmp_path, baseline)
    case.change({"src/util.py": G5_CLEAN[variant] + TAIL})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-5")
def test_g5_control_a_suppression_that_was_already_there_is_not_added(tmp_path, baseline):
    case = Case(tmp_path, baseline, base_edits={"src/util.py": "import os  # noqa\n" + TAIL})
    case.change({"src/util.py": "import os  # noqa\n\n\ndef helper():\n    return 2\n"})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-6

LOWERED = {
    "fail_under": ("pyproject.toml", "fail_under = 90", "fail_under = 80"),
    "cov-fail-under": ("pyproject.toml", "--cov-fail-under=90", "--cov-fail-under=70"),
    "fail-under-no-spaces": (".coveragerc", "fail-under=90", "fail-under=85"),
    "threshold-key-from-config": ("pyproject.toml", "min_score = 50", "min_score = 40"),
    "removed-fail_under": ("pyproject.toml", "fail_under = 90\n", ""),
    "removed-fail-under": (".coveragerc", "fail-under=90\n", ""),
}


@pytest.mark.req("G-6")
@pytest.mark.parametrize("variant", list(LOWERED))
def test_g6_lowered_or_removed_threshold_fires(tmp_path, baseline, variant):
    path, old, new = LOWERED[variant]
    case = Case(tmp_path, baseline)
    case.change({path: sub(BASE[path], old, new)})
    res, d = case.run()
    assert_fires(res, d, "THRESHOLD_LOWERED", path)


@pytest.mark.req("G-6")
@pytest.mark.parametrize("path,old,new", [
    ("pyproject.toml", "fail_under = 90", "fail_under = 95"),            # raised
    ("pyproject.toml", "other_limit = 70", "other_limit = 10"),          # a key that is not a threshold key
    ("pyproject.toml", "min_score = 50", "min_score = 60"),              # raised
    (".coveragerc", "fail-under=90", "fail-under=90\nprecision = 2"),    # unrelated edit in the same file
], ids=["raised", "other-key", "threshold-key-raised", "unrelated-edit"])
def test_g6_control_other_edits_are_clean(tmp_path, baseline, path, old, new):
    case = Case(tmp_path, baseline)
    case.change({path: sub(BASE[path], old, new)})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-6")
def test_g6_control_threshold_keys_come_from_the_configuration(tmp_path, baseline):
    case = Case(tmp_path, baseline, guard={"extra_protected": ["prompts/"]})
    case.change({"pyproject.toml": sub(PYPROJECT, "min_score = 50", "min_score = 10")})
    res, d = case.run()
    assert_clean(res, d)
    case2 = Case(tmp_path / "second", baseline)
    case2.change({"pyproject.toml": sub(PYPROJECT, "min_score = 50", "min_score = 10")})
    res2, d2 = case2.run()
    assert_fires(res2, d2, "THRESHOLD_LOWERED", "pyproject.toml")


# ----------------------------------------------------------------------------- G-7 and G-8

H = lambda c: c * 64  # noqa: E731  (a hash made of one repeated letter)


@pytest.mark.req("G-7")
@pytest.mark.parametrize("variant,text", [
    ("new-line-without-hash", BASE_LOCK + "newlib==1.0\n"),
    ("one-of-two-without-hash", BASE_LOCK + f"newlib==1.0 \\\n    --hash=sha256:{H('e')}\nbadlib==2.0\n"),
    ("hash-option-of-another-kind", BASE_LOCK + "newlib==1.0 \\\n    --hash=sha512:" + "f" * 128 + "\n"),
])
def test_g7_requirement_without_hash_fires(tmp_path, baseline, variant, text):
    case = Case(tmp_path, baseline)
    case.change({"requirements.lock": text})
    res, d = case.run()
    assert_fires(res, d, "DEPENDENCY_NO_HASH", "requirements.lock")


@pytest.mark.req("G-7")
@pytest.mark.parametrize("variant,text", [
    ("hash-after-a-continuation", BASE_LOCK + f"newlib==1.0 \\\n    --hash=sha256:{H('e')}\n"),
    ("hash-on-the-same-line", BASE_LOCK + f"newlib==1.0 --hash=sha256:{H('e')}\n"),
    ("two-hashes-two-continuations", BASE_LOCK + f"newlib==1.0 \\\n    --hash=sha256:{H('e')} \\\n    --hash=sha256:{H('f')}\n"),
    ("comments-and-blank-lines", BASE_LOCK + f"\n# a comment\nnewlib==1.0 \\\n    --hash=sha256:{H('e')}\n"),
])
def test_g7_control_hashed_requirements_are_not_a_violation(tmp_path, baseline, variant, text):
    case = Case(tmp_path, baseline)
    case.change({"requirements.lock": text})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == ["requirements.lock"]


@pytest.mark.req("G-7")
def test_g7_changed_dependency_source_without_a_dependency_file_change_fires(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"requirements.in": "examplelib\notherlib\nnewlib\n"})
    res, d = case.run()
    # CONTRACTS.md does not say which path this violation carries: accept the source or the dependency file.
    assert_fires(res, d, "DEPENDENCY_NO_HASH")
    assert {v["path"] for v in of(d, "DEPENDENCY_NO_HASH")} & {"requirements.in", "requirements.lock"}


@pytest.mark.req("G-7")
def test_g7_control_source_and_dependency_file_changed_together(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"requirements.in": "examplelib\notherlib\nnewlib\n",
                 "requirements.lock": BASE_LOCK + f"newlib==1.0 \\\n    --hash=sha256:{H('e')}\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-8")
def test_g8_upgrade_add_and_remove_are_listed_with_old_new_and_changelog(tmp_path, baseline):
    new_lock = lock_text([("examplelib", "2.0", "d"), ("newlib", "1.5", "e")])  # otherlib removed
    case = Case(tmp_path, baseline)
    case.change({"requirements.lock": new_lock})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == ["requirements.lock"]
    by_name = {c["name"]: c for c in d["dependency_changes"]}
    assert set(by_name) == {"examplelib", "newlib", "otherlib"}
    assert by_name["examplelib"] == {"name": "examplelib", "old": "1.0", "new": "2.0",
                                     "changelog": "https://pypi.org/project/examplelib/2.0/"}
    assert by_name["newlib"] == {"name": "newlib", "old": None, "new": "1.5",
                                 "changelog": "https://pypi.org/project/newlib/1.5/"}
    assert by_name["otherlib"] == {"name": "otherlib", "old": "2.0", "new": None,
                                   "changelog": "https://pypi.org/project/otherlib/2.0/"}


@pytest.mark.req("G-8")
def test_g8_unchanged_packages_are_not_listed(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"requirements.lock": lock_text([("examplelib", "1.1", "d"), ("otherlib", "2.0", "bc")])})
    res, d = case.run()
    assert_clean(res, d)
    assert [c["name"] for c in d["dependency_changes"]] == ["examplelib"]


@pytest.mark.req("G-8")
def test_g8_control_no_dependency_change_means_no_approval_needed(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == [] and d["dependency_changes"] == []


# ----------------------------------------------------------------------------- G-9 and the fingerprints


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


@pytest.mark.req("G-9")
def test_g9_the_same_fix_in_a_later_round_is_a_repeated_fix(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    r1, d1 = run_store(case, c1, reports, 5, 100)
    assert_clean(r1, d1)
    c2 = commit_app(case, "VALUE = 1", "OTHER = 'y'")
    r2, d2 = run_store(case, c2, reports, 5, 101)
    assert_clean(r2, d2)
    c3 = commit_app(case, "VALUE = 2", "OTHER = 'y'")  # the round-1 edit again, on a different tree
    r3, d3 = case.run(head=c3, reports=reports, pr=5)
    assert_fires(r3, d3, "REPEATED_FIX")
    assert d3["repeated_fix"] is True
    assert d3["fingerprint"]["round"] == d1["fingerprint"]["round"]
    assert d3["fingerprint"]["round"] == fp_between(case, c2, c3), "round covers the previous stored head to the head"
    assert d3["fingerprint"]["cumulative"] not in (d1["fingerprint"]["cumulative"], d2["fingerprint"]["cumulative"]), \
        "this case must be caught by the round fingerprint alone"


@pytest.mark.req("G-9", "V-3")
def test_g9_two_identical_rounds_end_in_needs_human_through_the_report(tmp_path, baseline):
    from reportkit import World

    case = Case(tmp_path / "git", baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    run_store(case, c1, reports, 5, 100)
    c2 = commit_app(case, "VALUE = 1", "OTHER = 'y'")
    run_store(case, c2, reports, 5, 101)
    c3 = commit_app(case, "VALUE = 2", "OTHER = 'y'")
    res, d = case.run(head=c3, reports=reports, pr=5)
    assert_fires(res, d, "REPEATED_FIX")
    world = World(tmp_path / "judge")
    world.guard = d               # the guard's own output, as the judge's artifact carries it
    world.fail("gate/guard", res.rc)
    out = world.run().need()
    assert out.verdict["verdict"] == "needs-human", out.describe()
    assert "REPEATED_FIX" in out.codes


@pytest.mark.req("G-9")
def test_g9_the_same_cumulative_diff_again_is_a_repeated_fix(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    r1, d1 = run_store(case, c1, reports, 5, 100)
    c2 = commit_app(case, "VALUE = 2", "OTHER = 'y'")
    r2, d2 = run_store(case, c2, reports, 5, 101)
    assert_clean(r2, d2)
    c3 = commit_app(case, "VALUE = 2", "OTHER = 'x'")  # back to the tree of round 1
    r3, d3 = case.run(head=c3, reports=reports, pr=5)
    assert_fires(r3, d3, "REPEATED_FIX")
    assert d3["repeated_fix"] is True
    assert d3["fingerprint"]["cumulative"] == d1["fingerprint"]["cumulative"]
    assert d3["fingerprint"]["round"] not in (d1["fingerprint"]["round"], d2["fingerprint"]["round"]), \
        "this case must be caught by the cumulative fingerprint alone"


@pytest.mark.req("G-9")
def test_g9_control_different_fixes_are_not_repeated(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    for run_id, (a, b) in enumerate([("VALUE = 2", "OTHER = 'x'"), ("VALUE = 2", "OTHER = 'y'"),
                                     ("VALUE = 2", "OTHER = 'z'")], start=100):
        head = commit_app(case, a, b)
        res, d = run_store(case, head, reports, 5, run_id)
        assert_clean(res, d)
        assert d["repeated_fix"] is False


@pytest.mark.req("G-9")
def test_g9_control_a_rerun_of_one_commit_is_not_a_repeat(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    r1, d1 = run_store(case, c1, reports, 5, 100)
    r2, d2 = case.run(head=c1, reports=reports, pr=5)
    assert_clean(r2, d2)
    assert d2["repeated_fix"] is False
    assert d2["fingerprint"]["round"] == d2["fingerprint"]["cumulative"] == d1["fingerprint"]["cumulative"], \
        "records of the same head are ignored, so the round runs from the merge base"


@pytest.mark.req("G-9")
def test_g9_control_without_reports_dir_or_pr_nothing_is_repeated(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    run_store(case, c1, reports, 5, 100)
    c2 = commit_app(case, "VALUE = 2", "OTHER = 'y'")
    run_store(case, c2, reports, 5, 101)
    c3 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    res, d = case.run(head=c3, reports=reports, pr=5)
    assert_fires(res, d, "REPEATED_FIX")  # sanity: with both, it is a repeat
    res, d = case.run(head=c3, reports=reports)  # no --pr
    assert_clean(res, d)
    assert d["repeated_fix"] is False
    res, d = case.run(head=c3, pr=5)  # no --reports-dir
    assert_clean(res, d)
    assert d["repeated_fix"] is False
    assert d["fingerprint"]["round"] == d["fingerprint"]["cumulative"], "with nothing stored the round starts at the merge base"


@pytest.mark.req("G-9")
def test_g9_control_records_of_another_pr_are_not_considered(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    run_store(case, c1, reports, 6, 100)
    c2 = commit_app(case, "VALUE = 2", "OTHER = 'y'")
    run_store(case, c2, reports, 6, 101)
    c3 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    res, d = case.run(head=c3, reports=reports, pr=5)
    assert_clean(res, d)


@pytest.mark.req("G-9")
def test_g9_first_round_covers_the_merge_base_to_the_head(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    res, d = case.run(head=c1, reports=tmp_path / "empty-reports", pr=5)
    assert_clean(res, d)
    assert d["fingerprint"]["round"] == d["fingerprint"]["cumulative"]


FP_NOTE = "the normalized diff drops index lines, hunk header numbers, trailing whitespace and carriage returns"


@pytest.mark.req("G-9")
def test_g9_fingerprint_ignores_index_lines_and_hunk_numbers(tmp_path, baseline):
    x = Case(tmp_path / "x", baseline, base_edits=None)
    y = Case(tmp_path / "y", baseline, base_edits={"src/app.py": lines_file(top=7)})
    hx = x.change({"src/app.py": lines_file(a="VALUE = 2")})
    hy = y.change({"src/app.py": lines_file(a="VALUE = 2", top=7)})
    rx, dx = x.run()
    ry, dy = y.run()
    assert dx["fingerprint"]["cumulative"] == dy["fingerprint"]["cumulative"], FP_NOTE
    z = Case(tmp_path / "z", baseline)
    z.change({"src/app.py": lines_file(a="VALUE = 3")})
    rz, dz = z.run()
    assert dz["fingerprint"]["cumulative"] != dx["fingerprint"]["cumulative"], "a different change must differ"


@pytest.mark.req("G-9")
@pytest.mark.parametrize("variant", ["trailing-spaces", "carriage-return"])
def test_g9_fingerprint_ignores_trailing_whitespace_and_carriage_returns(tmp_path, baseline, variant):
    x = Case(tmp_path / "x", baseline)
    x.change({"src/app.py": lines_file(a="VALUE = 2")})
    y = Case(tmp_path / "y", baseline)
    new = lines_file(a="VALUE = 2   ") if variant == "trailing-spaces" else lines_file(a="VALUE = 2\r")
    y.change({"src/app.py": new})
    rx, dx = x.run()
    ry, dy = y.run()
    assert dx["fingerprint"]["cumulative"] == dy["fingerprint"]["cumulative"], FP_NOTE


# ----------------------------------------------------------------------------- G-10

SHA40 = "a" * 40
UNPINNED = {
    "tag": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n",
    "branch": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@main\n",
    "short-sha": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@abcdef1\n",
    "39-hex": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{'a' * 39}\n",
    "41-hex": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{'a' * 41}\n",
    "without-list-marker": f"jobs:\n  a:\n    steps:\n      - name: x\n        uses: actions/checkout@v4\n",
}
PINNED = {
    "full-sha": f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA40}\n",
    "local-path": "jobs:\n  a:\n    steps:\n      - uses: ./local/action\n",
    "docker-digest": f"jobs:\n  a:\n    steps:\n      - uses: docker://alpine@sha256:{'b' * 64}\n",
}


@pytest.mark.req("G-10")
@pytest.mark.parametrize("ext", ["yml", "yaml"])
@pytest.mark.parametrize("variant", list(UNPINNED))
def test_g10_unpinned_action_fires(tmp_path, baseline, variant, ext):
    case = Case(tmp_path, baseline)
    path = f"tools/ci/flow.{ext}"
    case.change({path: UNPINNED[variant]})
    res, d = case.run()
    assert_fires(res, d, "UNPINNED_ACTION", path)


@pytest.mark.req("G-10")
@pytest.mark.parametrize("variant", list(PINNED))
def test_g10_control_pinned_local_and_digest_references_are_clean(tmp_path, baseline, variant):
    case = Case(tmp_path, baseline)
    case.change({"tools/ci/flow.yml": PINNED[variant]})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-10")
def test_g10_control_only_added_lines_in_yaml_files_count(tmp_path, baseline):
    old = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - run: echo one\n"
    case = Case(tmp_path, baseline, base_edits={"tools/ci/old.yml": old})
    case.change({"tools/ci/old.yml": sub(old, "echo one", "echo two"),
                 "docs/notes.md": "uses: actions/checkout@v4\n", "tools/ci/notes.txt": "uses: actions/checkout@v4\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-10")
def test_g10_still_applies_to_spec_prs_but_not_to_other_prs(tmp_path, baseline):
    spec = Case(tmp_path / "spec", baseline, branch="spec/tests-1")
    spec.change({"acceptance/ci.yml": UNPINNED["tag"]})
    res, d = spec.run()
    assert_fires(res, d, "UNPINNED_ACTION", "acceptance/ci.yml")
    assert "SPEC_OUTSIDE_ACCEPTANCE" not in rules(d)
    other = Case(tmp_path / "other", baseline, branch="maint/ci")
    other.change({"tools/ci/flow.yml": UNPINNED["tag"]})
    res, d = other.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-11


@pytest.mark.req("G-11")
@pytest.mark.parametrize("path", ["src/app.py", "tests/test_app.py", "README.md", "SPEC.md"])
def test_g11_spec_pr_touching_outside_acceptance_fires_only_g11(tmp_path, baseline, path):
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    case.change({path: "changed\n"})
    res, d = case.run()
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", path)
    assert set(rules(d)) == {"SPEC_OUTSIDE_ACCEPTANCE"}, "G-1 to G-10 do not apply to spec PRs"


@pytest.mark.req("G-11")
def test_g11_control_acceptance_only_is_clean_even_with_things_g2_g5_would_flag(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    weakened = "import os  # noqa\n\n\ndef test_permissions():\n    assert True\n"
    case.change({"acceptance/test_status.py": weakened, "acceptance/test_search.py": "def test_find():\n    assert 1 == 1\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-11")
def test_g11_only_the_outside_path_is_reported(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    case.change({"acceptance/test_search.py": "def test_find():\n    assert 1 == 1\n", "src/util.py": "x = 1\n"})
    res, d = case.run()
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", "src/util.py")
    assert [v["path"] for v in of(d, "SPEC_OUTSIDE_ACCEPTANCE")] == ["src/util.py"]


# ----------------------------------------------------------------------------- G-12, G-13, G-14

KNOWN = "acceptance/known-failing.txt"
T_HISTORY = "acceptance.test_status::test_history"
T_PERMS = "acceptance.test_status::test_permissions"
LIST_ONE = f"{T_HISTORY} PUB-01\n"
LIST_TWO = f"{T_HISTORY} PUB-01\n{T_PERMS} SPEC-6.1\n"


def store_acceptance(reports, pr, run_id, attempt, passed):
    write_json(Path(reports) / str(pr) / f"{run_id}-{attempt}" / "acceptance.json",
               {"ok": True, "mode": "subset", "list_size": 0, "failing_not_listed": [], "listed_failing": [],
                "remove_from_list": [], "missing_listed": [], "passed": sorted(passed), "reason_codes": []})


@pytest.mark.req("G-12")
def test_g12_adding_an_entry_for_a_test_that_has_a_stored_pass_fires(tmp_path, baseline):
    reports = tmp_path / "reports"
    store_acceptance(reports, 3, 200, 1, [T_HISTORY])
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    case.change({KNOWN: LIST_ONE})
    res, d = case.run(reports=reports, pr=9)
    assert_fires(res, d, "KNOWN_FAILING_ADD_PASSED", KNOWN)


@pytest.mark.req("G-12")
@pytest.mark.parametrize("branch", ["spec/tests-1", "ai/12-example", "maint/lists"])
def test_g12_applies_to_every_kind_of_pr(tmp_path, baseline, branch):
    reports = tmp_path / "reports"
    store_acceptance(reports, 3, 200, 1, [T_HISTORY])
    case = Case(tmp_path, baseline, branch=branch)
    case.change({KNOWN: LIST_ONE})
    res, d = case.run(reports=reports, pr=9)
    assert_fires(res, d, "KNOWN_FAILING_ADD_PASSED", KNOWN)


@pytest.mark.req("G-12")
@pytest.mark.parametrize("stored", ["nothing-stored", "other-test-passed", "test-only-failed"])
def test_g12_control_no_stored_pass_for_that_test_is_clean(tmp_path, baseline, stored):
    reports = tmp_path / "reports"
    if stored == "other-test-passed":
        store_acceptance(reports, 3, 200, 1, [T_PERMS])
    elif stored == "test-only-failed":
        store_acceptance(reports, 3, 200, 1, [])
    else:
        reports.mkdir()
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    case.change({KNOWN: LIST_ONE})
    res, d = case.run(reports=reports, pr=9)
    assert_clean(res, d)


@pytest.mark.req("G-13")
@pytest.mark.parametrize("branch", ["maint/lists", "ai/12-example"])
def test_g13_entry_added_on_a_pr_that_is_not_spec_fires(tmp_path, baseline, branch):
    case = Case(tmp_path, baseline, branch=branch)
    case.change({KNOWN: LIST_ONE})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_fires(res, d, "KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN)


@pytest.mark.req("G-13")
def test_g13_control_spec_pr_introducing_the_first_list_may_use_any_valid_id(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/tests-1")
    case.change({KNOWN: f"{T_HISTORY} PUB-01\n{T_PERMS} SPEC-6.2\nacceptance.test_status::test_extra DEF-found-1\n"})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_clean(res, d)


NEW_TEST = "def test_new_defect():\n    assert 2 + 2 == 4\n"


@pytest.mark.req("G-13")
@pytest.mark.parametrize("entry", [
    "acceptance.test_new::test_new_defect PUB-04",                 # not a DEF id
    "acceptance.test_new::test_new_defect SPEC-6.1",
])
def test_g13_with_an_existing_list_only_def_ids_are_allowed(tmp_path, baseline, entry):
    case = Case(tmp_path, baseline, branch="spec/tests-1", base_edits={KNOWN: LIST_ONE})
    case.change({KNOWN: LIST_ONE + entry + "\n", "acceptance/test_new.py": NEW_TEST})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_fires(res, d, "KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN)


@pytest.mark.req("G-13")
def test_g13_with_an_existing_list_a_test_that_already_exists_in_the_base_is_refused(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/tests-1", base_edits={KNOWN: LIST_ONE})
    case.change({KNOWN: LIST_ONE + f"{T_PERMS} DEF-x\n"})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_fires(res, d, "KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN)


@pytest.mark.req("G-13")
def test_g13_control_a_new_test_of_a_new_defect_is_allowed_on_a_spec_pr(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/tests-1", base_edits={KNOWN: LIST_ONE})
    case.change({KNOWN: LIST_ONE + "acceptance.test_new::test_new_defect DEF-new-bug\n", "acceptance/test_new.py": NEW_TEST})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_clean(res, d)


@pytest.mark.req("G-13", "G-12", "G-14")
@pytest.mark.parametrize("branch", ["spec/tests-1", "maint/lists"])
def test_g12_g13_g14_control_a_comment_only_edit_changes_no_entry(tmp_path, baseline, branch):
    case = Case(tmp_path, baseline, branch=branch, base_edits={KNOWN: LIST_ONE})
    case.change({KNOWN: "# the list only shrinks\n" + LIST_ONE})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_clean(res, d)


@pytest.mark.req("G-14")
@pytest.mark.parametrize("branch", ["maint/lists", "ai/12-example"])
def test_g14_removing_an_entry_without_a_stored_pass_fires(tmp_path, baseline, branch):
    case = Case(tmp_path, baseline, branch=branch, base_edits={KNOWN: LIST_TWO})
    case.change({KNOWN: LIST_ONE})
    res, d = case.run(reports=tmp_path / "reports", pr=9)
    assert_fires(res, d, "KNOWN_FAILING_REMOVED_NOT_PASSED", KNOWN)


@pytest.mark.req("G-14")
def test_g14_a_stored_pass_for_another_test_does_not_excuse_the_removal(tmp_path, baseline):
    reports = tmp_path / "reports"
    store_acceptance(reports, 3, 200, 1, [T_HISTORY])
    case = Case(tmp_path, baseline, branch="maint/lists", base_edits={KNOWN: LIST_TWO})
    case.change({KNOWN: f"{T_HISTORY} PUB-01\n"})  # removes T_PERMS, which never passed
    res, d = case.run(reports=reports, pr=9)
    assert_fires(res, d, "KNOWN_FAILING_REMOVED_NOT_PASSED", KNOWN)


@pytest.mark.req("G-14")
def test_g14_control_removal_of_an_entry_that_has_a_stored_pass_is_clean(tmp_path, baseline):
    reports = tmp_path / "reports"
    store_acceptance(reports, 3, 200, 1, [T_PERMS])
    case = Case(tmp_path, baseline, branch="maint/lists", base_edits={KNOWN: LIST_TWO})
    case.change({KNOWN: f"{T_HISTORY} PUB-01\n"})
    res, d = case.run(reports=reports, pr=9)
    assert_clean(res, d)
