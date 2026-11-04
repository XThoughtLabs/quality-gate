"""gate.guard after decisions U, V and W: the kind of a PR, G-1 and its parts, G-2/G-4/G-4a, G-5, G-9 additions.

Every strict case is proved with a change that a looser kind would let through; every firing case has a control.
"""
from __future__ import annotations

import pytest

from gatekit import write_text
from guardkit import (BASE, EXECUTOR, FREE_SETUP_CFG, FREE_TOX_INI, PERSON, PYPROJECT, REVIEWER, SETUP_CFG, TEST_EXTRA,
                      TOX_INI, Case, assert_clean, assert_fires, commit_app, lines_file, of, rules, run_store, sub)

HARM = {"SPEC.md": "# edited by someone who may not\n", "tests/test_app.py": None}   # G-1 and G-2 in an ai PR


# ----------------------------------------------------------------------------- the kind of a PR (decision V)

STRICT_AI = [
    # id, branch, --author, author name of the commit, committer name of the commit
    ("executor-on-an-innocent-branch", "feature/x", EXECUTOR, None, None),
    ("executor-on-main", "main", EXECUTOR, None, None),
    ("any-bot-author", "feature/x", "dependabot[bot]", None, None),
    ("reviewer-bot-author", "feature/x", REVIEWER, None, None),
    ("person-with-a-commit-authored-by-the-executor", "feature/x", PERSON, EXECUTOR, None),
    ("person-with-a-commit-committed-by-the-executor", "feature/x", PERSON, None, EXECUTOR),
    ("person-with-a-commit-authored-by-claude-bot", "feature/x", PERSON, "claude[bot]", None),
    ("person-with-a-commit-committed-by-claude-bot", "feature/x", PERSON, None, "claude[bot]"),
    ("AI/1-by-a-person", "AI/1", PERSON, None, None),
    ("Ai/1-by-a-person", "Ai/1", PERSON, None, None),
    ("Spec/x-by-a-person", "Spec/x", PERSON, None, None),
    ("executor-on-SPEC/x", "SPEC/x", EXECUTOR, None, None),
    ("executor-on-Spec/x", "Spec/x", EXECUTOR, None, None),
    ("person-on-spec/x", "spec/x", PERSON, None, None),
    ("another-bot-on-spec/x", "spec/x", "other-app[bot]", None, None),
    ("reviewer-bot-on-spec/x", "spec/x", REVIEWER, None, None),
]


@pytest.mark.req("V-KIND")
@pytest.mark.parametrize("branch,author,author_name,committer_name", [c[1:] for c in STRICT_AI],
                         ids=[c[0] for c in STRICT_AI])
def test_kind_strict_cases_are_ai_and_refuse_a_harmful_change(tmp_path, baseline, branch, author, author_name, committer_name):
    case = Case(tmp_path, baseline, branch=branch, author=author)
    case.change(HARM, author_name=author_name, committer_name=committer_name)
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", "SPEC.md")
    assert of(d, "TEST_DELETED"), "and the deleted test is refused too"


@pytest.mark.req("V-KIND")
def test_kind_one_executor_commit_among_a_persons_own_commits_makes_the_pr_strict(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="feature/x", author=PERSON)
    case.change({"README.md": "# edited by the executor\n"}, author_name=EXECUTOR)
    case.change({"src/util.py": "x = 1\n"}, author_name="A Person")
    case.change({"SPEC.md": "# edited\n"}, author_name="A Person")
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", "SPEC.md")


OTHER_BRANCHES = [("feature/x", PERSON), ("candidate/a", PERSON), ("main", PERSON), ("ai-fix", PERSON),
                  ("feature/ai/x", PERSON), ("aix/foo", PERSON), ("spec", PERSON), ("maint/lists", "another-person"),
                  ("feature/x", "example-executor")]   # the executor's name without [bot] is a person's login


@pytest.mark.req("V-KIND")
@pytest.mark.parametrize("branch,author", OTHER_BRANCHES, ids=[f"{b}-by-{a}" for b, a in OTHER_BRANCHES])
def test_kind_a_person_on_an_ordinary_branch_with_commits_of_their_own_is_other(tmp_path, baseline, branch, author):
    case = Case(tmp_path, baseline, branch=branch, author=author)
    case.change(HARM, author_name="A Person", committer_name="A Person")
    res, d = case.run()
    assert d["kind"] == "other"
    assert_clean(res, d)   # people may touch these paths; the same change by the executor is refused above


@pytest.mark.req("V-KIND")
@pytest.mark.parametrize("name", ["example-executor", "claude", "Claude Code", "example-executor-2"])
def test_kind_names_that_only_look_like_the_bots_do_not_make_a_pr_strict(tmp_path, baseline, name):
    case = Case(tmp_path, baseline, branch="feature/x", author=PERSON)
    case.change(HARM, author_name=name, committer_name=name)
    res, d = case.run()
    assert d["kind"] == "other"
    assert_clean(res, d)


@pytest.mark.req("V-KIND")
def test_kind_a_login_that_ends_in_bot_is_strict_but_one_that_merely_contains_it_is_not(tmp_path, baseline):
    near = Case(tmp_path / "near", baseline, branch="feature/x", author="robot-bot-fan")
    near.change(HARM)
    res, d = near.run()
    assert d["kind"] == "other" and not d["violations"]
    far = Case(tmp_path / "far", baseline, branch="feature/x", author="robot-bot-fan[bot]")
    far.change(HARM)
    res, d = far.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", "SPEC.md")


@pytest.mark.req("V-KIND")
def test_kind_the_executor_on_exactly_spec_slash_is_spec_and_may_touch_only_acceptance(tmp_path, baseline):
    case = Case(tmp_path / "ok", baseline, branch="spec/tests-2", author=EXECUTOR)
    case.change({"acceptance/test_new.py": "def test_new():\n    assert 1 + 1 == 2\n"})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)
    bad = Case(tmp_path / "bad", baseline, branch="spec/tests-2", author=EXECUTOR)
    bad.change({"acceptance/test_new.py": "def test_new():\n    assert 1 + 1 == 2\n", "src/app.py": lines_file(a="VALUE = 2")})
    res, d = bad.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", "src/app.py")


@pytest.mark.req("V-KIND")
@pytest.mark.parametrize("branch", ["SPEC/x", "Spec/x", "spec"])
def test_kind_the_executor_off_exactly_spec_slash_gets_the_stricter_ai_rules(tmp_path, baseline, branch):
    # a spec PR may touch acceptance/ and nothing else; an ai PR may not touch acceptance/ at all
    case = Case(tmp_path, baseline, branch=branch, author=EXECUTOR)
    case.change({"acceptance/test_new.py": "def test_new():\n    assert 1 + 1 == 2\n"})
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", "acceptance/test_new.py")


@pytest.mark.req("V-KIND")
def test_kind_a_person_on_spec_slash_cannot_use_the_spec_rules_to_touch_acceptance(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="spec/x", author=PERSON)
    case.change({"acceptance/test_new.py": "def test_new():\n    assert 1 + 1 == 2\n"})
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", "acceptance/test_new.py")


# ----------------------------------------------------------------------------- G-1, G-1a, G-1b, G-1c

G1A_NAMES = ["pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini", ".bandit", "bandit.yaml", "bandit.yml",
             ".gitleaks.toml", ".gitleaksignore"]
G1A_ROOT_ONLY = ["pytest.py", "pytest/plugin.py", "_pytest/plugin.py"]   # a file and two folders of the root


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("folder", ["", "pkg/sub/"], ids=["root", "subfolder"])
@pytest.mark.parametrize("name", G1A_NAMES)
def test_g1a_files_that_control_the_tests_and_the_security_tools_are_protected_in_any_folder(tmp_path, baseline, name, folder):
    case = Case(tmp_path, baseline)
    case.change({folder + name: "[pytest]\naddopts = -x\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("action", ["changed", "deleted"])
@pytest.mark.parametrize("path", ["pytest.ini", "sub/.bandit", ".gitleaksignore", "pytest.toml", "pkg/.pytest.toml",
                                  "pytest.py", "pytest/plugin.py", "_pytest/plugin.py"])
def test_g1a_changed_and_deleted_count_too(tmp_path, baseline, path, action):
    case = Case(tmp_path, baseline, base_edits={path: "original\n"})
    case.change({path: "edited\n" if action == "changed" else None})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("path", G1A_ROOT_ONLY)
def test_g1a_pytest_py_and_the_pytest_folders_are_protected_in_the_root(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change({path: "x = 1\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("path", ["sub/pytest.py", "sub/pytest/plugin.py", "sub/_pytest/plugin.py",
                                  "pkg/deep/pytest.py", "tests/pytest/plugin.py"])
def test_g1a_control_pytest_py_and_the_pytest_folders_are_only_watched_in_the_root(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change({path: "x = 1\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("path", ["docs/pytest.ini.md", "src/pytest_ini.py", "bandit.txt", "gitleaks.toml", "src/bandit_notes.md",
                                  "docs/pytest.toml.md", "pytest_plugin.py", "pytestx/plugin.py", "_pytest_notes.md",
                                  "src/pytest_toml.py", "pytest.tom"])
def test_g1a_control_names_that_only_look_alike_are_clean(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change({path: "x\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("action", ["added", "changed", "deleted"])
def test_g1a_conftest_in_the_root_is_protected(tmp_path, baseline, action):
    case = Case(tmp_path, baseline, base_edits=None if action == "added" else {"conftest.py": "import pytest\n"})
    case.change({"conftest.py": None if action == "deleted" else "import pytest\n\n\ndef pytest_configure(config):\n    pass\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "conftest.py")


@pytest.mark.req("G-1c")
@pytest.mark.parametrize("path", ["tests/conftest.py", "src/conftest.py", "pkg/sub/conftest.py"])
def test_g1c_any_other_conftest_is_no_violation_but_goes_to_the_code_owner(tmp_path, baseline, path):
    case = Case(tmp_path, baseline, base_edits={path: "import pytest\n"})
    case.change({path: "import pytest\n\n\n@pytest.fixture\ndef thing():\n    return 1\n"})
    res, d = case.run()
    assert_clean(res, d)
    assert path in d["needs_code_owner"]


@pytest.mark.req("G-1c")
def test_g1c_control_nothing_changed_in_any_conftest_means_nothing_for_the_code_owner(tmp_path, baseline):
    case = Case(tmp_path, baseline, base_edits={"tests/conftest.py": "import pytest\n"})
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == []


SECTION_EDITS = [
    # (id, file, old text, new text)  -- every one is a changed, added or removed section named in G-1b
    ("pyproject-tool-pytest-changed", "pyproject.toml", 'addopts = "--cov-fail-under=90"', 'addopts = "--cov-fail-under=90 -x"'),
    ("pyproject-tool-coverage-changed", "pyproject.toml", "fail_under = 90", "fail_under = 95"),
    # [tool.ruff] added or removed is no longer refused: in the root it is marked for the code owner (G-1b-mark, see test_guard_r4.py)
    ("setup-cfg-tool-pytest", "setup.cfg", "addopts = -q", "addopts = -q -x"),
    ("setup-cfg-coverage", "setup.cfg", "branch = True", "branch = False"),
    ("setup-cfg-bandit", "setup.cfg", "skips = B101", "skips = B101,B602"),
    ("setup-cfg-flake8", "setup.cfg", "max-line-length = 100", "max-line-length = 200"),
    ("setup-cfg-mypy", "setup.cfg", "strict = True", "strict = False"),
    ("setup-cfg-mypy-submodule-added", "setup.cfg", "strict = True\n", "strict = True\n\n[mypy-foo.*]\nignore_errors = True\n"),
    ("setup-cfg-flake8-removed", "setup.cfg", "\n[flake8]\nmax-line-length = 100\n", ""),
    ("tox-ini-tox", "tox.ini", "envlist = py313", "envlist = py312"),
    ("tox-ini-testenv", "tox.ini", "commands = pytest", "commands = pytest -x"),
    ("tox-ini-testenv-lint", "tox.ini", "commands = flake8", "commands = flake8 --exit-zero"),
    ("tox-ini-pytest", "tox.ini", "[pytest]\naddopts = -q", "[pytest]\naddopts = -q -x"),
    ("tox-ini-coverage", "tox.ini", "branch = True", "branch = False"),
    ("tox-ini-bandit", "tox.ini", "skips = B101", "skips = B101,B602"),
    ("tox-ini-flake8", "tox.ini", "max-line-length = 100", "max-line-length = 200"),
    ("tox-ini-mypy", "tox.ini", "strict = True", "strict = False"),
    ("tox-ini-new-testenv-added", "tox.ini", "[docs]\nnote = nothing\n", "[docs]\nnote = nothing\n\n[testenv:extra]\ncommands = true\n"),
]


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("name,path,old,new", SECTION_EDITS, ids=[e[0] for e in SECTION_EDITS])
def test_g1b_a_changed_added_or_removed_section_of_a_root_config_file_is_protected(tmp_path, baseline, name, path, old, new):
    case = Case(tmp_path, baseline)
    case.change({path: sub(BASE[path], old, new)})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


OTHER_SECTION_EDITS = [
    ("pyproject-project", "pyproject.toml", 'name = "example"', 'name = "example-two"'),
    ("pyproject-build-system-added", "pyproject.toml", "[project]", "[build-system]\nrequires = []\n\n[project]"),
    ("pyproject-tool-ruff-changed", "pyproject.toml", "line-length = 100", "line-length = 120"),
]
# (the old cases setup-cfg-metadata, setup-cfg-options and tox-ini-docs edited files that mention pytest, which G-1b now
# refuses whatever the section: they became proofs of the mention rule in test_guard_r4.py)


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("name,path,old,new", OTHER_SECTION_EDITS, ids=[e[0] for e in OTHER_SECTION_EDITS])
def test_g1b_control_a_change_to_any_other_section_is_allowed_and_marked_in_the_root(tmp_path, baseline, name, path, old, new):
    case = Case(tmp_path, baseline)
    case.change({path: sub(BASE[path], old, new)})
    res, d = case.run()
    assert_clean(res, d)
    assert path in d["needs_code_owner"], "in the root an allowed change to these files goes to the code owner (G-1b-mark)"


SUBFOLDER_FILES = {"sub/pyproject.toml": PYPROJECT, "sub/setup.cfg": SETUP_CFG, "sub/tox.ini": TOX_INI}


SUBFOLDER_PYTEST_EDITS = {
    "sub/pyproject.toml": ('addopts = "--cov-fail-under=90"', 'addopts = "--cov-fail-under=90 -x"'),   # [tool.pytest.ini_options]
    "sub/setup.cfg": ("addopts = -q", "addopts = -q -x"),                                          # the file mentions pytest
    "sub/tox.ini": ("[pytest]\naddopts = -q", "[pytest]\naddopts = -q -x"),                          # the file mentions pytest
}


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("path", list(SUBFOLDER_FILES))
def test_g1b_what_pytest_reads_is_refused_in_a_subfolder_too(tmp_path, baseline, path):
    # pytest reads these three in every folder from a test's path upwards
    original = SUBFOLDER_FILES[path]
    old, new = SUBFOLDER_PYTEST_EDITS[path]
    case = Case(tmp_path, baseline, base_edits={path: original})
    case.change({path: sub(original, old, new)})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


SUBFOLDER_OTHER_SECTIONS = {
    "sub/pyproject.toml": (PYPROJECT, 'name = "example"', 'name = "example-two"'),
    "sub/setup.cfg": (FREE_SETUP_CFG, "name = example", "name = example-two"),
    "sub/tox.ini": (FREE_TOX_INI, "note = nothing", "note = something"),
}


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("path", list(SUBFOLDER_OTHER_SECTIONS))
def test_g1b_control_another_section_of_the_same_files_in_a_subfolder_is_neither_refused_nor_marked(tmp_path, baseline, path):
    original, old, new = SUBFOLDER_OTHER_SECTIONS[path]
    case = Case(tmp_path, baseline, base_edits={path: original})
    case.change({path: sub(original, old, new)})
    res, d = case.run()
    assert_clean(res, d)
    assert path not in d["needs_code_owner"], "in a subfolder an ordinary change is not even marked"


ENTRY_POINTS = '\n[project.entry-points.pytest11]\nexample = "example.plugin"\n'
WITH_PYTEST11 = PYPROJECT.replace('name = "example"\n', 'name = "example"\n' + ENTRY_POINTS, 1)
assert WITH_PYTEST11 != PYPROJECT


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("action", ["added", "changed", "removed"])
@pytest.mark.parametrize("path", ["pyproject.toml", "sub/pyproject.toml"], ids=["root", "subfolder"])
def test_g1b_the_pytest11_entry_points_section_is_watched(tmp_path, baseline, path, action):
    # a plugin registered under pytest11 is loaded by every pytest run
    before = PYPROJECT if action == "added" else WITH_PYTEST11
    after = {"added": WITH_PYTEST11, "changed": WITH_PYTEST11.replace("example.plugin", "example.other"),
             "removed": PYPROJECT}[action]
    case = Case(tmp_path, baseline, base_edits={path: before} if path.startswith("sub/") or action != "added" else None)
    case.change({path: after})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("section", ["[project.entry-points.other]", "[project.scripts]", "[project.entry-points.console_scripts]"])
def test_g1b_control_another_entry_points_group_or_scripts_is_allowed(tmp_path, baseline, section):
    text = PYPROJECT.replace('name = "example"\n', f'name = "example"\n\n{section}\nexample = "example.plugin:main"\n', 1)
    case = Case(tmp_path, baseline)
    case.change({"pyproject.toml": text})
    res, d = case.run()
    assert_clean(res, d)
    assert "pyproject.toml" in d["needs_code_owner"], "an allowed root change is marked (G-1b-mark)"


UNPARSABLE = [
    ("pyproject.toml", "[project\nname = \n"),
    ("setup.cfg", "stray line before any section\n" + SETUP_CFG.replace("name = example", "name = example-two")),
    ("tox.ini", "stray line before any section\n" + TOX_INI.replace("note = nothing", "note = something")),
]


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("path,content", UNPARSABLE, ids=[p for p, _ in UNPARSABLE])
def test_g1b_a_file_that_cannot_be_parsed_counts_as_changed(tmp_path, baseline, path, content):
    case = Case(tmp_path, baseline)
    case.change({path: content})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


# ----------------------------------------------------------------------------- G-2, G-4 and G-4a on a richer test file

TF = "tests/test_extra.py"


def edit_extra(tmp_path, baseline, old, new, **kw):
    case = Case(tmp_path, baseline, **kw)
    case.change({TF: sub(TEST_EXTRA, old, new)})
    return case.run()


TESTFOO = "    def testFoo(self):\n        self.assertEqual(add(1, 2), 3)\n        self.assertEqual(add(2, 3), 5)\n"
TESTONE = "    def test_one(self):\n        assert add(1, 1) == 2\n        assert add(2, 2) == 4\n\n"


@pytest.mark.req("G-2")
@pytest.mark.parametrize("name,old,new", [
    ("method-testFoo-removed", TESTFOO, "    pass\n"),
    ("method-test_one-removed", TESTONE, ""),
    ("method-testFoo-renamed-so-it-is-no-test", "def testFoo(self):", "def helperFoo(self):"),
    ("method-testFoo-renamed-to-another-test-name", "def testFoo(self):", "def testBar(self):"),
])
def test_g2_a_method_whose_name_starts_with_test_that_disappears_fires(tmp_path, baseline, name, old, new):
    res, d = edit_extra(tmp_path, baseline, old, new)
    assert_fires(res, d, "TEST_DELETED", TF)


@pytest.mark.req("G-2")
@pytest.mark.parametrize("name,old,new", [
    ("helper-method-removed", "    def helper(self):\n        return 1\n", "    def other(self):\n        return 1\n"),
    ("helper-method-renamed", "def helper(self):", "def helper_two(self):"),
])
def test_g2_control_what_is_not_a_test_may_go(tmp_path, baseline, name, old, new):
    res, d = edit_extra(tmp_path, baseline, old, new)
    assert "TEST_DELETED" not in rules(d)


G4_WEAKENED = [
    ("tautology-same-call-both-sides", "assert add(1, 1) == 2\n", "assert add(1, 1) == add(1, 1)\n"),
    ("tautology-same-name-both-sides", "assert x > 0\n", "assert x == x\n"),
    ("or-true", "assert x > 0\n", "assert x > 0 or True\n"),
    ("early-return-ahead-of-the-checks", "def test_helpers():\n    assert_sum(1, 2, 3)", "def test_helpers():\n    return\n    assert_sum(1, 2, 3)"),
    ("fewer-parametrize-cases", "[1, 2, 3]", "[1, 2]"),
    ("an-assert-helper-call-removed", "    assert_sum(2, 2, 4)\n", ""),
    ("a-self-assert-removed", "        self.assertEqual(add(2, 3), 5)\n", ""),
    ("an-assert-replaced-by-assert-True", "assert add(0, 0) == 0", "assert True"),
]


@pytest.mark.req("G-4")
@pytest.mark.parametrize("name,old,new", G4_WEAKENED, ids=[g[0] for g in G4_WEAKENED])
def test_g4_each_weakening_fires(tmp_path, baseline, name, old, new):
    res, d = edit_extra(tmp_path, baseline, old, new)
    assert_fires(res, d, "TEST_WEAKENED", TF)


G4_CONTROLS = [
    ("more-parametrize-cases", "[1, 2, 3]", "[1, 2, 3, 4]"),
    ("return-after-the-last-check", "    assert add(0, 0) == 0\n", "    assert add(0, 0) == 0\n    return\n"),
    ("return-nested-in-a-branch-is-not-a-direct-statement", "def test_helpers():\n    assert_sum(1, 2, 3)",
     "def test_helpers():\n    if False:\n        return\n    assert_sum(1, 2, 3)"),
    ("an-assert-helper-call-replaced-by-an-assert", "    assert_sum(2, 2, 4)\n", "    assert add(2, 2) == 4\n"),
    ("a-check-added", "    assert add(0, 0) == 0\n", "    assert add(0, 0) == 0\n    assert_sum(3, 3, 6)\n"),
    ("two-different-sides", "assert x > 0\n", "assert x != 0\n"),
    ("or-with-something-real", "assert x > 0\n", "assert x > 0 or x < -5\n"),
]


@pytest.mark.req("G-4")
@pytest.mark.parametrize("name,old,new", G4_CONTROLS, ids=[g[0] for g in G4_CONTROLS])
def test_g4_control_equal_or_stronger_tests_are_not_refused(tmp_path, baseline, name, old, new):
    res, d = edit_extra(tmp_path, baseline, old, new)
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert "TEST_DELETED" not in rules(d)


@pytest.mark.req("G-4a")
def test_g4a_a_changed_expected_value_is_marked_not_refused(tmp_path, baseline):
    res, d = edit_extra(tmp_path, baseline, "    assert add(0, 0) == 0\n", "    assert add(0, 0) == 1\n")
    assert_clean(res, d)
    assert {"path": TF, "name": "test_helpers"} in d["marked_tests"]
    assert TF in d["needs_code_owner"]


@pytest.mark.req("G-4a")
def test_g4a_a_changed_expected_value_in_a_method_is_marked_too(tmp_path, baseline):
    res, d = edit_extra(tmp_path, baseline, "        assert add(2, 2) == 4\n\n    def helper", "        assert add(2, 2) == 5\n\n    def helper")
    assert_clean(res, d)
    assert any(m["path"] == TF and m["name"].endswith("test_one") for m in d["marked_tests"]), d["marked_tests"]
    assert TF in d["needs_code_owner"]


@pytest.mark.req("G-4a")
def test_g4a_any_other_changed_function_in_a_test_file_is_marked_too(tmp_path, baseline):
    res, d = edit_extra(tmp_path, baseline, "    assert add(a, b) == expected\n", "    assert add(a, b) == expected + 0\n")
    assert_clean(res, d)
    assert {"path": TF, "name": "assert_sum"} in d["marked_tests"]
    assert TF in d["needs_code_owner"]


@pytest.mark.req("G-4a")
def test_g4a_control_a_change_outside_the_tests_marks_nothing(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert d["marked_tests"] == [] and d["needs_code_owner"] == []


@pytest.mark.req("G-4a", "G-4")
def test_g4a_marking_never_excuses_a_weakening_a_tool_can_see(tmp_path, baseline):
    res, d = edit_extra(tmp_path, baseline, "    assert add(0, 0) == 0\n", "    assert True\n")
    assert_fires(res, d, "TEST_WEAKENED", TF)


# ----------------------------------------------------------------------------- G-5: each spelling

TAIL = "\n\ndef helper():\n    return 1\n"
G5_SPELLINGS = [
    ("noqa", "import os  # noqa\n"),
    ("noqa-no-space", "import os  #noqa\n"),
    ("noqa-capitals", "import os  # NOQA\n"),
    ("noqa-wide-space-and-code", "import os  #   NoQA: F401\n"),
    ("noqa-code-without-space", "import os  # noqa:F401\n"),
    ("type-ignore", "x: int = 'a'  # type: ignore\n"),
    ("type-ignore-no-spaces", "x: int = 'a'  #type:ignore\n"),
    ("type-ignore-capitals-and-code", "x: int = 'a'  # TYPE: IGNORE[assignment]\n"),
    ("type-ignore-two-spaces", "x: int = 'a'  # type:  ignore\n"),
    ("ruff-noqa", "# ruff: noqa\n"),
    ("ruff-noqa-no-spaces", "#ruff:noqa\n"),
    ("ruff-noqa-capitals-with-code", "# RUFF: NOQA: F401\n"),
    ("flake8-noqa", "# flake8: noqa\n"),
    ("flake8-noqa-no-spaces", "#flake8:noqa\n"),
    ("flake8-noqa-capitals", "# FLAKE8: NOQA\n"),
    ("mypy-ignore-errors", "# mypy: ignore-errors\n"),
    ("mypy-ignore-errors-no-spaces", "#mypy:ignore-errors\n"),
    ("mypy-ignore-errors-capitals", "# MYPY: IGNORE-ERRORS\n"),
    ("pylint-disable", "x = 1  # pylint: disable=invalid-name\n"),
    ("pylint-disable-no-spaces", "x = 1  #pylint:disable=foo\n"),
    ("pylint-disable-capitals", "x = 1  # PYLINT: DISABLE=foo\n"),
    ("pragma-no-cover", "def covered():  # pragma: no cover\n    return 1\n"),
    ("pragma-no-cover-no-spaces", "def covered():  #pragma:no cover\n    return 1\n"),
    ("pragma-no-cover-capitals", "def covered():  # PRAGMA: NO COVER\n    return 1\n"),
    ("pytest-skip-call", "import pytest\n\n\ndef later():\n    pytest.skip('x')\n"),
    ("pytest-skip-call-capitals", "import pytest\n\n\ndef later():\n    PYTEST.SKIP('x')\n"),
]


@pytest.mark.req("G-5")
@pytest.mark.parametrize("name,code", G5_SPELLINGS, ids=[g[0] for g in G5_SPELLINGS])
def test_g5_each_spelling_without_a_reason_fires(tmp_path, baseline, name, code):
    case = Case(tmp_path, baseline)
    case.change({"src/util.py": code + TAIL})
    res, d = case.run()
    assert_fires(res, d, "SUPPRESSION_NO_REASON", "src/util.py")


G5_WITH_REASON = [
    ("noqa", "import os  # noqa  # reason: re-export\n"),
    ("type-ignore", "x: int = 'a'  # type: ignore  # reason: stub gap\n"),
    ("ruff-noqa", "# ruff: noqa  # reason: generated code\n"),
    ("flake8-noqa", "# flake8: noqa  # reason: generated code\n"),
    ("mypy-ignore-errors", "# mypy: ignore-errors  # reason: generated code\n"),
    ("pylint-disable", "x = 1  # pylint: disable=invalid-name  # reason: protocol name\n"),
    ("pragma-no-cover", "def covered():  # pragma: no cover  # reason: debugging aid\n    return 1\n"),
    ("pytest-skip-call", "import pytest\n\n\ndef later():\n    pytest.skip('x')  # reason: needs a database\n"),
]


@pytest.mark.req("G-5")
@pytest.mark.parametrize("name,code", G5_WITH_REASON, ids=[g[0] for g in G5_WITH_REASON])
def test_g5_control_each_family_with_a_reason_on_the_same_line_is_clean(tmp_path, baseline, name, code):
    case = Case(tmp_path, baseline)
    case.change({"src/util.py": code + TAIL})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-5")
def test_g5_a_stub_file_is_checked_like_a_py_file(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"stubs/thing.pyi": "x: int  # type: ignore\n"})
    res, d = case.run()
    assert_fires(res, d, "SUPPRESSION_NO_REASON", "stubs/thing.pyi")


@pytest.mark.req("G-5")
@pytest.mark.parametrize("path", ["docs/notes.md", "ci/run.sh", "config.toml", "notes.txt"])
def test_g5_control_the_same_words_in_a_file_that_is_not_py_or_pyi_are_clean(tmp_path, baseline, path):
    case = Case(tmp_path, baseline)
    case.change({path: "# noqa\n# type: ignore\n# pragma: no cover\npytest.skip('x')\n"})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-9: merges, and .gitattributes

@pytest.mark.req("G-9")
def test_g9_a_merge_from_the_base_with_nothing_else_is_not_a_repeat_but_the_same_fix_with_its_own_commit_is(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    reports = tmp_path / "reports"
    c1 = commit_app(case, "VALUE = 2", "OTHER = 'x'")
    r1, d1 = run_store(case, c1, reports, 5, 100)
    assert d1["repeated_fix"] is False
    # the base moves on, and the PR merges it: the round's only new commit is a merge commit
    case.repo.checkout("main")
    case.repo.write("README.md", "# main moved on\n")
    base_tip = case.repo.commit("main moves on")
    case.repo.checkout("pr-branch")
    case.repo.git("merge", "-q", "--no-edit", "main")
    merged = case.repo.sha()
    res, d = case.run(base=base_tip, head=merged, reports=reports, pr=5)
    assert d["fingerprint"]["cumulative"] == d1["fingerprint"]["cumulative"], \
        "precondition: the merged head carries the very same fix, so only the merge rule tells it apart from a repeat"
    assert_clean(res, d)
    assert d["repeated_fix"] is False
    # the same fix again, now with a commit of its own on top of the merge
    own = case.repo.commit("own commit that changes nothing new")
    res2, d2 = case.run(base=base_tip, head=own, reports=reports, pr=5)
    assert_fires(res2, d2, "REPEATED_FIX")
    assert d2["repeated_fix"] is True


GITATTRIBUTES = "*.py -diff\nsrc/** -diff\n* -diff\n"


@pytest.mark.req("G-9")
def test_g9_a_gitattributes_with_minus_diff_neither_changes_nor_hides_a_fingerprint(tmp_path, baseline):
    plain = Case(tmp_path / "plain", baseline)
    plain.change({"src/app.py": lines_file(a="VALUE = 2")})
    res_a, plain_d = plain.run()
    marked = Case(tmp_path / "marked", baseline, base_edits={".gitattributes": GITATTRIBUTES})
    marked.change({"src/app.py": lines_file(a="VALUE = 2")})
    res_b, marked_d = marked.run()
    assert marked_d["fingerprint"]["cumulative"] == plain_d["fingerprint"]["cumulative"], \
        "a .gitattributes changes nothing about a fingerprint"
    other = Case(tmp_path / "other", baseline, base_edits={".gitattributes": GITATTRIBUTES})
    other.change({"src/app.py": lines_file(a="VALUE = 3")})
    res_c, other_d = other.run()
    assert other_d["fingerprint"]["cumulative"] != marked_d["fingerprint"]["cumulative"], \
        "and -diff must not make two different changes look the same"


@pytest.mark.req("G-9", "G-5")
@pytest.mark.parametrize("where", ["in-the-base", "added-by-the-same-pr"])
def test_g9_g5_a_gitattributes_with_minus_diff_does_not_hide_a_suppression(tmp_path, baseline, where):
    if where == "in-the-base":
        case = Case(tmp_path, baseline, base_edits={".gitattributes": GITATTRIBUTES})
        case.change({"src/util.py": "import os  # noqa\n" + TAIL})
    else:
        case = Case(tmp_path, baseline)
        case.change({".gitattributes": GITATTRIBUTES, "src/util.py": "import os  # noqa\n" + TAIL})
    res, d = case.run()
    assert_fires(res, d, "SUPPRESSION_NO_REASON", "src/util.py")


@pytest.mark.req("G-9", "G-5")
def test_g9_g5_control_without_the_suppression_the_same_gitattributes_is_clean(tmp_path, baseline):
    case = Case(tmp_path, baseline, base_edits={".gitattributes": GITATTRIBUTES})
    case.change({"src/util.py": "import os\n" + TAIL})
    res, d = case.run()
    assert_clean(res, d)
