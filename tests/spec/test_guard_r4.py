"""gate.guard after the CEO's answer of 2026-11-04 (HQ-ANSWERS-04): G-1b with its mention rule and named lists,
G-1b-mark, and G-11a (the test rules for a spec PR).

Every refusal has a control; every control that is an allowed change says whether the code owner is told (a change in the
root is marked, a change in a subfolder that no rule names is neither refused nor marked).
"""
from __future__ import annotations

import pytest

from guardkit import (ACC_STATUS, EXECUTOR, FREE_PYPROJECT, FREE_SETUP_CFG, FREE_TOX_INI, SETUP_CFG, TEST_EXTRA, TOX_INI,
                      Case, assert_clean, assert_fires, lines_file, of, rules, run_store, sub)
from test_guard_v import G4_CONTROLS, G4_WEAKENED, TESTFOO, TESTONE

ROOT, SUB = "", "sub/"
FOLDERS = [ROOT, SUB]
FOLDER_IDS = ["root", "subfolder"]


def edit(tmp_path, baseline, path, before, after, **case_kw):
    """The file `path` is `before` in the base and `after` in the head (everything else untouched)."""
    case = Case(tmp_path, baseline, base_edits={path: before}, **case_kw)
    case.change({path: after})
    return case.run()


def assert_marked(d, path):
    assert path in d["needs_code_owner"], f"{path} should go to the code owner: {d['needs_code_owner']}"


def assert_not_marked(d, path):
    assert path not in d["needs_code_owner"], f"{path} must be an ordinary change in a subfolder: {d['needs_code_owner']}"


# ----------------------------------------------------------------------------- G-1b: the mention rule (setup.cfg and tox.ini)

FREE_FILES = {"setup.cfg": FREE_SETUP_CFG, "tox.ini": FREE_TOX_INI}
# a change in a section that no rule names, even in the root: the mention rule alone can refuse it
BENIGN_EDIT = {"setup.cfg": ("name = example", "name = example-two"), "tox.ini": ("note = nothing", "note = something")}
WORDS = ["pytest", "PyTest", "PYTEST", "pytest-cov"]


def mention(word, text):
    """The text with a comment line at the very top that holds `word`: it belongs to no section."""
    return f"# collected by {word}\n" + text


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("word", WORDS)
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_a_change_that_makes_the_file_mention_pytest_is_refused_in_any_folder(tmp_path, baseline, name, folder, word):
    free = FREE_FILES[name]
    assert "pytest" not in free.lower(), "test setup: the base file must not mention it"
    res, d = edit(tmp_path, baseline, folder + name, free, mention(word, free))
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("word", WORDS)
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_a_file_that_already_mentions_pytest_is_refused_whatever_section_changes(tmp_path, baseline, name, folder, word):
    before = mention(word, FREE_FILES[name])
    old, new = BENIGN_EDIT[name]
    res, d = edit(tmp_path, baseline, folder + name, before, sub(before, old, new))
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("word", WORDS)
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_a_file_that_stops_mentioning_pytest_is_still_refused(tmp_path, baseline, name, folder, word):
    # the only change is that the mention goes: "before or after the change" counts
    free = FREE_FILES[name]
    res, d = edit(tmp_path, baseline, folder + name, mention(word, free), free)
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


MENTIONING_EDITS = [
    # the old fixture cases that were once allowed controls: the files mention pytest, so any change is refused
    ("setup.cfg", SETUP_CFG, "name = example", "name = example-two"),
    ("setup.cfg", SETUP_CFG, "packages = find:", "packages = find:\npython_requires = >=3.13"),
    ("tox.ini", TOX_INI, "note = nothing", "note = something"),
]


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name,text,old,new", MENTIONING_EDITS, ids=["setup-cfg-metadata", "setup-cfg-options", "tox-ini-docs"])
def test_g1b_a_section_that_has_nothing_to_do_with_pytest_is_refused_all_the_same_when_the_file_mentions_it(
        tmp_path, baseline, name, text, old, new, folder):
    res, d = edit(tmp_path, baseline, folder + name, text, sub(text, old, new))
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_control_a_mentioning_file_that_does_not_change_is_not_refused(tmp_path, baseline, name, folder):
    text = mention("pytest", FREE_FILES[name])
    case = Case(tmp_path, baseline, base_edits={folder + name: text})
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == []


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
def test_g1b_control_the_word_only_matters_in_setup_cfg_and_tox_ini_not_in_a_parseable_pyproject(tmp_path, baseline, folder):
    before = FREE_PYPROJECT.replace('name = "example"\n', 'name = "example"\ndescription = "helpers for pytest users"\n', 1)
    assert "pytest" in before
    res, d = edit(tmp_path, baseline, folder + "pyproject.toml", before, before.replace('name = "example"', 'name = "example-two"', 1))
    assert_clean(res, d)
    if folder == ROOT:
        assert_marked(d, "pyproject.toml")
    else:
        assert_not_marked(d, folder + "pyproject.toml")


# ----------------------------------------------------------------------------- G-1b: unparsable files

BROKEN_TOML = "[project\nname = \n"
BROKEN_INI = "stray line before any section\n"


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
def test_g1b_an_unparsable_pyproject_that_mentions_pytest_is_refused_in_any_folder(tmp_path, baseline, folder):
    res, d = edit(tmp_path, baseline, folder + "pyproject.toml", FREE_PYPROJECT, BROKEN_TOML + "# pytest\n")
    assert_fires(res, d, "PROTECTED_PATH", folder + "pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_an_unparsable_root_pyproject_is_refused_even_without_the_word(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "pyproject.toml", FREE_PYPROJECT, BROKEN_TOML)
    assert_fires(res, d, "PROTECTED_PATH", "pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_an_unparsable_subfolder_pyproject_without_the_word_is_ordinary(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", FREE_PYPROJECT, BROKEN_TOML)
    assert_clean(res, d)
    assert_not_marked(d, "sub/pyproject.toml")


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_an_unparsable_root_setup_cfg_or_tox_ini_is_refused_even_without_the_word(tmp_path, baseline, name):
    res, d = edit(tmp_path, baseline, name, FREE_FILES[name], BROKEN_INI + FREE_FILES[name])
    assert_fires(res, d, "PROTECTED_PATH", name)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_an_unparsable_setup_cfg_or_tox_ini_that_mentions_pytest_is_refused_in_any_folder(tmp_path, baseline, name, folder):
    res, d = edit(tmp_path, baseline, folder + name, FREE_FILES[name], BROKEN_INI + mention("pytest", FREE_FILES[name]))
    assert_fires(res, d, "PROTECTED_PATH", folder + name)


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("name", list(FREE_FILES))
def test_g1b_control_an_unparsable_subfolder_setup_cfg_or_tox_ini_without_the_word_is_ordinary(tmp_path, baseline, name):
    res, d = edit(tmp_path, baseline, SUB + name, FREE_FILES[name], BROKEN_INI + FREE_FILES[name])
    assert_clean(res, d)
    assert_not_marked(d, SUB + name)


# ----------------------------------------------------------------------------- G-1b: the named root list, and pytest's own sections

PY_NAMED = {
    "tool.coverage": '[tool.coverage]\nbranch = true\n',
    "tool.coverage.run": '[tool.coverage.run]\nbranch = true\n',
    "tool.bandit": '[tool.bandit]\nskips = ["B101"]\n',
    "tool.bandit.assert_used": '[tool.bandit.assert_used]\nskips = ["*_test.py"]\n',
    "tool.tox": '[tool.tox]\nenvlist = "py313"\n',
    "tool.semgrep": '[tool.semgrep]\nexclude = ["generated"]\n',
    "tool.gitleaks": '[tool.gitleaks]\nverbose = true\n',
    "tool.pip-audit": '[tool.pip-audit]\nstrict = true\n',
    "tool.pip_audit": '[tool.pip_audit]\nstrict = true\n',
}
PY_PYTEST = {
    "tool.pytest": '[tool.pytest]\nminversion = "9"\n',
    "tool.pytest.ini_options": '[tool.pytest.ini_options]\naddopts = "-x"\n',
}


def add_table(tmp_path, baseline, folder, table):
    path = folder + "pyproject.toml"
    res, d = edit(tmp_path, baseline, path, FREE_PYPROJECT, sub(FREE_PYPROJECT, "[tool.poetry]", table + "\n[tool.poetry]"))
    return path, res, d


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("key", list(PY_NAMED))
def test_g1b_the_named_pyproject_tables_are_refused_in_the_root(tmp_path, baseline, key):
    path, res, d = add_table(tmp_path, baseline, ROOT, PY_NAMED[key])
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("key", list(PY_NAMED))
def test_g1b_control_the_same_tables_in_a_subfolder_are_ordinary(tmp_path, baseline, key):
    path, res, d = add_table(tmp_path, baseline, SUB, PY_NAMED[key])
    assert_clean(res, d)
    assert_not_marked(d, path)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("action", ["changed", "removed"])
def test_g1b_a_named_table_that_is_changed_or_removed_in_the_root_is_refused(tmp_path, baseline, action):
    table = PY_NAMED["tool.coverage.run"]
    before = sub(FREE_PYPROJECT, "[tool.poetry]", table + "\n[tool.poetry]")
    after = before.replace("branch = true", "branch = false") if action == "changed" else FREE_PYPROJECT
    res, d = edit(tmp_path, baseline, "pyproject.toml", before, after)
    assert_fires(res, d, "PROTECTED_PATH", "pyproject.toml")


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("key", list(PY_PYTEST))
def test_g1b_pytests_own_tables_are_refused_in_any_folder(tmp_path, baseline, key, folder):
    path, res, d = add_table(tmp_path, baseline, folder, PY_PYTEST[key])
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
@pytest.mark.parametrize("action", ["changed", "removed"])
def test_g1b_pytests_own_table_changed_or_removed_is_refused_in_any_folder(tmp_path, baseline, folder, action):
    before = sub(FREE_PYPROJECT, "[tool.poetry]", PY_PYTEST["tool.pytest.ini_options"] + "\n[tool.poetry]")
    after = before.replace('addopts = "-x"', 'addopts = "-x -q"') if action == "changed" else FREE_PYPROJECT
    res, d = edit(tmp_path, baseline, folder + "pyproject.toml", before, after)
    assert_fires(res, d, "PROTECTED_PATH", folder + "pyproject.toml")


ROOT_NAMED_INI = [
    # (id, file, old, new): sections named for the root, in files that do not mention pytest
    ("setup-cfg-coverage", "setup.cfg", "branch = True", "branch = False"),
    ("setup-cfg-bandit", "setup.cfg", "skips = B101", "skips = B101,B602"),
    ("tox-ini-tox", "tox.ini", "envlist = py313", "envlist = py312"),
    ("tox-ini-testenv", "tox.ini", "commands = python -m unittest", "commands = python -m unittest -v"),
    ("tox-ini-testenv-lint", "tox.ini", "commands = flake8", "commands = flake8 --exit-zero"),
    ("tox-ini-coverage", "tox.ini", "branch = True", "branch = False"),
    ("tox-ini-bandit", "tox.ini", "skips = B101", "skips = B101,B602"),
]


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("name,file,old,new", ROOT_NAMED_INI, ids=[r[0] for r in ROOT_NAMED_INI])
def test_g1b_the_named_sections_of_setup_cfg_and_tox_ini_are_refused_in_the_root(tmp_path, baseline, name, file, old, new):
    text = FREE_FILES[file]
    res, d = edit(tmp_path, baseline, file, text, sub(text, old, new))
    assert_fires(res, d, "PROTECTED_PATH", file)


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("name,file,old,new", ROOT_NAMED_INI, ids=[r[0] for r in ROOT_NAMED_INI])
def test_g1b_control_the_same_sections_in_a_subfolder_are_ordinary(tmp_path, baseline, name, file, old, new):
    text = FREE_FILES[file]
    res, d = edit(tmp_path, baseline, SUB + file, text, sub(text, old, new))
    assert_clean(res, d)
    assert_not_marked(d, SUB + file)


# ----------------------------------------------------------------------------- G-1b-mark: the root, and the subfolder

MARKED_IN_THE_ROOT = [
    # (id, file, base text, old, new): changes that no rule refuses
    ("pyproject-tool-ruff-changed", "pyproject.toml", FREE_PYPROJECT, "line-length = 100", "line-length = 120"),
    ("pyproject-tool-ruff-added", "pyproject.toml", FREE_PYPROJECT, "[tool.poetry]", "[tool.black]\nline-length = 100\n\n[tool.poetry]"),
    ("pyproject-tool-ruff-removed", "pyproject.toml", FREE_PYPROJECT, "[tool.ruff]\nline-length = 100\n\n", ""),
    ("pyproject-tool-poetry-changed", "pyproject.toml", FREE_PYPROJECT, '[tool.poetry]\nname = "example"', '[tool.poetry]\nname = "example-two"'),
    ("pyproject-project-changed", "pyproject.toml", FREE_PYPROJECT, '[project]\nname = "example"', '[project]\nname = "example-two"'),
    ("setup-cfg-flake8", "setup.cfg", FREE_SETUP_CFG, "max-line-length = 100", "max-line-length = 120"),
    ("setup-cfg-mypy", "setup.cfg", FREE_SETUP_CFG, "strict = True", "strict = False"),
    ("setup-cfg-metadata", "setup.cfg", FREE_SETUP_CFG, "name = example", "name = example-two"),
    ("tox-ini-flake8", "tox.ini", FREE_TOX_INI, "max-line-length = 100", "max-line-length = 120"),
    ("tox-ini-docs", "tox.ini", FREE_TOX_INI, "note = nothing", "note = something"),
]


@pytest.mark.req("G-1b-mark")
@pytest.mark.parametrize("name,file,text,old,new", MARKED_IN_THE_ROOT, ids=[m[0] for m in MARKED_IN_THE_ROOT])
def test_g1b_mark_in_the_root_any_other_change_is_no_violation_but_goes_to_the_code_owner(tmp_path, baseline, name, file, text, old, new):
    res, d = edit(tmp_path, baseline, file, text, sub(text, old, new))
    assert_clean(res, d)
    assert_marked(d, file)


@pytest.mark.req("G-1b-mark")
@pytest.mark.parametrize("name,file,text,old,new", MARKED_IN_THE_ROOT, ids=[m[0] for m in MARKED_IN_THE_ROOT])
def test_g1b_mark_control_in_a_subfolder_the_same_change_is_neither_refused_nor_marked(tmp_path, baseline, name, file, text, old, new):
    res, d = edit(tmp_path, baseline, SUB + file, text, sub(text, old, new))
    assert_clean(res, d)
    assert_not_marked(d, SUB + file)


@pytest.mark.req("G-1b-mark")
def test_g1b_mark_control_a_change_elsewhere_marks_none_of_the_three_files(tmp_path, baseline):
    case = Case(tmp_path, baseline, base_edits={"pyproject.toml": FREE_PYPROJECT, "setup.cfg": FREE_SETUP_CFG, "tox.ini": FREE_TOX_INI})
    case.change({"src/app.py": lines_file(a="VALUE = 2")})
    res, d = case.run()
    assert_clean(res, d)
    assert d["needs_code_owner"] == []


# ----------------------------------------------------------------------------- G-11a: the test rules reach a spec PR

ACC = "acceptance/test_status.py"
RICH = "acceptance/test_rich.py"


def spec_case(tmp_path, baseline, **kw):
    case = Case(tmp_path, baseline, branch="spec/tests-1", author=EXECUTOR, **kw)
    return case


@pytest.mark.req("G-11a", "G-2")
def test_g11a_deleting_a_test_file_is_refused(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: None})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_DELETED", ACC)


@pytest.mark.req("G-11a", "G-2")
@pytest.mark.parametrize("name,new", [
    ("a-test-deleted", "def test_history():\n    assert 2 + 2 == 4\n"),
    ("a-test-renamed", ACC_STATUS.replace("def test_permissions", "def test_permissions_renamed")),
])
def test_g11a_deleting_or_renaming_a_test_is_refused(tmp_path, baseline, name, new):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: new})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_DELETED", ACC)


@pytest.mark.req("G-11a", "G-2")
@pytest.mark.parametrize("name,old,new", [
    ("method-testFoo-removed", TESTFOO, "    pass\n"),
    ("method-test_one-removed", TESTONE, ""),
])
def test_g11a_deleting_a_method_test_is_refused(tmp_path, baseline, name, old, new):
    case = spec_case(tmp_path, baseline, base_edits={RICH: TEST_EXTRA})
    case.change({RICH: sub(TEST_EXTRA, old, new)})
    res, d = case.run()
    assert_fires(res, d, "TEST_DELETED", RICH)


GAINED_SKIPS = {
    "mark.skip": lambda t: sub(t, "def test_history():", "@pytest.mark.skip\ndef test_history():"),
    "mark.skipif": lambda t: sub(t, "def test_history():", '@pytest.mark.skipif(True, reason="later")\ndef test_history():'),
    "mark.xfail": lambda t: sub(t, "def test_history():", "@pytest.mark.xfail\ndef test_history():"),
    "unittest.skip": lambda t: sub(t, "def test_history():", '@unittest.skip("later")\ndef test_history():'),
    "pytest.skip-call": lambda t: sub(t, "def test_history():\n", 'def test_history():\n    pytest.skip("later")\n'),
    "pytest.xfail-call": lambda t: sub(t, "def test_history():\n", 'def test_history():\n    pytest.xfail("later")\n'),
    "a-reason-line-does-not-excuse": lambda t: sub(t, "def test_history():", "# reason: flaky\n@pytest.mark.skip\ndef test_history():"),
}


@pytest.mark.req("G-11a", "G-3")
@pytest.mark.parametrize("variant", list(GAINED_SKIPS))
def test_g11a_adding_a_skip_to_a_test_is_refused(tmp_path, baseline, variant):
    base = "import unittest\n\nimport pytest\n\n\n" + ACC_STATUS
    case = spec_case(tmp_path, baseline, base_edits={ACC: base})
    case.change({ACC: GAINED_SKIPS[variant](base)})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_SKIPPED", ACC)


@pytest.mark.req("G-11a", "G-3")
def test_g11a_control_a_skip_on_a_test_that_is_new_is_not_a_test_of_the_base(tmp_path, baseline):
    base = "import pytest\n\n\n" + ACC_STATUS
    case = spec_case(tmp_path, baseline, base_edits={ACC: base})
    case.change({ACC: base + '\n\n@pytest.mark.skip(reason="later")\ndef test_brand_new():\n    assert 1 + 1 == 2\n'})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert "TEST_SKIPPED" not in rules(d), "G-3 is about a test present in the base that gains a skip"


@pytest.mark.req("G-11a", "G-4")
@pytest.mark.parametrize("name,old,new", [
    ("an-assert-replaced-by-assert-True", "assert 3 + 3 == 6", "assert True"),
    ("the-only-check-removed", "    assert 3 + 3 == 6\n", "    pass\n"),
    ("a-tautology", "assert 3 + 3 == 6", "assert 3 + 3 == 3 + 3"),
    ("or-true", "assert 2 + 2 == 4", "assert 2 + 2 == 5 or True"),
])
def test_g11a_weakening_a_test_is_refused(tmp_path, baseline, name, old, new):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: sub(ACC_STATUS, old, new)})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_WEAKENED", ACC)


@pytest.mark.req("G-11a", "G-4")
@pytest.mark.parametrize("name,old,new", G4_WEAKENED, ids=[g[0] for g in G4_WEAKENED])
def test_g11a_every_weakening_g4_knows_is_refused_in_a_spec_pr(tmp_path, baseline, name, old, new):
    case = spec_case(tmp_path, baseline, base_edits={RICH: TEST_EXTRA})
    case.change({RICH: sub(TEST_EXTRA, old, new)})
    res, d = case.run()
    assert_fires(res, d, "TEST_WEAKENED", RICH)


@pytest.mark.req("G-11a", "G-4")
@pytest.mark.parametrize("name,old,new", G4_CONTROLS, ids=[g[0] for g in G4_CONTROLS])
def test_g11a_control_equal_or_stronger_tests_are_not_refused_in_a_spec_pr(tmp_path, baseline, name, old, new):
    case = spec_case(tmp_path, baseline, base_edits={RICH: TEST_EXTRA})
    case.change({RICH: sub(TEST_EXTRA, old, new)})
    res, d = case.run()
    assert "TEST_WEAKENED" not in rules(d) and "TEST_DELETED" not in rules(d), d["violations"]


@pytest.mark.req("G-11a", "G-4a")
def test_g11a_a_changed_test_is_marked_not_refused(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: sub(ACC_STATUS, "assert 3 + 3 == 6", "assert 3 + 3 == 7")})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert {"path": ACC, "name": "test_permissions"} in d["marked_tests"]
    assert ACC in d["needs_code_owner"]


@pytest.mark.req("G-11a", "G-4a")
def test_g11a_any_other_changed_function_in_a_test_file_is_marked(tmp_path, baseline):
    case = spec_case(tmp_path, baseline, base_edits={RICH: TEST_EXTRA})
    case.change({RICH: sub(TEST_EXTRA, "    assert add(a, b) == expected\n", "    assert add(a, b) == expected + 0\n")})
    res, d = case.run()
    assert_clean(res, d)
    assert {"path": RICH, "name": "assert_sum"} in d["marked_tests"] and RICH in d["needs_code_owner"]


@pytest.mark.req("G-11a")
def test_g11a_adding_tests_stays_clean(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: ACC_STATUS + "\n\ndef test_added():\n    assert 4 + 4 == 8\n",
                 "acceptance/test_search.py": "def test_find():\n    assert 1 + 1 == 2\n\n\ndef test_empty():\n    assert 2 + 2 == 4\n"})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)


@pytest.mark.req("G-11a")
def test_g11a_a_test_file_outside_acceptance_is_still_only_a_g11_matter(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({"tests/test_app.py": None})
    res, d = case.run()
    assert set(rules(d)) == {"SPEC_OUTSIDE_ACCEPTANCE"}, "G-2 reaches the test files under acceptance/ only"


@pytest.mark.req("G-11a", "G-5", "G-6", "G-7", "G-8", "G-9")
def test_g11a_g5_to_g9_still_do_not_apply_to_a_spec_pr(tmp_path, baseline):
    cfg = {"extra_protected": ["prompts/"], "dependency_files": ["acceptance/requirements.lock"],
           "dependency_sources": [], "threshold_keys": ["min_score"]}
    hashed = "examplelib==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
    case = spec_case(tmp_path, baseline, guard=cfg,
                     base_edits={"acceptance/limits.cfg": "[report]\nfail_under = 90\n", "acceptance/requirements.lock": hashed})
    case.change({"acceptance/helper.py": "import os  # noqa\n",                                     # G-5
                 "acceptance/limits.cfg": "[report]\nfail_under = 10\n",                           # G-6
                 "acceptance/requirements.lock": "examplelib==2.0\n"})                             # G-7 (no hash) and G-8
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert d["dependency_changes"] == [] and "acceptance/requirements.lock" not in d["needs_code_owner"]


@pytest.mark.req("G-11a", "G-9")
def test_g11a_g9_a_spec_pr_that_repeats_a_cumulative_diff_is_not_a_repeated_fix(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    reports = tmp_path / "reports"

    def commit_data(text):
        return case.change({"acceptance/data.txt": text})

    c1 = commit_data("one\n")
    r1, d1 = run_store(case, c1, reports, 5, 100)
    c2 = commit_data("two\n")
    run_store(case, c2, reports, 5, 101)
    c3 = commit_data("one\n")           # the tree of round 1 again: a repeat for an ai PR
    res, d = case.run(head=c3, reports=reports, pr=5)
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert d["repeated_fix"] is False
    assert d["fingerprint"]["cumulative"] == d1["fingerprint"]["cumulative"], "test setup: this is a repeat for an ai PR"


@pytest.mark.req("G-11a", "G-10")
def test_g11a_g10_still_applies_to_a_spec_pr_next_to_the_test_rules(tmp_path, baseline):
    # CONTRACTS.md, end of section 5: "G-1 and G-5 to G-9 do not apply to spec PRs; G-10 does"
    case = spec_case(tmp_path, baseline)
    case.change({ACC: None, "acceptance/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: example-org/example-action@v1\n"})
    res, d = case.run()
    assert_fires(res, d, "UNPINNED_ACTION", "acceptance/ci.yml")
    assert_fires(res, d, "TEST_DELETED", ACC)


@pytest.mark.req("G-11a", "G-11")
def test_g11a_g11_still_fires_for_anything_outside_acceptance(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({ACC: sub(ACC_STATUS, "assert 3 + 3 == 6", "assert 3 + 3 == 7"), "src/util.py": "x = 1\n"})
    res, d = case.run()
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", "src/util.py")
    assert {"path": ACC, "name": "test_permissions"} in d["marked_tests"]


@pytest.mark.req("G-11a")
def test_g11a_control_the_same_deletion_in_an_ai_pr_is_refused_by_g1_and_g2_alike(tmp_path, baseline):
    case = Case(tmp_path, baseline, branch="ai/12-example")
    case.change({ACC: None})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", ACC)
    assert of(d, "TEST_DELETED")
