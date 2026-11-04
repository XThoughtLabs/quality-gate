"""gate.guard after the CEO's answer of round 4 (HQ-ANSWERS-06): G-1a (.gitattributes), G-1b (newlines as pytest reads them,
every table named pytest11, project.dynamic), G-1d (links and submodules), G-4 (a test's name bound again) and G-11b (what
controls the tests, under acceptance/ in a spec PR).

One case per way of breaking a rule, and a control for each family. Every case is built from a real temporary repository.
Links and submodules are written with git plumbing, `git hash-object -w --stdin` and
`git update-index --add --cacheinfo <mode>,<sha>,<path>`, so that no privilege and no link support is needed: the guard reads
what git stores. Entries that are not in the working tree must not be swept away by `git add -A`, so these cases stage by path.
"""
from __future__ import annotations

import textwrap

import pytest

from gatekit import run_git
from guardkit import (FREE_PYPROJECT, FREE_SETUP_CFG, FREE_TOX_INI, Case, assert_clean, assert_fires, of, rules, sub)

ROOT, SUB = "", "sub/"
FOLDERS = [ROOT, SUB]
FOLDER_IDS = ["root", "subfolder"]
AI, SPEC = "ai/12-example", "spec/tests-1"


def edit(tmp_path, baseline, path, before, after, **kw):
    """The file `path` is `before` in the base and `after` in the head."""
    case = Case(tmp_path, baseline, base_edits={path: before}, **kw)
    case.change({path: after})
    return case.run()


def assert_marked(d, path):
    assert path in d["needs_code_owner"], f"{path} should go to the code owner: {d['needs_code_owner']}"


def assert_not_marked(d, path):
    assert path not in d["needs_code_owner"], f"{path} must be an ordinary change: {d['needs_code_owner']}"


# ----------------------------------------------------------------------------- G-1a: .gitattributes

ATTR_BEFORE = "* text=auto\n*.py diff\n"
ATTR_AFTER = "* text eol=crlf\n*.py -diff\n"


@pytest.mark.req("G-1a")
@pytest.mark.parametrize("action", ["added", "changed", "deleted"])
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
def test_g1a_gitattributes_added_changed_or_deleted_is_refused_in_any_folder(tmp_path, baseline, folder, action):
    path = folder + ".gitattributes"
    case = Case(tmp_path, baseline, base_edits=None if action == "added" else {path: ATTR_BEFORE})
    case.change({path: None if action == "deleted" else (ATTR_BEFORE if action == "added" else ATTR_AFTER)})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1a")
def test_g1a_control_names_that_only_look_like_gitattributes_are_clean(tmp_path, baseline):
    case = Case(tmp_path, baseline)
    case.change({"gitattributes": "x\n", "docs/.gitattributes.md": "x\n", ".gitattribute": "x\n", ".gitattributesx": "x\n",
                 "src/my.gitattributes": "x\n", "docs/gitattributes.txt": "x\n"})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-1b: a pyproject.toml read as pytest reads it
#
# pytest reads the file in text mode, where "\r\n" and a lone "\r" are newlines. A strict TOML parser refuses a lone "\r".

BASE_TOML = FREE_PYPROJECT                       # [project], [tool.ruff], [tool.poetry]: nothing that a rule names
PYTEST_TABLE = '[tool.pytest.ini_options]\naddopts = "-x"\n'


def lone_cr(text):
    return text.replace("\n", "\r")


def crlf(text):
    return text.replace("\n", "\r\n")


PROJECT_RENAMED = BASE_TOML.replace('name = "example"', 'name = "example-two"', 1)


@pytest.mark.req("G-1b")
def test_g1b_a_table_hidden_behind_a_lone_cr_in_a_comment_is_seen(tmp_path, baseline):
    # a reader that splits on "\n" alone sees one comment line; pytest sees a comment and a table
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", BASE_TOML, BASE_TOML + '# a note\r[tool.pytest.ini_options]\raddopts = "-x"\r')
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_a_pytest_table_in_a_file_whose_newlines_are_all_lone_crs_is_refused(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", lone_cr(BASE_TOML), lone_cr(BASE_TOML + "\n" + PYTEST_TABLE))
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_a_pytest_table_in_a_file_with_crlf_newlines_is_refused(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", crlf(BASE_TOML), crlf(BASE_TOML + "\n" + PYTEST_TABLE))
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_a_root_coverage_table_in_a_file_with_lone_cr_newlines_is_refused(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "pyproject.toml", lone_cr(BASE_TOML), lone_cr(BASE_TOML + "\n[tool.coverage]\nbranch = true\n"))
    assert_fires(res, d, "PROTECTED_PATH", "pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_a_root_file_with_lone_cr_newlines_parses_as_pytest_reads_it_so_it_is_marked_not_refused(tmp_path, baseline):
    # a strict parser calls this file unparsable, which would refuse a root file; pytest reads it, so it parses
    res, d = edit(tmp_path, baseline, "pyproject.toml", lone_cr(BASE_TOML), lone_cr(PROJECT_RENAMED))
    assert_clean(res, d)
    assert_marked(d, "pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_a_root_file_with_crlf_newlines_is_marked_not_refused(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "pyproject.toml", crlf(BASE_TOML), crlf(PROJECT_RENAMED))
    assert_clean(res, d)
    assert_marked(d, "pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_a_subfolder_file_with_lone_cr_newlines_and_an_unnamed_change_is_neither_refused_nor_marked(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", lone_cr(BASE_TOML), lone_cr(PROJECT_RENAMED))
    assert_clean(res, d)
    assert_not_marked(d, "sub/pyproject.toml")


# ----------------------------------------------------------------------------- G-1b: pytest's tables, however they are spelled

SPELLINGS = {
    "unicode-escape-in-the-name": r'[tool."pytest".ini_options]' + '\naddopts = "-x"\n',
    "literal-quoted-key": "[tool.'pytest']\naddopts = \"-x\"\n",
    "spaces-around-the-dots": '[ tool . pytest ]\naddopts = "-x"\n',
    "dotted-key-in-the-tool-table": '[tool]\npytest.addopts = "-x"\n',
    "inline-table-in-the-tool-table": '[tool]\npytest = { addopts = "-x" }\n',
}


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("spelling", list(SPELLINGS))
def test_g1b_tool_pytest_is_found_by_its_meaning_not_by_its_spelling(tmp_path, baseline, spelling):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", BASE_TOML, BASE_TOML + "\n" + SPELLINGS[spelling])
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_a_root_table_written_with_a_toml_escape_is_found(tmp_path, baseline):
    # [tool."coverage"] is [tool.coverage]
    res, d = edit(tmp_path, baseline, "pyproject.toml", BASE_TOML, BASE_TOML + "\n" + r'[tool."coverage"]' + "\nbranch = true\n")
    assert_fires(res, d, "PROTECTED_PATH", "pyproject.toml")


# ----------------------------------------------------------------------------- G-1b: a table named pytest11, whichever tool it belongs to

PLUGIN = 'example = "example.plugin"\n'
PYTEST11 = {
    "poetry-plugins": "[tool.poetry.plugins.pytest11]\n" + PLUGIN,
    "flit-entrypoints": "[tool.flit.entrypoints.pytest11]\n" + PLUGIN,
    "an-unknown-tool": "[tool.example.plugins.pytest11]\n" + PLUGIN,
    "a-table-of-its-own-at-the-top": "[pytest11]\n" + PLUGIN,
    "name-written-with-escapes": r'[project.entry-points."pytest11"]' + "\n" + PLUGIN,
    "dotted-key-makes-the-table": "[project.entry-points]\npytest11.example = \"example.plugin\"\n",
}


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("spelling", list(PYTEST11))
def test_g1b_a_pytest11_table_is_refused_in_a_subfolder_whatever_tool_it_belongs_to(tmp_path, baseline, spelling):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", BASE_TOML, BASE_TOML + "\n" + PYTEST11[spelling])
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("spelling", ["poetry-plugins", "flit-entrypoints", "an-unknown-tool"])
def test_g1b_a_pytest11_table_is_refused_in_the_root_too(tmp_path, baseline, spelling):
    res, d = edit(tmp_path, baseline, "pyproject.toml", BASE_TOML, BASE_TOML + "\n" + PYTEST11[spelling])
    assert_fires(res, d, "PROTECTED_PATH", "pyproject.toml")


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("action", ["changed", "removed"])
def test_g1b_a_pytest11_table_changed_or_removed_is_refused(tmp_path, baseline, action):
    before = BASE_TOML + "\n" + PYTEST11["poetry-plugins"]
    after = before.replace("example.plugin", "other.plugin") if action == "changed" else BASE_TOML
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", before, after)
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


OTHER_GROUPS = {
    "poetry-plugins-of-another-group": "[tool.poetry.plugins.other]\n" + PLUGIN,
    "flit-entrypoints-of-another-group": "[tool.flit.entrypoints.other]\n" + PLUGIN,
    "names-that-only-look-like-it": "[tool.example.pytest111]\nx = 1\n\n[tool.example.xpytest11]\nx = 1\n\n[tool.example.pytest]\nx = 1\n",
}


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("group", list(OTHER_GROUPS))
def test_g1b_control_another_group_or_a_look_alike_name_is_ordinary_in_a_subfolder(tmp_path, baseline, group):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", BASE_TOML, BASE_TOML + "\n" + OTHER_GROUPS[group])
    assert_clean(res, d)
    assert_not_marked(d, "sub/pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_another_group_is_marked_not_refused_in_the_root(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "pyproject.toml", BASE_TOML, BASE_TOML + "\n" + OTHER_GROUPS["poetry-plugins-of-another-group"])
    assert_clean(res, d)
    assert_marked(d, "pyproject.toml")


# ----------------------------------------------------------------------------- G-1b: project.dynamic naming entry-points


def with_dynamic(items_text):
    return BASE_TOML.replace('name = "example"\n', f'name = "example"\ndynamic = {items_text}\n', 1)


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
def test_g1b_dynamic_naming_entry_points_added_is_refused_in_any_folder(tmp_path, baseline, folder):
    res, d = edit(tmp_path, baseline, folder + "pyproject.toml", BASE_TOML, with_dynamic('["entry-points"]'))
    assert_fires(res, d, "PROTECTED_PATH", folder + "pyproject.toml")


@pytest.mark.req("G-1b")
def test_g1b_dynamic_that_named_entry_points_before_the_change_is_refused(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", with_dynamic('["entry-points", "version"]'), with_dynamic('["version"]'))
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b")
@pytest.mark.parametrize("spelling", [r'["entry-points"]', "['entry-points']", '[\n    "version",\n    "entry-points",  # plugins\n]'],
                         ids=["unicode-escape", "literal-string", "several-lines-with-a-comment"])
def test_g1b_dynamic_is_found_by_its_meaning_not_by_its_spelling(tmp_path, baseline, spelling):
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", BASE_TOML, with_dynamic(spelling))
    assert_fires(res, d, "PROTECTED_PATH", "sub/pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
@pytest.mark.parametrize("folder", FOLDERS, ids=FOLDER_IDS)
def test_g1b_control_another_dynamic_field_is_ordinary_in_a_subfolder_and_marked_in_the_root(tmp_path, baseline, folder):
    res, d = edit(tmp_path, baseline, folder + "pyproject.toml", BASE_TOML, with_dynamic('["version", "description"]'))
    assert_clean(res, d)
    (assert_marked if folder == ROOT else assert_not_marked)(d, folder + "pyproject.toml")


@pytest.mark.req("G-1b", "G-1b-mark")
def test_g1b_control_dynamic_that_names_entry_points_and_does_not_change_is_not_a_changed_dynamic(tmp_path, baseline):
    before = with_dynamic('["entry-points"]')
    res, d = edit(tmp_path, baseline, "sub/pyproject.toml", before, before.replace('name = "example"', 'name = "example-two"', 1))
    assert_clean(res, d)
    assert_not_marked(d, "sub/pyproject.toml")


# ----------------------------------------------------------------------------- G-1d: plain files only (git plumbing)

LINK, GITLINK, EXEC = "120000", "160000", "100755"
SHA_ONE = "1234567890abcdef1234567890abcdef12345678"
SHA_TWO = "abcdef1234567890abcdef1234567890abcdef12"


def stage(repo, *, writes=None, deletes=(), entries=None):
    """Stage by path, never with `git add -A`: entries that are only in the index would be swept away by it."""
    for path, content in (writes or {}).items():
        repo.write(path, content)
        repo.git("add", "--", path)
    for path in deletes:
        repo.git("update-index", "--force-remove", path)
        working = repo.path / path
        if working.exists():
            working.unlink()
    for path, (mode, payload) in (entries or {}).items():
        if mode == GITLINK:
            sha = payload
        else:
            sha = run_git(repo.path, "hash-object", "-w", "--stdin", input_bytes=payload).stdout.decode().strip()
        repo.git("update-index", "--add", "--cacheinfo", f"{mode},{sha},{path}")


def start(tmp_path, baseline, branch, *, base_writes=None, base_entries=None):
    case = Case(tmp_path, baseline, branch=branch)
    if base_writes or base_entries:
        stage(case.repo, writes=base_writes, entries=base_entries)
        case.repo.commit("base entries", stage_all=False)
        case.base = case.head = case.repo.sha()
    return case


def change(case, **kw):
    stage(case.repo, **kw)
    case.head = case.repo.commit("change", stage_all=False)


def symlink(target):
    return (LINK, target.encode("utf-8"))


def submodule(sha=SHA_ONE):
    return (GITLINK, sha)


AI_LINKS = {
    "a-link-at-an-ordinary-source-name": ("src/linked.py", symlink("app.py")),
    "a-link-with-a-target-outside-the-repository": ("docs/guide.md", symlink("../../outside/secret")),
    "a-link-named-like-a-test": ("tests/test_linked.py", symlink("test_app.py")),
    "a-link-under-a-protected-folder": ("acceptance/linked", symlink("test_status.py")),
    "a-submodule-at-an-ordinary-name": ("vendor/lib", submodule()),
    "a-submodule-under-a-protected-folder": ("acceptance/lib", submodule()),
}


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("what", list(AI_LINKS))
def test_g1d_a_link_or_a_submodule_added_in_an_ai_pr_is_refused(tmp_path, baseline, what):
    path, entry = AI_LINKS[what]
    case = start(tmp_path, baseline, AI)
    change(case, entries={path: entry})
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1d")
def test_g1d_a_test_file_turned_into_a_link_is_refused(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, entries={"tests/test_app.py": symlink("../src/app.py")})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "tests/test_app.py")


@pytest.mark.req("G-1d")
def test_g1d_an_ordinary_file_turned_into_a_submodule_is_refused(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, entries={"src/util.py": submodule()})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "src/util.py")


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("kind", ["link", "submodule"])
def test_g1d_a_link_or_a_submodule_that_is_pointed_somewhere_else_is_a_changed_path(tmp_path, baseline, kind):
    first, second = (symlink("app.py"), symlink("util.py")) if kind == "link" else (submodule(SHA_ONE), submodule(SHA_TWO))
    case = start(tmp_path, baseline, AI, base_entries={"src/current": first})
    change(case, entries={"src/current": second})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "src/current")


SPEC_LINKS = {
    "a-link-to-a-data-file": ("acceptance/current_data", symlink("data.json")),
    "a-link-named-like-a-test": ("acceptance/test_linked.py", symlink("test_status.py")),
    "a-link-named-conftest": ("acceptance/conftest.py", symlink("../src/app.py")),
    "a-submodule": ("acceptance/lib", submodule()),
}


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("what", list(SPEC_LINKS))
def test_g1d_a_link_or_a_submodule_added_in_a_spec_pr_is_refused(tmp_path, baseline, what):
    path, entry = SPEC_LINKS[what]
    case = start(tmp_path, baseline, SPEC)
    change(case, entries={path: entry})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1d", "G-11a")
def test_g1d_an_acceptance_test_turned_into_a_link_is_refused_in_a_spec_pr(tmp_path, baseline):
    case = start(tmp_path, baseline, SPEC)
    change(case, entries={"acceptance/test_status.py": symlink("../src/app.py")})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", "acceptance/test_status.py")


@pytest.mark.req("G-1d", "G-11")
def test_g1d_a_link_outside_acceptance_is_refused_by_both_rules_in_a_spec_pr(tmp_path, baseline):
    case = start(tmp_path, baseline, SPEC)
    change(case, entries={"src/linked.py": symlink("app.py")})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "src/linked.py")
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", "src/linked.py")


KINDS = [(AI, "src/current", "README.md"), (SPEC, "acceptance/current", "acceptance/test_new.py")]
KIND_IDS = ["ai", "spec"]
NEW_FILE = "def test_new():\n    assert 1 + 1 == 2\n"


def other_change(path):
    return {path: NEW_FILE if path.endswith(".py") else "# changed\n"}


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("what", ["link", "submodule"])
@pytest.mark.parametrize("branch,path,elsewhere", KINDS, ids=KIND_IDS)
def test_g1d_control_a_link_or_a_submodule_already_in_the_base_and_left_alone_is_no_violation(tmp_path, baseline, branch, path,
                                                                                               elsewhere, what):
    case = start(tmp_path, baseline, branch, base_entries={path: symlink("app.py") if what == "link" else submodule()})
    change(case, writes=other_change(elsewhere))
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("what", ["link", "submodule"])
@pytest.mark.parametrize("branch,path,elsewhere", KINDS, ids=KIND_IDS)
def test_g1d_control_deleting_a_link_or_a_submodule_is_no_violation(tmp_path, baseline, branch, path, elsewhere, what):
    case = start(tmp_path, baseline, branch, base_entries={path: symlink("app.py") if what == "link" else submodule()})
    change(case, deletes=[path])
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("branch,path,elsewhere", KINDS, ids=KIND_IDS)
def test_g1d_control_a_plain_file_that_holds_the_text_of_a_link_is_no_violation(tmp_path, baseline, branch, path, elsewhere):
    case = start(tmp_path, baseline, branch)
    change(case, writes={path: "app.py", path + "_two": "../../outside/secret\n"})
    res, d = case.run()
    assert d["kind"] == ("ai" if branch == AI else "spec")
    assert_clean(res, d)


@pytest.mark.req("G-1d")
def test_g1d_control_a_link_replaced_by_a_plain_file_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, base_entries={"src/current.py": symlink("app.py")})
    # with core.symlinks=false, `git add` of a rewritten path keeps mode 120000, so the plain file is written as an entry
    change(case, entries={"src/current.py": ("100644", b"VALUE = 1\n")})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1d")
def test_g1d_control_an_executable_plain_file_and_a_gitmodules_file_are_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, writes={".gitmodules": '[submodule "lib"]\n\tpath = vendor/lib\n\turl = https://example.invalid/lib.git\n'},
           entries={"bin/run": (EXEC, b"#!/bin/sh\n")})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-4: a test's name bound again

BIND = "tests/test_bind.py"
BIND_BASE = '''import pytest

from src.app import add


def test_alpha():
    assert add(1, 1) == 2
    assert add(2, 2) == 4


class TestBeta:
    def test_one(self):
        assert add(1, 1) == 2

    def test_two(self):
        assert add(2, 2) == 4


def test_gamma():
    assert add(0, 0) == 0
'''
assert "pytest" in BIND_BASE


def at_the_end(snippet, base=BIND_BASE):
    return base + "\n\n" + snippet.strip("\n") + "\n"


def in_the_class(snippet, base=BIND_BASE):
    body = textwrap.indent(snippet.strip("\n"), "    ")
    return sub(base, "\n\n\ndef test_gamma", "\n\n" + body + "\n\n\ndef test_gamma")


EXCEPT_AS = "try:\n    pass\nexcept Exception as {name}:\n    pass"
REBIND_FUNCTION = {
    "an-assignment": "test_alpha = None",
    "an-annotated-assignment": "test_alpha: object = None",
    "an-import": "from os import getcwd as test_alpha",
    "del": "del test_alpha",
    "a-loop": "for test_alpha in []:\n    pass",
    "a-class": "class test_alpha:\n    pass",
    "except-as": EXCEPT_AS.format(name="test_alpha"),
    "another-def-in-an-if": "if True:\n    def test_alpha():\n        pass",
    "another-def-in-a-try": "try:\n    def test_alpha():\n        pass\nexcept ImportError:\n    pass",
    "another-def-in-a-with": "with open(__file__) as _handle:\n    def test_alpha():\n        pass",
}
REBIND_CLASS = {
    "an-assignment": "TestBeta = None",
    "del": "del TestBeta",
    "a-second-class": "class TestBeta:\n    pass",
    "except-as": EXCEPT_AS.format(name="TestBeta"),
    "a-def": "def TestBeta():\n    pass",
}
REBIND_METHOD_FROM_OUTSIDE = {
    "an-attribute-assignment-from-outside-the-class": "TestBeta.test_one = None",
    "an-attribute-del-from-outside-the-class": "del TestBeta.test_one",
}
REBIND_METHOD_IN_CLASS = {
    "an-assignment-in-the-class": "test_one = None",
    "del-in-the-class": "del test_one",
    "a-class-in-the-class": "class test_one:\n    pass",
    "another-def-in-an-if-in-the-class": "if True:\n    def test_one(self):\n        pass",
    "another-def-in-a-try-in-the-class": "try:\n    def test_one(self):\n        pass\nexcept ImportError:\n    pass",
}


def bound_case(tmp_path, baseline, head, base=BIND_BASE, **kw):
    case = Case(tmp_path, baseline, base_edits={BIND: base}, **kw)
    case.change({BIND: head})
    return case.run()


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(REBIND_FUNCTION))
def test_g4_a_test_function_whose_name_is_bound_again_at_module_level_is_a_weakening(tmp_path, baseline, way):
    res, d = bound_case(tmp_path, baseline, at_the_end(REBIND_FUNCTION[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(REBIND_CLASS))
def test_g4_the_name_of_the_class_a_test_stands_in_bound_again_is_a_weakening(tmp_path, baseline, way):
    res, d = bound_case(tmp_path, baseline, at_the_end(REBIND_CLASS[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(REBIND_METHOD_FROM_OUTSIDE))
def test_g4_a_method_replaced_from_outside_its_class_is_a_weakening(tmp_path, baseline, way):
    res, d = bound_case(tmp_path, baseline, at_the_end(REBIND_METHOD_FROM_OUTSIDE[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(REBIND_METHOD_IN_CLASS))
def test_g4_a_methods_name_bound_again_in_its_own_class_is_a_weakening(tmp_path, baseline, way):
    res, d = bound_case(tmp_path, baseline, in_the_class(REBIND_METHOD_IN_CLASS[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


ACC_BIND = "acceptance/test_bind.py"


def spec_bound_case(tmp_path, baseline, head):
    case = Case(tmp_path, baseline, branch=SPEC, base_edits={ACC_BIND: BIND_BASE})
    case.change({ACC_BIND: head})
    return case.run()


@pytest.mark.req("G-4", "G-11a")
@pytest.mark.parametrize("snippet", ["test_alpha = None", "TestBeta.test_one = None"], ids=["module-level-assignment", "attribute-assignment-from-outside"])
def test_g4_a_spec_pr_cannot_rebind_a_test_name_under_acceptance_either(tmp_path, baseline, snippet):
    res, d = spec_bound_case(tmp_path, baseline, at_the_end(snippet))
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_WEAKENED", ACC_BIND)


BIND_REBOUND = at_the_end("test_gamma = pytest.mark.slow(test_gamma)")
NEW_TESTS = "def test_delta():\n    assert add(3, 3) == 6\n\n\nclass TestEpsilon:\n    def test_epsilon_one(self):\n        assert add(1, 1) == 2"
SAME_METHOD_NAME = "class TestZeta:\n    def test_one(self):\n        assert add(1, 1) == 2"

CONTROLS = {
    "other-names": at_the_end("test_other = None\nhelper = test_alpha\nalias = TestBeta\nTestGamma = None\nTestBeta.helper_value = None"),
    "a-comprehensions-own-variable": at_the_end("values = [test_alpha for test_alpha in range(3)]\n"
                                                "lookup = {test_one: 1 for test_one in range(2)}\n"
                                                "lazy = (TestBeta for TestBeta in range(2))"),
    "a-lambdas-argument": at_the_end("use = lambda test_alpha, TestBeta: (test_alpha, TestBeta)"),
    "a-local-inside-a-function": at_the_end("def make():\n    test_alpha = 1\n    TestBeta = 2\n    return test_alpha + TestBeta"),
    "a-new-test-and-a-new-class": at_the_end(NEW_TESTS),
    "a-method-of-the-same-name-in-a-class-of-its-own": at_the_end(SAME_METHOD_NAME),
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("what", list(CONTROLS))
def test_g4_control_a_name_that_is_not_bound_at_module_or_class_level_is_no_weakening(tmp_path, baseline, what):
    res, d = bound_case(tmp_path, baseline, CONTROLS[what])
    assert d["kind"] == "ai"
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_a_binding_that_the_base_already_had_is_not_a_new_one(tmp_path, baseline):
    res, d = bound_case(tmp_path, baseline, at_the_end(NEW_TESTS, base=BIND_REBOUND), base=BIND_REBOUND)
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_fewer_bindings_than_the_base_are_no_weakening(tmp_path, baseline):
    res, d = bound_case(tmp_path, baseline, BIND_BASE, base=BIND_REBOUND)
    assert "TEST_WEAKENED" not in rules(d), d["violations"]


@pytest.mark.req("G-4")
def test_g4_control_the_same_name_in_a_file_that_has_no_such_test_in_the_base_is_no_weakening(tmp_path, baseline):
    case = Case(tmp_path, baseline, base_edits={BIND: BIND_BASE})
    case.change({"tests/test_other_bind.py": "test_alpha = None\nTestBeta = None\n"})
    res, d = case.run()
    assert "TEST_WEAKENED" not in rules(d), d["violations"]


# ----------------------------------------------------------------------------- G-11b: what controls how every test runs stays with people

ACCEPTANCE_CONFTEST = ["acceptance/conftest.py", "acceptance/sub/conftest.py"]
G1A_ANY_FOLDER = ["pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini", ".bandit", "bandit.yaml", "bandit.yml",
                  ".gitleaks.toml", ".gitleaksignore", ".gitattributes"]


def spec_case(tmp_path, baseline, **kw):
    return Case(tmp_path, baseline, branch=SPEC, **kw)


@pytest.mark.req("G-11b")
@pytest.mark.parametrize("action", ["added", "changed", "deleted"])
@pytest.mark.parametrize("path", ACCEPTANCE_CONFTEST)
def test_g11b_a_conftest_under_acceptance_added_changed_or_deleted_is_refused_in_a_spec_pr(tmp_path, baseline, path, action):
    case = spec_case(tmp_path, baseline, base_edits=None if action == "added" else {path: "import pytest\n"})
    case.change({path: None if action == "deleted" else "import pytest\n\n\n@pytest.fixture\ndef thing():\n    return 1\n"})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-11b")
def test_g11b_a_conftest_in_a_deeply_nested_folder_is_refused_too(tmp_path, baseline):
    path = "acceptance/a/b/c/conftest.py"
    case = spec_case(tmp_path, baseline)
    case.change({path: "import pytest\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-11b", "G-1a")
@pytest.mark.parametrize("folder", ["acceptance/", "acceptance/sub/"])
def test_g11b_every_kind_of_file_that_g1a_names_in_any_folder_is_refused_under_acceptance(tmp_path, baseline, folder):
    case = spec_case(tmp_path, baseline)
    case.change({folder + name: "x\n" for name in G1A_ANY_FOLDER})
    res, d = case.run()
    assert d["kind"] == "spec"
    refused = {v["path"] for v in of(d, "PROTECTED_PATH")}
    missing = [folder + n for n in G1A_ANY_FOLDER if folder + n not in refused]
    assert not missing, f"not refused: {missing}; violations: {d['violations']}"


@pytest.mark.req("G-11b", "G-1a")
@pytest.mark.parametrize("name", ["pytest.ini", ".gitattributes"])
@pytest.mark.parametrize("action", ["changed", "deleted"])
def test_g11b_a_g1a_file_changed_or_deleted_under_acceptance_is_refused(tmp_path, baseline, name, action):
    path = "acceptance/" + name
    case = spec_case(tmp_path, baseline, base_edits={path: "[pytest]\naddopts = -q\n"})
    case.change({path: None if action == "deleted" else "[pytest]\naddopts = -q -x\n"})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", path)


UNDER_ACCEPTANCE_SUBFOLDER = {
    "a-pytest-table": ("acceptance/pyproject.toml", BASE_TOML, BASE_TOML + "\n" + PYTEST_TABLE),
    "a-tox-ini-that-mentions-pytest": ("acceptance/tox.ini", FREE_TOX_INI, "# collected by pytest\n" + FREE_TOX_INI),
    "a-setup-cfg-that-mentions-pytest": ("acceptance/setup.cfg", FREE_SETUP_CFG, "# collected by PyTest\n" + FREE_SETUP_CFG),
    "a-pytest11-table": ("acceptance/pyproject.toml", BASE_TOML, BASE_TOML + "\n" + PYTEST11["poetry-plugins"]),
    "dynamic-naming-entry-points": ("acceptance/pyproject.toml", BASE_TOML, with_dynamic('["entry-points"]')),
    "an-unparsable-pyproject-that-mentions-pytest": ("acceptance/pyproject.toml", BASE_TOML, "[project\nname = \n# pytest\n"),
}


@pytest.mark.req("G-11b", "G-1b")
@pytest.mark.parametrize("what", list(UNDER_ACCEPTANCE_SUBFOLDER))
def test_g11b_what_g1b_refuses_in_a_subfolder_is_refused_under_acceptance(tmp_path, baseline, what):
    path, before, after = UNDER_ACCEPTANCE_SUBFOLDER[what]
    res, d = edit(tmp_path, baseline, path, before, after, branch=SPEC)
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-11b")
def test_g11b_control_a_test_a_helper_and_a_data_file_are_clean_and_nothing_goes_to_the_code_owner(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({"acceptance/test_new.py": "def test_new():\n    assert 1 + 1 == 2\n", "acceptance/helper.py": "VALUE = 1\n",
                 "acceptance/data/cases.json": '{"cases": []}\n'})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert d["needs_code_owner"] == []


@pytest.mark.req("G-11b", "G-1b-mark")
def test_g11b_control_a_pyproject_with_only_a_project_table_is_clean_and_not_marked_in_a_spec_pr(tmp_path, baseline):
    # G-1b-mark stays out of spec PRs
    res, d = edit(tmp_path, baseline, "acceptance/pyproject.toml", '[project]\nname = "one"\n', '[project]\nname = "two"\n', branch=SPEC)
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert_not_marked(d, "acceptance/pyproject.toml")


@pytest.mark.req("G-11b", "G-1b")
def test_g11b_control_what_g1b_names_for_the_root_only_is_clean_under_acceptance(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "acceptance/pyproject.toml", BASE_TOML, BASE_TOML + "\n[tool.coverage]\nbranch = true\n", branch=SPEC)
    assert_clean(res, d)


@pytest.mark.req("G-11b", "G-1b")
def test_g11b_control_a_tox_ini_that_does_not_mention_pytest_is_clean_and_not_marked_under_acceptance(tmp_path, baseline):
    res, d = edit(tmp_path, baseline, "acceptance/tox.ini", FREE_TOX_INI, FREE_TOX_INI.replace("note = nothing", "note = something"), branch=SPEC)
    assert_clean(res, d)
    assert_not_marked(d, "acceptance/tox.ini")


@pytest.mark.req("G-11b")
def test_g11b_control_names_that_only_look_like_conftest_are_clean(tmp_path, baseline):
    case = spec_case(tmp_path, baseline)
    case.change({"acceptance/conftest_helpers.py": "VALUE = 1\n", "acceptance/myconftest.py": "VALUE = 1\n",
                 "acceptance/conftest.txt": "x\n", "acceptance/pytest_helpers.py": "VALUE = 1\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-11b", "G-1c", "G-11")
@pytest.mark.parametrize("path", ["tests/conftest.py", "conftest.py"])
def test_g11b_control_a_conftest_outside_acceptance_is_only_a_g11_matter_and_not_marked(tmp_path, baseline, path):
    case = spec_case(tmp_path, baseline, base_edits={path: "import pytest\n"})
    case.change({path: "import pytest\n\n\n@pytest.fixture\ndef thing():\n    return 1\n"})
    res, d = case.run()
    assert_fires(res, d, "SPEC_OUTSIDE_ACCEPTANCE", path)
    assert set(rules(d)) == {"SPEC_OUTSIDE_ACCEPTANCE"}
    assert_not_marked(d, path)
