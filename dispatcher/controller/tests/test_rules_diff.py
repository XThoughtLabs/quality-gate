"""CR-4: the diff admits only ordinary application code and added ordinary tests."""

from __future__ import annotations

import pytest

import fake_github as F

CODE = {"filename": "workflow/service.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a = 1\n+a = 2\n"}
NEW_TEST = {"filename": "tests/test_overdue_today.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1\n"}


def with_files(world, *files, tree=None):
    world.gh.compare["files"] = [dict(f) for f in files]
    paths = [f["filename"] for f in files if f["status"] != "removed"]
    world.gh.head_tree = tree if tree is not None else [
        {"path": p, "mode": "100644", "type": "blob"} for p in paths]


def refused(world, result, code):
    assert result.code == 1, result.out
    assert "CR-4 " + code in result.stop, result.out
    assert world.rule("CR-4").get("code") == code
    assert "merge" not in world.gh.routes()
    assert [r["conclusion"] for r in world.gh.policy_runs()] == ["failure"]


def f(name, status="modified", patch="@@ -1 +1 @@\n-a\n+b\n", **extra):
    return {"filename": name, "status": status, "patch": patch, **extra}


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("bad, code", [
    (f("tests/test_api.py"), "TEST_CHANGED"),
    (f("tests/test_api.py", "removed"), "TEST_CHANGED"),
    (f("tests/test_new_name.py", "renamed", previous_filename="tests/test_api.py"), "TEST_CHANGED"),
    (f("tests/test_api.py", "changed"), "TEST_CHANGED"),
    (f("tests/test_copy.py", "copied", previous_filename="tests/test_api.py"), "TEST_CHANGED"),
    (f("workflow/test_inside.py"), "TEST_CHANGED"),
    (f("workflow/store_test.py"), "TEST_CHANGED"),
    (f("acceptance/test_spec_1.py"), "TEST_CHANGED"),
    (f("acceptance/test_spec_new.py", "added"), "ACCEPTANCE"),
    (f("acceptance/known-failing.txt"), "TEST_CHANGED"),
    (f("acceptance/notes.txt", "added"), "ACCEPTANCE"),
    (f("Tests/Test_Api.py"), "TEST_CHANGED"),
    (f("workflow/old.py", "removed"), "REMOVED"),
    (f("workflow/new.py", "renamed", previous_filename="workflow/old.py"), "RENAMED"),
    (f("workflow/service.py", "changed"), "MODE_CHANGED"),
    (f("tests/conftest.py"), "TEST_CHANGED"),
    (f("tests/conftest.py", "added"), "CONFTEST"),
    (f("workflow/conftest.py", "added"), "CONFTEST"),
    (f("Workflow/ConfTest.py", "added"), "CONFTEST"),
    (f(".github/workflows/judge.yml"), "WORKFLOW"),
    (f(".github/CODEOWNERS"), "WORKFLOW"),
    (f("workflow/.github/x.py", "added"), "WORKFLOW"),
    (f("pytest.ini"), "TEST_CONFIG"),
    (f("workflow/pytest.ini", "added"), "TEST_CONFIG"),
    (f(".coveragerc"), "TEST_CONFIG"),
    (f("setup.cfg", "added"), "TEST_CONFIG"),
    (f("tox.ini", "added"), "TEST_CONFIG"),
    (f(".gitattributes"), "TEST_CONFIG"),
    (f("security-review.md", "added"), "TEST_CONFIG"),
    (f("workflow/bandit.yaml", "added"), "TEST_CONFIG"),
    (f("quality.toml"), "CONTROL"),
    (f("CODEOWNERS"), "CONTROL"),
    (f("docs/CODEOWNERS", "added"), "CONTROL"),
    (f("requirements.lock"), "DEPENDENCY"),
    (f("requirements.in"), "DEPENDENCY"),
    (f("requirements-dev.txt", "added"), "DEPENDENCY"),
    (f("workflow/pyproject.toml", "added"), "DEPENDENCY"),
    (f("setup.py", "added"), "DEPENDENCY"),
    (f("uv.lock", "added"), "DEPENDENCY"),
    (f("workflow/migrations/0002_add.py", "added"), "SCHEMA"),
    (f("workflow/schema.sql", "added"), "SCHEMA"),
    (f("workflow/alembic/env.py", "added"), "SCHEMA"),
    (f("SPEC.md"), "CODEOWNERS_PATH"),
    (f("docs/idempotency-keys.md"), "OUTSIDE_POLICY"),
    (f("tools/benchmark.py"), "OUTSIDE_POLICY"),
    (f("README.md"), "OUTSIDE_POLICY"),
    (f("workflow/data.json", "added"), "OUTSIDE_POLICY"),
    (f("tests/helpers.py", "added"), "OUTSIDE_POLICY"),
    (f("workflow/test_new.py", "added"), "OUTSIDE_POLICY"),
    (f("workflow/new_test.py", "added"), "OUTSIDE_POLICY"),
    (f("workflow/../quality.toml"), "BAD_PATH"),
    (f("workflow\\service.py"), "BAD_PATH"),
    (f("/workflow/service.py"), "BAD_PATH"),
    (f("workflow//service.py"), "BAD_PATH"),
    (f("workflow/./service.py"), "BAD_PATH"),
    (f("workflow/ser\nvice.py"), "BAD_PATH"),
])
def test_one_bad_file_refuses(world, bad, code):
    with_files(world, CODE, bad, NEW_TEST)
    refused(world, world.run(), code)


@pytest.mark.cr("CR-4")
def test_the_first_bad_file_in_api_order_names_the_code(world):
    with_files(world, CODE, f("quality.toml"), f("tests/test_api.py"))
    refused(world, world.run(), "CONTROL")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("files", [
    [CODE, NEW_TEST],
    [f("workflow/new_module.py", "added"), f("tests/sub/test_deeper.py", "added")],
])
def test_admitted_kinds_pass(world, files):
    with_files(world, *files)
    result = world.run()
    assert result.code == 0, result.out
    assert world.rule("CR-4").get("ok") is True


@pytest.mark.cr("CR-4")
def test_empty_diff_refuses(world):
    with_files(world)
    refused(world, world.run(), "EMPTY_DIFF")


@pytest.mark.cr("CR-4")
def test_too_many_files_refuses(world):
    files = [f(f"workflow/m{i}.py", "added") for i in range(300)]
    with_files(world, *files)
    refused(world, world.run(), "TOO_MANY_FILES")


@pytest.mark.cr("CR-4")
def test_299_files_are_read(world):
    files = [f(f"workflow/m{i}.py", "added") for i in range(298)] + [NEW_TEST]
    with_files(world, *files)
    assert world.run().code == 0


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("line", [
    "+    db.execute('CREATE TABLE extra (id INTEGER)')",
    "-    db.execute('create   index idx on tasks(due)')",
    "+    sql = 'ALTER TABLE tasks ADD COLUMN x'",
    "+    cur.execute(\"Drop View v\")",
    "+    conn.execute('CREATE TRIGGER t AFTER INSERT ON tasks BEGIN SELECT 1; END')",
    "+    conn.execute('PRAGMA user_version = 3')",
])
def test_schema_words_in_a_code_patch_refuse(world, line):
    with_files(world, f("workflow/store.py", patch="@@ -1,2 +1,2 @@\n context\n" + line + "\n"), NEW_TEST)
    refused(world, world.run(), "SCHEMA")


@pytest.mark.cr("CR-4")
def test_schema_words_in_an_unchanged_context_line_do_not_refuse(world):
    with_files(world, f("workflow/store.py", patch="@@ -1,3 +1,3 @@\n CREATE TABLE tasks (\n-a\n+b\n"), NEW_TEST)
    assert world.run().code == 0


@pytest.mark.cr("CR-4")
def test_code_file_without_a_patch_refuses(world):
    code = dict(CODE)
    del code["patch"]
    with_files(world, code, NEW_TEST)
    refused(world, world.run(), "PATCH_UNREADABLE")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("entry", [
    {"path": "workflow/service.py", "mode": "120000", "type": "blob"},
    {"path": "workflow/service.py", "mode": "100755", "type": "blob"},
    {"path": "workflow/service.py", "mode": "160000", "type": "commit"},
])
def test_admitted_file_that_is_no_plain_file_refuses(world, entry):
    tree = [entry, {"path": NEW_TEST["filename"], "mode": "100644", "type": "blob"}]
    with_files(world, CODE, NEW_TEST, tree=tree)
    refused(world, world.run(), "MODE")


@pytest.mark.cr("CR-4")
def test_admitted_file_missing_from_the_tree_refuses(world):
    tree = [{"path": NEW_TEST["filename"], "mode": "100644", "type": "blob"}]
    with_files(world, CODE, NEW_TEST, tree=tree)
    refused(world, world.run(), "MODE")


@pytest.mark.cr("CR-4")
def test_truncated_head_tree_is_unreadable(world):
    world.gh.head_tree_truncated = True
    refused(world, world.run(), "UNREADABLE")


@pytest.mark.cr("CR-4")
def test_codeowners_names_an_application_file(world):
    world.gh.codeowners = {"CODEOWNERS": F.DEFAULT_CODEOWNERS + "/workflow/service.py @acme\n"}
    refused(world, world.run(), "CODEOWNERS_PATH")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("pattern, path", [
    ("/workflow/", "workflow/service.py"),
    ("workflow/", "workflow/service.py"),
    ("service.py", "workflow/service.py"),
    ("/WORKFLOW/SERVICE.PY", "workflow/service.py"),
    ("workflow", "workflow/service.py"),
    ("workflow/service.py", "workflow/service.py"),
])
def test_codeowners_pattern_forms(world, pattern, path):
    world.gh.codeowners = {"CODEOWNERS": f"{pattern} @acme\n"}
    with_files(world, f(path))
    refused(world, world.run(), "CODEOWNERS_PATH")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("pattern", ["/other/", "/workflow/store.py", "service", "/service.py", "flow/",
                                     "x/workflow/service.py", "/workflow/service.py/", "service.py/"])
def test_codeowners_patterns_that_do_not_name_the_file(world, pattern):
    world.gh.codeowners = {"CODEOWNERS": f"# comment\n\n{pattern} @acme\n"}
    with_files(world, f("workflow/service.py"), NEW_TEST)
    assert world.run().code == 0


@pytest.mark.cr("CR-4")
def test_codeowners_is_read_from_the_first_place_that_exists(world):
    world.gh.codeowners = {".github/CODEOWNERS": "/workflow/ @acme\n", "CODEOWNERS": "/nothing/ @acme\n"}
    refused(world, world.run(), "CODEOWNERS_PATH")
    contents = [c for c in world.gh.calls if c.route == "contents"]
    assert contents and contents[0].query.get("ref") == F.BASE_TIP


@pytest.mark.cr("CR-4")
def test_codeowners_missing_refuses(world):
    world.gh.codeowners = {}
    refused(world, world.run(), "CODEOWNERS_MISSING")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("pattern", ["*.py", "/workflow/*", "docs/**", "[ab].py", "!keep.py", "a\\ b"])
def test_codeowners_unsupported_pattern_refuses_every_pr(world, pattern):
    world.gh.codeowners = {"CODEOWNERS": f"{pattern} @acme\n"}
    refused(world, world.run(), "CODEOWNERS_UNSUPPORTED")


@pytest.mark.cr("CR-4")
def test_compare_uses_the_base_tip_and_the_head(world):
    world.run()
    compare = [c for c in world.gh.calls if c.route == "compare"]
    assert compare and compare[0].path.endswith(f"/compare/{F.BASE_TIP}...{F.HEAD}")
    assert world.last_record().get("base_tip") == F.BASE_TIP
