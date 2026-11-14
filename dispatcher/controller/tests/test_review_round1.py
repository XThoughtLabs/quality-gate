"""The amendments of review round 1 (R1, R2, R5, R6, R7, R8) and the paths the reviewer found untested."""

from __future__ import annotations

import json

import pytest

import fake_github as F

CODE = {"filename": "workflow/service.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a = 1\n+a = 2\n"}
NEW_TEST = {"filename": "tests/test_overdue_today.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1\n"}
STORE_PATCH = "@@ -6,3 +6,4 @@\n     id INTEGER PRIMARY KEY,\n+    tags TEXT,\n     priority INTEGER NOT NULL\n"


def with_files(world, *files, tree=None):
    world.gh.compare["files"] = [dict(f) for f in files]
    paths = [f["filename"] for f in files if f["status"] != "removed"]
    world.gh.head_tree = tree if tree is not None else [
        {"path": p, "mode": "100644", "type": "blob"} for p in paths]


def refused(world, result, rule, code):
    assert result.code == 1, result.out
    assert world.rule(rule).get("code") == code, world.last_record()
    assert "merge" not in world.gh.routes()


def store_world(world, head_source: bytes):
    store = {"filename": "workflow/store.py", "status": "modified", "patch": STORE_PATCH}
    with_files(world, store, NEW_TEST)
    world.gh.files[(F.BASE_TIP, "workflow/store.py")] = F.STORE_BASE
    world.gh.files[(F.HEAD, "workflow/store.py")] = head_source


# ---------------------------------------------------------------- R1: the schema inside string literals
@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("old, new", [
    (b"BETWEEN 1 AND 5", b"BETWEEN 1 AND 10"),
    (b"    id INTEGER PRIMARY KEY,\n", b"    id INTEGER PRIMARY KEY,\n    tags TEXT,\n"),
    (b'"DROP TABLE task_rows"', b'"DROP TABLE task_rows", "DROP TABLE tasks"'),
    (b'"CREATE TEMP TABLE task_rows AS SELECT * FROM tasks"', b'"CREATE TEMP TABLE task_rows AS SELECT id FROM tasks"'),
])
def test_a_schema_change_inside_a_string_literal_refuses(world, old, new):
    assert F.STORE_BASE.count(old) == 1
    store_world(world, F.STORE_BASE.replace(old, new))
    refused(world, world.run(), "CR-4", "SCHEMA")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("old, new", [
    (b'return {"query": query.lower()}', b'return {"query": query}'),
    (b"# A comment that names CREATE TABLE is no string literal.", b"# A comment, changed."),
    (b"    id INTEGER PRIMARY KEY,\n", b"    id   INTEGER   PRIMARY KEY,\n"),
])
def test_ordinary_code_and_white_space_in_a_schema_file_pass(world, old, new):
    """Controls: no schema string changes (white space inside one is made one space), so the PR is admitted."""
    assert F.STORE_BASE.count(old) == 1
    store_world(world, F.STORE_BASE.replace(old, new))
    store = {"filename": "workflow/store.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b\n"}
    world.gh.compare["files"][0] = store
    result = world.run()
    assert result.code == 0, result.out


@pytest.mark.cr("CR-4")
def test_contents_are_read_at_the_merge_base_and_the_head(world):
    world.gh.compare["merge_base_commit"]["sha"] = "5" * 40
    world.gh.files[("5" * 40, "workflow/service.py")] = F.DEFAULT_SOURCE
    world.run()
    refs = sorted(c.query.get("ref") for c in world.gh.calls if c.route == "contents"
                  and c.path.endswith("/workflow/service.py"))
    assert refs == sorted(["5" * 40, F.HEAD] * 2)


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("ref", ["base", "head"])
def test_a_code_file_that_cannot_be_read_is_unreadable(world, ref):
    world.gh.files[(F.BASE_TIP if ref == "base" else F.HEAD, "workflow/service.py")] = None
    refused(world, world.run(), "CR-4", "UNREADABLE")


@pytest.mark.cr("CR-4")
def test_a_code_file_that_does_not_tokenize_is_unreadable(world):
    world.gh.files[(F.HEAD, "workflow/service.py")] = b'X = """never closed\n'
    refused(world, world.run(), "CR-4", "UNREADABLE")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("line", ["+    conn.execute('CREATE UNIQUE INDEX i ON tasks(id)')",
                                  "+    conn.execute('create temp table t (x)')",
                                  "+    conn.execute('CREATE VIRTUAL TABLE f USING fts5(x)')"])
def test_the_schema_words_take_temp_unique_and_virtual(world, line):
    with_files(world, dict(CODE, patch="@@ -1 +1 @@\n" + line + "\n"), NEW_TEST)
    refused(world, world.run(), "CR-4", "SCHEMA")


# ---------------------------------------------------------------- R2: no answer
def github_error(world, result):
    assert result.code == 6, result.out
    assert len(result.stop_lines) == 1 and result.stop.startswith("CONTROLLER GITHUB_ERROR:"), result.out
    assert "Traceback" not in result.err and "Traceback" not in result.out
    assert world.last_record().get("outcome") == "GITHUB_ERROR"
    assert not world.log_file.with_name(world.log_file.name + ".lock").exists()


@pytest.mark.cr("CR-12")
@pytest.mark.parametrize("route", ["token", "pr", "post_check"])
def test_no_answer_is_a_github_error_with_a_record(world, route):
    world.gh.no_answer.add(route)
    github_error(world, world.run())
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-12")
@pytest.mark.parametrize("route", ["statuses", "check_runs", "compare", "closed"])
def test_no_answer_inside_a_rule_fails_that_rule(world, route):
    world.gh.no_answer.add(route)
    result = world.run()
    assert result.code in (1, 6), result.out
    assert "merge" not in world.gh.routes()
    assert len(result.stop_lines) == 1 and "Traceback" not in result.err
    assert not any(r.get("conclusion") == "success" for r in world.gh.policy_runs())


@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_of_a_merged_pr_is_merged(world):
    world.gh.lose_answer.add("merge")
    result = world.run()
    assert result.code == 0, result.out
    assert result.stop.startswith("CONTROLLER MERGED:") and F.MERGE_SHA in result.stop
    record = world.last_record()
    assert record["outcome"] == "MERGED" and record["merge_sha"] == F.MERGE_SHA
    assert "lost" in (record.get("message") or "")


@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_of_an_unmerged_pr_is_a_github_error(world):
    world.gh.no_answer.add("merge")
    result = world.run()
    github_error(world, result)
    assert "not merged" in result.stop


@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_with_the_pr_unreadable_after(world):
    world.gh.lose_answer.add("merge")

    def break_pr(gh):
        gh.no_answer.add("pr")
    world.gh.after["merge"] = break_pr
    result = world.run()
    github_error(world, result)
    assert "unknown" in result.stop


@pytest.mark.cr("CR-11")
@pytest.mark.parametrize("token", ["ghs_abc\r\ndef", "ghs_abc def", "", "ghs_ab\tc"])
def test_a_token_of_the_wrong_shape_is_refused(world, token):
    world.gh.token_value = token
    result = world.run()
    assert result.code == 6, result.out
    assert world.gh.routes() == ["token"]
    if token:
        assert token not in result.out + world.log_file.read_text(encoding="utf-8")


@pytest.mark.cr("CR-11")
@pytest.mark.parametrize("secret", ["ghs_" + "Z" * 36, "github_pat_" + "Q" * 40,
                                    "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOjF9.c2lnbmF0dXJlLXZhbHVl"])
def test_token_shaped_text_is_scrubbed(world, secret):
    world.gh.merge_answer = (405, {"message": "echo " + secret})
    result = world.run()
    assert result.code == 4, result.out
    text = result.out + world.log_file.read_text(encoding="utf-8")
    assert secret not in text


# ---------------------------------------------------------------- R5: filter=all
@pytest.mark.cr("CR-5")
def test_check_runs_are_read_with_filter_all(world):
    world.run()
    reads = [c for c in world.gh.calls if c.route == "check_runs"]
    assert reads and all(c.query.get("filter") == "all" for c in reads)


# ---------------------------------------------------------------- R6: letter case
@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("path", ["Tests/test_new.py", "TESTS/test_new.py"])
def test_a_test_folder_in_another_case_is_outside_the_policy(world, path):
    with_files(world, CODE, NEW_TEST, {"filename": path, "status": "added", "patch": "@@ +1 @@\n+x\n"})
    refused(world, world.run(), "CR-4", "OUTSIDE_POLICY")


@pytest.mark.cr("CR-4")
def test_a_code_folder_in_another_case_is_outside_the_policy(world):
    with_files(world, NEW_TEST, {"filename": "Workflow/service2.py", "status": "added", "patch": "@@ +1 @@\n+x\n"})
    refused(world, world.run(), "CR-4", "OUTSIDE_POLICY")


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("added", ["tests/test_API.py", "tests/TEST_api.py", "WORKFLOW/service.py"])
def test_an_added_path_that_clashes_by_case(world, added):
    tree = [{"path": p, "mode": "100644", "type": "blob"}
            for p in ("workflow/service.py", "tests/test_api.py", NEW_TEST["filename"], added)]
    with_files(world, CODE, NEW_TEST, {"filename": added, "status": "added", "patch": "@@ +1 @@\n+x\n"}, tree=tree)
    refused(world, world.run(), "CR-4", "CASE_CLASH")


# ---------------------------------------------------------------- R7: both a code change and a new test
@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("files, code", [([CODE], "NO_NEW_TEST"), ([NEW_TEST], "NO_CODE_CHANGE")])
def test_a_pr_needs_code_and_a_new_test(world, files, code):
    with_files(world, *files)
    refused(world, world.run(), "CR-4", code)


# ---------------------------------------------------------------- R8: CODEOWNERS answered without content
@pytest.mark.cr("CR-4")
def test_codeowners_without_base64_content_is_unreadable(world):
    world.gh.codeowners_encoding = "none"
    refused(world, world.run(), "CR-4", "UNREADABLE")


@pytest.mark.cr("CR-4")
def test_an_empty_codeowners_is_unreadable(world):
    world.gh.codeowners = {"CODEOWNERS": ""}
    refused(world, world.run(), "CR-4", "UNREADABLE")


# ---------------------------------------------------------------- paths the reviewer found untested
@pytest.mark.cr("CR-8")
def test_head_moved_on_the_third_read(world):
    world.gh.mergeable = [True, None, True]

    def move_after_the_second_evaluation(gh):
        # The statuses are the last read of an evaluation; the second evaluation is CR-8.1's.
        if gh.counts.get("statuses") == 2:
            gh.pr["head"]["sha"] = "9" * 40
    world.gh.after["statuses"] = move_after_the_second_evaluation
    result = world.run()
    assert result.code == 1 and "HEAD_MOVED" in result.stop, result.out
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-9")
def test_merged_by_someone_else_during_the_run(world):
    def merged_elsewhere(gh):
        gh.pr.update(merged=True, state="closed")
    world.gh.after["post_check"] = merged_elsewhere
    result = world.run()
    assert result.code == 5 and result.stop.startswith("CONTROLLER ALREADY_MERGED"), result.out
    assert "merge" not in world.gh.routes()


@pytest.mark.cr("CR-6")
def test_a_review_with_an_unknown_state_is_unreadable(world):
    world.gh.statuses = [F.review_status(50, state="weird")]
    refused(world, world.run(), "CR-6", "UNREADABLE")


@pytest.mark.cr("CR-10")
def test_the_record_of_a_github_error_holds_the_message(world):
    world.gh.no_answer.add("post_check")
    world.run()
    record = world.last_record()
    assert record["outcome"] == "GITHUB_ERROR" and record["message"]
    assert json.dumps(record).count(F.TOKEN) == 0
