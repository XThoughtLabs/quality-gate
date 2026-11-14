"""The amendments of review round 2 (S1, S2, S3) and the test gaps it named (S5)."""

from __future__ import annotations

import pytest

import fake_github as F

NEW_TEST = {"filename": "tests/test_overdue_today.py", "status": "added", "patch": "@@ -0,0 +1 @@\n+x = 1\n"}


def code_world(world, base: bytes | dict, head: bytes | dict, path="workflow/store.py"):
    world.gh.compare["files"] = [{"filename": path, "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b\n"},
                                 dict(NEW_TEST)]
    world.gh.head_tree = [{"path": p, "mode": "100644", "type": "blob"} for p in (path, NEW_TEST["filename"])]
    world.gh.files[(F.BASE_TIP, path)] = base
    world.gh.files[(F.HEAD, path)] = head


def refused(world, result, code):
    assert result.code == 1, result.out
    assert world.rule("CR-4").get("code") == code, world.last_record()
    assert "merge" not in world.gh.routes()


# ---------------------------------------------------------------- S3: whole runs of literals and whole f-strings
@pytest.mark.cr("CR-4")
def test_a_schema_in_an_f_string_changed_after_a_field_refuses(world):
    base = b'def make(name):\n    return f"CREATE TABLE {name} (id INTEGER, flag INTEGER CHECK(flag IN (0, 1)))"\n'
    code_world(world, base, base.replace(b"(0, 1)", b"(0, 1, 2)"))
    refused(world, world.run(), "SCHEMA")


@pytest.mark.cr("CR-4")
def test_a_schema_split_over_adjacent_literals_refuses(world):
    base = b'SQL = (\n    "CREATE TABLE t ("\n    "id INTEGER CHECK(id > 0))"\n)\n'
    code_world(world, base, base.replace(b"id > 0", b"id > 1"))
    refused(world, world.run(), "SCHEMA")


@pytest.mark.cr("CR-4")
def test_separate_literals_stay_separate(world):
    """A control: two list items are two literals; a change in a non-schema item is no schema change."""
    base = b'ITEMS = ["CREATE TABLE t (id INTEGER)", "plain text"]\n'
    code_world(world, base, base.replace(b"plain text", b"other text"))
    assert world.run().code == 0


@pytest.mark.cr("CR-4")
def test_letter_case_of_a_schema_string_is_ignored(world):
    """S5: the comparison is in lower case (a control that a mutant without lower() fails)."""
    base = b'SQL = "CREATE TABLE t (id INTEGER)"\n'
    code_world(world, base, b'SQL = "create table t (id integer)"\n')
    assert world.run().code == 0


@pytest.mark.cr("CR-4")
@pytest.mark.parametrize("side", ["base", "head"])
def test_code_contents_that_are_not_base64_are_unreadable(world, side):
    """S5: a file over 1 MB comes back with encoding none and no content; it must not compare equal."""
    big = {"type": "file", "encoding": "none", "content": ""}
    normal = b'LIMIT = 1\n'
    code_world(world, big if side == "base" else normal, big if side == "head" else normal)
    refused(world, world.run(), "UNREADABLE")


@pytest.mark.cr("CR-4")
def test_code_contents_both_not_base64_are_unreadable(world):
    big = {"type": "file", "encoding": "none", "content": ""}
    code_world(world, big, dict(big))
    refused(world, world.run(), "UNREADABLE")


# ---------------------------------------------------------------- S1: a lost merge answer at another head
@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_merged_at_another_head_is_a_github_error(world):
    """GitHub did not merge for this run (405), its answer was lost, and meanwhile the PR was merged at another head."""
    world.gh.merge_answer = (405, {"message": "not merged for this run"})
    world.gh.lose_answer.add("merge")

    def merged_elsewhere(gh):
        gh.pr.update(merged=True, state="closed")
        gh.pr["head"]["sha"] = "9" * 40
    world.gh.after["merge"] = merged_elsewhere
    result = world.run()
    assert result.code == 6, result.out
    assert "not at this run's head" in result.stop
    assert world.last_record()["outcome"] == "GITHUB_ERROR" and world.last_record()["merge_sha"] is None


@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_without_a_merge_sha_is_not_merged(world):
    """S5: MERGED needs a merge_commit_sha."""
    world.gh.lose_answer.add("merge")

    def merged_without_sha(gh):
        gh.pr["merge_commit_sha"] = None
    world.gh.after["merge"] = merged_without_sha
    result = world.run()
    assert result.code == 6, result.out
    assert world.last_record()["merge_sha"] is None


@pytest.mark.cr("CR-8")
def test_a_lost_merge_answer_names_merged_by(world):
    world.gh.lose_answer.add("merge")

    def by_controller(gh):
        gh.pr["merged_by"] = {"login": "acme-controller[bot]"}
    world.gh.after["merge"] = by_controller
    result = world.run()
    assert result.code == 0, result.out
    assert "acme-controller[bot]" in world.last_record()["message"]


# ---------------------------------------------------------------- S2: a record that cannot be written
@pytest.mark.cr("CR-10")
def test_a_record_that_cannot_be_written_keeps_the_outcome_and_one_stop_line(world):
    world.log_file.mkdir(parents=True)  # a folder where the log file should be: it cannot be opened for append
    result = world.run()
    assert len(result.stop_lines) == 1, result.out
    assert result.stop.endswith("; the record could not be written"), result.out
    assert "Traceback" not in result.err
    assert result.code in (1, 0)  # CR-3 cannot read a folder as the log, so the run is refused (exit 1)
    assert not world.log_file.with_name(world.log_file.name + ".lock").exists()
