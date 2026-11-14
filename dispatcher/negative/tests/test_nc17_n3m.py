"""NC-17 (amendment R3): N3M, one merge attempt by the executor's app on an existing, green PR."""

from __future__ import annotations

import json

import pytest

from conftest import BASE, REPOSITORY

HEAD = "a" * 40
BRANCH = "ai/1-sa1-t1-patch-accepts-a-description-over"


def add_pr(world, number=5, **changes):
    world.fake.branches[BRANCH] = HEAD
    pr = {"number": number, "html_url": f"https://github.com/{REPOSITORY}/pull/{number}", "state": "open",
          "merged": False, "draft": False, "user": {"login": "xtl-stage-a-executor[bot]", "type": "Bot"},
          "head": {"ref": BRANCH, "sha": HEAD}, "base": {"ref": BASE, "sha": world.fake.base_sha}}
    for key, value in changes.items():
        pr[key] = value
    world.fake.pulls[number] = pr


def n3m_argv(world, **changes):
    options = {"--case": "N3M", "--key-file": str(world.key_file), "--app-file": str(world.app_file),
               "--repo": REPOSITORY, "--base": BASE, "--pr": "5", "--expect-head": HEAD, "--log": str(world.log)}
    for key, value in changes.items():
        options["--" + key.replace("_", "-")] = value
    argv = []
    for key, value in options.items():
        if value is not None:
            argv += [key, value]
    return argv


def merges(world):
    return world.fake.calls_to("PUT", r"pulls/[0-9]+/merge")


@pytest.mark.parametrize("change", [{"pr": None}, {"expect_head": None}, {"pr": "0"}, {"pr": "5a"},
                                    {"expect_head": "A" * 40}, {"expect_head": "a" * 39}, {"branch": BRANCH}])
def test_nc17_usage(world, change):
    add_pr(world)
    result = world.run(argv=n3m_argv(world, **change))
    assert result.code == 2 and result.stop_line.startswith("NEGATIVE USAGE: "), result.out
    assert merges(world) == []


@pytest.mark.parametrize("option", ["--pr", "--expect-head"])
def test_nc17_n3m_options_are_refused_with_the_other_cases(world, option):
    result = world.run("N1", argv=world.argv("N1") + [option, "5" if option == "--pr" else HEAD])
    assert result.code == 2, result.out


@pytest.mark.parametrize("pr_change", [
    {"state": "closed"}, {"merged": True},
    {"base": {"ref": "main", "sha": "b" * 40}},
    {"user": {"login": "xtl-stage-a-reviewer[bot]", "type": "Bot"}},
])
def test_nc17_precondition_attempts_nothing(world, pr_change):
    add_pr(world, **pr_change)
    result = world.run(argv=n3m_argv(world))
    assert result.code == 3 and result.stop_line.startswith("NEGATIVE PRECONDITION: "), result.out
    assert merges(world) == []


def test_nc17_head_moved_attempts_nothing(world):
    add_pr(world)
    world.fake.pr_head_override = "c" * 40
    result = world.run(argv=n3m_argv(world))
    assert result.code == 3, result.out
    assert merges(world) == []


def test_nc17_refused_merge_is_done(world):
    add_pr(world)
    result = world.run(argv=n3m_argv(world))
    assert result.code == 0 and result.stop_line.startswith("NEGATIVE DONE: N3M"), result.out
    calls = merges(world)
    assert len(calls) == 1
    assert json.loads(calls[0]["body"]) == {"sha": HEAD, "merge_method": "merge"}
    record = json.loads(result.log_lines[-1])
    assert record["case"] == "N3M" and record["pr_number"] == 5 and record["head_sha"] == HEAD
    assert [(a["name"], a["status"], a["accepted"]) for a in record["attempts"]] == [("merge", 405, False)]
    assert "stage-a/policy" in record["attempts"][0]["message"]


def test_nc17_accepted_merge_is_a_finding(world):
    add_pr(world)
    world.fake.accept("merge")
    result = world.run(argv=n3m_argv(world))
    assert result.code == 1 and result.stop_line.startswith("NEGATIVE FINDING: "), result.out
    assert "ACCEPTED" in result.stop_line


def test_nc17_unclear_answer_is_a_github_error(world):
    add_pr(world)
    world.fake.attempts["merge"] = (502, "Bad Gateway")
    result = world.run(argv=n3m_argv(world))
    assert result.code == 6, result.out


def test_nc17_writes_nothing_but_the_merge_attempt(world):
    add_pr(world)
    world.run(argv=n3m_argv(world))
    writes = [c for c in world.fake.writes()]
    assert len(writes) == 1 and writes[0]["path"].endswith("/pulls/5/merge")


# ---------------------------------------------------------------- amendment S4 and the gaps of review round 2 (S5)
def test_nc17_draft_is_a_precondition(world):
    add_pr(world, draft=True)
    result = world.run(argv=n3m_argv(world))
    assert result.code == 3, result.out
    assert merges(world) == []


def test_nc17_done_quotes_the_policy_line(world):
    add_pr(world)
    result = world.run(argv=n3m_argv(world))
    assert result.code == 0, result.out
    assert 'Required status check "stage-a/policy" is expected' in result.stop_line


@pytest.mark.parametrize("status, message", [
    (405, "Repository rule violations found\n\nRequired status check \"gate/final\" is expected.\n"),
    (409, "Head branch was modified. Review and try the merge again."),
    (422, "Validation Failed"),
])
def test_nc17_a_refusal_for_another_reason_is_not_done(world, status, message):
    add_pr(world)
    world.fake.attempts["merge"] = (status, message)
    result = world.run(argv=n3m_argv(world))
    assert result.code == 6 and result.stop_line.startswith("NEGATIVE GITHUB_ERROR: "), result.out
    # The refusal is reported as such, with GitHub's first line, never as an unexpected error (closes mutant N02).
    assert "no refusal naming stage-a/policy" in result.stop_line and message.splitlines()[0][:40] in result.stop_line


@pytest.mark.parametrize("status", [201, 202, 204])
def test_nc17_any_2xx_is_a_finding(world, status):
    add_pr(world)
    world.fake.attempts["merge"] = (status, "accepted by the fake")
    result = world.run(argv=n3m_argv(world))
    assert result.code == 1 and result.stop_line.startswith("NEGATIVE FINDING: "), result.out


def test_nc17_no_answer_says_the_merge_may_have_been_done(world):
    add_pr(world)
    world.fake.disconnect("PUT", r"pulls/5/merge")
    result = world.run(argv=n3m_argv(world))
    assert result.code == 6, result.out
    assert "may have been done" in result.stop_line and "#5" in result.stop_line
