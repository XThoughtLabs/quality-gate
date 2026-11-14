"""NC-14 the record, NC-15 output and exit codes, NC-16 what the tool never does."""

from __future__ import annotations

import ast
import json
import re

import pytest

from conftest import BASE, REPOSITORY, TOOL_DIR

KEYS = {"time", "tool", "case", "repository", "base", "base_sha", "branch", "path", "blob_sha", "commit_sha",
        "pr_number", "pr_url", "head_sha", "attempts", "token_permissions", "created", "outcome", "exit_code",
        "detail"}


# ---------------------------------------------------------------- NC-14

@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc14_record_fields(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    assert len(result.log_lines) == 1
    record = result.record
    assert set(record) == KEYS
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", record["time"])
    assert record["tool"] == "xtl_negative"
    assert record["case"] == case and record["repository"] == REPOSITORY and record["base"] == BASE
    assert record["base_sha"] == world.fake.base_sha
    branch = f"ai/90-negative-{case.lower()}"
    assert record["branch"] == branch
    assert record["commit_sha"] == world.fake.branches[branch]
    assert record["pr_number"] == 41
    assert record["pr_url"] == f"https://github.com/{REPOSITORY}/pull/41"
    assert record["created"] == ["branch", "commit", "pull_request"]
    assert record["outcome"] == "DONE" and record["exit_code"] == 0
    assert record["detail"] == result.stop_line.split(": ", 1)[1]
    if case == "N3":
        assert [a["name"] for a in record["attempts"]] == ["check_run", "status", "merge"]
        assert set(record["attempts"][0]) == {"name", "method", "route", "status", "accepted", "message"}
        assert record["head_sha"] == record["commit_sha"]
    else:
        assert record["attempts"] == [] and record["head_sha"] is None


def test_nc14_record_appended_earlier_lines_kept(world):
    world.log.parent.mkdir(parents=True)
    world.log.write_text('{"earlier": true}\n', encoding="utf-8")
    first = world.run("N1")
    second = world.run("N2")
    assert first.code == 0 and second.code == 0
    lines = world.log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0]) == {"earlier": True}
    assert json.loads(lines[1])["case"] == "N1" and json.loads(lines[2])["case"] == "N2"


def test_nc14_record_is_ascii(world):
    world.fake.attempts["merge"] = (405, "refusé — rule")
    result = world.run("N3")
    raw = world.log.read_bytes()
    raw.decode("ascii")
    assert result.record["attempts"][2]["message"] == "refusé — rule"


@pytest.mark.parametrize("scenario", ["precondition", "github_error", "usage"])
def test_nc14_one_line_whatever_the_outcome(world, scenario):
    if scenario == "precondition":
        world.fake.branches["ai/90-negative-n1"] = world.fake.base_sha
    elif scenario == "github_error":
        world.fake.fail("POST", r"/pulls$", 500, {"message": "boom"})
    else:
        world.key_file.unlink()
    result = world.run("N1")
    assert len(result.log_lines) == 1
    assert set(result.record) == KEYS
    assert result.record["exit_code"] == result.code


# ---------------------------------------------------------------- NC-15

@pytest.mark.parametrize("scenario,code,outcome", [
    ("done", 0, "DONE"), ("finding", 1, "FINDING"), ("usage", 2, "USAGE"), ("precondition", 3, "PRECONDITION"),
    ("github_error", 6, "GITHUB_ERROR"),
])
def test_nc15_exit_codes_and_one_stop_line(world, scenario, code, outcome):
    if scenario == "finding":
        world.fake.accept("merge")
    elif scenario == "usage":
        world.app_file.write_text("{}", encoding="ascii")
    elif scenario == "precondition":
        world.fake.commits[world.fake.base_sha]["workflow/__init__.py"] = b"changed\n"
    elif scenario == "github_error":
        world.fake.fail("GET", r"/git/ref/heads/candidate/a$", 404, {"message": "Not Found"})
    result = world.run("N3")
    assert result.code == code, result.out
    stop_lines = [line for line in result.out.splitlines() if line.startswith("NEGATIVE ")]
    assert stop_lines == [result.stop_line]
    assert re.fullmatch(rf"NEGATIVE {outcome}: \S.*", result.stop_line)
    assert result.err == ""
    result.out.encode("ascii")
    if code in (2, 3):
        assert "Nothing was" in result.stop_line or "nothing was" in result.stop_line


def test_nc15_finding_says_so_plainly(world):
    world.fake.accept("check_run")
    result = world.run("N3")
    assert result.code == 1
    line = result.stop_line
    assert "ACCEPTED" in line and "executor's app" in line and "finding" in line.lower()


def test_nc15_unexpected_error_is_exit_6(world, monkeypatch):
    import urllib.request

    def broken(*handlers):
        raise ZeroDivisionError("unexpected")

    world.run("N1")  # import the tool first
    monkeypatch.setattr(urllib.request, "build_opener", broken)
    result = world.run("N2")
    assert result.code == 6, result.out
    assert result.stop_line.startswith("NEGATIVE GITHUB_ERROR: ")
    assert result.err == ""


# ---------------------------------------------------------------- NC-16

def tool_tree():
    return ast.parse((TOOL_DIR / "xtl_negative.py").read_text(encoding="utf-8"))


def test_nc16_no_subprocess_no_launcher_import():
    tree = tool_tree()
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"subprocess", "xtl_launcher", "requests", "http.server", "socketserver", "ctypes"}
    assert "importlib" not in imported
    allowed = {"__future__", "argparse", "base64", "binascii", "hashlib", "http", "json", "os", "re", "stat", "sys",
               "time", "urllib", "datetime", "pathlib", "dataclasses", "cryptography", "typing"}
    assert imported <= allowed, imported - allowed


def test_nc16_no_assert_for_runtime_checks():
    assert not [node for node in ast.walk(tool_tree()) if isinstance(node, ast.Assert)]


def test_nc16_no_environment_writes_in_code():
    source = (TOOL_DIR / "xtl_negative.py").read_text(encoding="utf-8")
    assert "putenv" not in source
    assert not re.search(r"os\.environ\s*\[[^\]]*\]\s*=", source)
    assert "os.environ.update" not in source and "os.environ.setdefault" not in source


@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc16_never_closes_deletes_or_reviews(world, case):
    world.fake.accept("merge") if case == "N3" else None
    world.run(case)
    for call in world.fake.calls:
        assert call["method"] in ("GET", "POST", "PUT")
        assert not re.search(r"/(reviews|labels|comments|requested_reviewers|rulesets|protection|hooks|"
                             r"collaborators|actions|issues)\b", call["path"])
        if call["method"] == "PUT":
            assert re.search(r"/contents/|/merge$", call["path"])
        if call["method"] == "POST" and call["body"]:
            body = json.loads(call["body"])
            assert body.get("state") != "closed"
