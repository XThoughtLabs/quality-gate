"""NC-10 the edits, NC-11 the order, NC-12 the writes, NC-13 N3's attempts."""

from __future__ import annotations

import base64
import difflib
import json

import pytest

from conftest import BASE, CASE_PATHS, FILES, REPOSITORY

EXPECTED_EDITS = {
    "N1": ("tests/test_api.py",
           'def test_health(client):\n    assert client.get("/health").json()["status"] == "ok"\n',
           'def test_health(client):\n    assert client.get("/health").json()["status"] == "ok"\n'
           '    assert client.get("/health").status_code == 200\n'),
    "N2": ("acceptance/test_spec_1_identity_and_visibility.py",
           'NOT_FOUND = {"detail": "task not found"}\n',
           '# Negative test N2: a harmless comment line in an acceptance file; it must not merge.\n'
           'NOT_FOUND = {"detail": "task not found"}\n'),
    "N3": ("workflow/__init__.py",
           '__version__ = "0.1.0"\n',
           '__version__ = "0.1.0"\n# Negative test N3: a harmless comment line; it must not merge.\n'),
}
ADDED_LINE = {
    "N1": '    assert client.get("/health").status_code == 200',
    "N2": "# Negative test N2: a harmless comment line in an acceptance file; it must not merge.",
    "N3": "# Negative test N3: a harmless comment line; it must not merge.",
}


def write_index(world) -> int:
    calls = world.fake.calls
    return min(i for i, c in enumerate(calls) if c["method"] != "GET" and not c["path"].startswith("/app/"))


def index_of(world, method, regex) -> int:
    for i, call in enumerate(world.fake.calls):
        if call["method"] == method and __import__("re").search(regex, call["path"]):
            return i
    raise AssertionError(f"no {method} {regex}")


# ---------------------------------------------------------------- NC-10

@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc10_edit_constants(neg, case):
    path, old, new = EXPECTED_EDITS[case]
    edit = neg.EDITS[case]
    assert (edit.path, edit.old, edit.new) == (path, old, new)


@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc10_apply_edit_exact(neg, case):
    path, old, new = EXPECTED_EDITS[case]
    content = FILES[path]
    before, after = content.split(old.encode("utf-8"))
    assert neg.apply_edit(case, content) == before + new.encode("utf-8") + after


@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
@pytest.mark.parametrize("copies", [0, 2])
def test_nc10_apply_edit_needs_exactly_one(neg, case, copies):
    path, old, _ = EXPECTED_EDITS[case]
    content = b"header\n" + old.encode("utf-8") * copies + b"footer\n"
    with pytest.raises(neg.AnchorNotOnce) as caught:
        neg.apply_edit(case, content)
    assert caught.value.count == copies


@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc10_commit_holds_exactly_the_intended_change(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    branch = f"ai/90-negative-{case.lower()}"
    files = world.fake.branch_files(branch)
    path = CASE_PATHS[case]
    for other, content in FILES.items():
        if other != path:
            assert files[other] == content
    new = files[path].decode("utf-8").splitlines()
    old = FILES[path].decode("utf-8").splitlines()
    diff = [line for line in difflib.ndiff(old, new) if line[:1] in "+-?"]
    assert diff == ["+ " + ADDED_LINE[case]]
    _, old_text, new_text = EXPECTED_EDITS[case]
    assert files[path] == FILES[path].replace(old_text.encode(), new_text.encode())


def test_nc10_content_read_at_the_base_sha(world):
    result = world.run("N1")
    assert result.code == 0, result.out
    call = world.fake.calls_to("GET", r"/contents/")[0]
    assert call["path"] == f"/repos/{REPOSITORY}/contents/tests/test_api.py"
    assert call["query"] == f"ref={world.fake.base_sha}"


def test_nc10_wrong_blob_sha_is_a_github_error(world):
    world.fake.wrong_blob_sha = True
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


def test_nc10_content_not_base64(world):
    world.fake.content_encoding = "none"
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


def test_nc10_content_not_a_file(world):
    world.fake.fail("GET", r"/contents/", 200, [{"type": "file", "name": "x"}])
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


# ---------------------------------------------------------------- NC-11

@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc11_order_reads_then_checks_then_writes(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    token = index_of(world, "POST", r"/access_tokens$")
    base = index_of(world, "GET", rf"/git/ref/heads/{BASE}$")
    content = index_of(world, "GET", r"/contents/")
    branch = index_of(world, "GET", rf"/git/ref/heads/ai/90-negative-{case.lower()}$")
    assert token < base < content < branch < write_index(world)
    assert [c["method"] + " " + c["path"].split("/")[-1] for c in world.fake.writes()][:3] == [
        "POST refs", f"PUT {CASE_PATHS[case].split('/')[-1]}", "POST pulls"]


@pytest.mark.parametrize("copies", [0, 2])
def test_nc11_anchor_not_once_creates_nothing(world, copies):
    path, old, _ = EXPECTED_EDITS["N1"]
    world.fake.commits[world.fake.base_sha][path] = b"# start\n" + old.encode() * copies + b"# end\n"
    result = world.run("N1")
    assert result.code == 3, result.out
    assert result.stop_line.startswith("NEGATIVE PRECONDITION: ")
    assert str(copies) in result.stop_line
    assert world.fake.writes() == []
    assert world.fake.calls_to("GET", r"/git/ref/heads/ai/") == []  # no request after the anchor check
    assert result.record["created"] == []


def test_nc11_branch_exists_creates_nothing(world):
    world.fake.branches["ai/90-negative-n2"] = world.fake.base_sha
    result = world.run("N2")
    assert result.code == 3, result.out
    assert result.stop_line.startswith("NEGATIVE PRECONDITION: ")
    assert "ai/90-negative-n2" in result.stop_line
    assert world.fake.writes() == []


def test_nc11_branch_check_other_answer(world):
    world.fake.fail("GET", r"/git/ref/heads/ai/", 500, {"message": "Server Error"})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []
    assert "nothing was created" in result.stop_line


def test_nc11_base_missing(world):
    result = world.run("N1", base="candidate/b")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


def test_nc11_base_answer_for_another_ref(world):
    world.fake.fail("GET", rf"/git/ref/heads/{BASE}$", 200,
                    {"ref": "refs/heads/other", "object": {"sha": "a" * 40, "type": "commit"}})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


# ---------------------------------------------------------------- NC-12

@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc12_write_bodies(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    branch = f"ai/90-negative-{case.lower()}"
    ref = json.loads(world.fake.calls_to("POST", r"/git/refs$")[0]["body"])
    assert ref == {"ref": f"refs/heads/{branch}", "sha": world.fake.base_sha}
    put = json.loads(world.fake.calls_to("PUT", r"/contents/")[0]["body"])
    assert set(put) == {"message", "content", "sha", "branch"}
    assert put["branch"] == branch
    assert put["sha"] == __import__("fake_github").blob_sha(FILES[CASE_PATHS[case]])
    assert put["message"].startswith(f"NEGATIVE {case}:")
    assert base64.b64decode(put["content"]) == world.fake.branch_files(branch)[CASE_PATHS[case]]
    pull = json.loads(world.fake.calls_to("POST", r"/pulls$")[0]["body"])
    assert set(pull) == {"title", "head", "base", "body", "draft"}
    assert pull["head"] == branch and pull["base"] == BASE and pull["draft"] is False
    assert pull["title"].startswith(f"NEGATIVE {case}:")
    body = pull["body"]
    assert f"Negative test {case} " in body
    assert "must not merge" in body
    assert "never closes" in body
    assert "no model run" in body


def test_nc12_put_fails_after_branch(world):
    world.fake.fail("PUT", r"/contents/", 409, {"message": "conflict"})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert result.stop_line.startswith("NEGATIVE GITHUB_ERROR: ")
    assert "ai/90-negative-n1" in result.stop_line
    assert result.record["created"] == ["branch"]
    assert world.fake.calls_to("POST", r"/pulls$") == []


def test_nc12_pull_fails_after_commit(world):
    world.fake.fail("POST", r"/pulls$", 422, {"message": "Validation Failed"})
    result = world.run("N2")
    assert result.code == 6, result.out
    assert result.record["created"] == ["branch", "commit"]
    assert result.record["commit_sha"] in result.stop_line


def test_nc12_write_without_answer(world):
    world.fake.disconnect("POST", r"/git/refs$")
    result = world.run("N1")
    assert result.code == 6, result.out
    assert "may" in result.stop_line
    assert world.fake.calls_to("PUT", r"/contents/") == []


def test_nc12_interrupted_run(world):
    world.fake.interrupt("POST", r"/pulls$")
    result = world.run("N1")
    assert result.code == 6, result.out
    assert result.stop_line.startswith("NEGATIVE GITHUB_ERROR: ")
    assert "interrupt" in result.stop_line.lower()
    assert result.record["created"] == ["branch", "commit"]


@pytest.mark.parametrize("case", ["N1", "N2"])
def test_nc12_n1_n2_done(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    assert result.stop_line.startswith("NEGATIVE DONE: ")
    pr = world.fake.pulls[41]
    assert f"#{pr['number']}" in result.stop_line and pr["html_url"] in result.stop_line
    assert world.fake.calls_to("GET", r"/pulls/[0-9]+$") == []
    assert world.fake.calls_to("POST", r"/check-runs$") == []


# ---------------------------------------------------------------- NC-13

def attempt_calls(world):
    return [c for c in world.fake.calls
            if (c["method"], c["path"].split("/")[-1]) in {("POST", "check-runs"), ("PUT", "merge")}
            or "/statuses/" in c["path"]]


def test_nc13_attempts_all_refused(world):
    result = world.run("N3")
    assert result.code == 0, result.out
    assert result.stop_line.startswith("NEGATIVE DONE: ")
    head = world.fake.branches["ai/90-negative-n3"]
    calls = attempt_calls(world)
    assert [c["method"] + " " + c["path"] for c in calls] == [
        f"POST /repos/{REPOSITORY}/check-runs",
        f"POST /repos/{REPOSITORY}/statuses/{head}",
        f"PUT /repos/{REPOSITORY}/pulls/41/merge",
    ]
    check = json.loads(calls[0]["body"])
    assert {k: check[k] for k in ("name", "head_sha", "status", "conclusion")} == {
        "name": "stage-a/policy", "head_sha": head, "status": "completed", "conclusion": "success"}
    assert "forged" in json.dumps(check["output"]).lower()
    status = json.loads(calls[1]["body"])
    assert status["state"] == "success" and status["context"] == "stage-a/policy"
    assert json.loads(calls[2]["body"]) == {"sha": head, "merge_method": "merge"}
    pull_read = index_of(world, "GET", r"/pulls/41$")
    assert pull_read < world.fake.calls.index(calls[0])
    attempts = result.record["attempts"]
    assert [(a["name"], a["status"], a["accepted"]) for a in attempts] == [
        ("check_run", 403, False), ("status", 403, False), ("merge", 405, False)]
    assert attempts[2]["message"].startswith("Repository rule violations found")
    for name in ("403", "405"):
        assert name in result.stop_line
    assert result.record["head_sha"] == head


@pytest.mark.parametrize("accepted", ["check_run", "status", "merge"])
def test_nc13_any_accepted_attempt_is_a_finding(world, accepted):
    world.fake.accept(accepted)
    result = world.run("N3")
    assert result.code == 1, result.out
    assert result.stop_line.startswith("NEGATIVE FINDING: ")
    assert "ACCEPTED" in result.stop_line and accepted in result.stop_line
    assert "finding" in result.stop_line.split(":", 1)[1].lower()
    assert len(attempt_calls(world)) == 3  # all three are tried whatever the earlier answers
    record = {a["name"]: a for a in result.record["attempts"]}
    assert record[accepted]["accepted"] is True
    assert result.record["outcome"] == "FINDING" and result.record["exit_code"] == 1


@pytest.mark.parametrize("status", [500, 502, 301])
def test_nc13_unclear_attempt(world, status):
    world.fake.attempts["status"] = (status, "unclear")
    result = world.run("N3")
    assert result.code == 6, result.out
    assert len(attempt_calls(world)) == 3
    assert [a["status"] for a in result.record["attempts"]] == [403, status, 405]


def test_nc13_attempt_without_answer(world):
    world.fake.disconnect("POST", r"/check-runs$")
    result = world.run("N3")
    assert result.code == 6, result.out
    assert len(attempt_calls(world)) == 3
    first = result.record["attempts"][0]
    assert first["status"] is None and first["accepted"] is False


def test_nc13_accepted_wins_over_unclear(world):
    world.fake.accept("merge")
    world.fake.disconnect("POST", r"/check-runs$")
    result = world.run("N3")
    assert result.code == 1, result.out


def test_nc13_never_retried(world):
    for name in ("check_run", "status", "merge"):
        world.fake.attempts[name] = (503, "unavailable")
    result = world.run("N3")
    assert result.code == 6
    assert len(attempt_calls(world)) == 3


def test_nc13_head_must_be_the_tools_commit(world):
    world.fake.pr_head_override = "e" * 40
    result = world.run("N3")
    assert result.code == 6, result.out
    assert attempt_calls(world) == []
    assert result.record["created"] == ["branch", "commit", "pull_request"]
    assert "#41" in result.stop_line


def test_nc13_pull_read_fails(world):
    world.fake.fail("GET", r"/pulls/41$", 404, {"message": "Not Found"})
    result = world.run("N3")
    assert result.code == 6, result.out
    assert attempt_calls(world) == []
