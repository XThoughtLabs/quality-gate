"""NC-8 where and how requests go, NC-9 the only routes."""

from __future__ import annotations

import re

import pytest

from conftest import REPOSITORY

R = re.escape(REPOSITORY)
ALLOWED = [
    ("POST", r"^/app/installations/[0-9]+/access_tokens$"),
    ("GET", rf"^/repos/{R}/git/ref/heads/.+$"),
    ("GET", rf"^/repos/{R}/contents/.+$"),
    ("POST", rf"^/repos/{R}/git/refs$"),
    ("PUT", rf"^/repos/{R}/contents/.+$"),
    ("POST", rf"^/repos/{R}/pulls$"),
    ("GET", rf"^/repos/{R}/pulls/[0-9]+$"),
    ("POST", rf"^/repos/{R}/check-runs$"),
    ("POST", rf"^/repos/{R}/statuses/[0-9a-f]{{40}}$"),
    ("PUT", rf"^/repos/{R}/pulls/[0-9]+/merge$"),
]


def allowed(call) -> bool:
    return any(call["method"] == m and re.search(p, call["path"]) for m, p in ALLOWED)


@pytest.mark.parametrize("case", ["N1", "N2", "N3"])
def test_nc8_every_request_to_api_github_com(world, case):
    result = world.run(case)
    assert result.code == 0, result.out
    assert world.fake.calls
    for call in world.fake.calls:
        assert call["url"].startswith("https://api.github.com/")
        assert call["host"] == "api.github.com"
        assert call["timeout"] == 30
        headers = call["headers"]
        assert headers["accept"] == "application/vnd.github+json"
        assert headers["x-github-api-version"] == "2022-11-28"
        assert headers["user-agent"] == "xtl-negative"
        assert headers["authorization"].startswith("Bearer ")
        if call["body"] is not None:
            assert headers["content-type"] == "application/json"
    assert world.fake.unknown == []


def test_nc8_no_proxy_whatever_the_environment(world, monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    result = world.run("N1")
    assert result.code == 0, result.out
    for call in world.fake.calls:
        assert call["host"] == "api.github.com"
        assert call["tunnel"] is None


def test_nc8_redirect_never_followed(world):
    world.fake.redirect("GET", r"/git/ref/heads/candidate/a$", "https://elsewhere.example/repos/x")
    result = world.run("N1")
    assert result.code == 6, result.out
    assert len(world.fake.calls_to("GET", r"/git/ref/heads/candidate/a$")) == 1
    assert all(c["host"] == "api.github.com" for c in world.fake.calls)
    assert world.fake.writes() == []


def test_nc8_no_answer_is_a_github_error(world):
    world.fake.disconnect("GET", r"/contents/")
    result = world.run("N1")
    assert result.code == 6, result.out
    assert len(world.fake.calls_to("GET", r"/contents/")) == 1  # never retried
    assert world.fake.writes() == []
    assert "nothing was created" in result.stop_line


def test_nc8_server_error_never_retried(world):
    world.fake.fail("GET", r"/git/ref/heads/candidate/a$", 502, {"message": "Bad gateway"})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert len(world.fake.calls_to("GET", r"/git/ref/heads/candidate/a$")) == 1


def test_nc8_wrong_shape_of_a_2xx_answer(world):
    world.fake.fail("GET", r"/git/ref/heads/candidate/a$", 200, {"ref": "refs/heads/candidate/a"})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []


def test_nc8_not_json_2xx_answer(world):
    world.fake.fail("GET", r"/git/ref/heads/candidate/a$", 200, b"<html>not json</html>")
    result = world.run("N1")
    assert result.code == 6, result.out


def test_nc8_message_cut_to_1000(world):
    world.fake.attempts["merge"] = (405, "M" * 5000)
    result = world.run("N3")
    assert result.code == 0, result.out
    merge = [a for a in result.record["attempts"] if a["name"] == "merge"][0]
    assert merge["message"] == "M" * 1000


def test_nc8_message_scrubbed_before_cut(world):
    """A secret that straddles the 1,000th character leaves no piece of itself behind."""
    world.fake.echo_token_in_messages = True
    world.fake.attempts["merge"] = (405, "M" * 985)
    result = world.run("N3")
    assert result.code == 0, result.out
    merge = [a for a in result.record["attempts"] if a["name"] == "merge"][0]
    assert len(merge["message"]) == 1000
    token = world.fake.tokens[0]
    assert token[:7] not in merge["message"]
    assert token[:7] not in result.out + "\n".join(result.log_lines)


SCENARIOS = {
    "n1": lambda f: None,
    "n3_refused": lambda f: None,
    "n3_accepted": lambda f: (f.accept("check_run"), f.accept("status"), f.accept("merge")),
    "anchor_missing": lambda f: f.commits[f.base_sha].__setitem__("tests/test_api.py", b"nothing here\n"),
    "branch_exists": lambda f: f.branches.__setitem__("ai/90-negative-n1", f.base_sha),
    "put_fails": lambda f: f.fail("PUT", r"/contents/", 409, {"message": "conflict"}),
    "pull_fails": lambda f: f.fail("POST", r"/pulls$", 422, {"message": "Validation Failed"}),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_nc9_only_listed_routes_each_at_most_once(world, name):
    SCENARIOS[name](world.fake)
    case = "N3" if name.startswith("n3") else "N1"
    world.run(case, branch="ai/90-negative-n1")
    seen = set()
    for call in world.fake.calls:
        assert allowed(call), (call["method"], call["path"])
        key = (call["method"], call["path"])
        assert key not in seen, key
        seen.add(key)
        assert call["method"] in ("GET", "POST", "PUT")
    assert world.fake.unknown == []
