"""Section 4: the JWT (LR-12), the installation (LR-13), revocation
(LR-14) and the token in the launcher's own requests (LR-15).

Most runs here stop at NOT_AN_ISSUE (the issue does not exist), the
cheapest way past the token."""

from __future__ import annotations

import pytest

import launcher_world as W


def no_issue(world):
    world.api.issues.clear()


# ---------------------------------------------------------------- LR-12
def test_lr12_jwt_is_rs256_with_the_documented_claims(world, check):
    no_issue(world)
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    app_requests = [r for r in res.requests if r["path"].startswith("/app/")]
    assert app_requests, "no request reached /app/"
    assert all(r.get("status") in (200, 201) for r in app_requests), \
        [(r["path"], r.get("status")) for r in app_requests]
    assert world.api.jwt_claims, "no JWT was verified with the key's public key"
    for header in world.api.jwt_headers:
        assert header.get("alg") == "RS256"
    for item in world.api.jwt_claims:
        claims, received = item["claims"], item["received"]
        assert type(claims["iss"]) is int and claims["iss"] == W.APP_ID, claims
        assert isinstance(claims["iat"], int) and isinstance(claims["exp"], int), claims
        assert abs((received - 60) - claims["iat"]) <= 15, (claims, received)
        assert 0 < claims["exp"] - claims["iat"] <= 600, claims
        assert claims["exp"] > received


# ---------------------------------------------------------------- LR-13
def test_lr13_installation_then_token_for_the_one_repository(world, check):
    no_issue(world)
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    paths = [(r["method"], r["path"]) for r in res.requests]
    i_list = paths.index(("GET", "/app/installations"))
    i_post = paths.index(("POST", f"/app/installations/{W.INSTALLATION_ID}/access_tokens"))
    assert i_list < i_post
    body = res.requests[i_post]["body"]
    assert body == {"repositories": [W.REPO_NAME]}, body


@pytest.mark.parametrize("variant", ["other_id", "other_account"])
def test_lr13_installation_not_listed(world, check, variant):
    no_issue(world)
    inst = world.api.installations[0]
    if variant == "other_id":
        inst["id"] = W.INSTALLATION_ID + 1
    else:
        inst["account"]["login"] = "SomeoneElse"
    res = world.run("task", "--issue", "5")
    check.stopped(res, "INSTALLATION")
    assert world.api.requests_to("POST", r"/access_tokens$") == []
    assert world.api.tokens_issued == []


@pytest.mark.parametrize("repos", [[W.REPO_NAME, "other-repo"], ["other-repo"], []])
def test_lr13_token_for_other_repositories(world, check, repos):
    no_issue(world)
    world.api.token_repositories = repos
    res = world.run("task", "--issue", "5")
    check.stopped(res, "INSTALLATION")  # also checks the minted token was revoked
    assert len(world.api.tokens_issued) == 1


def test_lr13_control_answer_without_repositories_passes(world, check):
    no_issue(world)
    world.api.token_repositories = None
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")


# ---------------------------------------------------------------- LR-14
def test_lr14_revoked_with_the_token_last_on_a_stop(world, check):
    no_issue(world)
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    token = world.api.tokens_issued[0]
    last = res.requests[-1]
    assert (last["method"], last["path"]) == ("DELETE", "/installation/token")
    assert last["headers"].get("Authorization") == f"Bearer {token}"
    assert "token revoked" in res.log_text


def test_lr14_revoked_on_an_error(world, check):
    """A failed request stops with `API` (amendment 1, A8) and still revokes
    the token. The error's body echoes the credentials, which must not reach
    the output (LR-50)."""
    world.api.fail("GET", r"^/users/", 500,
                   lambda rec: {"message": f"server error for {rec['headers'].get('Authorization')}"})
    res = world.run("task", "--issue", "5")
    # Revocation and secrets first, so they are judged even if the code is wrong.
    check.revoked(res)
    check.no_leak(res)
    assert res.model is None
    assert not res.pushed
    check.stopped(res, "API")


def test_lr14_revoked_on_ctrl_c(world, check):
    """Ctrl+C arrives as KeyboardInterrupt in the launcher's own thread; it is
    raised here from the second FOLDER_OPEN check (LR-30), after the token.
    Amendment 1, A8: it stops with `INTERRUPTED`, exit 1."""
    def interrupt_after_token(path):
        if world.api.tokens_issued:
            raise KeyboardInterrupt
        return None
    world.seams.folder_hook = interrupt_after_token
    res = world.run("spec", "--slug", "ctrl-c")
    assert world.api.tokens_issued, res.describe()
    check.stopped(res, "INTERRUPTED")
    assert res.model is None, "the model ran after Ctrl+C"
    assert not res.pushed


def test_a8_key_unreadable(world, check):
    """Amendment 1, A8: a key file that holds no private key stops with
    `KEY_UNREADABLE`; no JWT, so nothing reaches /app/."""
    world.key_file.write_text("this is not a private key\n", encoding="utf-8")
    res = world.run("task", "--issue", "5")
    check.stopped(res, "KEY_UNREADABLE")
    assert [r for r in res.requests if r["path"].startswith("/app/")] == []
    assert world.api.tokens_issued == []
    assert "this is not a private key" not in res.stdout + res.stderr + res.log_text


def test_lr14_failed_revocation_is_logged(world, check):
    no_issue(world)
    world.api.fail("DELETE", r"^/installation/token$", 500, {"message": "nope"})
    res = world.run("task", "--issue", "5")
    assert res.code == 1 and res.stop_code == "NOT_AN_ISSUE", res.describe()
    assert world.api.requests_to("DELETE", r"^/installation/token$"), "no revocation was tried"
    assert "token revoke failed" in res.log_text
    check.no_leak(res)
    check.routes(res)


# ---------------------------------------------------------------- LR-15 (the launcher's own requests)
def test_lr15_own_requests_carry_the_bearer_token(world, check):
    no_issue(world)
    res = world.run("task", "--issue", "5")
    check.stopped(res, "NOT_AN_ISSUE")
    token = world.api.tokens_issued[0]
    issue_reads = [r for r in res.requests if r["method"] == "GET"
                   and r["path"] == f"/repos/{W.REPOSITORY}/issues/5"]
    assert issue_reads, "the issue was not read"
    for r in issue_reads + world.api.requests_to("DELETE", r"^/installation/token$"):
        assert r["headers"].get("Authorization") == f"Bearer {token}", r["headers"]


def test_lr50_plain_token_is_scrubbed_by_value(world, check):
    """A token that matches none of scrub's patterns can only be removed by
    value: the error body echoes it. A 500 for the issue is `API` (A8)."""
    world.api.token_shape = "plain"
    world.api.fail("GET", r"^/repos/.*/issues/5$", 500,
                   lambda rec: {"message": f"echo {rec['headers'].get('Authorization')}"})
    res = world.run("task", "--issue", "5")
    assert world.api.tokens_issued, "no token was minted"
    # Revocation and secrets first, so they are judged even if the code is wrong.
    check.revoked(res)
    check.no_leak(res)
    check.stopped(res, "API")
