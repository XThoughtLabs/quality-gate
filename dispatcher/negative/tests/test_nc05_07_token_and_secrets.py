"""NC-5 the JWT, NC-6 the un-narrowed installation token, NC-7 secrets."""

from __future__ import annotations

import json
import os
import time

import pytest

from conftest import APP_ID, INSTALLATION_ID, REPOSITORY


# ---------------------------------------------------------------- NC-5

def test_nc5_jwt_claims_and_signature(world):
    before = int(time.time())
    result = world.run("N1")
    after = int(time.time())
    assert result.code == 0, result.out
    assert len(world.fake.jwt_claims) == 1
    claims, header = world.fake.jwt_claims[0], world.fake.jwt_headers[0]
    assert header == {"alg": "RS256", "typ": "JWT"}
    assert claims["iss"] == APP_ID
    assert before - 60 <= claims["iat"] <= after - 60
    assert claims["exp"] == claims["iat"] + 600
    assert list(claims) == ["iat", "exp", "iss"]


@pytest.mark.parametrize("now", [1_700_000_000.0, 1_800_000_123.9])
def test_nc5_make_jwt_equals_launcher(neg, launcher_ref, test_key, now):
    assert neg.make_jwt(APP_ID, test_key.pem, now) == launcher_ref.make_jwt(APP_ID, test_key.pem, now)


# ---------------------------------------------------------------- NC-6

def test_nc6_token_request_not_narrowed(world):
    result = world.run("N1")
    assert result.code == 0, result.out
    calls = world.fake.calls_to("POST", r"^/app/installations/")
    assert len(calls) == 1
    call = calls[0]
    assert call["path"] == f"/app/installations/{INSTALLATION_ID}/access_tokens"
    assert json.loads(call["body"]) == {"repositories": [REPOSITORY.split("/")[1]]}
    assert call["headers"]["authorization"] == f"Bearer {world.fake.jwts[0]}"


def test_nc6_token_used_on_every_other_request(world):
    result = world.run("N3")
    assert result.code == 0, result.out
    token = world.fake.tokens[0]
    jwt = world.fake.jwts[0]
    others = [c for c in world.fake.calls if not c["path"].startswith("/app/")]
    assert others
    for call in others:
        assert call["headers"]["authorization"] == f"Bearer {token}"
        assert jwt not in json.dumps({k: str(v) for k, v in call.items()})


def test_nc6_token_permissions_recorded(world):
    world.fake.token_permissions = {"contents": "write", "metadata": "read", "pull_requests": "write"}
    result = world.run("N3")
    assert result.record["token_permissions"] == {"contents": "write", "metadata": "read", "pull_requests": "write"}


def test_nc6_token_refused_is_github_error(world):
    world.fake.fail("POST", r"^/app/installations/", 401, {"message": "A JSON web token could not be decoded"})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert result.stop_line.startswith("NEGATIVE GITHUB_ERROR: ")
    assert "nothing was created" in result.stop_line
    assert len(world.fake.calls) == 1


def test_nc6_token_without_token_text(world):
    world.fake.fail("POST", r"^/app/installations/", 201, {"token": "", "permissions": {}})
    result = world.run("N1")
    assert result.code == 6, result.out
    assert len(world.fake.calls) == 1


@pytest.mark.parametrize("listed", [["other-repo"], [REPOSITORY.split("/")[1], "other-repo"], []])
def test_nc6_token_for_other_repositories(world, listed):
    world.fake.token_repositories = listed
    result = world.run("N1")
    assert result.code == 6, result.out
    assert world.fake.writes() == []
    assert result.record["created"] == []


def test_nc6_token_answer_without_repositories_is_accepted(world):
    world.fake.token_repositories = None
    result = world.run("N1")
    assert result.code == 0, result.out


def test_nc6_token_not_revoked(world):
    result = world.run("N3")
    assert result.code == 0, result.out
    assert world.fake.calls_to("DELETE", r".") == []


# ---------------------------------------------------------------- NC-7

@pytest.mark.parametrize("shape", ["ghs", "plain"])
def test_nc7_secrets_never_in_output_or_log(world, shape):
    world.fake.token_shape = shape
    world.fake.echo_token_in_messages = True
    result = world.run("N3")
    assert result.code == 0, result.out
    text = result.out + result.err + "\n".join(result.log_lines)
    secrets = world.secrets()
    assert world.fake.tokens and world.fake.jwts
    for secret in secrets:
        assert secret not in text
    assert "[removed]" in text  # the echoed messages were scrubbed, not dropped


def test_nc7_secrets_scrubbed_from_error_messages(world):
    world.fake.token_shape = "plain"
    world.fake.echo_token_in_messages = True
    world.fake.attempts["merge"] = (500, "server error")
    result = world.run("N3")
    assert result.code == 6, result.out
    text = result.out + result.err + "\n".join(result.log_lines)
    for secret in world.secrets():
        assert secret not in text


def test_nc7_no_environment_variable_set(world):
    before = dict(os.environ)
    result = world.run("N3")
    assert result.code == 0, result.out
    assert dict(os.environ) == before


def test_nc7_no_file_written_but_the_log(world):
    before = sorted(p.relative_to(world.root) for p in world.root.rglob("*"))
    key_bytes = world.key_file.read_bytes()
    app_bytes = world.app_file.read_bytes()
    result = world.run("N3")
    assert result.code == 0, result.out
    after = sorted(p.relative_to(world.root) for p in world.root.rglob("*"))
    added = set(after) - set(before)
    assert added == {world.log.relative_to(world.root), world.log.parent.relative_to(world.root)}
    assert world.key_file.read_bytes() == key_bytes and world.app_file.read_bytes() == app_bytes


SCRUB_SAMPLES = [
    "plain text",
    "token ghs_" + "a" * 36 + " end",
    "github_pat_" + "B" * 30,
    # The same text, written in pieces so that a secret scanner does not take the sample for a key.
    "-----BEGIN RSA " "PRIVATE KEY-----\nMIIabc\n-----END RSA " "PRIVATE KEY-----",
    "x -----BEGIN PRIVATE KEY----- y",
    "secret-one and secret-one-longer",
    "",
]


@pytest.mark.parametrize("text", SCRUB_SAMPLES)
def test_nc7_scrub_equals_launcher(neg, launcher_ref, text):
    listed = ["secret-one", "secret-one-longer", "", "MIIabc"]
    assert neg.scrub(text, listed) == launcher_ref.scrub(text, listed)
