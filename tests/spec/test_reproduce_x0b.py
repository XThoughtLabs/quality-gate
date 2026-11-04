"""gate.reproduce takes no secrets: X-0b and X-0a (HQ-ANSWERS-07 replaced both), and the X-0 refinement about a newer commit.

X-0b: `gate.reproduce` takes no secrets, because a rerun runs PR code under the same user, which can read this process. A
non-empty variable whose name holds a word of E-2 (TOKEN, SECRET, PASSWORD, PRIVATE_KEY, CREDENTIAL, API_KEY, in any letter
case) exits 2 before anything runs, and the message names the variables and holds no value. `make reproduce` passes no token
into the container.

X-0a (C-3): a credential in `--repo` exits 2 before anything runs, and the message holds no value: a password or a query in any
URL, or a user name in any URL but `ssh`. `git@host:path` and `ssh://git@host/path` hold no credential.

"Before anything runs" is shown by what did not happen: nothing under `--out`, and no request to the API stand-in. There is
nothing of the rerun to look at, which is the point of the rule. `make reproduce` is a text check of the Makefile at GATE_ROOT.
"""
from __future__ import annotations

import re

import pytest

from gatekit import GATE_ROOT, StubServer, assert_no_traceback, assert_rc
from test_reproduce_x0 import GITHUB_FORMS, Remote, assert_not_untrusted, assert_untrusted

# ----------------------------------------------------------------------------- the X-0 refinement: a newer commit on the API's side

NEWER = "e" * 40


@pytest.mark.req("X-0")
def test_x0_a_newer_commit_on_the_apis_side_is_no_failure(tmp_path, stub):
    # "a report may be stored meanwhile and its authors are checked too": the commit git read is among those the API lists
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    remote.api.mirror(remote.commits + [(NEWER, [remote.commits[-1][0]])])
    assert_not_untrusted(remote, remote.run(GITHUB_FORMS["https"]))


@pytest.mark.req("X-0")
def test_x0_a_newer_foreign_commit_on_the_apis_side_is_still_a_failure(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)
    remote.api.mirror(remote.commits + [(NEWER, [remote.commits[-1][0]])], foreign={NEWER: ("some-person", True)})
    assert_untrusted(remote, remote.run(GITHUB_FORMS["https"]))


# ----------------------------------------------------------------------------- X-0a: a credential in --repo

VALUE = "SENTINEL-VALUE-1234"
CREDENTIAL_URLS = {
    "https-user-name-and-password": f"https://x-access-token:{VALUE}@github.com/example-org/example-app.git",
    "https-token-as-the-user-name": f"https://{VALUE}@github.com/example-org/example-app",
    "https-query": f"https://github.com/example-org/example-app.git?access_token={VALUE}",
    "https-in-capitals-with-a-password": f"HTTPS://user:{VALUE}@GITHUB.COM/example-org/example-app.git",
    "http-user-name-on-another-host": f"http://{VALUE}@example.com/org/app.git",
    "https-password-on-another-host": f"https://user:{VALUE}@example.com/org/app.git",
    "git-protocol-user-name": f"git://{VALUE}@example.com/org/app.git",
    "ssh-url-with-a-password": f"ssh://git:{VALUE}@github.com/example-org/example-app.git",
    "ssh-url-with-a-query": f"ssh://git@github.com/example-org/example-app.git?token={VALUE}",
}


def nothing_ran(remote, stub):
    assert not remote.out.exists() or not any(remote.out.iterdir()), "something was written under --out"
    assert stub.requests == [], f"something ran: the API was asked {stub.requests}"


@pytest.mark.req("X-0a", "C-3")
@pytest.mark.parametrize("form", list(CREDENTIAL_URLS))
def test_x0a_a_credential_in_repo_exits_2_before_anything_runs_and_is_in_no_message(tmp_path, stub, form):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)
    res = remote.run(CREDENTIAL_URLS[form])
    assert_rc(res, 2)
    assert_no_traceback(res)
    assert res.both.strip(), "a refusal prints a short message (C-2)"
    assert VALUE not in remote.text(res), "the message or a file under --out holds the credential"
    assert "author" not in remote.text(res).lower(), "it got as far as the check of the authors, so something ran"
    nothing_ran(remote, stub)


@pytest.mark.req("X-0a")
def test_x0a_control_a_user_name_in_an_ssh_url_is_no_credential_on_a_github_remote(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    assert_not_untrusted(remote, remote.run("ssh://alice@github.com/example-org/example-app.git"))


@pytest.mark.req("X-0a")
def test_x0a_control_a_user_name_in_an_ssh_url_is_no_credential_on_another_host(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    res = remote.run("ssh://alice@example.com/example-org/example-app.git")
    assert_rc(res, 2)
    assert_no_traceback(res)
    assert "author" in remote.text(res).lower(), "it went on, and said that the authors cannot be checked on another remote"


# ----------------------------------------------------------------------------- X-0b: no secret-named variable

SECRET_VARIABLES = [
    "GATE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "EXECUTOR_APP_PRIVATE_KEY",
    # one name for each word that E-2 counts, and one in lower case
    "EXAMPLE_SECRET_A", "EXAMPLE_PASSWORD_B", "EXAMPLE_CREDENTIAL_C", "EXAMPLE_API_KEY_D", "EXAMPLE_PRIVATE_KEY_E",
    "example_token_f",
]
NAMES_WITHOUT_A_WORD = ["EXAMPLE_KEY", "PRIVATE_NAME", "EXAMPLE_API", "PASS_THROUGH", "CRED", "EXAMPLE_VISIBLE_SETTING"]


class Refusal:
    def __init__(self, remote, stub, res, failure):
        self.remote, self.stub, self.res, self.failure = remote, stub, res, failure

    def ran(self):
        assert self.failure is None, f"gate.reproduce did not run: {self.failure}"

    def said(self):
        return self.remote.text(self.res)


@pytest.fixture(scope="module")
def refusal(tmp_path_factory):
    stub = StubServer().start()
    try:
        remote = Remote(tmp_path_factory.mktemp("x0b"), stub, evidence_for_sha=True)
        res, failure = None, None
        try:
            res = remote.run(GITHUB_FORMS["https"], extra_env={name: f"{VALUE}-{name}" for name in SECRET_VARIABLES})
        except AssertionError as exc:    # the module is missing
            failure = exc
        yield Refusal(remote, stub, res, failure)
    finally:
        stub.stop()


@pytest.mark.req("X-0b")
def test_x0b_secret_named_variables_exit_2_before_anything_runs(refusal):
    refusal.ran()
    assert_rc(refusal.res, 2)
    assert_no_traceback(refusal.res)
    assert refusal.res.both.strip(), "a refusal prints a short message (C-2)"
    nothing_ran(refusal.remote, refusal.stub)


@pytest.mark.req("X-0b")
@pytest.mark.parametrize("name", SECRET_VARIABLES)
def test_x0b_the_message_names_each_variable(refusal, name):
    refusal.ran()
    assert name.upper() in refusal.res.both.upper(), f"the message does not name {name}:\n{refusal.res.describe()}"


@pytest.mark.req("X-0b", "C-3")
def test_x0b_no_value_is_in_any_output(refusal):
    refusal.ran()
    assert VALUE not in refusal.said(), "the value of a variable was printed or written under --out"


@pytest.mark.req("X-0b", "E-2")
def test_x0b_control_empty_variables_are_no_secret_and_the_run_goes_on(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    res = remote.run(GITHUB_FORMS["https"], extra_env={name: "" for name in SECRET_VARIABLES})
    assert_not_untrusted(remote, res)


@pytest.mark.req("X-0b", "E-2")
def test_x0b_control_variables_whose_names_hold_no_word_of_e2_do_not_stop_the_run(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    res = remote.run(GITHUB_FORMS["https"], extra_env={name: "1" for name in NAMES_WITHOUT_A_WORD})
    assert_not_untrusted(remote, res)


# ----------------------------------------------------------------------------- make reproduce passes no token


def reproduce_recipe() -> str:
    """The recipe of the `reproduce` target, with the make variables that the file defines at its left edge filled in."""
    makefile = GATE_ROOT / "Makefile"
    assert makefile.is_file(), f"{makefile} does not exist"
    lines = makefile.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ").splitlines()
    definitions = {}
    for line in lines:
        found = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]*=\s*(.*)$", line)
        if found:
            definitions[found.group(1)] = found.group(2)
    recipe, inside = [], False
    for line in lines:
        if re.match(r"^reproduce\s*:(?!=)", line):
            inside = True
            recipe.append(line.split(":", 1)[1])
            continue
        if inside:
            if line.startswith(("\t", " ")) or not line.strip() or line.startswith("#"):
                recipe.append(line)
            else:
                break
    assert inside, "the Makefile has no `reproduce` target"
    text = "\n".join(recipe)
    for _ in range(3):   # a few rounds, for variables that name other variables
        text = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]", lambda m: definitions.get(m.group(1), m.group(0)), text)
    return text


ENV_ARGUMENT = re.compile(r"""(?:^|\s)(?:-e|--env)(?:\s+|=)["']?([A-Za-z_][A-Za-z0-9_]*)""")
E2_WORDS = re.compile(r"TOKEN|SECRET|PASSWORD|PRIVATE_KEY|CREDENTIAL|API_KEY", re.IGNORECASE)


@pytest.mark.req("X-0b")
def test_x0b_make_reproduce_passes_no_secret_named_variable_into_the_container():
    recipe = reproduce_recipe()
    handed = ENV_ARGUMENT.findall(recipe)
    secret = [name for name in handed if E2_WORDS.search(name)]
    assert not secret, f"the recipe hands {secret} to the container:\n{recipe}"
