"""gate.publish post-proposal after the CEO's answer of 2026-11-04 (HQ-ANSWERS-04): P-6 and P-6a.

The model chooses what stands at the proposal's path, and the step that posts it holds a token. These tests make the file
a link, a second name, a folder, a device, or a text that holds a secret's value or is shaped like a secret, and look at the
GitHub stand-in: nothing may be written to it. Tests that need a link skip with a reason where the machine cannot make one.

CONTRACTS.md gives the route of no call of post-proposal, so the stand-in answers every write with 201 and lists the open
pull request of the branch wherever it is asked; "posts nothing" means that no request other than a GET reached it.
"""
from __future__ import annotations

import base64
import os
import textwrap

import pytest

from gatekit import assert_no_traceback, assert_rc, base_env, run_gate, write_bytes, write_text

REPO = "example-org/example-app"
BRANCH = "ai/12-example"
SECRET_VARIABLES = ["GATE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "EXECUTOR_APP_PRIVATE_KEY"]


def value_of(name: str) -> str:
    # not shaped like any secret: only the "value of the variable" rule can recognise it
    return f"SENTINEL-VALUE-1234-{name}"


def all_values() -> dict[str, str]:
    return {n: value_of(n) for n in SECRET_VARIABLES}


TOKEN = value_of("GATE_TOKEN")      # the step's own token
PR = 7
PLAIN = "Proposed entry for the review table: example tool, rule B000, path src/app.py, reason fixture only."


class Hub:
    """The GitHub stand-in: one open pull request for BRANCH, and a 201 for anything that is written."""

    def __init__(self, stub, branch=BRANCH):
        self.stub = stub
        pull = {"number": PR, "state": "open", "title": "example", "body": "", "html_url": f"http://example.invalid/pull/{PR}",
                "head": {"ref": branch, "sha": "1" * 40, "label": f"example-org:{branch}", "repo": {"full_name": REPO}},
                "base": {"ref": "candidate/a", "sha": "2" * 40, "repo": {"full_name": REPO}},
                "user": {"login": "example-executor[bot]"}}
        stub.route("GET", r".*/pulls", (200, [pull]))
        stub.route("GET", rf".*/pulls/{PR}", (200, pull))
        stub.route("GET", rf".*/issues/{PR}", (200, pull))
        stub.route("GET", rf".*/(issues|pulls)/{PR}/comments", (200, []))
        for method in ("POST", "PATCH", "PUT"):
            stub.route(method, r".*", (201, {"id": 1, "number": PR, "html_url": "http://example.invalid/c/1", "body": ""}))

    def writes(self):
        return [r for r in self.stub.requests if r.method not in ("GET", "HEAD")]

    def written_text(self):
        return "\n".join(r.body.decode("utf-8", "replace") for r in self.writes())


@pytest.fixture
def hub(stub):
    return Hub(stub)


def post(tmp_path, hub, path, *, env=None, branch=BRANCH, timeout=120):
    environment = base_env({"GATE_TOKEN": TOKEN, "GITHUB_API_URL": hub.stub.url, "GITHUB_REPOSITORY": REPO, **(env or {})})
    res = run_gate("publish", "post-proposal", "--file", path, "--branch", branch, env=environment, cwd=tmp_path, timeout=timeout)
    assert "No module named" not in res.err, "precondition: gate.publish exists and runs with python -P -m"
    assert_no_traceback(res)
    return res


def assert_posted(res, hub, text=PLAIN):
    assert_rc(res, 0)
    assert hub.writes(), f"nothing was written to GitHub\n{res.describe()}"
    assert text.split(":")[0] in hub.written_text(), "the proposal's text is not in what was written"


def assert_nothing_posted(res, hub, code, *, unseen=()):
    assert_rc(res, code)
    assert hub.writes() == [], f"posted although the file was refused: {hub.writes()}"
    assert res.both.strip(), "a refusal prints a short message (C-2)"
    for value in unseen:
        assert value not in res.both, "the refusal printed what it refused (C-3)"
        assert value not in hub.written_text()


def proposal(tmp_path, text=PLAIN, name="proposal.md"):
    return write_text(tmp_path / name, text)


# ----------------------------------------------------------------------------- P-6: the ordinary file, and nothing to post


@pytest.mark.req("P-6a", "P-6")
def test_p6a_control_a_plain_ordinary_file_is_posted(tmp_path, hub):
    assert_posted(post(tmp_path, hub, proposal(tmp_path)), hub)


@pytest.mark.req("P-6a", "P-6")
def test_p6a_control_the_names_of_the_secret_variables_are_no_secret(tmp_path, hub):
    text = "Proposed entry: the step reads GATE_TOKEN, GH_TOKEN, GITHUB_TOKEN, CLAUDE_CODE_OAUTH_TOKEN and EXECUTOR_APP_PRIVATE_KEY by name."
    assert_posted(post(tmp_path, hub, proposal(tmp_path, text), env=all_values()), hub, text)


@pytest.mark.req("P-6")
@pytest.mark.parametrize("what", ["missing", "empty"])
def test_p6_a_missing_or_empty_file_does_nothing(tmp_path, hub, what):
    path = tmp_path / "proposal.md"
    if what == "empty":
        write_bytes(path, b"")
    res = post(tmp_path, hub, path)
    assert_rc(res, 0)
    assert hub.writes() == []


# ----------------------------------------------------------------------------- P-6a: what is not a plain file


def can_make(kind: str, tmp_path) -> None:
    """Skip, with the reason, when this machine cannot make the thing the test needs."""
    probe = tmp_path / "probe-target"
    probe.write_bytes(b"x")
    try:
        if kind == "symlink":
            os.symlink(probe, tmp_path / "probe-link")
        elif kind == "hardlink":
            os.link(probe, tmp_path / "probe-second-name")
        elif kind == "fifo":
            os.mkfifo(tmp_path / "probe-fifo")
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"this machine cannot make a {kind} here ({type(exc).__name__}: {exc})")


@pytest.mark.req("P-6a")
def test_p6a_a_symbolic_link_to_a_plain_file_exits_2_and_is_not_followed(tmp_path, hub):
    can_make("symlink", tmp_path)
    target = proposal(tmp_path, PLAIN, "real-proposal.md")
    link = tmp_path / "proposal.md"
    os.symlink(target, link)
    assert_nothing_posted(post(tmp_path, hub, link), hub, 2, unseen=[PLAIN])


@pytest.mark.req("P-6a")
def test_p6a_a_symbolic_link_to_a_file_with_a_secret_is_still_exit_2_never_followed(tmp_path, hub):
    can_make("symlink", tmp_path)
    secret = "SENTINEL-VALUE-1234-GH_TOKEN"
    target = proposal(tmp_path, f"Proposed entry {secret}", "real-proposal.md")
    link = tmp_path / "proposal.md"
    os.symlink(target, link)
    # exit 1 would mean that the target was read
    assert_nothing_posted(post(tmp_path, hub, link, env={"GH_TOKEN": secret}), hub, 2, unseen=[secret])


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("what", ["folder", "missing"])
def test_p6a_a_symbolic_link_to_a_folder_or_to_nothing_exits_2(tmp_path, hub, what):
    # a link that points at nothing is still a symbolic link; it is not "a missing file" (see the report)
    can_make("symlink", tmp_path)
    target = tmp_path / "some-folder"
    if what == "folder":
        target.mkdir()
        (target / "proposal.md").write_text(PLAIN, encoding="utf-8")
    link = tmp_path / "proposal.md"
    os.symlink(target, link, target_is_directory=(what == "folder"))
    assert_nothing_posted(post(tmp_path, hub, link), hub, 2, unseen=[PLAIN])


@pytest.mark.req("P-6a")
def test_p6a_control_a_plain_file_in_a_folder_of_its_own_is_posted(tmp_path, hub):
    real = tmp_path / "real-folder"
    real.mkdir()
    proposal(real, PLAIN)
    assert_posted(post(tmp_path, hub, real / "proposal.md"), hub)


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("which", ["the-path-given", "the-other-name"])
def test_p6a_a_file_with_a_second_name_exits_2(tmp_path, hub, which):
    can_make("hardlink", tmp_path)
    first = proposal(tmp_path, PLAIN, "proposal.md")
    second = tmp_path / "second-name.md"
    os.link(first, second)
    path = first if which == "the-path-given" else second
    assert_nothing_posted(post(tmp_path, hub, path), hub, 2, unseen=[PLAIN])


@pytest.mark.req("P-6a")
def test_p6a_control_a_file_whose_second_name_is_gone_is_a_plain_file_again(tmp_path, hub):
    can_make("hardlink", tmp_path)
    first = proposal(tmp_path, PLAIN, "proposal.md")
    second = tmp_path / "second-name.md"
    os.link(first, second)
    second.unlink()
    assert_posted(post(tmp_path, hub, first), hub)


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("what", ["empty-folder", "folder-with-a-proposal-in-it"])
def test_p6a_a_folder_exits_2(tmp_path, hub, what):
    folder = tmp_path / "proposal.md"
    folder.mkdir()
    if what != "empty-folder":
        (folder / "proposal.md").write_text(PLAIN, encoding="utf-8")
    assert_nothing_posted(post(tmp_path, hub, folder), hub, 2, unseen=[PLAIN])


@pytest.mark.req("P-6a")
def test_p6a_a_device_exits_2_although_it_reads_as_empty(tmp_path, hub):
    # os.devnull is a character device on both families (/dev/null and NUL); "anything but a plain file" includes it
    assert_nothing_posted(post(tmp_path, hub, os.devnull), hub, 2)


@pytest.mark.req("P-6a")
def test_p6a_a_named_pipe_exits_2_and_does_not_block(tmp_path, hub):
    can_make("fifo", tmp_path)
    fifo = tmp_path / "proposal.md"
    os.mkfifo(fifo)
    assert_nothing_posted(post(tmp_path, hub, fifo, timeout=30), hub, 2)


# ----------------------------------------------------------------------------- P-6a: the value of a secret


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("name", SECRET_VARIABLES)
@pytest.mark.parametrize("placement", ["in-a-sentence", "glued-to-other-letters", "alone-on-a-line", "in-a-table-cell"])
def test_p6a_a_text_that_holds_the_value_of_a_named_variable_exits_1_and_posts_nothing(tmp_path, hub, name, placement):
    value = value_of(name)
    text = {
        "in-a-sentence": f"Proposed entry: the tool said {value} before it stopped.",
        "glued-to-other-letters": f"Proposed entry: xx{value}yy",
        "alone-on-a-line": f"Proposed entry:\n\n{value}\n\nend.",
        "in-a-table-cell": f"| example tool | B000 | src/app.py | {value} |",
    }[placement]
    # all five variables are set; the text holds the value of one of them
    res = post(tmp_path, hub, proposal(tmp_path, text), env=all_values())
    assert_nothing_posted(res, hub, 1, unseen=[value])


@pytest.mark.req("P-6a")
def test_p6a_a_value_that_spans_several_lines_counts_when_the_whole_of_it_is_held(tmp_path, hub):
    value = "first-line-SENTINEL-VALUE-1234\nsecond-line-SENTINEL-VALUE-1234\nthird-line-SENTINEL-VALUE-1234"
    text = f"Proposed entry: here is the key\n{value}\nand that was all."
    res = post(tmp_path, hub, proposal(tmp_path, text), env={"EXECUTOR_APP_PRIVATE_KEY": value})
    assert_nothing_posted(res, hub, 1, unseen=["first-line-SENTINEL-VALUE-1234", "third-line-SENTINEL-VALUE-1234"])


@pytest.mark.req("P-6a")
def test_p6a_control_all_five_variables_set_and_a_text_that_holds_none_of_them_is_posted(tmp_path, hub):
    assert_posted(post(tmp_path, hub, proposal(tmp_path), env=all_values()), hub)


@pytest.mark.req("P-6a")
def test_p6a_control_a_text_that_holds_only_the_beginning_of_a_value_is_posted(tmp_path, hub):
    text = "Proposed entry: the marker SENTINEL-VALUE-1234 alone is not a variable's value."
    assert_posted(post(tmp_path, hub, proposal(tmp_path, text), env=all_values()), hub, text)


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("name", [n for n in SECRET_VARIABLES if n != "GATE_TOKEN"])
def test_p6a_control_a_variable_that_is_empty_has_no_value_to_hold(tmp_path, hub, name):
    # the empty string is "contained" in every text; it is no secret (the contract does not say so in these words, see the report)
    assert_posted(post(tmp_path, hub, proposal(tmp_path), env={name: ""}), hub)


# ----------------------------------------------------------------------------- P-6a: what is shaped like a secret


def _repeat(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


def gh_token(prefix: str) -> str:
    return prefix + "_" + _repeat("Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2", 36)


def gh_fine_grained() -> str:
    return "github" + "_pat_" + _repeat("A1b2C3d4E5f6G7h8I9j0K1", 22) + "_" + _repeat("L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6a7B8c9D0e1F2g3H4i5J6k7", 59)


def anthropic_key(kind: str) -> str:
    return f"sk-ant-{kind}-" + _repeat("Zy9-Xw8_Vu7-Ts6_", 93) + "AA"


def pem(label: str) -> str:
    body = base64.b64encode(bytes((i * 7 + 3) % 256 for i in range(192))).decode()
    lines = textwrap.wrap(body, 64)
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def generated_pem(traditional: bool) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    fmt = serialization.PrivateFormat.TraditionalOpenSSL if traditional else serialization.PrivateFormat.PKCS8
    return key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption()).decode("ascii")


SHAPES = {
    "github-ghp": lambda: gh_token("ghp"),
    "github-gho": lambda: gh_token("gho"),
    "github-ghu": lambda: gh_token("ghu"),
    "github-ghs": lambda: gh_token("ghs"),
    "github-ghr": lambda: gh_token("ghr"),
    "github-fine-grained": gh_fine_grained,
    "anthropic-api-key": lambda: anthropic_key("api03"),
    "anthropic-oauth-token": lambda: anthropic_key("oat01"),
    "private-key-pkcs8": lambda: pem("PRIVATE KEY"),
    "private-key-rsa": lambda: pem("RSA PRIVATE KEY"),
    "private-key-ec": lambda: pem("EC PRIVATE KEY"),
    "private-key-openssh": lambda: pem("OPENSSH PRIVATE KEY"),
    "private-key-encrypted": lambda: pem("ENCRYPTED PRIVATE KEY"),
    "private-key-generated-pkcs8": lambda: generated_pem(False),
    "private-key-generated-traditional": lambda: generated_pem(True),
}

SETTINGS = {
    "in-a-sentence": "Proposed entry: the log showed {secret} and nothing else.",
    "in-a-code-span": "Proposed entry: `{secret}`",
    "in-a-table-cell": "| example tool | B000 | src/app.py | {secret} |",
    "alone": "{secret}",
}


def unseen_parts(secret: str) -> list[str]:
    """What must not be printed or posted: the secret, and, for a key, its longest body line."""
    lines = [ln for ln in secret.splitlines() if ln and not ln.startswith("-----")]
    return [secret.strip()] if not lines else [max(lines, key=len)]


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("shape", list(SHAPES))
def test_p6a_a_text_shaped_like_a_secret_exits_1_and_posts_nothing(tmp_path, hub, shape):
    secret = SHAPES[shape]()
    res = post(tmp_path, hub, proposal(tmp_path, SETTINGS["in-a-sentence"].format(secret=secret)))
    assert_nothing_posted(res, hub, 1, unseen=unseen_parts(secret))


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("setting", [s for s in SETTINGS if s != "in-a-sentence"])
@pytest.mark.parametrize("shape", ["github-ghp", "github-fine-grained", "anthropic-api-key", "private-key-pkcs8"])
def test_p6a_a_secret_shape_is_found_wherever_it_stands_in_the_text(tmp_path, hub, shape, setting):
    secret = SHAPES[shape]()
    res = post(tmp_path, hub, proposal(tmp_path, SETTINGS[setting].format(secret=secret)))
    assert_nothing_posted(res, hub, 1, unseen=unseen_parts(secret))


@pytest.mark.req("P-6a")
def test_p6a_a_secret_shape_in_a_later_line_of_a_long_text_is_found(tmp_path, hub):
    secret = gh_token("ghp")
    text = PLAIN + "\n" + "\n".join(f"Line {i} of an ordinary explanation." for i in range(200)) + f"\nLast line: {secret}\n"
    assert_nothing_posted(post(tmp_path, hub, proposal(tmp_path, text)), hub, 1, unseen=[secret])


@pytest.mark.req("P-6a")
@pytest.mark.parametrize("text", [
    "Proposed entry: a GitHub token and an Anthropic key and a private key are secrets, and none is quoted here.",
    "Proposed entry: commit 0123456789abcdef0123456789abcdef01234567 and digest "
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 are public values.",
    "Proposed entry: the prefix ghp is followed by an underscore in a real token, which this text does not hold.",
    "Proposed entry: BEGIN and END lines of a PEM block look like dashes and a label, and this text has none.",
    "Proposed entry: the key sk is short, ant is a word, and api03 is a version tag.",
], ids=["words-only", "hex-digests", "prefix-in-prose", "pem-in-prose", "anthropic-in-prose"])
def test_p6a_control_ordinary_text_that_only_talks_about_secrets_is_posted(tmp_path, hub, text):
    assert_posted(post(tmp_path, hub, proposal(tmp_path, text)), hub, text)


@pytest.mark.req("P-6a", "C-3")
@pytest.mark.parametrize("shape", ["github-ghp", "anthropic-api-key", "private-key-generated-pkcs8"])
def test_p6a_a_refusal_writes_no_file_with_the_secret_in_it(tmp_path, hub, shape):
    secret = SHAPES[shape]()
    work = tmp_path / "work"
    work.mkdir()
    res = post(work, hub, proposal(work, SETTINGS["in-a-sentence"].format(secret=secret)))
    assert_nothing_posted(res, hub, 1, unseen=unseen_parts(secret))
    for path in sorted(work.rglob("*")):
        if path.is_file() and path.name != "proposal.md":
            assert unseen_parts(secret)[0] not in path.read_bytes().decode("utf-8", "replace"), f"{path} holds the secret"
