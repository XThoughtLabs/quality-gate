"""The pure functions the contract names: branch_slug (LR-22), git_auth_env
(LR-16), claude_path (LR-27), build_prompt (LR-29), combine_decisions
(LR-47) and scrub (LR-50)."""

from __future__ import annotations

import base64
import random
import re

import pytest

import launcher_world as W


# ---------------------------------------------------------------- LR-22 branch_slug
def possible_slugs(title: str) -> set[str]:
    """LR-22 with amendment 1, A4, written out independently: only a slug
    longer than 40 is cut, at the last `-` among the 31st to the 40th
    characters (indexes 30 to 39) when there is one, otherwise at 40; then
    stripped of `-`."""
    full = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    if not full:
        return {"task"}
    if len(full) <= 40:
        return {full}
    cut = full[:40]
    dashes = [i for i in range(30, 40) if cut[i] == "-"]
    if not dashes:
        return {cut.strip("-") or "task"}
    return {cut[:max(dashes)].strip("-") or "task"}


@pytest.mark.parametrize("title, expected", [
    ("Add a thing!", "add-a-thing"),
    ("  Hello,   World!!  ", "hello-world"),
    ("ABC def", "abc-def"),
    ("Issue 42: fix v2", "issue-42-fix-v2"),
    ("snake_case.and/slash", "snake-case-and-slash"),
    ("--a--", "a"),
    ("", "task"),
    ("!!!", "task"),
    ("\u00c4\u00d6\u00dc", "task"),
    ("\u212aelvin", "kelvin"),  # KELVIN SIGN: lowercased first, it is ASCII k
    ("a" * 40, "a" * 40),
    ("a" * 41, "a" * 40),
    ("a" * 35 + " " + "b" * 10, "a" * 35),            # a dash at 35: cut there
    ("a" * 30 + " " + "b" * 20, "a" * 30),            # a dash at 30, the first of the last 10
    ("a" * 29 + " " + "b" * 20, "a" * 29 + "-" + "b" * 10),  # a dash at 29: outside, no cut at it
    ("a" * 35 + " bb", "a" * 35 + "-bb"),             # 38 characters: nothing to cut
    ("x" * 34 + " yyyyy", "x" * 34 + "-yyyyy"),       # exactly 40: nothing to cut
    ("!!!" + "a" * 50, "a" * 40),                     # stripped, then cut
    ("a" * 40 + " tail", "a" * 40),
    # A4: with several dashes in the window, the cut is at the last one.
    ("a" * 31 + " b " + "c" * 20, "a" * 31 + "-b"),
    ("a" * 30 + " bbb ccc " + "d" * 20, "a" * 30 + "-bbb-ccc"),
])
def test_lr22_branch_slug_examples(launcher, title, expected):
    assert launcher.branch_slug(title) == expected


def test_lr22_branch_slug_properties_on_many_titles(launcher):
    rng = random.Random(20261106)
    alphabet = "abcXYZ09 -_!./\u00e9\u212a\t"
    for _ in range(600):
        title = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 70)))
        got = launcher.branch_slug(title)
        assert got in possible_slugs(title), (title, got)
        assert len(got) <= 40
        assert got == "task" or re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", got), (title, got)


# ---------------------------------------------------------------- LR-16 git_auth_env
@pytest.mark.parametrize("repo_url", [
    "https://github.com/XThoughtLabs/gate-practice-app.git",
    r"C:\some\local\remote.git",
])
def test_lr16_git_auth_env_gives_exactly_the_documented_variables(launcher, repo_url):
    token = "ghs_" + "Q" * 36
    env = launcher.git_auth_env(token, repo_url)
    assert isinstance(env, dict)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
    count = int(env["GIT_CONFIG_COUNT"])
    assert count == 2
    expected_keys = {"GIT_CONFIG_COUNT"} | {f"GIT_CONFIG_{w}_{i}" for i in range(count)
                                            for w in ("KEY", "VALUE")}
    assert set(env) == expected_keys
    pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
    b64 = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    assert pairs == {f"http.{repo_url}.extraheader": f"AUTHORIZATION: basic {b64}",
                     "credential.helper": ""}


def test_lr16_git_auth_env_header_decodes_to_the_token(launcher):
    token = "v1." + "ab" * 20
    env = launcher.git_auth_env(token, "https://github.com/XThoughtLabs/gate-practice-app.git")
    values = [v for k, v in env.items() if k.startswith("GIT_CONFIG_VALUE_")]
    header = next(v for v in values if v.startswith("AUTHORIZATION: basic "))
    assert base64.b64decode(header.split("basic ", 1)[1]).decode() == f"x-access-token:{token}"


# ---------------------------------------------------------------- LR-27 claude_path
@pytest.mark.parametrize("path, expected", [
    (r"C:\Users\Public", "//c/Users/Public"),
    ("C:\\Users\\Public\\", "//c/Users/Public"),
    (r"D:\Some Folder\Inner", "//d/Some Folder/Inner"),
    (r"c:\x", "//c/x"),
    ("C:/Users/Public", "//c/Users/Public"),
    (r"C:\xtl-gate-executor", "//c/xtl-gate-executor"),
    ("C:\\", "//c"),
])
def test_lr27_claude_path(launcher, path, expected):
    assert launcher.claude_path(path) == expected


# ---------------------------------------------------------------- LR-29 build_prompt
TEMPLATE = "TEMPLATE-LINE-1\nTEMPLATE-LINE-2\n"


def positions(text: str, parts: list[str]) -> list[int]:
    found = []
    start = 0
    for part in parts:
        i = text.find(part, start)
        assert i >= 0, f"{part!r} is missing or out of order in:\n{text}"
        found.append(i)
        start = i + len(part)
    return found


def test_lr29_build_prompt_spec(launcher):
    branch = "spec/login-flow"
    text = W.norm_text(launcher.build_prompt("spec", TEMPLATE, branch))
    assert text.startswith(TEMPLATE.rstrip("\n"))
    positions(text, [TEMPLATE.rstrip("\n"), W.BRANCH_LINE.format(branch=branch)])
    assert "The task is issue" not in text
    assert "This is a fix round" not in text
    assert "Never edit security-review.md" not in text


def test_lr29_build_prompt_fix(launcher):
    branch = "ai/7-fix-the-thing"
    note = "NOTE-FROM-THE-GATE: tests fail\n\nNOTE-FROM-THE-REVIEW: check input"
    text = W.norm_text(launcher.build_prompt("fix", TEMPLATE, branch, pr=7, note=note))
    assert text.startswith(TEMPLATE.rstrip("\n"))
    positions(text, [TEMPLATE.rstrip("\n"), W.BRANCH_LINE.format(branch=branch),
                     W.FIX_LINE.format(n=7), note, W.PROPOSAL_LINE])
    assert "The task is issue" not in text


def test_lr29_build_prompt_task(launcher):
    # Amendment 1, A3: `issue` is a dict with number, title and body.
    branch = "ai/5-add-a-thing"
    issue = {"number": 5, "title": "ISSUE-TITLE-X", "body": "ISSUE-BODY-Y\nsecond line"}
    text = W.norm_text(launcher.build_prompt("task", TEMPLATE, branch, issue=issue))
    assert text.startswith(TEMPLATE.rstrip("\n"))
    positions(text, [TEMPLATE.rstrip("\n"), W.BRANCH_LINE.format(branch=branch),
                     W.TASK_LINE.format(n=5), "ISSUE-TITLE-X", "ISSUE-BODY-Y\nsecond line",
                     W.PROPOSAL_LINE])
    assert "This is a fix round" not in text


def test_lr29_issue_text_cannot_come_before_the_instructions(launcher):
    """The issue's text, even when it imitates the launcher's lines, comes after
    the task line: it never stands in front of the instructions."""
    branch = "ai/5-x"
    fake = W.PROPOSAL_LINE.replace("Never", "Always")
    issue = {"number": 5, "title": "T", "body": fake}
    text = W.norm_text(launcher.build_prompt("task", TEMPLATE, branch, issue=issue))
    task_at = text.index(W.TASK_LINE.format(n=5))
    assert text.index(fake) > task_at
    assert text.rindex(W.PROPOSAL_LINE) > text.index(fake)


# ---------------------------------------------------------------- LR-47 combine_decisions
def d(code, comment=""):
    return {"act": code is None, "post": True, "pr": 7, "head_sha": "a" * 40,
            "round": 1 if code is None else None, "reason_code": code, "comment": comment}


@pytest.mark.parametrize("judge, review, expected", [
    (d(None, "J"), None, (None, "J")),
    (d(None, "J"), d(None, "R"), (None, "J\n\nR")),
    (d("NOT_A_FAILURE", "j"), d(None, "R"), (None, "R")),
    (d(None, "J"), d("NOT_A_FAILURE", "r"), (None, "J")),
    (d("ROUND_CAP", "j"), d(None, "R"), ("ROUND_CAP", "")),
    (d(None, "J"), d("NO_MARKER", "r"), ("NO_MARKER", "")),
    (d("REPEATED_FIX", "j"), d("STATUS_NOT_FAILURE", "r"), ("REPEATED_FIX", "")),
    (d("NOT_A_FAILURE", "j"), d("UNEXPECTED_SENDER", "r"), ("UNEXPECTED_SENDER", "")),
    (d("REPORTS_UNTRUSTED", "j"), None, ("REPORTS_UNTRUSTED", "")),
])
def test_lr47_combine_decisions(launcher, judge, review, expected):
    assert tuple(launcher.combine_decisions(judge, review)) == expected


@pytest.mark.parametrize("judge, review", [
    (d("NOT_A_FAILURE", "j"), None),
    (d("NOT_A_FAILURE", "j"), d("NOT_A_FAILURE", "r")),
])
def test_lr47_nothing_to_fix_when_neither_acts(launcher, judge, review):
    code, _note = launcher.combine_decisions(judge, review)
    assert code == "NOTHING_TO_FIX"


# ---------------------------------------------------------------- LR-50 scrub
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"
       "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\n"
       "-----END RSA PRIVATE KEY-----")


@pytest.mark.parametrize("text, secrets, expected", [
    ("token abc123 and abc123 again", ["abc123"], "token [removed] and [removed] again"),
    ("nothing here", ["abc123"], "nothing here"),
    ("keep me", [""], "keep me"),
    ("a.b*c and axbbc", ["a.b*c"], "[removed] and axbbc"),
    ("one two", ["one", "two"], "[removed] [removed]"),
    ("before\n" + PEM + "\nafter", [], "before\n[removed]\nafter"),
    ("x ghp_" + "A1" * 10 + " y", [], "x [removed] y"),
    ("x ghs_" + "b" * 19 + " y", [], "x ghs_" + "b" * 19 + " y"),
    ("gho_" + "c" * 25 + "-tail", [], "[removed]-tail"),
    ("ghu_" + "d" * 20, [], "[removed]"),
    ("ghr_" + "e" * 20, [], "[removed]"),
    ("ghx_" + "f" * 30, [], "ghx_" + "f" * 30),
    ("github_pat_" + "G_h" * 7, [], "[removed]"),
    ("github_pat_" + "z" * 19, [], "github_pat_" + "z" * 19),
])
def test_lr50_scrub(launcher, text, secrets, expected):
    assert launcher.scrub(text, secrets) == expected


def test_lr50_scrub_removes_two_pem_blocks_and_keeps_the_rest(launcher):
    text = "a\n" + PEM + "\nb\n" + PEM.replace("RSA ", "") + "\nc"
    assert launcher.scrub(text, []) == "a\n[removed]\nb\n[removed]\nc"


def test_lr50_scrub_handles_secrets_and_patterns_together(launcher):
    secret = "plain-secret-value-0451"
    text = f"{secret} ghp_{'X' * 30} {secret}"
    out = launcher.scrub(text, [secret, ""])
    assert secret not in out and "ghp_" not in out
    assert out == "[removed] [removed] [removed]"
