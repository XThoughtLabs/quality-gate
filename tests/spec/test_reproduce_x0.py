"""gate.reproduce, X-0 (decision X, amended by HQ-ANSWERS-04): who wrote the `reports` branch.

gate.reproduce reads the stored evidence with git. On a GitHub remote, in any URL form, or with --api-repo, it first asks the
API who wrote the branch (W-12, W-14) and compares what the API shows with what git has read. A foreign commit, a failed read
or an API that does not show the branch git has read exits 1 with REPORTS_UNTRUSTED. On another remote it says that the
authors cannot be checked.

Nothing here touches the network: git rewrites each URL form below to a local bare repository (`url.<base>.insteadOf`, with
only the file protocol allowed), and the API is the in-memory stand-in on 127.0.0.1. CONTRACTS.md names no variable for the
API's address and token in section 8b, so those of section 9 are used (GITHUB_API_URL, GATE_TOKEN).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from gatekit import Repo, assert_no_traceback, assert_rc, base_env, git, make_bare, push_to, run_gate, write_json
from gitapi import FakeGitApi

CREDENTIAL = "SENTINEL-VALUE-1234"
SLUG = "example-org/example-app"
GITHUB_FORMS = {
    "https": "https://github.com/example-org/example-app",
    "https-dot-git": "https://github.com/example-org/example-app.git",
    "ssh-url": "ssh://git@github.com/example-org/example-app.git",
    "scp-like": "git@github.com:example-org/example-app.git",
    "scp-like-without-dot-git": "git@github.com:example-org/example-app",
    "https-user-and-password": f"https://x-access-token:{CREDENTIAL}@github.com/example-org/example-app.git",
    "https-token-as-user": f"https://{CREDENTIAL}@github.com/example-org/example-app",
    "https-capitals": "HTTPS://GITHUB.COM/example-org/example-app.git",
    "https-mixed-case-host": "https://GitHub.com/example-org/example-app",
    "ssh-url-capitals": "SSH://GIT@GITHUB.COM/example-org/example-app.git",
    "scp-like-capitals": "GIT@GITHUB.COM:example-org/example-app.git",
    "owner-and-name-in-capitals": "https://github.com/EXAMPLE-ORG/EXAMPLE-APP",
    "everything-in-capitals": "HTTPS://GITHUB.COM/EXAMPLE-ORG/EXAMPLE-APP",
}
OTHER_FORMS = {
    "local-path": None,    # the bare repository's own path
    "https-other-host": "https://example.com/example-org/example-app.git",
    "https-another-forge": "https://gitlab.com/example-org/example-app.git",
    "ssh-other-host": "ssh://git@example.com/example-org/example-app.git",
}


class Remote:
    """A bare repository that stands for the GitHub repository, a `reports` branch of two commits on it, and the API's view of it."""

    def __init__(self, tmp_path, stub, *, evidence_for_sha: bool):
        self.tmp, self.stub = Path(tmp_path), stub
        self.out = self.tmp / "rerun"
        work = Repo(self.tmp / "work")
        work.write("src/app.py", "x = 1\n")
        self.sha = work.commit("app")
        self.bare = make_bare(self.tmp / "gh" / "example-org" / "example-app.git")
        push_to(work, self.bare, "main")
        work.git("checkout", "-q", "--orphan", "reports")
        work.git("rm", "-rqf", ".")
        stored = self.sha if evidence_for_sha else "9" * 40
        for run_id in (1001, 1002):
            write_json(work.path / "reports" / "7" / f"{run_id}-1" / "context.json",
                       {"pr": 7, "run_id": run_id, "run_attempt": 1, "head_sha": stored, "trusted_sha": "8" * 40})
            work.commit(f"evidence {run_id}")
        push_to(work, self.bare, "reports")
        self.commits = [(line.split()[0], line.split()[1:])
                        for line in git(self.bare, "rev-list", "--reverse", "--parents", "reports").splitlines()]
        assert len(self.commits) == 2
        self.api = FakeGitApi(stub, ignore_case=True)
        self.show()

    def show(self, *, foreign=None):
        """What the API shows: the commits git holds, by the bot unless `foreign` says otherwise."""
        self.api.mirror(self.commits, foreign=foreign)

    def env(self, urls, extra=None):
        text = Path(base_env()["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
        for url in urls:
            text += f'[url "{self.bare.as_posix()}"]\n\tinsteadOf = {url}\n'
        for prefix in ("https://", "http://", "ssh://", "git://", "git@", "HTTPS://", "SSH://", "GIT@"):
            text += f'[url "file:///no-network-in-these-tests/"]\n\tinsteadOf = {prefix}\n'   # whatever is left goes nowhere
        # the same file as GIT_CONFIG_GLOBAL and as the child's ~/.gitconfig, so that a script that cleans its own environment
        # for git still finds it
        home = self.tmp / "home"
        home.mkdir(exist_ok=True)
        cfg = home / ".gitconfig"
        cfg.write_text(text, encoding="utf-8")
        return base_env({"HOME": home, "USERPROFILE": home, "GIT_CONFIG_GLOBAL": cfg, "GIT_ALLOW_PROTOCOL": "file",
                         "GITHUB_API_URL": self.stub.url, "GATE_TOKEN": self.api.token, **(extra or {})})

    def run(self, url=None, *, api_repo=None, extra_env=None):
        args = ["--repo", url or str(self.bare), "--sha", self.sha, "--out", self.out]
        if api_repo:
            args += ["--api-repo", api_repo]
        res = run_gate("reproduce", *args, env=self.env([url] if url else [], extra_env), cwd=self.tmp, timeout=120)
        assert "No module named" not in res.err, "precondition: gate.reproduce exists and runs with python -P -m"
        return res

    def text(self, res):
        """Everything it said: both streams, and whatever it wrote into --out."""
        parts = [res.both]
        if self.out.is_dir():
            parts += [p.read_bytes().decode("utf-8", "replace") for p in sorted(self.out.rglob("*")) if p.is_file()]
        elif self.out.is_file():
            parts.append(self.out.read_bytes().decode("utf-8", "replace"))
        return "\n".join(parts)

    def asked_who_wrote_it(self):
        return bool(self.stub.reqs("GET", r"/repos/(?i:example-org/example-app)/commits"))


def assert_untrusted(remote, res, *, unseen=()):
    assert_rc(res, 1)
    assert_no_traceback(res)
    said = remote.text(res)
    assert "REPORTS_UNTRUSTED" in said, f"exit 1 without the code REPORTS_UNTRUSTED\n{res.describe()}"
    for value in unseen:
        assert value not in said, "a credential of the URL was printed or written (C-3)"


def assert_not_untrusted(remote, res, *, unseen=()):
    """The check was made and found nothing: the run goes on to X-2, which finds no evidence for this SHA (exit 2)."""
    assert_rc(res, 2)
    assert_no_traceback(res)
    said = remote.text(res)
    assert "REPORTS_UNTRUSTED" not in said
    assert remote.asked_who_wrote_it(), "the API was never asked who wrote the branch, so the check was not made"
    for value in unseen:
        assert value not in said, "a credential of the URL was printed or written (C-3)"


def credentials_of(form: str):
    return [CREDENTIAL] if CREDENTIAL in GITHUB_FORMS[form] else []


# ----------------------------------------------------------------------------- every URL form of a GitHub remote


@pytest.mark.req("X-0")
@pytest.mark.parametrize("form", list(GITHUB_FORMS))
def test_x0_a_foreign_commit_exits_1_with_reports_untrusted_in_every_github_url_form(tmp_path, stub, form):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)   # the evidence for the very SHA is there, and must not be read
    remote.show(foreign={remote.commits[0][0]: ("some-person", True)})
    res = remote.run(GITHUB_FORMS[form])
    assert_untrusted(remote, res, unseen=credentials_of(form))


@pytest.mark.req("X-0")
@pytest.mark.parametrize("form", list(GITHUB_FORMS))
def test_x0_control_only_the_bots_commits_pass_the_check_in_every_github_url_form(tmp_path, stub, form):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    res = remote.run(GITHUB_FORMS[form])
    assert_not_untrusted(remote, res, unseen=credentials_of(form))


# ----------------------------------------------------------------------------- the three kinds of failure, by every way in


def scenario_foreign_author_newest(r):
    r.show(foreign={r.commits[1][0]: ("some-person", True)})


def scenario_bot_but_not_verified(r):
    r.show(foreign={r.commits[1][0]: ("github-actions[bot]", False)})


def scenario_unverified_oldest(r):
    r.show(foreign={r.commits[0][0]: ("github-actions[bot]", False)})


def scenario_another_app(r):
    r.show(foreign={r.commits[0][0]: ("example-executor[bot]", True)})


def scenario_read_fails_500(r):
    r.api.commits_status = 500


def scenario_read_fails_404(r):
    r.api.commits_status = 404


def scenario_token_refused(r):
    return {"GATE_TOKEN": "SENTINEL-VALUE-1234-WRONG"}


def scenario_api_has_no_such_branch(r):
    r.api.branches.clear()


def scenario_api_shows_another_history(r):
    r.api.branches.clear()
    r.api.commits.clear()
    r.api.seed({"reports/9/1-1/context.json": b"{}\n"})


def scenario_api_is_behind_git(r):
    r.api.branches.clear()
    r.api.mirror(r.commits[:1])


FAILURES = {
    "foreign-author-on-the-newest-commit": scenario_foreign_author_newest,
    "the-bot-but-not-verified": scenario_bot_but_not_verified,
    "not-verified-on-the-oldest-commit": scenario_unverified_oldest,
    "another-app-is-a-foreign-author": scenario_another_app,
    "the-read-of-the-commits-fails-500": scenario_read_fails_500,
    "the-read-of-the-commits-fails-404": scenario_read_fails_404,
    "the-token-is-refused": scenario_token_refused,
    "the-api-shows-no-such-branch": scenario_api_has_no_such_branch,
    "the-api-shows-another-history": scenario_api_shows_another_history,
    "the-api-is-behind-the-branch-git-has-read": scenario_api_is_behind_git,
}
WAYS_IN = ["https-url", "api-repo-with-a-local-remote", "api-repo-with-a-github-url"]


@pytest.mark.req("X-0")
@pytest.mark.parametrize("way", WAYS_IN)
@pytest.mark.parametrize("scenario", list(FAILURES))
def test_x0_a_foreign_commit_a_failed_read_or_an_api_that_does_not_show_the_branch_exits_1(tmp_path, stub, scenario, way):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)
    extra = FAILURES[scenario](remote)
    if way == "https-url":
        res = remote.run(GITHUB_FORMS["https"], extra_env=extra)
    elif way == "api-repo-with-a-local-remote":
        res = remote.run(None, api_repo=SLUG, extra_env=extra)
    else:
        res = remote.run(GITHUB_FORMS["https-dot-git"], api_repo=SLUG, extra_env=extra)
    assert_untrusted(remote, res)


# ----------------------------------------------------------------------------- --api-repo on its own


@pytest.mark.req("X-0")
def test_x0_with_api_repo_the_check_is_made_although_the_remote_is_a_local_path(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)
    remote.show(foreign={remote.commits[0][0]: ("some-person", True)})
    assert_untrusted(remote, remote.run(None, api_repo=SLUG))


@pytest.mark.req("X-0")
def test_x0_control_with_api_repo_and_only_the_bots_commits_the_run_goes_on(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    assert_not_untrusted(remote, remote.run(None, api_repo=SLUG))


# ----------------------------------------------------------------------------- another remote


@pytest.mark.req("X-0")
@pytest.mark.parametrize("form", list(OTHER_FORMS))
def test_x0_on_another_remote_the_authors_cannot_be_checked_and_it_says_so(tmp_path, stub, form):
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    remote.show(foreign={remote.commits[0][0]: ("some-person", True)})    # the API would object, if it were asked
    res = remote.run(OTHER_FORMS[form])
    assert_rc(res, 2)
    assert_no_traceback(res)
    said = remote.text(res)
    assert "REPORTS_UNTRUSTED" not in said, "another remote is not a GitHub remote: there is nothing to be untrusted by"
    assert "author" in said.lower(), f"it must say that the authors cannot be checked\n{res.describe()}"
    assert stub.reqs() == [], "no repository name is known on another remote, so the API is not asked"
