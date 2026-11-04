"""What review round 3 found: a token posted, tests taken away, ordinary changes refused."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.req("P-6a", "G-1b", "G-11a", "X-0")

FAKE_TOKEN = "FAKE-VALUE-NOT-A-REAL-TOKEN-1234"


def post(gate, stub, cwd: Path, name: str = "proposal.md", **extra: str):
    stub.routes[("GET", "/repos/example/app/pulls?state=open&head=example%3Aai%2F1-x")] = (200, [{"number": 7}])
    stub.routes[("POST", "/repos/example/app/issues/7/comments")] = (201, {})
    env = gate.env(GITHUB_API_URL=stub.url, GITHUB_REPOSITORY="example/app", GATE_TOKEN=FAKE_TOKEN, **extra)
    return gate.run("publish", "post-proposal", "--file", cwd / name, "--branch", "ai/1-x", env=env)


def posted(stub) -> list[str]:
    return [request["body"]["body"] for request in stub.requests if request["method"] == "POST"]


def test_a_plain_file_is_posted(gate, stub, tmp_path):
    (tmp_path / "proposal.md").write_text("| bandit | B101 | a.py | why |\n", encoding="utf-8")
    assert post(gate, stub, tmp_path).returncode == 0
    assert "B101" in posted(stub)[0]


def test_a_symbolic_link_is_never_followed(gate, stub, tmp_path):
    """The token's way out: the model links the file to the job's own environment."""
    target = tmp_path / "secret.txt"
    target.write_text(f"GATE_TOKEN={FAKE_TOKEN}\n", encoding="utf-8")
    link = tmp_path / "proposal.md"
    try:
        os.symlink(target, link)
    except OSError as error:
        pytest.skip(f"this machine cannot make a symbolic link: {error}; the next test covers it in this process")
    process = post(gate, stub, tmp_path)
    assert process.returncode == 2
    assert not posted(stub)
    assert FAKE_TOKEN not in process.stdout + process.stderr


def test_a_link_is_refused_without_reading_it(gate, tmp_path, monkeypatch):
    """Checked in this process, because this machine may not be allowed to make a link."""
    sys.path.insert(0, str(gate.root))
    try:
        from gate import common, publish
    finally:
        sys.path.remove(str(gate.root))
    path = tmp_path / "proposal.md"
    path.write_text("x", encoding="utf-8")
    real = os.lstat(path)
    fake = os.stat_result((stat.S_IFLNK | 0o777, *tuple(real)[1:]))
    monkeypatch.setattr(publish.os, "lstat", lambda _path: fake)
    with pytest.raises(common.UsageError):
        publish.read_proposal(str(path))


def test_a_second_name_for_a_file_is_refused(gate, stub, tmp_path):
    """A hard link could be the git config, which holds a token in its remote's URL."""
    config = tmp_path / "git-config"
    config.write_text(f"url = https://x:{FAKE_TOKEN}@example.invalid\n", encoding="utf-8")
    os.link(config, tmp_path / "proposal.md")
    process = post(gate, stub, tmp_path)
    assert process.returncode == 2
    assert not posted(stub)


@pytest.mark.skipif(not Path("/proc/self/environ").exists(), reason="this machine has no /proc, so the original attack cannot be shown here")
def test_the_original_attack_posts_nothing(gate, stub, tmp_path):
    os.symlink("/proc/self/environ", tmp_path / "proposal.md")
    assert post(gate, stub, tmp_path).returncode == 2
    assert not posted(stub)


def test_a_text_holding_the_tokens_value_is_not_posted(gate, stub, tmp_path):
    (tmp_path / "proposal.md").write_text(f"a row, then {FAKE_TOKEN}\n", encoding="utf-8")
    process = post(gate, stub, tmp_path)
    assert process.returncode == 1
    assert not posted(stub)
    assert FAKE_TOKEN not in process.stdout + process.stderr


@pytest.mark.parametrize(
    "text",
    [
        "ghs_" + "a" * 36,
        "ghp_" + "b" * 36,
        "github_pat_" + "c" * 40,
        "sk-ant-" + "d" * 30,
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
    ids=["app-token", "personal-token", "fine-grained", "anthropic", "private-key"],
)
def test_a_text_shaped_like_a_secret_is_not_posted(gate, stub, tmp_path, text):
    (tmp_path / "proposal.md").write_text(text, encoding="utf-8")
    assert post(gate, stub, tmp_path).returncode == 1
    assert not posted(stub)


def test_the_value_of_another_secret_in_the_job_is_not_posted(gate, stub, tmp_path):
    other = "ANOTHER-FAKE-VALUE-5678"
    (tmp_path / "proposal.md").write_text(other, encoding="utf-8")
    assert post(gate, stub, tmp_path, GH_TOKEN=other).returncode == 1
    assert not posted(stub)


# M1: what pytest reads is refused, and what it does not read stays an ordinary change.

PYPROJECT = '[project]\nname = "x"\n\n[tool.ruff]\nline-length = 100\n\n[tool.pytest.ini_options]\naddopts = "-q"\n'


def guard_on(gate, tmp_path: Path, base_files: dict[str, str], head_files: dict[str, str], branch: str = "ai/1-x", author: str = "example-executor[bot]", deleted: tuple[str, ...] = ()):
    repo = tmp_path / "repo"
    repo.mkdir()
    gate.git(repo, "init", "--quiet", "--initial-branch=line")

    def write(files: dict[str, str]) -> None:
        for name, text in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    write({"README.txt": "x\n", **base_files})
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "base")
    base = gate.git(repo, "rev-parse", "HEAD")
    gate.git(repo, "checkout", "--quiet", "-b", branch)
    write(head_files)
    for name in deleted:
        (repo / name).unlink()
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "the change")
    config = tmp_path / "quality.toml"
    config.write_text('[feedback]\nexecutor_app = "example-executor"\n', encoding="utf-8")
    out = tmp_path / "guard.json"
    process = gate.run("guard", "--repo", repo, "--base", base, "--head", "HEAD", "--branch", branch, "--author", author, "--config", config, "--out", out)
    return process, json.loads(out.read_text(encoding="utf-8")) if out.exists() else None


@pytest.mark.parametrize(
    ("name", "before", "after"),
    [
        ("pyproject.toml", PYPROJECT, PYPROJECT.replace("line-length = 100", "line-length = 120")),
        ("pyproject.toml", PYPROJECT, PYPROJECT + '\n[tool.poetry.dependencies]\nrequests = "*"\n'),
        ("setup.cfg", "[flake8]\nmax-line-length = 100\n", "[flake8]\nmax-line-length = 120\n"),
        ("tox.ini", "[mypy]\nstrict = true\n", "[mypy]\nstrict = false\n"),
        ("pyproject.toml", PYPROJECT, PYPROJECT.replace('name = "x"', 'name = "y"')),
    ],
    ids=["ruff", "poetry", "flake8", "mypy", "project"],
)
def test_another_tools_section_in_the_root_is_marked_not_refused(gate, tmp_path, name, before, after):
    process, guard = guard_on(gate, tmp_path, {name: before}, {name: after})
    assert process.returncode == 0, guard["violations"]
    assert guard["needs_code_owner"] == [name]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("packages/p/pyproject.toml", '[tool.setuptools]\npackages = ["p"]\n'),
        ("tests/fixtures/x/pyproject.toml", "[tool.black]\nline-length = 90\n"),
        ("tests/fixtures/x/setup.cfg", "[metadata]\nname = x\n"),
        ("sub/tox.ini", "[flake8]\nmax-line-length = 90\n"),
        ("tests/fixtures/x/broken/pyproject.toml", "not = valid = toml\n"),
    ],
    ids=["a-package", "a-fixture-toml", "a-fixture-cfg", "a-sub-tox", "a-broken-fixture"],
)
def test_an_ordinary_file_in_a_subfolder_is_not_refused(gate, tmp_path, name, text):
    process, guard = guard_on(gate, tmp_path, {}, {name: text})
    assert process.returncode == 0, guard["violations"]
    assert not guard["needs_code_owner"]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pyproject.toml", '[tool.coverage.run]\nomit = ["src/*"]\n'),
        ("pyproject.toml", "[tool.bandit]\nskips = []\n"),
        ("setup.cfg", "[coverage:run]\nomit = src/*\n"),
        ("tox.ini", "[testenv]\ncommands = true\n"),
        ("sub/pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n'),
        ("sub/tox.ini", "[pytest]\naddopts = -q\n"),
        ("sub/setup.cfg", "[tool:pytest]\naddopts = -q\n"),
        ("setup.cfg", "[options.entry_points]\npytest11 =\n    cheat = cheat\n"),
    ],
    ids=["root-coverage", "root-bandit", "root-coverage-cfg", "root-testenv", "sub-pytest-toml", "sub-pytest-tox", "sub-pytest-cfg", "cfg-entry-point"],
)
def test_what_controls_tests_and_security_tools_is_still_refused(gate, tmp_path, name, text):
    process, guard = guard_on(gate, tmp_path, {}, {name: text})
    assert process.returncode == 1
    assert ("PROTECTED_PATH", name) in {(item["rule"], item["path"]) for item in guard["violations"]}


@pytest.mark.parametrize("text", ['project = "x"\n', "tool = 1\n", "[project]\nentry-points = 1\n"], ids=["project", "tool", "entry-points"])
def test_an_odd_pyproject_gives_no_traceback(gate, tmp_path, text):
    process, guard = guard_on(gate, tmp_path, {}, {"sub/pyproject.toml": text})
    assert "Traceback" not in process.stderr
    assert guard is not None


# H3: a spec PR adds tests, and cannot take one away unseen.


def spec_guard(gate, tmp_path, head_files=None, deleted=()):
    base = {"acceptance/test_a.py": "def test_keep():\n    assert work() == 1\n", "acceptance/test_b.py": "def test_gone():\n    assert 1 == 1\n\n\ndef test_also():\n    assert 2 == 2\n"}
    return guard_on(gate, tmp_path, base, head_files or {}, branch="spec/more", deleted=deleted)


def test_a_spec_pr_cannot_delete_an_acceptance_test_file(gate, tmp_path):
    process, guard = spec_guard(gate, tmp_path, deleted=("acceptance/test_b.py",))
    assert guard["kind"] == "spec"
    assert process.returncode == 1
    assert ("TEST_DELETED", "acceptance/test_b.py") in {(item["rule"], item["path"]) for item in guard["violations"]}


def test_a_spec_pr_cannot_delete_a_test_from_a_file(gate, tmp_path):
    process, guard = spec_guard(gate, tmp_path, {"acceptance/test_b.py": "def test_also():\n    assert 2 == 2\n"})
    assert process.returncode == 1
    assert any(item["rule"] == "TEST_DELETED" for item in guard["violations"])


def test_a_spec_pr_cannot_weaken_an_acceptance_test(gate, tmp_path):
    process, guard = spec_guard(gate, tmp_path, {"acceptance/test_a.py": "def test_keep():\n    assert True\n"})
    assert process.returncode == 1
    assert any(item["rule"] == "TEST_WEAKENED" for item in guard["violations"])


def test_a_spec_pr_can_add_tests(gate, tmp_path):
    process, guard = spec_guard(gate, tmp_path, {"acceptance/test_c.py": "def test_new():\n    assert 1 == 1\n"})
    assert process.returncode == 0, guard["violations"]


# M2: reproduce tells a GitHub remote by its host.


def load_reproduce(gate):
    sys.path.insert(0, str(gate.root))
    try:
        from gate import reproduce
    finally:
        sys.path.remove(str(gate.root))
    return reproduce


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/o/n",
        "https://github.com/o/n.git",
        "https://github.com/o/n/",
        "HTTPS://GitHub.com/o/n",
        "https://x-access-token:SECRET@github.com/o/n.git",
        "ssh://git@github.com/o/n.git",
        "git@github.com:o/n.git",
        "git@GitHub.com:o/n",
        "http://www.github.com/o/n",
    ],
)
def test_each_form_of_a_github_url_is_known(gate, url):
    assert load_reproduce(gate).github_repository(url) == "o/n"


@pytest.mark.parametrize(
    "url",
    ["evil.example:x@github.com:o/n", "https://example.com/github.com/o/n", "https://github.com.example.com/o/n", "git@example.com:o/n.git", "/srv/git/o/n.git", "file:///srv/github.com/o/n", r"C:\repos\github.com\o\n"],
)
def test_another_remote_is_not_taken_for_github(gate, url):
    assert load_reproduce(gate).github_repository(url) is None


def test_a_github_url_with_no_repository_is_refused(gate):
    module = load_reproduce(gate)
    sys.path.insert(0, str(gate.root))
    try:
        from gate.common import UsageError
    finally:
        sys.path.remove(str(gate.root))
    with pytest.raises(UsageError):
        module.github_repository("https://github.com/only-one-part")


def test_a_404_for_a_branch_git_has_read_is_no_all_clear(gate, stub):
    """A private repository with no token, or a wrong name, must not read as trusted."""
    sys.path.insert(0, str(gate.root))
    try:
        from gate.archive import ApiRemote, actors_status
    finally:
        sys.path.remove(str(gate.root))
    stub.routes[("GET", "/repos/example/app/git/ref/heads/reports")] = (404, {})
    assert actors_status(ApiRemote("example/app", "reports", base=stub.url, token=""), {})["actors_ok"] is True, "a first run has no branch yet"
    module = load_reproduce(gate)
    with pytest.raises(module.Untrusted):
        env = os.environ.copy()
        os.environ["GITHUB_API_URL"] = stub.url
        try:
            module.check_stored_evidence("example/app", gate.root / "docs" / "quality.example.toml", "a" * 40)
        finally:
            os.environ.clear()
            os.environ.update(env)


def test_a_relative_path_to_the_remote_still_works(gate, tmp_path):
    """The later fetches run in the clone, where the same relative path means another folder."""
    remote = tmp_path / "remote"
    remote.mkdir()
    gate.git(remote, "init", "--quiet", "--initial-branch=main")
    (remote / "a.txt").write_text("x\n", encoding="utf-8")
    gate.git(remote, "add", "-A")
    gate.git(remote, "commit", "--quiet", "-m", "base")
    gate.git(remote, "branch", "reports")
    process = gate.run("reproduce", "--repo", "remote", "--sha", "1" * 40, "--out", tmp_path / "out", cwd=tmp_path)
    assert process.returncode == 2
    assert "no stored evidence" in process.stderr


def test_a_tip_the_api_does_not_list_is_untrusted(gate, stub, tmp_path, monkeypatch):
    module = load_reproduce(gate)
    monkeypatch.setenv("GITHUB_API_URL", stub.url)
    monkeypatch.setenv("GATE_TOKEN", "")
    good = {"sha": "a" * 40, "author": {"login": "github-actions[bot]"}, "commit": {"verification": {"verified": True}}}
    stub.routes[("GET", "/repos/o/n/git/ref/heads/reports")] = (200, {"object": {"sha": "a" * 40}})
    stub.routes[("GET", "/repos/o/n/commits?sha=reports&per_page=100")] = (200, [good])
    config = tmp_path / "quality.toml"
    config.write_text("", encoding="utf-8")
    module.check_stored_evidence("o/n", config, "a" * 40)
    with pytest.raises(module.Untrusted):
        module.check_stored_evidence("o/n", config, "b" * 40)
