"""The archive's writes through the API, against an in-memory stand-in for GitHub's git data.

Whether GitHub really signs these commits is a fact of the real service, which the first
real run shows; here the check that reads the answer is proved.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

pytestmark = pytest.mark.req("W-4", "W-5", "W-11", "W-12", "W-13", "F-4")

BOT = "github-actions[bot]"
SECRET = "SENTINEL-VALUE-1234"
PREFIX = "/repos/example/app"


class FakeGit:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.trees: dict[str, dict[str, str]] = {}
        self.commits: dict[str, dict] = {}
        self.refs: dict[str, str] = {}
        self.counter = 0
        self.commit_bodies: list[dict] = []
        self.ref_moves: list[dict] = []
        self.authorization: set[str] = set()
        self.refuse_moves = 0
        self.corrupt_blobs = False
        self.commits_status = 200
        self.commit_details: dict[str, dict] = {}
        self.lock = threading.Lock()

    def new_sha(self, kind: str) -> str:
        self.counter += 1
        return hashlib.sha1(f"{kind}{self.counter}".encode()).hexdigest()

    def add_commit(self, files: dict[str, bytes], author: str, verified: bool, parent: str | None) -> str:
        """Put a commit on the branch as someone else would, without the gate."""
        tree = dict(self.trees[self.commits[parent]["tree"]]) if parent else {}
        for path, data in files.items():
            sha = self.new_sha("blob")
            self.blobs[sha] = data
            tree[path] = sha
        tree_sha = self.new_sha("tree")
        self.trees[tree_sha] = tree
        commit = self.new_sha("commit")
        self.commits[commit] = {"tree": tree_sha, "parents": [parent] if parent else [], "author": author, "verified": verified}
        self.refs["refs/heads/reports"] = commit
        return commit

    def history(self) -> list[str]:
        found = []
        current = self.refs.get("refs/heads/reports")
        while current:
            found.append(current)
            parents = self.commits[current]["parents"]
            current = parents[0] if parents else None
        return found


class Handler(BaseHTTPRequestHandler):
    fake: FakeGit

    def _reply(self, status: int, payload: object) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve(self) -> None:
        fake = self.fake
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        fake.authorization.add(self.headers.get("Authorization") or "")
        parsed = urlparse(self.path)
        route = parsed.path.removeprefix(PREFIX)
        query = parse_qs(parsed.query)
        with fake.lock:
            if self.command == "GET" and route == "/git/ref/heads/reports":
                head = fake.refs.get("refs/heads/reports")
                return self._reply(200, {"object": {"sha": head}}) if head else self._reply(404, {})
            if self.command == "GET" and route.startswith("/git/trees/"):
                commit = route.rsplit("/", 1)[1]
                tree = fake.trees[fake.commits[commit]["tree"]]
                return self._reply(
                    200,
                    {
                        "sha": fake.commits[commit]["tree"],
                        "truncated": False,
                        "tree": [{"path": p, "type": "blob", "sha": s} for p, s in tree.items()],
                    },
                )
            if self.command == "GET" and route.startswith("/git/blobs/"):
                data = fake.blobs[route.rsplit("/", 1)[1]]
                if fake.corrupt_blobs:
                    data = data + b"x"
                return self._reply(200, {"content": base64.b64encode(data).decode(), "encoding": "base64"})
            if self.command == "GET" and route.startswith("/commits/"):
                sha = route.rsplit("/", 1)[1]
                page = int(query.get("page", ["1"])[0])
                detail = fake.commit_details.get(sha, {"parents": fake.commits[sha]["parents"], "files": []})
                files = detail["files"][(page - 1) * 100 : page * 100]
                return self._reply(200, {"parents": detail["parents"], "files": files})
            if self.command == "GET" and route == "/commits":
                if fake.commits_status != 200:
                    return self._reply(fake.commits_status, {})
                assert query["sha"] == ["reports"]
                page = int(query.get("page", ["1"])[0])
                shas = fake.history()[(page - 1) * 100 : page * 100]
                return self._reply(
                    200,
                    [
                        {
                            "sha": sha,
                            "author": {"login": fake.commits[sha]["author"]},
                            "commit": {"verification": {"verified": fake.commits[sha]["verified"]}},
                        }
                        for sha in shas
                    ],
                )
            if self.command == "POST" and route == "/git/blobs":
                sha = fake.new_sha("blob")
                fake.blobs[sha] = base64.b64decode(body["content"])
                return self._reply(201, {"sha": sha})
            if self.command == "POST" and route == "/git/trees":
                # base_tree names a tree: a commit's SHA here is a fault of the code.
                tree = dict(fake.trees[body["base_tree"]]) if body.get("base_tree") else {}
                for entry in body["tree"]:
                    tree[entry["path"]] = entry["sha"]
                sha = fake.new_sha("tree")
                fake.trees[sha] = tree
                return self._reply(201, {"sha": sha})
            if self.command == "POST" and route == "/git/commits":
                fake.commit_bodies.append(body)
                signed = not any(key in body for key in ("author", "committer", "signature"))
                sha = fake.new_sha("commit")
                fake.commits[sha] = {"tree": body["tree"], "parents": body["parents"], "author": BOT, "verified": signed}
                return self._reply(201, {"sha": sha})
            if self.command == "POST" and route == "/git/refs":
                fake.ref_moves.append(body)
                if body["ref"] in fake.refs:
                    return self._reply(422, {})
                fake.refs[body["ref"]] = body["sha"]
                return self._reply(201, {})
            if self.command == "PATCH" and route == "/git/refs/heads/reports":
                fake.ref_moves.append(body)
                if fake.refuse_moves > 0:
                    fake.refuse_moves -= 1
                    return self._reply(422, {"message": "Update is not a fast forward"})
                if fake.refs["refs/heads/reports"] not in fake.commits[body["sha"]]["parents"]:
                    return self._reply(422, {"message": "Update is not a fast forward"})
                fake.refs["refs/heads/reports"] = body["sha"]
                return self._reply(200, {})
        return self._reply(500, {"message": f"no route: {self.command} {route}"})

    do_GET = _serve
    do_POST = _serve
    do_PATCH = _serve

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def github():
    fake = FakeGit()
    handler = type("BoundHandler", (Handler,), {"fake": fake})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    fake.url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield fake
    server.shutdown()
    server.server_close()


@pytest.fixture
def inputs(tmp_path: Path) -> dict[str, Path]:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "exit-codes.tsv").write_bytes(b"check\tindex\n")
    (artifact / "binary.bin").write_bytes(bytes(range(256)))
    (artifact / "guard.json").write_text('{"repeated_fix": false}', encoding="utf-8")
    publish = tmp_path / "publish"
    publish.mkdir()
    (publish / "report.json").write_text("{}", encoding="utf-8")
    context = tmp_path / "context.json"
    context.write_text('{"pr": 7}', encoding="utf-8")
    return {"artifact": artifact, "publish": publish, "context": context, "out": tmp_path / "result.json"}


def store(gate, github, inputs, run_id: str = "11", attempt: str = "1"):
    env = gate.env(GITHUB_API_URL=github.url, GATE_TOKEN=SECRET)
    process = gate.run(
        "archive", "store", "--api-repo", "example/app", "--branch", "reports", "--pr", 7, "--run-id", run_id, "--attempt", attempt,
        "--artifact", inputs["artifact"], "--publish", inputs["publish"], "--context", inputs["context"], "--out", inputs["out"], env=env,
    )
    return process, json.loads(inputs["out"].read_text(encoding="utf-8"))


def test_a_store_creates_the_branch_and_keeps_the_bytes(gate, github, inputs):
    process, result = store(gate, github, inputs)
    assert process.returncode == 0, process.stderr
    assert result["stored"] is True
    assert result["sha256sums_match"] is True
    assert result["actors_ok"] is True
    head = github.refs["refs/heads/reports"]
    tree = github.trees[github.commits[head]["tree"]]
    assert github.blobs[tree["reports/7/11-1/artifact/binary.bin"]] == bytes(range(256))
    assert "reports/7/11-1/guard.json" in tree
    assert github.commits[head]["parents"] == []


def test_commits_carry_no_author_committer_or_signature(gate, github, inputs):
    """GitHub signs a commit only without them: this is what makes it verified."""
    store(gate, github, inputs)
    assert github.commit_bodies
    for body in github.commit_bodies:
        assert set(body) == {"message", "tree", "parents"}


def test_a_later_store_builds_on_the_branch_without_force(gate, github, inputs):
    store(gate, github, inputs)
    first = github.refs["refs/heads/reports"]
    process, result = store(gate, github, inputs, run_id="12")
    assert process.returncode == 0, process.stderr
    head = github.refs["refs/heads/reports"]
    assert github.commits[head]["parents"] == [first]
    tree = github.trees[github.commits[head]["tree"]]
    assert "reports/7/11-1/context.json" in tree
    assert "reports/7/12-1/context.json" in tree
    assert all(move.get("force") in (None, False) for move in github.ref_moves)
    assert result["stored"] is True


def test_the_token_goes_in_the_header_and_is_never_printed(gate, github, inputs):
    process, _ = store(gate, github, inputs)
    assert f"Bearer {SECRET}" in github.authorization
    assert SECRET not in process.stdout + process.stderr
    assert SECRET not in inputs["out"].read_text(encoding="utf-8")


def test_a_moved_branch_is_read_again_and_retried(gate, github, inputs):
    store(gate, github, inputs)
    github.refuse_moves = 3
    process, result = store(gate, github, inputs, run_id="12")
    assert process.returncode == 0, process.stderr
    assert result["stored"] is True
    assert github.refuse_moves == 0


def test_a_branch_that_keeps_moving_ends_not_stored(gate, github, inputs):
    store(gate, github, inputs)
    github.refuse_moves = 100
    process, result = store(gate, github, inputs, run_id="12")
    assert process.returncode == 1
    assert result["stored"] is False
    assert result["reason"] == "PUSH_REFUSED"


def test_an_existing_attempt_is_never_changed(gate, github, inputs):
    store(gate, github, inputs)
    head = github.refs["refs/heads/reports"]
    process, result = store(gate, github, inputs)
    assert process.returncode == 1
    assert result["reason"] == "ALREADY_EXISTS"
    assert github.refs["refs/heads/reports"] == head


def test_a_read_back_that_differs_is_not_a_match(gate, github, inputs):
    github.corrupt_blobs = True
    process, result = store(gate, github, inputs)
    assert process.returncode == 1
    assert result["stored"] is True
    assert result["sha256sums_match"] is False


@pytest.mark.parametrize(
    ("author", "verified"),
    [("xtl-example-executor[bot]", True), (BOT, False), ("someone", False)],
    ids=["another-app-signed", "the-bot-unsigned", "a-person-unsigned"],
)
def test_a_commit_by_another_actor_fails_the_archive(gate, github, inputs, author, verified):
    """The executor's app has Contents write, and the ruleset blocks only force and deletion."""
    store(gate, github, inputs)
    foreign = github.add_commit({"reports/7/99-1/report.json": b'{"forged": true}'}, author, verified, github.refs["refs/heads/reports"])
    process, result = store(gate, github, inputs, run_id="12")
    assert process.returncode == 1
    assert result["actors_ok"] is False
    assert result["reason"] == "reports written by another actor"
    assert result["foreign_commits"] == [foreign]
    # The evidence is still stored: only its trust is refused.
    assert result["stored"] is True
    assert "reports written by another actor" in process.stderr


def test_authors_that_cannot_be_checked_are_not_trusted(gate, github, inputs):
    github.commits_status = 500
    process, result = store(gate, github, inputs)
    assert process.returncode == 1
    assert result["actors_ok"] is False


def test_an_archive_with_another_actor_is_never_ready(gate, tmp_path):
    verdict = tmp_path / "verdict.json"
    verdict.write_text(json.dumps({"verdict": "ready-for-human", "reasons": [], "checks": {}}), encoding="utf-8")
    archive = tmp_path / "archive.json"
    archive.write_text(json.dumps({"stored": True, "sha256sums_match": True, "actors_ok": False, "reason": "reports written by another actor"}), encoding="utf-8")
    out = tmp_path / "final.json"
    assert gate.run("report", "final", "--verdict", verdict, "--archive", archive, "--out", out).returncode == 0
    final = json.loads(out.read_text(encoding="utf-8"))
    assert final["verdict"] == "blocked"
    assert final["conclusions"] == {"gate/archive": "failure", "gate/final": "failure"}
    assert any(item["code"] == "REPORTS_WRITTEN_BY_ANOTHER_ACTOR" for item in final["reasons"])


def test_append_adds_one_file_and_refuses_a_second(gate, github, inputs, tmp_path):
    store(gate, github, inputs)
    final = tmp_path / "final.json"
    final.write_text('{"verdict": "blocked"}', encoding="utf-8")
    env = gate.env(GITHUB_API_URL=github.url, GATE_TOKEN=SECRET)
    arguments = ("archive", "append", "--api-repo", "example/app", "--branch", "reports", "--path", "reports/7/11-1/final.json", "--file", final, "--out", inputs["out"])
    assert gate.run(*arguments, env=env).returncode == 0
    head = github.refs["refs/heads/reports"]
    tree = github.trees[github.commits[head]["tree"]]
    assert github.blobs[tree["reports/7/11-1/final.json"]] == final.read_bytes()
    assert gate.run(*arguments, env=env).returncode == 1
    assert json.loads(inputs["out"].read_text(encoding="utf-8"))["reason"] == "ALREADY_EXISTS"
    assert github.refs["refs/heads/reports"] == head


def test_append_also_checks_the_actors(gate, github, inputs, tmp_path):
    store(gate, github, inputs)
    github.add_commit({"reports/7/99-1/x": b"forged"}, "someone-else[bot]", True, github.refs["refs/heads/reports"])
    final = tmp_path / "final.json"
    final.write_text("{}", encoding="utf-8")
    env = gate.env(GITHUB_API_URL=github.url, GATE_TOKEN=SECRET)
    process = gate.run("archive", "append", "--api-repo", "example/app", "--branch", "reports", "--path", "reports/7/11-1/final.json", "--file", final, "--out", inputs["out"], env=env)
    assert process.returncode == 1
    assert json.loads(inputs["out"].read_text(encoding="utf-8"))["reason"] == "reports written by another actor"


def test_more_commits_than_the_pages_can_hold_are_not_trusted(gate, github, inputs, monkeypatch):
    """An unending list of commits is never read as an all-clear."""
    store(gate, github, inputs)
    import sys as system

    system.path.insert(0, str(gate.root))
    try:
        from gate import archive as archive_module
    finally:
        system.path.remove(str(gate.root))
    remote = archive_module.ApiRemote("example/app", "reports", base=github.url, token=SECRET)
    full_page = [{"sha": "a" * 40, "author": {"login": BOT}, "commit": {"verification": {"verified": True}}}] * 100
    real_call = remote._call
    monkeypatch.setattr(remote, "_call", lambda method, route, body=None: full_page if route.startswith("/commits?") else real_call(method, route, body))
    status = archive_module.actors_status(remote, {})
    assert status["actors_ok"] is False
    assert status["reason"] == "the authors of reports could not be checked"


def accepted_config(tmp_path: Path, sha: str) -> Path:
    config = tmp_path / "quality.toml"
    config.write_text(f'[[archive.accepted_foreign_commits]]\nsha = "{sha}"\nreason = "a stray commit"\ndate = "2026-11-03"\n', encoding="utf-8")
    return config


def test_append_reads_the_recovery_list_too(gate, github, inputs, tmp_path):
    store(gate, github, inputs)
    head = github.refs["refs/heads/reports"]
    foreign = github.add_commit({"reports/7/99-1/x": b"stray"}, "someone-else[bot]", True, head)
    github.commit_details[foreign] = {"parents": [head], "files": [{"filename": "reports/7/99-1/x", "status": "added"}]}
    final = tmp_path / "final.json"
    final.write_text("{}", encoding="utf-8")
    env = gate.env(GITHUB_API_URL=github.url, GATE_TOKEN=SECRET)
    process = gate.run(
        "archive", "append", "--api-repo", "example/app", "--branch", "reports", "--path", "reports/7/11-1/final.json",
        "--file", final, "--config", accepted_config(tmp_path, foreign), "--out", inputs["out"], env=env,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(inputs["out"].read_text(encoding="utf-8"))["accepted_commits"] == [foreign]


def test_a_listed_commit_is_read_to_its_last_page_of_files(gate, github, inputs, tmp_path):
    """A hundred added files must not hide a changed record on the next page."""
    store(gate, github, inputs)
    head = github.refs["refs/heads/reports"]
    foreign = github.add_commit({"reports/7/99-1/x": b"stray"}, "someone-else[bot]", True, head)
    added = [{"filename": f"reports/7/99-1/{index}", "status": "added"} for index in range(100)]
    github.commit_details[foreign] = {"parents": [head], "files": [*added, {"filename": "reports/7/11-1/report.json", "status": "modified"}]}
    env = gate.env(GITHUB_API_URL=github.url, GATE_TOKEN=SECRET)
    out = tmp_path / "actors.json"
    process = gate.run("archive", "check-actors", "--api-repo", "example/app", "--branch", "reports", "--config", accepted_config(tmp_path, foreign), "--out", out, env=env)
    assert process.returncode == 1
    assert json.loads(out.read_text(encoding="utf-8"))["foreign_commits"] == [foreign]


def test_a_git_remote_on_github_is_refused(gate, inputs):
    """A git push would leave commits unsigned, so GitHub is written only through the API."""
    process = gate.run(
        "archive", "store", "--remote", "https://github.com/example/app.git", "--branch", "reports", "--pr", 7, "--run-id", 1, "--attempt", 1,
        "--artifact", inputs["artifact"], "--publish", inputs["publish"], "--context", inputs["context"], "--out", inputs["out"],
    )
    assert process.returncode == 2
    assert not inputs["out"].exists()
