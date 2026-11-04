"""Store one attempt's evidence on the append-only reports branch.

Evidence is never rewritten: no force push, and an attempt's folder is written once.

On GitHub the branch is written through the API, with no custom author, so that GitHub
signs each commit. A `git push` would leave it unsigned. The executor's app can also
append to the branch, because the ruleset blocks only force pushes and deletion, so every
store checks that each commit on the branch was written and signed for github-actions[bot].
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from gate.common import EXIT_OK, EXIT_RULE_FAILED, EXIT_USAGE, UsageError, load_config, sha256_bytes, write_json

MAX_PUSH_TRIES = 6  # the first try and 5 retries
DEFAULT_MAX_BYTES = 200_000_000
TOP_LEVEL_FROM_ARTIFACT = ("guard.json", "acceptance.json")
UNSAFE_NAMES = {".git"}
# Above any .gitattributes in the tree: stored bytes are never converted.
_RAW_ATTRIBUTES = b"* -text -filter -ident\n"
SUMS = "SHA256SUMS"
EXPECTED_AUTHOR = "github-actions[bot]"
ANOTHER_ACTOR = "reports written by another actor"
UNCHECKED_ACTORS = "the authors of reports could not be checked"
COMMIT_PAGES = 100
FILE_PAGES = 30
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENTITY = (
    "-c",
    "user.name=gate-archive",
    "-c",
    "user.email=gate-archive@example.invalid",
    "-c",
    "core.autocrlf=false",
    "-c",
    "core.safecrlf=false",
    "-c",
    "commit.gpgsign=false",
)


class Conflict(Exception):
    """The branch moved under this write. Read it again and retry."""


class RemoteError(OSError):
    """The remote could not be read or written."""


def _force_remove(function: Any, path: str, _error: Any) -> None:
    os.chmod(path, 0o700)
    function(path)


def parse_accepted(config: dict) -> dict[str, dict]:
    """The accepted foreign commits of a configuration. An incomplete entry is ignored."""
    entries = (config.get("archive") or {}).get("accepted_foreign_commits") or []
    accepted: dict[str, dict] = {}
    if not isinstance(entries, list):
        return accepted
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sha, reason, date = entry.get("sha"), entry.get("reason"), entry.get("date")
        if isinstance(sha, str) and _FULL_SHA.match(sha) and str(reason or "").strip() and str(date or "").strip():
            accepted[sha] = entry
    return accepted


def load_accepted(path: str | None) -> dict[str, dict]:
    """An unreadable configuration accepts nothing: every foreign commit then stays foreign."""
    if not path:
        return {}
    try:
        return parse_accepted(load_config(path))
    except UsageError:
        return {}


class GitRemote:
    """A plain git remote, such as a local bare repository. Never used for GitHub."""

    def __init__(self, url: str, branch: str, scratch: Path) -> None:
        self.url = url
        self.branch = branch
        self.scratch = scratch
        self.work = scratch / "work"

    def _git(self, cwd: Path | None, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *_IDENTITY, *args],
            cwd=cwd,
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )

    def _clone(self, target: Path) -> bool:
        """Clone the branch. Returns False when the branch does not exist yet."""
        if target.exists():
            shutil.rmtree(target, onexc=_force_remove)
        listed = self._git(None, "ls-remote", "--heads", self.url, f"refs/heads/{self.branch}")
        if listed.returncode != 0:
            raise RemoteError("the remote cannot be read")
        if not listed.stdout.strip():
            return False
        cloned = self._git(None, "clone", "--quiet", "--no-checkout", "--single-branch", "--branch", self.branch, self.url, str(target))
        if cloned.returncode != 0:
            raise RemoteError("the branch cannot be cloned")
        self._keep_bytes_raw(target)
        if self._git(target, "reset", "--quiet", "--hard", "HEAD").returncode != 0:
            raise RemoteError("the branch cannot be checked out")
        return True

    @staticmethod
    def _keep_bytes_raw(target: Path) -> None:
        info = target / ".git" / "info"
        info.mkdir(parents=True, exist_ok=True)
        (info / "attributes").write_bytes(_RAW_ATTRIBUTES)

    def paths(self) -> set[str]:
        if not self._clone(self.work):
            self.work.mkdir(parents=True)
            for args in (("init", "--quiet"), ("remote", "add", "origin", self.url), ("checkout", "--quiet", "--orphan", self.branch)):
                if self._git(self.work, *args).returncode != 0:
                    raise RemoteError("a new branch cannot be prepared")
            self._keep_bytes_raw(self.work)
            return set()
        return {
            path.relative_to(self.work).as_posix()
            for path in self.work.rglob("*")
            if path.is_file() and path.relative_to(self.work).parts[0] != ".git"
        }

    def commit(self, files: dict[str, bytes], message: str) -> str:
        for name, data in files.items():
            target = self.work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if self._git(self.work, "add", "-A", "-f").returncode != 0:
            raise RemoteError("the files cannot be added")
        if self._git(self.work, "commit", "--quiet", "-m", message).returncode != 0:
            raise RemoteError("the files cannot be committed")
        if self._git(self.work, "push", "--quiet", "origin", f"HEAD:refs/heads/{self.branch}").returncode != 0:
            raise Conflict
        return self._git(self.work, "rev-parse", "HEAD").stdout.decode().strip()

    def read_all(self, folder: str) -> dict[str, bytes]:
        check = self.scratch / "read-back"
        if not self._clone(check):
            raise RemoteError("the branch is gone")
        root = check / folder
        return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def foreign_commits(self, _accepted: dict[str, dict]) -> tuple[list[str], list[str]]:
        return [], []


class ApiRemote:
    """The branch on GitHub, written through the API so that GitHub signs each commit."""

    def __init__(self, repository: str, branch: str, base: str | None = None, token: str | None = None, must_exist: bool = False) -> None:
        self.repository = repository
        self.branch = branch
        self.must_exist = must_exist
        self.base = (base or os.environ.get("GITHUB_API_URL", "https://api.github.com")).rstrip("/")
        self.token = os.environ.get("GATE_TOKEN", "") if token is None else token
        self.head: str | None = None
        self.head_tree: str | None = None
        self.listed: set[str] = set()

    def _call(self, method: str, route: str, body: Any = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"{self.base}/repos/{self.repository}{route}", data=data, method=method)
        request.add_header("Accept", "application/vnd.github+json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read()
        return json.loads(payload) if payload else None

    def _safe(self, method: str, route: str, body: Any = None) -> Any:
        try:
            return self._call(method, route, body)
        except (urllib.error.URLError, OSError, ValueError) as error:
            # Names the kind of failure only: the token never enters a message.
            raise RemoteError(f"{type(error).__name__} on {method}") from None

    def _read_head(self) -> str | None:
        try:
            return self._call("GET", f"/git/ref/heads/{self.branch}")["object"]["sha"]
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise RemoteError(f"HTTP {error.code} reading the branch") from None
        except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as error:
            raise RemoteError(f"{type(error).__name__} reading the branch") from None

    def _tree(self, commit: str) -> dict[str, str]:
        tree = self._safe("GET", f"/git/trees/{commit}?recursive=1")
        if tree.get("truncated"):
            raise RemoteError("the tree of the branch is too large to read whole")
        self.head_tree = tree.get("sha")
        return {entry["path"]: entry["sha"] for entry in tree.get("tree", []) if entry.get("type") == "blob"}

    def paths(self) -> set[str]:
        self.head = self._read_head()
        return set(self._tree(self.head)) if self.head else set()

    def commit(self, files: dict[str, bytes], message: str) -> str:
        entries = []
        for name, data in files.items():
            blob = self._safe("POST", "/git/blobs", {"content": base64.b64encode(data).decode(), "encoding": "base64"})
            entries.append({"path": name, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        tree_body: dict[str, Any] = {"tree": entries}
        if self.head:
            tree_body["base_tree"] = self.head_tree
        tree = self._safe("POST", "/git/trees", tree_body)
        # No author, committer or signature: GitHub signs a commit only without them.
        commit = self._safe(
            "POST", "/git/commits", {"message": message, "tree": tree["sha"], "parents": [self.head] if self.head else []}
        )
        try:
            if self.head:
                self._call("PATCH", f"/git/refs/heads/{self.branch}", {"sha": commit["sha"], "force": False})
            else:
                self._call("POST", "/git/refs", {"ref": f"refs/heads/{self.branch}", "sha": commit["sha"]})
        except urllib.error.HTTPError as error:
            if error.code in (409, 422):
                raise Conflict from None
            raise RemoteError(f"HTTP {error.code} moving the branch") from None
        except (urllib.error.URLError, OSError, ValueError) as error:
            raise RemoteError(f"{type(error).__name__} moving the branch") from None
        return commit["sha"]

    def read_all(self, folder: str) -> dict[str, bytes]:
        head = self._read_head()
        if head is None:
            raise RemoteError("the branch is gone")
        prefix = folder.rstrip("/") + "/"
        found = {}
        for path, sha in self._tree(head).items():
            if path.startswith(prefix):
                blob = self._safe("GET", f"/git/blobs/{sha}")
                found[path[len(prefix) :]] = base64.b64decode(blob["content"])
        return found

    def _only_adds_records(self, sha: str) -> bool:
        """Whether a commit has one parent and only adds files under reports/."""
        for page in range(1, FILE_PAGES + 1):
            commit = self._safe("GET", f"/commits/{sha}?per_page=100&page={page}")
            if len(commit.get("parents") or []) != 1:
                return False
            files = commit.get("files") or []
            for item in files:
                if item.get("status") != "added" or not str(item.get("filename", "")).startswith("reports/"):
                    return False
            if len(files) < 100:
                return True
        return False

    def foreign_commits(self, accepted: dict[str, dict]) -> tuple[list[str], list[str]]:
        """Each commit not written and signed for github-actions[bot], and those accepted of them."""
        if self._read_head() is None:
            if self.must_exist:
                raise RemoteError("the branch exists, and the API does not show it")
            return [], []
        foreign: list[str] = []
        found: list[str] = []
        for page in range(1, COMMIT_PAGES + 1):
            commits = self._safe("GET", f"/commits?sha={self.branch}&per_page=100&page={page}")
            for item in commits:
                sha = str(item.get("sha"))
                self.listed.add(sha)
                author = (item.get("author") or {}).get("login")
                verified = ((item.get("commit") or {}).get("verification") or {}).get("verified")
                if author == EXPECTED_AUTHOR and verified is True:
                    continue
                if sha in accepted and self._only_adds_records(sha):
                    found.append(sha)
                else:
                    foreign.append(sha)
            if len(commits) < 100:
                return foreign, found
        raise RemoteError("too many commits on the branch to check")


def actors_status(remote: Any, accepted: dict[str, dict]) -> dict:
    """Whether the branch can be trusted. Anything unreadable means it cannot."""
    try:
        foreign, found = remote.foreign_commits(accepted)
    except (RemoteError, KeyError, TypeError, ValueError, AttributeError):
        return {"actors_ok": False, "foreign_commits": [], "accepted_commits": [], "reason": UNCHECKED_ACTORS}
    return {
        "actors_ok": not foreign,
        "foreign_commits": foreign,
        "accepted_commits": found,
        "reason": ANOTHER_ACTOR if foreign else None,
    }


def is_unsafe(relative: Path, full: Path) -> bool:
    return full.is_symlink() or any(part.lower() in UNSAFE_NAMES for part in relative.parts)


def scan_artifact(artifact: Path) -> tuple[list[Path], list[str], int]:
    """List what may be stored. Symbolic links are never followed."""
    files: list[Path] = []
    skipped: list[str] = []
    total = 0
    for folder, subfolders, names in os.walk(artifact, followlinks=False):
        here = Path(folder)
        for name in list(subfolders):
            full = here / name
            relative = full.relative_to(artifact)
            if is_unsafe(relative, full):
                skipped.append(relative.as_posix())
                subfolders.remove(name)
        for name in names:
            full = here / name
            relative = full.relative_to(artifact)
            if is_unsafe(relative, full) or not full.is_file():
                skipped.append(relative.as_posix())
                continue
            files.append(relative)
            total += full.stat().st_size
    return sorted(files), sorted(skipped), total


def sums_text(files: dict[str, bytes]) -> bytes:
    lines = [f"{sha256_bytes(files[name])}  {name}\n" for name in sorted(files)]
    return "".join(lines).encode("utf-8")


def stored_matches(stored: dict[str, bytes]) -> bool:
    """Recompute every SHA-256 of what the remote now holds."""
    sums = stored.get(SUMS)
    if sums is None:
        return False
    named = set()
    for line in sums.decode("utf-8", "replace").splitlines():
        digest, _, name = line.partition("  ")
        if not name or name not in stored or sha256_bytes(stored[name]) != digest:
            return False
        named.add(name)
    # final.json is appended after the sums are written.
    return set(stored) - {SUMS, "final.json"} == named - {"final.json"}


def result(**fields: Any) -> dict:
    base = {
        "stored": False,
        "sha256sums_match": False,
        "path": None,
        "commit": None,
        "reason": None,
        "artifact_present": False,
        "skipped_unsafe": [],
        "actors_ok": True,
        "accepted_commits": [],
    }
    return {**base, **fields}


def check_actors(remote: Any, outcome: dict, accepted: dict[str, dict]) -> dict:
    """Fail the store when anyone but the judge wrote to the branch. The evidence stays stored."""
    status = actors_status(remote, accepted)
    outcome = {**outcome, "actors_ok": status["actors_ok"], "accepted_commits": status["accepted_commits"]}
    if status["actors_ok"]:
        return outcome
    outcome["reason"] = status["reason"]
    if status["foreign_commits"]:
        outcome["foreign_commits"] = status["foreign_commits"]
    return outcome


def store(args: argparse.Namespace, remote: Any) -> dict:
    relative = f"reports/{args.pr}/{args.run_id}-{args.attempt}"
    artifact = Path(args.artifact)
    publish = Path(args.publish)
    present = artifact.is_dir()
    members: list[Path] = []
    skipped: list[str] = []
    if present:
        members, skipped, total = scan_artifact(artifact)
        if total > args.max_bytes:
            return result(path=relative, reason="TOO_LARGE", artifact_present=True, skipped_unsafe=skipped)

    files: dict[str, bytes] = {"context.json": Path(args.context).read_bytes()}
    if publish.is_dir():
        for path in sorted(publish.iterdir()):
            if path.is_file() and not path.is_symlink() and path.name.lower() not in UNSAFE_NAMES:
                files[path.name] = path.read_bytes()
    for member in members:
        files[f"artifact/{member.as_posix()}"] = (artifact / member).read_bytes()
    for name in TOP_LEVEL_FROM_ARTIFACT:
        if Path(name) in members and name not in files:
            files[name] = (artifact / name).read_bytes()
    files[SUMS] = sums_text(files)
    prefixed = {f"{relative}/{name}": data for name, data in files.items()}

    for _ in range(MAX_PUSH_TRIES):
        existing = remote.paths()
        if any(path.startswith(relative + "/") for path in existing):
            return result(path=relative, reason="ALREADY_EXISTS", artifact_present=present, skipped_unsafe=skipped)
        try:
            commit = remote.commit(prefixed, f"evidence: PR {args.pr}, run {args.run_id}, attempt {args.attempt}")
        except Conflict:
            continue
        matches = stored_matches(remote.read_all(relative))
        outcome = result(
            stored=True,
            sha256sums_match=matches,
            path=relative,
            commit=commit,
            reason=None if matches else "READ_BACK_MISMATCH",
            artifact_present=present,
            skipped_unsafe=skipped,
        )
        return check_actors(remote, outcome, load_accepted(args.config))
    return result(path=relative, reason="PUSH_REFUSED", artifact_present=present, skipped_unsafe=skipped)


def append(args: argparse.Namespace, remote: Any) -> dict:
    data = Path(args.file).read_bytes()
    target = args.path.strip("/")
    relative, _, name = target.rpartition("/")
    for _ in range(MAX_PUSH_TRIES):
        existing = remote.paths()
        if target in existing:
            return result(path=target, reason="ALREADY_EXISTS")
        if not any(path.startswith(relative + "/") for path in existing):
            return result(path=target, reason="NO_SUCH_FOLDER")
        try:
            commit = remote.commit({target: data}, f"evidence: add {target}")
        except Conflict:
            continue
        matches = remote.read_all(relative).get(name) == data
        outcome = result(
            stored=True,
            sha256sums_match=matches,
            path=target,
            commit=commit,
            reason=None if matches else "READ_BACK_MISMATCH",
        )
        return check_actors(remote, outcome, load_accepted(args.config))
    return result(path=target, reason="PUSH_REFUSED")


def check_only(args: argparse.Namespace, remote: Any) -> dict:
    return actors_status(remote, load_accepted(args.config))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.archive")
    commands = parser.add_subparsers(dest="command", required=True)

    def where(command: argparse.ArgumentParser) -> None:
        group = command.add_mutually_exclusive_group(required=True)
        group.add_argument("--remote", help="a plain git remote, never GitHub")
        group.add_argument("--api-repo", help="OWNER/NAME on GitHub, written through the API")
        command.add_argument("--branch", required=True)
        command.add_argument("--out", required=True)
        command.add_argument("--config", help="the configuration from the default branch")

    store_parser = commands.add_parser("store")
    where(store_parser)
    store_parser.add_argument("--pr", type=int, required=True)
    store_parser.add_argument("--run-id", required=True)
    store_parser.add_argument("--attempt", required=True)
    store_parser.add_argument("--artifact", required=True)
    store_parser.add_argument("--publish", required=True)
    store_parser.add_argument("--context", required=True)
    store_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)

    append_parser = commands.add_parser("append")
    where(append_parser)
    append_parser.add_argument("--path", required=True)
    append_parser.add_argument("--file", required=True)

    check_parser = commands.add_parser("check-actors")
    where(check_parser)

    args = parser.parse_args(argv)
    if args.remote and "github.com" in args.remote.lower():
        print("usage error: on GitHub use --api-repo, so that GitHub signs the commits", file=sys.stderr)
        return EXIT_USAGE

    handlers = {"store": store, "append": append, "check-actors": check_only}
    with tempfile.TemporaryDirectory(prefix="gate-archive-", ignore_cleanup_errors=True) as tmp:
        remote: Any = ApiRemote(args.api_repo, args.branch) if args.api_repo else GitRemote(args.remote, args.branch, Path(tmp))
        try:
            outcome = handlers[args.command](args, remote)
        except OSError as error:
            outcome = result(reason=f"REMOTE_ERROR: {error}")
    write_json(args.out, outcome)
    if outcome["reason"]:
        print(f"archive: {outcome['reason']}", file=sys.stderr)
    if args.command == "check-actors":
        return EXIT_OK if outcome["actors_ok"] else EXIT_RULE_FAILED
    good = outcome["stored"] and outcome["sha256sums_match"] and outcome["actors_ok"]
    return EXIT_OK if good else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
