"""A fake GitHub for the controller's tests: in memory, no network.

It answers only the routes CONTROLLER-CONTRACT.md names, records every call, checks the app's JWT with the test's
public key and the installation token on every other request, and starts from a world in which every rule holds.
A test changes one thing to make one rule fail.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://api.github.com"
REPO = "acme/demo-stand"
BASE = "candidate/a"
PR = 7
HEAD = "a" * 40
BASE_TIP = "b" * 40
REPORTS_HEAD = "c" * 40
MERGE_SHA = "d" * 40
NOW = 1_800_000_000

APP_ID = 111
INSTALLATION_ID = 222
EXECUTOR_SLUG = "acme-executor"
EXECUTOR_APP = 333
EXECUTOR_BOT = 4444
REVIEWER_SLUG = "acme-reviewer"
REVIEWER_APP = 555
REVIEWER_BOT = 6666
ACTIONS = 15368
GATE_CHECKS = ["gate/env", "gate/tests", "gate/acceptance", "gate/guard", "gate/security", "gate/report",
               "gate/archive", "gate/final"]
POLICY = "stage-a/policy"
TOKEN = "ghs_" + "FakeInstallationToken0123456789"

TASKS = [
    ("SA1-T1", "SA1-T1 Overdue misses today"),
    ("SA1-T2", "SA1-T2 Search ignores closed"),
    ("SA1-T3", "SA1-T3 Paging skips last item"),
]
HEAD_REF = "ai/12-sa1-t1-overdue-misses-today"
T2_REF = "ai/13-sa1-t2-search-ignores-closed"

OPERATOR_SID = "S-1-5-21-1000-2000-3000-1001"
FULL = 2032127

DEFAULT_CODEOWNERS = """# owners
/.github/                 @acme
/acceptance/              @acme
/quality.toml             @acme
/CODEOWNERS               @acme
pytest.ini                @acme
conftest.py               @acme
/requirements.lock        @acme
/SPEC.md                  @acme
"""


DEFAULT_SOURCE = b'"""An ordinary module."""\n\nLIMIT = 2000\n'

STORE_BASE = b'''"""A store."""

TASKS_TABLE = """
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    priority INTEGER NOT NULL CHECK(priority BETWEEN 1 AND 5)
)
"""
# A comment that names CREATE TABLE is no string literal.
COPY = ["CREATE TEMP TABLE task_rows AS SELECT * FROM tasks", "DROP TABLE task_rows"]


def visible(query):
    return {"query": query.lower()}
'''


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def blob_sha(path: str, data: bytes) -> str:
    return hashlib.sha1(path.encode() + b"\0" + data).hexdigest()


def check_run(run_id: int, name: str, conclusion: str | None = "success", status: str = "completed",
              app: int = ACTIONS, head: str = HEAD) -> dict:
    return {"id": run_id, "name": name, "head_sha": head, "status": status, "conclusion": conclusion,
            "app": {"id": app, "slug": "github-actions" if app == ACTIONS else "other"}}


def review_status(status_id: int, state: str = "success", login: str = REVIEWER_SLUG + "[bot]",
                  user_id: int = REVIEWER_BOT, kind: str = "Bot", context: str = "independent-review") -> dict:
    return {"id": status_id, "context": context, "state": state,
            "creator": {"login": login, "id": user_id, "type": kind}}


def good_record(head: str = HEAD, pr: int = PR) -> dict:
    """The four files of one stored attempt in which the gate found the PR ready and nothing marked."""
    return {
        "context.json": {"head_sha": head, "pr": pr, "repository": REPO},
        "verdict.json": {"verdict": "ready-for-human", "reasons": [],
                         "checks": {"gate/env": "success", "gate/guard": "success", "gate/tests": "success",
                                    "gate/acceptance": "success", "gate/security": "success",
                                    "gate/report": "success"}},
        "final.json": {"verdict": "awaiting-review", "gate_verdict": "ready-for-human", "gate_reasons": [],
                       "conclusions": {"gate/archive": "success", "gate/final": None}},
        "report.json": {"verification": {"head_sha": head, "pr": pr, "repository": REPO, "head_repository": REPO},
                        "marked_tests": [], "needs_code_owner": [], "dependency_changes": [],
                        "security_review_changes": [], "verdicts": {"preliminary": "ready-for-human"}},
    }


@dataclass
class Call:
    method: str
    url: str
    path: str
    query: dict
    headers: dict
    body: object
    route: str


@dataclass
class FakeGitHub:
    public_key: object
    now: int = NOW
    calls: list = field(default_factory=list)

    def __post_init__(self) -> None:
        self.pr = {
            "number": PR, "state": "open", "merged": False, "draft": False,
            "user": {"login": EXECUTOR_SLUG + "[bot]", "id": EXECUTOR_BOT, "type": "Bot"},
            "base": {"ref": BASE, "sha": BASE_TIP, "repo": {"full_name": REPO}},
            "head": {"ref": HEAD_REF, "sha": HEAD, "repo": {"full_name": REPO}},
        }
        self.mergeable = [True]
        self.closed_prs: list[dict] = []
        self.base_tip = BASE_TIP
        self.compare = {
            "status": "ahead", "merge_base_commit": {"sha": BASE_TIP},
            "files": [
                {"filename": "workflow/service.py", "status": "modified",
                 "patch": "@@ -10,7 +10,7 @@\n-    return due < today\n+    return due <= today\n"},
                {"filename": "tests/test_overdue_today.py", "status": "added",
                 "patch": "@@ -0,0 +1,3 @@\n+def test_today():\n+    assert True\n"},
            ],
        }
        self.head_tree = [
            {"path": "workflow", "mode": "040000", "type": "tree"},
            {"path": "workflow/service.py", "mode": "100644", "type": "blob"},
            {"path": "tests", "mode": "040000", "type": "tree"},
            {"path": "tests/test_overdue_today.py", "mode": "100644", "type": "blob"},
        ]
        self.head_tree_truncated = False
        self.codeowners = {"CODEOWNERS": DEFAULT_CODEOWNERS}
        run_id = 100
        self.check_runs = []
        for name in GATE_CHECKS:
            run_id += 1
            self.check_runs.append(check_run(run_id, name))
        self.statuses = [review_status(50)]
        self.reports_exists = True
        self.reports_commits = [
            {"sha": REPORTS_HEAD, "author": {"login": "github-actions[bot]"},
             "commit": {"verification": {"verified": True}}},
            {"sha": "e" * 40, "author": {"login": "github-actions[bot]"},
             "commit": {"verification": {"verified": True}}},
        ]
        self.records = {f"{PR}/1000-1": good_record()}
        self.reports_tree_truncated = False
        self.merge_answer = (200, {"merged": True, "sha": MERGE_SHA, "message": "Pull Request successfully merged"})
        self.next_id = 9000
        self.fail: dict[str, tuple[int, object]] = {}
        self.after: dict[str, object] = {}
        self.token_bodies: list = []
        # Review round 1. Files at a ref for the contents route: {(ref, path): bytes or None (404)}; a code path not
        # listed answers DEFAULT_SOURCE at the merge base and at the head.
        self.files: dict[tuple[str, str], bytes | None] = {}
        self.codeowners_encoding = "base64"
        # Routes that get no answer: raise ConnectionResetError before acting ("no_answer") or after acting
        # ("lose_answer"), as a lost connection would.
        self.no_answer: set[str] = set()
        self.lose_answer: set[str] = set()
        self.token_value = TOKEN
        self.counts: dict[str, int] = {}

    # ------------------------------------------------------------------ helpers for tests
    def routes(self, method: str | None = None) -> list[str]:
        return [c.route for c in self.calls if method is None or c.method == method]

    def writes(self) -> list[Call]:
        return [c for c in self.calls if c.method in ("POST", "PATCH", "PUT") and c.route != "token"]

    def policy_runs(self) -> list[dict]:
        return [r for r in self.check_runs if r["name"] == POLICY]

    # ------------------------------------------------------------------ the transport
    def handle(self, method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
        parsed = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        payload = json.loads(body) if body else None
        route = self._route(method, parsed.path)
        self.calls.append(Call(method, url, parsed.path, query, dict(headers), payload, route))
        self.counts[route] = self.counts.get(route, 0) + 1
        if route in self.no_answer:
            raise ConnectionResetError("the connection was reset (fake)")
        if not url.startswith(API + "/") or parsed.scheme != "https" or parsed.netloc != "api.github.com":
            return 404, b'{"message": "wrong host"}'
        if route == "token":
            if not self._jwt_ok(headers.get("Authorization", "")):
                return 401, b'{"message": "A JSON web token could not be decoded"}'
        elif headers.get("Authorization") not in ("Bearer " + TOKEN, "token " + TOKEN):
            return 401, b'{"message": "Bad credentials"}'
        if route in self.fail:
            status, answer = self.fail[route]
            return status, json.dumps(answer).encode()
        status, answer = self._answer(method, route, parsed.path, query, payload)
        hook = self.after.get(route)
        if hook is not None:
            hook(self)
        if route in self.lose_answer:
            raise ConnectionResetError("the answer was lost (fake)")
        return status, json.dumps(answer).encode()

    def _route(self, method: str, path: str) -> str:
        r = re.escape("/repos/" + REPO)
        table = [
            ("POST", rf"^/app/installations/{INSTALLATION_ID}/access_tokens$", "token"),
            ("GET", rf"^{r}/pulls/{PR}$", "pr"),
            ("GET", rf"^{r}/pulls$", "closed"),
            ("GET", rf"^{r}/branches/[^/]+$", "branch"),
            ("GET", rf"^{r}/compare/[^/]+$", "compare"),
            ("GET", rf"^{r}/contents/.+$", "contents"),
            ("GET", rf"^{r}/git/trees/[0-9a-f]{{40}}$", "tree"),
            ("GET", rf"^{r}/commits/[0-9a-f]{{40}}/check-runs$", "check_runs"),
            ("GET", rf"^{r}/commits/[0-9a-f]{{40}}/statuses$", "statuses"),
            ("GET", rf"^{r}/commits$", "reports_commits"),
            ("GET", rf"^{r}/git/blobs/[0-9a-f]{{40}}$", "blob"),
            ("POST", rf"^{r}/check-runs$", "post_check"),
            ("PATCH", rf"^{r}/check-runs/[0-9]+$", "patch_check"),
            ("PUT", rf"^{r}/pulls/{PR}/merge$", "merge"),
        ]
        for verb, pattern, name in table:
            if verb == method and re.match(pattern, path):
                return name
        return "UNKNOWN"

    def _jwt_ok(self, header: str) -> bool:
        if not header.startswith("Bearer "):
            return False
        try:
            head, claims, signature = header[7:].split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
            self.public_key.verify(base64.urlsafe_b64decode(pad(signature)), f"{head}.{claims}".encode(),
                                   padding.PKCS1v15(), hashes.SHA256())
            values = json.loads(base64.urlsafe_b64decode(pad(claims)))
            alg = json.loads(base64.urlsafe_b64decode(pad(head)))
        except (ValueError, InvalidSignature):
            return False
        self.jwt_claims = values
        return (alg.get("alg") == "RS256" and str(values.get("iss")) == str(APP_ID)
                and values.get("iat") == self.now - 60 and values.get("exp") == self.now + 540)

    def _reports_files(self) -> dict[str, bytes]:
        """Each record's key is `<pr>/<run_id>-<attempt>`; a value is JSON, or raw bytes."""
        files = {}
        for folder, record in self.records.items():
            for name, value in record.items():
                data = value if isinstance(value, bytes) else json.dumps(value).encode()
                files[f"reports/{folder}/{name}"] = data
        return files

    def _answer(self, method: str, route: str, path: str, query: dict, payload: object) -> tuple[int, object]:
        page = int(query.get("page", "1"))
        if route == "token":
            self.token_bodies.append(payload)
            return 201, {"token": self.token_value, "expires_at": "2027-01-15T08:00:00Z"}
        if route == "pr":
            pr = copy.deepcopy(self.pr)
            if pr.get("merged"):
                pr.setdefault("merge_commit_sha", MERGE_SHA)
            pr["mergeable"] = self.mergeable.pop(0) if len(self.mergeable) > 1 else self.mergeable[0]
            return 200, pr
        if route == "closed":
            if query.get("state") != "closed" or query.get("base") != BASE:
                return 422, {"message": "bad query"}
            items = self.closed_prs[(page - 1) * 100: page * 100]
            return 200, items
        if route == "branch":
            name = urllib.parse.unquote(path.rsplit("/", 1)[1])
            if name != BASE:
                return 404, {"message": "Branch not found"}
            return 200, {"name": BASE, "commit": {"sha": self.base_tip}}
        if route == "compare":
            basehead = urllib.parse.unquote(path.rsplit("/", 1)[1])
            if basehead != f"{self.base_tip}...{self.pr['head']['sha']}":
                return 404, {"message": "Not Found"}
            return 200, copy.deepcopy(self.compare)
        if route == "contents":
            name = urllib.parse.unquote(path.split("/contents/", 1)[1])
            ref = query.get("ref")
            if name.endswith("CODEOWNERS"):
                if ref != self.base_tip or name not in self.codeowners:
                    return 404, {"message": "Not Found"}
                if self.codeowners_encoding != "base64":
                    return 200, {"type": "file", "encoding": self.codeowners_encoding, "content": ""}
                return 200, {"type": "file", "encoding": "base64", "content": b64(self.codeowners[name].encode())}
            if (ref, name) in self.files:
                data = self.files[(ref, name)]
            elif ref in (self.compare["merge_base_commit"]["sha"], self.pr["head"]["sha"]):
                data = DEFAULT_SOURCE
            else:
                data = None
            if data is None:
                return 404, {"message": "Not Found"}
            return 200, {"type": "file", "encoding": "base64", "content": b64(data)}
        if route == "tree":
            sha = path.rsplit("/", 1)[1]
            if query.get("recursive") != "1":
                return 422, {"message": "recursive expected"}
            if sha == self.pr["head"]["sha"]:
                return 200, {"sha": sha, "tree": copy.deepcopy(self.head_tree), "truncated": self.head_tree_truncated}
            if sha == REPORTS_HEAD and self.reports_exists:
                entries = [{"path": p, "mode": "100644", "type": "blob", "sha": blob_sha(p, d)}
                           for p, d in self._reports_files().items()]
                return 200, {"sha": sha, "tree": entries, "truncated": self.reports_tree_truncated}
            return 404, {"message": "Not Found"}
        if route == "blob":
            sha = path.rsplit("/", 1)[1]
            for p, d in self._reports_files().items():
                if blob_sha(p, d) == sha:
                    return 200, {"sha": sha, "encoding": "base64", "content": b64(d)}
            return 404, {"message": "Not Found"}
        if route == "check_runs":
            sha = path.split("/commits/", 1)[1].split("/", 1)[0]
            runs = [r for r in self.check_runs if r["head_sha"] == sha]
            return 200, {"total_count": len(runs), "check_runs": copy.deepcopy(runs[(page - 1) * 100: page * 100])}
        if route == "statuses":
            ordered = sorted(self.statuses, key=lambda s: s["id"], reverse=True)
            return 200, copy.deepcopy(ordered[(page - 1) * 100: page * 100])
        if route == "reports_commits":
            if query.get("sha") != "reports":
                return 422, {"message": "bad query"}
            if not self.reports_exists:
                return 404, {"message": "Not Found"}
            return 200, copy.deepcopy(self.reports_commits[(page - 1) * 100: page * 100])
        if route == "post_check":
            self.next_id += 1
            run = {"id": self.next_id, "name": payload.get("name"), "head_sha": payload.get("head_sha"),
                   "status": payload.get("status"), "conclusion": payload.get("conclusion"),
                   "output": payload.get("output"), "app": {"id": APP_ID, "slug": "acme-controller"}}
            self.check_runs.append(run)
            return 201, run
        if route == "patch_check":
            run_id = int(path.rsplit("/", 1)[1])
            for run in self.check_runs:
                if run["id"] == run_id:
                    for key in ("status", "conclusion", "output", "name"):
                        if key in payload:
                            run[key] = payload[key]
                    return 200, run
            return 404, {"message": "Not Found"}
        if route == "merge":
            status, answer = self.merge_answer
            if status == 200:
                self.pr["merged"] = True
                self.pr["state"] = "closed"
            return status, answer
        return 404, {"message": f"route not in the contract: {method} {path}"}


class FakeWindows:
    """The setup script's Windows seam: the operator's SID and each path's access rules."""

    def __init__(self) -> None:
        self.sid = OPERATOR_SID
        self.rules: dict[str, list] = {}
        self.asked: list[str] = []

    def current_sid(self) -> str:
        return self.sid

    def acl_of(self, path):
        self.asked.append(str(path))
        return True, self.rules.get(str(path), [(OPERATOR_SID, FULL, "Allow", "False")])
