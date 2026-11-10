"""A fake GitHub REST API on 127.0.0.1 for the launcher's black-box tests.

It records every request (method, path with query, headers, body), checks
the RS256 JWT on /app/... routes with the test key's public key, issues and
revokes installation tokens, and answers the routes of LR-41 that the
launcher and the pinned gate's commands call. Branch facts (whether a
branch exists, its head, the commits of `reports`) are read from the local
bare repository that serves as the remote.

Nothing here knows the launcher's code: it is GitHub's side of the contract.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import string
import subprocess
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# The audit hook in conftest.py ignores processes started while this flag is
# set, so the fake's own `git` calls are never taken for the launcher's.
SERVER_THREAD = threading.local()


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def new_token(shape: str = "ghs") -> str:
    alphabet = string.ascii_letters + string.digits
    if shape == "ghs":
        return "ghs_" + "".join(secrets.choice(alphabet) for _ in range(36))
    # A token that matches none of scrub's patterns, so only scrubbing by
    # value can remove it.
    return "v1." + secrets.token_hex(20)


class FakeGitHub:
    """State and configuration of one fake API; one per test."""

    def __init__(self, public_key, *, app_id, installation_id, account, repository,
                 bare_repo, bot_slug="xtl-gate-executor", bot_id=987654):
        self.public_key = public_key
        self.app_id = app_id
        self.installation_id = installation_id
        self.account = account
        self.repository = repository
        self.bare_repo = bare_repo
        self.bot_slug = bot_slug
        self.bot_id = bot_id
        self.lock = threading.RLock()
        self.requests: list[dict] = []
        self.jwt_claims: list[dict] = []
        self.jwt_headers: list[dict] = []
        self.jwts: list[str] = []
        self.tokens_issued: list[str] = []
        self.tokens_revoked: list[str] = []
        self.token_shape = "ghs"
        # GET /app/installations answer; tests may replace it.
        self.installations = [{
            "id": installation_id,
            "app_id": app_id,
            "account": {"login": account, "type": "Organization"},
            "repository_selection": "selected",
        }]
        # The `repositories` list of the access-token answer: None leaves the
        # key out; a list gives those names.
        self.token_repositories: list[str] | None = [repository.split("/", 1)[1]]
        self.issues: dict[int, dict] = {}
        self.pulls: dict[int, dict] = {}
        self.comments: dict[int, list[dict]] = {}
        self.statuses: dict[str, list[dict]] = {}
        self.foreign_report_commits: set[str] = set()
        # (method, regex on the path) -> (status, body or callable)
        self.failures: list[tuple[str, str, int, object]] = []
        self.next_pr_number = 41
        self.next_comment_id = 9000
        # When this file exists, GET /repos/R/pulls/N answers head sha
        # `moved_head_sha` for PR `moved_pr` (LR-38).
        self.moved_head_flag: str | None = None
        self.moved_head_sha: str | None = None
        self.moved_pr: int | None = None
        # (method, regex on the path, callable): called once, after the answer
        # to the first matching request was sent (LR-44).
        self.after_hooks: list[list] = []
        # A PR's head follows its branch on the remote, as on GitHub, when
        # that branch exists there; otherwise the configured sha is given.
        self.pulls_follow_branches = True
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    # ---- life cycle ------------------------------------------------------
    def start(self) -> "FakeGitHub":
        fake = self

        class Handler(_Handler):
            state = fake

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        # Kept after stop(): tests of a shared run compare it once the run ended.
        self._url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name="fake-github", daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    @property
    def url(self) -> str:
        assert getattr(self, "_url", None), "the fake API was never started"
        return self._url

    # ---- helpers for tests -----------------------------------------------
    def fail(self, method: str, path_regex: str, status: int, body=None) -> None:
        self.failures.append((method, path_regex, status, body))

    def after(self, method: str, path_regex: str, action, when=None) -> None:
        """Run `action` once, on the first matching request for which
        `when()` holds, after its answer is computed and before it is sent."""
        self.after_hooks.append([method, path_regex, action, False, when])

    def live_pr(self, pr: dict) -> dict:
        pr = json.loads(json.dumps(pr))
        if self.pulls_follow_branches:
            sha = self.branch_sha(pr["head"]["ref"])
            if sha is not None:
                pr["head"]["sha"] = sha
        return pr

    def requests_to(self, method: str, path_regex: str) -> list[dict]:
        with self.lock:
            return [r for r in self.requests
                    if r["method"] == method and re.search(path_regex, r["path"])]

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        SERVER_THREAD.active = True
        try:
            return subprocess.run(["git", "--git-dir", self.bare_repo, *args],
                                  capture_output=True, text=True, check=check)
        finally:
            SERVER_THREAD.active = False

    def branch_sha(self, branch: str) -> str | None:
        res = self.git("rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}",
                       check=False)
        return res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else None

    def html_pr(self, number: int) -> str:
        return f"https://github.com/{self.repository}/pull/{number}"


class _Handler(BaseHTTPRequestHandler):
    state: FakeGitHub = None  # set by the subclass in start()
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output quiet
        pass

    # ---- plumbing --------------------------------------------------------
    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return raw, None
        try:
            return raw, json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return raw, None

    def _send(self, status: int, body=None, headers: dict | None = None):
        hooks, self._pending_hooks = getattr(self, "_pending_hooks", []), []
        for h in hooks:
            h[2]()
        record = getattr(self, "_record", None)
        if record is not None:
            record["status"] = status
        data = b"" if body is None else json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_PUT(self):
        self._dispatch("PUT")

    def _dispatch(self, method: str):
        SERVER_THREAD.active = True
        try:
            st = self.state
            raw, body = self._read_body()
            record = {
                "method": method,
                "path": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "raw_body": raw.decode("utf-8", "replace"),
                "body": body,
                "time": time.time(),
            }
            with st.lock:
                st.requests.append(record)
            self._record = record
            for fm, rx, status, fbody in st.failures:
                if fm == method and re.search(rx, self.path):
                    if callable(fbody):
                        fbody = fbody(record)
                    self._send(status, fbody)
                    return
            with st.lock:
                due = [h for h in st.after_hooks
                       if h[0] == method and re.search(h[1], self.path) and not h[3]
                       and (h[4] is None or h[4]())]
                for h in due:
                    h[3] = True
            # Run once the answer is computed, before it is sent, so the
            # client cannot act before the hook did.
            self._pending_hooks = due
            try:
                self._route(method, body, record)
            except Exception as exc:  # a bug in the fake must be visible
                self._send(599, {"message": f"fake github error: {exc!r}"})
        finally:
            SERVER_THREAD.active = False

    # ---- authentication --------------------------------------------------
    def _auth_value(self) -> tuple[str, str]:
        value = self.headers.get("Authorization") or ""
        scheme, _, cred = value.partition(" ")
        return scheme.lower(), cred.strip()

    def _check_jwt(self) -> bool:
        st = self.state
        scheme, cred = self._auth_value()
        if scheme != "bearer" or cred.count(".") != 2:
            return False
        head_b64, payload_b64, sig_b64 = cred.split(".")
        try:
            header = json.loads(_b64url_decode(head_b64))
            claims = json.loads(_b64url_decode(payload_b64))
            st.public_key.verify(_b64url_decode(sig_b64),
                                 f"{head_b64}.{payload_b64}".encode("ascii"),
                                 padding.PKCS1v15(), hashes.SHA256())
        except (ValueError, InvalidSignature, json.JSONDecodeError):
            return False
        with st.lock:
            st.jwts.append(cred)
            st.jwt_headers.append(header)
            st.jwt_claims.append({"claims": claims, "received": time.time()})
        if header.get("alg") != "RS256":
            return False
        now = time.time()
        if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= now:
            return False
        return True

    def _token_ok(self) -> str | None:
        st = self.state
        scheme, cred = self._auth_value()
        if scheme not in ("bearer", "token"):
            return None
        with st.lock:
            if cred in st.tokens_issued and cred not in st.tokens_revoked:
                return cred
        return None

    # ---- routes ------------------------------------------------------------
    def _route(self, method: str, body, record):
        st = self.state
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        repo_prefix = f"/repos/{st.repository}"

        if path.startswith("/app/") or path == "/app":
            if not self._check_jwt():
                self._send(401, {"message": "A JSON web token could not be decoded"})
                return
            if method == "GET" and path == "/app/installations":
                self._send(200, st.installations)
                return
            m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", path)
            if method == "POST" and m:
                if int(m.group(1)) not in [i["id"] for i in st.installations]:
                    self._send(404, {"message": "Not Found"})
                    return
                tok = new_token(st.token_shape)
                with st.lock:
                    st.tokens_issued.append(tok)
                answer = {
                    "token": tok,
                    "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                time.gmtime(time.time() + 3600)),
                    "permissions": {"contents": "write", "pull_requests": "write",
                                    "issues": "write", "metadata": "read"},
                    "repository_selection": "selected",
                }
                if st.token_repositories is not None:
                    owner = st.repository.split("/", 1)[0]
                    answer["repositories"] = [
                        {"id": 1000 + i, "name": n, "full_name": f"{owner}/{n}"}
                        for i, n in enumerate(st.token_repositories)]
                self._send(201, answer)
                return
            self._send(404, {"message": "Not Found"})
            return

        token = self._token_ok()
        if token is None:
            self._send(401, {"message": "Bad credentials"})
            return

        if method == "DELETE" and path == "/installation/token":
            with st.lock:
                st.tokens_revoked.append(token)
            self._send(204)
            return

        m = re.fullmatch(r"/users/(.+)%5[Bb]bot%5[Dd]", path)
        if method == "GET" and m:
            if m.group(1) != st.bot_slug:
                self._send(404, {"message": "Not Found"})
                return
            self._send(200, {"login": f"{st.bot_slug}[bot]", "id": st.bot_id, "type": "Bot"})
            return

        if not path.startswith(repo_prefix + "/"):
            self._send(404, {"message": "Not Found"})
            return
        rest = path[len(repo_prefix):]

        m = re.fullmatch(r"/issues/(\d+)", rest)
        if method == "GET" and m:
            n = int(m.group(1))
            if n in st.issues:
                self._send(200, st.issues[n])
            elif n in st.pulls:
                pr = st.pulls[n]
                self._send(200, {"number": n, "title": pr.get("title", ""),
                                 "body": pr.get("body", ""), "state": pr["state"],
                                 "pull_request": {"url": f"{st.url}{repo_prefix}/pulls/{n}"},
                                 "user": pr.get("user")})
            else:
                self._send(404, {"message": "Not Found"})
            return

        m = re.fullmatch(r"/issues/(\d+)/comments", rest)
        if m:
            n = int(m.group(1))
            if method == "GET":
                self._paginate(st.comments.get(n, []), query, default_per_page=30)
                return
            if method == "POST":
                with st.lock:
                    cid = st.next_comment_id
                    st.next_comment_id += 1
                    comment = {"id": cid, "body": (body or {}).get("body", ""),
                               "user": {"login": f"{st.bot_slug}[bot]"},
                               "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "html_url": f"https://github.com/{st.repository}/issues/{n}#issuecomment-{cid}"}
                    st.comments.setdefault(n, []).append(comment)
                self._send(201, comment)
                return

        m = re.fullmatch(r"/pulls/(\d+)", rest)
        if method == "GET" and m:
            n = int(m.group(1))
            if n not in st.pulls:
                self._send(404, {"message": "Not Found"})
                return
            pr = st.live_pr(st.pulls[n])
            if (st.moved_head_flag and st.moved_pr == n
                    and __import__("os").path.exists(st.moved_head_flag)):
                pr["head"]["sha"] = st.moved_head_sha
            self._send(200, pr)
            return

        if rest == "/pulls":
            if method == "GET":
                found = []
                for pr in [st.live_pr(x) for x in st.pulls.values()]:
                    if "state" in query and query["state"][0] not in ("all", pr["state"]):
                        continue
                    if "head" in query:
                        want = query["head"][0]
                        owner = pr["head"]["repo"]["full_name"].split("/", 1)[0]
                        if want not in (f"{owner}:{pr['head']['ref']}", pr["head"]["ref"]):
                            continue
                    if "base" in query and query["base"][0] != pr["base"]["ref"]:
                        continue
                    found.append(pr)
                self._paginate(found, query, default_per_page=30)
                return
            if method == "POST":
                body = body or {}
                head = body.get("head", "")
                head_ref = head.split(":", 1)[1] if ":" in head else head
                sha = st.branch_sha(head_ref)
                if sha is None:
                    self._send(422, {"message": "Validation Failed",
                                     "errors": [{"field": "head", "code": "invalid"}]})
                    return
                with st.lock:
                    n = st.next_pr_number
                    st.next_pr_number += 1
                    pr = {
                        "number": n, "state": "open", "title": body.get("title", ""),
                        "body": body.get("body", ""), "html_url": st.html_pr(n),
                        "url": f"{st.url}{repo_prefix}/pulls/{n}",
                        "head": {"ref": head_ref, "sha": sha,
                                 "repo": {"full_name": st.repository}},
                        "base": {"ref": body.get("base", ""),
                                 "repo": {"full_name": st.repository}},
                        "user": {"login": f"{st.bot_slug}[bot]"},
                        "draft": bool(body.get("draft", False)),
                    }
                    st.pulls[n] = pr
                self._send(201, pr)
                return

        m = re.fullmatch(r"/git/ref/heads/(.+)", rest)
        if method == "GET" and m:
            branch = urllib.parse.unquote(m.group(1))
            sha = st.branch_sha(branch)
            if sha is None:
                self._send(404, {"message": "Not Found"})
                return
            self._send(200, {"ref": f"refs/heads/{branch}",
                             "object": {"sha": sha, "type": "commit"}})
            return

        if method == "GET" and rest == "/commits":
            ref = query.get("sha", ["HEAD"])[0]
            res = st.git("rev-list", ref, "--", check=False)
            if res.returncode != 0:
                self._send(404, {"message": "Not Found"})
                return
            items = []
            for sha in res.stdout.split():
                foreign = sha in st.foreign_report_commits
                items.append({
                    "sha": sha,
                    "author": {"login": "mallory" if foreign else "github-actions[bot]"},
                    "committer": {"login": "web-flow"},
                    "commit": {"verification": {"verified": not foreign,
                                                "reason": "unsigned" if foreign else "valid"}},
                    "parents": [{"sha": p} for p in
                                st.git("rev-list", "--parents", "-n", "1", sha).stdout.split()[1:]],
                })
            self._paginate(items, query, default_per_page=30)
            return

        m = re.fullmatch(r"/commits/([0-9a-f]{40})/statuses", rest)
        if method == "GET" and m:
            self._paginate(st.statuses.get(m.group(1), []), query, default_per_page=30)
            return

        m = re.fullmatch(r"/commits/([0-9a-f]{40})", rest)
        if method == "GET" and m:
            sha = m.group(1)
            res = st.git("show", "--no-renames", "--name-status", "--format=%P", sha, check=False)
            if res.returncode != 0:
                self._send(404, {"message": "Not Found"})
                return
            lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
            parents = lines[0].split() if lines else []
            files = []
            for ln in lines[1:]:
                status, _, name = ln.partition("\t")
                files.append({"filename": name,
                              "status": {"A": "added", "M": "modified", "D": "removed"}.get(
                                  status[:1], "modified")})
            self._send(200, {"sha": sha, "parents": [{"sha": p} for p in parents],
                             "files": files})
            return

        self._send(404, {"message": "Not Found"})

    def _paginate(self, items: list, query: dict, default_per_page: int):
        per_page = int(query.get("per_page", [default_per_page])[0])
        page = int(query.get("page", ["1"])[0])
        start = (page - 1) * per_page
        chunk = items[start:start + per_page]
        headers = {}
        if start + per_page < len(items):
            q = {k: v[0] for k, v in query.items()}
            q["page"] = str(page + 1)
            q["per_page"] = str(per_page)
            path = urllib.parse.urlsplit(self.path).path
            headers["Link"] = (f'<{self.state.url}{path}?{urllib.parse.urlencode(q)}>; '
                               f'rel="next"')
        self._send(200, chunk, headers)
