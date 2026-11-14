"""An in-memory fake GitHub REST API for the negative tool's black-box tests.

The tool reaches the network only through `urllib.request.build_opener` (NEGATIVE-CONTRACT.md, NC-8). The tests
replace `urllib.request.HTTPSHandler` and `urllib.request.HTTPHandler` with the handler classes made here, so every
request the tool makes lands in `FakeGitHub.answer` and never leaves the process.

The fake records every request (method, URL, host, proxy tunnel, headers, body, timeout), checks the RS256 JWT with
the test key's public key, issues installation tokens, keeps branches and commits of one repository in memory, and
answers the routes of NC-9. N3's three attempts are refused by default, as GitHub is expected to; a test may make
any of them accepted. Anything else is answered 404 and recorded as unknown.

Nothing here knows the tool's code: it is GitHub's side of the contract.
"""

from __future__ import annotations

import base64
import email.message
import hashlib
import io
import json
import re
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.response

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://api.github.com"

REFUSALS = {
    "check_run": (403, "Resource not accessible by integration"),
    "status": (403, "Resource not accessible by integration"),
    "merge": (405, "Repository rule violations found\n\nRequired status check \"stage-a/policy\" is expected.\n\n"),
}


def b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def new_token(shape: str) -> str:
    alphabet = string.ascii_letters + string.digits
    if shape == "ghs":
        return "ghs_" + "".join(secrets.choice(alphabet) for _ in range(36))
    # A token that matches none of scrub's patterns, so only scrubbing by value can remove it.
    return "v1." + secrets.token_hex(20)


class Disconnect(Exception):
    """Raised inside the fake to mean: no answer at all."""


class FakeGitHub:
    def __init__(self, public_key, *, app_id: int, installation_id: int, repository: str, base: str,
                 files: dict[str, bytes]) -> None:
        self.public_key = public_key
        self.app_id = app_id
        self.installation_id = installation_id
        self.repository = repository
        self.owner, self.name = repository.split("/", 1)
        self.base = base
        self.base_sha = hashlib.sha1(b"base commit").hexdigest()
        self.commits: dict[str, dict[str, bytes]] = {self.base_sha: dict(files)}
        self.branches: dict[str, str] = {base: self.base_sha}
        self.pulls: dict[int, dict] = {}
        self.next_pr = 41
        self.calls: list[dict] = []
        self.unknown: list[dict] = []
        self.jwts: list[str] = []
        self.jwt_claims: list[dict] = []
        self.jwt_headers: list[dict] = []
        self.tokens: list[str] = []
        self.token_shape = "ghs"
        self.token_permissions = {"contents": "write", "metadata": "read", "pull_requests": "write"}
        # None leaves `repositories` out of the token answer; a list gives those names.
        self.token_repositories: list[str] | None = [self.name]
        self.attempts = dict(REFUSALS)  # name -> (status, message); a 2xx status means accepted
        self.echo_token_in_messages = False
        self.wrong_blob_sha = False
        self.content_encoding = "base64"
        self.pr_head_override: str | None = None
        # (method, regex on the path) -> ("status", status, body) or ("disconnect",) or ("interrupt",)
        # or ("redirect", location)
        self.failures: list[tuple] = []

    # ---- helpers for tests -----------------------------------------------------------------------------
    def fail(self, method: str, path_regex: str, status: int, body: object = None) -> None:
        self.failures.append((method, path_regex, ("status", status, body)))

    def disconnect(self, method: str, path_regex: str) -> None:
        self.failures.append((method, path_regex, ("disconnect",)))

    def interrupt(self, method: str, path_regex: str) -> None:
        self.failures.append((method, path_regex, ("interrupt",)))

    def redirect(self, method: str, path_regex: str, location: str) -> None:
        self.failures.append((method, path_regex, ("redirect", location)))

    def accept(self, name: str) -> None:
        self.attempts[name] = (201 if name != "merge" else 200, "accepted by the fake")

    def calls_to(self, method: str, path_regex: str) -> list[dict]:
        return [c for c in self.calls if c["method"] == method and re.search(path_regex, c["path"])]

    def writes(self) -> list[dict]:
        """Every request other than a GET, apart from the token request (NC-11's meaning of a write)."""
        return [c for c in self.calls if c["method"] != "GET" and not c["path"].startswith("/app/")]

    def branch_files(self, branch: str) -> dict[str, bytes]:
        return self.commits[self.branches[branch]]

    def handler_classes(self):
        fake = self

        class FakeHTTPS(urllib.request.HTTPSHandler):
            def https_open(self, req):
                return fake.answer(req)

        class FakeHTTP(urllib.request.HTTPHandler):
            def http_open(self, req):
                return fake.answer(req)

        return FakeHTTPS, FakeHTTP

    # ---- the answer --------------------------------------------------------------------------------------
    def answer(self, req: urllib.request.Request):
        url = req.full_url
        parts = urllib.parse.urlsplit(url)
        headers = {k.lower(): v for k, v in req.header_items()}
        body = req.data
        call = {
            "method": req.get_method(), "url": url, "scheme": parts.scheme, "host": req.host,
            "tunnel": getattr(req, "_tunnel_host", None), "path": parts.path, "query": parts.query,
            "headers": headers, "body": body, "timeout": getattr(req, "timeout", None),
        }
        self.calls.append(call)
        if parts.scheme != "https" or parts.netloc != "api.github.com":
            self.unknown.append(call)
            raise urllib.error.URLError("the fake answers only https://api.github.com")
        for method, regex, action in self.failures:
            if method == call["method"] and re.search(regex, parts.path):
                if action[0] == "disconnect":
                    raise urllib.error.URLError("fake: no connection")
                if action[0] == "interrupt":
                    raise KeyboardInterrupt
                if action[0] == "redirect":
                    return self._response(req, 301, {"message": "Moved Permanently", "url": action[1]},
                                          extra={"Location": action[1]})
                return self._response(req, action[1], action[2] if action[2] is not None else {"message": "fake failure"})
        status, data = self._route(call)
        return self._response(req, status, data)

    def _response(self, req, status: int, data: object, extra: dict | None = None):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode("utf-8")
        headers = email.message.Message()
        headers["Content-Type"] = "application/json; charset=utf-8"
        for key, value in (extra or {}).items():
            headers[key] = value
        response = urllib.response.addinfourl(io.BytesIO(raw), headers, req.full_url, status)
        response.msg = "fake"
        return response

    def _message(self, text: str) -> str:
        if self.echo_token_in_messages and self.tokens:
            return f"{text} (token {self.tokens[-1]}, jwt {self.jwts[-1] if self.jwts else ''})"
        return text

    def _check_jwt(self, authorization: str) -> bool:
        if not authorization.startswith("Bearer "):
            return False
        jwt = authorization[len("Bearer "):]
        try:
            header_b64, claims_b64, signature_b64 = jwt.split(".")
            self.public_key.verify(b64url_decode(signature_b64), f"{header_b64}.{claims_b64}".encode("ascii"),
                                   padding.PKCS1v15(), hashes.SHA256())
            header = json.loads(b64url_decode(header_b64))
            claims = json.loads(b64url_decode(claims_b64))
        except (ValueError, InvalidSignature):
            return False
        self.jwts.append(jwt)
        self.jwt_headers.append(header)
        self.jwt_claims.append(claims)
        now = time.time()
        return (header.get("alg") == "RS256" and claims.get("iss") == self.app_id
                and isinstance(claims.get("iat"), int) and isinstance(claims.get("exp"), int)
                and claims["iat"] <= now and claims["exp"] > now and claims["exp"] - claims["iat"] <= 600)

    def _route(self, call: dict) -> tuple[int, object]:
        method, path = call["method"], call["path"]
        authorization = call["headers"].get("authorization", "")
        not_found = {"message": "Not Found", "documentation_url": "https://docs.github.com/rest"}

        match = re.fullmatch(r"/app/installations/([0-9]+)/access_tokens", path)
        if match and method == "POST":
            if not self._check_jwt(authorization):
                return 401, {"message": "A JSON web token could not be decoded"}
            if int(match.group(1)) != self.installation_id:
                return 404, not_found
            token = new_token(self.token_shape)
            self.tokens.append(token)
            answer = {"token": token, "expires_at": "2026-11-14T12:00:00Z", "permissions": dict(self.token_permissions),
                      "repository_selection": "selected"}
            if self.token_repositories is not None:
                answer["repositories"] = [{"name": n, "full_name": f"{self.owner}/{n}"} for n in self.token_repositories]
            return 201, answer

        prefix = f"/repos/{self.owner}/{self.name}/"
        if not path.startswith(prefix):
            self.unknown.append(call)
            return 404, not_found
        if not self.tokens or authorization != f"Bearer {self.tokens[-1]}":
            return 401, {"message": "Bad credentials"}
        rest = path[len(prefix):]
        data = json.loads(call["body"]) if call["body"] else None

        match = re.fullmatch(r"git/ref/heads/(.+)", rest)
        if match and method == "GET":
            name = urllib.parse.unquote(match.group(1))
            if name not in self.branches:
                return 404, not_found
            return 200, {"ref": f"refs/heads/{name}", "node_id": "REF",
                         "object": {"sha": self.branches[name], "type": "commit", "url": "https://api.github.com/x"}}

        match = re.fullmatch(r"contents/(.+)", rest)
        if match and method == "GET":
            file_path = urllib.parse.unquote(match.group(1))
            ref = urllib.parse.parse_qs(call["query"]).get("ref", [""])[0]
            files = self.commits.get(ref)
            if files is None or file_path not in files:
                return 404, not_found
            raw = files[file_path]
            encoded = base64.b64encode(raw).decode("ascii")
            content = "\n".join(encoded[i:i + 60] for i in range(0, len(encoded), 60)) + "\n"
            sha = blob_sha(raw) if not self.wrong_blob_sha else "0" * 40
            if self.content_encoding != "base64":
                content = ""
            return 200, {"type": "file", "encoding": self.content_encoding, "size": len(raw),
                         "name": file_path.rsplit("/", 1)[-1], "path": file_path, "content": content, "sha": sha}

        if rest == "git/refs" and method == "POST":
            ref = str((data or {}).get("ref") or "")
            sha = (data or {}).get("sha")
            if not ref.startswith("refs/heads/") or sha not in self.commits:
                return 422, {"message": "Invalid request"}
            name = ref[len("refs/heads/"):]
            if name in self.branches:
                return 422, {"message": "Reference already exists"}
            self.branches[name] = sha
            return 201, {"ref": ref, "object": {"sha": sha, "type": "commit"}}

        match = re.fullmatch(r"contents/(.+)", rest)
        if match and method == "PUT":
            file_path = urllib.parse.unquote(match.group(1))
            branch = (data or {}).get("branch")
            if branch not in self.branches:
                return 404, not_found
            files = dict(self.commits[self.branches[branch]])
            if file_path not in files or blob_sha(files[file_path]) != (data or {}).get("sha"):
                return 409, {"message": f"{file_path} does not match"}
            try:
                files[file_path] = base64.b64decode((data or {}).get("content", ""), validate=True)
            except ValueError:
                return 422, {"message": "content is not valid Base64"}
            commit = hashlib.sha1(f"commit {len(self.commits)} {(data or {}).get('message')}".encode()).hexdigest()
            self.commits[commit] = files
            self.branches[branch] = commit
            return 200, {"content": {"path": file_path, "sha": blob_sha(files[file_path])},
                         "commit": {"sha": commit, "message": (data or {}).get("message")}}

        if rest == "pulls" and method == "POST":
            head, base = (data or {}).get("head"), (data or {}).get("base")
            if head not in self.branches or base not in self.branches:
                return 422, {"message": "Validation Failed"}
            number = self.next_pr
            self.next_pr += 1
            pr = {"number": number, "html_url": f"https://github.com/{self.repository}/pull/{number}",
                  "state": "open", "draft": bool((data or {}).get("draft")), "title": (data or {}).get("title"),
                  "body": (data or {}).get("body"), "head": {"ref": head, "sha": self.branches[head]},
                  "base": {"ref": base, "sha": self.branches[base]}}
            self.pulls[number] = pr
            return 201, pr

        match = re.fullmatch(r"pulls/([0-9]+)", rest)
        if match and method == "GET":
            pr = self.pulls.get(int(match.group(1)))
            if pr is None:
                return 404, not_found
            pr = json.loads(json.dumps(pr))
            pr["head"]["sha"] = self.pr_head_override or self.branches[pr["head"]["ref"]]
            return 200, pr

        if rest == "check-runs" and method == "POST":
            return self._attempt("check_run", {"id": 777, "name": (data or {}).get("name")})

        match = re.fullmatch(r"statuses/([0-9a-f]{40})", rest)
        if match and method == "POST":
            return self._attempt("status", {"id": 778, "context": (data or {}).get("context")})

        match = re.fullmatch(r"pulls/([0-9]+)/merge", rest)
        if match and method == "PUT":
            return self._attempt("merge", {"merged": True, "sha": "f" * 40, "message": "Pull Request successfully merged"})

        self.unknown.append(call)
        return 404, not_found

    def _attempt(self, name: str, accepted: dict) -> tuple[int, object]:
        status, message = self.attempts[name]
        if 200 <= status < 300:
            return status, accepted
        return status, {"message": self._message(message), "documentation_url": "https://docs.github.com/rest"}
