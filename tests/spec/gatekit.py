"""Shared helpers for the spec tests.

Black box only: nothing in here imports the gate. Every script is reached through
`python -P -m gate.<name>` with PYTHONPATH set to GATE_ROOT, in a clean environment
(no credentials of the machine running the tests ever reach a child process).
"""
from __future__ import annotations

import atexit
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

GATE_ROOT = Path(os.environ.get("GATE_ROOT", ".")).resolve()

# --------------------------------------------------------------------------- environment

_HOME = Path(tempfile.mkdtemp(prefix="gate-spec-home-"))
_NEUTRAL_CWD = Path(tempfile.mkdtemp(prefix="gate-spec-cwd-"))
(_HOME / ".gitconfig").write_text(
    "[core]\n\tautocrlf = false\n\tsafecrlf = false\n\tlongpaths = true\n"
    "[user]\n\tname = Spec Test\n\temail = spec-test@example.invalid\n"
    "[init]\n\tdefaultBranch = main\n"
    "[commit]\n\tgpgsign = false\n"
    "[protocol \"file\"]\n\tallow = always\n"
    "[safe]\n\tdirectory = *\n",
    encoding="utf-8",
)
atexit.register(shutil.rmtree, _HOME, ignore_errors=True)
atexit.register(shutil.rmtree, _NEUTRAL_CWD, ignore_errors=True)

_PASS_THROUGH = (
    "PATH", "SYSTEMROOT", "SystemRoot", "SYSTEMDRIVE", "COMSPEC", "PATHEXT", "WINDIR",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "LD_LIBRARY_PATH",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS",
)

SENTINEL = "SENTINEL-VALUE-1234"
SENTINEL_PREFIX = "SENTINEL-VALUE"


def base_env(extra: dict | None = None) -> dict[str, str]:
    """A clean child environment. A value of None in `extra` removes the key."""
    env = {k: os.environ[k] for k in _PASS_THROUGH if k in os.environ}
    env.update(
        HOME=str(_HOME),
        USERPROFILE=str(_HOME),
        PYTHONPATH=str(GATE_ROOT),
        PYTHONUTF8="1",
        PYTHONIOENCODING="utf-8",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=str(_HOME / ".gitconfig"),
        GIT_TERMINAL_PROMPT="0",
        GIT_AUTHOR_NAME="Spec Test",
        GIT_AUTHOR_EMAIL="spec-test@example.invalid",
        GIT_COMMITTER_NAME="Spec Test",
        GIT_COMMITTER_EMAIL="spec-test@example.invalid",
    )
    for k, v in (extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = str(v)
    return env


def git_env() -> dict[str, str]:
    env = base_env()
    env.pop("PYTHONPATH", None)
    return env


# --------------------------------------------------------------------------- running scripts


@dataclass
class Result:
    rc: int
    out: str
    err: str
    args: list
    elapsed: float

    @property
    def both(self) -> str:
        return f"{self.out}\n{self.err}"

    def describe(self) -> str:
        return (f"command: {' '.join(map(str, self.args))}\nexit code: {self.rc}\n"
                f"--- stdout ---\n{self.out}\n--- stderr ---\n{self.err}\n---")


def run_gate(module: str, *args, cwd=None, env=None, stdin: str | None = None,
             timeout: float = 180, pyflags: tuple = ("-P",)) -> Result:
    """Run `python -P -m gate.<module> ARGS` the way the contract says (C-1)."""
    cmd = [sys.executable, *pyflags, "-m", f"gate.{module}", *[str(a) for a in args]]
    t0 = time.monotonic()
    try:
        cp = subprocess.run(
            cmd, cwd=str(cwd) if cwd else str(_NEUTRAL_CWD), env=env if env is not None else base_env(),
            input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - failure path
        out = (exc.stdout or b"")
        err = (exc.stderr or b"")
        out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        err = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
        pytest.fail(f"{' '.join(cmd)} did not finish within {timeout}s\nstdout:\n{out}\nstderr:\n{err}")
    return Result(cp.returncode, cp.stdout, cp.stderr, cmd, time.monotonic() - t0)


def assert_rc(res: Result, expected: int) -> None:
    assert res.rc == expected, f"expected exit code {expected}\n{res.describe()}"


def assert_no_traceback(res: Result) -> None:
    assert "Traceback (most recent call last)" not in res.both, (
        f"an expected failure must print a short message, not a traceback (C-2)\n{res.describe()}")


def assert_refused(res: Result, code: int, *paths_must_not_exist) -> None:
    """A refusal: exact exit code, a short message, no traceback, nothing written."""
    assert_rc(res, code)
    assert_no_traceback(res)
    for p in paths_must_not_exist:
        assert not Path(p).exists(), f"{p} was written although the call was refused"


# --------------------------------------------------------------------------- files


def write_text(path, text: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode("utf-8"))
    return p


def write_bytes(path, data: bytes) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def write_json(path, obj) -> Path:
    return write_text(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


def read_json(path):
    p = Path(path)
    assert p.exists(), f"expected output file {p} was not written"
    return json.loads(p.read_text(encoding="utf-8"))


class NoOut:
    """Stands in for an --out file that was not written: any use of it fails with the command's own output."""

    def __init__(self, res, path):
        self._res, self._path = res, path

    def _fail(self, *a, **k):
        raise AssertionError(f"the output file {self._path} was not written\n{self._res.describe()}")

    __getitem__ = __iter__ = __contains__ = __len__ = get = keys = items = _fail

    def __bool__(self):
        return False


def load_out(res, path):
    """The JSON the script wrote to `path`, or a NoOut that explains what happened if it wrote nothing."""
    p = Path(path)
    return read_json(p) if p.exists() else NoOut(res, p)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def write_script(path, code: str) -> Path:
    return write_text(path, code.strip("\n") + "\n")


def tree_snapshot(root) -> dict[str, bytes]:
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


# --------------------------------------------------------------------------- quality.toml


def toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_val(x) for x in v) + "]"
    raise TypeError(f"cannot write {v!r} as TOML")


def _table(name: str, mapping: dict) -> str:
    lines = [f"[{name}]"]
    for k, v in mapping.items():
        lines.append(f"{k} = {toml_val(v)}")
    return "\n".join(lines) + "\n"


def make_config(path, *, baseline_sha: str = "a" * 40, integration_branch: str = "candidate/a",
                environment: dict | None = None, limits: dict | None = None, guard: dict | None = None,
                feedback: dict | None = None, spec_tests: dict | None = None,
                checks: dict | None = None, setup: dict | None = None, acceptance: dict | None = None,
                archive_accepted: list | None = None, raw_text: str = "") -> Path:
    project = {"baseline_sha": baseline_sha}
    if integration_branch is not None:   # None leaves project.integration_branch out of the file
        project["integration_branch"] = integration_branch
    parts = [_table("project", project)]
    if environment is not None:
        parts.append(_table("environment", environment))
    parts.append(_table("limits", limits if limits is not None else
                        {"max_turns": 40, "timeout_minutes": 60, "max_fix_rounds": 3}))
    parts.append(_table("guard", guard if guard is not None else {}))
    parts.append(_table("feedback", feedback if feedback is not None else
                        {"judge_workflow_path": ".github/workflows/judge.yml", "reviewer_app": "example-reviewer",
                         "executor_app": "example-executor"}))
    if acceptance is not None:
        parts.append(_table("acceptance", acceptance))
    for entry in archive_accepted or []:
        table = _table("archive.accepted_foreign_commits", entry)  # written as an array of tables
        parts.append(table.replace("[archive.accepted_foreign_commits]", "[[archive.accepted_foreign_commits]]", 1))
    parts.append(_table("spec_tests", spec_tests if spec_tests is not None else {"deny_read": ["src/**", "tests/**"]}))
    for cid, body in (checks or {}).items():
        parts.append(_table(f'checks."{cid}"', {k: v for k, v in body.items() if not isinstance(v, dict)}))
        for key, sub in body.items():
            if isinstance(sub, dict):  # for example the optional `env` table of a check
                parts.append(_table(f'checks."{cid}".{key}', sub))
    if setup is not None:
        parts.append(_table("setup", {k: v for k, v in setup.items() if not isinstance(v, dict)}))
        for key, sub in setup.items():
            if isinstance(sub, dict):
                parts.append(_table(f"setup.{key}", sub))
    if raw_text:
        parts.append(raw_text if raw_text.endswith("\n") else raw_text + "\n")
    return write_text(path, "\n".join(parts))


def py_cmd(script, *args) -> list[str]:
    """A check command that runs a helper script with the interpreter of this test run."""
    return [sys.executable, str(script), *[str(a) for a in args]]


# --------------------------------------------------------------------------- junit


def junit_xml(cases: list[tuple[str, str, str]]) -> str:
    """cases: (classname, name, status) with status pass | fail | error | skip."""
    from xml.sax.saxutils import quoteattr

    counts = {"fail": 0, "error": 0, "skip": 0}
    body = []
    for classname, name, status in cases:
        inner = ""
        if status == "fail":
            counts["fail"] += 1
            inner = '<failure message="assertion failed">AssertionError</failure>'
        elif status == "error":
            counts["error"] += 1
            inner = '<error message="boom">RuntimeError</error>'
        elif status == "skip":
            counts["skip"] += 1
            inner = '<skipped message="skipped"/>'
        elif status != "pass":
            raise ValueError(status)
        body.append(f"<testcase classname={quoteattr(classname)} name={quoteattr(name)} time=\"0.001\">{inner}</testcase>")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n<testsuites>'
        f'<testsuite name="pytest" tests="{len(cases)}" failures="{counts["fail"]}" '
        f'errors="{counts["error"]}" skipped="{counts["skip"]}">' + "".join(body) + "</testsuite></testsuites>\n"
    )


# --------------------------------------------------------------------------- @mentions

_CODE_SPAN = re.compile(r"(`+).+?\1", re.S)
_MENTION = re.compile(r"(?<![\w`])@[A-Za-z0-9][A-Za-z0-9_-]*")


def bare_mentions(text: str) -> list[str]:
    """Every `@word` that is not inside backticks (C-4, C-5)."""
    return _MENTION.findall(_CODE_SPAN.sub("", text))


# --------------------------------------------------------------------------- git


def run_git(cwd, *args, check: bool = True, input_bytes: bytes | None = None, env=None) -> subprocess.CompletedProcess:
    cp = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-c", "commit.gpgsign=false", *map(str, args)],
        cwd=str(cwd), env=env or git_env(), input=input_bytes, capture_output=True,
    )
    if check and cp.returncode != 0:
        raise AssertionError(f"git {' '.join(map(str, args))} failed ({cp.returncode}): "
                             f"{cp.stderr.decode('utf-8', 'replace')}")
    return cp


def git(cwd, *args, **kw) -> str:
    return run_git(cwd, *args, **kw).stdout.decode("utf-8", "replace").rstrip("\n")


class Repo:
    """A real temporary repository with a local test identity and autocrlf off."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        git(self.path, "init", "-q")
        git(self.path, "symbolic-ref", "HEAD", "refs/heads/main")
        for k, v in (("user.name", "Spec Test"), ("user.email", "spec-test@example.invalid"),
                     ("core.autocrlf", "false"), ("core.ignorecase", "false"), ("commit.gpgsign", "false")):
            git(self.path, "config", k, v)

    @classmethod
    def clone(cls, src, dst) -> "Repo":
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        git(dst.parent, "clone", "-q", "-c", "core.ignorecase=false", str(src), str(dst))
        obj = cls.__new__(cls)
        obj.path = dst
        return obj

    def git(self, *args, **kw) -> str:
        return git(self.path, *args, **kw)

    def write(self, rel: str, data) -> None:
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))

    def remove(self, rel: str) -> None:
        (self.path / rel).unlink()

    def mv(self, old: str, new: str) -> None:
        (self.path / new).parent.mkdir(parents=True, exist_ok=True)
        self.git("mv", old, new)

    def raw_add(self, rel: str, data) -> None:
        """Put a path in the index with exactly this spelling, whatever the file system says about case."""
        blob = run_git(self.path, "hash-object", "-w", "--stdin",
                       input_bytes=data if isinstance(data, bytes) else data.encode("utf-8")).stdout.decode().strip()
        self.git("update-index", "--add", "--cacheinfo", f"100644,{blob},{rel}")

    def commit(self, msg: str = "change", stage_all: bool = True, *, author_name: str | None = None,
               committer_name: str | None = None) -> str:
        if stage_all:
            self.git("add", "-A")
        env = git_env()
        if author_name:
            env["GIT_AUTHOR_NAME"] = author_name
        if committer_name:
            env["GIT_COMMITTER_NAME"] = committer_name
        self.git("commit", "-q", "--allow-empty", "-m", msg, env=env)
        return self.sha()

    def branch(self, name: str, start: str = "HEAD") -> None:
        self.git("checkout", "-q", "-b", name, start)

    def checkout(self, name: str) -> None:
        self.git("checkout", "-q", name)

    def sha(self, ref: str = "HEAD") -> str:
        return self.git("rev-parse", ref)


def make_bare(path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    git(p, "init", "-q", "--bare")
    return p


def remote_url(bare) -> str:
    return str(bare)


def push_to(repo: Repo, bare, refspec: str = "main") -> None:
    repo.git("push", "-q", str(bare), refspec)


def branch_tip(bare, branch: str) -> str | None:
    cp = run_git(bare, "rev-parse", "--verify", "-q", f"refs/heads/{branch}", check=False)
    return cp.stdout.decode().strip() if cp.returncode == 0 else None


def branch_files(bare, branch: str, ref: str | None = None) -> dict[str, bytes] | None:
    tip = ref or branch_tip(bare, branch)
    if tip is None:
        return None
    raw = run_git(bare, "ls-tree", "-r", "-z", "--full-tree", tip).stdout
    files = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        meta, _, path = entry.partition(b"\t")
        blob = meta.split()[2].decode()
        files[path.decode("utf-8")] = run_git(bare, "cat-file", "blob", blob).stdout
    return files


def rev_list(bare, ref: str) -> list[str]:
    return git(bare, "rev-list", ref).split()


def parents_of(bare, sha: str) -> list[str]:
    parts = git(bare, "rev-list", "--parents", "-n", "1", sha).split()
    return parts[1:]


# --------------------------------------------------------------------------- local HTTP stub


class Req:
    def __init__(self, method, path, query, headers, body):
        self.method, self.path, self.query, self.headers, self.body = method, path, query, headers, body

    def json(self):
        return json.loads(self.body.decode("utf-8")) if self.body else None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")

    def q(self, name: str) -> str | None:
        v = self.query.get(name)
        return v[0] if v else None

    def __repr__(self):
        return f"<Req {self.method} {self.path}?{self.query}>"


class StubServer:
    """A small stand-in for the GitHub API. Routes are matched in the order they were added."""

    def __init__(self):
        self.requests: list[Req] = []
        self._routes: list = []
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None

    def route(self, method: str, pattern: str, handler) -> None:
        """handler: a callable(Req) -> response, or a fixed response.
        A response is (status, body) or (status, body, headers); body is bytes, str, dict or list."""
        self._routes.append((method.upper(), re.compile(pattern), handler))

    def prepend(self, method: str, pattern: str, handler) -> None:
        self._routes.insert(0, (method.upper(), re.compile(pattern), handler))

    def _dispatch(self, req: Req):
        for method, rx, handler in self._routes:
            if method == req.method and rx.fullmatch(req.path):
                resp = handler(req) if callable(handler) else handler
                if len(resp) == 2:
                    resp = (*resp, {})
                return resp
        return 404, {"message": "Not Found"}, {}

    def start(self) -> "StubServer":
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):  # silence
                pass

            def _serve(self):
                parts = urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                req = Req(self.command, unquote(parts.path), parse_qs(parts.query),
                          {k.lower(): v for k, v in self.headers.items()}, body)
                with server._lock:
                    server.requests.append(req)
                status, payload, headers = server._dispatch(req)
                ctype = "text/plain; charset=utf-8"
                if isinstance(payload, (dict, list)):
                    payload, ctype = json.dumps(payload).encode("utf-8"), "application/json"
                elif isinstance(payload, str):
                    payload = payload.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", headers.get("Content-Type", ctype))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _serve

        self._httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._httpd.server_address[1]}"

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    def reqs(self, method: str | None = None, path: str | None = None) -> list[Req]:
        with self._lock:
            found = list(self.requests)
        if method:
            found = [r for r in found if r.method == method.upper()]
        if path:
            found = [r for r in found if re.fullmatch(path, r.path)]
        return found

    def posts(self) -> list[Req]:
        return self.reqs("POST")


def closed_port_url() -> str:
    """A URL on which nothing listens (a network error for the caller)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def assert_not_leaked(texts: dict[str, str], *needles: str) -> None:
    for where, text in texts.items():
        for n in needles:
            assert n not in text, f"{n!r} leaked into {where}"
