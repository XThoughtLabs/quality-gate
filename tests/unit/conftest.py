"""Helpers for the gate's own tests. Synthetic data only; no network beyond localhost."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
KEPT_VARIABLES = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")


def clean_env(**extra: str) -> dict[str, str]:
    """An environment without the developer's own secrets."""
    env = {name: os.environ[name] for name in KEPT_VARIABLES if name in os.environ}
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def run_gate(module: str, *args: object, env: dict[str, str] | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-P", "-m", f"gate.{module}", *map(str, args)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env or clean_env(),
        cwd=cwd,
        check=False,
    )


def git(cwd: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "user.name=test", "-c", "user.email=test@example.invalid", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError(f"git {args} failed: {process.stderr}")
    return process.stdout.strip()


class Stub:
    """A local stand-in for the GitHub API. Records what it receives."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.routes: dict[tuple[str, str], tuple[int, object]] = {}
        self.default_post = 403
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                stub.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "body": json.loads(body) if body else None,
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                path = self.path.split("&page=")[0].split("?page=")[0]
                status, payload = stub.routes.get((self.command, path), (None, None))
                if status is None:
                    status, payload = (200, {}) if self.command == "GET" else (stub.default_post, {})
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _serve
            do_POST = _serve

            def log_message(self, *_args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    server = Stub()
    yield server
    server.close()


@pytest.fixture
def gate():
    """The helpers, as one object: fixtures are the way to share them under importlib mode."""

    class Helpers:
        root = ROOT
        env = staticmethod(clean_env)
        run = staticmethod(run_gate)
        git = staticmethod(git)

    return Helpers


@pytest.fixture
def short_tmp(tmp_path: Path):
    yield tmp_path
    shutil.rmtree(tmp_path, ignore_errors=True)
