"""Fixtures for the negative tool's tests, written from NEGATIVE-CONTRACT.md.

The tool (`xtl_negative.py`, one folder up) is imported lazily inside the `neg` fixture, so collection works while it
does not exist yet. Every test runs with the network blocked at the socket level, and with `urllib.request`'s HTTPS
and HTTP handlers replaced by the in-memory fake GitHub of `fake_github.py` (the seam of NC-8). The key is a
throwaway RSA key made for this session only.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import socket
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TESTS_DIR = Path(__file__).resolve().parent
TOOL_DIR = TESTS_DIR.parent
REPO_ROOT = TOOL_DIR.parents[1]
LAUNCHER_FILE = REPO_ROOT / "launcher" / "xtl_launcher.py"
for p in (str(TESTS_DIR), str(TOOL_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fake_github import FakeGitHub  # noqa: E402

REPOSITORY = "ExampleOrg/demo-stand"
BASE = "candidate/a"
APP_ID = 424242
INSTALLATION_ID = 5151

# Excerpts of the demo repository's files at 310f0ba around each anchor (NC-10), with the anchor exactly once.
TEST_API = (
    b'import csv\nimport io\nimport pytest\n\n\n'
    b'def test_health(client):\n    assert client.get("/health").json()["status"] == "ok"\n\n\n'
    b'@pytest.mark.parametrize("path", ["/users", "/tasks", "/tasks/1", "/tasks/export"])\n'
    b'def test_authentication_required(client, path):\n    assert client.get(path).status_code == 401\n\n\n'
    b'def test_bad_token(client):\n'
    b'    assert client.get("/tasks", headers={"Authorization": "Bearer unknown"}).status_code == 401\n'
)
ACCEPTANCE = (
    b'"""Acceptance tests for SPEC.md section 1: identity and visibility.\n"""\n\n'
    b'import csv\nimport io\nfrom contextlib import contextmanager\n\nimport pytest\n\n'
    b'TOKENS = {\n    "admin": "demo-admin",\n    "alice": "demo-alice",\n}\n'
    b'NOT_FOUND = {"detail": "task not found"}\nMISSING_TASK_ID = 999_999\n'
    b'INVALID_TOKEN = {"Authorization": "Bearer not-a-fixture-token"}\n'
)
INIT = b'"""WorkFlow API: synthetic hiring exercise, not a production service."""\n\n__version__ = "0.1.0"\n'
FILES = {
    "tests/test_api.py": TEST_API,
    "acceptance/test_spec_1_identity_and_visibility.py": ACCEPTANCE,
    "workflow/__init__.py": INIT,
}
CASE_PATHS = {"N1": "tests/test_api.py", "N2": "acceptance/test_spec_1_identity_and_visibility.py",
              "N3": "workflow/__init__.py"}


@pytest.fixture(scope="session")
def neg():
    return importlib.import_module("xtl_negative")


@pytest.fixture(scope="session")
def launcher_ref():
    """The launcher's own module, loaded by file path, as the reference for NC-3, NC-5 and NC-7."""
    spec = importlib.util.spec_from_file_location("xtl_launcher_reference", LAUNCHER_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass
class KeyMaterial:
    pem: bytes
    public_key: object
    lines: list


@pytest.fixture(scope="session")
def test_key():
    """A throwaway RSA key, made for this session only. Never a real key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    lines = [line.strip() for line in pem.decode("ascii").splitlines() if line.strip()]
    return KeyMaterial(pem=pem, public_key=key.public_key(), lines=lines)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test may reach a real network: sockets refuse to connect or resolve."""
    def blocked(*args, **kwargs):
        raise RuntimeError("network blocked in tests")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


def app_data(**changes) -> dict:
    data = {"app_id": APP_ID, "installation_id": INSTALLATION_ID, "slug": "xtl-stage-a-executor",
            "repository": REPOSITORY, "executor_user": "executor-user", "executor_sid": "S-1-5-21-1-2-3-1007",
            "ceo_sid": "S-1-5-21-1-2-3-1002"}
    data.update(changes)
    return data


@dataclass
class Result:
    code: int
    out: str
    err: str
    log_lines: list = field(default_factory=list)

    @property
    def stop_line(self) -> str:
        lines = self.out.strip().splitlines()
        return lines[-1] if lines else ""

    @property
    def record(self) -> dict:
        return json.loads(self.log_lines[-1])


class World:
    def __init__(self, root: Path, test_key: KeyMaterial, monkeypatch, capsys, neg_loader) -> None:
        self.root = root
        self.key = test_key
        self.capsys = capsys
        self.neg_loader = neg_loader
        self.keys = root / "keys"
        self.keys.mkdir()
        self.key_file = self.keys / "executor.pem"
        self.key_file.write_bytes(test_key.pem)
        self.app_file = self.keys / "executor.app.json"
        self.app_file.write_text(json.dumps(app_data(), indent=2) + "\n", encoding="ascii")
        self.log = root / "logs" / "negative.jsonl"
        self.fake = FakeGitHub(test_key.public_key, app_id=APP_ID, installation_id=INSTALLATION_ID,
                               repository=REPOSITORY, base=BASE, files=FILES)
        https, http = self.fake.handler_classes()
        monkeypatch.setattr(urllib.request, "HTTPSHandler", https)
        monkeypatch.setattr(urllib.request, "HTTPHandler", http)

    def argv(self, case_name: str = "N1", **changes) -> list[str]:
        options = {"--case": case_name, "--key-file": str(self.key_file), "--app-file": str(self.app_file),
                   "--repo": REPOSITORY, "--base": BASE, "--branch": f"ai/90-negative-{case_name.lower()}",
                   "--log": str(self.log)}
        for key, value in changes.items():
            options["--" + key.replace("_", "-")] = value
        argv: list[str] = []
        for key, value in options.items():
            if value is not None:
                argv += [key, value]
        return argv

    def run(self, case_name: str = "N1", argv: list[str] | None = None, **changes) -> Result:
        neg = self.neg_loader()
        self.capsys.readouterr()
        code = neg.main(argv if argv is not None else self.argv(case_name, **changes))
        captured = self.capsys.readouterr()
        lines = self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []
        return Result(code=code, out=captured.out, err=captured.err, log_lines=lines)

    def secrets(self) -> list[str]:
        return [s for s in self.key.lines + self.fake.tokens + self.fake.jwts if s]


@pytest.fixture
def world(tmp_path, test_key, monkeypatch, capsys):
    return World(tmp_path, test_key, monkeypatch, capsys, lambda: importlib.import_module("xtl_negative"))
