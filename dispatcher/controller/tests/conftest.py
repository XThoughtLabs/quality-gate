"""Fixtures for the controller's tests, written from CONTROLLER-CONTRACT.md before the code.

The controller (`xtl_controller.py`, one folder up) is imported lazily inside the `controller` fixture, so the tests
collect while it does not exist yet. Every run goes through `main(argv, http=..., windows=..., sleep=..., clock=...)`
with the fake GitHub of fake_github.py: no network, no real key (a throwaway RSA key made here), no real Windows ACL.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TESTS_DIR = Path(__file__).resolve().parent
CONTROLLER_DIR = TESTS_DIR.parent
REPO_ROOT = CONTROLLER_DIR.parent.parent
for p in (str(TESTS_DIR), str(CONTROLLER_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import fake_github as F  # noqa: E402


@pytest.fixture(scope="session")
def controller():
    return importlib.import_module("xtl_controller")


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def queue_document(tasks=None, **overrides) -> dict:
    doc = {
        "format": "xtl-stage-a-queue/1",
        "queue_id": "SA1",
        "repository": F.REPO,
        "integration_branch": F.BASE,
        "base_sha": F.BASE_TIP,
        "defects_sha": "f" * 40,
        "tasks": [
            {"id": tid, "title": title, "text": f"What is wrong in {tid}.", "expected": "A new regression test.",
             "depends_on": []}
            for tid, title in (tasks if tasks is not None else F.TASKS)
        ],
    }
    doc.update(overrides)
    return doc


def config_text(key_path: Path, log_path: Path, **override) -> str:
    values = {
        "app_id": str(F.APP_ID), "installation_id": str(F.INSTALLATION_ID),
        "key_file": f"'{key_path}'", "log_file": f"'{log_path}'",
        "base_branch": f'"{F.BASE}"', "reports_branch": '"reports"',
        "exec_slug": f'"{F.EXECUTOR_SLUG}"', "exec_app": str(F.EXECUTOR_APP), "exec_bot": str(F.EXECUTOR_BOT),
        "rev_slug": f'"{F.REVIEWER_SLUG}"', "rev_app": str(F.REVIEWER_APP), "rev_bot": str(F.REVIEWER_BOT),
        "actions": str(F.ACTIONS), "checks": json.dumps(F.GATE_CHECKS), "policy": f'"{F.POLICY}"',
        "code_folders": '["workflow/"]', "test_folder": '"tests/"',
    }
    values.update(override)
    return f"""[controller]
app_id = {values['app_id']}
installation_id = {values['installation_id']}
key_file = {values['key_file']}
log_file = {values['log_file']}
base_branch = {values['base_branch']}
reports_branch = {values['reports_branch']}

[executor]
app_slug = {values['exec_slug']}
app_id = {values['exec_app']}
bot_id = {values['exec_bot']}

[reviewer]
app_slug = {values['rev_slug']}
app_id = {values['rev_app']}
bot_id = {values['rev_bot']}

[gate]
actions_app_id = {values['actions']}
checks = {values['checks']}
policy_check = {values['policy']}

[policy]
code_folders = {values['code_folders']}
test_folder = {values['test_folder']}
"""


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def stop_lines(self) -> list[str]:
        return [line for line in self.out.splitlines() if line.startswith("CONTROLLER ")]

    @property
    def stop(self) -> str:
        lines = self.stop_lines
        return lines[0] if len(lines) == 1 else f"<{len(lines)} stop lines>"


class World:
    def __init__(self, tmp_path: Path, controller, rsa_key, capsys) -> None:
        self.tmp = tmp_path
        self.controller = controller
        self.capsys = capsys
        self.gh = F.FakeGitHub(rsa_key.public_key())
        self.win = F.FakeWindows()
        self.sleeps: list = []
        keys = tmp_path / "keys"
        keys.mkdir()
        self.key_file = keys / "controller.pem"
        self.pem = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                         serialization.NoEncryption())
        self.key_file.write_bytes(self.pem)
        self.log_file = tmp_path / "log" / "controller.jsonl"
        self.config_file = tmp_path / "controller.toml"
        self.config_file.write_text(config_text(self.key_file, self.log_file), encoding="utf-8")
        self.queue_file = tmp_path / "queue" / "queue.json"
        self.queue_file.parent.mkdir()
        self.set_queue(queue_document())

    def set_queue(self, doc: dict | None = None, raw: bytes | None = None) -> None:
        data = raw if raw is not None else json.dumps(doc, indent=2).encode("utf-8")
        self.queue_file.write_bytes(data)
        self.queue_sha = hashlib.sha256(data).hexdigest()

    def set_config(self, **override) -> None:
        self.config_file.write_text(config_text(self.key_file, self.log_file, **override), encoding="utf-8")

    def argv(self, **override) -> list[str]:
        values = {"--config": str(self.config_file), "--repo": F.REPO, "--pr": str(F.PR),
                  "--queue": str(self.queue_file), "--queue-sha256": self.queue_sha}
        values.update(override)
        argv: list[str] = []
        for key, value in values.items():
            if value is not None:
                argv += [key, value]
        return argv

    def run(self, argv: list[str] | None = None) -> Result:
        code = self.controller.main(argv if argv is not None else self.argv(), http=self.gh.handle,
                                    windows=self.win, sleep=self.sleeps.append, clock=lambda: F.NOW)
        captured = self.capsys.readouterr()
        return Result(code, captured.out, captured.err)

    def log_lines(self) -> list[dict]:
        if not self.log_file.exists():
            return []
        return [json.loads(line) for line in self.log_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    def last_record(self) -> dict:
        lines = self.log_lines()
        return lines[-1] if lines else {}

    def rule(self, rule_id: str) -> dict:
        return self.last_record().get("rules", {}).get(rule_id, {})


@pytest.fixture
def world(tmp_path, controller, rsa_key, capsys):
    return World(tmp_path, controller, rsa_key, capsys)
