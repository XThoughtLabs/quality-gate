"""Fixtures for the launcher's spec-only tests.

The launcher (`xtl_launcher.py`, one folder up) is imported lazily inside
the `launcher` fixture, so collection works while it does not exist yet.
"""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

TESTS_DIR = Path(__file__).resolve().parent
LAUNCHER_DIR = TESTS_DIR.parent
for p in (str(TESTS_DIR), str(LAUNCHER_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import launcher_world as W  # noqa: E402

W.install_audit_hook()


# ---------------------------------------------------------------- session
@pytest.fixture(scope="session")
def launcher():
    return importlib.import_module("xtl_launcher")


@dataclass
class KeyMaterial:
    pem: bytes
    public_key: object
    lines: list


@pytest.fixture(scope="session")
def test_key():
    """A throwaway RSA key, made for this session only."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    lines = [ln.strip() for ln in pem.decode("ascii").splitlines() if ln.strip()]
    return KeyMaterial(pem=pem, public_key=key.public_key(), lines=lines)


@pytest.fixture(scope="session")
def template(tmp_path_factory):
    root = tmp_path_factory.mktemp("template")
    remote = root / "remote.git"
    with W.quiet_audit():
        facts = W.build_template_remote(remote)
    return remote, facts


@pytest.fixture(scope="session")
def gate_at_pin(tmp_path_factory):
    """The pinned gate, for the harness's own checks of the fakes."""
    root = tmp_path_factory.mktemp("gatepin") / "gate"
    with W.quiet_audit():
        subprocess.run(["git", "clone", "-q", W.GATE_URL, str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "checkout", "-q", W.GATE_PIN], check=True)
    return root


def make_world(root: Path, mp, launcher, test_key, template) -> W.World:
    remote, facts = template
    return W.World(root, key=test_key, template_remote=remote, facts=facts,
                   monkeypatch=mp, launcher=launcher)


@pytest.fixture
def world(tmp_path, monkeypatch, launcher, test_key, template):
    w = make_world(tmp_path / "w", monkeypatch, launcher, test_key, template)
    yield w
    w.close()


def shared_run(tmp_path_factory, name, launcher, test_key, template, prepare, args, steps):
    """One run shared by several tests of a module, to keep the suite fast."""
    mp = pytest.MonkeyPatch()
    w = make_world(tmp_path_factory.mktemp(name), mp, launcher, test_key, template)
    try:
        if prepare is not None:
            prepare(w, mp)
        res = w.run(*args, steps=steps)
    finally:
        w.close()
        mp.undo()
    return res


# ---------------------------------------------------------------- checks
def secrets_of(res: W.RunResult, key: KeyMaterial) -> list[str]:
    api = res.world.api
    # A key's last body line can be a few characters long and match by chance;
    # lines of 16 characters or more are compared.
    found = list(api.tokens_issued) + list(api.jwts) + [ln for ln in key.lines if len(ln) >= 16]
    for tok in api.tokens_issued:
        header = W.basic_header(tok)
        found += [header, header.split("basic ", 1)[1]]
    for req in api.requests:
        value = req["headers"].get("Authorization")
        if value:
            found.append(value)
    return [s for s in found if s]


def assert_no_secret_leak(res: W.RunResult, key: KeyMaterial):
    """LR-50: no token, JWT, key line or Authorization value in stdout,
    stderr or the log, whatever the outcome."""
    places = {"stdout": res.stdout, "stderr": res.stderr, "log": res.log_text}
    for secret in secrets_of(res, key):
        for where, text in places.items():
            assert secret not in text, f"a secret ({secret[:6]}...) appears in {where}"


def assert_routes_allowed(res: W.RunResult):
    """LR-41: every request is a method and route of the table."""
    bad = W.disallowed_requests(res.world.api.requests)
    assert bad == [], f"requests outside LR-41's table: {bad}"


def assert_tokens_revoked(res: W.RunResult):
    """LR-14: a run that minted a token revokes it, however it ends."""
    api = res.world.api
    missing = [t[:6] for t in api.tokens_issued if t not in api.tokens_revoked]
    assert not missing, f"tokens not revoked: {missing}\n{res.describe()}"
    if api.tokens_issued:
        assert "token revoked" in res.log_text, res.describe()


def assert_harness_ok(res: W.RunResult):
    """A step of the fake claude that failed is a fault of the harness, not
    of the launcher (the fake exits 97 and writes why)."""
    assert res.model_error is None, f"HARNESS FAULT: {res.model_error}"


def assert_common(res: W.RunResult, key: KeyMaterial):
    assert_harness_ok(res)
    assert_routes_allowed(res)
    assert_tokens_revoked(res)
    assert_no_secret_leak(res, key)


def assert_stopped(res: W.RunResult, code: str, key: KeyMaterial):
    assert_harness_ok(res)
    assert res.exc is None, res.describe()
    assert res.code == 1, res.describe()
    assert res.last.startswith(f"STOPPED {code}: "), res.describe()
    assert code in res.log_text, f"the log does not record {code}\n{res.describe()}"
    assert_common(res, key)


def assert_preflight_stop(res: W.RunResult, code: str, key: KeyMaterial):
    """A preflight refusal: no request, no clone, no run folder, a log."""
    assert_stopped(res, code, key)
    assert res.requests == [], [f"{r['method']} {r['path']}" for r in res.requests]
    assert res.run_dirs == [], res.run_dirs
    assert not any("clone" in (e.get("argv") or []) for e in res.events), "a clone was started"
    assert res.model is None, "the model ran"
    assert_only_the_log_under_runs_dir(res)
    assert not res.pushed


def assert_only_the_log_under_runs_dir(res: W.RunResult):
    """Section 3 / LR-49: the preflight writes nothing under runs_dir but
    the run's log, `runs_dir/logs/<run id>.log`."""
    assert len(res.logs) == 1, f"expected one log under runs_dir/logs, found {list(res.logs)}"
    runs = res.world.runs_dir
    files = sorted(p for p in runs.rglob("*") if p.is_file())
    assert [p.relative_to(runs).as_posix() for p in files] == [f"logs/{next(iter(res.logs))}"]


def assert_post_model_stop(res: W.RunResult, code: str, key: KeyMaterial):
    """A refusal after the model: nothing pushed, the token revoked."""
    assert_stopped(res, code, key)
    assert res.model is not None, "the model did not run"
    assert not res.pushed, f"the remote changed: {res.refs_before} -> {res.refs_after}"
    assert res.world.api.requests_to("POST", r"/pulls$") == []
    assert res.git_commands("push") == [], "git push was started"


def assert_config_error(res: W.RunResult):
    assert res.exc is None, res.describe()
    assert res.code == 2, res.describe()
    assert res.last.startswith("CONFIG: "), res.describe()
    assert res.world.api.requests == [], "a request reached the API"
    assert res.run_dirs == []
    assert res.model is None


def assert_success(res: W.RunResult, key: KeyMaterial):
    assert res.exc is None, res.describe()
    assert res.code == 0, res.describe()
    assert_common(res, key)


@pytest.fixture
def check(test_key):
    """The shared assertions, bound to the session's key."""

    class Check:
        stopped = staticmethod(lambda res, code: assert_stopped(res, code, test_key))
        preflight_stop = staticmethod(lambda res, code: assert_preflight_stop(res, code, test_key))
        post_model_stop = staticmethod(lambda res, code: assert_post_model_stop(res, code, test_key))
        config_error = staticmethod(assert_config_error)
        success = staticmethod(lambda res: assert_success(res, test_key))
        common = staticmethod(lambda res: assert_common(res, test_key))
        no_leak = staticmethod(lambda res: assert_no_secret_leak(res, test_key))
        routes = staticmethod(assert_routes_allowed)
        revoked = staticmethod(assert_tokens_revoked)

    return Check


UTC_STAMP = re.compile(r"(\d{4})-?(\d{2})-?(\d{2})[T _]?(\d{2}):?(\d{2}):?(\d{2})")


def pytest_configure(config):
    config.addinivalue_line("markers", "lr(n): the contract rule a test checks")
