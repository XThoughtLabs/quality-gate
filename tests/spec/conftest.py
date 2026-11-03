"""Spec tests for the quality gate. They are written from CONTRACTS.md only.

GATE_ROOT must name the root folder of the code under test. Every script is reached
through `python -P -m gate.<name>` with PYTHONPATH=GATE_ROOT; workflows and
ACTIONS-LOCK.md are read from GATE_ROOT.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def _check_gate_root() -> Path:
    value = os.environ.get("GATE_ROOT")
    if not value:
        raise pytest.UsageError(
            "GATE_ROOT is not set. Point it at the root folder of the code under test, "
            "for example: set GATE_ROOT=C:\\path\\to\\quality-gate"
        )
    root = Path(value)
    if not root.is_dir():
        raise pytest.UsageError(f"GATE_ROOT={value!r} is not an existing folder")
    return root


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "req(rule_id, ...): the CONTRACTS.md rule(s) this test checks, for example req('G-1')",
    )
    _check_gate_root()


def pytest_report_header(config):
    return f"GATE_ROOT={os.environ.get('GATE_ROOT')}"


def pytest_collection_modifyitems(config, items):
    missing = [i.nodeid for i in items if not list(i.iter_markers("req"))]
    if missing:
        raise pytest.UsageError("tests without a @pytest.mark.req(...) marker:\n  " + "\n  ".join(missing))


@pytest.fixture
def stub():
    from gatekit import StubServer

    server = StubServer().start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(scope="session")
def baseline(tmp_path_factory):
    """The synthetic repository that the guard tests change (see guardkit.py)."""
    from guardkit import build_baseline

    return build_baseline(tmp_path_factory)
