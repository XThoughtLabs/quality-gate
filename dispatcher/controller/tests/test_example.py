"""CR-1a: the example configuration holds every key and nothing personal."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

import pytest

from conftest import CONTROLLER_DIR

EXAMPLE = CONTROLLER_DIR / "controller.example.toml"


@pytest.mark.cr("CR-1a")
def test_example_has_exactly_the_contracts_tables_and_keys(controller):
    data = tomllib.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert {table: set(keys) for table, keys in data.items()} == \
        {table: set(keys) for table, keys in controller.CONFIG_SCHEMA.items()}


@pytest.mark.cr("CR-1a")
def test_example_and_code_hold_no_personal_name():
    """The operator's Windows user name and profile folder are read at run time, never written into this test."""
    names = {value.lower() for value in (os.environ.get("USERNAME", ""), Path(os.environ.get("USERPROFILE", "")).name)
             if len(value) >= 3}
    for path in (EXAMPLE, CONTROLLER_DIR / "xtl_controller.py", CONTROLLER_DIR / "CONTROLLER-CONTRACT.md"):
        text = path.read_text(encoding="utf-8").lower()
        assert not re.search(r"c:\\users\\(?!<)", text), f"{path.name} holds a profile path"
        for name in names:
            assert name not in text, f"{path.name} holds the operator's name (<name>)"
