"""Stage A: explicit configuration (LR-63).

Written from LAUNCHER-CONTRACT.md section 12. These tests read the launcher's files as text and
TOML; they do not read the code's logic."""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import PureWindowsPath

import pytest

import launcher_world as W

PILOT_VALUES = ("mp-claude", "gate-practice-app", "xtl-gate-executor", "xtl-gate-reviewer", "codex-candidate")
# Shown in place of the operator's own name, so that a failure's message and log never hold the name itself.
OPERATOR_NAME = "<the operator's own name, from USERNAME or USERPROFILE>"
REQUIRED_KEYS = {"key_file", "app_file", "runs_dir", "claude_command", "app_python", "deny_read_paths",
                 "must_not_open", "ledger_file", "max_messages_attempt", "max_messages_task", "max_runs_task"}
PUBLIC_DEFAULTS = {"api_url": "https://api.github.com",
                   "gate_url": "https://github.com/XThoughtLabs/quality-gate.git"}
PILOT_HEADING = "## The pilot's example"


def generic_part(text: str) -> str:
    """The text before a section headed as the pilot's example, which may keep the pilot's values."""
    return text.split(PILOT_HEADING, 1)[0]


def operator_names() -> tuple[str, ...]:
    """The operator's own names, read at run time and never written into this file: the Windows user name
    (USERNAME) and the last part of the profile folder (USERPROFILE). Unset or empty values are left out."""
    names = (os.environ.get("USERNAME", ""), PureWindowsPath(os.environ.get("USERPROFILE", "")).name)
    return tuple(dict.fromkeys(name.strip() for name in names if name.strip()))


def pilot_values_in(text: str) -> list[str]:
    """The pilot's values the text holds, and OPERATOR_NAME once if it holds one of the operator's own names
    (compared without regard to case, as Windows compares user names)."""
    found = [value for value in PILOT_VALUES if value in text]
    if any(name.lower() in text.lower() for name in operator_names()):
        found.append(OPERATOR_NAME)
    return found


def strings_in(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings_in(item)


@pytest.mark.lr(63)
def test_lr63_the_example_configuration_shows_every_key_with_placeholders():
    example = tomllib.loads((W.LAUNCHER_DIR / "launcher.example.toml").read_text(encoding="utf-8"))
    section = example["launcher"]
    missing = REQUIRED_KEYS - set(section)
    assert not missing, f"launcher.example.toml lacks {sorted(missing)}"
    for key, value in section.items():
        if key in PUBLIC_DEFAULTS:
            assert value == PUBLIC_DEFAULTS[key], key
            continue
        if isinstance(value, int):
            continue
        for text in strings_in(value):
            assert "<" in text and ">" in text, f"{key} holds a value that is not a placeholder: {text!r}"
    assert (section["max_messages_attempt"], section["max_messages_task"], section["max_runs_task"]) == (80, 240, 3)


@pytest.mark.lr(63)
@pytest.mark.parametrize("name", ["README.md", "INSTRUCTION-CEO.md", "launcher.example.toml"])
def test_lr63_the_documents_are_generic(name):
    text = generic_part((W.LAUNCHER_DIR / name).read_text(encoding="utf-8"))
    found = pilot_values_in(text)
    assert not found, f"{name} names the pilot's {found} outside a section marked as the pilot's example"
    concrete_users = [m for m in re.findall(r"C:\\Users\\[^\\<\s'\"`]+", text) if not m.endswith("Public")]
    assert not concrete_users, f"{name} names a concrete user folder: {concrete_users}"


@pytest.mark.lr(63)
def test_lr63_the_code_holds_no_pilot_value():
    """A guard: the code's defaults hold none of the pilot's values (it held none at the base either)."""
    text = (W.LAUNCHER_DIR / "xtl_launcher.py").read_text(encoding="utf-8")
    found = pilot_values_in(text)
    assert not found, found
    assert "C:\\\\xtl" not in text and "C:\\xtl" not in text


@pytest.mark.lr(63)
def test_lr63_the_check_takes_the_operators_name_at_run_time(monkeypatch):
    """The check of the examples finds the operator's own Windows user name and profile folder name, read at
    run time (HQ-TASK-M1-A5 section 4 D): planted into a copy of the real example, each is reported; the real
    example, and a run where neither variable is set, report nothing."""
    monkeypatch.setenv("USERNAME", "planted-user-a5")
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\planted-profile-a5")
    example = generic_part((W.LAUNCHER_DIR / "launcher.example.toml").read_text(encoding="utf-8"))
    assert "<" in example
    assert pilot_values_in(example) == []
    by_user = example.replace("<", "Planted-User-A5 <", 1)
    by_profile = example.replace("<", "C:\\Users\\planted-profile-a5\\keys <", 1)
    assert pilot_values_in(by_user) == [OPERATOR_NAME]
    assert pilot_values_in(by_profile) == [OPERATOR_NAME]
    monkeypatch.delenv("USERNAME")
    monkeypatch.delenv("USERPROFILE")
    assert operator_names() == ()
    assert pilot_values_in(by_user) == []
