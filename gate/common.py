"""Shared helpers for the gate's scripts. Standard library only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

EXIT_OK = 0
EXIT_RULE_FAILED = 1
EXIT_USAGE = 2

TIMEOUT_EXIT = 124
NOT_FOUND_EXIT = 127

MANDATORY_CHECKS = (
    "gate/env",
    "gate/tests",
    "gate/acceptance",
    "gate/guard",
    "gate/security",
    "gate/report",
    "gate/archive",
    "gate/final",
)
DIAGNOSTIC_CHECKS = (
    "diag/coverage",
    "diag/mypy",
    "diag/ruff",
    "diag/semgrep",
    "diag/schemathesis",
    "diag/mutation",
    "diag/benchmark",
)
# Fixed before the start and never reclassified after a failure (design section 6).
FIXED_CLASSES = {
    **{check: "mandatory" for check in MANDATORY_CHECKS},
    **{check: "diagnostic" for check in DIAGNOSTIC_CHECKS},
}

MENTION = "`@claude`"

_MENTION_RE = re.compile(r"@(?=[A-Za-z0-9_-])[A-Za-z0-9_./-]*")


class UsageError(Exception):
    """A usage or configuration error: exit code 2."""


def slug(check_id: str) -> str:
    return check_id.replace("/", "-")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path | str, data: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def read_json(path: Path | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_json_or_none(path: Path | str) -> Any:
    """Read a JSON file that may be missing or malformed (untrusted input)."""
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def neutralize(text: Any) -> str:
    """Make untrusted text safe to post.

    Backticks are replaced first, so that untrusted text cannot open or close a
    code span. Every @word then goes inside its own backticks, which GitHub does
    not treat as a mention. Angle brackets are escaped, so that no hidden HTML
    comment or tag survives.
    """
    value = str(text).replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
    return _MENTION_RE.sub(lambda match: f"`{match.group(0)}`", value)


def load_config(path: Path | str) -> dict[str, Any]:
    """Load quality.toml and refuse any change to the fixed check classes."""
    config_path = Path(path)
    try:
        raw = config_path.read_bytes()
    except OSError as error:
        raise UsageError(f"cannot read configuration {config_path.name}: {error.strerror}") from error
    try:
        config = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise UsageError(f"configuration {config_path.name} is not valid TOML: {error}") from error

    checks = config.get("checks", {})
    if not isinstance(checks, dict):
        raise UsageError("[checks] must be a table")
    for check_id, check in checks.items():
        if check_id not in FIXED_CLASSES:
            raise UsageError(f"unknown check in configuration: {check_id}")
        if not isinstance(check, dict):
            raise UsageError(f"check {check_id} must be a table")
        declared = check.get("class", FIXED_CLASSES[check_id])
        if declared != FIXED_CLASSES[check_id]:
            raise UsageError(
                f"check {check_id} is fixed as {FIXED_CLASSES[check_id]}; "
                f"the configuration says {declared}"
            )
    return config


def config_hash(path: Path | str) -> str:
    return sha256_file(Path(path))


def kill_tree(process: subprocess.Popen) -> None:
    """Kill a process and its children."""
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def popen_kwargs() -> dict[str, Any]:
    """Start a child in its own group, so that a timeout can kill its children."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def run_command(
    argv: list[str],
    log_path: Path,
    cwd: Path | str | None,
    timeout: float,
    env: dict[str, str] | None = None,
) -> tuple[int, float]:
    """Run one command into a log file. Return its numeric exit code and duration."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log_path.open("wb") as log:
        try:
            process = subprocess.Popen(
                argv,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=env,
                **popen_kwargs(),
            )
        except OSError as error:
            log.write(f"cannot start command: {error.strerror}\n".encode())
            return NOT_FOUND_EXIT, time.monotonic() - started
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(process)
            log.write(f"\nkilled after {timeout} seconds\n".encode())
            return TIMEOUT_EXIT, time.monotonic() - started
    return code, time.monotonic() - started


def fail_usage(message: str) -> int:
    print(f"usage error: {message}", file=sys.stderr)
    return EXIT_USAGE
