"""Run every command of one check, and record each numeric exit code."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from gate.collected import ids_in_source, is_collected_file, is_ignored, junit_ids
from gate.common import (
    EXIT_OK,
    EXIT_RULE_FAILED,
    UsageError,
    fail_usage,
    load_config,
    run_command,
    slug,
    write_json,
)

HEADER = "check\tindex\texit_code\tduration_seconds\traw_path\targv_json\n"
DEFAULT_TIMEOUT = 1800
_ENV_PLACEHOLDER = re.compile(r"\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


def substitute(argument: str, raw_dir: Path) -> str:
    """Fill {raw} and {env:NAME}, so that a command can name trusted paths and SHAs."""
    value = argument.replace("{raw}", str(raw_dir.resolve()))

    def from_environment(match: re.Match) -> str:
        name = match.group(1)
        if name not in os.environ:
            raise UsageError(f"a command needs the variable {name}, which is not set")
        return os.environ[name]

    return _ENV_PLACEHOLDER.sub(from_environment, value)


def append_row(tsv: Path, check: str, index: object, code: int, duration: float, raw: str, argv: list[str]) -> None:
    new_file = not tsv.exists()
    with tsv.open("a", encoding="utf-8", newline="\n") as handle:
        if new_file:
            handle.write(HEADER)
        handle.write(
            "\t".join([check, str(index), str(code), f"{duration:.3f}", raw, json.dumps(argv, ensure_ascii=False)])
            + "\n"
        )


def read_junit_counts(path: Path) -> dict[str, int]:
    root = ElementTree.parse(path).getroot()
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for case in root.iter("testcase"):
        counts["tests"] += 1
        if case.find("failure") is not None:
            counts["failures"] += 1
        elif case.find("error") is not None:
            counts["errors"] += 1
        elif case.find("skipped") is not None:
            counts["skipped"] += 1
    return counts


def _git(workdir: str | None, *args: str) -> str:
    process = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.quotepath=off", *args],
        cwd=workdir,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise UsageError(f"git {args[0]} failed: {process.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return process.stdout.decode("utf-8", "replace")


def tests_of_the_base(workdir: str | None, check: dict) -> set[str]:
    """Each test the base holds, read by parsing, before any of this check's commands run.

    acceptance/ is always left out: gate/acceptance has its own rule for those tests.
    """
    base_sha = os.environ.get("GATE_BASE_SHA")
    if not base_sha:
        raise UsageError("expected_tests_from_base needs the variable GATE_BASE_SHA")
    ignore = ["acceptance/", *check.get("expected_tests_ignore", [])]
    root = str(check.get("expected_tests_root", "")).strip("/")
    base = _git(workdir, "merge-base", base_sha, "HEAD").strip()
    found: set[str] = set()
    for path in _git(workdir, "ls-tree", "-r", "--name-only", base).splitlines():
        if not is_collected_file(path) or is_ignored(path, ignore):
            continue
        if root and not path.startswith(root + "/"):
            continue
        relative = path[len(root) + 1 :] if root else path
        try:
            found |= {
                test_id
                for test_id in ids_in_source(_git(workdir, "show", f"{base}:{path}"), relative)
                if test_id not in ignore
            }
        except (SyntaxError, ValueError):
            continue
    return found


def post_checks(check: dict, raw_dir: Path, expected: set[str] | None) -> list[str]:
    """Return the failures found after the commands ran."""
    failures = []
    if expected is not None and check.get("junit"):
        try:
            missing = sorted(expected - junit_ids(raw_dir / check["junit"]))
        except (OSError, ElementTree.ParseError):
            missing = []  # the unreadable file is its own failure, below
        write_json(raw_dir / "missing_tests.json", missing)
        if missing:
            failures.append(f"{len(missing)} tests of the base did not run")
    junit = check.get("junit")
    if junit:
        try:
            counts = read_junit_counts(raw_dir / junit)
        except (OSError, ElementTree.ParseError):
            failures.append(f"JUnit file {junit} is missing or unreadable")
        else:
            write_json(raw_dir / "counts.json", counts)
            if counts["failures"] + counts["errors"] > 0:
                failures.append(f"the JUnit file records {counts['failures'] + counts['errors']} failed tests")
            if check.get("forbid_skips") and counts["skipped"] > 0:
                failures.append(f"{counts['skipped']} tests were skipped")
    for output in check.get("required_outputs", []):
        if not (raw_dir / output).exists():
            failures.append(f"required output {output} is missing")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.run_checks")
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", required=True, help="a check ID, or 'setup' for the [setup] commands")
    parser.add_argument("--out", required=True)
    parser.add_argument("--workdir")
    parser.add_argument("--if-configured", action="store_true", help="exit 0 when the check is not configured")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except UsageError as error:
        return fail_usage(str(error))

    check = config.get("setup") if args.check == "setup" else config.get("checks", {}).get(args.check)
    if check is None:
        if args.if_configured:
            print(f"{args.check} is not configured")
            return EXIT_OK
        return fail_usage(f"unknown check: {args.check}")

    commands = check.get("commands")
    if not isinstance(commands, list) or not all(
        isinstance(command, list) and command and all(isinstance(part, str) for part in command)
        for command in commands
    ):
        return fail_usage(f"check {args.check} needs commands as a list of lists of strings")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tsv = out / "exit-codes.tsv"
    check_slug = slug(args.check)
    raw_dir = out / "raw" / check_slug
    raw_dir.mkdir(parents=True, exist_ok=True)
    timeout = float(check.get("timeout_seconds", DEFAULT_TIMEOUT))

    declared_env = check.get("env", {})
    if not isinstance(declared_env, dict):
        return fail_usage(f"check {args.check}: env must be a table")
    child_env = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    try:
        resolved = [[substitute(part, raw_dir) for part in command] for command in commands]
        child_env.update({str(name): substitute(str(value), raw_dir) for name, value in declared_env.items()})
    except UsageError as error:
        return fail_usage(str(error))

    expected: set[str] | None = None
    if check.get("expected_tests_from_base"):
        try:
            expected = tests_of_the_base(args.workdir, check)
        except UsageError as error:
            return fail_usage(str(error))

    first_failure = 0
    for index, command in enumerate(resolved):
        raw_rel = f"raw/{check_slug}/{index}.log"
        code, duration = run_command(command, out / raw_rel, args.workdir, timeout, child_env)
        append_row(tsv, args.check, index, code, duration, raw_rel, commands[index])
        print(f"{args.check} command {index}: exit code {code}")
        if code != 0 and first_failure == 0:
            first_failure = code

    failures = post_checks(check, raw_dir, expected)
    for failure in failures:
        append_row(tsv, args.check, "post", EXIT_RULE_FAILED, 0.0, "", [failure])
        print(f"{args.check}: {failure}", file=sys.stderr)

    if first_failure:
        return first_failure
    return EXIT_RULE_FAILED if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
