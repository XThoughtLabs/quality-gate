"""Compare the spec-derived tests' results with the known-failing list (decision O)."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from gate.collected import ids_under_folder, strip_parameters
from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, load_config, popen_kwargs, write_json

MAP_ID = re.compile(r"^(PUB-\d{2}|SPEC-6\.1|SPEC-6\.2|DEF-[A-Za-z0-9-]+)$")
TEST_COMMAND_OK = (0, 1, 5)  # pytest: all passed, some failed, none collected


def parse_list(text: str) -> dict[str, str]:
    """Parse a known-failing list. Raises UsageError on any entry it cannot trust."""
    entries: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # The map ID is the last whitespace-separated field; the test ID is everything
        # before it, its own spaces kept (a parametrized ID may hold a space, e.g.
        # "...[GET /tasks/{id}/history-invalid]").
        parts = stripped.rsplit(None, 1)
        if len(parts) != 2 or not MAP_ID.match(parts[1]):
            raise UsageError(f"known-failing list line {number} has no valid map ID")
        if parts[0] in entries:
            raise UsageError(f"known-failing list line {number} repeats an entry")
        entries[parts[0]] = parts[1]
    return entries


def read_list(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    return parse_list(path.read_text(encoding="utf-8"))


def read_results(path: Path) -> tuple[set[str], set[str]]:
    """Return the IDs that passed and the IDs that did not (failed, errored or skipped)."""
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        raise UsageError(f"cannot read JUnit file {path.name}") from error
    passed: set[str] = set()
    failing: set[str] = set()
    for case in root.iter("testcase"):
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        bad = any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
        (failing if bad else passed).add(test_id)
    return passed - failing, failing


def compare(
    listed: set[str], passed: set[str], failing: set[str], mode: str, require_empty: bool, expected: set[str]
) -> dict:
    failing_not_listed = failing - listed
    listed_failing = failing & listed
    remove_from_list = listed & passed
    missing_listed = listed - passed - failing
    # A test that exists and did not run is never a pass, whatever narrowed the run.
    seen = {strip_parameters(test_id) for test_id in passed | failing | listed}
    missing_tests = expected - seen

    codes: list[str] = []
    if failing_not_listed:
        codes.append("FAILING_NOT_LISTED")
    if missing_listed:
        codes.append("MISSING_LISTED")
    if missing_tests:
        codes.append("MISSING_TEST")
    if not passed and not failing:
        codes.append("NO_TESTS")
    if mode == "exact" and failing != listed:
        codes.append("LIST_NOT_EXACT")
    if require_empty and listed:
        codes.append("LIST_NOT_EMPTY")

    return {
        "ok": not codes,
        "mode": mode,
        "list_size": len(listed),
        "failing_not_listed": sorted(failing_not_listed),
        "listed_failing": sorted(listed_failing),
        "remove_from_list": sorted(remove_from_list),
        "missing_listed": sorted(missing_listed),
        "missing_tests": sorted(missing_tests),
        "passed": sorted(passed),
        "reason_codes": codes,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    command: list[str] = []
    if "--" in arguments:
        split = arguments.index("--")
        arguments, command = arguments[:split], arguments[split + 1 :]

    parser = argparse.ArgumentParser(prog="gate.acceptance")
    parser.add_argument("--junit", required=True)
    parser.add_argument("--known-failing", required=True)
    parser.add_argument("--mode", choices=("subset", "exact"), default="subset")
    parser.add_argument("--require-empty", action="store_true")
    parser.add_argument("--config", help="the configuration from the default branch")
    parser.add_argument("--tests-dir", help="the folder whose tests must all appear in the JUnit file")
    parser.add_argument("--tests-root", help="the folder pytest counts its IDs from, when not the working folder")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(arguments)

    # An optional test command runs here, so that one exit code stands for the check:
    # a listed failure makes the test command exit 1 and must not make the check red.
    command_code = None
    if command:
        try:
            command_code = subprocess.run(command, check=False, **popen_kwargs()).returncode
        except OSError as error:
            return fail_usage(f"cannot start the test command: {error.strerror}")

    try:
        listed = read_list(Path(args.known_failing))
        passed, failing = read_results(Path(args.junit))
        config = load_config(args.config) if args.config else {}
        expected: set[str] = set()
        if args.tests_dir:
            folder = Path(args.tests_dir).resolve()
            root = Path(args.tests_root).resolve() if args.tests_root else Path.cwd().resolve()
            if not folder.is_relative_to(root):
                raise UsageError("--tests-dir must be under the folder the IDs are counted from")
            ignore = config.get("acceptance", {}).get("expected_tests_ignore", [])
            expected = {test_id for test_id in ids_under_folder(folder, root, ignore) if test_id not in ignore}
    except UsageError as error:
        return fail_usage(str(error))

    require_empty = args.require_empty or config.get("acceptance", {}).get("require_empty") is True
    result = compare(set(listed), passed, failing, args.mode, require_empty, expected)
    if command_code is not None:
        result["test_command_exit_code"] = command_code
        if command_code not in TEST_COMMAND_OK:
            result["reason_codes"].append("TEST_COMMAND_ERROR")
            result["ok"] = False
    write_json(args.out, result)
    for code in result["reason_codes"]:
        print(f"acceptance: {code}", file=sys.stderr)
    return EXIT_OK if result["ok"] else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
