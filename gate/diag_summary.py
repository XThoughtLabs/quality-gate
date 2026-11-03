"""Turn diagnostic tools' outputs into the summaries the report reads.

Diagnostic only: nothing here changes a verdict.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from gate.common import EXIT_OK, UsageError, fail_usage, write_json
from gate.guard import Git

_MUTANT_LINE = re.compile(r"^\s*\S+:\s*(killed|survived|suspicious|timeout|no tests|skipped|not checked|segfault)\s*$")


def percent(part: int, whole: int) -> float | str:
    return round(100.0 * part / whole, 2) if whole else "unknown"


def coverage_summary(args: argparse.Namespace) -> dict:
    try:
        data = json.loads(Path(args.coverage_json).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise UsageError("cannot read the coverage JSON") from error
    files = data.get("files", {})
    whole = data.get("totals", {}).get("percent_covered", "unknown")

    git = Git(args.repo)
    head = git.run("rev-parse", f"{args.head}^{{commit}}").decode().strip()
    base = git.run("merge-base", args.base, head).decode().strip()

    changed = covered = 0
    per_file = {}
    for status, path in git.changes(base, head):
        if status == "D" or path not in files:
            continue
        executed = set(files[path].get("executed_lines", []))
        missing = set(files[path].get("missing_lines", []))
        added = {number for number, _ in git.added_lines(base, head, path)}
        measurable = added & (executed | missing)
        hit = added & executed
        if measurable:
            per_file[path] = {"changed": len(measurable), "covered": len(hit)}
            changed += len(measurable)
            covered += len(hit)
    return {
        "whole_percent": whole,
        "changed_lines": changed,
        "changed_lines_covered": covered,
        "changed_percent": percent(covered, changed),
        "files": per_file,
    }


def mutation_summary(args: argparse.Namespace) -> dict:
    try:
        text = Path(args.results).read_text(encoding="utf-8")
    except OSError as error:
        raise UsageError("cannot read the mutation results") from error
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = _MUTANT_LINE.match(line)
        if match:
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    killed = counts.get("killed", 0)
    survived = counts.get("survived", 0)
    return {"counts": counts, "score_percent": percent(killed, killed + survived)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.diag_summary")
    commands = parser.add_subparsers(dest="command", required=True)

    coverage = commands.add_parser("coverage")
    coverage.add_argument("--coverage-json", required=True)
    coverage.add_argument("--repo", required=True)
    coverage.add_argument("--base", required=True)
    coverage.add_argument("--head", required=True)
    coverage.add_argument("--out", required=True)

    mutation = commands.add_parser("mutation")
    mutation.add_argument("--results", required=True)
    mutation.add_argument("--out", required=True)

    args = parser.parse_args(argv)
    try:
        summary = coverage_summary(args) if args.command == "coverage" else mutation_summary(args)
    except UsageError as error:
        return fail_usage(str(error))
    write_json(args.out, summary)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
