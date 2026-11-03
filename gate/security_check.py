"""Zero unreviewed findings: compare the tools' outputs with security-review.md."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, popen_kwargs, write_json
from gate.guard import Git

_MARKERS = {"# nosec": "bandit", "gitleaks:allow": "gitleaks"}


def clean_path(path: object) -> str:
    text = str(path).replace("\\", "/")
    return text[2:] if text.startswith("./") else text


def read_review(path: Path) -> set[tuple[str, str, str]]:
    """Read the reviewed rows. A row with a blank reason does not count."""
    if not path.exists():
        return set()
    reviewed: set[tuple[str, str, str]] = set()
    columns: dict[str, int] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            columns = None
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if columns is None:
            names = [cell.lower() for cell in cells]
            if {"tool", "rule", "path", "reason"} <= set(names):
                columns = {name: names.index(name) for name in ("tool", "rule", "path", "reason")}
            continue
        if set("".join(cells)) <= {"-", ":", " "}:
            continue
        if max(columns.values()) >= len(cells):
            continue
        if cells[columns["reason"]]:
            reviewed.add(
                (cells[columns["tool"]].lower(), cells[columns["rule"]], clean_path(cells[columns["path"]]))
            )
    return reviewed


def read_findings(args: argparse.Namespace) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    missing: list[str] = []

    def load(path: str, tool: str):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            missing.append(tool)
            return None

    bandit = load(args.bandit, "bandit")
    if bandit is not None:
        if isinstance(bandit, dict) and isinstance(bandit.get("results"), list):
            for item in bandit["results"]:
                findings.append(
                    {"tool": "bandit", "rule": str(item.get("test_id")), "path": clean_path(item.get("filename")), "line": item.get("line_number")}
                )
        else:
            missing.append("bandit")

    audit = load(args.pip_audit, "pip-audit")
    if audit is not None:
        if isinstance(audit, dict) and isinstance(audit.get("dependencies"), list):
            for dependency in audit["dependencies"]:
                for vuln in dependency.get("vulns", []):
                    findings.append(
                        {"tool": "pip-audit", "rule": str(vuln.get("id")), "path": str(dependency.get("name")), "line": None}
                    )
        else:
            missing.append("pip-audit")

    leaks = load(args.gitleaks, "gitleaks")
    if leaks is not None:
        if isinstance(leaks, list):
            for item in leaks:
                findings.append(
                    {"tool": "gitleaks", "rule": str(item.get("RuleID")), "path": clean_path(item.get("File")), "line": item.get("StartLine")}
                )
        else:
            missing.append("gitleaks")
    return findings, missing


def read_suppressions(args: argparse.Namespace, reviewed: set[tuple[str, str, str]]) -> list[dict]:
    git = Git(args.repo)
    head = git.run("rev-parse", f"{args.head}^{{commit}}").decode().strip()
    base = git.run("merge-base", args.base, head).decode().strip()
    entries = {(tool, path) for tool, _, path in reviewed}
    found = []
    for status, path in git.changes(base, head):
        if status == "D":
            continue
        for number, text in git.added_lines(base, head, path):
            for marker, tool in _MARKERS.items():
                if marker in text:
                    found.append({"tool": tool, "path": path, "line": number, "has_entry": (tool, path) in entries})
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.security_check")
    parser.add_argument("--bandit", required=True)
    parser.add_argument("--pip-audit", required=True)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--review", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--tool-command",
        action="append",
        default=[],
        help="a JSON list: one tool to run first. A finding makes a tool exit non-zero, so its exit code is only recorded.",
    )
    args = parser.parse_args(argv)

    tool_codes = []
    for raw in args.tool_command:
        try:
            command = json.loads(raw)
        except ValueError:
            return fail_usage("--tool-command needs a JSON list")
        if not (isinstance(command, list) and command and all(isinstance(part, str) for part in command)):
            return fail_usage("--tool-command needs a JSON list of strings")
        try:
            code = subprocess.run(command, check=False, **popen_kwargs()).returncode
        except OSError:
            code = 127
        tool_codes.append({"argv": command, "exit_code": code})

    reviewed = read_review(Path(args.review))
    findings, missing = read_findings(args)
    try:
        suppressions = read_suppressions(args, reviewed)
    except UsageError as error:
        return fail_usage(str(error))

    for finding in findings:
        finding["reviewed"] = (finding["tool"], finding["rule"], finding["path"]) in reviewed

    codes = []
    if missing:
        codes.append("MISSING_TOOL_OUTPUT")
    if any(not finding["reviewed"] for finding in findings):
        codes.append("UNREVIEWED_FINDING")
    if any(not item["has_entry"] for item in suppressions):
        codes.append("SUPPRESSION_WITHOUT_ENTRY")

    write_json(
        args.out,
        {
            "ok": not codes,
            "findings": findings,
            "suppressions": suppressions,
            "reason_codes": codes,
            "missing_tools": sorted(set(missing)),
            "tool_exit_codes": tool_codes,
        },
    )
    for code in codes:
        print(f"security: {code}", file=sys.stderr)
    return EXIT_OK if not codes else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
