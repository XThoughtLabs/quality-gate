"""Generate the report and the verdict. No model writes or edits any of this.

Trusted inputs (the context, the jobs from the API, the extras) decide the verdict.
The artifact comes from the job that ran the PR's code, so it is untrusted data: it
can only move a verdict away from ready, never towards it.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import json
import os
import platform
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from gate.common import (
    DIAGNOSTIC_CHECKS,
    EXIT_OK,
    EXIT_RULE_FAILED,
    FIXED_CLASSES,
    MANDATORY_CHECKS,
    UsageError,
    fail_usage,
    load_config,
    neutralize,
    read_json,
    read_json_or_none,
    sha256_file,
    slug,
    write_json,
)
from gate.feedback import latest_review_status

READY = "ready-for-human"
BLOCKED = "blocked"
NEEDS_HUMAN = "needs-human"
INCOMPLETE = "incomplete"
# The final verdict while gate/final waits for the independent review (FN-2). Never a pass.
AWAITING = "awaiting-review"
GATE_VERDICTS = (READY, BLOCKED, NEEDS_HUMAN, INCOMPLETE)

# The GitHub Actions app on github.com: the integration the ruleset requires for the gate's checks (FN-1).
ACTIONS_APP_ID = 15368
# What must be green on the head before gate/final may be: every mandatory class but gate/final itself (FN-1).
FINAL_INPUTS = tuple(check for check in MANDATORY_CHECKS if check != "gate/final")
REVIEW_STATES = {"success": "success", "failure": "failed", "error": "failed", "pending": "pending"}
_REVIEW_DETAIL = {
    "REVIEW_MISSING": "no independent review of {sha} exists yet",
    "REVIEW_PENDING": "the independent review of {sha} is pending",
    "REVIEW_NOT_BY_REVIEWER": "the newest independent-review status on {sha} was not created by the reviewer's app",
    "REVIEW_UNREADABLE": "the independent review of {sha} could not be read",
}

RUN_STEPS = ("gate/env", "gate/guard", "gate/tests", "gate/acceptance", "gate/security")
CONTRADICTIONS = {"FORK_PR", "SHA_MISMATCH", "EXIT_CODE_MISMATCH", "CHECKSUM_MISMATCH", "CLAIM_MISMATCH", "REPORTS_UNTRUSTED"}
GAPS = {"UNFINISHED_STAGE", "NO_ARTIFACT", "MISSING_OUTPUT"}
CONTEXT_FIELDS = (
    "repository",
    "head_repository",
    "pr",
    "run_id",
    "run_attempt",
    "event",
    "baseline_sha",
    "base_sha",
    "head_sha",
    "gate_sha",
    "head_ref",
    "config_hashes",
)
RESOURCES = ("executor_runs", "executor_turns", "codex_runs", "codex_tokens", "actions_minutes")
VOLATILE_KEYS = {"generated_at", "duration_seconds", "raw_sha256"}
VOLATILE_PATHS = {
    "verification.run_id",
    "verification.run_attempt",
    "verification.execution_environment",
    "environment",
}
SCHEMA_PATH = Path(__file__).parent / "schema" / "report.schema.json"


def conclusion_for(verdict: str) -> str:
    """Only ready passes. GitHub counts neutral and skipped as success, so neither is ever used."""
    return "success" if verdict == READY else "failure"


def is_count(value: Any) -> bool:
    """A positive integer. True and False are integers in Python, and are refused."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def same_account(creator: Any, reviewer: Any) -> bool:
    """The status's creator is the reviewer's bot account: login, id and type, never a text (FN-1)."""
    if not isinstance(creator, dict) or not isinstance(reviewer, dict) or not is_count(reviewer.get("id")):
        return False
    return (
        creator.get("login") == reviewer.get("login")
        and is_count(creator.get("id"))
        and creator.get("id") == reviewer.get("id")
        and creator.get("type") == "Bot"
    )


def review_of(statuses: Any, reviewer: Any) -> tuple[str, str | None]:
    """The state of the newest independent review of the head, and the reason when it is no valid review."""
    if not isinstance(statuses, list) or not isinstance(reviewer, dict):
        return "missing", "REVIEW_UNREADABLE"
    newest = latest_review_status(statuses)
    if newest is None:
        return "missing", "REVIEW_MISSING"
    if not same_account(newest.get("creator"), reviewer):
        return "missing", "REVIEW_NOT_BY_REVIEWER"
    state = REVIEW_STATES.get(newest.get("state"))
    if state is None:
        return "missing", "REVIEW_UNREADABLE"
    return state, "REVIEW_PENDING" if state == "pending" else None


def check_conclusions(check_runs: Any, head_sha: str, own_checks: dict | None) -> dict[str, str] | None:
    """The newest check run of each mandatory check on the head, from the GitHub Actions app only. None when unreadable."""
    if not isinstance(check_runs, list):
        return None
    newest: dict[str, dict] = {}
    for run in check_runs:
        if not isinstance(run, dict) or run.get("head_sha") != head_sha or run.get("name") not in FINAL_INPUTS:
            continue
        app = run.get("app") if isinstance(run.get("app"), dict) else {}
        if not is_count(app.get("id")) or app.get("id") != ACTIONS_APP_ID or not is_count(run.get("id")):
            continue
        if run["name"] not in newest or run["id"] > newest[run["name"]]["id"]:
            newest[run["name"]] = run
    found = {name: str(run.get("conclusion")) if run.get("status") == "completed" else "not-completed" for name, run in newest.items()}
    found.update(own_checks or {})
    return found


def final_decision(
    *,
    mode: str,
    head_sha: str,
    gate_verdict: Any,
    gate_reasons: Any,
    archive_ok: Any,
    check_runs: Any,
    statuses: Any,
    reviewer: Any,
    own_checks: dict | None = None,
) -> dict:
    """FN-1, FN-2, FN-4, FN-5 and FN-8: the one decision of gate/final, for the archive job and for finalize.

    mode is "archive" or "finalize". The check runs and the statuses are the head's, as the API lists them, or None
    when they could not be read. Returns whether to post, the check's status and conclusion, the final verdict and
    the reasons. Nothing here is ever success unless every fact FN-1 names is there.
    """
    state, review_code = review_of(statuses, reviewer)
    reasons = [item for item in gate_reasons if isinstance(item, dict)] if isinstance(gate_reasons, list) else []

    def result(status: str | None, verdict: str | None) -> dict:
        conclusion = conclusion_for(str(verdict)) if status == "completed" else None
        return {
            "post": status is not None,
            "status": status,
            "conclusion": conclusion,
            "verdict": verdict,
            "reasons": reasons,
            "review": {"state": state, "code": review_code},
        }

    if mode == "finalize" and state == "pending":
        return result(None, None)
    if state == "failed":
        reasons.append({"code": "REVIEW_FAILED", "detail": f"the independent review of {head_sha} did not pass"})
    if gate_verdict not in GATE_VERDICTS:
        reasons.append({"code": "NO_RECORD", "detail": f"no readable gate verdict is stored for {head_sha}"})
        return result("completed", INCOMPLETE)
    if gate_verdict != READY:
        return result("completed", gate_verdict)
    if archive_ok is not True:
        reasons.append({"code": "EVIDENCE_NOT_STORED", "detail": "the stored archive of this run is not complete"})
        return result("completed", INCOMPLETE)
    if state == "failed":
        return result("completed", BLOCKED)
    if state == "success":
        found = check_conclusions(check_runs, head_sha, own_checks)
        if found is None:
            reasons.append({"code": "CHECKS_UNREADABLE", "detail": f"the check runs on {head_sha} could not be read"})
            return result("completed", INCOMPLETE)
        failed = [name for name in FINAL_INPUTS if found.get(name) not in (None, "success", "not-completed")]
        missing = [name for name in FINAL_INPUTS if found.get(name) in (None, "not-completed")]
        reasons += [{"code": "FAILED_CHECK", "detail": f"{name} did not succeed on {head_sha}"} for name in failed]
        reasons += [{"code": "MISSING_CHECK", "detail": f"{name} has no completed check run on {head_sha}"} for name in missing]
        if failed:
            return result("completed", BLOCKED)
        if missing:
            return result("completed", INCOMPLETE)
        return result("completed", READY)
    reasons.append({"code": str(review_code), "detail": _REVIEW_DETAIL.get(str(review_code), "no valid review").format(sha=head_sha)})
    return result("in_progress", AWAITING)


def find_run_job(jobs: dict) -> dict | None:
    for job in jobs.get("jobs", []):
        name = str(job.get("name", ""))
        if name == "run" or name.endswith(" / run"):
            return job
    return None


def read_rows(path: Path) -> list[dict[str, str]] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    reader = csv.DictReader(io.StringIO(text), delimiter="\t", quoting=csv.QUOTE_NONE)
    if reader.fieldnames is None or "check" not in reader.fieldnames or "exit_code" not in reader.fieldnames:
        return None
    return [row for row in reader if row.get("check")]


def parse_exit_code(value: Any) -> int | None:
    text = str(value).strip()
    return int(text) if re.fullmatch(r"-?\d+", text) else None


def safe_member(root: Path, relative: str) -> Path | None:
    """Resolve a path named by the artifact, refusing any that leaves the artifact."""
    pure = PurePosixPath(relative.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts or (pure.parts and ":" in pure.parts[0]):
        return None
    return root.joinpath(*pure.parts)


def read_sums(path: Path) -> list[tuple[str, str]] | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    pairs = []
    for line in lines:
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        if not name:
            return None
        pairs.append((digest.strip().lower(), name.strip().lstrip("*")))
    return pairs


def judge(context: dict, jobs: dict, artifact: Path, config: dict, extras: dict) -> tuple[str, list[dict], dict, dict]:
    """Apply the rules V-1 to V-5. Returns the verdict, reasons, the checks and the facts found."""
    reasons: list[dict] = []

    def reason(code: str, detail: str) -> None:
        reasons.append({"code": code, "detail": detail})

    # The trusted facts: which steps ran and how they ended.
    job = find_run_job(jobs)
    steps = {str(step.get("name")): step for step in (job or {}).get("steps", [])}
    step_success: dict[str, bool] = {}
    if job is None:
        reason("UNFINISHED_STAGE", "the run job is absent")
    elif job.get("status") != "completed" or job.get("conclusion") not in ("success", "failure"):
        reason("UNFINISHED_STAGE", "the run job did not finish")
    for check in RUN_STEPS:
        step = steps.get(check)
        if step is None:
            reason("UNFINISHED_STAGE", f"the step {check} is absent")
            step_success[check] = False
        elif step.get("status") != "completed" or step.get("conclusion") not in ("success", "failure"):
            reason("UNFINISHED_STAGE", f"the step {check} did not finish")
            step_success[check] = False
        else:
            step_success[check] = step.get("conclusion") == "success"

    if context.get("head_repository") != context.get("repository"):
        reason("FORK_PR", "the PR comes from a fork; its code was not run")

    # The untrusted facts: what the artifact says.
    rows_by_check: dict[str, list[dict[str, str]]] = {}
    meta: Any = None
    sums: list[tuple[str, str]] | None = None
    if not artifact.is_dir():
        reason("NO_ARTIFACT", "the artifact is missing")
    else:
        meta = read_json_or_none(artifact / "meta.json")
        if not isinstance(meta, dict):
            reason("MISSING_OUTPUT", "meta.json is missing or unreadable")
            meta = None
        else:
            for key, field in (("head_sha", "head_sha"), ("run_id", "run_id"), ("run_attempt", "run_attempt")):
                if key not in meta:
                    reason("MISSING_OUTPUT", f"meta.json has no {key}")
                elif str(meta[key]) != str(context.get(field)):
                    reason("SHA_MISMATCH", f"meta.json gives another {key} than the trusted context")

        rows = read_rows(artifact / "exit-codes.tsv")
        if rows is None:
            reason("MISSING_OUTPUT", "exit-codes.tsv is missing or unreadable")
        else:
            for row in rows:
                rows_by_check.setdefault(row["check"], []).append(row)

        sums = read_sums(artifact / "SHA256SUMS")
        if sums is None:
            reason("MISSING_OUTPUT", "SHA256SUMS is missing or unreadable")
        else:
            for digest, name in sums:
                member = safe_member(artifact, name)
                if member is None:
                    reason("CHECKSUM_MISMATCH", f"SHA256SUMS names a path outside the artifact: {name}")
                elif not member.is_file():
                    reason("MISSING_OUTPUT", f"{name} is named in SHA256SUMS and is missing")
                elif sha256_file(member) != digest:
                    reason("CHECKSUM_MISMATCH", f"{name} does not match SHA256SUMS")

        # Cross-check each step's trusted conclusion against its exit codes.
        if rows is not None:
            for check in (*RUN_STEPS, *DIAGNOSTIC_CHECKS, "setup"):
                check_rows = rows_by_check.get(check)
                step = steps.get(check)
                if not check_rows:
                    if check in RUN_STEPS:
                        reason("MISSING_OUTPUT", f"{check} has no exit code")
                    continue
                codes = [parse_exit_code(row.get("exit_code")) for row in check_rows]
                if any(code is None for code in codes):
                    reason("EXIT_CODE_MISMATCH", f"{check} has an exit code that is not an integer")
                    continue
                if step is None or step.get("status") != "completed":
                    continue
                any_failed = any(code != 0 for code in codes)
                if step.get("conclusion") == "success" and any_failed:
                    reason("EXIT_CODE_MISMATCH", f"{check} succeeded with a non-zero exit code")
                elif step.get("conclusion") == "failure" and not any_failed:
                    reason("EXIT_CODE_MISMATCH", f"{check} failed with every exit code zero")

    # A claim of ready can only hurt: when a mandatory step failed it is a contradiction.
    if isinstance(meta, dict) and meta.get("claimed_verdict") == READY:
        if not all(step_success.get(check) for check in RUN_STEPS):
            reason("CLAIM_MISMATCH", "the artifact claims ready while a mandatory step did not succeed")

    failed_checks = [
        check
        for check in RUN_STEPS
        if steps.get(check, {}).get("status") == "completed" and steps[check].get("conclusion") == "failure"
    ]
    guard = read_json_or_none(artifact / "guard.json") if artifact.is_dir() else None
    guard = guard if isinstance(guard, dict) else {}
    if guard.get("repeated_fix") is True:
        reason("REPEATED_FIX", "this round repeats an earlier round's fix")

    limits = config.get("limits", {})
    cap = limits.get("max_fix_rounds", 3)
    heads = {str(item.get("head_sha")) for item in extras.get("rounds", []) if isinstance(item, dict)}
    heads.add(str(context.get("head_sha")))
    if failed_checks and len(heads) - 1 >= cap:
        reason("ROUND_CAP", f"{len(heads) - 1} fix rounds were used; the cap is {cap}")

    for check in failed_checks:
        reason("FAILED_CHECK", f"{check} failed")
    if extras.get("reports_untrusted") is True:
        reason("REPORTS_UNTRUSTED", "the reports branch holds a commit the gate did not write, so its records were not read")
    if steps.get("setup", {}).get("conclusion") == "failure":
        reason("FAILED_CHECK", "setup failed, so the checks did not run on a prepared application")
    env_failures = extras.get("env_failures", [])
    for role in env_failures if isinstance(env_failures, list) else []:
        reason("FAILED_CHECK", f"gate/env failed in the {role} job")

    codes = {item["code"] for item in reasons}
    if codes & CONTRADICTIONS:
        verdict = BLOCKED
    elif codes & GAPS:
        verdict = INCOMPLETE
    elif codes & {"REPEATED_FIX", "ROUND_CAP"}:
        verdict = NEEDS_HUMAN
    elif "FAILED_CHECK" in codes:
        verdict = BLOCKED
    else:
        verdict = READY

    checks: dict[str, str] = {}
    for check in RUN_STEPS:
        check_rows = rows_by_check.get(check, [])
        codes_for = [parse_exit_code(row.get("exit_code")) for row in check_rows]
        passed = bool(step_success.get(check)) and bool(check_rows) and all(code == 0 for code in codes_for)
        checks[check] = "success" if passed else "failure"
    if env_failures:
        checks["gate/env"] = "failure"
    checks["gate/report"] = "failure" if codes & GAPS else "success"

    facts = {"steps": steps, "rows": rows_by_check, "guard": guard, "sums": sums}
    return verdict, reasons, checks, facts


def build_checks(artifact: Path, facts: dict) -> list[dict]:
    steps = facts["steps"]
    rows_by_check = facts["rows"]
    entries = []
    for check in (*RUN_STEPS, *DIAGNOSTIC_CHECKS):
        step = steps.get(check)
        commands = []
        for row in rows_by_check.get(check, []):
            raw_path = str(row.get("raw_path") or "")
            member = safe_member(artifact, raw_path) if raw_path else None
            digest = sha256_file(member) if member is not None and member.is_file() else None
            code = parse_exit_code(row.get("exit_code"))
            duration: Any = row.get("duration_seconds")
            try:
                duration = float(duration)
            except (TypeError, ValueError):
                duration = "unknown"
            try:
                argv = json.loads(row.get("argv_json") or "[]")
                argv = [str(part) for part in argv] if isinstance(argv, list) else []
            except ValueError:
                argv = []
            commands.append(
                {
                    "argv": argv,
                    "exit_code": code if code is not None else str(row.get("exit_code")),
                    "duration_seconds": duration,
                    "raw_path": raw_path,
                    "raw_sha256": digest,
                }
            )
        counts = read_json_or_none(artifact / "raw" / slug(check) / "counts.json") if artifact.is_dir() else None
        entries.append(
            {
                "id": check,
                "class": FIXED_CLASSES[check],
                "conclusion": str(step.get("conclusion")) if step else "not-run",
                "commands": commands,
                "counts": counts if isinstance(counts, dict) else None,
            }
        )
    return entries


def bypass_merges(merges: list[Any]) -> list[dict]:
    flagged = []
    for merge in merges:
        if not isinstance(merge, dict):
            continue
        if (
            merge.get("via_pr") is not True
            or not merge.get("approvals")
            or merge.get("final_conclusion") != "success"
            or merge.get("security_review_changed") is True
        ):
            flagged.append(merge)
    return flagged


def build_report(
    context: dict, artifact: Path, extras: dict, verdict: str, reasons: list[dict], facts: dict, config: dict
) -> dict:
    def artifact_json(*parts: str) -> Any:
        return read_json_or_none(artifact.joinpath(*parts)) if artifact.is_dir() else None

    def object_or_unknown(value: Any) -> Any:
        return value if isinstance(value, dict) else "unknown"

    guard = facts["guard"]
    findings: list[dict] = []
    for violation in guard.get("violations", []) if isinstance(guard.get("violations"), list) else []:
        if isinstance(violation, dict):
            findings.append({"tool": "guard", **violation})
    security = artifact_json("raw", "gate-security", "security.json")
    if isinstance(security, dict) and isinstance(security.get("findings"), list):
        findings += [item for item in security["findings"] if isinstance(item, dict)]
    for review in extras.get("review_verdicts", []) if isinstance(extras.get("review_verdicts"), list) else []:
        if isinstance(review, dict):
            findings.append({"tool": "review", "rule": str(review.get("verdict")), "path": str(review.get("sha"))})

    acceptance = artifact_json("acceptance.json")
    known_failing: Any = "unknown"
    if (
        isinstance(acceptance, dict)
        and isinstance(acceptance.get("list_size"), int)
        and isinstance(acceptance.get("remove_from_list"), list)
    ):
        known_failing = {
            "size": acceptance["list_size"],
            "remove_from_list": [str(item) for item in acceptance["remove_from_list"]],
        }

    given = extras.get("resources", {}) if isinstance(extras.get("resources"), dict) else {}
    resources = {name: given.get(name, "unknown") for name in RESOURCES}

    human_entries = extras.get("human")
    if isinstance(human_entries, list):
        human: dict[str, Any] = {
            "interventions": len(human_entries),
            "minutes": sum(item.get("minutes", 0) for item in human_entries if isinstance(item, dict)),
        }
    else:
        human = {"interventions": "unknown", "minutes": "unknown"}

    rounds = extras.get("rounds")
    rounds = list(rounds) if isinstance(rounds, list) else []
    own = guard.get("fingerprint")
    if isinstance(own, dict) and not any(isinstance(item, dict) and item.get("head_sha") == context.get("head_sha") for item in rounds):
        rounds.append({"head_sha": context.get("head_sha"), "round": own.get("round"), "cumulative": own.get("cumulative")})
    dependency_changes = guard.get("dependency_changes")
    needs_code_owner = guard.get("needs_code_owner")
    marked_tests = guard.get("marked_tests")
    security_changes = guard.get("security_review_changes")
    setup_rows = facts["rows"].get("setup", [])
    setup: Any = "not-configured"
    if setup_rows:
        setup = {
            "conclusion": str(facts["steps"].get("setup", {}).get("conclusion", "not-run")),
            "exit_codes": [parse_exit_code(row.get("exit_code")) for row in setup_rows],
        }
    accepted = (config.get("archive") or {}).get("accepted_foreign_commits")

    return {
        "verification": {
            **{field: context.get(field) for field in CONTEXT_FIELDS},
            "trusted_sha": context.get("trusted_sha", "unknown"),
            "author": context.get("author", "unknown"),
            "execution_environment": context.get("execution_environment", "unknown"),
        },
        "setup": setup,
        "needs_code_owner": needs_code_owner if isinstance(needs_code_owner, list) else [],
        "marked_tests": marked_tests if isinstance(marked_tests, list) else [],
        "security_review_changes": security_changes if isinstance(security_changes, list) else [],
        "accepted_foreign_commits": accepted if isinstance(accepted, list) else [],
        "independent_review": extras.get("independent_review", "unknown"),
        "environment": object_or_unknown(artifact_json("environment.json")),
        "checks": build_checks(artifact, facts),
        "coverage": object_or_unknown(artifact_json("raw", "diag-coverage", "summary.json")),
        "mutation": object_or_unknown(artifact_json("raw", "diag-mutation", "summary.json")),
        "dependency_changes": dependency_changes if isinstance(dependency_changes, list) else [],
        "findings": findings,
        "rounds": rounds,
        "resources": resources,
        "human": human,
        "bypass_merges": bypass_merges(extras.get("merges", []) if isinstance(extras.get("merges"), list) else []),
        "known_failing": known_failing,
        "verdicts": {"preliminary": verdict, "final": None, "reasons": reasons},
        "semi_automatic_steps": extras.get("semi_automatic_steps", [])
        if isinstance(extras.get("semi_automatic_steps"), list)
        else [],
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
    }


def cell(value: Any) -> str:
    return neutralize(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    """Render the Markdown from the JSON only."""
    verification = report["verification"]
    preliminary = report["verdicts"]["preliminary"]
    if preliminary == READY:
        # FN-7: the word ready belongs to the final verdict alone, which waits for the independent review.
        headline = [
            "**Preliminary result: the gate's checks passed.**",
            "",
            "The final verdict waits for the independent review on the same commit, after the evidence is stored: "
            "see the check `gate/final`, and `final.json` beside this report.",
        ]
    else:
        headline = [
            f"**Preliminary verdict: {cell(preliminary)}**",
            "",
            "The final verdict comes after the evidence is stored: see the check `gate/final`, and `final.json` beside this report.",
        ]
    lines = [
        "# Quality gate report",
        "",
        *headline,
        "",
        "## Verification record",
        "",
        "| Field | Value |",
        "|---|---|",
    ]
    for field in CONTEXT_FIELDS:
        if field != "config_hashes":
            lines.append(f"| {field} | {cell(verification.get(field))} |")
    for path, digest in sorted((verification.get("config_hashes") or {}).items()):
        lines.append(f"| config {cell(path)} | {cell(digest)} |")

    lines += ["", "## Reasons", ""]
    reasons = report["verdicts"]["reasons"]
    lines += [f"- {cell(item['code'])}: {cell(item['detail'])}" for item in reasons] or ["None."]

    lines += ["", "## Checks", "", "| Check | Class | Conclusion | Exit codes |", "|---|---|---|---|"]
    for check in report["checks"]:
        codes = ", ".join(cell(command["exit_code"]) for command in check["commands"]) or "none"
        lines.append(f"| {cell(check['id'])} | {cell(check['class'])} | {cell(check['conclusion'])} | {codes} |")

    known = report["known_failing"]
    lines += ["", "## Marked for the code owner", ""]
    lines += [f"- {cell(path)}" for path in report["needs_code_owner"]] or ["None."]
    lines += [
        f"- changed test: {cell(item.get('path'))}: {cell(item.get('name'))}"
        for item in report["marked_tests"]
        if isinstance(item, dict)
    ]

    lines += ["", "## Changes to security-review.md, flagged", ""]
    lines += [
        f"- {cell(item.get('change'))}: {cell(item.get('row'))}"
        for item in report["security_review_changes"]
        if isinstance(item, dict)
    ] or ["None."]

    lines += ["", "## Accepted foreign commits on the reports branch", ""]
    lines += [
        f"- {cell(item.get('sha'))}, {cell(item.get('date'))}: {cell(item.get('reason'))}"
        for item in report["accepted_foreign_commits"]
        if isinstance(item, dict)
    ] or ["None."]

    lines += ["", "## Known-failing list", ""]
    if isinstance(known, dict):
        lines.append(f"Size: {known['size']}.")
        lines += [f"- remove from list: {cell(test)}" for test in known["remove_from_list"]]
    else:
        lines.append("Size: unknown.")

    lines += ["", "## Findings", ""]
    lines += [
        f"- {cell(item.get('tool', ''))} {cell(item.get('rule', ''))} {cell(item.get('path', ''))} {cell(item.get('detail', ''))}{' (reviewed)' if item.get('reviewed') is True else ''}".rstrip()
        for item in report["findings"]
    ] or ["None."]

    lines += ["", "## Dependency changes", ""]
    lines += [
        f"- {cell(item.get('name'))}: {cell(item.get('old'))} to {cell(item.get('new'))} ({cell(item.get('changelog'))})"
        for item in report["dependency_changes"]
        if isinstance(item, dict)
    ] or ["None."]

    lines += ["", "## Bypass merges", ""]
    lines += [
        f"- PR {cell(item.get('pr'))}, merge {cell(item.get('merge_sha'))}, by {cell(item.get('merged_by'))}"
        for item in report["bypass_merges"]
    ] or ["None."]

    lines += ["", "## Resources", ""]
    lines += [f"- {name}: {cell(value)}" for name, value in report["resources"].items()]
    lines += [
        f"- human interventions: {cell(report['human']['interventions'])}",
        f"- human minutes: {cell(report['human']['minutes'])}",
    ]
    lines += ["", "## Semi-automatic steps", ""]
    lines += [f"- {cell(step)}" for step in report["semi_automatic_steps"]] or ["None."]
    lines += ["", "This report was generated by a script. No model wrote or edited it.", ""]
    return "\n".join(lines)


def load_trusted(path: str, label: str) -> dict:
    try:
        data = read_json(path)
    except (OSError, ValueError) as error:
        raise UsageError(f"cannot read {label}") from error
    if not isinstance(data, dict):
        raise UsageError(f"{label} must be a JSON object")
    return data


def cmd_generate(args: argparse.Namespace) -> int:
    context = load_trusted(args.context, "the context")
    missing = [field for field in CONTEXT_FIELDS if field not in context]
    if missing:
        raise UsageError("the context lacks: " + ", ".join(missing))
    jobs = load_trusted(args.jobs, "the jobs")
    extras = load_trusted(args.extras, "the extras") if args.extras else {}
    config = load_config(args.config)
    artifact = Path(args.artifact)

    verdict, reasons, checks, facts = judge(context, jobs, artifact, config, extras)
    report = build_report(context, artifact, extras, verdict, reasons, facts, config)
    import jsonschema  # noqa: PLC0415  # reason: only this command needs the library (C-6)

    try:
        jsonschema.validate(report, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    except jsonschema.ValidationError as error:
        raise UsageError(f"the report does not match its schema: {error.message}") from error

    out = Path(args.out)
    write_json(out / "report.json", report)
    (out / "report.md").write_text(render_markdown(report), encoding="utf-8", newline="\n")
    write_json(out / "verdict.json", {"verdict": verdict, "reasons": reasons, "checks": checks})
    print(f"preliminary verdict: {verdict}")
    return EXIT_OK


def cmd_final(args: argparse.Namespace) -> int:
    preliminary = read_json_or_none(args.verdict)
    extra_reasons = []
    if not isinstance(preliminary, dict):
        preliminary = {"verdict": INCOMPLETE, "reasons": []}
        extra_reasons.append({"code": "NO_PRELIMINARY", "detail": "the preliminary verdict is missing or unreadable"})
    elif args.expect_verdict_sha256 is not None and sha256_file(Path(args.verdict)) != args.expect_verdict_sha256:
        preliminary = {"verdict": BLOCKED, "reasons": []}
        extra_reasons.append({"code": "PUBLISH_OUTPUT_MISMATCH", "detail": "the verdict differs from what the publish job computed"})
    if args.env_result:
        environment = read_json_or_none(args.env_result)
        if not (isinstance(environment, dict) and environment.get("ok") is True):
            extra_reasons.append({"code": "FAILED_CHECK", "detail": "gate/env failed in the archive job"})
            if preliminary.get("verdict") == READY:
                preliminary = {**preliminary, "verdict": BLOCKED}
    archive = read_json_or_none(args.archive)
    verdict = preliminary.get("verdict")
    reasons = [*preliminary.get("reasons", []), *extra_reasons]
    stored = (
        isinstance(archive, dict) and archive.get("stored") is True and archive.get("sha256sums_match") is True
    )
    actors_ok = not isinstance(archive, dict) or archive.get("actors_ok") is not False
    own_checks = preliminary.get("checks")
    if verdict == READY and isinstance(own_checks, dict) and any(value != "success" for value in own_checks.values()):
        verdict = BLOCKED
        reasons.append({"code": "FAILED_CHECK", "detail": "the preliminary verdict lists a check that did not succeed"})
    if not stored:
        reasons.append({"code": "EVIDENCE_NOT_STORED", "detail": "evidence not stored"})
        if verdict == READY:
            verdict = INCOMPLETE
    if not actors_ok:
        reasons.append({"code": "REPORTS_WRITTEN_BY_ANOTHER_ACTOR", "detail": str(archive.get("reason"))})
        if verdict == READY:
            verdict = BLOCKED
    if verdict not in GATE_VERDICTS:
        verdict = INCOMPLETE
        reasons.append({"code": "UNKNOWN_VERDICT", "detail": "the preliminary verdict is not known"})
    archive_conclusion = "success" if stored and actors_ok else "failure"
    # FN-2 and FN-8: the gate's own verdict is not yet the final one. A missing or unreadable facts file leaves every
    # fact unreadable, so the final verdict can only wait or fail.
    facts = read_json_or_none(args.facts) if args.facts else None
    facts = facts if isinstance(facts, dict) else {}
    decision = final_decision(
        mode="archive",
        head_sha=str(facts.get("head_sha") or ""),
        gate_verdict=verdict,
        gate_reasons=list(reasons),
        archive_ok=stored and actors_ok,
        check_runs=facts.get("check_runs"),
        statuses=facts.get("statuses"),
        reviewer=facts.get("reviewer"),
        own_checks={"gate/archive": archive_conclusion},
    )
    write_json(
        args.out,
        {
            "verdict": decision["verdict"],
            "gate_verdict": verdict,
            "gate_reasons": reasons,
            "reasons": decision["reasons"],
            "conclusions": {"gate/archive": archive_conclusion, "gate/final": decision["conclusion"]},
            "final_check": {"status": decision["status"], "conclusion": decision["conclusion"]},
            "review": decision["review"],
        },
    )
    print(f"gate verdict: {verdict}; final verdict: {decision['verdict']}")
    return EXIT_OK


def differences(left: Any, right: Any, path: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        found: list[str] = []
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else str(key)
            if key in VOLATILE_KEYS or child in VOLATILE_PATHS:
                continue
            if key not in left or key not in right:
                found.append(child)
            else:
                found += differences(left[key], right[key], child)
        return found
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return [path]
        found = []
        for index, (a, b) in enumerate(zip(left, right)):
            found += differences(a, b, f"{path}[{index}]")
        return found
    return [] if left == right else [path]


def cmd_compare(args: argparse.Namespace) -> int:
    found = differences(load_trusted(args.first, "the first report"), load_trusted(args.second, "the second report"))
    for path in found:
        print(f"differs: {path}")
    return EXIT_RULE_FAILED if found else EXIT_OK


def cmd_seal(args: argparse.Namespace) -> int:
    """Write meta.json and SHA256SUMS at the end of the run job."""
    artifact = Path(args.artifact)
    artifact.mkdir(parents=True, exist_ok=True)
    for source, name in (("gate-guard", "guard.json"), ("gate-acceptance", "acceptance.json")):
        found = artifact / "raw" / source / name
        if found.is_file() and not found.is_symlink():
            (artifact / name).write_bytes(found.read_bytes())
    write_json(
        artifact / "environment.json",
        {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "image_os": os.environ.get("ImageOS", "unknown"),
            "image_version": os.environ.get("ImageVersion", "unknown"),
        },
    )
    write_json(
        artifact / "meta.json",
        {"head_sha": args.head_sha, "run_id": args.run_id, "run_attempt": args.run_attempt},
    )
    names = sorted(
        path.relative_to(artifact).as_posix()
        for path in artifact.rglob("*")
        if path.is_file() and not path.is_symlink() and path != artifact / "SHA256SUMS"
    )
    with (artifact / "SHA256SUMS").open("w", encoding="utf-8", newline="\n") as handle:
        for name in names:
            handle.write(f"{sha256_file(artifact / name)}  {name}\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.report")
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate")
    generate.add_argument("--context", required=True)
    generate.add_argument("--jobs", required=True)
    generate.add_argument("--artifact", required=True)
    generate.add_argument("--config", required=True)
    generate.add_argument("--out", required=True)
    generate.add_argument("--extras")

    final = commands.add_parser("final")
    final.add_argument("--verdict", required=True)
    final.add_argument("--archive", required=True)
    final.add_argument("--out", required=True)
    final.add_argument("--expect-verdict-sha256")
    final.add_argument("--env-result")
    final.add_argument("--facts", help="the head's statuses, check runs and reviewer account, from gate.publish final-facts")

    compare = commands.add_parser("compare")
    compare.add_argument("first")
    compare.add_argument("second")

    seal = commands.add_parser("seal")
    seal.add_argument("--artifact", required=True)
    seal.add_argument("--head-sha", required=True)
    seal.add_argument("--run-id", required=True)
    seal.add_argument("--run-attempt", required=True)

    args = parser.parse_args(argv)
    handlers = {"generate": cmd_generate, "final": cmd_final, "compare": cmd_compare, "seal": cmd_seal}
    try:
        return handlers[args.command](args)
    except UsageError as error:
        return fail_usage(str(error))


if __name__ == "__main__":
    sys.exit(main())
