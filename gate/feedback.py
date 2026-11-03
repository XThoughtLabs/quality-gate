"""Decide whether a fix round may start (decisions N and R). Standard library only.

A round starts from a finished judge run (workflow_run) or from the independent
reviewer's comment (issue_comment). Nothing in a comment's text is believed: the sender
comes from the event, and the verdict from the status the reviewer's app posted.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

from gate.common import EXIT_OK, MENTION, UsageError, fail_usage, load_config, neutralize, read_json, read_json_or_none, write_json

REVIEW_CONTEXT = "independent-review"
SAFE_REF = re.compile(r"[A-Za-z0-9._/-]+")
# Written by gate.review_local. Only its SHA is used, and that SHA is then checked.
MARKER = re.compile(r"<!-- gate-review sha=([0-9a-f]{40}) verdict=(pass|changes_requested) -->")

_EXPLAIN = {
    "UNEXPECTED_SENDER": "the event did not come from the expected app or workflow",
    "NO_RECORD": "no stored record exists for this judge run",
    "NOT_A_FAILURE": "nothing failed, so there is nothing to fix",
    "NOT_A_REVIEW": "this comment is not on a pull request",
    "NEEDS_HUMAN": "this PR already needs a person",
    "NO_MARKER": "the reviewer's comment has no valid marker",
    "STATUS_NOT_FAILURE": f"the {REVIEW_CONTEXT} status on this commit is not a failure",
    "STATUS_WRONG_CREATOR": f"the {REVIEW_CONTEXT} status on this commit was not posted by the reviewer's app",
    "SHA_NOT_CURRENT_HEAD": "this commit is not the current head of an open PR",
    "PR_NOT_INTO_INTEGRATION": "this PR does not target the integration branch",
    "ROUND_CAP": "the cap on fix rounds is reached, so a person must decide",
    "REPEATED_FIX": "this round repeats an earlier fix, so a person must decide",
}
# Said nowhere: anyone can comment on a public repository, and the gate must not answer each one.
SILENT = {"NOT_A_FAILURE", "NOT_A_REVIEW", "UNEXPECTED_SENDER"}


def find_record(reports_dir: Path, run_id: Any, attempt: Any) -> Path | None:
    matches = sorted(reports_dir.glob(f"*/{run_id}-{attempt}"))
    return matches[0] if matches else None


def done_rounds(reports_dir: Path, pr: int) -> tuple[int, list[dict]]:
    records = []
    for path in sorted((reports_dir / str(pr)).glob("*/guard.json")):
        record = read_json_or_none(path)
        if isinstance(record, dict):
            records.append(record)
    heads = {record.get("head_sha") for record in records if record.get("head_sha")}
    return max(len(heads) - 1, 0), records


def outcome(code: str | None, pr: Any, head_sha: Any, round_number: Any = None, failures: list[str] | None = None) -> dict:
    if code is None:
        text = f"{MENTION} fix round {round_number} for commit {neutralize(head_sha)}. The gate reports:"
        items = [f"- {neutralize(item)}" for item in failures or []]
        comment = "\n".join([text, *items]) if items else text
    else:
        comment = f"The gate did not start a fix round ({code}): {_EXPLAIN[code]}."
    return {
        "act": code is None,
        "post": code not in SILENT,
        "pr": pr,
        "head_sha": head_sha,
        "round": round_number,
        "reason_code": code,
        "comment": comment,
    }


def latest_review_status(statuses: Any) -> dict | None:
    """The newest independent-review status. The API lists a commit's newest status first."""
    if not isinstance(statuses, list):
        return None
    for status in statuses:
        if isinstance(status, dict) and status.get("context") == REVIEW_CONTEXT:
            return status
    return None


def read_comment_event(event: dict, feedback: dict, statuses: Any) -> tuple[str | None, Any, Any, list[str]]:
    """Check a comment event. Returns a reason code or None, then the PR, the SHA and the failures."""
    issue = event.get("issue") if isinstance(event.get("issue"), dict) else {}
    if event.get("action") != "created" or not issue.get("pull_request"):
        return "NOT_A_REVIEW", None, None, []
    pr = issue.get("number")
    expected = f"{feedback.get('reviewer_app')}[bot]"
    sender = event.get("sender") if isinstance(event.get("sender"), dict) else {}
    if sender.get("login") != expected:
        return "UNEXPECTED_SENDER", pr, None, []
    comment = event.get("comment") if isinstance(event.get("comment"), dict) else {}
    marker = MARKER.search(str(comment.get("body") or ""))
    if marker is None:
        return "NO_MARKER", pr, None, []
    head_sha = marker.group(1)
    if marker.group(2) != "changes_requested":
        return "NOT_A_FAILURE", pr, head_sha, []
    status = latest_review_status(statuses)
    if status is None or status.get("state") != "failure":
        return "STATUS_NOT_FAILURE", pr, head_sha, []
    creator = status.get("creator") if isinstance(status.get("creator"), dict) else {}
    if creator.get("login") != expected:
        return "STATUS_WRONG_CREATOR", pr, head_sha, []
    return None, pr, head_sha, ["the independent review requested changes; its findings are in the PR's comments"]


def decide(event_name: str, event: dict, pulls: list[dict], reports_dir: Path, config: dict, integration: str, statuses: Any) -> dict:
    if not reports_dir.is_dir():
        raise UsageError("the folder of stored runs is missing")
    feedback = config.get("feedback", {})
    failures: list[str] = []
    pr: Any = None

    if event_name == "workflow_run":
        run = event.get("workflow_run", {})
        if run.get("path") != feedback.get("judge_workflow_path") or run.get("event") != "pull_request_target":
            return outcome("UNEXPECTED_SENDER", None, None)
        record = find_record(reports_dir, run.get("id"), run.get("run_attempt"))
        if record is None:
            return outcome("NO_RECORD", None, None)
        context = read_json_or_none(record / "context.json")
        final = read_json_or_none(record / "final.json")
        if not isinstance(context, dict) or not isinstance(final, dict):
            return outcome("NO_RECORD", None, None)
        pr = context.get("pr")
        head_sha = context.get("head_sha")
        if final.get("verdict") == "ready-for-human":
            return outcome("NOT_A_FAILURE", pr, head_sha)
        if final.get("verdict") == "needs-human":
            return outcome("NEEDS_HUMAN", pr, head_sha)
        for item in final.get("reasons", []):
            if isinstance(item, dict):
                failures.append(f"{item.get('code')}: {item.get('detail')}")
    elif event_name == "issue_comment":
        code, pr, head_sha, failures = read_comment_event(event, feedback, statuses)
        if code is not None:
            return outcome(code, pr, head_sha)
    else:
        raise UsageError(f"unsupported event: {event_name}")

    pull = next((item for item in pulls if item.get("head_sha") == head_sha), None)
    if pull is None or (event_name == "issue_comment" and pull.get("number") != pr):
        return outcome("SHA_NOT_CURRENT_HEAD", pr, head_sha)
    pr = pull.get("number")
    if pull.get("base_ref") != integration:
        return outcome("PR_NOT_INTO_INTEGRATION", pr, head_sha)

    done, records = done_rounds(reports_dir, pr)
    if done >= config.get("limits", {}).get("max_fix_rounds", 3):
        return outcome("ROUND_CAP", pr, head_sha)
    if any(record.get("head_sha") == head_sha and record.get("repeated_fix") is True for record in records):
        return outcome("REPEATED_FIX", pr, head_sha)
    decision = outcome(None, pr, head_sha, done + 1, failures)
    decision["head_ref"] = pull.get("head_ref")
    return decision


def cmd_outputs(args: argparse.Namespace) -> int:
    """Hand a decision to the workflow. Each value is checked: it reaches an expression."""
    decision = read_json(args.decision)
    config = load_config(args.config)
    feedback = config.get("feedback", {})
    head_ref = str(decision.get("head_ref") or "")
    if head_ref and not SAFE_REF.fullmatch(head_ref):
        raise UsageError("the PR's branch name holds characters the gate does not pass on")
    pr = decision.get("pr")
    if pr is not None and not (isinstance(pr, int) and not isinstance(pr, bool) and pr > 0):
        raise UsageError("the PR number is not a positive integer")
    apps = [str(feedback.get(key)) for key in ("reviewer_app", "executor_app") if feedback.get(key)]
    if not all(SAFE_REF.fullmatch(app) for app in apps):
        raise UsageError("an app's name holds characters the gate does not pass on")
    with open(args.output, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"act={'true' if decision.get('act') else 'false'}\n")
        handle.write(f"post={'true' if decision.get('post') and pr else 'false'}\n")
        handle.write(f"pr={pr or ''}\n")
        handle.write(f"head-ref={head_ref}\n")
        handle.write(f"allowed-bots={','.join(apps)}\n")
    note = Path(args.note)
    note.parent.mkdir(parents=True, exist_ok=True)
    note.write_text(str(decision.get("comment", "")) + "\n", encoding="utf-8", newline="\n")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.feedback")
    commands = parser.add_subparsers(dest="command", required=True)
    outputs_parser = commands.add_parser("outputs")
    outputs_parser.add_argument("--decision", required=True)
    outputs_parser.add_argument("--config", required=True)
    outputs_parser.add_argument("--output", required=True)
    outputs_parser.add_argument("--note", required=True)
    decide_parser = commands.add_parser("decide")
    decide_parser.add_argument("--event-name", required=True)
    decide_parser.add_argument("--event", required=True)
    decide_parser.add_argument("--pulls", required=True)
    decide_parser.add_argument("--reports-dir", required=True)
    decide_parser.add_argument("--config", required=True)
    decide_parser.add_argument("--out", required=True)
    decide_parser.add_argument("--integration-branch")
    decide_parser.add_argument("--statuses", help="the commit's statuses from the API, for a comment event")
    args = parser.parse_args(argv)

    if args.command == "outputs":
        try:
            return cmd_outputs(args)
        except (UsageError, OSError, ValueError) as error:
            return fail_usage(str(error))

    try:
        config = load_config(args.config)
        try:
            event = read_json(args.event)
            pulls = read_json(args.pulls)
        except (OSError, ValueError) as error:
            raise UsageError("cannot read the event or the pulls") from error
        statuses = read_json_or_none(args.statuses) if args.statuses else None
        integration = args.integration_branch or config.get("project", {}).get("integration_branch", "candidate/a")
        decision = decide(args.event_name, event, pulls, Path(args.reports_dir), config, integration, statuses)
    except UsageError as error:
        return fail_usage(str(error))

    write_json(args.out, decision)
    print(decision["comment"])
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
