"""The GitHub side of the judge: read trusted facts from the API and post the results.

Every value used here comes from the workflow's trusted context or from the API.
The token is read from GATE_TOKEN and never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from gate.feedback import MARKER as REVIEW_MARKER
from gate.common import (
    EXIT_OK,
    EXIT_RULE_FAILED,
    UsageError,
    fail_usage,
    load_config,
    neutralize,
    read_json,
    read_json_or_none,
    sha256_file,
    write_json,
)

MAX_COMMENT = 60_000
_TIME_COMMENT = re.compile(r"^/time\s+(\d+)\s*$", re.MULTILINE)
CONTEXT_VARIABLES = {
    "repository": "GATE_REPOSITORY",
    "head_repository": "GATE_HEAD_REPOSITORY",
    "pr": "GATE_PR",
    "run_id": "GATE_RUN_ID",
    "run_attempt": "GATE_RUN_ATTEMPT",
    "event": "GATE_EVENT",
    "base_sha": "GATE_BASE_SHA",
    "head_sha": "GATE_HEAD_SHA",
    "gate_sha": "GATE_SHA",
    "head_ref": "GATE_HEAD_REF",
}


def api_base() -> str:
    return os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")


def call(method: str, route: str, body: Any = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(api_base() + route, data=data, method=method)
    request.add_header("Accept", "application/vnd.github+json")
    token = os.environ.get("GATE_TOKEN", "")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read()
    return json.loads(payload) if payload else None


def get_all(route: str, key: str | None = None) -> list[Any]:
    """Read every page of a list."""
    items: list[Any] = []
    joiner = "&" if "?" in route else "?"
    for page in range(1, 101):
        data = call("GET", f"{route}{joiner}per_page=100&page={page}")
        batch = data[key] if key else data
        items += batch
        if len(batch) < 100:
            return items
    raise UsageError(f"too many pages at {route}")


def cmd_context(args: argparse.Namespace) -> int:
    context: dict[str, Any] = {}
    for field, variable in CONTEXT_VARIABLES.items():
        value = os.environ.get(variable)
        if not value:
            raise UsageError(f"{variable} is not set")
        context[field] = value
    context["pr"] = int(context["pr"])
    config = load_config(args.config)
    context["baseline_sha"] = str(config.get("project", {}).get("baseline_sha", ""))
    context["config_hashes"] = {Path(path).name: sha256_file(Path(path)) for path in args.hash}
    if os.environ.get("GATE_TRUSTED_SHA"):
        context["trusted_sha"] = os.environ["GATE_TRUSTED_SHA"]
    context["execution_environment"] = {
        "image_os": os.environ.get("ImageOS", "unknown"),
        "image_version": os.environ.get("ImageVersion", "unknown"),
    }
    write_json(args.out, context)
    return EXIT_OK


def cmd_jobs(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    route = f"/repos/{repository}/actions/runs/{args.run_id}/attempts/{args.attempt}/jobs"
    write_json(args.out, {"jobs": get_all(route, "jobs")})
    return EXIT_OK


def stored_rounds(reports_dir: Path, pr: int) -> list[dict]:
    rounds = []
    seen = set()
    for path in sorted((reports_dir / str(pr)).glob("*/guard.json")):
        record = read_json_or_none(path)
        if not isinstance(record, dict):
            continue
        head = record.get("head_sha")
        if head in seen or not isinstance(record.get("fingerprint"), dict):
            continue
        seen.add(head)
        rounds.append(
            {
                "head_sha": head,
                "round": record["fingerprint"].get("round"),
                "cumulative": record["fingerprint"].get("cumulative"),
            }
        )
    return rounds


def collect_merges(repository: str, integration: str) -> list[dict]:
    merges = []
    base = urllib.parse.quote(integration, safe="")
    for pull in get_all(f"/repos/{repository}/pulls?state=closed&base={base}"):
        if not pull.get("merged_at"):
            continue
        head = pull["head"]["sha"]
        number = pull["number"]
        runs = call("GET", f"/repos/{repository}/commits/{head}/check-runs?check_name=gate%2Ffinal").get("check_runs", [])
        conclusion = next((run.get("conclusion") for run in runs), None)
        reviews = get_all(f"/repos/{repository}/pulls/{number}/reviews")
        approvals = sum(review.get("state") == "APPROVED" and review.get("commit_id") == head for review in reviews)
        merges.append(
            {
                "pr": number,
                "merge_sha": pull.get("merge_commit_sha"),
                "merged_by": (pull.get("merged_by") or {}).get("login"),
                "head_sha": head,
                "final_conclusion": conclusion,
                "approvals": approvals,
                "via_pr": True,
            }
        )
    return merges


def collect_human(repository: str, pr: int) -> list[dict]:
    """Human minutes, from /time comments by the repository's owner only."""
    entries = []
    for comment in get_all(f"/repos/{repository}/issues/{pr}/comments"):
        if comment.get("author_association") != "OWNER":
            continue
        for match in _TIME_COMMENT.finditer(comment.get("body") or ""):
            entries.append({"minutes": int(match.group(1))})
    return entries


def cmd_extras(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    if not Path(args.reports_dir).is_dir():
        raise UsageError("the folder of stored runs is missing")
    environment = read_json_or_none(args.env_result) if args.env_result else {"ok": True}
    env_failures = [] if isinstance(environment, dict) and environment.get("ok") is True else ["publish"]
    write_json(
        args.out,
        {
            "env_failures": env_failures,
            "rounds": stored_rounds(Path(args.reports_dir), args.pr),
            "human": collect_human(repository, args.pr),
            "merges": collect_merges(repository, args.integration),
        },
    )
    return EXIT_OK


def post_check(repository: str, name: str, head_sha: str, conclusion: str, summary: str) -> None:
    call(
        "POST",
        f"/repos/{repository}/check-runs",
        {
            "name": name,
            "head_sha": head_sha,
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": f"{name}: {conclusion}", "summary": neutralize(summary)[:60_000]},
        },
    )


def reasons_text(reasons: list[Any]) -> str:
    lines = [f"- {item.get('code')}: {item.get('detail')}" for item in reasons if isinstance(item, dict)]
    return "\n".join(lines) or "No reasons."


def cmd_post_checks(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    verdict = read_json(args.verdict)
    summary = f"Preliminary verdict: {verdict['verdict']}\n{reasons_text(verdict.get('reasons', []))}"
    for name, conclusion in sorted(verdict["checks"].items()):
        post_check(repository, name, args.head_sha, conclusion, summary)
    return EXIT_OK


def cmd_post_final(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    final = read_json(args.final)
    summary = f"Final verdict: {final['verdict']}\n{reasons_text(final.get('reasons', []))}"
    for name in ("gate/archive", "gate/final"):
        post_check(repository, name, args.head_sha, final["conclusions"][name], summary)
    return EXIT_OK


def cmd_comment(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    body = Path(args.body).read_text(encoding="utf-8")
    if len(body) > MAX_COMMENT:
        body = body[:MAX_COMMENT] + "\n\nThe report was cut here; the whole report is on the reports branch.\n"
    call("POST", f"/repos/{repository}/issues/{args.pr}/comments", {"body": body})
    return EXIT_OK


def cmd_pulls(args: argparse.Namespace) -> int:
    repository = os.environ["GITHUB_REPOSITORY"]
    pulls = [
        {
            "number": pull["number"],
            "head_sha": pull["head"]["sha"],
            "base_ref": pull["base"]["ref"],
            "head_ref": pull["head"]["ref"],
        }
        for pull in get_all(f"/repos/{repository}/pulls?state=open")
    ]
    write_json(args.out, pulls)
    return EXIT_OK


def cmd_review_statuses(args: argparse.Namespace) -> int:
    """Fetch the statuses of the commit a reviewer's comment names, once its SHA is validated."""
    statuses: list[Any] = []
    event = read_json(args.event)
    if args.event_name == "issue_comment":
        match = REVIEW_MARKER.search(str((event.get("comment") or {}).get("body") or ""))
        if match:
            repository = os.environ["GITHUB_REPOSITORY"]
            statuses = get_all(f"/repos/{repository}/commits/{match.group(1)}/statuses")
    write_json(args.out, statuses)
    return EXIT_OK


def cmd_limits(args: argparse.Namespace) -> int:
    """Write the limits for the next job's expressions, into the step's output file."""
    config = load_config(args.config)
    limits = config.get("limits", {})
    max_turns = limits.get("max_turns")
    timeout = limits.get("timeout_minutes")
    if not isinstance(max_turns, int) or not isinstance(timeout, int) or max_turns < 1 or timeout < 1:
        raise UsageError("[limits] needs max_turns and timeout_minutes as positive integers")
    deny = config.get("spec_tests", {}).get("deny_read", [])
    settings = {
        "permissions": {
            "deny": [f"{tool}({path})" for path in deny for tool in ("Read", "Grep", "Glob", "Edit", "Write")]
        }
    }
    with open(args.output, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"max-turns={max_turns}\n")
        handle.write(f"timeout-minutes={timeout}\n")
        handle.write(f"integration-branch={config.get('project', {}).get('integration_branch', '')}\n")
        handle.write(f"spec-settings={json.dumps(settings, separators=(',', ':'))}\n")
    return EXIT_OK


def cmd_hide_paths(args: argparse.Namespace) -> int:
    """Take the denied paths out of the working folder, without marking them as deleted."""
    config = load_config(args.config)
    deny = config.get("spec_tests", {}).get("deny_read", [])
    if not deny:
        raise UsageError("spec_tests.deny_read is empty: the spec-test author would see the code")
    patterns = ["/*"] + [f"!/{path.rstrip('*').rstrip('/')}/" for path in deny]
    process = subprocess.run(
        ["git", "-C", args.repo, "sparse-checkout", "set", "--no-cone", *patterns],
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        print("sparse-checkout failed", file=sys.stderr)
        return EXIT_RULE_FAILED
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.publish")
    commands = parser.add_subparsers(dest="command", required=True)

    context = commands.add_parser("context")
    context.add_argument("--config", required=True)
    context.add_argument("--hash", action="append", default=[])
    context.add_argument("--out", required=True)
    context.set_defaults(handler=cmd_context)

    jobs = commands.add_parser("jobs")
    jobs.add_argument("--run-id", required=True)
    jobs.add_argument("--attempt", required=True)
    jobs.add_argument("--out", required=True)
    jobs.set_defaults(handler=cmd_jobs)

    extras = commands.add_parser("extras")
    extras.add_argument("--reports-dir", required=True)
    extras.add_argument("--pr", type=int, required=True)
    extras.add_argument("--integration", required=True)
    extras.add_argument("--env-result")
    extras.add_argument("--out", required=True)
    extras.set_defaults(handler=cmd_extras)

    post_checks = commands.add_parser("post-checks")
    post_checks.add_argument("--verdict", required=True)
    post_checks.add_argument("--head-sha", required=True)
    post_checks.set_defaults(handler=cmd_post_checks)

    post_final = commands.add_parser("post-final")
    post_final.add_argument("--final", required=True)
    post_final.add_argument("--head-sha", required=True)
    post_final.set_defaults(handler=cmd_post_final)

    comment = commands.add_parser("comment")
    comment.add_argument("--pr", type=int, required=True)
    comment.add_argument("--body", required=True)
    comment.set_defaults(handler=cmd_comment)

    pulls = commands.add_parser("pulls")
    pulls.add_argument("--out", required=True)
    pulls.set_defaults(handler=cmd_pulls)

    review_statuses = commands.add_parser("review-statuses")
    review_statuses.add_argument("--event-name", required=True)
    review_statuses.add_argument("--event", required=True)
    review_statuses.add_argument("--out", required=True)
    review_statuses.set_defaults(handler=cmd_review_statuses)

    limits = commands.add_parser("limits")
    limits.add_argument("--config", required=True)
    limits.add_argument("--output", required=True)
    limits.set_defaults(handler=cmd_limits)

    hide = commands.add_parser("hide-paths")
    hide.add_argument("--config", required=True)
    hide.add_argument("--repo", required=True)
    hide.set_defaults(handler=cmd_hide_paths)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except UsageError as error:
        return fail_usage(str(error))
    except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
        # The message names the kind of failure only: a token never enters it.
        print(f"publish: {type(error).__name__} in {args.command}", file=sys.stderr)
        return EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
