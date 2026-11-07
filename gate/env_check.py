"""Check the environment of one job, per role. Names what is broken, never a value."""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, load_config, write_json

SECRET_NAME_PARTS = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL", "API_KEY")
PROBE_TOKEN = "GATE_PROBE_TOKEN"

WRITE_PROBES = {
    "checks": ("POST", "/repos/{repo}/check-runs"),
    "contents": ("POST", "/repos/{repo}/git/refs"),
    "pull-requests": ("PATCH", "/repos/{repo}/pulls/{pr}"),
}
READ_PROBES = {
    "actions": "/repos/{repo}/actions/runs?per_page=1",
    "contents": "/repos/{repo}",
}
# A write probe changes nothing: a denied token answers 403, an allowed token 422 (the request
# is well-formed but cannot succeed). Two probes need a well-formed body, because an empty {}
# body is validated before the permission is checked and a read-only token would read as
# "allowed":
#   - contents: POST /git/refs a fresh unused branch at an all-zero (non-existent) object
#     (the false positive found on run 42361091565);
#   - pull-requests: PATCH /pulls/{pr}, moving the open PR's base to a non-existent branch. This
#     is a write the gate's actors legitimately hold (pull-requests: write). It is not the same
#     as POST /pulls, which the repository's "Allow GitHub Actions to create and approve pull
#     requests" setting blocks (off by default) and which the gate never needs: the launcher
#     opens PRs with the app token, and publish only posts PR comments. The empty-body POST
#     /pulls probe returned 403 even for an allowed token (run 42368667062, publish job).
# The checks write probe keeps the empty {} body (POST /check-runs answers 422 when allowed).
CONTENTS_PROBE_REF_PREFIX = "refs/heads/gate-probe-"
ZERO_SHA = "0" * 40
PR_PROBE_BASE_PREFIX = "gate-probe-"


def write_probe_body(name: str) -> dict:
    """The JSON body of a write probe: well-formed and doomed for contents and pull-requests, {} for checks."""
    if name == "contents":
        return {"ref": f"{CONTENTS_PROBE_REF_PREFIX}{secrets.token_hex(6)}", "sha": ZERO_SHA}
    if name == "pull-requests":
        return {"base": f"{PR_PROBE_BASE_PREFIX}{secrets.token_hex(6)}"}
    return {}


def event_pr_number() -> int | None:
    """The PR number from the workflow event (GITHUB_EVENT_PATH), or None.

    pull_request_target carries pull_request.number; issue_comment carries issue.number;
    workflow_run (same-repo) carries workflow_run.pull_requests[0].number. The pull-requests
    write probe needs an open PR to PATCH.
    """
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(event, dict):
        return None
    candidates = [event.get("pull_request"), event.get("issue")]
    runs = event.get("workflow_run")
    if isinstance(runs, dict) and isinstance(runs.get("pull_requests"), list) and runs["pull_requests"]:
        candidates.append(runs["pull_requests"][0])
    for obj in candidates:
        if isinstance(obj, dict) and isinstance(obj.get("number"), int):
            return obj["number"]
    return None

# Each job's permissions, as amended by AA-01.
ROLE_PERMISSIONS = {
    "run": {"read": ["contents"], "write": [], "denied": ["contents", "checks", "pull-requests"]},
    "publish": {
        "read": ["actions", "contents"],
        "write": ["checks", "pull-requests"],
        "denied": ["contents"],
    },
    "archive": {"read": [], "write": ["contents", "checks"], "denied": ["pull-requests"]},
    "feedback": {"read": ["contents"], "write": ["pull-requests"], "denied": ["contents", "checks"]},
}
ROLES = ("executor", "spec-tests", "run", "publish", "archive", "feedback", "reproduce")


@dataclass
class Item:
    item: str
    ok: bool
    reason: str = ""


def check_executor_secrets() -> list[Item]:
    items = []
    token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
    items.append(Item("secret:CLAUDE_CODE_OAUTH_TOKEN", bool(token), "" if token else "missing or empty"))

    key = os.environ.get("EXECUTOR_APP_PRIVATE_KEY", "")
    if not key:
        items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", False, "missing or empty"))
    elif not any(
        line.startswith("-----BEGIN ") and "PRIVATE KEY" in line for line in key.splitlines()
    ):
        items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", False, "has no PEM header line"))
    else:
        items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", True))

    app_id = os.environ.get("EXECUTOR_APP_ID", "")
    if not app_id:
        items.append(Item("variable:EXECUTOR_APP_ID", False, "missing or empty"))
    elif not (app_id.isascii() and app_id.isdigit() and int(app_id) > 0):
        items.append(Item("variable:EXECUTOR_APP_ID", False, "is not a positive integer"))
    else:
        items.append(Item("variable:EXECUTOR_APP_ID", True))
    return items


def check_no_secrets() -> list[Item]:
    items = []
    for name in sorted(os.environ):
        if name == PROBE_TOKEN or not os.environ[name]:
            continue
        if any(part in name.upper() for part in SECRET_NAME_PARTS):
            items.append(Item(f"secret-present:{name}", False, "a secret is present in this job"))
    return items


def probe(method: str, url: str, token: str, payload: dict | None = None) -> int | None:
    """Return the HTTP status of one harmless request, or None on a network error.

    A write (POST or PATCH) carries ``payload`` as JSON; a read (GET) carries no body. The body
    never changes anything: a write probe either lacks the permission (403) or sends a request
    that cannot succeed (422). See ``write_probe_body``.
    """
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check_permissions(role: str) -> list[Item]:
    table = ROLE_PERMISSIONS[role]
    expected = [
        *[(name, "read", "allowed") for name in table["read"]],
        *[(name, "write", "allowed") for name in table["write"]],
        *[(name, "write", "denied") for name in table["denied"]],
    ]
    token = os.environ.get(PROBE_TOKEN, "")
    api = os.environ.get("GITHUB_API_URL", "").rstrip("/")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = event_pr_number()
    items = []
    for name, kind, want in expected:
        label = f"permission:{name}-{kind}:{want}"
        if not token:
            items.append(Item(label, False, f"no token in {PROBE_TOKEN}"))
            continue
        if not api or not repo:
            items.append(Item(label, False, "GITHUB_API_URL or GITHUB_REPOSITORY is not set"))
            continue
        if kind == "read":
            status = probe("GET", api + READ_PROBES[name].format(repo=repo), token)
        else:
            method, route_template = WRITE_PROBES[name]
            if name == "pull-requests" and pr is None:
                items.append(Item(label, False, "no PR number in the event to probe pull-requests write"))
                continue
            route = route_template.format(repo=repo, pr=pr)
            status = probe(method, api + route, token, write_probe_body(name))
        if status is None:
            items.append(Item(label, False, "network error"))
        elif kind == "read":
            ok = status == 200
            items.append(Item(label, ok, "" if ok else f"read probe returned {status}"))
        elif status == 422:
            ok = want == "allowed"
            items.append(Item(label, ok, "" if ok else f"{name} write is allowed and must be denied"))
        elif status == 403:
            ok = want == "denied"
            items.append(Item(label, ok, "" if ok else f"{name} write is denied and must be allowed"))
        else:
            items.append(Item(label, False, f"write probe returned {status}"))
    return items


def check_environment(config: dict) -> list[Item]:
    wanted = config.get("environment", {})
    items = []
    if "python" in wanted:
        found = ".".join(platform.python_version_tuple()[:2])
        ok = found == str(wanted["python"])
        items.append(Item("environment:python", ok, "" if ok else f"expected {wanted['python']}, found {found}"))
    if "image_os" in wanted:
        found = os.environ.get("ImageOS", "") or "(not set)"
        ok = found == str(wanted["image_os"])
        items.append(Item("environment:image_os", ok, "" if ok else f"expected {wanted['image_os']}, found {found}"))
    return items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.env_check")
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--config")
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    config = {}
    if args.config:
        try:
            config = load_config(args.config)
        except UsageError as error:
            return fail_usage(str(error))

    items: list[Item] = []
    if args.role in ("executor", "spec-tests"):
        items += check_executor_secrets()
    if args.role in ("run", "reproduce"):
        items += check_no_secrets()
    if args.role in ROLE_PERMISSIONS:
        items += check_permissions(args.role)
    # A rerun runs in the pinned container, not on the runner, so ImageOS does not apply.
    if args.role == "reproduce":
        config = {"environment": {key: value for key, value in config.get("environment", {}).items() if key == "python"}}
    items += check_environment(config)

    for item in items:
        print(f"OK {item.item}" if item.ok else f"BROKEN {item.item}: {item.reason}")
    ok = all(item.ok for item in items)
    if args.out:
        write_json(args.out, {"role": args.role, "ok": ok, "items": [asdict(item) for item in items]})
    return EXIT_OK if ok else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
