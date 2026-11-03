"""Check the environment of one job, per role. Names what is broken, never a value."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, load_config, write_json

SECRET_NAME_PARTS = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL", "API_KEY")
PROBE_TOKEN = "GATE_PROBE_TOKEN"

WRITE_PROBES = {
    "checks": "/repos/{repo}/check-runs",
    "contents": "/repos/{repo}/git/refs",
    "pull-requests": "/repos/{repo}/pulls",
}
READ_PROBES = {
    "actions": "/repos/{repo}/actions/runs?per_page=1",
    "contents": "/repos/{repo}",
}

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


def probe(method: str, url: str, token: str) -> int | None:
    """Return the HTTP status of one harmless request, or None on a network error."""
    body = b"{}" if method == "POST" else None
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
    items = []
    for name, kind, want in expected:
        label = f"permission:{name}-{kind}:{want}"
        if not token:
            items.append(Item(label, False, f"no token in {PROBE_TOKEN}"))
            continue
        if not api or not repo:
            items.append(Item(label, False, "GITHUB_API_URL or GITHUB_REPOSITORY is not set"))
            continue
        route = (WRITE_PROBES if kind == "write" else READ_PROBES)[name].format(repo=repo)
        status = probe("POST" if kind == "write" else "GET", api + route, token)
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
