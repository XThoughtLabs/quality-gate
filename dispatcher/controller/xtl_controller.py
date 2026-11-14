"""The milestone controller of stage A: one run for one PR of the approved queue (CONTROLLER-CONTRACT.md).

    <python> -I xtl_controller.py --config <controller.toml> --repo <owner>/<name> --pr <N>
                                  --queue <queue.json> --queue-sha256 <64 hex>

It checks the PR, its task, its diff, the gate's checks and stored report, and the independent review (CR-2 to CR-6),
posts the required check stage-a/policy as the controller's app (CR-7), and merges through GitHub's protected path
with the expected head (CR-8). It prints one stop line and exits with the code of CR-12.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

API = "https://api.github.com"
ROOT = Path(__file__).resolve().parents[2]
SETUP_SCRIPT = ROOT / "setup" / "setup_apps.py"

EXIT = {"MERGED": 0, "REFUSED": 1, "USAGE": 2, "WAITING": 3, "MERGE_REFUSED": 4, "ALREADY_MERGED": 5,
        "GITHUB_ERROR": 6, "LOCKED": 7}
RULES = ("CR-2", "CR-3", "CR-4", "CR-5", "CR-6")
WAITING_CODES = {"GATE_CHECK_MISSING", "GATE_CHECK_PENDING", "REPORT_MISSING", "REVIEW_MISSING", "REVIEW_PENDING"}
OPTIONS = ("--config", "--repo", "--pr", "--queue", "--queue-sha256")
QUEUE_FORMAT = "xtl-stage-a-queue/1"
READY = "ready-for-human"
REVIEW_CONTEXT = "independent-review"
REPORTS_AUTHOR = "github-actions[bot]"
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
TOKEN_PERMISSIONS = {"contents": "write", "checks": "write", "pull_requests": "read", "statuses": "read"}
MAX_PAGES = 10
PER_PAGE = 100
MAX_COMPARE_FILES = 300
MERGEABLE_WAIT_SECONDS = 5
TIMEOUT_SECONDS = 30
SHA40 = re.compile(r"[0-9a-f]{40}")
BRANCH = re.compile(r"ai/[1-9][0-9]{0,9}-(.+)")
TEST_CONFIG_NAMES = {
    "pytest.ini", ".pytest.ini", "pytest.toml", ".pytest.toml", "tox.ini", "setup.cfg", ".coveragerc", ".bandit",
    "bandit.yaml", "bandit.yml", ".gitleaks.toml", ".gitleaksignore", ".gitattributes", "ruff.toml", ".ruff.toml",
    "mypy.ini", ".mypy.ini", ".semgrep.yml", "security-review.md",
}
CONTROL_NAMES = {"quality.toml", "codeowners"}
DEPENDENCY_NAMES = {"pyproject.toml", "setup.py", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock"}
DEPENDENCY_PATTERN = re.compile(r"(requirements.*\.(txt|in|lock)|constraints.*\.txt)")
SCHEMA_FOLDERS = {"migrations", "migration", "alembic"}
DDL = re.compile(r"\b(CREATE|ALTER|DROP)\s+(TABLE|INDEX|VIEW|TRIGGER)\b|\bPRAGMA\s+user_version\b", re.IGNORECASE)
CODEOWNERS_PLACES = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
CODEOWNERS_UNSUPPORTED = set("*?[]!\\")


class ControllerError(Exception):
    """A stop of the run with an outcome of CR-12 and its detail."""

    def __init__(self, outcome: str, detail: str) -> None:
        super().__init__(detail)
        self.outcome = outcome
        self.detail = detail


class Unreadable(Exception):
    """A request failed or an answer had the wrong shape (fail closed)."""

    def __init__(self, detail: str, status: int | None = None) -> None:
        super().__init__(detail)
        self.status = status


class NotFound(Unreadable):
    pass


class Failed(Exception):
    """A rule failed with a code of the contract."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------- small pure helpers
def branch_slug(title: str) -> str:
    """LR-22 of the launcher's contract, re-implemented (a test compares it with the launcher's)."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(title).lower()).strip("-")
    if len(slug) > 40:
        cut = slug[:40]
        dash = cut.rfind("-")
        if dash >= 30:
            cut = cut[:dash]
        slug = cut.strip("-")
    return slug or "task"


def is_count(value: Any) -> bool:
    """A positive integer; True and False are integers in Python and are refused."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def is_text(value: Any) -> bool:
    return isinstance(value, str) and value != "" and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


class Secrets:
    """Every JWT and token of the run; each printed or logged text passes through scrub()."""

    def __init__(self) -> None:
        self.values: list[str] = []

    def add(self, value: str) -> None:
        if value:
            self.values.append(value)

    def scrub(self, text: str) -> str:
        for value in self.values:
            text = text.replace(value, "[secret]")
        return text


def default_http(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
    """One request to GitHub's API with a 30 s timeout; an HTTP error's status and body are an answer (CR-11)."""
    parts = urllib.parse.urlsplit(url)
    if not url.startswith(API + "/") or parts.scheme != "https" or parts.netloc != "api.github.com":
        raise ControllerError("GITHUB_ERROR", "a request to a host other than api.github.com was refused")
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310  # reason: https only, checked above
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, OSError) as error:
        raise Unreadable(f"no answer from GitHub ({type(error).__name__})") from None


def default_windows() -> Any:
    """The setup script's Windows object (setup/setup_apps.py of this repository), for the key's access rules."""
    name = "xtl_setup_apps"
    module = sys.modules.get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, SETUP_SCRIPT)
        if spec is None or spec.loader is None:
            raise ControllerError("USAGE", f"KEY_UNSAFE: the setup script {SETUP_SCRIPT} cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module.Windows()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(app_id: int, key: Any, now: float) -> str:
    """The app's JWT: RS256, issued 60 s back, expiring 9 minutes ahead (CR-11)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    issued = int(now)
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"iat": issued - 60, "exp": issued + 540, "iss": app_id}, separators=(",", ":")).encode())
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{claims}.{b64url(signature)}"


# ---------------------------------------------------------------- CR-1: the inputs
def usage(detail: str) -> ControllerError:
    return ControllerError("USAGE", detail)


def parse_args(argv: list[str]) -> dict[str, Any]:
    if len(argv) % 2:
        raise usage("every option takes one value: " + " ".join(OPTIONS))
    values: dict[str, str] = {}
    for index in range(0, len(argv), 2):
        key, value = argv[index], argv[index + 1]
        if key not in OPTIONS:
            raise usage(f"unknown option {key!r}")
        if key in values:
            raise usage(f"{key} is given twice")
        values[key] = value
    missing = [key for key in OPTIONS if key not in values]
    if missing:
        raise usage("missing " + ", ".join(missing))
    if not re.fullmatch(r"[1-9][0-9]{0,9}", values["--pr"]):
        raise usage("--pr must be a positive decimal integer")
    if not re.fullmatch(r"[0-9a-f]{64}", values["--queue-sha256"]):
        raise usage("--queue-sha256 must be 64 lowercase hexadecimal characters")
    if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", values["--repo"]):
        raise usage("--repo must be <owner>/<name>")
    return {"config": Path(values["--config"]), "repo": values["--repo"], "pr": int(values["--pr"]),
            "queue": Path(values["--queue"]), "queue_sha256": values["--queue-sha256"]}


def _folder(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/", value) is not None \
        and ".." not in value.split("/") and "." not in value.split("/")


CONFIG_SCHEMA: dict[str, dict[str, Callable[[Any], bool]]] = {
    "controller": {
        "app_id": is_count, "installation_id": is_count,
        "key_file": lambda v: isinstance(v, str) and Path(v).is_absolute(),
        "log_file": lambda v: isinstance(v, str) and Path(v).is_absolute(),
        "base_branch": is_text, "reports_branch": is_text,
    },
    "executor": {"app_slug": lambda v: isinstance(v, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", v) is not None,
                 "app_id": is_count, "bot_id": is_count},
    "reviewer": {"app_slug": lambda v: isinstance(v, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", v) is not None,
                 "app_id": is_count, "bot_id": is_count},
    "gate": {
        "actions_app_id": is_count,
        "checks": lambda v: isinstance(v, list) and len(v) > 0 and len(set(map(str, v))) == len(v)
        and all(isinstance(x, str) and re.fullmatch(r"gate/[a-z]+", x) for x in v),
        "policy_check": is_text,
    },
    "policy": {"code_folders": lambda v: isinstance(v, list) and len(v) > 0 and all(_folder(x) for x in v),
               "test_folder": _folder},
}


def load_config(path: Path) -> dict[str, dict[str, Any]]:
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise usage(f"the configuration {path} cannot be read ({type(error).__name__})") from None
    if set(data) != set(CONFIG_SCHEMA):
        raise usage("the configuration must hold exactly the tables " + ", ".join(CONFIG_SCHEMA))
    for table, keys in CONFIG_SCHEMA.items():
        given = data[table]
        if not isinstance(given, dict) or set(given) != set(keys):
            raise usage(f"[{table}] must hold exactly: " + ", ".join(keys))
        for key, valid in keys.items():
            if not valid(given[key]):
                raise usage(f"[{table}] {key} has a value of the wrong kind")
    return data


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def load_queue(path: Path, recorded: str, repo: str, config: dict) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise usage(f"QUEUE_INVALID: the queue {path} cannot be read ({type(error).__name__})") from None
    digest = hashlib.sha256(data).hexdigest()
    if digest != recorded:
        raise usage(f"QUEUE_CHANGED: the queue's SHA-256 is {digest}, the approved one is {recorded}")

    def invalid(why: str) -> ControllerError:
        return usage(f"QUEUE_INVALID: {why}")

    try:
        queue = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError) as error:
        raise invalid(f"not strict JSON ({error})") from None
    if not isinstance(queue, dict) or queue.get("format") != QUEUE_FORMAT:
        raise invalid(f"format must be {QUEUE_FORMAT}")
    if queue.get("repository") != repo:
        raise invalid("its repository is not --repo")
    if queue.get("integration_branch") != config["controller"]["base_branch"]:
        raise invalid("its integration_branch is not [controller] base_branch")
    for key in ("base_sha", "defects_sha"):
        if not isinstance(queue.get(key), str) or not SHA40.fullmatch(queue[key]):
            raise invalid(f"{key} must be 40 lowercase hexadecimal characters")
    tasks = queue.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise invalid("tasks must be a non-empty list")
    ids: set[str] = set()
    slugs: dict[str, str] = {}
    for task in tasks:
        if not isinstance(task, dict):
            raise invalid("each task must be an object")
        task_id, title = task.get("id"), task.get("title")
        if not isinstance(task_id, str) or not re.fullmatch(r"[A-Z][A-Z0-9]*-T[1-9][0-9]*", task_id):
            raise invalid(f"task id {task_id!r} has the wrong form")
        if task_id in ids:
            raise invalid(f"task id {task_id} is given twice")
        ids.add(task_id)
        if not isinstance(title, str) or not title.startswith(task_id + " ") or not is_text(title):
            raise invalid(f"the title of {task_id} must start with its ID and a space")
        if task.get("depends_on") != []:
            raise invalid(f"{task_id} has dependencies; stage A's queue has none")
        for key in ("text", "expected"):
            if not isinstance(task.get(key), str) or not task[key].strip():
                raise invalid(f"{task_id} has no {key}")
        slug = branch_slug(title)
        if slug in slugs:
            raise invalid(f"{task_id} and {slugs[slug]} have the same branch slug {slug}")
        slugs[slug] = task_id
    queue["_sha256"] = digest
    queue["_slugs"] = slugs
    return queue


# ---------------------------------------------------------------- CR-11: the key
def check_key(path: Path, windows: Any) -> bytes:
    """The key file and its folder open to nobody but the operator, SYSTEM and Administrators; then read it."""
    def unsafe(why: str) -> ControllerError:
        return usage(f"KEY_UNSAFE: {why}")

    try:
        info = os.lstat(path)
    except OSError:
        raise unsafe(f"{path} does not exist or cannot be seen") from None
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:  # 0x400: a reparse point
        raise unsafe(f"{path} is a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        raise unsafe(f"{path} is not a regular file")
    try:
        operator = windows.current_sid()
        for target in (path, path.parent):
            _protected, rules = windows.acl_of(target)
            for sid, _rights, kind, _inherited in rules:
                if kind == "Allow" and sid not in (operator, SYSTEM_SID, ADMINISTRATORS_SID):
                    raise unsafe(f"{target} gives access to {sid}, beyond your user, SYSTEM and Administrators")
    except ControllerError:
        raise
    except Exception as error:  # noqa: BLE001  # reason: any failure to read the rules refuses the key (fail closed)
        raise unsafe(f"the access rules of {path} cannot be read ({type(error).__name__})") from None
    try:
        return path.read_bytes()
    except OSError:
        raise unsafe(f"{path} cannot be read") from None


def load_key(pem: bytes) -> Any:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise usage("KEY_UNSAFE: the key file is not a readable private key") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise usage("KEY_UNSAFE: the key file is not an RSA private key")
    return key


# ---------------------------------------------------------------- CR-4: paths
def plain_path(path: Any) -> bool:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def codeowners_names(pattern: str, path: str) -> bool:
    """Whether one supported CODEOWNERS pattern names the path or one of its folders (both in lower case)."""
    folder_only = pattern.endswith("/")
    body = pattern.rstrip("/")
    anchored = body.startswith("/")
    body = body.lstrip("/")
    if not body:
        return True
    segments = path.split("/")
    if anchored or "/" in body:
        wanted = body.split("/")
        if segments[: len(wanted)] != wanted:
            return False
        return not (folder_only and len(segments) == len(wanted))
    for index, segment in enumerate(segments):
        if segment == body and not (folder_only and index == len(segments) - 1):
            return True
    return False


# ---------------------------------------------------------------- the run on GitHub
class Run:
    def __init__(self, args: dict, config: dict, queue: dict, http: Callable, sleep: Callable, clock: Callable,
                 key: Any, secrets: Secrets) -> None:
        self.args = args
        self.config = config
        self.queue = queue
        self.http = http
        self.sleep = sleep
        self.clock = clock
        self.key = key
        self.secrets = secrets
        self.repo = args["repo"]
        self.pr = args["pr"]
        self.token: str | None = None
        self.record: dict[str, Any] = {
            "time": None, "repository": self.repo, "pr": self.pr, "head_sha": None, "base_tip": None,
            "task_id": None, "queue_sha256": queue["_sha256"], "rules": {}, "outcome": None,
            "policy_check_id": None, "merge_sha": None, "message": None,
        }
        self.posted = "nothing"

    # ------------------------------------------------------------ requests
    def request(self, method: str, route: str, body: Any = None, bearer: str | None = None) -> tuple[int, Any]:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {bearer if bearer is not None else self.token}",
            "User-Agent": "xtl-controller",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, raw = self.http(method, API + route, headers, data)
        try:
            answer = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError):
            answer = None
        return status, answer

    def get(self, route: str) -> Any:
        status, answer = self.request("GET", route)
        if status == 404:
            raise NotFound(f"GET {route.split('?')[0]} answered 404", 404)
        if status != 200:
            raise Unreadable(f"GET {route.split('?')[0]} answered {status}", status)
        return answer

    def pages(self, route: str, key: str | None = None) -> list:
        items: list = []
        joiner = "&" if "?" in route else "?"
        for page in range(1, MAX_PAGES + 1):
            answer = self.get(f"{route}{joiner}per_page={PER_PAGE}&page={page}")
            batch = answer.get(key) if key is not None and isinstance(answer, dict) else answer
            if not isinstance(batch, list):
                raise Unreadable(f"GET {route.split('?')[0]} gave no list")
            items.extend(batch)
            if len(batch) < PER_PAGE:
                return items
        raise Unreadable(f"GET {route.split('?')[0]} has more than {MAX_PAGES} pages")

    def message(self, status: int, answer: Any) -> str:
        text = answer.get("message") if isinstance(answer, dict) else None
        return self.secrets.scrub(f"{status} {text if isinstance(text, str) else 'no message'}")

    def get_token(self) -> None:
        cfg = self.config["controller"]
        jwt = make_jwt(cfg["app_id"], self.key, self.clock())
        self.secrets.add(jwt)
        name = self.repo.split("/", 1)[1]
        status, answer = self.request("POST", f"/app/installations/{cfg['installation_id']}/access_tokens",
                                      {"repositories": [name], "permissions": dict(TOKEN_PERMISSIONS)}, bearer=jwt)
        token = answer.get("token") if isinstance(answer, dict) else None
        if status != 201 or not isinstance(token, str) or not token:
            self.record["message"] = self.message(status, answer)
            raise ControllerError("GITHUB_ERROR", f"no installation token: GitHub answered {self.record['message']}")
        self.secrets.add(token)
        self.token = token

    def read_pr(self) -> dict:
        try:
            pr = self.get(f"/repos/{self.repo}/pulls/{self.pr}")
            head = pr["head"]["sha"]
        except (Unreadable, KeyError, TypeError) as error:
            raise ControllerError("GITHUB_ERROR", f"the PR cannot be read ({error}); posted: {self.posted}") from None
        if not isinstance(head, str) or not SHA40.fullmatch(head):
            raise ControllerError("GITHUB_ERROR", f"the PR gives no head SHA; posted: {self.posted}")
        return pr

    # ------------------------------------------------------------ CR-2 to CR-6
    def rule_pr(self, pr: dict, info: dict) -> None:
        cfg, executor = self.config["controller"], self.config["executor"]
        if pr.get("state") != "open" or pr.get("merged") is True:
            raise Failed("PR_NOT_OPEN", f"the PR is {pr.get('state')}")
        if pr.get("draft") is not False:
            raise Failed("PR_DRAFT", "the PR is a draft")
        base = pr["base"]
        if base.get("ref") != cfg["base_branch"] or str((base.get("repo") or {}).get("full_name")).lower() != self.repo.lower():
            raise Failed("PR_WRONG_BASE", f"the PR's base is {base.get('ref')} of {(base.get('repo') or {}).get('full_name')}")
        head_repo = pr["head"].get("repo")
        if not isinstance(head_repo, dict) or str(head_repo.get("full_name")).lower() != self.repo.lower():
            raise Failed("PR_FROM_FORK", "the PR does not come from a branch of this repository")
        user = pr.get("user") or {}
        login = f"{executor['app_slug']}[bot]"
        if user.get("login") != login or not is_count(user.get("id")) or user.get("id") != executor["bot_id"] \
                or user.get("type") != "Bot":
            raise Failed("PR_NOT_BY_EXECUTOR", f"the PR was opened by {user.get('login')}, not {login}")
        info["pr_line"] = f"PR #{self.pr} by {login} into {cfg['base_branch']} from {self.repo}"

    def rule_task(self, pr: dict, info: dict) -> None:
        ref = pr["head"]["ref"]
        match = BRANCH.fullmatch(ref) if isinstance(ref, str) else None
        task_id = self.queue["_slugs"].get(match.group(1)) if match else None
        if task_id is None:
            raise Failed("NO_TASK", f"the branch {ref} maps to no task of the queue")
        info["task_id"] = task_id
        self.record["task_id"] = task_id
        slug = match.group(1)
        log = Path(self.config["controller"]["log_file"])
        if log.exists():
            for line in log.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                entry = json.loads(line)
                if str(entry.get("repository", "")).lower() == self.repo.lower() and entry.get("task_id") == task_id \
                        and entry.get("outcome") == "MERGED":
                    raise Failed("TASK_DONE", f"the run log records {task_id} as merged (PR {entry.get('pr')})")
        base = urllib.parse.quote(self.config["controller"]["base_branch"], safe="")
        for item in self.pages(f"/repos/{self.repo}/pulls?state=closed&base={base}"):
            other = BRANCH.fullmatch(str((item.get("head") or {}).get("ref", "")))
            if other and other.group(1) == slug and item.get("merged_at"):
                raise Failed("TASK_DONE", f"{task_id} was merged by PR {item.get('number')}")
        title = next(t["title"] for t in self.queue["tasks"] if t["id"] == task_id)
        info["task_line"] = f"task {task_id} ({title}), branch {ref}"

    def read_codeowners(self, tip: str) -> list[str]:
        for place in CODEOWNERS_PLACES:
            try:
                answer = self.get(f"/repos/{self.repo}/contents/{urllib.parse.quote(place)}?ref={tip}")
            except NotFound:
                continue
            text = base64.b64decode(answer["content"]).decode("utf-8")
            patterns = []
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                pattern = line.split()[0]
                if set(pattern) & CODEOWNERS_UNSUPPORTED:
                    raise Failed("CODEOWNERS_UNSUPPORTED", f"{place} holds the pattern {pattern}, which is not supported")
                patterns.append(pattern.lower())
            return patterns
        raise Failed("CODEOWNERS_MISSING", "no CODEOWNERS file at the base tip")

    def classify(self, item: dict, patterns: list[str], tree: dict[str, dict]) -> tuple[str, str] | None:
        policy = self.config["policy"]
        name, status = item.get("filename"), item.get("status")
        if not plain_path(name):
            return "BAD_PATH", f"{name!r} is not a plain relative path"
        low = name.lower()
        parts = low.split("/")
        leaf = parts[-1]
        test_folder = policy["test_folder"].lower()
        is_test = low.startswith(test_folder) or parts[0] == "acceptance" \
            or (leaf.startswith("test_") and leaf.endswith(".py")) or leaf.endswith("_test.py")
        if is_test and status != "added":
            return "TEST_CHANGED", f"{name} ({status}) is an existing test file"
        if status == "renamed":
            return "RENAMED", f"{name} was renamed from {item.get('previous_filename')}"
        if status == "removed":
            return "REMOVED", f"{name} was removed"
        if status not in ("added", "modified"):
            return "MODE_CHANGED", f"{name} has the status {status}"
        if parts[0] == "acceptance":
            return "ACCEPTANCE", f"{name} is an acceptance file"
        if leaf == "conftest.py":
            return "CONFTEST", f"{name} is a conftest.py"
        if ".github" in parts:
            return "WORKFLOW", f"{name} is under .github"
        if leaf in TEST_CONFIG_NAMES:
            return "TEST_CONFIG", f"{name} is test, coverage or security configuration"
        if leaf in CONTROL_NAMES:
            return "CONTROL", f"{name} is a control file"
        if leaf in DEPENDENCY_NAMES or DEPENDENCY_PATTERN.fullmatch(leaf):
            return "DEPENDENCY", f"{name} is a dependency file"
        if SCHEMA_FOLDERS & set(parts[:-1]) or leaf.endswith(".sql"):
            return "SCHEMA", f"{name} is a schema or migration file"
        is_code = not is_test and leaf.endswith(".py") and any(low.startswith(f.lower()) for f in policy["code_folders"])
        if is_code:
            patch = item.get("patch")
            if not isinstance(patch, str):
                return "PATCH_UNREADABLE", f"GitHub gives no patch for {name}"
            for line in patch.splitlines():
                if line[:1] in ("+", "-") and DDL.search(line):
                    return "SCHEMA", f"{name} adds or removes a schema statement"
        for pattern in patterns:
            if codeowners_names(pattern, low):
                return "CODEOWNERS_PATH", f"{name} is named by the CODEOWNERS pattern {pattern}"
        is_new_test = status == "added" and low.startswith(test_folder) and leaf.startswith("test_") \
            and leaf.endswith(".py")
        if not (is_code or is_new_test):
            return "OUTSIDE_POLICY", f"{name} ({status}) is neither ordinary application code nor an added ordinary test"
        entry = tree.get(name)
        if not entry or entry.get("type") != "blob" or entry.get("mode") != "100644":
            return "MODE", f"{name} is not a plain file in the head's tree"
        return None

    def rule_diff(self, pr: dict, info: dict) -> None:
        head = pr["head"]["sha"]
        base = urllib.parse.quote(self.config["controller"]["base_branch"], safe="")
        tip = self.get(f"/repos/{self.repo}/branches/{base}")["commit"]["sha"]
        if not isinstance(tip, str) or not SHA40.fullmatch(tip):
            raise Unreadable("the base tip is not a commit SHA")
        self.record["base_tip"] = tip
        compare = self.get(f"/repos/{self.repo}/compare/{tip}...{head}")
        files = compare["files"]
        if not isinstance(files, list):
            raise Unreadable("the compare gives no file list")
        if len(files) >= MAX_COMPARE_FILES:
            raise Failed("TOO_MANY_FILES", f"{len(files)} files; GitHub's compare lists at most {MAX_COMPARE_FILES}")
        if not files:
            raise Failed("EMPTY_DIFF", "the PR changes no file")
        patterns = self.read_codeowners(tip)
        answer = self.get(f"/repos/{self.repo}/git/trees/{head}?recursive=1")
        if answer.get("truncated") is not False or not isinstance(answer.get("tree"), list):
            raise Unreadable("the head's tree is truncated or unreadable")
        tree = {entry.get("path"): entry for entry in answer["tree"] if isinstance(entry, dict)}
        for item in files:
            if not isinstance(item, dict):
                raise Unreadable("a file entry of the compare is not an object")
            found = self.classify(item, patterns, tree)
            if found is not None:
                raise Failed(*found)
        info["files_line"] = f"{len(files)} files: " + ", ".join(f"{f['filename']} ({f['status']})" for f in files)

    def rule_gate(self, pr: dict, info: dict) -> None:
        head = pr["head"]["sha"]
        gate = self.config["gate"]
        runs = self.pages(f"/repos/{self.repo}/commits/{head}/check-runs", key="check_runs")
        failed, pending, missing = [], [], []
        for name in gate["checks"]:
            mine = [r for r in runs if isinstance(r, dict) and r.get("name") == name and r.get("head_sha") == head
                    and (r.get("app") or {}).get("id") == gate["actions_app_id"] and is_count(r.get("id"))]
            if not mine:
                missing.append(name)
                continue
            newest = max(mine, key=lambda r: r["id"])
            if newest.get("status") != "completed":
                pending.append(name)
            elif newest.get("conclusion") != "success":
                failed.append(f"{name} ({newest.get('conclusion')})")
        if failed:
            raise Failed("GATE_CHECK_FAILED", "did not succeed: " + ", ".join(failed))
        if pending:
            raise Failed("GATE_CHECK_PENDING", "not completed: " + ", ".join(pending))
        if missing:
            raise Failed("GATE_CHECK_MISSING", "no run from the Actions app: " + ", ".join(missing))
        folder, files = self.stored_record(head)
        final, verdict, report = files["final.json"], files["verdict.json"], files["report.json"]
        if final.get("gate_verdict") != READY or (final.get("conclusions") or {}).get("gate/archive") != "success":
            raise Failed("GATE_NOT_READY", f"{folder}/final.json: gate verdict {final.get('gate_verdict')}")
        checks = verdict.get("checks")
        if verdict.get("verdict") != READY or not isinstance(checks, dict) or not checks \
                or any(value != "success" for value in checks.values()):
            raise Failed("GATE_NOT_READY", f"{folder}/verdict.json: verdict {verdict.get('verdict')}")
        verification = report.get("verification") or {}
        if verification.get("head_sha") != head or verification.get("pr") != self.pr \
                or isinstance(verification.get("pr"), bool):
            raise Failed("REPORT_MISMATCH", f"{folder}/report.json is for another commit or PR")
        for field, code in (("marked_tests", "MARKED_TESTS"), ("needs_code_owner", "NEEDS_CODE_OWNER"),
                            ("dependency_changes", "DEPENDENCY_CHANGES"),
                            ("security_review_changes", "SECURITY_CHANGES")):
            value = report.get(field)
            if not isinstance(value, list):
                raise Unreadable(f"{folder}/report.json: {field} is not a list")
            if value:
                raise Failed(code, f"{folder}/report.json lists {field}: {json.dumps(value)[:500]}")
        info["gate_line"] = (", ".join(gate["checks"]) + f" success from app {gate['actions_app_id']}; record {folder}: "
                             f"{READY}, no marks")

    def stored_record(self, head: str) -> tuple[str, dict]:
        branch = urllib.parse.quote(self.config["controller"]["reports_branch"], safe="")
        try:
            commits = self.pages(f"/repos/{self.repo}/commits?sha={branch}")
        except NotFound:
            raise Failed("REPORT_MISSING", "the reports branch does not exist") from None
        if not commits:
            raise Failed("REPORT_MISSING", "the reports branch has no commit")
        for commit in commits:
            author = (commit.get("author") or {}).get("login")
            verified = ((commit.get("commit") or {}).get("verification") or {}).get("verified")
            if author != REPORTS_AUTHOR or verified is not True:
                raise Failed("REPORTS_UNTRUSTED", f"commit {commit.get('sha')} on the reports branch was not written "
                                                  f"and signed for {REPORTS_AUTHOR}")
        newest = commits[0]["sha"]
        if not isinstance(newest, str) or not SHA40.fullmatch(newest):
            raise Unreadable("the reports branch's newest commit has no SHA")
        answer = self.get(f"/repos/{self.repo}/git/trees/{newest}?recursive=1")
        if answer.get("truncated") is not False or not isinstance(answer.get("tree"), list):
            raise Unreadable("the reports tree is truncated or unreadable")
        blobs = {e.get("path"): e.get("sha") for e in answer["tree"] if isinstance(e, dict) and e.get("type") == "blob"}
        pattern = re.compile(rf"reports/{self.pr}/([0-9]+)-([0-9]+)/context\.json")
        records = []
        for path, sha in blobs.items():
            match = pattern.fullmatch(str(path))
            if not match:
                continue
            context = self.blob_json(sha, path)
            if isinstance(context, dict) and context.get("head_sha") == head and str(context.get("pr")) == str(self.pr):
                records.append((int(match.group(1)), int(match.group(2)), path.rsplit("/", 1)[0]))
        if not records:
            raise Failed("REPORT_MISSING", f"no stored record of PR {self.pr} at {head}")
        folder = max(records)[2]
        files = {}
        for name in ("final.json", "verdict.json", "report.json"):
            sha = blobs.get(f"{folder}/{name}")
            if sha is None:
                raise Failed("REPORT_MISSING", f"{folder}/{name} is missing")
            value = self.blob_json(sha, f"{folder}/{name}")
            if not isinstance(value, dict):
                raise Unreadable(f"{folder}/{name} is not an object")
            files[name] = value
        return folder, files

    def blob_json(self, sha: Any, path: str) -> Any:
        answer = self.get(f"/repos/{self.repo}/git/blobs/{sha}")
        try:
            return json.loads(base64.b64decode(answer["content"]).decode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeDecodeError):
            raise Unreadable(f"{path} cannot be read as JSON") from None

    def rule_review(self, pr: dict, info: dict) -> None:
        head = pr["head"]["sha"]
        reviewer = self.config["reviewer"]
        statuses = self.pages(f"/repos/{self.repo}/commits/{head}/statuses")
        reviews = [s for s in statuses if isinstance(s, dict) and s.get("context") == REVIEW_CONTEXT
                   and is_count(s.get("id"))]
        if not reviews:
            raise Failed("REVIEW_MISSING", f"no {REVIEW_CONTEXT} status on {head}")
        newest = max(reviews, key=lambda s: s["id"])
        creator = newest.get("creator") or {}
        login = f"{reviewer['app_slug']}[bot]"
        if creator.get("login") != login or not is_count(creator.get("id")) or creator.get("id") != reviewer["bot_id"] \
                or creator.get("type") != "Bot":
            raise Failed("REVIEW_NOT_BY_REVIEWER", f"the newest {REVIEW_CONTEXT} was created by {creator.get('login')}")
        state = newest.get("state")
        if state == "pending":
            raise Failed("REVIEW_PENDING", f"the {REVIEW_CONTEXT} status is pending")
        if state in ("failure", "error"):
            raise Failed("REVIEW_FAILED", f"the {REVIEW_CONTEXT} status is {state}")
        if state != "success":
            raise Unreadable(f"the {REVIEW_CONTEXT} status has the state {state!r}")
        info["review_line"] = f"{REVIEW_CONTEXT} success by {login}"

    def evaluate(self, pr: dict) -> tuple[dict, dict]:
        rules: dict[str, dict] = {}
        info: dict[str, Any] = {}
        for rule_id, rule in zip(RULES, (self.rule_pr, self.rule_task, self.rule_diff, self.rule_gate, self.rule_review)):
            try:
                rule(pr, info)
                rules[rule_id] = {"ok": True}
            except Failed as failure:
                rules[rule_id] = {"ok": False, "code": failure.code, "detail": self.secrets.scrub(failure.detail)}
            except Exception as error:  # noqa: BLE001  # reason: any unreadable answer fails the rule (fail closed)
                rules[rule_id] = {"ok": False, "code": "UNREADABLE",
                                  "detail": self.secrets.scrub(f"{type(error).__name__}: {error}")[:500]}
        return rules, info

    # ------------------------------------------------------------ CR-7
    def post_policy(self, head: str, conclusion: str, title: str, summary: str) -> None:
        policy = self.config["gate"]["policy_check"]
        app_id = self.config["controller"]["app_id"]
        try:
            runs = self.pages(f"/repos/{self.repo}/commits/{head}/check-runs", key="check_runs")
        except Unreadable as error:
            raise ControllerError("GITHUB_ERROR", f"the check runs cannot be read before posting ({error}); "
                                                  f"posted: {self.posted}") from None
        own = [r for r in runs if isinstance(r, dict) and r.get("name") == policy and r.get("head_sha") == head
               and (r.get("app") or {}).get("id") == app_id and is_count(r.get("id"))]
        output = {"title": self.secrets.scrub(title)[:250], "summary": self.secrets.scrub(summary)[:60000]}
        if own:
            run_id = max(own, key=lambda r: r["id"])["id"]
            status, answer = self.request("PATCH", f"/repos/{self.repo}/check-runs/{run_id}",
                                          {"status": "completed", "conclusion": conclusion, "output": output})
            expected = 200
        else:
            status, answer = self.request("POST", f"/repos/{self.repo}/check-runs",
                                          {"name": policy, "head_sha": head, "status": "completed",
                                           "conclusion": conclusion, "output": output})
            expected = 201
        if status != expected or not isinstance(answer, dict) or not is_count(answer.get("id")):
            self.record["message"] = self.message(status, answer)
            raise ControllerError("GITHUB_ERROR", f"{policy} could not be posted: GitHub answered "
                                                  f"{self.record['message']}; posted: {self.posted}")
        self.record["policy_check_id"] = answer["id"]
        self.posted = f"{policy} {conclusion} on {head}"

    @staticmethod
    def failing(rules: dict) -> list[tuple[str, dict]]:
        return [(rule_id, rules[rule_id]) for rule_id in RULES if not rules[rule_id]["ok"]]

    def failure_texts(self, failing: list[tuple[str, dict]]) -> tuple[str, str, str]:
        first_id, first = failing[0]
        head_line = f"{first_id} {first['code']}: {first['detail']}"
        others = ", ".join(f"{rule_id} {rule['code']}" for rule_id, rule in failing[1:])
        summary = f"Refused: {head_line}\n" + (f"Other failing rules: {others}\n" if others else "")
        title = f"{self.config['gate']['policy_check']}: failure, {first_id} {first['code']}"
        return head_line, title, summary

    def success_texts(self, head: str, info: dict) -> tuple[str, str]:
        lines = [f"All rules held on {head}.",
                 f"- CR-2 {info.get('pr_line')}", f"- CR-3 {info.get('task_line')}", f"- CR-4 {info.get('files_line')}",
                 f"- CR-5 {info.get('gate_line')}", f"- CR-6 {info.get('review_line')}"]
        return f"{self.config['gate']['policy_check']}: success", "\n".join(lines) + "\n"

    # ------------------------------------------------------------ the whole run
    def execute(self) -> tuple[str, str]:
        self.get_token()
        pr = self.read_pr()
        head = pr["head"]["sha"]
        self.record["head_sha"] = head
        if pr.get("merged") is True:
            return "ALREADY_MERGED", f"PR {self.pr} was merged before this run; nothing was posted"
        rules, info = self.evaluate(pr)
        self.record["rules"] = rules
        failing = self.failing(rules)
        if failing:
            head_line, title, summary = self.failure_texts(failing)
            self.post_policy(head, "failure", title, summary)
            waiting = all(rule["code"] in WAITING_CODES for _rule_id, rule in failing)
            return ("WAITING" if waiting else "REFUSED"), head_line
        title, summary = self.success_texts(head, info)
        self.post_policy(head, "success", title, summary)
        # CR-8: everything again, then the merge.
        again = self.read_pr()
        if again["head"]["sha"] != head:
            return "REFUSED", f"HEAD_MOVED: the PR's head moved from {head} to {again['head']['sha']}; no merge"
        if again.get("merged") is True:
            return "ALREADY_MERGED", f"PR {self.pr} was merged by someone else during this run"
        rules2, _info2 = self.evaluate(again)
        self.record["rules"] = rules2
        failing2 = self.failing(rules2)
        if failing2:
            head_line, title, summary = self.failure_texts(failing2)
            self.post_policy(head, "failure", title, summary)
            return "REFUSED", head_line
        mergeable = again.get("mergeable")
        if mergeable is None:
            self.sleep(MERGEABLE_WAIT_SECONDS)
            third = self.read_pr()
            if third["head"]["sha"] != head:
                return "REFUSED", f"HEAD_MOVED: the PR's head moved from {head} to {third['head']['sha']}; no merge"
            mergeable = third.get("mergeable")
        if mergeable is not True:
            return "MERGE_REFUSED", f"NOT_MERGEABLE: GitHub gives mergeable {json.dumps(mergeable)} for PR {self.pr}"
        status, answer = self.request("PUT", f"/repos/{self.repo}/pulls/{self.pr}/merge",
                                      {"sha": head, "merge_method": "merge"})
        merge_sha = answer.get("sha") if isinstance(answer, dict) else None
        if status == 200 and isinstance(answer, dict) and answer.get("merged") is True \
                and isinstance(merge_sha, str) and SHA40.fullmatch(merge_sha):
            self.record["merge_sha"] = merge_sha
            return "MERGED", f"PR {self.pr} at {head} merged as {merge_sha}"
        self.record["message"] = self.message(status, answer)
        return "MERGE_REFUSED", f"GitHub refused the merge: {self.record['message']}"


# ---------------------------------------------------------------- CR-9, CR-10, CR-12
def write_record(log_file: Path, record: dict, secrets: Secrets, clock: Callable) -> None:
    record = dict(record)
    record["time"] = datetime.fromtimestamp(clock(), timezone.utc).isoformat(timespec="seconds")
    line = secrets.scrub(json.dumps(record, ensure_ascii=False, sort_keys=False)) + "\n"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def take_lock(lock: Path) -> None:
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise ControllerError("LOCKED", f"{lock} exists: another run holds the lock, or a crashed run left it "
                                        "(remove it after checking that no controller runs)") from None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"pid {os.getpid()}\n")


def main(argv: list[str] | None = None, *, http: Callable | None = None, windows: Any = None,
         sleep: Callable | None = None, clock: Callable | None = None) -> int:
    http = http or default_http
    sleep = sleep or time.sleep
    clock = clock or time.time
    secrets = Secrets()
    lock: Path | None = None
    run: Run | None = None
    log_file: Path | None = None
    outcome, detail = "USAGE", ""
    try:
        try:
            args = parse_args(list(sys.argv[1:] if argv is None else argv))
            config = load_config(args["config"])
            queue = load_queue(args["queue"], args["queue_sha256"], args["repo"], config)
            pem = check_key(Path(config["controller"]["key_file"]), windows if windows is not None else default_windows())
            key = load_key(pem)
            log_file = Path(config["controller"]["log_file"])
            candidate = Path(str(log_file) + ".lock")
            take_lock(candidate)
            lock = candidate
            run = Run(args, config, queue, http, sleep, clock, key, secrets)
            outcome, detail = run.execute()
        except ControllerError as stop:
            outcome, detail = stop.outcome, stop.detail
        if run is not None and log_file is not None and outcome not in ("USAGE", "LOCKED"):
            run.record["outcome"] = outcome
            if outcome == "GITHUB_ERROR" and run.record.get("message") is None:
                run.record["message"] = detail
            write_record(log_file, run.record, secrets, clock)
    finally:
        if lock is not None:
            try:
                lock.unlink()
            except OSError:
                pass
    print(secrets.scrub(f"CONTROLLER {outcome}: {detail}"))
    return EXIT[outcome]


if __name__ == "__main__":
    sys.exit(main())
