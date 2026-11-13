"""Create and install the GitHub Apps of a stage-A stand by GitHub's App Manifest flow.

Run by the operator in their own Windows terminal, never inside an AI session:

    <python with cryptography> -I setup_apps.py --config setup.toml [--role all|executor|reviewer|controller]

The configuration (see setup.example.toml and README.md beside this file) names the owner, the one
repository, each role's app name, the executor's Windows user and the key locations. Nothing of a
particular laptop or of the pilot is built in.

Three roles, each with a fixed set of repository permissions, which is also the most it may ask for:

    executor    contents: write, pull_requests: write, issues: write (only with issues = true)
    reviewer    contents: read, pull_requests: write, statuses: write
    controller  contents: write, checks: write, pull_requests: read, statuses: read, issues: read (only with
                issues = true)

and metadata: read, which GitHub adds to every app. A configuration that asks for anything else is
refused. For each selected role the script:
  1. checks that the app's name is new: any answer but GitHub's "not found" stops it, and on "not found",
     which a private app of that name also gives, it asks the operator to confirm the name is new;
  2. serves the generated manifest (webhook off, no events) from 127.0.0.1 and opens the browser, where
     the operator clicks Create;
  3. receives GitHub's one-time code on 127.0.0.1 and exchanges it at once;
  4. checks the new app: its name, owner, permissions and events must be exactly the manifest's;
  5. stores the private key in a file, never in GitHub, never on a command line:
     - the executor's in a folder outside every user profile, readable only by the executor's Windows
       user, beside a small non-secret app file for the launcher; the operator's own user loses access;
     - the reviewer's and the controller's in files the configuration names, outside every repository,
       readable only by the operator's user, so the executor's user cannot read them;
  6. opens the installation page, where the operator installs the app on the one repository;
  7. checks, as the app, that it has exactly one installation, on exactly that repository, with exactly
     the role's permissions.
It discards the client secret and the webhook secret, never prints, logs or echoes a key or a secret,
writes no temporary copy of a key, and stops with a message on any error.
"""

from __future__ import annotations

import argparse
import base64
import html
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "setup.toml"
API = "https://api.github.com"
CODE_LIMIT_SECONDS = 55 * 60  # GitHub allows one hour for the whole manifest flow.
WAIT_CREATE_SECONDS = 30 * 60
WAIT_INSTALL_SECONDS = 20 * 60
FULL_CONTROL = 2032127  # FileSystemRights.FullControl
READ_DATA = 0x1
# WriteData, AppendData, WriteEA, WriteAttributes, Delete, WriteDAC, WriteOwner, GenericAll, GenericWrite
WRITE_BITS = 0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
ADMINISTRATORS = "S-1-5-32-544"
LEVELS = {"read": 1, "write": 2}
# Each role's fixed permissions, its one optional permission (taken only with `issues = true`), and
# metadata: read, which GitHub adds to every app. Together they are the most the role may ask for.
ROLES = {
    "executor": {"fixed": {"contents": "write", "pull_requests": "write"}, "optional": ("issues", "write")},
    "reviewer": {"fixed": {"contents": "read", "pull_requests": "write", "statuses": "write"}, "optional": None},
    "controller": {"fixed": {"contents": "write", "checks": "write", "pull_requests": "read", "statuses": "read"},
                   "optional": ("issues", "read")},
}
ROLE_KEYS = {
    "executor": {"app_name", "windows_user", "key_folder", "issues"},
    "reviewer": {"app_name", "key_file"},
    "controller": {"app_name", "key_file", "issues"},
}
SETUP_KEYS = {"owner", "repository", "homepage"}
OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
REPOSITORY = re.compile(r"[A-Za-z0-9._-]{1,100}")
APP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,33}")
WINDOWS_USER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,19}")
DRIVE_PATH = re.compile(r"[A-Za-z]:\\[^\r\n]*")
AI_SESSION_VARIABLES = ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED")
DEBUG_VARIABLES = ("GH_DEBUG", "DEBUG", "GH_TRACE")
# DEV-06: no executor secret or variable lives in GitHub.
GITHUB_SECRETS_NOT_ALLOWED = {"CLAUDE_CODE_OAUTH_TOKEN", "EXECUTOR_APP_PRIVATE_KEY"}
GITHUB_VARIABLES_NOT_ALLOWED = {"EXECUTOR_APP_ID"}


class Stop(Exception):
    """An expected stop. Its message is safe to print: it never holds a key or a secret."""


PROGRESS: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)


def step(text: str) -> None:
    PROGRESS.append(text)
    say(f"  done: {text}")


# ---------------------------------------------------------------- the configuration


def _key_path(value: object, where: str, folder: bool) -> Path:
    """A full local drive path, outside OneDrive and every .git folder; a key folder also outside C:\\Users."""
    if not isinstance(value, str) or not DRIVE_PATH.fullmatch(value):
        raise Stop(f"{where} must be a full local drive path, such as C:\\...")
    parts = [part.lower() for part in re.split(r"[\\/]+", value) if part]
    if ".git" in parts or any("onedrive" in part for part in parts) or ".." in parts:
        raise Stop(f"{where} must lie outside every repository and outside OneDrive, which copies files to the cloud.")
    if folder and len(parts) > 1 and parts[1] == "users":
        raise Stop(f"{where} must lie outside C:\\Users: the executor's user cannot reach the operator's profile, "
                   "nor the operator its, and in C:\\Users\\Public every signed-in user may delete what another put there.")
    if not folder and not value.lower().endswith(".pem"):
        raise Stop(f"{where} must name a .pem file.")
    return Path(value)


def load_config(path: Path) -> dict:
    """The setup's configuration, checked strictly: an unknown table or key is refused."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        raise Stop(f"Cannot read the configuration {path}.") from None
    except tomllib.TOMLDecodeError as error:
        raise Stop(f"The configuration is not valid TOML: {error}") from None
    unknown = set(data) - {"setup", *ROLES}
    if unknown:
        raise Stop(f"The configuration holds unknown tables: {', '.join(sorted(unknown))}.")
    setup = data.get("setup")
    if not isinstance(setup, dict):
        raise Stop("The configuration has no [setup] table.")
    extra = set(setup) - SETUP_KEYS
    if extra:
        raise Stop(f"[setup] holds unknown keys: {', '.join(sorted(extra))}.")
    owner, repository = setup.get("owner"), setup.get("repository")
    if not isinstance(owner, str) or not OWNER.fullmatch(owner):
        raise Stop("[setup] owner must be a GitHub account name.")
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise Stop("[setup] repository must be a repository name, without its owner.")
    homepage = setup.get("homepage", f"https://github.com/{owner}/{repository}")
    if not isinstance(homepage, str) or not re.fullmatch(r"https://[^\s\"'<>]+", homepage):
        raise Stop("[setup] homepage must be an https:// address.")
    config = {"owner": owner, "repository": repository, "full_name": f"{owner}/{repository}", "homepage": homepage,
              "roles": {}}
    names, keys = set(), set()
    for role, allowed in ROLE_KEYS.items():
        table = data.get(role)
        if table is None:
            continue
        if not isinstance(table, dict):
            raise Stop(f"[{role}] must be a table.")
        extra = set(table) - allowed
        if extra:
            raise Stop(f"[{role}] holds keys this role may not have: {', '.join(sorted(extra))}. "
                       "A role's permissions are fixed by the script, not by the configuration.")
        name = table.get("app_name")
        if not isinstance(name, str) or not APP_NAME.fullmatch(name):
            raise Stop(f"[{role}] app_name must be 1 to 34 lower-case letters, digits or dashes.")
        if name in names:
            raise Stop(f"[{role}] app_name is used by another role.")
        names.add(name)
        issues = table.get("issues", False)
        if not isinstance(issues, bool):
            raise Stop(f"[{role}] issues must be true or false.")
        entry = {"app_name": name, "issues": issues}
        if role == "executor":
            user = table.get("windows_user")
            if not isinstance(user, str) or not WINDOWS_USER.fullmatch(user):
                raise Stop("[executor] windows_user must be a Windows user name: 1 to 20 letters, digits, dots, "
                           "dashes, underscores or spaces.")
            entry["windows_user"] = user
            entry["key_folder"] = _key_path(table.get("key_folder"), "[executor] key_folder", folder=True)
            entry["key_file"] = entry["key_folder"] / f"{name}.pem"
            entry["app_file"] = entry["key_folder"] / f"{name}.app.json"
        else:
            entry["key_file"] = _key_path(table.get("key_file"), f"[{role}] key_file", folder=False)
        key = str(entry["key_file"]).lower()
        if key in keys:
            raise Stop(f"[{role}] key_file is used by another role.")
        keys.add(key)
        entry["permissions"] = role_permissions(role, issues)
        config["roles"][role] = entry
    if not config["roles"]:
        raise Stop("The configuration names no role: add [executor], [reviewer] or [controller].")
    return config


# ---------------------------------------------------------------- permissions and the manifest


def most_for_role(role: str) -> dict[str, str]:
    """The ceiling: the role's fixed permissions, its optional one, and metadata: read."""
    spec = ROLES[role]
    ceiling = dict(spec["fixed"])
    if spec["optional"]:
        ceiling[spec["optional"][0]] = spec["optional"][1]
    ceiling["metadata"] = "read"
    return ceiling


def role_permissions(role: str, issues: bool) -> dict[str, str]:
    """What the role asks for: its fixed set, the optional one only when `issues` is true, and metadata: read."""
    spec = ROLES[role]
    permissions = dict(spec["fixed"])
    if issues:
        if not spec["optional"]:
            raise Stop(f"The {role} role cannot have issues.")
        permissions[spec["optional"][0]] = spec["optional"][1]
    permissions["metadata"] = "read"
    check_within_role(role, permissions)
    return permissions


def check_within_role(role: str, permissions: object) -> None:
    """Refuse any permission outside the role's ceiling, or above its level there."""
    ceiling = most_for_role(role)
    if not isinstance(permissions, dict):
        raise Stop(f"The {role} app's permissions are not a list of permissions.")
    for name, level in permissions.items():
        if name not in ceiling:
            raise Stop(f"The {role} app may not have the permission {name}.")
        if level not in LEVELS or LEVELS[level] > LEVELS[ceiling[name]]:
            raise Stop(f"The {role} app may have {name} at most as {ceiling[name]}, not {level}.")


def build_manifest(config: dict, role: str) -> dict:
    """The manifest GitHub's form receives: private, webhook off, no events, the role's permissions."""
    entry = config["roles"][role]
    manifest = {
        "name": entry["app_name"],
        "url": config["homepage"],
        "description": f"The {role} of the stage-A stand for {config['full_name']}, made by setup_apps.py.",
        "public": False,
        "hook_attributes": {"url": "https://example.com/no-webhook", "active": False},
        "default_events": [],
        "default_permissions": dict(entry["permissions"]),
        "request_oauth_on_install": False,
        "setup_on_update": False,
    }
    check_within_role(role, manifest["default_permissions"])
    return manifest


# ---------------------------------------------------------------- tools


WINDOWS_TOOLS = {
    "icacls": ("System32", "icacls.exe"),
    "whoami": ("System32", "whoami.exe"),
    "powershell": ("System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
}


def tool(name: str) -> str:
    """gh and git from PATH; the Windows tools by their full path, so that no other whoami or icacls is used."""
    if name in WINDOWS_TOOLS:
        found = Path(os.environ.get("SystemRoot", "C:\\Windows"), *WINDOWS_TOOLS[name])
        if not found.is_file():
            raise Stop(f"{found} was not found. It is part of Windows and is needed.")
        return str(found)
    found = shutil.which(name)
    if not found:
        raise Stop(f"{name} was not found on PATH. It is needed.")
    return found


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment for gh and the other tools: no debug output that could print a response."""
    env = {k: v for k, v in os.environ.items() if k.upper() not in DEBUG_VARIABLES}
    env.update({"GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1", "NO_COLOR": "1", "GH_PAGER": "", "PAGER": ""})
    env.update(extra or {})
    return env


def run(argv: list[str], what: str, stdin: bytes | None = None, extra_env: dict[str, str] | None = None,
        timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a tool. Its output is captured and never printed by this function."""
    try:
        return subprocess.run(argv, input=stdin, capture_output=True, env=child_env(extra_env), timeout=timeout,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Stop(f"{what}: {type(error).__name__}") from None


def gh(args: list[str]) -> subprocess.CompletedProcess:
    """The GitHub CLI, signed in as the owner. The only seam to it."""
    return run([tool("gh"), *args], "gh " + (args[0] if args else ""))


def first_line(data: bytes) -> str:
    return data.decode("utf-8", "replace").strip().splitlines()[0] if data.strip() else ""


def inside_a_repository(folder: Path) -> bool:
    result = run([tool("git"), "-C", str(folder), "rev-parse", "--is-inside-work-tree"], "checking for a repository")
    return result.returncode == 0 and first_line(result.stdout) == "true"


# ---------------------------------------------------------------- the name of a new app (closes the pilot's O-14)


def check_name_is_new(name: str, gh_call=gh, ask=input) -> None:
    """Any answer but GitHub's "not found" stops; "not found", which a private app also gives, needs the
    operator's confirmation that the name is new. Nothing is created before this passes."""
    result = gh_call(["api", f"apps/{name}", "--jq", ".slug"])
    if result.returncode == 0:
        raise Stop(f"An app named {name} already exists. Choose another name in the configuration, or delete it first.")
    answer = result.stderr or b""
    if not (b"HTTP 404" in answer or b"Not Found" in answer):
        raise Stop(f"Could not check whether an app named {name} exists (gh exited {result.returncode}). "
                   "Nothing was created.")
    say(f"  GitHub answers 'not found' for {name}. A private app of that name answers the same, so check by eye:")
    say("  open https://github.com/settings/apps (and the app settings of each organization you belong to)")
    say(f"  and make sure no app named {name} is listed there.")
    typed = ask(f"  Type {name} again to confirm that it is new, or press Enter to stop: ")
    if typed.strip() != name:
        raise Stop(f"The name {name} was not confirmed as new. Nothing was created.")


def names_in(args: list[str], what: str, gh_call=gh) -> set[str]:
    result = gh_call(args)
    if result.returncode != 0:
        raise Stop(f"{what} failed (gh exited {result.returncode}).")
    return set(result.stdout.decode("utf-8", "replace").split())


def github_holds_no_executor_secret(full_name: str, gh_call=gh) -> None:
    secrets_now = names_in(["secret", "list", "--repo", full_name, "--json", "name", "--jq", ".[].name"],
                           "listing the secrets' names", gh_call)
    variables_now = names_in(["variable", "list", "--repo", full_name, "--json", "name", "--jq", ".[].name"],
                             "listing the variables' names", gh_call)
    found = sorted((secrets_now & GITHUB_SECRETS_NOT_ALLOWED) | (variables_now & GITHUB_VARIABLES_NOT_ALLOWED))
    if found:
        raise Stop("GitHub holds " + ", ".join(found) + ". No executor secret or variable lives in GitHub: "
                   "delete them in the repository's settings first.")


# ---------------------------------------------------------------- Windows: users and file access (one seam)


class Windows:
    """Every Windows call the key files need. Tests replace the whole object."""

    def powershell(self, command: str, what: str, values: dict[str, str]) -> list[str]:
        """Values reach PowerShell through the environment only, never inside the command's text."""
        result = run([tool("powershell"), "-NoProfile", "-NonInteractive", "-Command",
                      "$ErrorActionPreference = 'Stop'; " + command], what, extra_env=values)
        if result.returncode != 0:
            raise Stop(f"Could not finish {what}.")
        return [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]

    def current_sid(self) -> str:
        result = run([tool("whoami"), "/user", "/fo", "csv", "/nh"], "reading your Windows user")
        match = re.search(rb'"(S-1-[0-9-]+)"\s*$', result.stdout.strip())
        if result.returncode != 0 or not match:
            raise Stop("Could not read your Windows user's SID with whoami.")
        return match.group(1).decode("ascii")

    def resolve_local_user(self, name: str) -> tuple[str, bool]:
        lines = self.powershell("$u = Get-LocalUser -Name $env:XTL_USER_NAME; 'SID=' + $u.SID.Value; 'ENABLED=' + $u.Enabled",
                                "finding that Windows user", {"XTL_USER_NAME": name})
        sid = next((line[4:] for line in lines if line.startswith("SID=")), "")
        return sid, "ENABLED=True" in lines

    def local_admin_sids(self) -> set[str]:
        lines = self.powershell("Get-LocalGroupMember -SID $env:XTL_GROUP | ForEach-Object { 'MEMBER=' + $_.SID.Value }",
                                "reading the Administrators group", {"XTL_GROUP": ADMINISTRATORS})
        return {line[7:] for line in lines if line.startswith("MEMBER=")}

    def icacls(self, path: Path, *args: str) -> bool:
        return run([tool("icacls"), str(path), *args], f"setting the permissions of {path.name}").returncode == 0

    def acl_of(self, path: Path) -> tuple[bool, list[tuple[str, int, str, str]]]:
        """The file's protection and access rules by SID, whatever the language of Windows."""
        lines = self.powershell(
            "$a = Get-Acl -LiteralPath $env:XTL_KEY_PATH; 'PROTECTED=' + $a.AreAccessRulesProtected; "
            "foreach ($r in $a.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) "
            "{ 'RULE=' + $r.IdentityReference.Value + '|' + [int]$r.FileSystemRights + '|' + $r.AccessControlType + '|' + $r.IsInherited }",
            "reading the file's permissions", {"XTL_KEY_PATH": str(path)})
        protected = "PROTECTED=True" in lines
        rules = []
        for line in lines:
            if line.startswith("RULE="):
                sid, rights, kind, inherited = line[5:].split("|")
                rules.append((sid, int(rights), kind, inherited))
        return protected, rules

    def owner_of(self, path: Path) -> str:
        lines = self.powershell("'OWNER=' + (Get-Acl -LiteralPath $env:XTL_KEY_PATH).GetOwner("
                                "[System.Security.Principal.SecurityIdentifier]).Value",
                                "reading the file's owner", {"XTL_KEY_PATH": str(path)})
        return next((line[6:] for line in lines if line.startswith("OWNER=")), "")

    def can_read(self, path: Path) -> bool:
        try:
            with open(path, "rb"):
                return True
        except PermissionError:
            return False

    def create_with_acl(self, path: Path, sddl: str) -> None:
        """Create the file new (CREATE_NEW), with exactly the access the SDDL gives, never its folder's (A2, R7)."""
        import ctypes
        from ctypes import wintypes

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                        ("bInheritHandle", wintypes.BOOL)]

        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.ULONG)]
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(SecurityAttributes),
                                    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.LocalFree.argtypes = [wintypes.HLOCAL]
        descriptor = wintypes.LPVOID()
        if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise Stop("Could not build the key file's permissions.")
        try:
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            handle = k32.CreateFileW(str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)  # CREATE_NEW
            if not handle or handle == wintypes.HANDLE(-1).value:
                raise Stop(f"Could not create {path}. Nothing is overwritten.")
            k32.CloseHandle(handle)
        finally:
            k32.LocalFree(descriptor)


OPEN_TO_ALL = {"S-1-5-32-545": "Users", "S-1-5-11": "Authenticated Users", "S-1-1-0": "Everyone"}


FOLDER_TRUSTED = ("S-1-5-18", "S-1-5-32-544")  # S10: SYSTEM and Administrators, besides the operator


def check_key_folder(win: Windows, folder: Path, executor_sid: str | None) -> None:
    """R7, S10: the folder of the reviewer's or the controller's key gives access only to the operator, SYSTEM and
    Administrators: never to all users, INTERACTIVE, local accounts or the executor."""
    operator_sid = win.current_sid()
    _, rules = win.acl_of(folder)
    for sid, _rights, kind, _inherited in rules:
        if kind == "Allow" and sid != operator_sid and sid not in FOLDER_TRUSTED:
            who = OPEN_TO_ALL.get(sid, "the executor's user" if executor_sid and sid == executor_sid else sid)
            raise Stop(f"The key's folder {folder} gives access to {who}. Choose a folder only your user can open.")


def _write_all(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    try:
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if path.stat().st_size != len(data):
        raise Stop(f"{path.name}'s size is not what was written.")


def check_operator_only(win: Windows, path: Path, operator_sid: str, executor_sid: str | None = None) -> None:
    """Exactly one rule, full control for the operator's user; no inherited rule; never the executor's user."""
    protected, rules = win.acl_of(path)
    if executor_sid and any(rule[0] == executor_sid for rule in rules):
        raise Stop(f"The executor's user appears in {path.name}'s permissions.")
    if not protected or rules != [(operator_sid, FULL_CONTROL, "Allow", "False")]:
        raise Stop(f"{path.name}'s permissions are not 'only your user'.")


def check_executor_only(win: Windows, path: Path, executor_sid: str) -> None:
    """Exactly one rule, for the executor's user, reading and never writing; no inherited rule; not readable by us."""
    protected, rules = win.acl_of(path)
    if not protected or len(rules) != 1:
        raise Stop(f"{path.name}'s permissions are not 'only the executor's user'.")
    sid, rights, kind, inherited = rules[0]
    if sid != executor_sid or kind != "Allow" or inherited != "False" or not rights & READ_DATA or rights & WRITE_BITS:
        raise Stop(f"{path.name}'s permissions are not 'read, for the executor's user only'.")
    if win.can_read(path):
        raise Stop(f"Your own user can still read {path.name}.")


def write_operator_key(win: Windows, path: Path, pem: bytes, executor_sid: str | None = None) -> None:
    """Create the file empty, limit it to the operator's user, and only then write the key into it."""
    operator_sid = win.current_sid()
    win.create_with_acl(path, f"D:P(A;;FA;;;{operator_sid})")  # never with its folder's inherited access (R7)
    try:
        check_operator_only(win, path, operator_sid, executor_sid)
        _write_all(path, pem)
        check_operator_only(win, path, operator_sid, executor_sid)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            say(f"  Could not remove the unfinished key file {path}. Delete it by hand.")
        raise


def write_for_executor(win: Windows, path: Path, data: bytes, executor_sid: str) -> None:
    """Create the file empty, give it to the executor's user to read and to us to write, write it, then drop our access."""
    operator_sid = win.current_sid()
    win.create_with_acl(path, f"D:P(A;;FA;;;{operator_sid})(A;;FR;;;{executor_sid})")  # never inherited access (R7)
    try:
        protected, rules = win.acl_of(path)
        if not protected or sorted(rule[0] for rule in rules) != sorted([operator_sid, executor_sid]):
            raise Stop(f"{path.name} holds other permissions than expected before it is written.")
        _write_all(path, data)
        if not win.icacls(path, "/remove:g", f"*{operator_sid}"):
            raise Stop(f"icacls could not remove your access to {path.name}.")
        if win.owner_of(path) != operator_sid:
            raise Stop(f"{path.name}'s owner is not your user.")
        check_executor_only(win, path, executor_sid)
    except BaseException:
        # As the owner we may always change the rules again, so that we can delete our unfinished file.
        win.icacls(path, "/grant", f"*{operator_sid}:(M)")
        try:
            path.unlink()
        except OSError:
            say(f"  Could not remove the unfinished file {path}. Delete it from an administrator's window.")
        raise


def check_executor_user(win: Windows, name: str, operator_sid: str) -> str:
    sid, enabled = win.resolve_local_user(name)
    if not re.fullmatch(r"S-1-5-21-[0-9-]+", sid):
        raise Stop(f"{name} is not a local account of this computer.")
    if sid == operator_sid:
        raise Stop("That is your own user. The executor must run under a separate one.")
    if not enabled:
        raise Stop(f"The Windows user {name} is disabled.")
    if sid in win.local_admin_sids():
        raise Stop(f"{name} is in the Administrators group. The executor's user must be a standard user.")
    return sid


def check_key_places(config: dict, roles: list[str], win: Windows, executor_sid: str | None) -> None:
    """Before anything is created: every key path is free, its folder exists, and no folder is in a repository."""
    for role in roles:
        entry = config["roles"][role]
        if role == "executor":
            folder = entry["key_folder"]
            if folder.exists() and not folder.is_dir():
                raise Stop(f"{folder} is a file, not a folder.")
            if not folder.parent.is_dir():
                raise Stop(f"{folder}'s parent folder does not exist.")
            if folder.is_dir() and inside_a_repository(folder):
                raise Stop(f"{folder} is inside a git repository. Choose a folder outside every repository.")
            for path in (entry["key_file"], entry["app_file"]):
                if path.exists():
                    raise Stop(f"{path} already exists. Nothing is overwritten; move it away first.")
        else:
            path = entry["key_file"]
            if path.exists():
                raise Stop(f"{path} already exists. Nothing is overwritten; choose a new name.")
            if not path.parent.is_dir():
                raise Stop(f"{path.parent} does not exist. Create the folder first, then run again.")
            if inside_a_repository(path.parent):
                raise Stop(f"{path.parent} is inside a git repository. Choose a folder outside every repository.")
            check_key_folder(win, path.parent, executor_sid)


# ---------------------------------------------------------------- GitHub, as the app itself


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def app_jwt(app_id: int, pem: bytes) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise Stop("GitHub's private key could not be read.") from None
    now = int(time.time())
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = b64url(json.dumps({"iat": now - 60, "exp": now + 540, "iss": app_id}, separators=(",", ":")).encode())
    signing_input = header + b"." + claims
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + b64url(signature)).decode("ascii")


def api(method: str, route: str, bearer: str, what: str, expect: int = 200) -> dict | list | None:
    """GitHub's REST API. The only seam to it."""
    request = urllib.request.Request(f"{API}{route}", method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {bearer}",
        "User-Agent": "xtl-setup-apps",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        raise Stop(f"GitHub answered {error.code} to {what}.") from None
    except (urllib.error.URLError, OSError):
        raise Stop(f"No connection to GitHub for {what}.") from None
    if status != expect:
        raise Stop(f"GitHub answered {status} to {what}.")
    return json.loads(body) if body else None


def exchange_code(code: str, opener=urllib.request.urlopen) -> dict:
    """R8: GitHub's one-time manifest code, exchanged by this process itself (HTTPS POST, no authentication), so it is
    never on a command line."""
    request = urllib.request.Request(f"{API}/app-manifests/{urllib.parse.quote(code, safe='')}/conversions", data=b"",
                                     method="POST", headers={"Accept": "application/vnd.github+json",
                                                             "User-Agent": "xtl-setup-apps",
                                                             "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with opener(request, timeout=30) as response:
            status, body = response.status, response.read()
    except urllib.error.HTTPError as error:
        raise Stop(f"GitHub answered {error.code} to the code's exchange. If the app was created, delete it at "
                   "https://github.com/settings/apps and run again.") from None
    except (urllib.error.URLError, OSError):
        raise Stop("No connection to GitHub for the code's exchange.") from None
    if status != 201:
        raise Stop(f"GitHub answered {status} to the code's exchange.")
    try:
        conversion = json.loads(body)
    except ValueError:
        raise Stop("GitHub's answer to the exchange could not be read.") from None
    if not isinstance(conversion, dict):
        raise Stop("GitHub's answer to the exchange is not an object.")
    return conversion


def check_installation(config: dict, role: str, app_id: int, slug: str, jwt: str, hint: str = "",
                       api_call=api) -> int:
    """As the app: exactly one installation, on this account, on exactly this repository, with exactly the role's
    permissions. Returns the installation's ID."""
    expected = config["roles"][role]["permissions"]
    full_name = config["full_name"]
    app = api_call("GET", "/app", jwt, "reading the app")
    if (not isinstance(app, dict) or app.get("id") != app_id or app.get("slug") != slug
            or app.get("permissions") != expected or app.get("events") != []):
        raise Stop(f"The app {slug} does not hold exactly the expected permissions and events.")
    installations = api_call("GET", "/app/installations", jwt, "listing the app's installations")
    if not isinstance(installations, list) or len(installations) != 1 or not isinstance(installations[0], dict):
        count = len(installations) if isinstance(installations, list) else "an unreadable number of"
        raise Stop(f"The app {slug} has {count} installations; it must have exactly one.")
    installation = installations[0]
    installation_id = installation.get("id")
    if not isinstance(installation_id, int) or isinstance(installation_id, bool) or installation_id <= 0:
        raise Stop(f"The installation of {slug} has no readable ID.")
    if (installation.get("account") or {}).get("login") != config["owner"]:
        raise Stop(f"The app {slug} is installed on another account.")
    if installation.get("repository_selection") != "selected":
        raise Stop(f"The app {slug} is installed on all repositories; choose 'Only select repositories'.")
    if installation.get("permissions") != expected:
        raise Stop(f"The installation of {slug} holds other permissions than the role's.")
    if hint and hint != str(installation_id):
        raise Stop("The installation GitHub reported to the browser is not the one the app sees.")
    answer = api_call("POST", f"/app/installations/{installation_id}/access_tokens", jwt, "a short check token", 201)
    token = str((answer or {}).get("token") or "") if isinstance(answer, dict) else ""
    if not token:
        raise Stop("GitHub gave no check token.")
    try:
        repositories = api_call("GET", "/installation/repositories?per_page=100", token, "the installed repositories")
        listed = repositories.get("repositories") if isinstance(repositories, dict) else None
        names = [item.get("full_name") for item in listed or [] if isinstance(item, dict)]
        if not isinstance(repositories, dict) or repositories.get("total_count") != 1 or names != [full_name]:
            raise Stop(f"The app {slug} must be installed on {full_name} only; it is installed on {len(names)} repositories.")
    finally:
        try:
            api_call("DELETE", "/installation/token", token, "revoking the check token", 204)
        except Stop:
            say("  The one-hour check token could not be revoked; it expires by itself within the hour.")
        del token
    return installation_id


# ---------------------------------------------------------------- the local page that receives GitHub's redirects


class Flow:
    """What the local page waits for. One flow at a time."""

    def __init__(self) -> None:
        self.nonce = secrets.token_urlsafe(16)
        self.port = 0
        self.lock = threading.Lock()
        self.role = ""
        self.owner = ""
        self.manifest: dict = {}
        self.state = ""
        self.code = ""
        self.created = threading.Event()
        self.installed = threading.Event()
        self.installation_hint = ""
        self.served_at = 0.0

    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}/{self.nonce}"


FLOW = Flow()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "xtl-setup-apps"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # reason: the base class's name
        """Log nothing: a request line can hold GitHub's one-time code."""

    def reply(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802  # reason: the base class's name
        if self.headers.get("Host") != f"127.0.0.1:{FLOW.port}":
            self.reply(400, "Wrong host.")
            return
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        prefix = f"/{FLOW.nonce}/"
        if not url.path.startswith(prefix):
            self.reply(404, "Not found.")
            return
        route = url.path[len(prefix):]
        with FLOW.lock:
            if route == "start" and FLOW.role and not FLOW.created.is_set():
                FLOW.served_at = FLOW.served_at or time.monotonic()
                name = html.escape(FLOW.manifest["name"])
                action = html.escape(f"https://github.com/settings/apps/new?state={FLOW.state}", quote=True)
                value = html.escape(json.dumps(FLOW.manifest), quote=True)
                self.reply(200, (
                    f"<!doctype html><meta charset='utf-8'><title>Create {name}</title>"
                    f"<p>Check that this browser is signed in to GitHub as {html.escape(FLOW.owner)}.</p>"
                    f"<form method='post' action='{action}'>"
                    f"<input type='hidden' name='manifest' value='{value}'>"
                    f"<button type='submit'>Create {name} on GitHub</button></form>"
                ))
            elif route == "created":
                state = (query.get("state") or [""])[0]
                code = (query.get("code") or [""])[0]
                if not FLOW.state or not secrets.compare_digest(state, FLOW.state) or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", code):
                    self.reply(400, "This answer does not belong to the current step. Nothing was done.")
                    return
                if not FLOW.created.is_set():
                    FLOW.code = code
                    FLOW.created.set()
                self.reply(200, "<p>Created. Return to the terminal.</p>")
            elif route == "installed":
                hint = (query.get("installation_id") or [""])[0]
                if re.fullmatch(r"[0-9]{1,20}", hint) and FLOW.role:
                    FLOW.installation_hint = hint
                    FLOW.installed.set()
                self.reply(200, "<p>Installed. Return to the terminal.</p>")
            else:
                self.reply(404, "Not found.")


def start_server() -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    FLOW.port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def open_in_browser(url: str, what: str) -> None:
    say(f"  Opening {what} in your browser. If it does not open, paste this address there:")
    say(f"    {url}")
    if not webbrowser.open(url):
        say("  (the browser did not open by itself)")


def wait_for(event: threading.Event, seconds: int, allow_enter: bool) -> bool:
    """Wait for GitHub's redirect. With allow_enter, Enter in the terminal also ends the wait."""
    import msvcrt

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if event.wait(0.25):
            return True
        if allow_enter and msvcrt.kbhit() and msvcrt.getwch() in "\r\n":
            return False
    raise Stop("No answer from the browser in time. Nothing more was done in this step.")


# ---------------------------------------------------------------- one app


def create_app(config: dict, role: str) -> tuple[int, str, bytes]:
    """Create the app through the browser and exchange the code. Returns the ID, the slug and the key."""
    entry = config["roles"][role]
    manifest = build_manifest(config, role)
    manifest["redirect_url"] = f"{FLOW.base()}/created"
    manifest["setup_url"] = f"{FLOW.base()}/installed"
    with FLOW.lock:
        FLOW.role, FLOW.owner, FLOW.manifest, FLOW.state = role, config["owner"], manifest, secrets.token_urlsafe(32)
        FLOW.code, FLOW.served_at = "", 0.0
        FLOW.created.clear()
        FLOW.installed.clear()
        FLOW.installation_hint = ""
    say(f"\nCreate {entry['app_name']} ({role}):")
    say(f"  In the browser, click 'Create {entry['app_name']} on GitHub', check the name and the permissions,")
    say(f"  and click 'Create GitHub App for {config['owner']}'. Do not change the name or the permissions.")
    open_in_browser(f"{FLOW.base()}/start", "the creation page")
    wait_for(FLOW.created, WAIT_CREATE_SECONDS, allow_enter=False)
    with FLOW.lock:
        code, served_at = FLOW.code, FLOW.served_at
        FLOW.code, FLOW.state = "", ""
    if served_at and time.monotonic() - served_at > CODE_LIMIT_SECONDS:
        raise Stop("GitHub's code is close to its one-hour limit. Delete the new app on GitHub and run again.")
    conversion = exchange_code(code)
    del code
    app_id = conversion.get("id")
    slug = str(conversion.get("slug") or "")
    pem_text = conversion.get("pem") or ""
    owner = (conversion.get("owner") or {}).get("login")
    permissions = conversion.get("permissions")
    events = conversion.get("events")
    for secret_field in ("client_secret", "webhook_secret", "pem", "client_id"):
        conversion.pop(secret_field, None)
    del conversion
    delete_hint = (f"Delete it at https://github.com/settings/apps/{slug}/advanced and run again."
                   if re.fullmatch(r"[a-z0-9-]+", slug) else "")
    if not isinstance(app_id, int) or app_id <= 0:
        raise Stop("GitHub's answer holds no app ID. " + delete_hint)
    PROGRESS.append(f"an app was created on GitHub: {slug}, app ID {app_id}")
    if slug != entry["app_name"]:
        raise Stop(f"The new app's name is not {entry['app_name']}, the configuration's. " + delete_hint)
    if owner != config["owner"]:
        raise Stop(f"The app was created under another account, not {config['owner']}. Delete it there and run again.")
    if permissions != entry["permissions"] or events != []:
        raise Stop("The new app's permissions or events differ from the manifest. " + delete_hint)
    if not (pem_text.startswith("-----BEGIN") and "PRIVATE KEY-----" in pem_text):
        raise Stop("GitHub's answer holds no private key. " + delete_hint)
    step(f"{slug} created under {config['owner']}, app ID {app_id}; client secret and webhook secret discarded")
    return app_id, slug, pem_text.encode("ascii")


def install_app(config: dict, role: str, app_id: int, slug: str, pem: bytes) -> int:
    say(f"\nInstall {slug}:")
    say(f"  In the browser choose 'Only select repositories', pick {config['repository']} and nothing else, "
        "and click Install.")
    say("  The terminal goes on when GitHub sends the browser back, or when you press Enter here.")
    with FLOW.lock:
        FLOW.installed.clear()
        FLOW.installation_hint = ""
    open_in_browser(f"https://github.com/apps/{slug}/installations/new", "the installation page")
    wait_for(FLOW.installed, WAIT_INSTALL_SECONDS, allow_enter=True)
    for attempt in range(1, 4):
        try:
            installation_id = check_installation(config, role, app_id, slug, app_jwt(app_id, pem), FLOW.installation_hint)
            step(f"{slug} installed on {config['full_name']} only, installation ID {installation_id}")
            return installation_id
        except Stop as problem:
            if attempt == 3:
                raise
            say(f"  Not yet right: {problem}")
            say("  Fix it at https://github.com/settings/installations , then press Enter here to check again.")
            input()
            FLOW.installation_hint = ""
    raise Stop("unreachable")


def setup_role(config: dict, role: str, win: Windows, executor_sid: str | None) -> dict:
    entry = config["roles"][role]
    if role == "executor":
        folder = entry["key_folder"]
        if not folder.exists():
            try:
                folder.mkdir()
            except OSError:
                raise Stop(f"Could not create the folder {folder}.") from None
            step(f"the folder {folder} created")
    check_key_places(config, [role], win, executor_sid)
    app_id, slug, pem = create_app(config, role)
    try:
        if role == "executor":
            write_for_executor(win, entry["key_file"], pem, executor_sid)
            step(f"the executor's key written to {entry['key_file']}, readable only by {entry['windows_user']}; "
                 "your user cannot read it")
        else:
            write_operator_key(win, entry["key_file"], pem, executor_sid)
            step(f"the {role}'s key written to {entry['key_file']}, readable only by your Windows user")
        installation_id = install_app(config, role, app_id, slug, pem)
    finally:
        del pem
    if role == "executor":
        app_file = {"app_id": app_id, "installation_id": installation_id, "slug": slug,
                    "repository": config["full_name"], "executor_user": entry["windows_user"],
                    "executor_sid": executor_sid, "ceo_sid": win.current_sid()}
        write_for_executor(win, entry["app_file"], (json.dumps(app_file, indent=2) + "\n").encode("ascii"), executor_sid)
        step(f"the executor's app file written to {entry['app_file']}, readable only by {entry['windows_user']}")
    return {"name": slug, "app_id": app_id, "installation_id": installation_id, "key_file": str(entry["key_file"]),
            "permissions": entry["permissions"]}


# ---------------------------------------------------------------- checks before anything is created


def preflight(config: dict) -> None:
    if os.name != "nt":
        raise Stop("Run this on the Windows machine of the stand, in your own terminal.")
    found = [name for name in AI_SESSION_VARIABLES if os.environ.get(name)]
    if found:
        raise Stop("This window looks like an AI session (" + ", ".join(found) + "). Run it in your own terminal.")
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Stop("Run it in an interactive terminal, not through a pipe or a log.")
    try:
        import cryptography  # noqa: F401  # reason: only checks that the library is present
    except ImportError:
        raise Stop("cryptography is missing: run this with a Python made from locks/review.lock.") from None
    login = gh(["api", "user", "--jq", ".login"])
    if login.returncode != 0:
        raise Stop(f"gh is not signed in. Run 'gh auth login' as {config['owner']} first.")
    if first_line(login.stdout) != config["owner"]:
        raise Stop(f"gh is signed in as another account. Sign in as {config['owner']}.")
    admin = gh(["api", f"repos/{config['full_name']}", "--jq", ".permissions.admin"])
    if admin.returncode != 0 or first_line(admin.stdout) != "true":
        raise Stop(f"{config['owner']} must be an admin of {config['full_name']}, and the repository must be reachable.")
    say(f"  gh is signed in as {config['owner']}, admin of {config['full_name']}")


def before_anything(config: dict, roles: list[str], win: Windows) -> str | None:
    """Every question and check that can stop the run, before any app is created. Returns the executor's SID."""
    for role in roles:
        check_name_is_new(config["roles"][role]["app_name"])
    executor_sid = None
    if "executor" in config["roles"]:
        executor_sid = check_executor_user(win, config["roles"]["executor"]["windows_user"], win.current_sid())
    check_key_places(config, roles, win, executor_sid)
    if "executor" in roles:
        github_holds_no_executor_secret(config["full_name"])
    return executor_sid


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create and install the GitHub Apps of a stage-A stand.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--role", choices=["all", *ROLES], default="all")
    args = parser.parse_args(argv)
    server = None
    try:
        config = load_config(Path(args.config))
        roles = [role for role in ROLES if role in config["roles"]] if args.role == "all" else [args.role]
        if args.role != "all" and args.role not in config["roles"]:
            raise Stop(f"The configuration has no [{args.role}] table.")
        say(f"GitHub Apps setup for {config['full_name']}: " + ", ".join(roles))
        for role in roles:
            say(f"  {role}: {config['roles'][role]['app_name']}, permissions {config['roles'][role]['permissions']}")
        preflight(config)
        win = Windows()
        executor_sid = before_anything(config, roles, win)
        server = start_server()
        results = {role: setup_role(config, role, win, executor_sid) for role in roles}
        say("\nFinished. Nothing secret is shown here. Write these down for the stand's records:")
        for role, result in results.items():
            say(f"  {role}: {result['name']}, app ID {result['app_id']}, installation ID {result['installation_id']}")
            say(f"    permissions {result['permissions']}")
            say(f"    key file {result['key_file']}")
        say("  Nothing was stored in GitHub.")
        return 0
    except Stop as stop:
        say(f"\nSTOPPED: {stop}")
    except KeyboardInterrupt:
        say("\nSTOPPED by you (Ctrl+C).")
    except Exception as error:  # noqa: BLE001  # reason: never print a traceback, which could quote data
        say(f"\nSTOPPED by an unexpected error: {type(error).__name__}. Nothing secret was printed.")
    finally:
        if server is not None:
            server.shutdown()
    if PROGRESS:
        say("What was done before the stop:")
        for item in PROGRESS:
            say(f"  - {item}")
    else:
        say("Nothing was stored. If you clicked Create on GitHub, look at https://github.com/settings/apps "
            "and delete an app you do not want.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
