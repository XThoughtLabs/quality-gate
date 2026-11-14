"""The operator's command (LAUNCHER-CONTRACT.md, LR-98).

The operator runs it as himself, in his own window, and it is the only thing he starts for a run:

    python xtl_operator.py [--config FILE] task --issue N | fix --pr N | spec --slug S [--max-messages M]
    python xtl_operator.py [--config FILE] preflight
    python xtl_operator.py [--config FILE] watch --minutes M

It reads launcher.toml (beside it by default: the same file the launcher reads) for `witness_file`, `windows_user` and
`launcher_python`, then:

1. creates the witness's folder if it is missing, and in any case sets and reads back its permissions: only the
   operator, SYSTEM and Administrators may write, and the executor's user may read; otherwise it stops;
2. starts the witness (`xtl_witness.py`) in the background as the operator, tied to this command (a job that ends
   with it, its parent's id, and a lifetime of its own), and waits at most 5 s for its first fresh write;
3. starts the launcher as the executor's user through Windows' own runas prompt, where the operator types the
   executor's password; this program never reads, stores, passes or prints it;
4. keeps the witness while the launcher's process lives, and stops it when that process has ended, at Ctrl+C, or
   when the window is closed.

It prints the steps in plain words and the time; never a name, a SID or the password. The launcher's own end line
stays in the executor's window, which waits for a key. It is not a service, a scheduled task or an autostart.
Standard library only; Windows.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
FULL = 0x1F01FF  # FILE_ALL_ACCESS
READ_EXECUTE = 0x1200A9  # read, read attributes and extended attributes, traverse, synchronize; no write right
READ_DATA = 0x1
# WriteData/AddFile, AppendData/AddSubdirectory, WriteEA, DeleteChild, WriteAttributes, Delete, WriteDAC, WriteOwner,
# GenericAll, GenericWrite: write, delete, add, change the owner or the permissions (amendment 1, section 2 rule 3)
WRITE_BITS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
SECOND = 10_000_000  # FILETIME steps in one second
WITNESS_FORMAT = "xtl-witness/1"
WITNESS_START_SECONDS = 5  # the first fresh write must come within this
FRESH_SECONDS = 2
RUN_LIFETIME_MINUTES = 59 + 30  # the launcher's longest model timeout, its preparation and its checks
PREFLIGHT_LIFETIME_MINUTES = 10
WATCH_EXTRA_MINUTES = 5
FIND_SECONDS = 20  # how long the launcher's process is looked for after runas
POLL_SECONDS = 0.5
DRIVE_PATH = re.compile(r"[A-Za-z]:\\[^\"%&|<>^!\r\n]*")  # a full path that cmd.exe cannot read as anything else
# A Windows user name (at most 20 characters, none of " / \ [ ] : ; | = , + * ? < > or a control character), with an
# optional domain or computer part before a backslash (review round 1, F11)
_NAME_PART = r'[^"/\\\[\]:;|=,+*?<>\x00-\x1f]'
USER_NAME = re.compile(rf"(?:{_NAME_PART}{{1,15}}\\)?{_NAME_PART}{{1,20}}")
# Review round 1, F2: on a folder above the witness's, the rights that let someone move, replace or re-permit it
ANCESTOR_BITS = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
USAGE = ("CONFIG: usage: xtl_operator [--config FILE] task --issue N | fix --pr N | spec --slug S [--max-messages M]"
         " | preflight | watch --minutes M")


class Stop(Exception):
    """A stop: exit 1. The message holds no name, SID or password."""


class ConfigError(Exception):
    """A usage or configuration error: exit 2."""


def positive(text: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]{0,9}", text):
        raise argparse.ArgumentTypeError("must be a positive integer")
    return int(text)


def slug(text: str) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", text):
        raise argparse.ArgumentTypeError("must match [a-z0-9][a-z0-9-]{0,39}")
    return text


def parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xtl_operator", description="The operator's command (LR-98).")
    parser.add_argument("--config", default=str(HERE / "launcher.toml"))
    commands = parser.add_subparsers(dest="command", required=True)
    for name, flag, kind in (("task", "--issue", positive), ("spec", "--slug", slug), ("fix", "--pr", positive)):
        command = commands.add_parser(name)
        command.add_argument(flag, type=kind, required=True)
        command.add_argument("--max-messages", type=positive, default=None)
    commands.add_parser("preflight")
    commands.add_parser("watch").add_argument("--minutes", type=positive, required=True)
    return parser.parse_args(argv)


def load(path: Path) -> dict:
    """The three keys this command reads from launcher.toml."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        raise ConfigError("cannot read the config file") from None
    except tomllib.TOMLDecodeError:
        raise ConfigError("the config file is not valid TOML") from None
    section = data.get("launcher")
    if not isinstance(section, dict):
        raise ConfigError("the config file has no [launcher] table")
    witness, user, python = section.get("witness_file"), section.get("windows_user"), section.get("launcher_python")
    if not isinstance(witness, str) or not DRIVE_PATH.fullmatch(witness):
        raise ConfigError("[launcher] witness_file must be a full drive path")
    if not isinstance(user, str) or not USER_NAME.fullmatch(user):
        raise ConfigError("[launcher] windows_user must be a Windows user name")
    if not isinstance(python, str) or not DRIVE_PATH.fullmatch(python) or not python.lower().endswith(".exe"):
        raise ConfigError("[launcher] launcher_python must be the full path of the executor's python.exe")
    return {"witness_file": witness, "windows_user": user, "launcher_python": python}


class Operator:
    """The command's steps, on a machine `win` (the real one is `Machine`; the tests give a stand-in)."""

    def __init__(self, win, out, here: Path = HERE) -> None:
        self.win, self.out, self.here = win, out, Path(here)
        self.witness = None
        self.witness_until: int | None = None
        self.started = False

    def say(self, text: str) -> None:
        self.out(f"{time.strftime('%H:%M:%S')} {text}\n")

    # ---------------------------------------------------------------- the whole command

    def main(self, argv: list[str] | None = None) -> int:
        try:
            args = parse(argv)
        except SystemExit:
            self.out(USAGE + "\n")
            return 2
        try:
            config_path = Path(args.config).resolve()
            cfg = load(config_path)
            for path in (config_path, self.here / "xtl_launcher.py", self.here / "xtl_witness.py"):
                if not DRIVE_PATH.fullmatch(str(path)):
                    raise ConfigError("a path holds a character cmd.exe would read as a command")
        except ConfigError as error:
            self.out(f"CONFIG: {error}\n")
            return 2
        try:
            return self.run(args, cfg, config_path)
        except Stop as stop:
            self.stop_witness()
            self.say(f"STOPPED: {stop}" + ("" if self.started else " Nothing was started."))
            return 1
        except KeyboardInterrupt:
            self.stop_witness()
            self.say("STOPPED by Ctrl+C: the witness is stopped. A launcher still running goes on under its old "
                     "rules; stop it in its own window if you want.")
            return 1
        except Exception as error:  # noqa: BLE001  # review round 1, F4: never a traceback, which shows paths
            self.stop_witness()
            self.say(f"STOPPED: an unexpected {type(error).__name__}; the witness is stopped."
                     + ("" if self.started else " Nothing was started."))
            return 1

    def run(self, args: argparse.Namespace, cfg: dict, config_path: Path) -> int:
        operator = self.win.own_sid()
        if not operator:
            raise Stop("your own user could not be read.")
        if self.win.elevated():
            raise Stop("this window runs as administrator, so the witness's file would belong to the Administrators "
                       "group. Start a normal window.")
        executor = self.win.account_sid(cfg["windows_user"])
        if not executor:
            raise Stop("the executor's user named in launcher.toml does not exist on this computer.")
        if executor == operator:
            raise Stop("the executor's user named in launcher.toml is your own user.")
        witness_file = Path(cfg["witness_file"])
        self.say("step 1 of 4: the witness's folder and its permissions")
        self.ensure_folder(witness_file.parent, operator, executor)
        minutes = {"preflight": PREFLIGHT_LIFETIME_MINUTES,
                   "watch": getattr(args, "minutes", 0) + WATCH_EXTRA_MINUTES}.get(args.command, RUN_LIFETIME_MINUTES)
        self.say("step 2 of 4: the witness starts")
        self.start_witness(witness_file, minutes * 60)
        self.say("step 3 of 4: Windows asks for the executor's password. Type it and press Enter; nothing shows "
                 "while you type.")
        code, output, runas_pid, runas_created = self.win.runas(cfg["windows_user"],
                                                                self.launcher_command(cfg, args, config_path))
        if code != 0:
            numbers = re.findall(rb"^\s*(\d{1,10}):", output or b"", re.M)
            detail = f" (Windows error {numbers[-1].decode('ascii')})" if numbers else f" (exit {code})"
            raise Stop(f"Windows did not start the launcher{detail}: a wrong password, or the user cannot log on.")
        self.started = True
        self.say("step 4 of 4: the launcher runs in the executor's window; the witness runs until it ends")
        launcher = self.find_launcher(runas_pid, runas_created, witness_file)
        if launcher is None:
            self.say("the launcher's process was not found: the witness keeps running until its lifetime ends "
                     "(Ctrl+C stops it)")
            self.wait_witness()
        else:
            self.wait_gone(launcher)
            self.say("the run has ended; its end line is in the executor's window. Press a key there to close it.")
        self.stop_witness()
        self.say("the witness is stopped")
        return 0

    # ---------------------------------------------------------------- step 1: the folder

    @staticmethod
    def right_rules(operator: str, executor: str) -> list[tuple[str, int, str]]:
        return [(operator, FULL, "Allow"), (SYSTEM_SID, FULL, "Allow"), (ADMINISTRATORS, FULL, "Allow"),
                (executor, READ_EXECUTE, "Allow")]

    @staticmethod
    def folder_right(state, operator: str, executor: str) -> bool:
        if state is None:
            return False
        owner, rules, protected, reparse, is_dir = state
        if owner != operator or not protected or reparse or not is_dir or rules is None:
            return False
        for sid, mask, kind in rules:
            if kind != "Deny" and sid not in (operator, SYSTEM_SID, ADMINISTRATORS) and mask & WRITE_BITS:
                return False
        return any(sid == executor and kind == "Allow" and mask & READ_DATA for sid, mask, kind in rules)

    def ancestors_safe(self, folder: Path, operator: str) -> bool:
        """Review round 1, F2: every folder above the witness's folder is no link, belongs to the operator, SYSTEM,
        Administrators or TrustedInstaller, and lets nobody else move, replace or re-permit what it holds."""
        trusted = (operator, SYSTEM_SID, ADMINISTRATORS, TRUSTED_INSTALLER)
        for ancestor in folder.parents:
            state = self.win.folder(str(ancestor))
            if state is None:
                return False
            owner, rules, _, reparse, is_dir = state
            if reparse or not is_dir or owner not in trusted or rules is None:
                return False
            if any(kind != "Deny" and sid not in trusted and mask & ANCESTOR_BITS for sid, mask, kind in rules):
                return False
        return True

    def ensure_folder(self, folder: Path, operator: str, executor: str) -> None:
        rules = self.right_rules(operator, executor)
        if not self.ancestors_safe(folder, operator):
            raise Stop("a folder above the witness's folder is a link, belongs to another user, or lets another "
                       "user move or change it.")
        state = self.win.folder(str(folder))
        if state is None:
            if not self.win.make_folder(str(folder), operator, rules):
                raise Stop("the witness's folder could not be created.")
        else:
            owner, _, _, reparse, is_dir = state
            if reparse or not is_dir:
                raise Stop("the witness's path is not a plain folder.")
            if owner != operator:
                raise Stop("the witness's folder belongs to another user; an administrator must remove it first.")
            if not self.folder_right(state, operator, executor) and not self.win.set_acl(str(folder), rules):
                raise Stop("Windows refused to set the witness's folder's permissions.")
        if not self.folder_right(self.win.folder(str(folder)), operator, executor):
            raise Stop("the witness's folder's permissions are not right after setting them.")

    # ---------------------------------------------------------------- step 2: the witness

    def fresh(self, path: Path, before: int) -> bool:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            return False
        if not isinstance(data, dict) or data.get("format") != WITNESS_FORMAT:
            return False
        started, written = data.get("started"), data.get("written")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (started, written)):
            return False
        return started >= before and written >= started and self.win.now() - written <= FRESH_SECONDS * SECOND

    def start_witness(self, path: Path, lifetime_seconds: int) -> None:
        pid, created = self.win.own_process()
        before = self.win.now()
        python = getattr(sys, "_base_executable", sys.executable)  # review round 1, F5: never a venv's redirector
        argv = [python, "-I", str(self.here / "xtl_witness.py"), "--file", str(path),
                "--lifetime-seconds", str(lifetime_seconds), "--parent", f"{pid}:{created}"]
        self.witness = self.win.start_witness(argv)
        self.witness_until = before + lifetime_seconds * SECOND
        deadline = before + WITNESS_START_SECONDS * SECOND
        while not self.fresh(path, before):
            if self.witness.poll() is not None or self.win.now() >= deadline:
                raise Stop(f"the witness made no fresh write in {WITNESS_START_SECONDS} s.")
            self.win.sleep(0.1)

    def stop_witness(self) -> None:
        if self.witness is not None:
            witness, self.witness = self.witness, None
            witness.stop()

    def wait_witness(self) -> None:
        while self.witness is not None and self.witness.poll() is None and self.win.now() < self.witness_until:
            self.win.sleep(POLL_SECONDS)

    # ---------------------------------------------------------------- step 3: the launcher, through runas

    def launcher_command(self, cfg: dict, args: argparse.Namespace, config_path: Path) -> str:
        tail = {"task": lambda: f"task --issue {args.issue}", "fix": lambda: f"fix --pr {args.pr}",
                "spec": lambda: f"spec --slug {args.slug}", "preflight": lambda: "check",
                "watch": lambda: f"watch --minutes {args.minutes}"}[args.command]()
        if getattr(args, "max_messages", None):
            tail += f" --max-messages {args.max_messages}"
        shell = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "cmd.exe"
        inner = f'"{cfg["launcher_python"]}" -I "{self.here / "xtl_launcher.py"}" --config "{config_path}" {tail}'
        return f'"{shell}" /c "{inner} & pause"'

    # ---------------------------------------------------------------- step 4: the end of the run

    def operator_pairs(self, path: Path) -> set:
        try:
            return {tuple(p) for p in json.loads(path.read_text(encoding="utf-8")).get("pairs", [])}
        except (OSError, UnicodeDecodeError, ValueError, AttributeError, TypeError):
            return set()

    def find_launcher(self, runas_pid: int, runas_created: int, witness_file: Path) -> tuple[int, int] | None:
        """The launcher's process: the child of the window runas started. Windows names runas as that window's
        parent; failing that, the one new cmd.exe of this session that the witness does not list as the operator's."""
        own_pid, _ = self.win.own_process()
        deadline = self.win.now() + FIND_SECONDS * SECOND
        while self.win.now() < deadline:
            table = self.win.processes()
            session = table.get(own_pid, {}).get("session")
            shells = [pid for pid, e in table.items() if e["ppid"] == runas_pid and e["created"] >= runas_created]
            if not shells:
                mine = self.operator_pairs(witness_file)
                shells = [pid for pid, e in table.items() if str(e["image"]).lower() == "cmd.exe"
                          and e["created"] >= runas_created and e.get("session") == session
                          and (pid, e["created"]) not in mine]
                shells = shells if len(shells) == 1 else []
            for shell in shells:
                children = sorted((e["created"], pid) for pid, e in table.items()
                                  if e["ppid"] == shell and e["created"] >= table[shell]["created"]
                                  and str(e["image"]).lower() != "conhost.exe")
                if children:
                    created, pid = children[0]
                    return pid, created
            self.win.sleep(POLL_SECONDS)
        return None

    def wait_gone(self, launcher: tuple[int, int]) -> None:
        pid, created = launcher
        warned = False
        while True:
            entry = self.win.processes().get(pid)
            if entry is None or entry["created"] != created:
                return
            if not warned and (self.witness is None or self.witness.poll() is not None):
                self.say("the witness has stopped before the run's end: the launcher goes on under its old rules")
                warned = True
            self.win.sleep(POLL_SECONDS)


# ---------------------------------------------------------------- the real machine (Windows)


class Machine:
    """The Windows calls the command needs. Nothing here reads a name into the output."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes
        self.ctypes, self.wintypes = ctypes, wintypes
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.nt = ctypes.WinDLL("ntdll")
        k32, adv, nt = self.k32, self.adv, self.nt
        signatures = {
            (k32, "GetCurrentProcess"): ([], wintypes.HANDLE),
            (k32, "CloseHandle"): ([wintypes.HANDLE], wintypes.BOOL),
            (k32, "LocalFree"): ([wintypes.HLOCAL], wintypes.HLOCAL),
            (k32, "GetSystemTimeAsFileTime"): ([ctypes.POINTER(wintypes.FILETIME)], None),
            (k32, "GetProcessTimes"): ([wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4, wintypes.BOOL),
            (k32, "CreateDirectoryW"): ([wintypes.LPCWSTR, ctypes.c_void_p], wintypes.BOOL),
            (k32, "CreateJobObjectW"): ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            (k32, "SetInformationJobObject"): ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD],
                                               wintypes.BOOL),
            (k32, "AssignProcessToJobObject"): ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            (k32, "TerminateJobObject"): ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            (adv, "OpenProcessToken"): ([wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
                                        wintypes.BOOL),
            (adv, "GetTokenInformation"): ([wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (adv, "ConvertSidToStringSidW"): ([ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)], wintypes.BOOL),
            (adv, "LookupAccountNameW"): ([wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p,
                                           ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int)],
                                          wintypes.BOOL),
            (adv, "GetNamedSecurityInfoW"): ([wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD]
                                             + [ctypes.POINTER(ctypes.c_void_p)] * 5, wintypes.DWORD),
            (adv, "SetNamedSecurityInfoW"): ([wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p], wintypes.DWORD),
            (adv, "GetSecurityDescriptorControl"): ([ctypes.c_void_p, ctypes.POINTER(wintypes.WORD),
                                                     ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            (adv, "GetSecurityDescriptorDacl"): ([ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL),
                                                  ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL)],
                                                 wintypes.BOOL),
            (adv, "ConvertStringSecurityDescriptorToSecurityDescriptorW"): (
                [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p], wintypes.BOOL),
            (adv, "GetAce"): ([ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)], wintypes.BOOL),
            (nt, "NtQuerySystemInformation"): ([ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                ctypes.POINTER(wintypes.ULONG)], ctypes.c_long),
        }
        for (dll, name), (argtypes, restype) in signatures.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = argtypes, restype

    # identities

    def _sid_text(self, pointer) -> str | None:
        ctypes, wintypes = self.ctypes, self.wintypes
        if not pointer:
            return None
        text = wintypes.LPWSTR()
        if not self.adv.ConvertSidToStringSidW(pointer, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            self.k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    def _token_information(self, kind: int):
        ctypes, wintypes = self.ctypes, self.wintypes
        token = wintypes.HANDLE()
        if not self.adv.OpenProcessToken(self.k32.GetCurrentProcess(), 0x8, ctypes.byref(token)):  # TOKEN_QUERY
            return None
        try:
            size = wintypes.DWORD()
            self.adv.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
            if not size.value:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not self.adv.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
                return None
            return buffer
        finally:
            self.k32.CloseHandle(token)

    def own_sid(self) -> str | None:
        buffer = self._token_information(1)  # TokenUser
        return None if buffer is None else self._sid_text(self.ctypes.c_void_p.from_buffer(buffer).value)

    def elevated(self) -> bool:
        buffer = self._token_information(20)  # TokenElevation
        return buffer is None or self.ctypes.c_uint32.from_buffer(buffer).value != 0  # unreadable counts as elevated

    def account_sid(self, name: str) -> str | None:
        ctypes, wintypes = self.ctypes, self.wintypes
        sid_size, domain_size, use = wintypes.DWORD(0), wintypes.DWORD(0), ctypes.c_int()
        self.adv.LookupAccountNameW(None, name, None, ctypes.byref(sid_size), None, ctypes.byref(domain_size),
                                    ctypes.byref(use))
        if not sid_size.value:
            return None
        sid = ctypes.create_string_buffer(sid_size.value)
        domain = ctypes.create_unicode_buffer(max(domain_size.value, 1))
        if not self.adv.LookupAccountNameW(None, name, sid, ctypes.byref(sid_size), domain, ctypes.byref(domain_size),
                                           ctypes.byref(use)):
            return None
        if use.value != 1:  # SidTypeUser only (review round 1, F11): not a group, an alias or a well-known SID
            return None
        return self._sid_text(ctypes.cast(sid, ctypes.c_void_p))

    # the folder

    def folder(self, path: str):
        """(owner, rules, protected, reparse, is_dir), or None when the path does not exist or cannot be read."""
        ctypes, wintypes = self.ctypes, self.wintypes
        try:
            attributes = os.lstat(path).st_file_attributes
        except OSError:
            return None
        reparse, is_dir = bool(attributes & 0x400), bool(attributes & 0x10)

        class Acl(ctypes.Structure):
            _fields_ = [("AclRevision", ctypes.c_ubyte), ("Sbz1", ctypes.c_ubyte), ("AclSize", wintypes.WORD),
                        ("AceCount", wintypes.WORD), ("Sbz2", wintypes.WORD)]

        class Ace(ctypes.Structure):
            _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte), ("AceSize", wintypes.WORD),
                        ("Mask", wintypes.DWORD)]

        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        if self.adv.GetNamedSecurityInfoW(path, 1, 0x1 | 0x4, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                                          ctypes.byref(descriptor)) != 0:
            return None
        try:
            control, revision = wintypes.WORD(), wintypes.DWORD()
            if not self.adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                return None
            protected = bool(control.value & 0x1000)  # SE_DACL_PROTECTED
            rules = None
            if dacl.value:
                rules = []
                for index in range(Acl.from_address(dacl.value).AceCount):
                    pointer = ctypes.c_void_p()
                    if not self.adv.GetAce(dacl.value, index, ctypes.byref(pointer)):
                        return None
                    ace = Ace.from_address(pointer.value)
                    if ace.AceFlags & 0x8:  # INHERIT_ONLY_ACE: it grants nothing on this folder itself
                        continue
                    if ace.AceType in (0, 1):
                        sid = self._sid_text(pointer.value + ctypes.sizeof(Ace))
                        rules.append((sid or "?", int(ace.Mask), "Allow" if ace.AceType == 0 else "Deny"))
                    elif ace.AceType in (6, 10, 12):
                        rules.append(("?", int(ace.Mask), "Deny"))
                    else:
                        rules.append(("?", 0xFFFFFFFF, "Allow"))
            return self._sid_text(owner.value), rules, protected, reparse, is_dir
        finally:
            self.k32.LocalFree(descriptor)

    @staticmethod
    def _sddl(rules) -> str:
        return "D:P" + "".join(f"(A;OICI;{mask:#x};;;{sid})" for sid, mask, _ in rules)

    def make_folder(self, path: str, owner: str, rules) -> bool:
        """The folder made with its owner and its protected rules at once: no moment with inherited rules."""
        ctypes, wintypes = self.ctypes, self.wintypes

        class Attributes(ctypes.Structure):
            _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                        ("bInheritHandle", wintypes.BOOL)]

        descriptor = ctypes.c_void_p()
        if not self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(f"O:{owner}{self._sddl(rules)}", 1,
                                                                             ctypes.byref(descriptor), None):
            return False
        try:
            attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
            return bool(self.k32.CreateDirectoryW(path, ctypes.byref(attributes)))
        finally:
            self.k32.LocalFree(descriptor)

    def set_acl(self, path: str, rules) -> bool:
        ctypes, wintypes = self.ctypes, self.wintypes
        descriptor = ctypes.c_void_p()
        if not self.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(self._sddl(rules), 1,
                                                                             ctypes.byref(descriptor), None):
            return False
        try:
            present, dacl, defaulted = wintypes.BOOL(), ctypes.c_void_p(), wintypes.BOOL()
            if not self.adv.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl),
                                                      ctypes.byref(defaulted)):
                return False
            # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
            return self.adv.SetNamedSecurityInfoW(path, 1, 0x4 | 0x80000000, None, None, dacl, None) == 0
        finally:
            self.k32.LocalFree(descriptor)

    # time and processes

    def now(self) -> int:
        value = self.wintypes.FILETIME()
        self.k32.GetSystemTimeAsFileTime(self.ctypes.byref(value))
        return (value.dwHighDateTime << 32) | value.dwLowDateTime

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def processes(self) -> dict[int, dict]:
        ctypes, wintypes = self.ctypes, self.wintypes

        class UnicodeString(ctypes.Structure):
            _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]

        class ProcessInfo(ctypes.Structure):
            _fields_ = [("NextEntryOffset", wintypes.ULONG), ("NumberOfThreads", wintypes.ULONG),
                        ("WorkingSetPrivateSize", ctypes.c_int64), ("HardFaultCount", wintypes.ULONG),
                        ("NumberOfThreadsHighWatermark", wintypes.ULONG), ("CycleTime", ctypes.c_uint64),
                        ("CreateTime", ctypes.c_int64), ("UserTime", ctypes.c_int64), ("KernelTime", ctypes.c_int64),
                        ("ImageName", UnicodeString), ("BasePriority", wintypes.LONG),
                        ("UniqueProcessId", ctypes.c_void_p), ("InheritedFromUniqueProcessId", ctypes.c_void_p),
                        ("HandleCount", wintypes.ULONG), ("SessionId", wintypes.ULONG)]

        size = 1 << 20
        while True:
            buffer = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG()
            status = self.nt.NtQuerySystemInformation(5, buffer, size, ctypes.byref(needed)) & 0xFFFFFFFF
            if status == 0xC0000004 and size < (1 << 28):
                size = max(size * 2, needed.value + (1 << 16))
                continue
            if status != 0:
                raise OSError(f"the process list cannot be read ({status:#x})")
            break
        found: dict[int, dict] = {}
        base, offset = ctypes.addressof(buffer), 0
        while True:
            entry = ProcessInfo.from_address(base + offset)
            name = entry.ImageName
            image = ctypes.wstring_at(name.Buffer, name.Length // 2) if name.Buffer else ""
            found[int(entry.UniqueProcessId or 0)] = {"ppid": int(entry.InheritedFromUniqueProcessId or 0),
                                                      "image": image, "created": int(entry.CreateTime),
                                                      "session": int(entry.SessionId)}
            if not entry.NextEntryOffset:
                return found
            offset += entry.NextEntryOffset

    def own_process(self) -> tuple[int, int]:
        pid = os.getpid()
        return pid, self.processes()[pid]["created"]

    # the witness and runas

    def start_witness(self, argv: list[str]) -> "WitnessProcess":
        return WitnessProcess(self, argv)

    def runas(self, user: str, command: str) -> tuple[int, bytes, int, int]:
        """Windows' runas, its prompt and its messages captured (they name the user and the computer); the password
        is typed at runas's own prompt, read by runas from the console, never by this program."""
        runas = Path(os.environ.get("SystemRoot") or r"C:\Windows") / "System32" / "runas.exe"
        process = subprocess.Popen([str(runas), f"/user:{user}", command], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        created = self.processes().get(process.pid, {}).get("created", 0)
        output, _ = process.communicate()
        return process.returncode, output, process.pid, created


class WitnessProcess:
    """The witness, in a job that ends it when this command ends (a closed window included), in its own process
    group so that Ctrl+C reaches this command, which then stops it."""

    def __init__(self, machine: Machine, argv: list[str]) -> None:
        ctypes, wintypes = machine.ctypes, machine.wintypes
        self.machine = machine
        self.job = machine.k32.CreateJobObjectW(None, None)
        if not self.job:
            raise Stop("the witness's job could not be made.")

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in ("a", "b", "c", "d", "e", "f")]

        class Extended(ctypes.Structure):
            _fields_ = [("Basic", Basic), ("Io", Counters), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        limits = Extended()
        limits.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not machine.k32.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            machine.k32.CloseHandle(self.job)
            raise Stop("the witness's job could not be set up.")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | 0x08000000  # CREATE_NO_WINDOW
        self.process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, creationflags=flags, close_fds=True)
        self.pid = self.process.pid
        if not machine.k32.AssignProcessToJobObject(self.job, int(self.process._handle)):
            self.stop()
            raise Stop("the witness could not be tied to this command.")

    def poll(self):
        return self.process.poll()

    def stop(self) -> None:
        if self.job:
            self.machine.k32.TerminateJobObject(self.job, 1)
            self.machine.k32.CloseHandle(self.job)
            self.job = None
        if self.process.poll() is None:
            self.process.kill()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass


def main(argv: list[str] | None = None) -> int:
    if os.name != "nt":
        print("STOPPED: the operator's command runs on Windows only.", flush=True)
        return 1
    return Operator(Machine(), lambda text: print(text, end="", flush=True)).main(argv)


if __name__ == "__main__":
    sys.exit(main())
