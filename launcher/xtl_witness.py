"""The operator's witness (LAUNCHER-CONTRACT.md, LR-97 and LR-98).

The operator's command (`xtl_operator.py`) starts it as the operator, in the background, for one run or one watch. It
only reads: every INTERVAL_SECONDS at most it lists the processes whose owner it reads as its own user and replaces
one file, whole, with:

- the format;
- the time it started;
- the time of this write (the clock, read before the list is taken);
- every (process id, creation time) pair of its own user it has seen since it started.

No name, SID or computer name goes in the file. A process it cannot read is never listed. It stops at its lifetime,
when its parent (the operator's command) is gone, or when its history would pass MAX_PAIRS; the file then goes stale,
and the launcher returns to its old rules.

Usage: python -I xtl_witness.py --file PATH --lifetime-seconds N [--parent PID:CREATED]
Standard library only; Windows for the real machine.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

FORMAT = "xtl-witness/1"
INTERVAL_SECONDS = 0.25
MAX_PAIRS = 200_000
SECOND = 10_000_000  # FILETIME steps in one second


class Witness:
    """One witness. `table()` maps a process id to its creation time; `sid_of(pid, created)` gives the owner's SID,
    or None when the process cannot be read; `clock()` gives the time as a FILETIME."""

    def __init__(self, path: str, own_sid: str, *, table, sid_of, clock, lifetime_seconds: int,
                 parent: tuple[int, int] | None = None, max_pairs: int = MAX_PAIRS) -> None:
        self.path = Path(path)
        self.own = own_sid
        self.table, self.sid_of, self.clock = table, sid_of, clock
        self.started = clock()
        self.until = self.started + int(lifetime_seconds) * SECOND
        self.parent = parent
        self.max_pairs = max_pairs
        self.history: set[tuple[int, int]] = set()
        self.others: set[tuple[int, int]] = set()  # read and not its own: never asked again

    def tick(self) -> bool:
        """One look and one write. False when the witness must stop (and then it writes nothing)."""
        written = self.clock()  # before the list: every process created before this time is in the list
        if written > self.until:
            return False
        table = self.table()
        if self.parent is not None and table.get(self.parent[0]) != self.parent[1]:
            return False
        for pid, created in table.items():
            pair = (pid, created)
            if pair in self.history or pair in self.others:
                continue
            sid = self.sid_of(pid, created)
            if sid is None:
                continue  # not readable now: never listed, asked again next time while it lives
            if sid == self.own:
                self.history.add(pair)
            else:
                self.others.add(pair)
        if len(self.history) > self.max_pairs:
            return False
        self.write(written)
        return True

    def write(self, written: int) -> None:
        data = json.dumps({"format": FORMAT, "started": self.started, "written": written,
                           "pairs": sorted([pid, created] for pid, created in self.history)}).encode("utf-8")
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}-{secrets.token_hex(4)}.tmp")
        with open(temporary, "xb") as handle:
            handle.write(data)
        for _ in range(20):
            try:
                os.replace(temporary, self.path)  # the whole file at once
                return
            except PermissionError:  # the launcher reads the file this instant
                time.sleep(0.01)
        temporary.unlink(missing_ok=True)


def run(witness: Witness, sleep=time.sleep, interval: float = INTERVAL_SECONDS) -> int:
    """Look and write until the witness must stop; never more often than every `interval` seconds."""
    while witness.tick():
        sleep(interval)
    return 0


# ---------------------------------------------------------------- the real machine (Windows)


def _windows():
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]

    class ProcessInfo(ctypes.Structure):  # SYSTEM_PROCESS_INFORMATION, up to UniqueProcessId
        _fields_ = [("NextEntryOffset", wintypes.ULONG), ("NumberOfThreads", wintypes.ULONG),
                    ("WorkingSetPrivateSize", ctypes.c_int64), ("HardFaultCount", wintypes.ULONG),
                    ("NumberOfThreadsHighWatermark", wintypes.ULONG), ("CycleTime", ctypes.c_uint64),
                    ("CreateTime", ctypes.c_int64), ("UserTime", ctypes.c_int64), ("KernelTime", ctypes.c_int64),
                    ("ImageName", UnicodeString), ("BasePriority", wintypes.LONG),
                    ("UniqueProcessId", ctypes.c_void_p)]

    nt = ctypes.WinDLL("ntdll")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    nt.NtQuerySystemInformation.argtypes = [ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                            ctypes.POINTER(wintypes.ULONG)]
    nt.NtQuerySystemInformation.restype = ctypes.c_long
    k32.OpenProcess.argtypes, k32.OpenProcess.restype = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE
    k32.CloseHandle.argtypes, k32.CloseHandle.restype = [wintypes.HANDLE], wintypes.BOOL
    k32.GetCurrentProcess.argtypes, k32.GetCurrentProcess.restype = [], wintypes.HANDLE
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k32.GetProcessTimes.restype = wintypes.BOOL
    k32.GetSystemTimeAsFileTime.argtypes, k32.GetSystemTimeAsFileTime.restype = [ctypes.POINTER(wintypes.FILETIME)], None
    k32.LocalFree.argtypes, k32.LocalFree.restype = [wintypes.HLOCAL], wintypes.HLOCAL
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.OpenProcessToken.restype = wintypes.BOOL
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    adv.GetTokenInformation.restype = wintypes.BOOL
    adv.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    adv.ConvertSidToStringSidW.restype = wintypes.BOOL

    def clock() -> int:
        value = wintypes.FILETIME()
        k32.GetSystemTimeAsFileTime(ctypes.byref(value))
        return (value.dwHighDateTime << 32) | value.dwLowDateTime

    def table() -> dict[int, int]:
        size = 1 << 20
        while True:
            buffer = ctypes.create_string_buffer(size)
            needed = wintypes.ULONG()
            status = nt.NtQuerySystemInformation(5, buffer, size, ctypes.byref(needed)) & 0xFFFFFFFF
            if status == 0xC0000004 and size < (1 << 28):  # STATUS_INFO_LENGTH_MISMATCH
                size = max(size * 2, needed.value + (1 << 16))
                continue
            if status != 0:
                raise OSError(f"the process list cannot be read ({status:#x})")
            break
        found: dict[int, int] = {}
        base, offset = ctypes.addressof(buffer), 0
        while True:
            entry = ProcessInfo.from_address(base + offset)
            pid = int(entry.UniqueProcessId or 0)
            if pid not in (0, 4):
                found[pid] = int(entry.CreateTime)
            if not entry.NextEntryOffset:
                return found
            offset += entry.NextEntryOffset

    def token_sid(handle) -> str | None:
        token = wintypes.HANDLE()
        if not adv.OpenProcessToken(handle, 0x8, ctypes.byref(token)):  # TOKEN_QUERY
            return None
        try:
            size = wintypes.DWORD()
            adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if not size.value:
                return None
            buffer = ctypes.create_string_buffer(size.value)
            if not adv.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                return None
            text = wintypes.LPWSTR()
            if not adv.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(buffer).value, ctypes.byref(text)):
                return None
            try:
                return text.value
            finally:
                k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            k32.CloseHandle(token)

    def sid_of(pid: int, created: int) -> str | None:
        """The owner of the process with this id, only if it is still the one created at `created`."""
        handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            times = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                return None
            if ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) != created:
                return None  # the id was reused between the list and the opening
            return token_sid(handle)
        finally:
            k32.CloseHandle(handle)

    own = token_sid(k32.GetCurrentProcess())
    return own, table, sid_of, clock


def parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xtl_witness", description="The operator's witness (LR-97).")
    parser.add_argument("--file", required=True)
    parser.add_argument("--lifetime-seconds", type=int, required=True)
    parser.add_argument("--parent", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    if os.name != "nt" or args.lifetime_seconds < 1:
        return 2
    parent = None
    if args.parent:
        pid, _, created = args.parent.partition(":")
        if not (pid.isdigit() and created.isdigit()):
            return 2
        parent = (int(pid), int(created))
    own, table, sid_of, clock = _windows()
    if own is None:
        return 2
    witness = Witness(args.file, own, table=table, sid_of=sid_of, clock=clock,
                      lifetime_seconds=args.lifetime_seconds, parent=parent)
    try:
        return run(witness)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
