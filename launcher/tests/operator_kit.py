"""Shared helpers for the tests of LR-96 (the model's own exited process), LR-97 (the operator's witness) and LR-98
(the operator's command), written from HQ-TASK-M1-C2R, HQ-TASK-M1-C2S and its amendments 1 and 2.

Every SID and name here is a stand-in; no real process is opened or ended through these helpers."""

from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path

OP_SID = "S-1-5-21-1111111111-2222222222-3333333333-1021"  # a stand-in operator, not the app file's ceo_sid
SYSTEM_SID = "S-1-5-18"
ADMINS_SID = "S-1-5-32-544"
FULL = 0x1F01FF
READ_EXECUTE = 0x1200A9
WITNESS_FORMAT = "xtl-witness/1"
ORPHAN_PID = 4_000_000_004  # no real process has such an id
OWN_STRAY_PID = 4_000_000_008
SECOND = 10_000_000  # FILETIME steps in one second


def watch_model(monkeypatch, launcher) -> dict:
    """Keep the attempt and its model's creation time as the process list gives it at the start."""
    seen: dict = {}
    real_start = launcher.ModelRun.start

    def start(self):
        ok = real_start(self)
        if ok and self.process is not None:
            entry = launcher._system_processes().get(self.process.pid)
            seen["run"], seen["created"] = self, (entry["created"] if entry else None)
        return ok

    monkeypatch.setattr(launcher.ModelRun, "start", start)
    return seen


def list_extra(monkeypatch, launcher, extra) -> None:
    """Every search also lists the records `extra()` returns."""
    listed = launcher.user_processes

    def user_processes(job, *args, **kwargs):
        return list(listed(job, *args, **kwargs)) + list(extra())

    monkeypatch.setattr(launcher, "user_processes", user_processes)


def once(condition, make):
    """`make()` at the first search where `condition()` holds, and never again."""
    state = {"done": False}

    def extra():
        if state["done"] or not condition():
            return []
        state["done"] = True
        return [make()]

    return extra


def stand_in_end(monkeypatch, launcher, answer: bool) -> list:
    calls: list = []
    monkeypatch.setattr(launcher, "end_process", lambda pid: calls.append(pid) or answer)
    return calls


def stand_in_alive(monkeypatch, launcher, alive: dict) -> None:
    """process_alive answers from `alive` for the stand-in pids, and from the real list for the others."""
    real = launcher.process_alive

    def process_alive(pid, created):
        if int(pid) in alive:
            return alive[int(pid)]
        return real(pid, created)

    monkeypatch.setattr(launcher, "process_alive", process_alive)


def orphan(pid: int, created: int, image: str = "sleep.exe") -> dict:
    """A process of unknown owner whose parent is gone: today's LR-82 judges it foreign (run 1's sleep.exe)."""
    return {"pid": pid, "ppid": 4_000_000_100, "image": image, "path": None, "parent_image": None,
            "parent_path": None, "created": created, "in_job": False, "broker": None, "owner": "unknown",
            "session": 1, "same_session": True, "parent_owner": None, "parent_in_job": False,
            "parent_alive": False}


def own_stray(pid: int, created: int, image: str = "python.exe") -> dict:
    """A process of the launcher's own user outside the job."""
    return {"pid": pid, "ppid": 4_000_000_100, "image": image, "path": sys.executable, "parent_image": None,
            "parent_path": None, "created": created, "in_job": False, "broker": None, "owner": "self",
            "session": 1, "same_session": True, "parent_owner": None, "parent_in_job": False,
            "parent_alive": False}


def right_acl(operator: str, executor: str) -> list:
    return [(operator, FULL, "Allow"), (SYSTEM_SID, FULL, "Allow"), (ADMINS_SID, FULL, "Allow"),
            (executor, READ_EXECUTE, "Allow")]


class StandInWitness:
    """Writes a witness file of LR-97's format every `interval` seconds, from a thread, with the real clock."""

    def __init__(self, path: Path, clock, pairs=None, interval: float = 0.2, age_seconds: float = 0.0):
        self.path = Path(path)
        self.clock = clock
        self.pairs: set = set(pairs or ())
        self.interval = interval
        self.age = int(age_seconds * SECOND)
        self.started = clock()
        self.writes = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def write(self) -> None:
        while True:  # the tests add pairs from their own thread (review round 1, F8e)
            try:
                pairs = sorted([list(p) for p in list(self.pairs)])
                break
            except RuntimeError:
                continue
        data = {"format": WITNESS_FORMAT, "started": self.started, "written": self.clock() - self.age,
                "pairs": pairs}
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}-{secrets.token_hex(4)}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        for _ in range(20):
            try:
                os.replace(tmp, self.path)
                self.writes += 1
                return
            except PermissionError:  # the reader holds the file this instant
                time.sleep(0.01)
        tmp.unlink(missing_ok=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.write()
            self._stop.wait(self.interval)

    def start(self) -> "StandInWitness":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.write()
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
