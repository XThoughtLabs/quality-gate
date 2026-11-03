"""Run the same thing several times at once, to expose races and hangs."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable

from gate.common import EXIT_OK, EXIT_RULE_FAILED, fail_usage, kill_tree, popen_kwargs, write_json


class ConcurrencyFailure(Exception):
    """A worker raised an exception or did not finish in time."""


def run_together(fn: Callable[[int, int], Any], workers: int, rounds: int, timeout: float) -> list[Any]:
    """Call fn(worker, round) on threads released by one barrier, round after round.

    Returns the results in order of round, then worker. An exception or a hang
    raises ConcurrencyFailure.
    """
    results: list[Any] = []
    for round_number in range(rounds):
        barrier = threading.Barrier(workers)
        outcome: list[Any] = [None] * workers
        errors: list[tuple[int, BaseException]] = []

        def work(worker: int) -> None:
            try:
                barrier.wait(timeout=timeout)
                outcome[worker] = fn(worker, round_number)
            except BaseException as error:  # noqa: BLE001  # reason: every failure is reported to the caller
                errors.append((worker, error))

        threads = [threading.Thread(target=work, args=(index,), daemon=True) for index in range(workers)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads):
            raise ConcurrencyFailure(f"round {round_number}: a worker did not finish within {timeout} seconds")
        if errors:
            worker, error = errors[0]
            raise ConcurrencyFailure(f"round {round_number}, worker {worker}: {error!r}") from error
        results.extend(outcome)
    return results


def run_round(command: list[str], workers: int, round_number: int, timeout: float) -> list[dict]:
    failures: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="gate-harness-") as root:
        processes = []
        for worker in range(workers):
            worker_tmp = os.path.join(root, str(worker))
            os.mkdir(worker_tmp)
            env = {
                **os.environ,
                "GATE_WORKER_INDEX": str(worker),
                "GATE_ROUND": str(round_number),
                "GATE_WORKER_TMP": worker_tmp,
            }
            try:
                process = subprocess.Popen(
                    command,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    **popen_kwargs(),
                )
            except OSError:
                failures.append({"round": round_number, "worker": worker, "exit_code": 127, "reason": "not started"})
                continue
            processes.append((worker, process))

        deadline = time.monotonic() + timeout
        for worker, process in processes:
            try:
                code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                kill_tree(process)
                failures.append({"round": round_number, "worker": worker, "exit_code": None, "reason": "timeout"})
                continue
            if code != 0:
                failures.append({"round": round_number, "worker": worker, "exit_code": code, "reason": "exit code"})
    return failures


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--" not in arguments:
        return fail_usage("give the command after --")
    split = arguments.index("--")
    command = arguments[split + 1 :]
    if not command:
        return fail_usage("give the command after --")

    parser = argparse.ArgumentParser(prog="gate.concurrency_harness")
    parser.add_argument("--rounds", type=int, required=True)
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(arguments[:split])
    if args.rounds < 1 or args.workers < 1 or args.timeout <= 0:
        return fail_usage("rounds, workers and timeout must be positive")

    failures: list[dict] = []
    for round_number in range(args.rounds):
        failures += run_round(command, args.workers, round_number, args.timeout)

    ok = not failures
    write_json(
        args.out,
        {
            "rounds": args.rounds,
            "workers": args.workers,
            "runs": args.rounds * args.workers,
            "failures": failures,
            "ok": ok,
        },
    )
    return EXIT_OK if ok else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
