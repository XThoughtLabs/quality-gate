"""gate.concurrency_harness: rules H-1 to H-4."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gatekit import assert_no_traceback, assert_rc, assert_refused, base_env, read_json, run_gate, write_script

WORKER = r'''
import json, os, sys, time
shared = sys.argv[1]
mode = sys.argv[2]
rnd = os.environ["GATE_ROUND"]
idx = os.environ["GATE_WORKER_INDEX"]
tmp = os.environ["GATE_WORKER_TMP"]
rec = {"round": rnd, "worker": idx, "tmp": tmp, "tmp_is_dir": os.path.isdir(tmp), "listing_at_start": sorted(os.listdir(tmp)) if os.path.isdir(tmp) else None}
with open(os.path.join(shared, "rec-%s-%s.json" % (rnd, idx)), "w") as f:
    json.dump(rec, f)
try:
    with open(os.path.join(tmp, "left-behind.txt"), "w") as f:
        f.write("x")
except OSError:
    pass
if mode == "ok":
    sys.exit(0)
if mode == "fail-once":
    try:
        fd = os.open(os.path.join(shared, "failed-flag"), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.close(fd)
    except FileExistsError:
        sys.exit(0)
    with open(os.path.join(shared, "failed.json"), "w") as f:
        json.dump({"round": rnd, "worker": idx}, f)
    sys.exit(3)
if mode.startswith("barrier"):
    need = int(mode.split(":")[1])
    open(os.path.join(shared, "barrier-%s-%s" % (rnd, idx)), "w").close()
    deadline = time.time() + 8
    while time.time() < deadline:
        n = len([x for x in os.listdir(shared) if x.startswith("barrier-%s-" % rnd)])
        if n >= need:
            sys.exit(0)
        time.sleep(0.05)
    sys.exit(1)
if mode == "heartbeat":
    path = os.path.join(shared, "hb-%s-%s.txt" % (rnd, idx))
    end = time.time() + 40
    while time.time() < end:
        with open(path, "a") as f:
            f.write(".")
        time.sleep(0.2)
    sys.exit(0)
sys.exit(int(mode))
'''

LIB_RUNNER = r'''
import itertools, json, os, sys, threading, time
from gate.concurrency_harness import run_together, ConcurrencyFailure

scenario = sys.argv[1]
out = {"scenario": scenario}
t0 = time.time()
try:
    if scenario == "results":
        calls = []
        lock = threading.Lock()
        def fn(worker, rnd):
            with lock:
                calls.append([worker, rnd])
            return "r-%s-%s" % (worker, rnd)
        res = run_together(fn, 3, 2, 10)
        out["calls"] = sorted(calls)
        out["res"] = res
    elif scenario == "barrier":
        barriers = {}
        lock = threading.Lock()
        def fn(worker, rnd):
            with lock:
                b = barriers.setdefault(rnd, threading.Barrier(4))
            b.wait(timeout=5)
            return 1
        out["res"] = run_together(fn, 4, 2, 30)
    elif scenario == "exception":
        counter = itertools.count()
        def fn(worker, rnd):
            if next(counter) == 2:
                raise ValueError("boom")
            return 1
        out["res"] = run_together(fn, 3, 2, 10)
    elif scenario == "hang":
        def fn(worker, rnd):
            threading.Event().wait(60)
        out["res"] = run_together(fn, 2, 1, 2)
    out["raised"] = None
except ConcurrencyFailure as exc:
    out["raised"] = "ConcurrencyFailure"
    out["message"] = str(exc)
except BaseException as exc:
    out["raised"] = type(exc).__name__
    out["message"] = str(exc)
out["elapsed"] = time.time() - t0
sys.stdout.write(json.dumps(out, default=str))
sys.stdout.flush()
os._exit(0)
'''


@pytest.fixture
def h(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    worker = write_script(tmp_path / "worker.py", WORKER)
    return type("H", (), {"tmp": tmp_path, "shared": shared, "worker": worker, "out": tmp_path / "harness.json"})()


def harness(h, rounds, workers, timeout, mode, *, timeout_run=120):
    return run_gate("concurrency_harness", "--rounds", rounds, "--workers", workers, "--timeout", timeout,
                    "--out", h.out, "--", sys.executable, h.worker, h.shared, mode, cwd=h.tmp, timeout=timeout_run)


def records(h):
    return [json.loads(p.read_text()) for p in sorted(h.shared.glob("rec-*.json"))]


# ----------------------------------------------------------------------------- H-1 and the environment of each copy


@pytest.mark.req("H-1")
def test_h1_all_copies_of_all_rounds_exit_0(h):
    res = harness(h, 2, 3, 30, "ok")
    assert_rc(res, 0)
    assert_no_traceback(res)
    d = read_json(h.out)
    assert d["rounds"] == 2 and d["workers"] == 3 and d["runs"] == 6
    assert d["failures"] == [] and d["ok"] is True
    assert len(records(h)) == 6, "every copy of every round ran"


@pytest.mark.req("H-1")
def test_h1_one_failing_copy_fails_the_whole_run(h):
    res = harness(h, 2, 3, 30, "fail-once")
    assert_rc(res, 1)
    assert_no_traceback(res)
    d = read_json(h.out)
    assert d["ok"] is False and d["rounds"] == 2 and d["workers"] == 3
    failed = json.loads((h.shared / "failed.json").read_text())
    assert len(d["failures"]) == 1
    f = d["failures"][0]
    assert {"round", "worker", "exit_code", "reason"} <= set(f)
    assert str(f["round"]) == failed["round"] and str(f["worker"]) == failed["worker"]
    assert f["exit_code"] == 3


@pytest.mark.req("H-1")
def test_h1_a_copy_that_exits_nonzero_for_any_reason_is_a_failure(h):
    res = harness(h, 1, 2, 30, "7")
    assert_rc(res, 1)
    d = read_json(h.out)
    assert len(d["failures"]) == 2 and {f["exit_code"] for f in d["failures"]} == {7}


@pytest.mark.req("H-0")
def test_each_copy_gets_its_round_its_index_and_its_own_empty_temporary_folder(h):
    res = harness(h, 2, 3, 30, "ok")
    assert_rc(res, 0)
    recs = records(h)
    pairs = {(r["round"], r["worker"]) for r in recs}
    rounds = sorted({int(r["round"]) for r in recs})
    workers = sorted({int(r["worker"]) for r in recs})
    assert len(rounds) == 2 and rounds == list(range(rounds[0], rounds[0] + 2)), f"GATE_ROUND values: {rounds}"
    assert len(workers) == 3 and workers == list(range(workers[0], workers[0] + 3)), f"GATE_WORKER_INDEX values: {workers}"
    assert len(pairs) == 6, "every (round, worker) pair appears once"
    for rnd in rounds:
        in_round = [r["tmp"] for r in recs if int(r["round"]) == rnd]
        assert len(in_round) == len(set(in_round)) == 3, "copies running together never share a temporary folder"
    for r in recs:
        assert r["tmp_is_dir"] is True, "GATE_WORKER_TMP must be an existing folder"
        assert r["listing_at_start"] == [], "the temporary folder starts empty (nothing left by an earlier copy)"


# ----------------------------------------------------------------------------- H-2


@pytest.mark.req("H-2")
def test_h2_a_copy_past_the_timeout_is_killed_and_reported_as_timeout(h):
    res = harness(h, 1, 2, 2, "heartbeat")
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert res.elapsed < 35, "the harness must not wait for the copies to finish by themselves"
    d = read_json(h.out)
    assert d["ok"] is False and len(d["failures"]) == 2
    assert {f["reason"] for f in d["failures"]} == {"timeout"}
    sizes = {p.name: p.stat().st_size for p in h.shared.glob("hb-*.txt")}
    assert sizes, "the copies did start"
    time.sleep(1.5)
    after = {p.name: p.stat().st_size for p in h.shared.glob("hb-*.txt")}
    assert after == sizes, "a killed copy must stop running"


@pytest.mark.req("H-2")
def test_h2_control_a_copy_inside_the_timeout_is_not_a_failure(h):
    res = harness(h, 1, 2, 20, "ok")
    assert_rc(res, 0)
    assert read_json(h.out)["failures"] == []


# ----------------------------------------------------------------------------- H-3


@pytest.mark.req("H-3")
@pytest.mark.parametrize("workers", [2, 4])
def test_h3_copies_that_wait_for_each_other_finish_because_they_start_together(h, workers):
    res = harness(h, 2, workers, 30, f"barrier:{workers}")
    assert_rc(res, 0)
    d = read_json(h.out)
    assert d["ok"] is True and d["failures"] == []
    assert res.elapsed < 25


# ----------------------------------------------------------------------------- H-4 (library form)


def lib(tmp_path, scenario):
    runner = write_script(tmp_path / "lib_runner.py", LIB_RUNNER)
    cp = subprocess.run([sys.executable, "-P", str(runner), scenario], cwd=str(tmp_path), env=base_env(),
                        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    assert cp.stdout.strip(), f"the runner printed nothing\nstderr:\n{cp.stderr}"
    return json.loads(cp.stdout)


def flatten(x):
    if isinstance(x, (list, tuple)):
        return [y for item in x for y in flatten(item)]
    return [x]


@pytest.mark.req("H-4")
def test_h4_run_together_calls_fn_for_every_worker_and_round_and_returns_the_results(tmp_path):
    out = lib(tmp_path, "results")
    assert out["raised"] is None, out
    calls = out["calls"]
    assert len(calls) == 6 and len({tuple(c) for c in calls}) == 6, "fn(worker, round) once for each pair"
    workers = sorted({c[0] for c in calls})
    rounds = sorted({c[1] for c in calls})
    assert len(workers) == 3 and workers == list(range(workers[0], workers[0] + 3))
    assert len(rounds) == 2 and rounds == list(range(rounds[0], rounds[0] + 2))
    assert sorted(flatten(out["res"])) == sorted(f"r-{w}-{r}" for w, r in calls), "the results of the calls come back"


@pytest.mark.req("H-4", "H-3")
def test_h4_the_threads_are_released_together_by_one_barrier(tmp_path):
    out = lib(tmp_path, "barrier")
    assert out["raised"] is None, f"four calls that wait for each other must all be running at once: {out}"


@pytest.mark.req("H-4")
def test_h4_an_exception_in_a_call_raises_concurrency_failure(tmp_path):
    out = lib(tmp_path, "exception")
    assert out["raised"] == "ConcurrencyFailure", out


@pytest.mark.req("H-4")
def test_h4_a_hang_raises_concurrency_failure_after_the_timeout(tmp_path):
    out = lib(tmp_path, "hang")
    assert out["raised"] == "ConcurrencyFailure", out
    assert out["elapsed"] < 30, "the timeout (2 s) must end the wait"


# ----------------------------------------------------------------------------- C-2


@pytest.mark.req("C-2")
def test_usage_error_exits_2(tmp_path):
    out = tmp_path / "o.json"
    res = run_gate("concurrency_harness", "--rounds", "1", "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out)
