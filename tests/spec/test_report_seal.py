"""gate.report seal (rule Z-1): the artifact is sealed after the checks, before it is uploaded."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from gatekit import (SENTINEL_PREFIX, assert_no_traceback, assert_rc, assert_refused, base_env, run_gate, sha256_bytes,
                     tree_snapshot, write_bytes)
from reportkit import H3, World

GUARD = b'{"kind": "ai", "violations": [], "repeated_fix": false}'
ACCEPTANCE = b'{"ok": true, "passed": ["acceptance.test_a::test_x"]}'


def raw_artifact(tmp_path, *, guard=True, acceptance=True):
    art = Path(tmp_path) / "artifact"
    write_bytes(art / "exit-codes.tsv", b"check\tindex\texit_code\tduration_seconds\traw_path\targv_json\n")
    write_bytes(art / "raw" / "gate-tests" / "0.log", b"log \xff\x00 line\r\n")
    if guard:
        write_bytes(art / "raw" / "gate-guard" / "guard.json", GUARD)
    if acceptance:
        write_bytes(art / "raw" / "gate-acceptance" / "acceptance.json", ACCEPTANCE)
    return art


def seal(art, *, run_id="1001", attempt="1", env_extra=None, cwd=None):
    return run_gate("report", "seal", "--artifact", art, "--head-sha", H3, "--run-id", run_id, "--run-attempt", attempt,
                    env=base_env(env_extra), cwd=cwd or Path(art).parent)


@pytest.mark.req("Z-1")
def test_z1_copies_the_guard_and_acceptance_outputs_to_the_top_level(tmp_path):
    art = raw_artifact(tmp_path)
    res = seal(art)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert (art / "guard.json").read_bytes() == GUARD
    assert (art / "acceptance.json").read_bytes() == ACCEPTANCE
    assert (art / "raw" / "gate-guard" / "guard.json").read_bytes() == GUARD, "copied, not moved"
    assert (art / "raw" / "gate-acceptance" / "acceptance.json").read_bytes() == ACCEPTANCE


@pytest.mark.req("Z-1")
def test_z1_writes_meta_json_with_the_head_sha_run_id_and_attempt(tmp_path):
    art = raw_artifact(tmp_path)
    assert_rc(seal(art, run_id="1001", attempt="2"), 0)
    meta = json.loads((art / "meta.json").read_text(encoding="utf-8"))
    assert meta["head_sha"] == H3
    assert str(meta["run_id"]) == "1001" and str(meta["run_attempt"]) == "2"


@pytest.mark.req("Z-1", "C-3")
def test_z1_writes_environment_json_and_never_a_secret_value(tmp_path):
    art = raw_artifact(tmp_path)
    res = seal(art, env_extra={"SEALING_TEST_TOKEN": f"{SENTINEL_PREFIX}-4711", "ImageOS": "ubuntu24"})
    assert_rc(res, 0)
    env = json.loads((art / "environment.json").read_text(encoding="utf-8"))
    assert isinstance(env, dict) and env, "environment.json describes the environment"
    for name, data in tree_snapshot(art).items():
        assert SENTINEL_PREFIX.encode() not in data, f"a secret value was written into {name}"
    assert SENTINEL_PREFIX not in res.both


@pytest.mark.req("Z-1")
def test_z1_sha256sums_covers_every_other_file_and_is_correct(tmp_path):
    art = raw_artifact(tmp_path)
    assert_rc(seal(art), 0)
    files = tree_snapshot(art)
    sums = files.pop("SHA256SUMS").decode("utf-8")
    listed = {}
    for line in sums.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        assert m, f"not '<sha256>  <path>': {line!r}"
        listed[m.group(2)] = m.group(1)
    assert set(listed) == set(files), "every other file, and not SHA256SUMS itself"
    assert {"guard.json", "acceptance.json", "meta.json", "environment.json", "exit-codes.tsv",
            "raw/gate-tests/0.log"} <= set(listed)
    for path, digest in listed.items():
        assert digest == sha256_bytes(files[path]), f"wrong hash for {path}"


@pytest.mark.req("Z-1")
@pytest.mark.parametrize("guard,acceptance", [(False, True), (True, False), (False, False)])
def test_z1_only_what_is_present_is_copied(tmp_path, guard, acceptance):
    art = raw_artifact(tmp_path, guard=guard, acceptance=acceptance)
    res = seal(art)
    assert_rc(res, 0)
    assert (art / "guard.json").exists() == guard and (art / "acceptance.json").exists() == acceptance
    listed = (art / "SHA256SUMS").read_text(encoding="utf-8")
    assert bool(re.search(r"^[0-9a-f]{64}  guard\.json$", listed, re.M)) == guard
    assert bool(re.search(r"^[0-9a-f]{64}  acceptance\.json$", listed, re.M)) == acceptance
    assert (art / "meta.json").exists() and (art / "environment.json").exists()


@pytest.mark.req("Z-1", "C-2")
def test_z1_usage_error_exits_2(tmp_path):
    res = run_gate("report", "seal", "--artifact", tmp_path, cwd=tmp_path)
    assert_refused(res, 2)


@pytest.mark.req("Z-1", "V-5")
def test_z1_a_sealed_artifact_is_what_generate_needs_for_a_ready_verdict(tmp_path):
    w = World(tmp_path / "judge")
    w.omit_files |= {"guard.json", "acceptance.json", "environment.json", "meta.json", "SHA256SUMS"}
    w.extra_files["raw/gate-guard/guard.json"] = json.dumps(w.guard).encode()
    w.extra_files["raw/gate-acceptance/acceptance.json"] = json.dumps(w.acceptance).encode()
    w.build()
    res = run_gate("report", "seal", "--artifact", w.tmp / "artifact", "--head-sha", w.ctx["head_sha"],
                   "--run-id", str(w.ctx["run_id"]), "--run-attempt", str(w.ctx["run_attempt"]), cwd=w.tmp)
    assert_rc(res, 0)
    out = w.run(build=False).need()
    assert out.verdict["verdict"] == "ready-for-human", out.describe()
    assert out.verdict["reasons"] == []
