"""gate.archive store and append: rules W-1 to W-8. The remote is a real local bare repository."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gatekit import (Repo, assert_no_traceback, assert_rc, base_env, branch_files, branch_tip, git, make_bare,
                     load_out, parents_of, push_to, read_json, remote_url, rev_list, run_gate, run_git, sha256_bytes,
                     write_bytes, write_json, write_script, write_text)

CTX = {"repository": "example-org/gate-app", "pr": 7, "run_id": 1001, "run_attempt": 1, "head_sha": "3" * 40}
ART = {
    "exit-codes.tsv": b"check\tindex\texit_code\n",
    "meta.json": b'{"head_sha": "' + b"3" * 40 + b'", "run_id": 1001, "run_attempt": 1}',
    "SHA256SUMS": b"deadbeef  raw/gate-tests/0.log\n",
    "raw/gate-tests/0.log": b"line one\r\nline two\n\x00\x01\xff binary tail\n",
    "guard.json": b'{"head_sha": "' + b"3" * 40 + b'", "repeated_fix": false}',
    "acceptance.json": b'{"passed": ["acceptance.test_status::test_history"]}',
}
PUB = {"report.json": b'{"report": 1}\n', "report.md": b"# Report\n", "verdict.json": b'{"verdict": "ready-for-human"}\n'}
RESULT_KEYS = {"stored", "sha256sums_match", "path", "commit", "reason", "artifact_present", "skipped_unsafe"}


class Inputs:
    pass


def make_inputs(tmp_path, *, artifact=True, artifact_files=None, publish_files=None, tag="in"):
    inp = Inputs()
    root = Path(tmp_path) / tag
    inp.artifact, inp.publish, inp.context = root / "artifact", root / "publish", root / "context.json"
    inp.art_files = dict(ART if artifact_files is None else artifact_files)
    inp.pub_files = dict(PUB if publish_files is None else publish_files)
    if artifact:
        inp.artifact.mkdir(parents=True, exist_ok=True)
        for name, data in inp.art_files.items():
            write_bytes(inp.artifact / name, data)
    inp.publish.mkdir(parents=True, exist_ok=True)
    for name, data in inp.pub_files.items():
        write_bytes(inp.publish / name, data)
    write_json(inp.context, CTX)
    inp.has_artifact = artifact
    return inp


@pytest.fixture
def remote(tmp_path):
    seed = Repo(tmp_path / "seed")
    seed.write("README.md", "seed\n")
    seed.commit("seed")
    bare = make_bare(tmp_path / "remote.git")
    push_to(seed, bare, "main")
    run_git(bare, "config", "receive.denyNonFastForwards", "true")  # a force push can never succeed
    run_git(bare, "config", "receive.denyDeletes", "true")
    return bare


def store_args(remote, inp, out, *, pr=7, run_id=1001, attempt=1, branch="reports", max_bytes=None):
    args = ["store", "--remote", remote_url(remote), "--branch", branch, "--pr", pr, "--run-id", run_id,
            "--attempt", attempt, "--artifact", inp.artifact, "--publish", inp.publish, "--context", inp.context,
            "--out", out]
    if max_bytes is not None:
        args += ["--max-bytes", max_bytes]
    return args


def store(tmp_path, remote, inp, *, out_name="archive-out.json", **kw):
    out = Path(tmp_path) / out_name
    if out.exists():
        out.unlink()
    res = run_gate("archive", *store_args(remote, inp, out, **kw), cwd=tmp_path)
    return res, load_out(res, out)


def folder(files, pr=7, run_id=1001, attempt=1):
    prefix = f"reports/{pr}/{run_id}-{attempt}/"
    return {p[len(prefix):]: data for p, data in files.items() if p.startswith(prefix)}


def sums_of(folder_files):
    listed = {}
    for line in folder_files["SHA256SUMS"].decode("utf-8").splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        assert m, f"SHA256SUMS line is not '<sha256>  <relative path>': {line!r}"
        listed[m.group(2)] = m.group(1)
    return listed


# ----------------------------------------------------------------------------- the layout


@pytest.mark.req("W-0", "W-5")
def test_store_writes_the_documented_layout_and_a_checkable_sha256sums(tmp_path, remote):
    inp = make_inputs(tmp_path)
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert RESULT_KEYS <= set(d)
    assert d["stored"] is True and d["sha256sums_match"] is True and d["artifact_present"] is True
    assert d["skipped_unsafe"] == []
    assert d["path"].replace("\\", "/").strip("/").endswith("reports/7/1001-1")
    assert d["commit"] == branch_tip(remote, "reports")
    f = folder(branch_files(remote, "reports"))
    assert f["context.json"] == inp.context.read_bytes()
    for name, data in inp.pub_files.items():
        assert f[name] == data, f"{name} from --publish sits at the top of the attempt's folder"
    for name, data in inp.art_files.items():
        assert f[f"artifact/{name}"] == data, f"artifact/{name} must be stored byte for byte"
    assert f["guard.json"] == inp.art_files["guard.json"] and f["acceptance.json"] == inp.art_files["acceptance.json"], \
        "for later runs guard.json and acceptance.json are also stored at the top of the folder"
    expected = {"context.json", "SHA256SUMS", *inp.pub_files, *(f"artifact/{n}" for n in inp.art_files),
                "guard.json", "acceptance.json"}
    assert set(f) == expected
    listed = sums_of(f)
    assert set(listed) == expected - {"SHA256SUMS"}, "SHA256SUMS covers all of them"
    for path, digest in listed.items():
        assert digest == sha256_bytes(f[path]), f"SHA256SUMS is wrong for {path}"


@pytest.mark.req("W-0")
def test_store_control_guard_and_acceptance_are_not_invented_when_the_artifact_has_none(tmp_path, remote):
    files = {k: v for k, v in ART.items() if k not in ("guard.json", "acceptance.json")}
    inp = make_inputs(tmp_path, artifact_files=files)
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    f = folder(branch_files(remote, "reports"))
    assert "guard.json" not in f and "acceptance.json" not in f


@pytest.mark.req("W-0")
def test_store_usage_error_exits_2(tmp_path, remote):
    res = run_gate("archive", "store", "--remote", remote_url(remote), cwd=tmp_path)
    assert res.rc == 2
    assert_no_traceback(res)
    assert branch_tip(remote, "reports") is None


# ----------------------------------------------------------------------------- W-1, W-8


@pytest.mark.req("W-1")
def test_w1_the_branch_is_created_without_a_parent_when_missing(tmp_path, remote):
    main_before = branch_tip(remote, "main")
    assert branch_tip(remote, "reports") is None
    res, d = store(tmp_path, remote, make_inputs(tmp_path))
    assert_rc(res, 0)
    tip = branch_tip(remote, "reports")
    assert tip is not None and parents_of(remote, tip) == [], "the new branch has no parent"
    assert len(rev_list(remote, "reports")) == 1
    assert branch_tip(remote, "main") == main_before, "the other branches are left alone"
    assert all(p.startswith("reports/7/") for p in branch_files(remote, "reports")), "nothing from main in the new branch"


@pytest.mark.req("W-1", "W-8")
def test_w8_earlier_attempts_are_never_changed(tmp_path, remote):
    r1, d1 = store(tmp_path, remote, make_inputs(tmp_path, tag="in1"), attempt=1)
    assert_rc(r1, 0)
    first_tip = branch_tip(remote, "reports")
    first_tree = git(remote, "rev-parse", f"{first_tip}:reports/7/1001-1")
    inp2 = make_inputs(tmp_path, tag="in2", publish_files={"report.json": b'{"report": 2}\n'})
    r2, d2 = store(tmp_path, remote, inp2, attempt=2, out_name="out2.json")
    assert_rc(r2, 0)
    r3, d3 = store(tmp_path, remote, make_inputs(tmp_path, tag="in3"), pr=8, run_id=1002, out_name="out3.json")
    assert_rc(r3, 0)
    tip = branch_tip(remote, "reports")
    assert git(remote, "rev-parse", f"{tip}:reports/7/1001-1") == first_tree, "attempt 1 must be byte-identical"
    assert first_tip in rev_list(remote, "reports"), "history is only ever appended to"
    assert len(rev_list(remote, "reports")) == 3
    files = branch_files(remote, "reports")
    assert folder(files, 7, 1001, 2)["report.json"] == b'{"report": 2}\n'
    assert set(folder(files, 7, 1001, 1)) and set(folder(files, 8, 1002, 1))


# ----------------------------------------------------------------------------- W-2


@pytest.mark.req("W-2")
def test_w2_a_missing_artifact_folder_still_stores_the_rest(tmp_path, remote):
    inp = make_inputs(tmp_path, artifact=False)
    assert not inp.artifact.exists()
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    assert d["stored"] is True and d["sha256sums_match"] is True and d["artifact_present"] is False
    f = folder(branch_files(remote, "reports"))
    assert set(f) == {"context.json", "SHA256SUMS", *PUB}
    assert not [p for p in f if p.startswith("artifact/")]
    assert set(sums_of(f)) == {"context.json", *PUB}


# ----------------------------------------------------------------------------- W-3


@pytest.mark.req("W-3")
def test_w3_append_only_a_second_store_of_the_same_attempt_changes_nothing(tmp_path, remote):
    r1, d1 = store(tmp_path, remote, make_inputs(tmp_path, tag="in1"))
    assert_rc(r1, 0)
    tip, files = branch_tip(remote, "reports"), branch_files(remote, "reports")
    changed = make_inputs(tmp_path, tag="in2", publish_files={"report.json": b'{"report": "DIFFERENT"}\n'})
    r2, d2 = store(tmp_path, remote, changed, out_name="out2.json")
    assert_rc(r2, 1)
    assert_no_traceback(r2)
    assert d2["stored"] is False and d2["reason"] == "ALREADY_EXISTS"
    assert RESULT_KEYS <= set(d2)
    assert branch_tip(remote, "reports") == tip and branch_files(remote, "reports") == files


@pytest.mark.req("W-3")
@pytest.mark.parametrize("kw", [{"attempt": 2}, {"run_id": 1002}, {"pr": 8}], ids=["next-attempt", "next-run", "other-pr"])
def test_w3_control_a_different_attempt_run_or_pr_is_stored(tmp_path, remote, kw):
    r1, _ = store(tmp_path, remote, make_inputs(tmp_path, tag="in1"))
    assert_rc(r1, 0)
    r2, d2 = store(tmp_path, remote, make_inputs(tmp_path, tag="in2"), out_name="out2.json", **kw)
    assert_rc(r2, 0)
    assert d2["stored"] is True


# ----------------------------------------------------------------------------- hooks on the remote (shell shims that start Python)


def install_hook(bare, name, code, *args):
    script = write_script(Path(bare).parent / f"hook-{name}-{len(list(Path(bare).parent.glob('hook-*')))}.py", code)
    quoted = " ".join(f'"{Path(a).as_posix() if os.sep in str(a) or "/" in str(a) else a}"' for a in args)
    body = f'#!/bin/sh\nexec "{Path(sys.executable).as_posix()}" "{script.as_posix()}" {quoted}\n'
    hook = Path(bare) / "hooks" / name
    hook.write_bytes(body.encode("utf-8"))
    os.chmod(hook, 0o755)


REJECT_FIRST_N = '''
import os, sys
counter, n = sys.argv[1], int(sys.argv[2])
sys.stdin.read()
cur = int(open(counter).read()) if os.path.exists(counter) else 0
open(counter, "w").write(str(cur + 1))
if cur < n:
    sys.stderr.write("simulated refusal %d\\n" % (cur + 1))
    sys.exit(1)
'''

BARRIER = '''
import os, sys, time, uuid
d, need, tmo = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
sys.stdin.read()
open(os.path.join(d, "arrived-" + uuid.uuid4().hex), "w").close()
end = time.time() + tmo
while time.time() < end:
    if len(os.listdir(d)) >= need:
        break
    time.sleep(0.05)
'''

TAMPER = '''
import os, subprocess, sys
marker = sys.argv[1]
sys.stdin.read()
if os.path.exists(marker):
    sys.exit(0)
open(marker, "w").write("1")
def g(*a, inp=None, env=None):
    return subprocess.run(["git", *a], input=inp, capture_output=True, check=True, env=env).stdout
tip = g("rev-parse", "refs/heads/reports").decode().strip()
target = None
for e in g("ls-tree", "-r", "-z", "--full-tree", tip).split(b"\\0"):
    if e.endswith(b"/context.json"):
        target = e.split(b"\\t", 1)[1].decode()
blob = g("hash-object", "-w", "--stdin", inp=b'{"tampered": true}\\n').decode().strip()
env = dict(os.environ, GIT_INDEX_FILE=os.path.join(os.path.dirname(marker), "tamper-index"),
           GIT_AUTHOR_NAME="x", GIT_AUTHOR_EMAIL="x@example.invalid", GIT_COMMITTER_NAME="x", GIT_COMMITTER_EMAIL="x@example.invalid")
g("read-tree", tip, env=env)
g("update-index", "--cacheinfo", "100644,%s,%s" % (blob, target), env=env)
tree = g("write-tree", env=env).decode().strip()
commit = g("commit-tree", tree, "-p", tip, "-m", "tamper", env=env).decode().strip()
g("update-ref", "refs/heads/reports", commit, tip)
'''


# ----------------------------------------------------------------------------- W-4


@pytest.mark.req("W-4")
def test_w4_a_refused_push_is_fetched_and_retried_and_never_forced(tmp_path, remote):
    counter = tmp_path / "pushes.txt"
    install_hook(remote, "pre-receive", REJECT_FIRST_N, counter, 3)
    res, d = store(tmp_path, remote, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert d["stored"] is True and d["sha256sums_match"] is True
    assert int(counter.read_text()) == 4, "three refused pushes, then the accepted one"
    assert len(rev_list(remote, "reports")) == 1


@pytest.mark.req("W-4")
def test_w4_it_gives_up_after_the_retries_and_reports_not_stored(tmp_path, remote):
    counter = tmp_path / "pushes.txt"
    install_hook(remote, "pre-receive", REJECT_FIRST_N, counter, 1000)
    res, d = store(tmp_path, remote, make_inputs(tmp_path))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["stored"] is False
    pushes = int(counter.read_text())
    # Assumption: "retries, up to 5 times" means between 5 and 6 pushes in all (the first plus up to five retries).
    assert 5 <= pushes <= 6, f"expected the push to be tried and retried up to 5 times, saw {pushes} pushes"
    assert branch_tip(remote, "reports") is None


def popen_store(tmp_path, remote, tag, **kw):
    inp = make_inputs(tmp_path, tag=tag)
    out = Path(tmp_path) / f"out-{tag}.json"
    cmd = [sys.executable, "-P", "-m", "gate.archive", *[str(a) for a in store_args(remote, inp, out, **kw)]]
    proc = subprocess.Popen(cmd, cwd=str(tmp_path), env=base_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace")
    return proc, out


@pytest.mark.req("W-4", "W-1")
@pytest.mark.parametrize("branch_exists", [True, False], ids=["branch-exists", "branch-missing"])
def test_w4_two_runs_at_once_both_end_stored(tmp_path, remote, branch_exists):
    if branch_exists:
        r0, _ = store(tmp_path, remote, make_inputs(tmp_path, tag="seed"), run_id=1000, out_name="seed-out.json")
        assert_rc(r0, 0)
    barrier = tmp_path / "barrier"
    barrier.mkdir()
    install_hook(remote, "pre-receive", BARRIER, barrier, 2, 25)  # both pushes are held until both have arrived
    pa, outa = popen_store(tmp_path, remote, "a", run_id=2001)
    pb, outb = popen_store(tmp_path, remote, "b", run_id=2002)
    results = []
    for proc in (pa, pb):
        stdout, stderr = proc.communicate(timeout=240)
        results.append((proc.returncode, stdout, stderr))
    for rc, stdout, stderr in results:
        assert rc == 0, f"both runs must end stored\nstdout:\n{stdout}\nstderr:\n{stderr}"
        assert "Traceback" not in stderr
    assert read_json(outa)["stored"] is True and read_json(outb)["stored"] is True
    assert len(list(barrier.glob("arrived-*"))) >= 3, "precondition: one push was refused and retried"
    files = branch_files(remote, "reports")
    assert folder(files, 7, 2001, 1) and folder(files, 7, 2002, 1), "neither run may overwrite the other"
    assert len(rev_list(remote, "reports")) == (3 if branch_exists else 2), "every store adds one commit, none is lost"


# ----------------------------------------------------------------------------- W-5


@pytest.mark.req("W-5")
def test_w5_read_back_notices_when_the_branch_does_not_hold_what_was_pushed(tmp_path, remote):
    marker = tmp_path / "tamper-done.txt"
    install_hook(remote, "post-receive", TAMPER, marker)
    res, d = store(tmp_path, remote, make_inputs(tmp_path))
    assert marker.exists(), "precondition: the remote changed the branch after the push"
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["sha256sums_match"] is False


# ----------------------------------------------------------------------------- W-6


@pytest.mark.req("W-6")
def test_w6_git_folders_in_the_artifact_are_not_stored_and_are_listed(tmp_path, remote):
    inp = make_inputs(tmp_path)
    write_bytes(inp.artifact / ".git" / "config", b"[core]\n\thooksPath = evil\n")
    write_bytes(inp.artifact / "sub" / ".git" / "HEAD", b"ref: refs/heads/evil\n")
    write_bytes(inp.artifact / "sub" / "kept.txt", b"kept\n")
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    assert d["stored"] is True and d["sha256sums_match"] is True
    files = branch_files(remote, "reports")
    assert not [p for p in files if ".git/" in p or p.endswith("/.git")], "nothing under a .git folder may be stored"
    assert folder(files)["artifact/sub/kept.txt"] == b"kept\n", "its neighbours are stored"
    assert ".git" in json.dumps(d["skipped_unsafe"]) and d["skipped_unsafe"], "the skipped paths are listed"


@pytest.mark.req("W-6")
def test_w6_symbolic_links_in_the_artifact_are_not_stored_and_are_listed(tmp_path, remote):
    inp = make_inputs(tmp_path)
    secret = tmp_path / "outside-secret.txt"
    write_text(secret, "SENTINEL-VALUE-OUTSIDE\n")
    try:
        os.symlink(secret, inp.artifact / "link-to-outside.txt")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symbolic link on this machine ({exc}); W-6 symlink part is not checked here")
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    files = branch_files(remote, "reports")
    assert "artifact/link-to-outside.txt" not in folder(files)
    assert not any(b"SENTINEL-VALUE-OUTSIDE" in data for data in files.values()), "the link's target must not be followed"
    assert "link-to-outside.txt" in json.dumps(d["skipped_unsafe"])


@pytest.mark.req("W-6", "W-5", "C-4")
def test_w6_control_hostile_git_metadata_files_are_stored_faithfully(tmp_path, remote):
    files = dict(ART)
    files[".gitignore"] = b"*\n!.gitignore\n"
    files[".gitattributes"] = b"* text eol=lf\n*.bin -text\n"
    files["crlf.txt"] = b"a\r\nb\r\nc\r\n"
    files[".github/notes.md"] = b"a folder that merely starts with .git\n"
    inp = make_inputs(tmp_path, artifact_files=files)
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 0)
    assert d["stored"] is True and d["sha256sums_match"] is True and d["skipped_unsafe"] == []
    f = folder(branch_files(remote, "reports"))
    for name, data in files.items():
        assert f[f"artifact/{name}"] == data, f"{name} must be stored exactly as it was in the artifact"
    assert sums_of(f)["artifact/crlf.txt"] == sha256_bytes(files["crlf.txt"])


# ----------------------------------------------------------------------------- W-7


@pytest.mark.req("W-7")
def test_w7_an_artifact_larger_than_max_bytes_is_not_stored(tmp_path, remote):
    inp = make_inputs(tmp_path, artifact_files={"big.bin": b"x" * 1001})
    res, d = store(tmp_path, remote, inp, max_bytes=1000)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["stored"] is False and d["reason"] == "TOO_LARGE"
    assert branch_tip(remote, "reports") is None, "nothing may be pushed"


@pytest.mark.req("W-7")
def test_w7_control_an_artifact_of_exactly_max_bytes_is_stored(tmp_path, remote):
    # Assumption: the size is the sum of the sizes of the artifact's files.
    inp = make_inputs(tmp_path, artifact_files={"big.bin": b"x" * 1000})
    res, d = store(tmp_path, remote, inp, max_bytes=1000)
    assert_rc(res, 0)
    assert d["stored"] is True


@pytest.mark.req("W-7")
def test_w7_the_default_limit_is_200_000_000_bytes(tmp_path, remote):
    inp = make_inputs(tmp_path, artifact_files={"small.txt": b"x"})
    with open(inp.artifact / "huge.bin", "wb") as f:
        f.truncate(200_000_001)
    res, d = store(tmp_path, remote, inp)
    assert_rc(res, 1)
    assert d["stored"] is False and d["reason"] == "TOO_LARGE"
    assert branch_tip(remote, "reports") is None


# ----------------------------------------------------------------------------- append


def append(tmp_path, remote, path, file, *, out_name="append-out.json"):
    out = Path(tmp_path) / out_name
    if out.exists():
        out.unlink()
    res = run_gate("archive", "append", "--remote", remote_url(remote), "--branch", "reports", "--path", path,
                   "--file", file, "--out", out, cwd=tmp_path)
    return res, load_out(res, out)


@pytest.mark.req("W-9")
def test_append_adds_one_new_file_to_a_stored_folder_with_a_read_back(tmp_path, remote):
    r1, _ = store(tmp_path, remote, make_inputs(tmp_path))
    assert_rc(r1, 0)
    before_tip, before = branch_tip(remote, "reports"), branch_files(remote, "reports")
    final = write_text(tmp_path / "final.json", '{"verdict": "ready-for-human"}\n')
    res, d = append(tmp_path, remote, "reports/7/1001-1/final.json", final)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert RESULT_KEYS <= set(d)
    assert d["stored"] is True and d["sha256sums_match"] is True
    after = branch_files(remote, "reports")
    assert after["reports/7/1001-1/final.json"] == final.read_bytes()
    assert {p: b for p, b in after.items() if p != "reports/7/1001-1/final.json"} == before, \
        "every file that was stored before is unchanged"
    assert parents_of(remote, branch_tip(remote, "reports")) == [before_tip]


@pytest.mark.req("W-9", "W-3")
def test_append_to_an_existing_file_is_refused_and_changes_nothing(tmp_path, remote):
    r1, _ = store(tmp_path, remote, make_inputs(tmp_path))
    assert_rc(r1, 0)
    tip, files = branch_tip(remote, "reports"), branch_files(remote, "reports")
    other = write_text(tmp_path / "other.json", '{"replaced": true}\n')
    res, d = append(tmp_path, remote, "reports/7/1001-1/report.json", other)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["stored"] is False and d["reason"] == "ALREADY_EXISTS"
    assert branch_tip(remote, "reports") == tip and branch_files(remote, "reports") == files
