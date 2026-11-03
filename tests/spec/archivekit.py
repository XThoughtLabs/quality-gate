"""Shared inputs and checks for the archive tests (the plain git remote and the API)."""
from __future__ import annotations

import re
from pathlib import Path

from gatekit import write_bytes, write_json

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
RESULT_KEYS = {"stored", "sha256sums_match", "path", "commit", "reason", "artifact_present", "skipped_unsafe",
               "actors_ok"}


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

