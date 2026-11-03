"""A consistent, all-green world for gate.report generate, and the means to break one piece at a time.

Everything here is made of the inputs that CONTRACTS.md section 8.1 names: a trusted context, the API's job list,
an untrusted artifact folder, the configuration and the trusted extras.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from gatekit import GATE_ROOT, load_out, make_config, run_gate, sha256_bytes, write_bytes, write_json, write_text

MANDATORY = ["gate/env", "gate/guard", "gate/tests", "gate/acceptance", "gate/security"]
DIAG = ["diag/coverage", "diag/mypy"]
FIXED_CLASS = {**{c: "mandatory" for c in MANDATORY + ["gate/report", "gate/archive", "gate/final"]},
               **{f"diag/{n}": "diagnostic" for n in ("coverage", "mypy", "ruff", "semgrep", "schemathesis",
                                                       "mutation", "benchmark")}}

H1, H2, H3, H4 = "1" * 40, "2" * 40, "3" * 40, "4" * 40
KNOWN_LISTED = ["acceptance.test_status::test_history", "acceptance.test_status::test_permissions"]


def slug(cid: str) -> str:
    return cid.replace("/", "-")


class Outcome:
    def __init__(self, res, out_dir):
        self.res = res
        self.out_dir = Path(out_dir)
        self.report = self._load("report.json")
        self.verdict = self._load("verdict.json")
        md = self.out_dir / "report.md"
        self.md = md.read_text(encoding="utf-8") if md.exists() else None

    def _load(self, name):
        return load_out(self.res, self.out_dir / name)

    def need(self) -> "Outcome":
        """Fail, with the command output, unless the three report files were written."""
        for name in ("report.json", "verdict.json", "report.md"):
            assert (self.out_dir / name).exists(), f"{name} was not written\n{self.describe()}"
        return self

    @property
    def codes(self) -> list[str]:
        return [r["code"] for r in self.verdict["reasons"]]

    def describe(self) -> str:
        return f"{self.res.describe()}\nverdict.json: {json.dumps(self.verdict, indent=1) if self.verdict else None}"


class World:
    def __init__(self, tmp, diag=tuple(DIAG)):
        self.tmp = Path(tmp)
        self.ctx = {
            "repository": "example-org/gate-app", "head_repository": "example-org/gate-app", "pr": 7,
            "run_id": 1001, "run_attempt": 1, "event": "pull_request_target",
            "baseline_sha": H1, "base_sha": H2, "head_sha": H3, "gate_sha": H4, "head_ref": "ai/7-example",
            "config_hashes": {"quality.toml": "5" * 64, ".github/workflows/judge.yml": "6" * 64},
        }
        self.checks = MANDATORY + list(diag)
        self.steps = {c: {"status": "completed", "conclusion": "success"} for c in self.checks}
        self.rows = {c: [self._row(c, 0, 0)] for c in self.checks}
        self.run_job_name = "run"
        self.drop_run_job = False
        self.run_status = "completed"
        self.run_conclusion = None  # derived
        self.publish_steps_extra: list[dict] = []
        self.meta = {"head_sha": H3, "run_id": 1001, "run_attempt": 1}
        self.guard = {"kind": "ai", "head_sha": H3, "violations": [], "needs_code_owner": [], "marked_tests": [],
                      "dependency_changes": [],
                      "fingerprint": {"round": "a" * 64, "cumulative": "b" * 64}, "repeated_fix": False}
        self.acceptance = {"ok": True, "mode": "subset", "list_size": 2, "failing_not_listed": [],
                           "listed_failing": ["acceptance.test_status::test_history"],
                           "remove_from_list": ["acceptance.test_status::test_permissions"], "missing_listed": [],
                           "passed": ["acceptance.test_search::test_find", "acceptance.test_status::test_permissions"],
                           "reason_codes": []}
        self.environment = {"python": "3.13.1", "image_os": "ubuntu24"}
        self.coverage = {"line_percent": 91.5}
        self.mutation = {"score": 0.62}
        self.counts = {"tests": 12, "failures": 0, "errors": 0, "skipped": 0}
        self.extras: dict | None = None
        self.extra_files: dict[str, bytes] = {}
        self.omit_artifact = False
        self.omit_files: set[str] = set()      # top-level files not written at all
        self.drop_after_sums: set[str] = set()  # written, listed in SHA256SUMS, then removed
        self.tamper_after_sums: dict[str, bytes] = {}
        self.config_limits = {"max_turns": 40, "timeout_minutes": 60, "max_fix_rounds": 3}
        self.config_raw = ""
        self.config_accepted: list[dict] = []   # [[archive.accepted_foreign_commits]] of quality.toml (W-14)
        self.setup_step: str | None = None      # the conclusion of a step named `setup` in the run job (V-10)
        self.setup_codes: list = [0]            # its rows in exit-codes.tsv

    # ------------------------------------------------------------------ editing
    @staticmethod
    def _row(cid, index, code, argv=None):
        return {"check": cid, "index": index, "exit_code": code, "duration": 0.25,
                "argv": argv or ["python", "-m", "check", cid]}

    def set_rows(self, cid, codes):
        self.rows[cid] = [self._row(cid, i, c) for i, c in enumerate(codes)]

    def fail(self, cid, code=1):
        self.steps[cid] = {"status": "completed", "conclusion": "failure"}
        self.set_rows(cid, [code])

    def set_step(self, cid, conclusion, status="completed"):
        self.steps[cid] = {"status": status, "conclusion": conclusion}

    def drop_step(self, cid, rows=True):
        self.steps.pop(cid, None)
        if rows:
            self.rows.pop(cid, None)

    def unfinish(self, cid, status="in_progress", conclusion=None):
        self.steps[cid] = {"status": status, "conclusion": conclusion}
        self.rows.pop(cid, None)

    # ------------------------------------------------------------------ writing
    def _jobs(self):
        steps = [{"name": "Set up job", "status": "completed", "conclusion": "success", "number": 1},
                 {"name": "Checkout", "status": "completed", "conclusion": "success", "number": 2}]
        n = 3
        if self.setup_step is not None:
            steps.append({"name": "setup", "number": n, "status": "completed", "conclusion": self.setup_step})
            n += 1
        for cid in self.checks:
            if cid in self.steps:
                steps.append({"name": cid, "number": n, **self.steps[cid]})
                n += 1
        failed = any(self.steps.get(c, {}).get("conclusion") == "failure" for c in MANDATORY)
        conclusion = None if self.run_status != "completed" else (self.run_conclusion or ("failure" if failed else "success"))
        job = {"name": self.run_job_name, "status": self.run_status, "conclusion": conclusion, "steps": steps}
        publish = {"name": "publish", "status": "in_progress", "conclusion": None,
                   "steps": [{"name": "Set up job", "status": "completed", "conclusion": "success", "number": 1},
                             *self.publish_steps_extra]}
        return {"jobs": [publish] if self.drop_run_job else [job, publish]}

    def _tsv(self):
        lines = ["check\tindex\texit_code\tduration_seconds\traw_path\targv_json"]
        for cid in self.checks:
            for r in self.rows.get(cid, []):
                raw = f"raw/{slug(cid)}/{r['index']}.log" if isinstance(r["index"], int) else ""
                lines.append("\t".join([cid, str(r["index"]), str(r["exit_code"]), str(r["duration"]), raw,
                                        json.dumps(r["argv"])]))
        if self.setup_step is not None:
            for i, code in enumerate(self.setup_codes):
                lines.append("\t".join(["setup", str(i), str(code), "0.25", f"raw/setup/{i}.log",
                                        json.dumps(["python", "-m", "check", "setup"])]))
        return "\n".join(lines) + "\n"

    def build(self):
        write_json(self.tmp / "context.json", self.ctx)
        write_json(self.tmp / "jobs.json", self._jobs())
        checks_cfg = {c: {"class": FIXED_CLASS[c], "commands": [["python", "-m", "check"]]} for c in self.checks}
        make_config(self.tmp / "quality.toml", limits=self.config_limits, checks=checks_cfg, raw_text=self.config_raw,
                    archive_accepted=self.config_accepted)
        if self.extras is not None:
            write_json(self.tmp / "extras.json", self.extras)
        art = self.tmp / "artifact"
        if art.exists():
            shutil.rmtree(art)
        if self.omit_artifact:
            return
        art.mkdir()
        files: dict[str, bytes] = {}
        for cid in self.checks:
            for r in self.rows.get(cid, []):
                if isinstance(r["index"], int):
                    files[f"raw/{slug(cid)}/{r['index']}.log"] = f"output of {cid} command {r['index']}\n".encode()
        if "gate/tests" in self.steps and self.counts is not None:
            files["raw/gate-tests/counts.json"] = json.dumps(self.counts).encode()
        if self.coverage is not None:
            files["raw/diag-coverage/summary.json"] = json.dumps(self.coverage).encode()
        if self.mutation is not None:
            files["raw/diag-mutation/summary.json"] = json.dumps(self.mutation).encode()
        if self.setup_step is not None:
            for i in range(len(self.setup_codes)):
                files[f"raw/setup/{i}.log"] = f"output of setup command {i}\n".encode()
        files["exit-codes.tsv"] = self._tsv().encode()
        files["meta.json"] = json.dumps(self.meta).encode()
        if self.guard is not None:
            files["guard.json"] = json.dumps(self.guard).encode()
        if self.acceptance is not None:
            files["acceptance.json"] = json.dumps(self.acceptance).encode()
        if self.environment is not None:
            files["environment.json"] = json.dumps(self.environment).encode()
        files.update(self.extra_files)
        for name in self.omit_files:
            files.pop(name, None)
        sums = "".join(f"{sha256_bytes(data)}  {name}\n" for name, data in sorted(files.items()) if name != "SHA256SUMS")
        for name, data in files.items():
            write_bytes(art / name, data)
        if "SHA256SUMS" not in self.omit_files:
            write_text(art / "SHA256SUMS", sums)
        for name in self.drop_after_sums:
            (art / name).unlink()
        for name, data in self.tamper_after_sums.items():
            write_bytes(art / name, data)

    def run(self, extra_args=(), build=True) -> Outcome:
        if build:
            self.build()
        out = self.tmp / "report-out"
        if out.exists():
            shutil.rmtree(out)
        args = ["generate", "--context", self.tmp / "context.json", "--jobs", self.tmp / "jobs.json", "--artifact",
                self.tmp / "artifact", "--config", self.tmp / "quality.toml", "--out", out]
        if self.extras is not None:
            args += ["--extras", self.tmp / "extras.json"]
        args += list(extra_args)
        return Outcome(run_gate("report", *args, cwd=self.tmp), out)


def load_schema():
    path = GATE_ROOT / "gate" / "schema" / "report.schema.json"
    assert path.exists(), f"{path} is named by CONTRACTS.md section 8.1 and must exist"
    return json.loads(path.read_text(encoding="utf-8"))


def schema_errors(report) -> list[str]:
    import jsonschema

    schema = load_schema()
    validator = jsonschema.validators.validator_for(schema)(schema)
    return [e.message for e in validator.iter_errors(report)]
