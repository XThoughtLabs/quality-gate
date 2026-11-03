"""Rerun every deterministic check for one commit, and compare the report with the stored one.

AI steps are reproducible as a procedure, not as identical output, so only the
deterministic checks run here: the mandatory checks of the run job. The trusted
facts that came from the original run (its context and extras) are taken from the
stored evidence. The result must equal the stored report except for the times.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from gate import report as report_module
from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, read_json, read_json_or_none, slug, write_json

RUN_STEPS = report_module.RUN_STEPS
GATE_ROOT = Path(__file__).resolve().parent.parent


def git(*args: str, cwd: Path | None = None) -> str:
    process = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    if process.returncode != 0:
        raise UsageError(f"git {args[0]} failed: {process.stderr.decode('utf-8', 'replace').strip()[:300]}")
    return process.stdout.decode("utf-8", "replace").strip()


def find_stored(reports: Path, sha: str) -> Path:
    """The newest stored attempt for this head SHA."""

    def order(path: Path) -> tuple[int, int]:
        run_id, _, attempt = path.name.partition("-")
        return (int(run_id) if run_id.isdigit() else 0, int(attempt) if attempt.isdigit() else 0)

    found = []
    for folder in reports.glob("*/*"):
        context = read_json_or_none(folder / "context.json")
        if isinstance(context, dict) and context.get("head_sha") == sha:
            found.append(folder)
    if not found:
        raise UsageError(f"no stored evidence for {sha}")
    return max(found, key=order)


def copy_earlier_runs(stored: Path, target: Path) -> Path:
    """The runs stored before this attempt, as the original guard saw them."""

    def order(name: str) -> tuple[int, int]:
        run_id, _, attempt = name.partition("-")
        return (int(run_id) if run_id.isdigit() else 0, int(attempt) if attempt.isdigit() else 0)

    limit = order(stored.name)
    reports = stored.parent.parent
    target.mkdir(parents=True, exist_ok=True)
    for name in ("guard.json", "acceptance.json"):
        for path in reports.glob(f"*/*/{name}"):
            if order(path.parent.name) < limit:
                copy = target / path.parent.parent.name / path.parent.name / name
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, copy)
    return target


def run_step(check: str, config: Path, out: Path, workdir: Path, environment: dict[str, str]) -> str:
    process = subprocess.run(
        [sys.executable, "-P", "-m", "gate.run_checks", "--config", str(config), "--check", check, "--out", str(out), "--workdir", str(workdir)],
        env=environment,
        check=False,
    )
    return "success" if process.returncode == 0 else "failure"


def reproduce(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    work = out / "work"
    for folder in (work, out / "artifact", out / "regenerated"):
        if folder.exists():
            shutil.rmtree(folder)
    work.mkdir(parents=True)

    pr_dir = work / "pr"
    git("clone", "--quiet", args.repo, str(pr_dir))
    git("checkout", "--quiet", "--detach", args.sha, cwd=pr_dir)
    git("fetch", "--quiet", "--no-tags", "origin", "+refs/heads/reports:refs/remotes/origin/reports", cwd=pr_dir)
    stored_tree = work / "stored"
    git("worktree", "add", "--quiet", "--detach", str(stored_tree), "origin/reports", cwd=pr_dir)
    stored = find_stored(stored_tree / "reports", args.sha)

    context = read_json(stored / "context.json")
    extras_path = stored / "extras.json"
    trusted_ref = context.get("trusted_sha") or git("symbolic-ref", "--short", "refs/remotes/origin/HEAD", cwd=pr_dir)
    trusted_tree = work / "trusted"
    git("worktree", "add", "--quiet", "--detach", str(trusted_tree), trusted_ref, cwd=pr_dir)
    config = trusted_tree / "quality.toml"
    earlier_reports = copy_earlier_runs(stored, work / "earlier")

    artifact = out / "artifact"
    environment = {
        **os.environ,
        "GATE_ENV_ROLE": "reproduce",
        "PYTHONPATH": str(GATE_ROOT),
        "GATE_HOME": str(GATE_ROOT),
        "GATE_PY": sys.executable,
        "GATE_CONFIG": str(config),
        "GATE_PR_DIR": str(pr_dir),
        "GATE_BASE_SHA": str(context["base_sha"]),
        "GATE_HEAD_SHA": str(context["head_sha"]),
        "GATE_HEAD_REF": str(context["head_ref"]),
        "GATE_PR": str(context["pr"]),
        "GATE_REPORTS_DIR": str(earlier_reports),
        "GATE_KNOWN_FAILING": str(pr_dir / "acceptance" / "known-failing.txt"),
        "GATE_ACCEPTANCE_MODE": "exact" if str(context["head_ref"]).startswith("spec/") else "subset",
    }

    subprocess.run(
        [sys.executable, "-P", "-m", "gate.run_checks", "--config", str(config), "--check", "setup", "--if-configured", "--out", str(artifact), "--workdir", str(pr_dir)],
        env=environment,
        check=False,
    )

    steps = []
    builtin = GATE_ROOT / "gate" / "builtin_checks.toml"
    for number, check in enumerate(RUN_STEPS, start=1):
        source = builtin if check in ("gate/env", "gate/guard") else config
        if check == "gate/acceptance" and not str(context["head_ref"]).startswith("spec/"):
            target = pr_dir / "acceptance"
            if target.exists():
                shutil.rmtree(target)
            if (trusted_tree / "acceptance").is_dir():
                shutil.copytree(trusted_tree / "acceptance", target)
        conclusion = run_step(check, source, artifact, pr_dir, environment)
        steps.append({"name": check, "status": "completed", "conclusion": conclusion, "number": number})
        raw_dir = artifact / "raw" / slug(check)
        raw_dir.mkdir(parents=True, exist_ok=True)

    all_ok = all(step["conclusion"] == "success" for step in steps)
    jobs = {"jobs": [{"name": "run", "status": "completed", "conclusion": "success" if all_ok else "failure", "steps": steps}]}
    jobs_path = out / "jobs.json"
    write_json(jobs_path, jobs)

    seal = report_module.main(
        ["seal", "--artifact", str(artifact), "--head-sha", str(context["head_sha"]), "--run-id", str(context["run_id"]), "--run-attempt", str(context["run_attempt"])]
    )
    if seal != EXIT_OK:
        return seal

    generate = ["generate", "--context", str(stored / "context.json"), "--jobs", str(jobs_path), "--artifact", str(artifact), "--config", str(config), "--out", str(out / "regenerated")]
    if extras_path.is_file():
        generate += ["--extras", str(extras_path)]
    code = report_module.main(generate)
    if code != EXIT_OK:
        return code
    return report_module.main(["compare", str(stored / "report.json"), str(out / "regenerated" / "report.json")])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.reproduce")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        code = reproduce(args)
    except (UsageError, OSError, KeyError, ValueError) as error:
        return fail_usage(str(error))
    print("reproduced: equal except for the times" if code == EXIT_OK else "not reproduced")
    return EXIT_OK if code == EXIT_OK else EXIT_RULE_FAILED


if __name__ == "__main__":
    sys.exit(main())
