"""Prove the tests by breaking the code: each mutant must make its tests fail.

Each mutant is one deliberately broken version of a script, made in a copy of the
repository. The real files are never changed. Writes the results to a JSON file.

    python tests/mutants/run_mutants.py --out docs/mutants-results.json [--only GUARD]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", "reproduce-out"}

# The tests that should notice a broken script. A mutant is judged by these only, so that
# a mutant left alive costs minutes and not the whole suite; a broader run can only kill more.
UNIT = "tests/unit/test_unit_scripts.py"
E2E = "tests/unit/test_unit_end_to_end.py"
TESTS_FOR = {
    "GUARD": ["tests/spec/test_guard.py", "tests/spec/test_guard_v.py", E2E],
    "ENV": ["tests/spec/test_env_check.py", UNIT],
    "RUN": ["tests/spec/test_run_checks.py", "tests/spec/test_run_checks_base.py", "tests/spec/test_common.py", UNIT],
    "ACC": ["tests/spec/test_acceptance.py", UNIT],
    "REP": ["tests/spec/test_report_generate.py", "tests/spec/test_report_final_compare.py", "tests/spec/test_report_seal.py", "tests/unit/test_unit_archive_api.py", UNIT, E2E],
    "COMMON": ["tests/spec/test_report_generate.py", "tests/spec/test_common.py"],
    "ARC": ["tests/spec/test_archive.py", "tests/spec/test_archive_api.py", "tests/unit/test_unit_archive_api.py"],
    "FB": ["tests/spec/test_feedback.py", UNIT],
    "REV": ["tests/spec/test_review_local.py"],
    "HAR": ["tests/spec/test_concurrency_harness.py"],
    "SEC": ["tests/spec/test_security_check.py"],
}

# id, file, the exact text, what it becomes, the rule it should break.
MUTANTS: list[tuple[str, str, str, str, str]] = [
    # guard: every rule fires
    ("GUARD-G1", "gate/guard.py", "if is_protected(path, protected) or is_protected_control_file(path):", "if is_protected_control_file(path):", "G-1 protected path"),
    ("GUARD-G1-case", "gate/guard.py", "lowered = path.lower()", "lowered = path", "G-1 any letter case"),
    ("GUARD-G2-file", "gate/guard.py", 'result.add("TEST_DELETED", path, "the test file was deleted")', "pass", "G-2 test file deleted"),
    ("GUARD-G2-func", "gate/guard.py", 'result.add("TEST_DELETED", path, f"{name} was removed")', "pass", "G-2 test function removed"),
    ("GUARD-G3", "gate/guard.py", "if after.skips > before.skips:", "if False:", "G-3 test skipped"),
    ("GUARD-G4-count", "gate/guard.py", "if after.checks < before.checks:", "if False:", "G-4 fewer checks"),
    ("GUARD-G4-true", "gate/guard.py", "if after.always_true > before.always_true:", "if False:", "G-4 always-true assert"),
    ("GUARD-G4-raises", "gate/guard.py", "if after.broad_raises > before.broad_raises:", "if False:", "G-4 broad raises"),
    ("GUARD-G5", "gate/guard.py", "if not (_REASON.search(text) or _REASON.search(above)):", "if False:", "G-5 no reason line"),
    ("GUARD-G5-spelling", "gate/guard.py", 're.compile(r"#\\s*noqa\\b", re.IGNORECASE)', 're.compile(r"# noqa")', "G-5 another spelling of noqa"),
    ("GUARD-G6-lower", "gate/guard.py", "elif min(new_values) < min(old_values):", "elif False:", "G-6 threshold lowered"),
    ("GUARD-G6-removed", "gate/guard.py", 'result.add("THRESHOLD_LOWERED", path, f"{key} was removed")', "pass", "G-6 threshold removed"),
    ("GUARD-G7", "gate/guard.py", "if unhashed:", "if False:", "G-7 no hash"),
    ("GUARD-G7-source", "gate/guard.py", 'result.add("DEPENDENCY_NO_HASH", path, "a dependency source changed with no locked file with hashes")', "pass", "G-7 source without lock"),
    ("GUARD-G8", "gate/guard.py", "result.needs_code_owner.append(path)\n        for key", "for key", "G-8 code-owner approval"),
    ("GUARD-G9", "gate/guard.py", 'if stored.get("round") == result.fingerprint["round"] or stored.get("cumulative") == result.fingerprint["cumulative"]:', "if False:", "G-9 repeated fix"),
    ("GUARD-G10", "gate/guard.py", "if not _FULL_SHA.match(ref):", "if False:", "G-10 unpinned action"),
    ("GUARD-G11", "gate/guard.py", 'if not is_protected(path, ["acceptance/"]):', "if False:", "G-11 spec outside acceptance"),
    ("GUARD-G12", "gate/guard.py", "if test_id in passes:", "if False:", "G-12 add a passed test"),
    ("GUARD-G13-kind", "gate/guard.py", 'if kind != "spec":', "if False:", "G-13 add outside a spec PR"),
    ("GUARD-G13-def", "gate/guard.py", 'if not map_id.startswith("DEF-"):', "if False:", "G-13 add without a defect ID"),
    ("GUARD-G13-new", "gate/guard.py", "if function_exists_in_base(git, base, test_id):", "if False:", "G-13 add an old test"),
    ("GUARD-G14", "gate/guard.py", "if test_id not in passes:", "if False:", "G-14 remove without a pass"),
    ("GUARD-no-ext-diff", "gate/guard.py", '"--no-ext-diff", "--no-textconv", "--text")', '"--no-textconv", "--text")', "the guard starts an external diff"),
    # env_check: names the broken part, per role, never a value
    ("ENV-E1", "gate/env_check.py", 'items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", False, "missing or empty"))', 'items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", True))', "E-1 missing key"),
    ("ENV-E1-pem", "gate/env_check.py", 'items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", False, "has no PEM header line"))', 'items.append(Item("secret:EXECUTOR_APP_PRIVATE_KEY", True))', "E-1 malformed key"),
    ("ENV-E2", "gate/env_check.py", "if any(part in name.upper() for part in SECRET_NAME_PARTS):", "if False:", "E-2 secret in the run job"),
    ("ENV-E3-allowed", "gate/env_check.py", 'ok = want == "allowed"', "ok = True", "E-3 write allowed when it must be denied"),
    ("ENV-E3-denied", "gate/env_check.py", 'ok = want == "denied"', "ok = True", "E-3 write denied when it must be allowed"),
    ("ENV-E3-other", "gate/env_check.py", 'items.append(Item(label, False, f"write probe returned {status}"))', "items.append(Item(label, True))", "E-3 another status passes"),
    ("ENV-E5-pem", "gate/env_check.py", '"has no PEM header line"', "key", "E-5 prints a malformed key"),
    ("ENV-E5-id", "gate/env_check.py", '"is not a positive integer"', "app_id", "E-5 prints a malformed value"),
    ("ENV-E5-name", "gate/env_check.py", 'items.append(Item(f"secret-present:{name}", False, "a secret is present in this job"))', 'items.append(Item(f"secret-present:{name}", False, os.environ[name]))', "E-5 prints a present secret"),
    # run_checks
    ("RUN-R3", "gate/run_checks.py", "if code != 0 and first_failure == 0:", "if False:", "R-3 failure hidden"),
    ("RUN-R5", "gate/run_checks.py", 'if check.get("forbid_skips") and counts["skipped"] > 0:', "if False:", "R-5 skips allowed"),
    ("RUN-R6", "gate/run_checks.py", "if not (raw_dir / output).exists():", "if False:", "R-6 missing output"),
    ("RUN-R4", "gate/common.py", "return TIMEOUT_EXIT, time.monotonic() - started", "return 0, time.monotonic() - started", "R-4 timeout passes"),
    ("RUN-Q2", "gate/common.py", 'if declared != FIXED_CLASSES[check_id]:', "if False:", "Q-2 a check reclassified"),
    # acceptance
    ("ACC-A1", "gate/acceptance.py", "if failing_not_listed:", "if False:", "A-1 unlisted failure"),
    ("ACC-A4", "gate/acceptance.py", "if missing_listed:", "if False:", "A-4 listed test missing"),
    ("ACC-A5", "gate/acceptance.py", 'if mode == "exact" and failing != listed:', "if False:", "A-5 list not exact"),
    ("ACC-A6", "gate/acceptance.py", "if require_empty and listed:", "if False:", "A-6 list not empty"),
    ("ACC-A7", "gate/acceptance.py", "if len(parts) != 2 or not MAP_ID.match(parts[1]):", "if False:", "A-7 no map ID"),
    # report: missing output, unfinished stage, disagreement, claims
    ("REP-V1-sha", "gate/report.py", "elif str(meta[key]) != str(context.get(field)):", "elif False:", "V-1 another SHA"),
    ("REP-V1-exit", "gate/report.py", 'if step.get("conclusion") == "success" and any_failed:', "if False:", "V-1 success with a failed exit code"),
    ("REP-V1-exit2", "gate/report.py", 'elif step.get("conclusion") == "failure" and not any_failed:', "elif False:", "V-1 failure with all zero"),
    ("REP-V1-sum", "gate/report.py", "elif sha256_file(member) != digest:", "elif False:", "V-1 checksum"),
    ("REP-V1-claim", "gate/report.py", "if not all(step_success.get(check) for check in RUN_STEPS):", "if False:", "V-1 false claim"),
    ("REP-V1-fork", "gate/report.py", 'if context.get("head_repository") != context.get("repository"):', "if False:", "V-1 fork"),
    ("REP-V2-step", "gate/report.py", 'reason("UNFINISHED_STAGE", f"the step {check} is absent")', "pass", "V-2 absent step"),
    ("REP-V2-unfinished", "gate/report.py", 'reason("UNFINISHED_STAGE", f"the step {check} did not finish")', "pass", "V-2 unfinished step"),
    ("REP-V2-art", "gate/report.py", 'reason("NO_ARTIFACT", "the artifact is missing")', "pass", "V-2 no artifact"),
    ("REP-V2-file", "gate/report.py", 'reason("MISSING_OUTPUT", f"{name} is named in SHA256SUMS and is missing")', "pass", "V-2 missing output"),
    ("REP-V3", "gate/report.py", 'elif codes & {"REPEATED_FIX", "ROUND_CAP"}:', "elif False:", "V-3 needs-human"),
    ("REP-V4", "gate/report.py", 'reason("FAILED_CHECK", f"{check} failed")', "pass", "V-4 a failed check"),
    ("REP-F1", "gate/report.py", 'isinstance(archive, dict) and archive.get("stored") is True and archive.get("sha256sums_match") is True', "True", "F-1 ready without a stored archive"),
    ("REP-F1-own", "gate/report.py", 'if verdict == READY and isinstance(own_checks, dict) and any(value != "success" for value in own_checks.values()):', "if False:", "F-1 a failed check listed by the verdict"),
    ("REP-F3", "gate/report.py", 'return "success" if verdict == READY else "failure"', 'return "success" if verdict == READY else "neutral"', "F-3 a verdict published as neutral"),
    ("REP-B1", "gate/report.py", 'if merge.get("via_pr") is not True or not merge.get("approvals") or merge.get("final_conclusion") != "success":', "if False:", "B-1 bypass not flagged"),
    ("REP-CONTEXT", "gate/report.py", '**{field: context.get(field) for field in CONTEXT_FIELDS},', '**{field: context.get(field) for field in CONTEXT_FIELDS if field != "gate_sha"},', "the verification record lacks a SHA"),
    ("REP-RES", "gate/report.py", 'resources = {name: given.get(name, "unknown") for name in RESOURCES}', "resources = {name: given.get(name, 0) for name in RESOURCES}", "a cost not given reported as 0"),
    ("COMMON-C4", "gate/common.py", 'return _MENTION_RE.sub(lambda match: f"`{match.group(0)}`", value)', "return value", "C-4 a bare mention"),
    # archive
    ("ARC-W3", "gate/archive.py", 'return result(path=relative, reason="ALREADY_EXISTS", artifact_present=present, skipped_unsafe=skipped)', "pass", "W-3 an attempt overwritten"),
    ("ARC-actor", "gate/archive.py", '"actors_ok": not foreign,', '"actors_ok": True,', "W-12 reports written by another actor"),
    ("ARC-actor-append", "gate/archive.py", 'reason=None if matches else "READ_BACK_MISMATCH",\n        )\n        return check_actors(remote, outcome, load_accepted(args.config))\n    return result(path=target, reason="PUSH_REFUSED")', 'reason=None if matches else "READ_BACK_MISMATCH",\n        )\n        return outcome\n    return result(path=target, reason="PUSH_REFUSED")', "the actor check in append"),
    ("ARC-page-limit", "gate/archive.py", 'raise RemoteError("too many commits on the branch to check")', 'return foreign, found', "an unending list of commits reads as all clear"),
    ("ARC-accept-only-adds", "gate/archive.py", 'if sha in accepted and self._only_adds_records(sha):', 'if sha in accepted:', "W-14 a listed commit that changes a record"),
    ("REP-seal-symlink", "gate/report.py", 'if path.is_file() and not path.is_symlink() and path != artifact / "SHA256SUMS"', 'if path.is_file() and path != artifact / "SHA256SUMS"', "seal follows a symbolic link"),
    ("REP-V10", "gate/report.py", 'if steps.get("setup", {}).get("conclusion") == "failure":', "if False:", "V-10 a failed setup gives ready"),
    ("GUARD-V-author", "gate/guard.py", 'author_lower.endswith("[bot]")\n        or', 'False\n        or', "V: the executor on an innocent branch name"),
    ("GUARD-V-commits", "gate/guard.py", 'or bool(names & bot_names)\n', '\n', "V: a person's PR with the executor's commit"),
    ("GUARD-V-branch", "gate/guard.py", 'branch.lower().startswith(("ai/", "spec/"))', 'branch.startswith(("ai/", "spec/"))', "V: a branch name in another letter case"),
    ("GUARD-W-file", "gate/guard.py", '    "security-review.md",\n', '', "W: the executor edits the security review"),
    ("GUARD-W-names", "gate/guard.py", "return PurePosixPath(lowered).name in PROTECTED_NAMES_ANY_FOLDER", "return False", "W: pytest.ini and the tools' configs"),
    ("GUARD-W-conftest", "gate/guard.py", "if lowered == PROTECTED_ROOT_CONFTEST:", "if False:", "W: the root conftest.py"),
    ("GUARD-W-sections", "gate/guard.py", 'section = protected_section_changed(path, git.show(base, path), git.show(head, path))', 'section = None', "W: the test sections of pyproject.toml"),
    ("GUARD-U-marks", "gate/guard.py", "if not weakened and before.code != after.code:", "if False:", "U: a changed test is not marked"),
    ("GUARD-G4-return", "gate/guard.py", "if after.early_returns > before.early_returns:", "if False:", "G-4 an early return"),
    ("GUARD-G4-cases", "gate/guard.py", "if before.cases is not None and (after.cases is None or after.cases < before.cases):", "if False:", "G-4 fewer parametrized cases"),
    ("GUARD-G4-taut", "gate/guard.py", "return ast.dump(test.left) == ast.dump(test.comparators[0])", "return False", "G-4 a tautology"),
    ("GUARD-G6-comment", "gate/guard.py", 'bare = "\\n".join(_COMMENT.sub("", line) for line in text.split("\\n"))', "bare = text", "G-6 a commented-out threshold"),
    ("GUARD-G6-nocov", "gate/guard.py", 'if _NO_COV.search(_COMMENT.sub("", text)):', "if False:", "G-6 an added --no-cov"),
    ("GUARD-G9-merge", "gate/guard.py", "if previous != base and git.own_commits(previous, base, head) == 0:", "if False:", "G-9 a merge from the base as a repeat"),
    ("GUARD-G9-text", "gate/guard.py", '"--no-textconv", "--text")', '"--no-textconv")', "G-9 a .gitattributes hides a change"),
    ("RUN-R11", "gate/run_checks.py", "if missing:\n            failures.append", "if False:\n            failures.append", "R-11 a test of the base did not run"),
    ("ACC-A11", "gate/acceptance.py", "if missing_tests:", "if False:", "A-11 an acceptance test did not run"),
    ("ACC-A10", "gate/acceptance.py", 'config.get("acceptance", {}).get("require_empty") is True', "False", "A-10 the list on the final PR"),
    ("FB-D0", "gate/feedback.py", 'return isinstance(actors, dict) and actors.get("actors_ok") is True', "return True", "D-0 untrusted reports are read"),
    ("FB-D2a-fork", "gate/feedback.py", 'if not pull.get("head_repository") or pull.get("head_repository") != pull.get("repository"):', "if False:", "D-2a a fork"),
    ("FB-D2a-ai", "gate/feedback.py", 'if not str(pull.get("head_ref") or "").startswith("ai/"):', "if False:", "D-2a a spec or maintenance PR"),
    ("FB-cancelled", "gate/feedback.py", 'if run.get("conclusion") == "cancelled":', "if False:", "a cancelled run starts a model"),
    ("FB-verdict", "gate/feedback.py", 'if verdict != "blocked":', "if False:", "a lost run starts a model"),
    ("FB-record", "gate/feedback.py", "return matches[0] if len(matches) == 1 else None", "return matches[0] if matches else None", "a record in two PR folders"),
    ("REV-L1a", "gate/review_local.py", "    check_reports(api, repo)\n", "", "L-1a untrusted reports reach the model"),
    ("REV-L1-env", "gate/review_local.py", "return {name: os.environ[name] for name in MODEL_ENVIRONMENT if name in os.environ}", "return dict(os.environ)", "L-1 the whole environment reaches the model"),
    ("SEC-S5-spelling", "gate/security_check.py", 're.compile(r"#\\s*nosec\\b", re.IGNORECASE)', 're.compile(r"# nosec")', "S-5 another spelling of nosec"),
    ("ARC-actor-author", "gate/archive.py", "if author == EXPECTED_AUTHOR and verified is True:", "if verified is True:", "W-12 another author"),
    ("ARC-actor-signed", "gate/archive.py", "if author == EXPECTED_AUTHOR and verified is True:", "if author == EXPECTED_AUTHOR:", "W-12 an unsigned commit"),
    ("ARC-actor-unknown", "gate/archive.py", 'return {"actors_ok": False, "foreign_commits": [], "accepted_commits": [], "reason": UNCHECKED_ACTORS}', 'return {"actors_ok": True, "foreign_commits": [], "accepted_commits": [], "reason": None}', "W-12 authors unchecked"),
    ("ARC-signed-body", "gate/archive.py", '{"message": message, "tree": tree["sha"], "parents": [self.head] if self.head else []}', '{"message": message, "tree": tree["sha"], "parents": [self.head] if self.head else [], "author": {"name": "x", "email": "x@example.invalid"}}', "W-13 a custom author stops GitHub signing"),
    ("ARC-force", "gate/archive.py", '{"sha": commit["sha"], "force": False}', '{"sha": commit["sha"], "force": True}', "W-4 a force move"),
    ("ARC-github-remote", "gate/archive.py", 'if args.remote and "github.com" in args.remote.lower():', "if False:", "W-11 a git push to GitHub"),
    ("REP-F4", "gate/report.py", 'actors_ok = not isinstance(archive, dict) or archive.get("actors_ok") is not False', "actors_ok = True", "F-4 another actor still ready"),
    ("ARC-W6", "gate/archive.py", "return full.is_symlink() or any(part.lower() in UNSAFE_NAMES for part in relative.parts)", "return False", "W-6 unsafe files stored"),
    ("ARC-W7", "gate/archive.py", "if total > args.max_bytes:", "if False:", "W-7 too large"),
    ("ARC-W5", "gate/archive.py", 'if not name or name not in stored or sha256_bytes(stored[name]) != digest:', "if False:", "W-5 read-back skipped"),
    # feedback
    ("FB-D1", "gate/feedback.py", 'return outcome("SHA_NOT_CURRENT_HEAD", pr, head_sha)', "pull = {}", "D-1 not the head"),
    ("FB-D2", "gate/feedback.py", 'if pull.get("base_ref") != integration:', "if False:", "D-2 another base"),
    ("FB-D3", "gate/feedback.py", 'if done >= config.get("limits", {}).get("max_fix_rounds", 3):', "if False:", "D-3 round cap"),
    ("FB-D4", "gate/feedback.py", 'if any(record.get("head_sha") == head_sha and record.get("repeated_fix") is True for record in records):', "if False:", "D-4 repeated fix"),
    ("FB-sender", "gate/feedback.py", 'if sender.get("login") != expected:', "if False:", "R: the expected sender"),
    ("FB-marker", "gate/feedback.py", "if marker is None:", "if False:", "R: no marker"),
    ("FB-status", "gate/feedback.py", 'if status is None or status.get("state") != "failure":', "if False:", "R: the status is not a failure"),
    ("FB-creator", "gate/feedback.py", 'if creator.get("login") != expected:', "if False:", "R: the status came from another app"),
    ("FB-pr", "gate/feedback.py", 'if pull is None or (event_name == "issue_comment" and pull.get("number") != pr):', "if pull is None:", "R: the marker's SHA on another PR"),
    ("FB-silent", "gate/feedback.py", '"post": code not in SILENT,', '"post": True,', "R: the gate answers every comment"),
    ("FB-path", "gate/feedback.py", 'if run.get("path") != feedback.get("judge_workflow_path") or run.get("event") != "pull_request_target":', "if False:", "the expected workflow"),
    ("FB-mention", "gate/common.py", 'MENTION = "`@claude`"', 'MENTION = "@claude"', "C-5 a bare mention of the executor"),
    # review_local
    ("REV-R-marker", "gate/review_local.py", 'f"<!-- gate-review sha={sha} verdict={answer[\'verdict\']} -->",', '"",', "R: no marker in the comment"),
    ("REV-L3", "gate/review_local.py", 'VERDICTS = {"pass": "success", "changes_requested": "failure"}', 'VERDICTS = {"pass": "success", "changes_requested": "success"}', "L-3 changes requested posted as success"),
    ("REV-L5", "gate/review_local.py", 'if not isinstance(answer, dict) or answer.get("verdict") not in VERDICTS:', "if False:", "L-5 invalid output"),
    ("REV-L6", "gate/review_local.py", 'raise Stop("MISSING_INPUT")\n\n\ndef check_reports', 'return "{}"\n\n\ndef check_reports', "L-6 no judge's report"),
    # concurrency_harness
    ("HAR-H1", "gate/concurrency_harness.py", "if code != 0:", "if False:", "H-1 a failed copy"),
    ("HAR-H2", "gate/concurrency_harness.py", 'failures.append({"round": round_number, "worker": worker, "exit_code": None, "reason": "timeout"})', "pass", "H-2 a hang passes"),
    ("HAR-H4", "gate/concurrency_harness.py", "if errors:", "if False:", "H-4 an exception passes"),
    # security_check
    ("SEC-S3", "gate/security_check.py", 'if any(not finding["reviewed"] for finding in findings):', "if False:", "S-3 unreviewed finding"),
    ("SEC-S4", "gate/security_check.py", "if missing:", "if False:", "S-4 tool output missing"),
    ("SEC-S5", "gate/security_check.py", 'if any(not item["has_entry"] for item in suppressions):', "if False:", "S-5 suppression without an entry"),
    ("SEC-S2", "gate/security_check.py", 'if cells[columns["reason"]]:', "if True:", "S-2 a blank reason counts"),
]


def copy_tree(target: Path) -> None:
    shutil.copytree(ROOT, target, ignore=lambda _folder, names: [name for name in names if name in SKIP])


def run_mutant(mutant: tuple[str, str, str, str, str], base: Path) -> dict:
    mutant_id, relative, old, new, rule = mutant
    tree = base / mutant_id
    copy_tree(tree)
    selection = TESTS_FOR[mutant_id.split("-", 1)[0]]
    target = tree / relative
    source = target.read_text(encoding="utf-8")
    if source.count(old) < 1:
        shutil.rmtree(tree, ignore_errors=True)
        return {"id": mutant_id, "rule": rule, "outcome": "not-applied", "detail": "the text was not found"}
    target.write_text(source.replace(old, new, 1), encoding="utf-8", newline="\n")
    started = time.monotonic()
    env = {**os.environ, "GATE_ROOT": str(tree), "PYTHONPATH": str(tree)}
    process = subprocess.run(
        [sys.executable, "-m", "pytest", *selection, "-x", "-q", "--no-header", "--basetemp", str(base / f"{mutant_id}-t")],
        cwd=tree,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    killer = next((line for line in process.stdout.splitlines() if line.startswith(("FAILED", "ERROR"))), "")
    shutil.rmtree(tree, ignore_errors=True)
    shutil.rmtree(base / f"{mutant_id}-t", ignore_errors=True)
    return {
        "id": mutant_id,
        "rule": rule,
        "outcome": "killed" if process.returncode == 1 else ("survived" if process.returncode == 0 else f"pytest-exit-{process.returncode}"),
        "killed_by": killer.split(" - ")[0],
        "seconds": round(time.monotonic() - started, 1),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", default="", help="only mutants whose ID starts with this")
    parser.add_argument("--jobs", type=int, default=6, help="mutants run at once, each in its own copy")
    parser.add_argument("--ids", default="", help="only these mutants, by ID, separated by commas")
    args = parser.parse_args()

    wanted = set(filter(None, args.ids.split(",")))
    selected = [mutant for mutant in MUTANTS if mutant[0].startswith(args.only) and (not wanted or mutant[0] in wanted)]
    results = []
    with tempfile.TemporaryDirectory(prefix="gate-mut-", ignore_cleanup_errors=True) as tmp:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for result in pool.map(lambda mutant: run_mutant(mutant, Path(tmp)), selected):
                results.append(result)
                print(f"{result['id']}: {result['outcome']} {result.get('killed_by', '')}", flush=True)
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    bad = [result["id"] for result in results if result["outcome"] != "killed"]
    print(f"{len(results) - len(bad)} of {len(results)} killed; not killed: {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
