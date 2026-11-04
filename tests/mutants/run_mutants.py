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
REAL = "tests/unit/test_unit_real_pytest.py"
ROUND3 = "tests/unit/test_unit_repairs_round3.py"
ROUND4 = "tests/unit/test_unit_repairs_round4.py"
ROUND5 = "tests/unit/test_unit_repairs_round5.py"
TESTS_FOR = {
    "GUARD": ["tests/spec/test_guard.py", "tests/spec/test_guard_v.py", "tests/spec/test_guard_r4.py", ROUND5, ROUND4, ROUND3, REAL, UNIT, E2E],
    "COL": [REAL, "tests/spec/test_run_checks_base.py", "tests/spec/test_acceptance.py"],
    "PUB": [UNIT, ROUND3, "tests/spec/test_publish_r4.py", "tests/spec/test_reproduce.py"],
    "WF": ["tests/unit/test_unit_workflows.py", "tests/spec/test_workflows.py"],
    "REPRO": [ROUND5, "tests/spec/test_reproduce_x0.py", E2E, ROUND3],
    "ENV": ["tests/spec/test_env_check.py", UNIT],
    "RUN": ["tests/spec/test_run_checks.py", "tests/spec/test_run_checks_base.py", "tests/spec/test_common.py", REAL, UNIT],
    "ACC": ["tests/spec/test_acceptance.py", REAL, UNIT],
    "REP": ["tests/spec/test_report_generate.py", "tests/spec/test_report_final_compare.py", "tests/spec/test_report_seal.py", "tests/unit/test_unit_archive_api.py", UNIT, E2E],
    "COMMON": ["tests/spec/test_report_generate.py", "tests/spec/test_common.py"],
    "ARC": ["tests/spec/test_archive.py", "tests/spec/test_archive_api.py", "tests/unit/test_unit_archive_api.py", ROUND3],
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
    ("GUARD-no-ext-diff", "gate/guard.py", '"--no-ext-diff", "--no-textconv", "--text",', '"--no-textconv", "--text",', "the guard starts an external diff"),
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
    ("REP-B1", "gate/report.py", 'merge.get("via_pr") is not True\n            or not merge.get("approvals")', 'not merge.get("approvals")', "B-1 a direct push not flagged"),
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
    ("GUARD-W-conftest", "gate/guard.py", "if lowered == PROTECTED_ROOT_CONFTEST or is_protected", "if is_protected", "W: the root conftest.py"),
    ("GUARD-W-sections", "gate/guard.py", "refusal, mark = section_change(path, git.show(base, path), git.show(head, path))", "refusal, mark = None, False", "W: the test sections of pyproject.toml"),
    ("GUARD-U-marks", "gate/guard.py", "if not weakened and before.code != after.code:", "if False:", "U: a changed test is not marked"),
    ("GUARD-G4-return", "gate/guard.py", "if after.early_returns > before.early_returns:", "if False:", "G-4 an early return"),
    ("GUARD-G4-cases", "gate/guard.py", "if before.cases is not None and (after.cases is None or after.cases < before.cases):", "if False:", "G-4 fewer parametrized cases"),
    ("GUARD-G4-taut", "gate/guard.py", "return ast.dump(test.left) == ast.dump(test.comparators[0])", "return False", "G-4 a tautology"),
    ("GUARD-G6-comment", "gate/guard.py", 'bare = "\\n".join(_COMMENT.sub("", line) for line in text.split("\\n"))', "bare = text", "G-6 a commented-out threshold"),
    ("GUARD-G6-nocov", "gate/guard.py", 'if _NO_COV.search(_COMMENT.sub("", text)):', "if False:", "G-6 an added --no-cov"),
    ("GUARD-G9-merge", "gate/guard.py", "if previous != base and git.own_commits(previous, base, head) == 0:", "if False:", "G-9 a merge from the base as a repeat"),
    ("GUARD-G9-text", "gate/guard.py", '"--no-textconv", "--text",', '"--no-textconv",', "G-9 a .gitattributes hides a change"),
    ("RUN-R11", "gate/run_checks.py", "if missing:\n            failures.append", "if False:\n            failures.append", "R-11 a test of the base did not run"),
    ("ACC-A11", "gate/acceptance.py", "if missing_tests:", "if False:", "A-11 an acceptance test did not run"),
    ("ACC-A10", "gate/acceptance.py", 'config.get("acceptance", {}).get("require_empty") is True', "False", "A-10 the list on the final PR"),
    ("FB-D0", "gate/feedback.py", 'return isinstance(actors, dict) and actors.get("actors_ok") is True', "return True", "D-0 untrusted reports are read"),
    ("FB-D2a-fork", "gate/feedback.py", 'if not pull.get("head_repository") or pull.get("head_repository") != pull.get("repository"):', "if False:", "D-2a a fork"),
    ("FB-D2a-ai", "gate/feedback.py", 'if not str(pull.get("head_ref") or "").startswith("ai/"):', "if False:", "D-2a a spec or maintenance PR"),
    ("FB-cancelled", "gate/feedback.py", 'if run.get("conclusion") == "cancelled":', "if False:", "a cancelled run starts a model"),
    ("FB-verdict", "gate/feedback.py", 'if verdict != "blocked":', "if False:", "a lost run starts a model"),
    ("FB-record", "gate/feedback.py", "return matches[0] if len(matches) == 1 else None", "return matches[0] if matches else None", "a record in two PR folders"),
    # Decision X: review round 2.
    ("GUARD-X-toml", "gate/guard.py", '    "pytest.toml",\n', "", "F2 pytest.toml"),
    ("GUARD-X-dot-toml", "gate/guard.py", '    ".pytest.toml",\n', "", "F2 .pytest.toml"),
    ("GUARD-X-any-folder", "gate/guard.py", 'watched = PROTECTED_TOOLS_IN_ROOT if is_root else ("pytest",)', "watched = PROTECTED_TOOLS_IN_ROOT if is_root else ()", "F2 pytest's section in a subfolder"),
    ("GUARD-X-shadow", "gate/guard.py", "or is_protected(lowered, list(PROTECTED_ROOT_SHADOWS))", "", "F2 a module standing in for pytest"),
    ("GUARD-X-plugin", "gate/guard.py", "if plugins[0] != plugins[1]:", "if False:", "F2 a plugin entry point"),
    # Review round 3.
    ("GUARD-R3-mention", "gate/guard.py", 'if "pytest" in (base_text or "").lower() or "pytest" in (head_text or "").lower():', "if False:", "H1 a file pytest reads differently"),
    ("GUARD-R3-spec-delete", "gate/guard.py", "            elif is_test_file(path):\n                check_tests(git, base, head, status, path, result)\n", "", "H3 a spec PR takes a test away"),
    ("GUARD-R3-named", "gate/guard.py", "hit = [key for key in changed if key.lower() in watched]", "hit = changed", "M1 an ordinary section refused"),
    ("GUARD-R3-sub-ini", "gate/guard.py", "    if not is_root:\n        return None, False\n", "", "M1 an ordinary subfolder file refused"),
    ("GUARD-R3-mark", "gate/guard.py", "            elif mark:\n                result.needs_code_owner.append(path)\n", "", "M1 another tool's section not marked"),
    ("GUARD-R3-table", "gate/guard.py", "    return value if isinstance(value, dict) else {}\n", "    return value\n", "a traceback on an odd pyproject.toml"),
    ("PUB-R3-link", "gate/publish.py", "if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:", "if False:", "H2 a link or a second name is followed"),
    ("PUB-R3-value", "gate/publish.py", "return any(value and value in text for value in values) or SECRET_PATTERN.search(text) is not None", "return SECRET_PATTERN.search(text) is not None", "H2 a token's value is posted"),
    ("PUB-R3-pattern", "gate/publish.py", "return any(value and value in text for value in values) or SECRET_PATTERN.search(text) is not None", "return any(value and value in text for value in values)", "H2 a token's shape is posted"),
    ("REPRO-R3-host", "gate/reproduce.py", 'if (parts.hostname or "").lower() not in ("github.com", "www.github.com"):', 'if parts.scheme != "https" or parts.hostname != "github.com":', "M2 a GitHub URL taken for another remote"),
    ("REPRO-R3-scp", "gate/reproduce.py", "    if scp_form:\n        path = scp_form.group(1)\n    else:\n", "    if True:\n", "M2 the git@ form"),
    ("REPRO-R3-tip", "gate/reproduce.py", "if tip not in remote.listed:", "if False:", "X-0 another history than git read"),
    # Review round 5, and what round 4's repairs became.
    ("GUARD-R5-link", "gate/guard.py", 'if fields[index].split(" ")[1] in NOT_PLAIN_MODES:', "if False:", "R4-H1 a link is read by its target's name"),
    ("GUARD-R5-hidden-submodule", "gate/guard.py", ', "--ignore-submodules=none")', ")", "R5-M2 a submodule hidden by .gitmodules"),
    ("GUARD-R5-encoding", "gate/guard.py", "if declares_other_encoding(head_text):", "if False:", "R5-H2 another encoding"),
    ("GUARD-R5-encoding-unknown", "gate/guard.py", "    except (SyntaxError, LookupError):\n        return True\n", "    except (SyntaxError, LookupError):\n        return False\n", "R5-H2 an encoding Python does not know"),
    ("GUARD-R5-encoding-newline", "gate/guard.py", 'lines = _with_newlines_as_pytest_reads_them(text).encode("utf-8", "replace")', 'lines = text.encode("utf-8", "replace")', "R5-H2 a cookie after a lone CR"),
    ("GUARD-R5-not-source", "gate/guard.py", "if is_not_source(path):", "if False:", "R5-H4 and R5-H6 no source to read"),
    ("GUARD-R5-bytecode", "gate/guard.py", 'NOT_SOURCE_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd")', 'NOT_SOURCE_SUFFIXES = (".pyo", ".so", ".pyd")', "R5-H6 a bytecode file"),
    ("GUARD-R5-pycache", "gate/guard.py", 'part == "__pycache__" or ', "", "R5-H6 anything under __pycache__"),
    ("GUARD-R5-metadata", "gate/guard.py", 'NOT_SOURCE_FOLDER_SUFFIXES = (".dist-info", ".egg-info", ".egg")', 'NOT_SOURCE_FOLDER_SUFFIXES = (".egg-info", ".egg")', "R5-H4 a dist-info folder"),
    ("GUARD-R5-egg-info", "gate/guard.py", 'NOT_SOURCE_FOLDER_SUFFIXES = (".dist-info", ".egg-info", ".egg")', 'NOT_SOURCE_FOLDER_SUFFIXES = (".dist-info", ".egg")', "R5-H4 an egg-info folder"),
    ("GUARD-R5-plugins", "gate/guard.py", "if plugin_line_added(path, git.show(base, path), head_text):", "if False:", "R5-H3 pytest_plugins"),
    ("GUARD-R5-plugins-star", "gate/guard.py", '        watched.append("*")\n', "        pass\n", "R5-H3 a star import in a new test file"),
    ("GUARD-R5-root-shadow", "gate/guard.py", "for name in new_root_shadows(git, base, head, head_files):", "for name in []:", "R5-H6 a new top-level name"),
    ("GUARD-R5-root-known", "gate/guard.py", "        if parts[0] in known:\n            continue\n", "", "G-1g a name the base has is refused"),
    ("GUARD-R5-root-package", "gate/guard.py", 'elif len(parts) == 2 and parts[1] == "__init__.py" and parts[0] in tools:', "elif False:", "R5-H6 a new top-level package"),
    ("GUARD-R5-stand-in", "gate/guard.py", 'if status == "A" and stands_in_for_a_module(path, test_folders, names):', "if False:", "R5-H3 a module under tests stands in"),
    ("GUARD-R5-stand-in-new", "gate/guard.py", 'if status == "A" and stands_in_for_a_module(path, test_folders, names):', "if stands_in_for_a_module(path, test_folders, names):", "G-1h a shadow the base has is refused"),
    ("GUARD-R5-src-layout", "gate/guard.py", 'parts = parts[1:] if parts[0] == "src" else parts', "parts = parts", "R5-H3 a src layout's module"),
    ("GUARD-R5-star", "gate/guard.py", 'if bound_name == "*" or bound_name in scopes:', "if bound_name in scopes:", "R5-H1 a star import"),
    ("GUARD-R5-global", "gate/guard.py", "if isinstance(inner, ast.Global):", "if False:", "R5-H1 a global"),
    ("GUARD-R5-match", "gate/guard.py", "(ast.ExceptHandler, ast.MatchAs, ast.MatchStar)", "(ast.ExceptHandler, ast.MatchStar)", "R5-H1 a match pattern"),
    ("GUARD-R5-swap", "gate/guard.py", "bound[(prefix + name, ast.dump(statement))] += 1", 'bound[(prefix + name, "")] += 1', "R5-H1 a binding replaced"),
    ("GUARD-R5-comprehension", "gate/guard.py", "if isinstance(inner, ast.NamedExpr):", "if False:", "R5-H1 a := in a comprehension"),
    ("GUARD-R5-outside", "gate/guard.py", "            for part in outside:\n                visit(part, prefix, statement)\n", "", "R5-H1 a default or a decorator"),
    ("GUARD-R5-lambda", "gate/guard.py", "        elif isinstance(node, ast.Lambda):\n            visit(node.args, prefix, statement)\n", "        elif isinstance(node, ast.Lambda):\n            pass\n", "R5-H1 a lambda's default"),
    ("GUARD-R5-attribute-in-class", "gate/guard.py", '                    bound[(prefix + dotted, f"attribute: {ast.dump(statement)}")] += 1\n', "", "R5-H1 an attribute set in the test's own class"),
    ("GUARD-R5-attribute-chain", "gate/guard.py", 'if how.startswith("attribute:") and bound_name.startswith(f"{name}."):', "if False:", "R5-H1 test.__code__ set"),
    ("GUARD-R5-bom", "gate/guard.py", 'return ast.parse(source.removeprefix("\\ufeff"))', "return ast.parse(source)", "R5-M4 a byte-order mark"),
    ("COL-R5-bom", "gate/collected.py", 'tree = ast.parse(source.removeprefix("\\ufeff"))', "tree = ast.parse(source)", "R5-M4 a byte-order mark"),
    ("RUN-R5-junit-failed", "gate/run_checks.py", 'if counts["failures"] + counts["errors"] > 0:', "if False:", "R5-H7 pytest.exit with code 0"),
    ("RUN-R5-junit-errors", "gate/run_checks.py", 'if counts["failures"] + counts["errors"] > 0:', 'if counts["failures"] > 0:', "R-12 errors in the file"),
    ("REPRO-R5-secret", "gate/reproduce.py", "    refuse_secrets(args.repo)\n", "", "R5-H5 a rerun with a secret"),
    ("REPRO-R5-empty", "gate/reproduce.py", "if value and any(part in name.upper()", "if any(part in name.upper()", "X-0b an empty variable"),
    ("REPRO-R5-credential", "gate/reproduce.py", "    if holds_a_credential(repo):\n", "    if False:\n", "X-0a a credential in the URL"),
    ("REPRO-R5-ssh-user", "gate/reproduce.py", 'parts.scheme.lower() != "ssh"', "True", "X-0a ssh://git@ refused"),
    ("REPRO-R5-scp", "gate/reproduce.py", r'r"(?:[^@/:\s]+@)?(?:www\.)?github\.com:(.+)"', r'r"(?:[^@/\s]+@)?(?:www\.)?github\.com:(.+)"', "a look-alike taken for GitHub"),
    # Review round 4.
    ("GUARD-R4-submodule", "gate/guard.py", 'NOT_PLAIN_MODES = ("120000", "160000")', 'NOT_PLAIN_MODES = ("120000",)', "R4-H1 a submodule passes"),
    ("GUARD-R4-attributes", "gate/guard.py", '    ".gitattributes",\n', "", "R4-H2 the checkout differs from the blob"),
    ("GUARD-R4-newlines", "gate/guard.py", 'return (text or "").replace("\\r\\n", "\\n").replace("\\r", "\\n")', 'return text or ""', "R4-H5 a lone CR splits the guard from pytest"),
    ("GUARD-R4-plugin-any", "gate/guard.py", 'plugins = [_values_named(doc, "pytest11") for doc in (before_doc, after_doc)]', 'plugins = [_as_table(_as_table(doc.get("project")).get("entry-points")).get("pytest11") for doc in (before_doc, after_doc)]', "R4-M3 another tool's plugin table"),
    ("GUARD-R4-dynamic", "gate/guard.py", 'if dynamic[0] != dynamic[1] and "entry-points" in f"{dynamic[0]}{dynamic[1]}":', "if False:", "R4-M3 entry points declared dynamic"),
    ("GUARD-R4-spec-conftest", "gate/guard.py", "if PurePosixPath(path.lower()).name == PROTECTED_ROOT_CONFTEST:\n        return \"a spec PR", "if False:\n        return \"a spec PR", "R4-H3 a conftest.py in a spec PR"),
    ("GUARD-R4-spec-names", "gate/guard.py", 'if is_protected_control_file(path):\n        return "a spec PR may not', 'if False:\n        return "a spec PR may not', "R4-H3 pytest.ini under acceptance/ in a spec PR"),
    ("GUARD-R4-spec-sections", "gate/guard.py", "return section_change(path, git.show(base, path), git.show(head, path))[0]", "return None", "R4-H3 a section under acceptance/ in a spec PR"),
    ("GUARD-X-review", "gate/guard.py", "result.security_review_changes = security_review_changes(git, base, head)", "pass", "F8 a change to the security review"),
    ("GUARD-X-parse", "gate/guard.py", 'result.add("TEST_WEAKENED", path, "the changed test file cannot be parsed")', "pass", "an unparsable test file"),
    ("RUN-X-acceptance", "gate/run_checks.py", 'ignore = ["acceptance/", *check.get("expected_tests_ignore", [])]', 'ignore = [*check.get("expected_tests_ignore", [])]', "F1 acceptance tests expected of gate/tests"),
    ("RUN-X-ignore", "gate/run_checks.py", 'ignore = ["acceptance/", *check.get("expected_tests_ignore", [])]', 'ignore = ["acceptance/"]', "F3 the trusted ignore list"),
    ("RUN-X-root", "gate/run_checks.py", 'root = str(check.get("expected_tests_root", "")).strip("/")', 'root = ""', "F3 a moved root"),
    ("COL-fixture", "gate/collected.py", " and not _is_fixture(node):", ":", "F3 a fixture named test_"),
    ("COL-init", "gate/collected.py", 'return not any(isinstance(item, _FUNCTIONS) and item.name == "__init__" for item in node.body)', "return True", "F3 a class with __init__"),
    ("COL-class-off", "gate/collected.py", "    if _sets_test_false(node.body):\n        return False\n", "", "F3 __test__ = False on a class"),
    ("COL-module-off", "gate/collected.py", "    if _sets_test_false(tree.body):\n        return found\n", "", "F3 __test__ = False on a module"),
    ("COL-function-off", "gate/collected.py", " and node.name not in turned_off", "", "F3 __test__ = False on a function"),
    ("COL-helper-class", "gate/collected.py", '    if not node.name.startswith("Test"):\n        return False\n', "", "F3 a class pytest does not collect"),
    ("FB-note-record", "gate/feedback.py", "return None, pr, head_sha, [*failures, *details_of_the_record(record)]", "return None, pr, head_sha, failures", "F4 the note says what is wrong"),
    ("FB-note-comment", "gate/feedback.py", '*findings_of_the_comment(str(comment.get("body") or ""))', "", "F4 the note holds the review's findings"),
    ("REP-X-untrusted", "gate/report.py", 'if extras.get("reports_untrusted") is True:', "if False:", "V-11 untrusted reports"),
    ("REP-X-review-flag", "gate/report.py", '            or merge.get("security_review_changed") is True\n', "", "F8 a green merge changing the review"),
    ("REP-X-review-list", "gate/report.py", '"security_review_changes": security_changes if isinstance(security_changes, list) else [],', '"security_review_changes": [],', "F8 the changes in the report"),
    ("REPRO-check", "gate/reproduce.py", 'check_stored_evidence(args.api_repo or github_repository(args.repo), default_tree / "quality.toml", tip)', "pass", "F7 reproduce reads unchecked"),
    ("REPRO-review", "gate/reproduce.py", "    review.unlink(missing_ok=True)\n", "", "reproduce keeps the PR's own review"),
    ("REPRO-pull-ref", "gate/reproduce.py", 'f"refs/pull/{context[\'pr\']}/head"', '"refs/heads/no-such-branch"', "reproduce loses a closed PR's head"),
    ("ARC-X-append-list", "gate/archive.py", 'return check_actors(remote, outcome, load_accepted(args.config))\n    return result(path=target, reason="PUSH_REFUSED")', 'return check_actors(remote, outcome, {})\n    return result(path=target, reason="PUSH_REFUSED")', "append ignores the recovery list"),
    ("ARC-X-file-pages", "gate/archive.py", "            if len(files) < 100:\n                return True\n        return False", "            return True\n        return False", "W-14 only the first page of a commit's files"),
    # gate/publish.py, in its own group.
    ("PUB-branch", "gate/publish.py", 'if not branch.startswith(args.prefix) or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):', "if False:", "F9 a branch outside the prefix"),
    ("PUB-not-pushed", "gate/publish.py", 'print(f"the model did not push {branch}", file=sys.stderr)\n        return EXIT_RULE_FAILED', "pass", "F9 a branch not pushed"),
    ("PUB-once", "gate/publish.py", 'if call("GET", f"/repos/{repository}/pulls?state=open&head={head}"):', "if False:", "a second PR for one branch"),
    ("PUB-delimiter", "gate/publish.py", 'delimiter = f"GATE_PROMPT_{secrets.token_hex(16)}"', 'delimiter = "GATE_PROMPT_FIXED_AND_LONG_ENOUGH_TO_LOOK_RANDOM"', "a fixed delimiter"),
    ("PUB-head-state", "gate/publish.py", 'if pull.get("state") != "open" or pull.get("head", {}).get("sha") != args.sha:', "if False:", "head-check passes all"),
    ("PUB-rounds", "gate/publish.py", 'for path in sorted((reports_dir / str(pr)).glob("*/context.json")):', 'for path in sorted((reports_dir / str(pr)).glob("*/guard.json")):', "rounds from guard records only"),
    ("PUB-review", "gate/publish.py", '    head = context.get("head_sha")\n    if head:\n        try:', '    head = None\n    if head:\n        try:', "the review status not read"),
    ("PUB-refused", "gate/publish.py", "        except (urllib.error.URLError, OSError, ValueError):\n            statuses = None", "        except ZeroDivisionError:\n            statuses = None", "F10 a refused read stops the report"),
    ("PUB-author", "gate/publish.py", 'context["author"] = os.environ["GATE_PR_AUTHOR"]', "pass", "the context lacks the author"),
    ("PUB-untrusted", "gate/publish.py", '"reports_untrusted": not trusted,', '"reports_untrusted": False,', "F7 untrusted reports not said"),
    ("PUB-rounds-read", "gate/publish.py", "stored_rounds(Path(args.reports_dir), args.pr) if trusted else []", "stored_rounds(Path(args.reports_dir), args.pr)", "F7 untrusted reports read"),
    ("PUB-direct", "gate/publish.py", "if sha not in covered:", "if False:", "a direct push not flagged"),
    ("PUB-review-file", "gate/publish.py", 'changed_review = any(str(item.get("filename", "")).lower() == "security-review.md" for item in files)', "changed_review = False", "F8 a merge changing the review"),
    ("PUB-owner", "gate/publish.py", 'if comment.get("author_association") != "OWNER":', "if False:", "anyone's /time comment counts"),
    ("PUB-proposal", "gate/publish.py", "text = neutralize(raw)[:MAX_PROPOSAL]", "text = raw[:MAX_PROPOSAL]", "a proposal posted with bare mentions"),
    ("PUB-hide", "gate/publish.py", "    if not deny:\n", "    if False:\n", "an empty deny list passes"),
    # The workflows' own wiring.
    ("WF-config-store", ".github/workflows/judge.yml", '--context context.json --config "$GATE_CONFIG" --out archive-result.json', "--context context.json --out archive-result.json", "--config dropped from the store"),
    ("WF-config-append", ".github/workflows/judge.yml", '--file final/final.json --config "$GATE_CONFIG" --out append-result.json', "--file final/final.json --out append-result.json", "--config dropped from the append"),
    ("WF-review-copy", ".github/workflows/judge.yml", 'if [ -f .trusted/security-review.md ]; then cp .trusted/security-review.md "$GATE_PR_DIR/security-review.md"; fi', "true", "security-review.md never copied"),
    ("WF-review-remove", ".github/workflows/judge.yml", 'rm -f "$GATE_PR_DIR/security-review.md"', "true", "the PR's own security review stays"),
    ("WF-head-off", ".github/workflows/executor.yml", "if: ${{ inputs.expected-head != '' }}", "if: ${{ false }}", "the head check turned off"),
    ("WF-head-swallowed", ".github/workflows/executor.yml", '--sha "$GATE_EXPECTED_HEAD"', '--sha "$GATE_EXPECTED_HEAD" || true', "the head check swallowed"),
    ("WF-trusted-move", ".github/workflows/executor.yml", 'mv .trusted "$RUNNER_TEMP/trusted"', "true", "the prompt left for the wiping checkout"),
    ("WF-spec-copy", ".github/workflows/spec-tests.yml", 'run: rm -rf "$RUNNER_TEMP/trusted"', "run: 'true'", "F5 the code beside the spec-test author"),
    ("WF-run-actors", ".github/workflows/judge.yml", '"$GATE_PY" -P -m gate.archive check-actors --api-repo "$GATE_REPOSITORY" --branch reports --config "$GATE_CONFIG" --out "$GATE_OUT/actors.json"', "true", "F7 the guard reads unchecked"),
    ("WF-publish-actors", ".github/workflows/judge.yml", "--env-result publish-env.json --actors actors.json --context", "--env-result publish-env.json --actors no-such-file --context", "F7 extras not given the check"),
    ("WF-branch", ".github/workflows/executor.yml", '--branch "$(git branch --show-current)" --prefix', '--branch "ai/x" --prefix', "F9 a branch not from the working tree"),
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
