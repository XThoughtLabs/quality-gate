"""Judge a PR's change against the rules of design section 6, from git objects only.

This script never runs code from the repository it reads.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from gate.acceptance import parse_list
from gate.common import EXIT_OK, EXIT_RULE_FAILED, UsageError, fail_usage, load_config, write_json

FIXED_PROTECTED = (
    ".github/",
    "acceptance/",
    "quality.toml",
    "CODEOWNERS",
    "SPEC.md",
    "TASK.md",
    "BASELINE.md",
    "OPEN-ISSUES.md",
    "SOURCE-MANIFEST.json",
    "evidence/",
)
FIXED_THRESHOLD_KEYS = ("fail_under", "fail-under", "cov-fail-under")
KNOWN_FAILING_PATH = "acceptance/known-failing.txt"

# A repository's own settings must never start a command from here.
_SAFE_DIFF = ("--no-renames", "--no-color", "--no-ext-diff", "--no-textconv")
_SKIP_DECORATORS = (
    "pytest.mark.skip",
    "pytest.mark.skipif",
    "pytest.mark.xfail",
    "unittest.skip",
    "unittest.skipIf",
    "unittest.skipUnless",
    "unittest.expectedFailure",
)
_SKIP_CALLS = ("pytest.skip", "pytest.xfail")
_SUPPRESSIONS = ("# noqa", "type: ignore", "pytest.skip(")
_REASON = re.compile(r"#\s*reason:\s*\S")
_USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)""")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:==\s*([^\s;]+))?")


@dataclass
class Result:
    kind: str
    head_sha: str
    violations: list[dict] = field(default_factory=list)
    needs_code_owner: list[str] = field(default_factory=list)
    dependency_changes: list[dict] = field(default_factory=list)
    fingerprint: dict = field(default_factory=dict)
    repeated_fix: bool = False

    def add(self, rule: str, path: str, detail: str) -> None:
        self.violations.append({"rule": rule, "path": path, "detail": detail})


class Git:
    """Read-only access to one repository's objects."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def run(self, *args: str) -> bytes:
        process = subprocess.run(
            ["git", "-C", self.repo, "-c", "core.quotepath=off", "-c", "core.fsmonitor=false", *args],
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            raise UsageError(f"git {args[0]} failed: {process.stderr.decode('utf-8', 'replace').strip()[:300]}")
        return process.stdout

    def show(self, rev: str, path: str) -> str | None:
        process = subprocess.run(
            ["git", "-C", self.repo, "-c", "core.fsmonitor=false", "show", "--no-textconv", f"{rev}:{path}"],
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            return None
        return process.stdout.decode("utf-8", "replace")

    def exists(self, rev: str) -> bool:
        process = subprocess.run(
            ["git", "-C", self.repo, "cat-file", "-e", f"{rev}^{{commit}}"], capture_output=True, check=False
        )
        return process.returncode == 0

    def changes(self, start: str, end: str) -> list[tuple[str, str]]:
        raw = self.run("diff", *_SAFE_DIFF, "--name-status", "-z", start, end)
        fields = raw.decode("utf-8", "replace").split("\0")
        return [(fields[i], fields[i + 1]) for i in range(0, len(fields) - 1, 2)]

    def added_lines(self, start: str, end: str, path: str) -> list[tuple[int, str]]:
        raw = self.run("diff", *_SAFE_DIFF, "-U0", start, end, "--", path)
        added = []
        number = 0
        for line in raw.decode("utf-8", "replace").splitlines():
            hunk = _HUNK.match(line)
            if hunk:
                number = int(hunk.group(1))
            elif line.startswith("+") and not line.startswith("+++"):
                added.append((number, line[1:]))
                number += 1
        return added

    def fingerprint(self, start: str, end: str) -> str:
        raw = self.run("diff", *_SAFE_DIFF, start, end)
        return normalized_fingerprint(raw.decode("utf-8", "replace"))


def normalized_fingerprint(diff: str) -> str:
    """SHA-256 of a diff with its line numbers, blob hashes and line endings removed."""
    sections: list[list[str]] = []
    for line in diff.split("\n"):
        text = line.rstrip()
        if text.startswith("diff --git "):
            sections.append([text])
        elif not sections:
            continue
        elif text.startswith("index "):
            continue
        elif text.startswith("@@"):
            sections[-1].append("@@")
        else:
            sections[-1].append(text)
    sections.sort(key=lambda section: section[0])
    normalized = "\n".join("\n".join(section) for section in sections)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def branch_kind(branch: str) -> str:
    if branch.startswith("ai/"):
        return "ai"
    if branch.startswith("spec/"):
        return "spec"
    return "other"


def is_protected(path: str, protected: list[str]) -> bool:
    lowered = path.lower()
    for entry in protected:
        target = entry.lower().rstrip("/")
        if lowered == target or lowered.startswith(target + "/"):
            return True
    return False


def is_test_file(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return False
    return (
        pure.name.startswith("test_")
        or pure.name.endswith("_test.py")
        or "tests" in pure.parts[:-1]
    )


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _decorator_name(node: ast.AST) -> str:
    return _dotted(node.func if isinstance(node, ast.Call) else node)


@dataclass
class TestFacts:
    checks: int
    skips: int
    always_true: int
    broad_raises: int
    first_line: int
    last_line: int


def _facts_of(function: ast.AST, inherited_skips: int) -> TestFacts:
    checks = skips = always_true = broad_raises = 0
    for decorator in function.decorator_list:
        if _decorator_name(decorator) in _SKIP_DECORATORS:
            skips += 1
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            checks += 1
            if isinstance(node.test, ast.Constant) and bool(node.test.value):
                always_true += 1
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name == "pytest.raises":
                checks += 1
                if node.args and _dotted(node.args[0]) in ("Exception", "BaseException"):
                    broad_raises += 1
            elif name.startswith("self.assert"):
                checks += 1
            elif name in _SKIP_CALLS:
                skips += 1
    return TestFacts(checks, skips + inherited_skips, always_true, broad_raises, function.lineno, function.end_lineno)


def collect_tests(source: str) -> dict[str, TestFacts]:
    """Map each test function, by qualified name, to what it checks. Raises SyntaxError."""
    tree = ast.parse(source)
    module_skips = 0
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets
        ):
            values = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            module_skips += sum(_decorator_name(value) in _SKIP_DECORATORS for value in values)

    tests: dict[str, TestFacts] = {}
    function_types = (ast.FunctionDef, ast.AsyncFunctionDef)

    def visit(body: list[ast.stmt], prefix: str, inherited: int) -> None:
        for node in body:
            if isinstance(node, function_types) and node.name.startswith("test_"):
                tests[prefix + node.name] = _facts_of(node, inherited)
            elif isinstance(node, ast.ClassDef):
                own = sum(_decorator_name(d) in _SKIP_DECORATORS for d in node.decorator_list)
                visit(node.body, f"{prefix}{node.name}.", inherited + own)

    visit(tree.body, "", module_skips)
    return tests


def check_tests(git: Git, base: str, head: str, status: str, path: str, result: Result) -> list[tuple[int, int]]:
    """Apply the test rules. Return the head's line ranges already flagged as skipped."""
    if status == "D":
        result.add("TEST_DELETED", path, "the test file was deleted")
        return []
    base_source = git.show(base, path)
    head_source = git.show(head, path)
    if base_source is None or head_source is None:
        return []
    try:
        base_tests = collect_tests(base_source)
    except SyntaxError:
        return []
    try:
        head_tests = collect_tests(head_source)
    except SyntaxError:
        result.add("TEST_WEAKENED", path, "the changed test file cannot be parsed")
        return []

    flagged: list[tuple[int, int]] = []
    for name, before in sorted(base_tests.items()):
        after = head_tests.get(name)
        if after is None:
            result.add("TEST_DELETED", path, f"{name} was removed")
            continue
        if after.skips > before.skips:
            result.add("TEST_SKIPPED", path, f"{name} gained a skip or an expected failure")
            flagged.append((after.first_line, after.last_line))
        if after.checks < before.checks:
            result.add("TEST_WEAKENED", path, f"{name} has {after.checks} checks, down from {before.checks}")
        if after.always_true > before.always_true:
            result.add("TEST_WEAKENED", path, f"{name} gained an always-true assert")
        if after.broad_raises > before.broad_raises:
            result.add("TEST_WEAKENED", path, f"{name} gained pytest.raises(Exception)")
    return flagged


def check_suppressions(
    git: Git, base: str, head: str, path: str, flagged: list[tuple[int, int]], result: Result
) -> None:
    if PurePosixPath(path).suffix not in (".py", ".pyi"):
        return
    source = git.show(head, path)
    lines = source.split("\n") if source is not None else []
    for number, text in git.added_lines(base, head, path):
        marker = next((mark for mark in _SUPPRESSIONS if mark in text), None)
        if marker is None:
            continue
        if marker == "pytest.skip(" and any(first <= number <= last for first, last in flagged):
            continue
        above = lines[number - 2] if 2 <= number <= len(lines) + 1 else ""
        if not (_REASON.search(text) or _REASON.search(above)):
            result.add("SUPPRESSION_NO_REASON", path, f"line {number} adds {marker.strip('(')} without a reason line")


def threshold_values(text: str, keys: list[str]) -> dict[str, list[float]]:
    values: dict[str, list[float]] = {}
    for key in keys:
        pattern = re.compile(rf"(?:^|[^\w-]|--){re.escape(key)}\s*=\s*(-?\d+(?:\.\d+)?)", re.MULTILINE)
        found = [float(match.group(1)) for match in pattern.finditer(text)]
        if found:
            values[key] = found
    return values


def check_thresholds(git: Git, base: str, head: str, path: str, keys: list[str], result: Result) -> None:
    before = threshold_values(git.show(base, path) or "", keys)
    after = threshold_values(git.show(head, path) or "", keys)
    for key, old_values in before.items():
        new_values = after.get(key, [])
        if len(new_values) < len(old_values):
            result.add("THRESHOLD_LOWERED", path, f"{key} was removed")
            continue
        for old, new in zip(old_values, new_values):
            if new < old:
                result.add("THRESHOLD_LOWERED", path, f"{key} went from {old:g} to {new:g}")


def parse_requirements(text: str) -> dict[str, tuple[str, str | None, bool]]:
    """Map a normalized package name to its written name, version and whether it has a hash."""
    logical: list[str] = []
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        logical.append(current + stripped)
        current = ""
    if current:
        logical.append(current)

    packages: dict[str, tuple[str, str | None, bool]] = {}
    for line in logical:
        if not line or line.startswith(("#", "-")):
            continue
        match = _REQUIREMENT.match(line)
        if not match:
            continue
        name = match.group(1)
        key = re.sub(r"[-_.]+", "-", name).lower()
        packages[key] = (name, match.group(3), "--hash=sha256:" in line)
    return packages


def check_dependencies(git: Git, base: str, head: str, changed: set[str], guard: dict, result: Result) -> None:
    dependency_files = list(guard.get("dependency_files", []))
    sources = list(guard.get("dependency_sources", []))
    changed_files = [path for path in dependency_files if path in changed]

    for path in sources:
        if path in changed:
            if changed_files:
                result.needs_code_owner.append(path)
            else:
                result.add("DEPENDENCY_NO_HASH", path, "a dependency source changed with no locked file with hashes")

    for path in changed_files:
        before = parse_requirements(git.show(base, path) or "")
        after = parse_requirements(git.show(head, path) or "")
        unhashed = [entry[0] for entry in after.values() if not entry[2]]
        if unhashed:
            result.add("DEPENDENCY_NO_HASH", path, "no hash on: " + ", ".join(sorted(unhashed)))
            continue
        result.needs_code_owner.append(path)
        for key in sorted(set(before) | set(after)):
            old = before.get(key)
            new = after.get(key)
            if old and new and old[1] == new[1]:
                continue
            entry = new or old
            version = (new[1] if new else None) or (old[1] if old else None)
            result.dependency_changes.append(
                {
                    "name": entry[0],
                    "old": old[1] if old else None,
                    "new": new[1] if new else None,
                    "changelog": f"https://pypi.org/project/{entry[0]}/{version}/",
                }
            )


def check_pins(git: Git, base: str, head: str, path: str, result: Result) -> None:
    if PurePosixPath(path).suffix.lower() not in (".yml", ".yaml"):
        return
    for number, text in git.added_lines(base, head, path):
        match = _USES.match(text)
        if not match:
            continue
        reference = match.group(1)
        if reference.startswith("./"):
            continue
        if reference.startswith("docker://"):
            if "@sha256:" not in reference:
                result.add("UNPINNED_ACTION", path, f"line {number}: {reference} has no digest")
            continue
        _, _, ref = reference.partition("@")
        if not _FULL_SHA.match(ref):
            result.add("UNPINNED_ACTION", path, f"line {number}: {reference} is not pinned to a full SHA")


def stored_runs(reports_dir: str, pr: int) -> list[dict]:
    """The stored guard records of one PR, oldest first."""

    def order(path: Path) -> tuple[int, int]:
        run_id, _, attempt = path.parent.name.partition("-")
        return (int(run_id) if run_id.isdigit() else 0, int(attempt) if attempt.isdigit() else 0)

    records = []
    for path in sorted(Path(reports_dir, str(pr)).glob("*/guard.json"), key=order):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def check_repeated(git: Git, base: str, head: str, head_sha: str, args: argparse.Namespace, result: Result) -> None:
    earlier = []
    if args.reports_dir and not Path(args.reports_dir).is_dir():
        # A lost read of the stored runs must never look like "no earlier rounds".
        raise UsageError("the folder of stored runs is missing")
    if args.reports_dir and args.pr is not None:
        earlier = [r for r in stored_runs(args.reports_dir, args.pr) if r.get("head_sha") != head_sha]

    previous = base
    for record in reversed(earlier):
        candidate = record.get("head_sha")
        if isinstance(candidate, str) and git.exists(candidate):
            previous = candidate
            break

    result.fingerprint = {
        "round": git.fingerprint(previous, head),
        "cumulative": git.fingerprint(base, head),
    }
    for record in earlier:
        stored = record.get("fingerprint")
        if not isinstance(stored, dict):
            continue
        if stored.get("round") == result.fingerprint["round"] or stored.get("cumulative") == result.fingerprint["cumulative"]:
            result.repeated_fix = True
            result.add("REPEATED_FIX", "", "this round repeats an earlier round's fix")
            return


def stored_passes(reports_dir: str | None) -> set[str]:
    passes: set[str] = set()
    if not reports_dir:
        return passes
    for path in Path(reports_dir).glob("*/*/acceptance.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and isinstance(record.get("passed"), list):
            passes.update(item for item in record["passed"] if isinstance(item, str))
    return passes


def function_exists_in_base(git: Git, base: str, test_id: str) -> bool:
    """Whether a test named by its JUnit ID already exists in the base."""
    classname, _, name = test_id.partition("::")
    function = name.split("[", 1)[0]
    parts = classname.split(".")
    for end in range(len(parts), 0, -1):
        source = git.show(base, "/".join(parts[:end]) + ".py")
        if source is not None:
            return re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(function)}\s*\(", source, re.MULTILINE) is not None
    return False


def check_known_failing(git: Git, base: str, head: str, kind: str, args: argparse.Namespace, result: Result) -> None:
    base_text = git.show(base, KNOWN_FAILING_PATH)
    head_text = git.show(head, KNOWN_FAILING_PATH)
    if base_text == head_text:
        return
    try:
        before = parse_list(base_text or "")
        after = parse_list(head_text or "")
    except UsageError as error:
        result.add("KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN_FAILING_PATH, str(error))
        return

    passes = stored_passes(args.reports_dir)
    for test_id, map_id in sorted(after.items()):
        if test_id in before:
            continue
        if test_id in passes:
            result.add("KNOWN_FAILING_ADD_PASSED", KNOWN_FAILING_PATH, f"{test_id} has already passed in a stored run")
        if kind != "spec":
            result.add("KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN_FAILING_PATH, f"{test_id} may be added only in a spec PR")
        elif base_text is not None:
            if not map_id.startswith("DEF-"):
                result.add("KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN_FAILING_PATH, f"{test_id} must map to a newly found defect")
            if function_exists_in_base(git, base, test_id):
                result.add("KNOWN_FAILING_ADD_NOT_ALLOWED", KNOWN_FAILING_PATH, f"{test_id} is not a new test")
    for test_id in sorted(set(before) - set(after)):
        if test_id not in passes:
            result.add("KNOWN_FAILING_REMOVED_NOT_PASSED", KNOWN_FAILING_PATH, f"{test_id} has no stored pass")


def judge(args: argparse.Namespace, config: dict) -> Result:
    git = Git(args.repo)
    head = git.run("rev-parse", f"{args.head}^{{commit}}").decode().strip()
    base = git.run("merge-base", args.base, head).decode().strip()
    kind = branch_kind(args.branch)
    result = Result(kind=kind, head_sha=head)
    changes = git.changes(base, head)
    guard = config.get("guard", {})

    if kind == "ai":
        protected = [*FIXED_PROTECTED, *guard.get("extra_protected", [])]
        keys = [*FIXED_THRESHOLD_KEYS, *guard.get("threshold_keys", [])]
        changed = {path for _, path in changes}
        for status, path in changes:
            if is_protected(path, protected):
                result.add("PROTECTED_PATH", path, f"status {status}")
            flagged: list[tuple[int, int]] = []
            if is_test_file(path):
                flagged = check_tests(git, base, head, status, path, result)
            if status != "D":
                check_suppressions(git, base, head, path, flagged, result)
            check_thresholds(git, base, head, path, keys, result)
        check_dependencies(git, base, head, changed, guard, result)

    if kind == "spec":
        for _, path in changes:
            if not is_protected(path, ["acceptance/"]):
                result.add("SPEC_OUTSIDE_ACCEPTANCE", path, "a spec PR may touch only acceptance/")

    if kind in ("ai", "spec"):
        for status, path in changes:
            if status != "D":
                check_pins(git, base, head, path, result)

    check_repeated(git, base, head, head, args, result)
    if kind != "ai":
        # Repeats are a rule for executor rounds only; the fingerprints stay on record.
        result.violations = [v for v in result.violations if v["rule"] != "REPEATED_FIX"]
        result.repeated_fix = False

    check_known_failing(git, base, head, kind, args, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.guard")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--reports-dir")
    parser.add_argument("--pr", type=int)
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        result = judge(args, config)
    except UsageError as error:
        return fail_usage(str(error))

    write_json(
        args.out,
        {
            "kind": result.kind,
            "head_sha": result.head_sha,
            "violations": result.violations,
            "needs_code_owner": sorted(set(result.needs_code_owner)),
            "dependency_changes": result.dependency_changes,
            "fingerprint": result.fingerprint,
            "repeated_fix": result.repeated_fix,
        },
    )
    for violation in result.violations:
        print(f"{violation['rule']}: {violation['path']}: {violation['detail']}", file=sys.stderr)
    return EXIT_RULE_FAILED if result.violations else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
