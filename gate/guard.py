"""Judge a PR's change against the rules of design section 6, from git objects only.

This script never runs code from the repository it reads, nor any command its git
settings name.
"""

from __future__ import annotations

import argparse
import ast
import collections
import configparser
import fnmatch
import hashlib
import json
import re
import subprocess
import sys
import tomllib
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
    "security-review.md",
)
# What controls which tests are collected or how the security tools run (decisions W, X).
# The pytest names are those of CONFIG_LOADERS_BY_NAME in pytest 9.2.0, the pinned version,
# which looks for them upwards from the common ancestor of its arguments and from each
# argument, so any folder a command names can hold one.
PROTECTED_NAMES_ANY_FOLDER = {
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    ".bandit",
    "bandit.yaml",
    "bandit.yml",
    ".gitleaks.toml",
    ".gitleaksignore",
    # It can make what is checked out differ from what git stores, which is what the guard reads.
    ".gitattributes",
}
# In what git stores, a link is only the name of its target, and a submodule only a commit's name.
NOT_PLAIN_MODES = ("120000", "160000")
PROTECTED_ROOT_CONFTEST = "conftest.py"
# `python -m pytest` runs from the working folder, so these would stand in for pytest itself.
PROTECTED_ROOT_SHADOWS = ("pytest.py", "pytest/", "_pytest/")
# In the root only: the tools that decide what is tested and how the security checks run.
PROTECTED_TOOLS_IN_ROOT = ("pytest", "coverage", "bandit", "tox", "semgrep", "gitleaks", "pip-audit", "pip_audit")
PROTECTED_INI_SECTIONS_IN_ROOT = {
    "setup.cfg": ("coverage:*", "bandit"),
    "tox.ini": ("tox*", "testenv*", "coverage:*", "bandit"),
}
FIXED_THRESHOLD_KEYS = ("fail_under", "fail-under", "cov-fail-under")
KNOWN_FAILING_PATH = "acceptance/known-failing.txt"
SECURITY_REVIEW_PATH = "security-review.md"
# The action's default git identity, for commits that do not name the app.
ACTION_DEFAULT_BOT = "claude[bot]"

# A repository's own settings must never start a command from here. --text keeps a
# .gitattributes in the repository from hiding a change.
_SAFE_DIFF = ("--no-renames", "--no-color", "--no-ext-diff", "--no-textconv", "--text")
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
_SUPPRESSIONS = (
    ("# noqa", re.compile(r"#\s*noqa\b", re.IGNORECASE)),
    ("# type: ignore", re.compile(r"#\s*type:\s*ignore\b", re.IGNORECASE)),
    ("# ruff: noqa", re.compile(r"#\s*ruff:\s*noqa\b", re.IGNORECASE)),
    ("# flake8: noqa", re.compile(r"#\s*flake8:\s*noqa\b", re.IGNORECASE)),
    ("# mypy: ignore-errors", re.compile(r"#\s*mypy:\s*ignore-errors\b", re.IGNORECASE)),
    ("# pylint: disable", re.compile(r"#\s*pylint:\s*disable\b", re.IGNORECASE)),
    ("# pragma: no cover", re.compile(r"#\s*pragma:\s*no\s*cover\b", re.IGNORECASE)),
    ("pytest.skip(", re.compile(r"pytest\.skip\(", re.IGNORECASE)),
)
_REASON = re.compile(r"#\s*reason:\s*\S")
_USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^'"\s#]+)""")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(?:==\s*([^\s;]+))?")
_COMMENT = re.compile(r"(^|\s)[#;].*$")
_NO_COV = re.compile(r"(?<![\w-])--no-cov\b")
_TRUE_COMPARISONS = (ast.Eq, ast.Is, ast.LtE, ast.GtE)


@dataclass
class Result:
    kind: str
    head_sha: str
    violations: list[dict] = field(default_factory=list)
    needs_code_owner: list[str] = field(default_factory=list)
    marked_tests: list[dict] = field(default_factory=list)
    security_review_changes: list[dict] = field(default_factory=list)
    dependency_changes: list[dict] = field(default_factory=list)
    fingerprint: dict = field(default_factory=dict)
    repeated_fix: bool = False

    def add(self, rule: str, path: str, detail: str) -> None:
        self.violations.append({"rule": rule, "path": path, "detail": detail})

    def mark(self, path: str, name: str) -> None:
        self.marked_tests.append({"path": path, "name": name})
        self.needs_code_owner.append(path)


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

    def mode(self, rev: str, path: str) -> str | None:
        """A path's mode in a commit: 120000 is a link and 160000 a submodule. None when absent."""
        raw = self.run("ls-tree", "-z", "--full-tree", rev, "--", path)
        return raw.split(b" ", 1)[0].decode("ascii", "replace") if raw else None

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

    def commit_identities(self, start: str, end: str) -> set[str]:
        """The author and committer names of the commits a PR adds."""
        raw = self.run("log", "--format=%an%x00%cn", f"{start}..{end}")
        names: set[str] = set()
        for line in raw.decode("utf-8", "replace").splitlines():
            names.update(line.split("\0"))
        return names

    def own_commits(self, previous: str, base: str, head: str) -> int:
        """The commits since the previous round that are neither merges nor from the base."""
        return int(self.run("rev-list", "--no-merges", "--count", head, f"^{previous}", f"^{base}").decode().strip())


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


def pr_kind(branch: str, author: str, identities: set[str], config: dict) -> str:
    """The kind of a PR (decision V). A branch name can only make the rules stricter."""
    app = config.get("feedback", {}).get("executor_app")
    app_login = f"{app}[bot]".lower() if app else None
    author_lower = author.lower()
    names = {name.lower() for name in identities}
    bot_names = {ACTION_DEFAULT_BOT} | ({app_login} if app_login else set())
    strict = (
        author_lower.endswith("[bot]")
        or bool(names & bot_names)
        or branch.lower().startswith(("ai/", "spec/"))
    )
    if not strict:
        return "other"
    if app_login and author_lower == app_login and branch.startswith("spec/"):
        return "spec"
    return "ai"


def is_protected(path: str, protected: list[str]) -> bool:
    lowered = path.lower()
    for entry in protected:
        target = entry.lower().rstrip("/")
        if lowered == target or lowered.startswith(target + "/"):
            return True
    return False


def is_protected_control_file(path: str) -> bool:
    lowered = path.lower()
    if lowered == PROTECTED_ROOT_CONFTEST or is_protected(lowered, list(PROTECTED_ROOT_SHADOWS)):
        return True
    return PurePosixPath(lowered).name in PROTECTED_NAMES_ANY_FOLDER


def _ini_sections(text: str, patterns: tuple[str, ...]) -> dict[str, dict[str, str]] | None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    return {
        name: dict(parser.items(name))
        for name in parser.sections()
        if any(fnmatch.fnmatch(name.lower(), pattern) for pattern in patterns)
    }


def _as_table(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _with_newlines_as_pytest_reads_them(text: str | None) -> str:
    return (text or "").replace("\r\n", "\n").replace("\r", "\n")


def _values_named(value: object, name: str) -> list[object]:
    """Every value under a key of this name, anywhere in a parsed file."""
    found: list[object] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() == name:
                found.append(item)
            found += _values_named(item, name)
    elif isinstance(value, list):
        for item in value:
            found += _values_named(item, name)
    return found


def _toml_change(is_root: bool, base_text: str | None, head_text: str | None) -> tuple[str | None, bool]:
    try:
        before_doc = tomllib.loads(_with_newlines_as_pytest_reads_them(base_text))
        after_doc = tomllib.loads(_with_newlines_as_pytest_reads_them(head_text))
    except tomllib.TOMLDecodeError:
        mentions_pytest = "pytest" in f"{base_text}{head_text}".lower()
        return ("the file cannot be parsed", False) if is_root or mentions_pytest else (None, False)
    before = _as_table(before_doc.get("tool"))
    after = _as_table(after_doc.get("tool"))
    changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    watched = PROTECTED_TOOLS_IN_ROOT if is_root else ("pytest",)
    hit = [key for key in changed if key.lower() in watched]
    if hit:
        return f"[tool.{hit[0]}] changed", False
    plugins = [_values_named(doc, "pytest11") for doc in (before_doc, after_doc)]
    if plugins[0] != plugins[1]:
        return "a table named pytest11 changed", False
    dynamic = [_as_table(doc.get("project")).get("dynamic") for doc in (before_doc, after_doc)]
    if dynamic[0] != dynamic[1] and "entry-points" in f"{dynamic[0]}{dynamic[1]}":
        return "project.dynamic names entry-points", False
    return None, is_root and base_text != head_text


def _ini_change(name: str, is_root: bool, base_text: str | None, head_text: str | None) -> tuple[str | None, bool]:
    if base_text == head_text:
        return None, False
    # pytest reads these files with its own parser, which cuts lines and section names
    # differently from configparser. So no reading of them is trusted: any change to a file
    # that mentions pytest is refused, whatever the sections seem to be.
    if "pytest" in (base_text or "").lower() or "pytest" in (head_text or "").lower():
        return "a change to a file that mentions pytest", False
    if not is_root:
        return None, False
    patterns = PROTECTED_INI_SECTIONS_IN_ROOT[name]
    before = _ini_sections(base_text or "", patterns)
    after = _ini_sections(head_text or "", patterns)
    if before is None or after is None:
        return "the file cannot be parsed", False
    changed = sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    return (f"[{changed[0]}] changed", False) if changed else (None, True)


def section_change(path: str, base_text: str | None, head_text: str | None) -> tuple[str | None, bool]:
    """Whether a change to a configuration file is refused, with why, or marked for a person."""
    lowered = path.lower()
    name = PurePosixPath(lowered).name
    is_root = lowered == name
    if name == "pyproject.toml":
        return _toml_change(is_root, base_text, head_text)
    if name in PROTECTED_INI_SECTIONS_IN_ROOT:
        return _ini_change(name, is_root, base_text, head_text)
    return None, False


def is_test_file(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return False
    return pure.name.startswith("test_") or pure.name.endswith("_test.py") or "tests" in pure.parts[:-1]


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
    early_returns: int
    cases: int | None
    code: str
    first_line: int
    last_line: int


def _is_check_call(name: str) -> bool:
    last = name.rsplit(".", 1)[-1]
    return name == "pytest.raises" or name.startswith("self.assert") or last.startswith("assert_")


def _assert_is_always_true(test: ast.AST) -> bool:
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(isinstance(value, ast.Constant) and bool(value.value) for value in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], _TRUE_COMPARISONS):
        return ast.dump(test.left) == ast.dump(test.comparators[0])
    return False


def _has_check(statements: list[ast.stmt]) -> bool:
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Assert) or (isinstance(node, ast.Call) and _is_check_call(_dotted(node.func))):
                return True
    return False


def _parametrize_cases(function: ast.AST) -> int | None:
    total = None
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Call) and _decorator_name(decorator) == "pytest.mark.parametrize":
            if len(decorator.args) >= 2 and isinstance(decorator.args[1], (ast.List, ast.Tuple)):
                total = (total or 0) + len(decorator.args[1].elts)
    return total


def _facts_of(function: ast.AST, inherited_skips: int) -> TestFacts:
    checks = skips = always_true = broad_raises = 0
    for decorator in function.decorator_list:
        if _decorator_name(decorator) in _SKIP_DECORATORS:
            skips += 1
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            checks += 1
            if _assert_is_always_true(node.test):
                always_true += 1
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name == "pytest.raises" and node.args and _dotted(node.args[0]) in ("Exception", "BaseException"):
                broad_raises += 1
            if _is_check_call(name):
                checks += 1
            elif name in _SKIP_CALLS:
                skips += 1
    early_returns = sum(
        isinstance(statement, ast.Return) and _has_check(function.body[index + 1 :])
        for index, statement in enumerate(function.body)
    )
    return TestFacts(
        checks,
        skips + inherited_skips,
        always_true,
        broad_raises,
        early_returns,
        _parametrize_cases(function),
        ast.dump(function),
        function.lineno,
        function.end_lineno,
    )


def collect_functions(source: str) -> tuple[dict[str, TestFacts], dict[str, str]]:
    """Map each test to what it checks, and each other function to its code. Raises SyntaxError."""
    tree = ast.parse(source)
    module_skips = 0
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "pytestmark" for target in node.targets
        ):
            values = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            module_skips += sum(_decorator_name(value) in _SKIP_DECORATORS for value in values)

    tests: dict[str, TestFacts] = {}
    others: dict[str, str] = {}
    function_types = (ast.FunctionDef, ast.AsyncFunctionDef)

    def visit(body: list[ast.stmt], prefix: str, inherited: int, in_class: bool) -> None:
        for node in body:
            if isinstance(node, function_types):
                is_test = node.name.startswith("test") if in_class else node.name.startswith("test_")
                if is_test:
                    tests[prefix + node.name] = _facts_of(node, inherited)
                else:
                    others[prefix + node.name] = ast.dump(node)
            elif isinstance(node, ast.ClassDef):
                own = sum(_decorator_name(d) in _SKIP_DECORATORS for d in node.decorator_list)
                visit(node.body, f"{prefix}{node.name}.", inherited + own, True)

    visit(tree.body, "", module_skips, False)
    return tests, others


def rebound_names(source: str) -> collections.Counter[str]:
    """How often each name is bound at module or class level, a test's own `def` included once."""
    bound: collections.Counter[str] = collections.Counter()
    own_scopes = (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

    def scan(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Another def replaces the one before it, and can replace a class of that name.
                bound[prefix + child.name] += 1
                if isinstance(child, ast.ClassDef):
                    scan(child, f"{prefix}{child.name}.")
            elif not isinstance(child, own_scopes):
                if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
                    bound[prefix + child.id] += 1
                elif (
                    isinstance(child, ast.Attribute)
                    and isinstance(child.ctx, (ast.Store, ast.Del))
                    and isinstance(child.value, ast.Name)
                ):
                    bound[f"{prefix}{child.value.id}.{child.attr}"] += 1
                elif isinstance(child, ast.alias):
                    bound[prefix + (child.asname or child.name.split(".", 1)[0])] += 1
                elif isinstance(child, ast.ExceptHandler) and child.name:
                    bound[prefix + child.name] += 1
                scan(child, prefix)

    scan(ast.parse(source), "")
    return bound


def _scopes(name: str) -> list[str]:
    """A test and the classes it stands in: rebinding any of them takes the test away."""
    parts = name.split(".")
    return [".".join(parts[: index + 1]) for index in range(len(parts))]


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
        base_tests, base_others = collect_functions(base_source)
    except SyntaxError:
        return []
    try:
        head_tests, head_others = collect_functions(head_source)
    except SyntaxError:
        result.add("TEST_WEAKENED", path, "the changed test file cannot be parsed")
        return []

    base_bound = rebound_names(base_source)
    head_bound = rebound_names(head_source)
    flagged: list[tuple[int, int]] = []
    for name, before in sorted(base_tests.items()):
        after = head_tests.get(name)
        if after is None:
            result.add("TEST_DELETED", path, f"{name} was removed")
            continue
        weakened = False
        if any(head_bound[scope] > base_bound[scope] for scope in _scopes(name)):
            result.add("TEST_WEAKENED", path, f"{name} is bound again at module or class level")
            weakened = True
        if after.skips > before.skips:
            result.add("TEST_SKIPPED", path, f"{name} gained a skip or an expected failure")
            flagged.append((after.first_line, after.last_line))
            weakened = True
        if after.checks < before.checks:
            result.add("TEST_WEAKENED", path, f"{name} has {after.checks} checks, down from {before.checks}")
            weakened = True
        if after.always_true > before.always_true:
            result.add("TEST_WEAKENED", path, f"{name} gained an always-true assert")
            weakened = True
        if after.broad_raises > before.broad_raises:
            result.add("TEST_WEAKENED", path, f"{name} gained pytest.raises(Exception)")
            weakened = True
        if after.early_returns > before.early_returns:
            result.add("TEST_WEAKENED", path, f"{name} gained a return ahead of a check")
            weakened = True
        if before.cases is not None and (after.cases is None or after.cases < before.cases):
            result.add("TEST_WEAKENED", path, f"{name} has fewer parametrized cases")
            weakened = True
        if not weakened and before.code != after.code:
            result.mark(path, name)
    for name, before_code in sorted(base_others.items()):
        if head_others.get(name) != before_code:
            result.mark(path, name)
    return flagged


def check_suppressions(
    git: Git, base: str, head: str, path: str, flagged: list[tuple[int, int]], result: Result
) -> None:
    if PurePosixPath(path).suffix not in (".py", ".pyi"):
        return
    source = git.show(head, path)
    lines = source.split("\n") if source is not None else []
    for number, text in git.added_lines(base, head, path):
        marker = next((label for label, pattern in _SUPPRESSIONS if pattern.search(text)), None)
        if marker is None:
            continue
        if marker == "pytest.skip(" and any(first <= number <= last for first, last in flagged):
            continue
        above = lines[number - 2] if 2 <= number <= len(lines) + 1 else ""
        if not (_REASON.search(text) or _REASON.search(above)):
            result.add("SUPPRESSION_NO_REASON", path, f"line {number} adds {marker.strip('(')} without a reason line")


def threshold_values(text: str, keys: list[str]) -> dict[str, list[float]]:
    """The numeric values of each threshold key. A key in a comment does not count."""
    bare = "\n".join(_COMMENT.sub("", line) for line in text.split("\n"))
    values: dict[str, list[float]] = {}
    for key in keys:
        spelled = r"[-_]".join(re.escape(part) for part in re.split(r"[-_]", key))
        pattern = re.compile(
            rf"""(?<![\w-])(?:--)?{spelled}["']?\s*(?:=|:|,|\s)\s*["']?(-?\d+(?:\.\d+)?)""",
            re.IGNORECASE,
        )
        found = [float(match.group(1)) for match in pattern.finditer(bare)]
        if found:
            values[key] = found
    return values


def check_thresholds(git: Git, base: str, head: str, status: str, path: str, keys: list[str], result: Result) -> None:
    before = threshold_values(git.show(base, path) or "", keys)
    after = threshold_values(git.show(head, path) or "", keys)
    for key, old_values in before.items():
        new_values = after.get(key)
        if not new_values:
            result.add("THRESHOLD_LOWERED", path, f"{key} was removed")
        elif min(new_values) < min(old_values):
            result.add("THRESHOLD_LOWERED", path, f"{key} went from {min(old_values):g} to {min(new_values):g}")
    if status != "D":
        for number, text in git.added_lines(base, head, path):
            if _NO_COV.search(_COMMENT.sub("", text)):
                result.add("THRESHOLD_LOWERED", path, f"line {number} adds --no-cov")


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
    earlier: list[dict] = []
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
    # A round of merges from the base holds no fix at all, so it cannot repeat one.
    if previous != base and git.own_commits(previous, base, head) == 0:
        return
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


def security_review_changes(git: Git, base: str, head: str) -> list[dict]:
    """Each table row of security-review.md that a PR adds or removes, whoever made the PR."""

    def rows(text: str | None) -> list[str]:
        return [line.strip() for line in (text or "").splitlines() if line.strip().startswith("|")]

    before = rows(git.show(base, SECURITY_REVIEW_PATH))
    after = rows(git.show(head, SECURITY_REVIEW_PATH))
    changes = [{"change": "added", "row": row} for row in after if row not in before]
    changes += [{"change": "removed", "row": row} for row in before if row not in after]
    return changes


def spec_control_refusal(git: Git, base: str, head: str, path: str) -> str | None:
    """A spec PR adds tests. What controls how every test runs stays with people."""
    if PurePosixPath(path.lower()).name == PROTECTED_ROOT_CONFTEST:
        return "a spec PR may not change a conftest.py: fixtures go in the test file, or in a person's PR"
    if is_protected_control_file(path):
        return "a spec PR may not change what controls the tests"
    return section_change(path, git.show(base, path), git.show(head, path))[0]


def check_ai_rules(git: Git, base: str, head: str, changes: list[tuple[str, str]], guard: dict, result: Result) -> None:
    protected = [*FIXED_PROTECTED, *guard.get("extra_protected", [])]
    keys = [*FIXED_THRESHOLD_KEYS, *guard.get("threshold_keys", [])]
    changed = {path for _, path in changes}
    for status, path in changes:
        if is_protected(path, protected) or is_protected_control_file(path):
            result.add("PROTECTED_PATH", path, f"status {status}")
        else:
            refusal, mark = section_change(path, git.show(base, path), git.show(head, path))
            if refusal:
                result.add("PROTECTED_PATH", path, refusal)
            elif mark:
                result.needs_code_owner.append(path)
        if PurePosixPath(path).name.lower() == PROTECTED_ROOT_CONFTEST and path.lower() != PROTECTED_ROOT_CONFTEST:
            result.needs_code_owner.append(path)
        flagged: list[tuple[int, int]] = []
        if is_test_file(path):
            flagged = check_tests(git, base, head, status, path, result)
        if status != "D":
            check_suppressions(git, base, head, path, flagged, result)
        check_thresholds(git, base, head, status, path, keys, result)
    check_dependencies(git, base, head, changed, guard, result)


def judge(args: argparse.Namespace, config: dict) -> Result:
    git = Git(args.repo)
    head = git.run("rev-parse", f"{args.head}^{{commit}}").decode().strip()
    base = git.run("merge-base", args.base, head).decode().strip()
    kind = pr_kind(args.branch, args.author, git.commit_identities(base, head), config)
    result = Result(kind=kind, head_sha=head)
    changes = git.changes(base, head)

    if kind == "ai":
        check_ai_rules(git, base, head, changes, config.get("guard", {}), result)

    if kind == "spec":
        for status, path in changes:
            if not is_protected(path, ["acceptance/"]):
                result.add("SPEC_OUTSIDE_ACCEPTANCE", path, "a spec PR may touch only acceptance/")
                continue
            refusal = spec_control_refusal(git, base, head, path)
            if refusal:
                result.add("PROTECTED_PATH", path, refusal)
            elif is_test_file(path):
                check_tests(git, base, head, status, path, result)

    if kind in ("ai", "spec"):
        for status, path in changes:
            if status != "D":
                check_pins(git, base, head, path, result)
                if git.mode(head, path) in NOT_PLAIN_MODES:
                    result.add("PROTECTED_PATH", path, "a symbolic link or a submodule: tools follow what the guard cannot read")

    check_repeated(git, base, head, head, args, result)
    if kind != "ai":
        # Repeats are a rule for executor rounds only; the fingerprints stay on record.
        result.violations = [v for v in result.violations if v["rule"] != "REPEATED_FIX"]
        result.repeated_fix = False

    check_known_failing(git, base, head, kind, args, result)
    result.security_review_changes = security_review_changes(git, base, head)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gate.guard")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--author", required=True)
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
            "marked_tests": result.marked_tests,
            "security_review_changes": result.security_review_changes,
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
