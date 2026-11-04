"""Which tests a file holds, read by parsing, never by running. Standard library only.

This follows what pytest collects by default. A folder or a test that pytest treats
differently in one repository is named in the trusted configuration's ignore list.
"""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path, PurePosixPath

_PARAMETERS = re.compile(r"\[.*\]$", re.DOTALL)
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def is_collected_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def is_ignored(path_or_id: str, ignore: list[str]) -> bool:
    """Whether a path or a test ID falls under an entry of a trusted ignore list."""
    for entry in ignore:
        target = entry.rstrip("/")
        if path_or_id == target or path_or_id.startswith(target + "/"):
            return True
    return False


def _inherits_test_case(node: ast.ClassDef) -> bool:
    for base in node.bases:
        name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
        if str(name).endswith("TestCase"):
            return True
    return False


def _sets_test_false(body: list[ast.stmt]) -> bool:
    """Whether a body says `__test__ = False`, which tells pytest to pass over it."""
    for node in body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is False:
            if any(isinstance(target, ast.Name) and target.id == "__test__" for target in node.targets):
                return True
    return False


def _functions_turned_off(body: list[ast.stmt]) -> set[str]:
    """The functions of a body named in a `name.__test__ = False` statement."""
    names: set[str] = set()
    for node in body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value is False:
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "__test__" and isinstance(target.value, ast.Name):
                    names.add(target.value.id)
    return names


def _is_fixture(node: ast.AST) -> bool:
    for decorator in node.decorator_list:
        call = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = call.attr if isinstance(call, ast.Attribute) else getattr(call, "id", "")
        if name in ("fixture", "yield_fixture"):
            return True
    return False


def _is_collected_class(node: ast.ClassDef) -> bool:
    if _sets_test_false(node.body):
        return False
    if _inherits_test_case(node):
        return True
    if not node.name.startswith("Test"):
        return False
    # pytest passes over a Test* class with its own __init__.
    return not any(isinstance(item, _FUNCTIONS) and item.name == "__init__" for item in node.body)


def ids_in_source(source: str, path: str) -> set[str]:
    """The IDs of the tests in one file, as a JUnit file names them. Raises SyntaxError."""
    module = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    found: set[str] = set()
    tree = ast.parse(source.removeprefix("\ufeff"))
    if _sets_test_false(tree.body):
        return found

    def visit(body: list[ast.stmt], prefix: str) -> None:
        turned_off = _functions_turned_off(body)
        for node in body:
            if isinstance(node, _FUNCTIONS):
                if node.name.startswith("test") and node.name not in turned_off and not _is_fixture(node):
                    found.add(f"{prefix}::{node.name}")
            elif isinstance(node, ast.ClassDef) and _is_collected_class(node):
                visit(node.body, f"{prefix}.{node.name}")

    visit(tree.body, module)
    return found


def strip_parameters(test_id: str) -> str:
    return _PARAMETERS.sub("", test_id)


def junit_ids(path: Path) -> set[str]:
    """Every test ID in a JUnit file, without the parameters of its name. Raises on a bad file."""
    root = ElementTree.parse(path).getroot()
    return {strip_parameters(f"{case.get('classname', '')}::{case.get('name', '')}") for case in root.iter("testcase")}


def ids_under_folder(folder: Path, root: Path, ignore: list[str] | None = None) -> set[str]:
    """The IDs of every test under a folder, with paths relative to root. A file that cannot be parsed is skipped."""
    found: set[str] = set()
    for path in sorted(folder.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if not is_collected_file(relative) or is_ignored(relative, ignore or []):
            continue
        try:
            found |= ids_in_source(path.read_text(encoding="utf-8"), relative)
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            continue
    return found
