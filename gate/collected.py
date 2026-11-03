"""Which tests a file holds, read by parsing, never by running. Standard library only."""

from __future__ import annotations

import ast
import re
import xml.etree.ElementTree as ElementTree
from pathlib import Path, PurePosixPath

_PARAMETERS = re.compile(r"\[.*\]$", re.DOTALL)


def is_collected_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _is_test_class(node: ast.ClassDef) -> bool:
    if node.name.startswith("Test"):
        return True
    for base in node.bases:
        name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
        if str(name).endswith("TestCase"):
            return True
    return False


def ids_in_source(source: str, path: str) -> set[str]:
    """The IDs of the tests in one file, as a JUnit file names them. Raises SyntaxError."""
    module = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    found: set[str] = set()
    function_types = (ast.FunctionDef, ast.AsyncFunctionDef)

    def visit(body: list[ast.stmt], prefix: str, in_class: bool) -> None:
        for node in body:
            if isinstance(node, function_types) and node.name.startswith("test"):
                found.add(f"{prefix}::{node.name}")
            elif isinstance(node, ast.ClassDef) and _is_test_class(node):
                visit(node.body, f"{prefix}.{node.name}", True)

    visit(ast.parse(source).body, module, False)
    return found


def strip_parameters(test_id: str) -> str:
    return _PARAMETERS.sub("", test_id)


def junit_ids(path: Path) -> set[str]:
    """Every test ID in a JUnit file, without the parameters of its name. Raises on a bad file."""
    root = ElementTree.parse(path).getroot()
    return {strip_parameters(f"{case.get('classname', '')}::{case.get('name', '')}") for case in root.iter("testcase")}


def ids_under_folder(folder: Path, root: Path) -> set[str]:
    """The IDs of every test under a folder, with paths relative to root. A file that cannot be parsed is skipped."""
    found: set[str] = set()
    for path in sorted(folder.rglob("*.py")):
        relative = path.relative_to(root).as_posix()
        if not is_collected_file(relative):
            continue
        try:
            found |= ids_in_source(path.read_text(encoding="utf-8"), relative)
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            continue
    return found
