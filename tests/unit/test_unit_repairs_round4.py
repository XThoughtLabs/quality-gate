"""What review round 4 found: ways for a PR to turn a real pytest run green that the guard passed.

Each attack is first shown to work with real pytest on a broken module. Links are built with
git's plumbing, so these tests need no privilege to make a symbolic link on this machine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.req("G-1a", "G-1b", "G-1d", "G-4", "G-11b")

GOOD = "def add(a, b):\n    return a + b\n"
BAD = "def add(a, b):\n    return a - b\n"
TEST = "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
PLUGIN = "def pytest_pyfunc_call(pyfuncitem):\n    return True\n"
EXECUTOR = "example-executor[bot]"


class World:
    def __init__(self, gate, root: Path, base_files: dict[str, str | bytes], branch: str = "ai/1-x") -> None:
        self.gate = gate
        self.root = root
        self.branch = branch
        self.repo = root / "repo"
        self.repo.mkdir()
        gate.git(self.repo, "init", "--quiet", "--initial-branch=line")
        gate.git(self.repo, "config", "core.autocrlf", "false")
        self.write(base_files)
        gate.git(self.repo, "add", "-A")
        gate.git(self.repo, "commit", "--quiet", "-m", "base")
        self.base = gate.git(self.repo, "rev-parse", "HEAD")
        gate.git(self.repo, "checkout", "--quiet", "-b", branch)

    def write(self, files: dict[str, str | bytes]) -> None:
        for name, data in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data if isinstance(data, bytes) else data.encode())

    def stage_entry(self, mode: str, path: str, text: str = "") -> None:
        """Put a link or a submodule in the index without making it on the disk."""
        if mode == "160000":
            sha = "1" * 40
        else:
            sha = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"], cwd=self.repo, input=text.encode(), capture_output=True, check=True
            ).stdout.decode().strip()
        self.gate.git(self.repo, "update-index", "--add", "--cacheinfo", f"{mode},{sha},{path}")

    def commit(self, stage_all: bool = True) -> None:
        if stage_all:
            self.gate.git(self.repo, "add", "-A")
        self.gate.git(self.repo, "commit", "--quiet", "-m", "the change")

    def guard(self) -> tuple[int, dict]:
        config = self.root / "quality.toml"
        config.write_text('[feedback]\nexecutor_app = "example-executor"\n', encoding="utf-8")
        out = self.root / "guard.json"
        process = self.gate.run("guard", "--repo", self.repo, "--base", self.base, "--head", "HEAD", "--branch", self.branch, "--author", EXECUTOR, "--config", config, "--out", out)
        assert "Traceback" not in process.stderr
        return process.returncode, json.loads(out.read_text(encoding="utf-8"))

    def real_pytest(self, *args: str) -> int:
        """What a fresh checkout gives, as a runner would have it."""
        fresh = self.root / "fresh"
        self.gate.git(self.root, "clone", "--quiet", "--branch", self.branch, str(self.repo), str(fresh))
        env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args], cwd=fresh, env=env, capture_output=True, check=False).returncode


def rules_of(guard: dict) -> set[tuple[str, str]]:
    return {(item["rule"], item["path"]) for item in guard["violations"]}


@pytest.fixture
def world(gate, tmp_path):
    return World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": TEST})


def test_a_broken_module_fails_with_nothing_else_changed(world):
    """The control for every attack below that runs real pytest."""
    world.write({"app.py": BAD})
    world.commit()
    assert world.real_pytest("tests") == 1


# G-1d: a link or a submodule, whatever its name and its text.


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("tests/tox.ini", "../cfg.txt"),
        ("tests/pyproject.toml", "../cfg.txt"),
        ("tests/setup.cfg", "../cfg.txt"),
        ("tox.ini", "[x]"),
        ("pyproject.toml", "a=1"),
        ("setup.cfg", "[metadata]"),
        ("anything.txt", "app.py"),
    ],
)
def test_an_added_symbolic_link_is_refused(world, path, text):
    world.stage_entry("120000", path, text)
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", path) in rules_of(guard)


def test_a_test_file_turned_into_a_link_with_its_own_old_text_is_refused(world):
    """git stores the same text, so nothing about the text differs: only the mode does."""
    world.stage_entry("120000", "tests/test_a.py", TEST)
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", "tests/test_a.py") in rules_of(guard)


def test_an_added_submodule_is_refused(world):
    world.stage_entry("160000", "vendor/lib")
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", "vendor/lib") in rules_of(guard)


def test_a_link_in_a_spec_pr_is_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "acceptance/test_status.py": TEST}, branch="spec/x")
    world.stage_entry("120000", "acceptance/test_status.py", TEST)
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert guard["kind"] == "spec"
    assert code == 1
    assert ("PROTECTED_PATH", "acceptance/test_status.py") in rules_of(guard)


def test_a_plain_file_with_a_links_text_is_ordinary(world):
    world.write({"notes.txt": "../cfg.txt"})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]


def test_a_link_the_base_already_had_and_a_deleted_link_are_no_violation(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD})
    world.gate.git(world.repo, "checkout", "--quiet", "line")
    world.stage_entry("120000", "old-link", "app.py")
    world.stage_entry("120000", "gone-link", "app.py")
    world.gate.git(world.repo, "commit", "--quiet", "-m", "two links")
    world.base = world.gate.git(world.repo, "rev-parse", "HEAD")
    world.gate.git(world.repo, "branch", "--force", world.branch, "HEAD")
    world.gate.git(world.repo, "symbolic-ref", "HEAD", f"refs/heads/{world.branch}")
    world.gate.git(world.repo, "rm", "--quiet", "--cached", "gone-link")
    world.gate.git(world.repo, "update-index", "--add", "--cacheinfo", f"100644,{world.gate.git(world.repo, 'rev-parse', 'HEAD:app.py')},copied.py")
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert code == 0, guard["violations"]


# G-1a: .gitattributes. The checkout holds what the guard never read.


def utf16_stored(wanted: bytes) -> bytes:
    """Bytes for the working tree. `git add` stores them read as UTF-16LE, so no `pytest` is stored."""
    return wanted + b"\n" if len(wanted) % 2 else wanted


@pytest.mark.parametrize(
    ("attributes", "path", "wanted", "args"),
    [
        (".gitattributes", "tests/tox.ini", b"[pytest]\naddopts = -p evilplug\n", ("tests",)),
        (".gitattributes", "tox.ini", b"#\x00\n[pytest]\naddopts = -p evilplug\n", ()),
        ("tests/.gitattributes", "tests/tox.ini", b"[pytest]\naddopts = -p evilplug\n", ("tests",)),
    ],
    ids=["subfolder-file", "root-file", "subfolder-attributes"],
)
def test_attributes_that_change_a_checkout_turn_a_failure_green_and_are_refused(world, attributes, path, wanted, args):
    name = path.rsplit("/", 1)[-1] if "/" in attributes else path
    world.write({"app.py": BAD, "evilplug.py": PLUGIN, attributes: f"{name} working-tree-encoding=UTF-16LE\n"})
    world.gate.git(world.repo, "add", "-A")
    world.write({path: utf16_stored(wanted)})
    world.commit()
    assert b"pytest" not in subprocess.run(["git", "show", f"HEAD:{path}"], cwd=world.repo, capture_output=True, check=True).stdout
    assert world.real_pytest(*args) == 0, "this attack must work, or the test proves nothing"
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", attributes) in rules_of(guard)


# G-4: a test's name bound again.


@pytest.mark.parametrize(
    "line",
    [
        "test_add = lambda: None",
        "test_add: object = None",
        "from os import getcwd as test_add",
        "import os as test_add",
        "del test_add",
        "class test_add:\n    pass",
        "for test_add in [print]:\n    pass",
        "with open(__file__) as test_add:\n    pass",
        "try:\n    raise ValueError\nexcept ValueError as test_add:\n    pass",
        "if True:\n    def test_add():\n        pass",
        "try:\n    def test_add():\n        pass\nexcept ValueError:\n    pass",
        "def test_add():\n    pass",
        "(test_add := print)",
        "test_add, other = print, print",
    ],
    ids=["assign", "annotated", "from-import", "import", "del", "class", "for", "with", "except", "def-in-if", "def-in-try", "second-def", "walrus", "tuple"],
)
def test_binding_a_tests_name_again_is_refused(world, line):
    world.write({"tests/test_a.py": f"{TEST}\n\n{line}\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_a.py") in rules_of(guard)


def test_rebinding_a_tests_name_turns_a_failure_green(world):
    world.write({"app.py": BAD, "tests/test_a.py": f"{TEST}\n\ntest_add = lambda: None\n"})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    code, _guard = world.guard()
    assert code == 1


CLASS_TEST = "class TestA:\n    def test_x(self):\n        assert work() == 1\n"


@pytest.mark.parametrize(
    "added",
    ["\nTestA = object\n", "\nclass TestA:\n    pass\n", "\ndef TestA():\n    pass\n", "\nTestA.test_x = None\n"],
    ids=["class-name", "second-class", "a-def", "attribute-set-from-outside"],
)
def test_rebinding_the_class_a_test_stands_in(gate, tmp_path, added):
    world = World(gate, tmp_path, {"tests/test_c.py": CLASS_TEST})
    world.write({"tests/test_c.py": CLASS_TEST + added})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_c.py") in rules_of(guard)


def test_a_class_attribute_with_a_tests_name_is_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"tests/test_c.py": CLASS_TEST})
    world.write({"tests/test_c.py": CLASS_TEST + "    test_x = None\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_c.py") in rules_of(guard)


@pytest.mark.parametrize(
    "line",
    [
        "helper = 1",
        "import os",
        "values = [test_add for test_add in [1]]",
        "pairs = {test_add: 1 for test_add in [1]}",
        "other = lambda test_add: test_add",
        "def helper():\n    test_add = 1\n    return test_add",
        "def test_new():\n    assert 1 + 1 == 2",
    ],
    ids=["other-name", "other-import", "list-comprehension", "dict-comprehension", "lambda-argument", "inside-a-function", "a-new-test"],
)
def test_other_bindings_are_not_refused(world, line):
    world.write({"tests/test_a.py": f"{TEST}\n\n{line}\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]


def test_a_binding_the_base_already_had_is_no_new_weakening(gate, tmp_path):
    source = f"{TEST}\n\ntest_add = lambda: None\n"
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": source})
    world.write({"tests/test_a.py": source + "\n\nvalue = 1\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]


# G-11b: what a spec PR may not touch under acceptance/.


def spec_world(gate, tmp_path) -> World:
    return World(gate, tmp_path, {"app.py": GOOD, "acceptance/test_status.py": TEST}, branch="spec/x")


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("acceptance/conftest.py", PLUGIN),
        ("acceptance/deep/conftest.py", PLUGIN),
        ("acceptance/pytest.ini", "[pytest]\naddopts = -q\n"),
        ("acceptance/.gitattributes", "*.py text\n"),
        ("acceptance/tox.ini", "[pytest]\naddopts = -q\n"),
        ("acceptance/setup.cfg", "[tool:pytest]\naddopts = -q\n"),
        ("acceptance/pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n'),
    ],
)
def test_a_spec_pr_may_not_change_what_controls_the_tests(gate, tmp_path, path, text):
    world = spec_world(gate, tmp_path)
    world.write({path: text})
    world.commit()
    code, guard = world.guard()
    assert guard["kind"] == "spec"
    assert code == 1
    assert ("PROTECTED_PATH", path) in rules_of(guard)


def test_a_spec_prs_conftest_turns_a_later_failure_green(gate, tmp_path):
    world = spec_world(gate, tmp_path)
    world.write({"acceptance/conftest.py": PLUGIN, "app.py": BAD})
    world.gate.git(world.repo, "add", "acceptance/conftest.py")
    world.gate.git(world.repo, "commit", "--quiet", "-m", "the spec PR")
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", "acceptance/conftest.py") in rules_of(guard)
    world.gate.git(world.repo, "add", "-A")
    world.gate.git(world.repo, "commit", "--quiet", "-m", "a later PR breaks the module")
    assert world.real_pytest("acceptance") == 0, "this attack must work, or the test proves nothing"


def test_a_spec_pr_may_delete_no_conftest_either(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "acceptance/test_status.py": TEST, "acceptance/conftest.py": "VALUE = 1\n"}, branch="spec/x")
    (world.repo / "acceptance" / "conftest.py").unlink()
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", "acceptance/conftest.py") in rules_of(guard)


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("acceptance/test_more.py", "def test_more():\n    assert len('ab') == 2\n"),
        ("acceptance/helpers.py", "VALUE = 1\n"),
        ("acceptance/data/case.json", "{}\n"),
        ("acceptance/pyproject.toml", '[project]\nname = "x"\n'),
    ],
    ids=["a-test", "a-helper", "a-data-file", "a-plain-pyproject"],
)
def test_a_spec_pr_may_add_what_controls_nothing(gate, tmp_path, path, text):
    world = spec_world(gate, tmp_path)
    world.write({path: text})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]


# G-1b: newlines as pytest reads them, and plugin tables under any tool's name.

ESCAPED = '[tool."\\u0070ytest".ini_options]{0}addopts = "-p evilplug"{0}'


@pytest.mark.parametrize("newline", ["\r", "\r\n", "\n"], ids=["lone-cr", "crlf", "lf"])
def test_a_subfolders_pytest_table_is_seen_with_any_newline(world, newline):
    world.write({"tests/pyproject.toml": ESCAPED.format(newline).encode()})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", "tests/pyproject.toml") in rules_of(guard)


def test_a_lone_cr_turns_a_failure_green_and_is_refused(world):
    world.write({"app.py": BAD, "evilplug.py": PLUGIN, "tests/pyproject.toml": ESCAPED.format("\r").encode()})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    code, _guard = world.guard()
    assert code == 1


def test_a_subfolders_plain_pyproject_with_a_lone_cr_stays_ordinary(world):
    world.write({"tests/pyproject.toml": b'[project]\rname = "x"\r'})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]
    assert not guard["needs_code_owner"]


@pytest.mark.parametrize("folder", ["", "sub/"], ids=["root", "subfolder"])
@pytest.mark.parametrize(
    "text",
    [
        '[project.entry-points.pytest11]\ncheat = "cheat"\n',
        '[tool.poetry.plugins.pytest11]\ncheat = "cheat"\n',
        '[tool.flit.entrypoints.pytest11]\ncheat = "cheat"\n',
        '[tool.other.deep.table."\\u0070ytest11"]\ncheat = "cheat"\n',
        '[project]\nname = "x"\ndynamic = ["entry-points"]\n',
    ],
    ids=["project", "poetry", "flit", "escaped-name", "dynamic"],
)
def test_a_plugin_declaration_is_refused_under_any_tools_name(world, folder, text):
    path = f"{folder}pyproject.toml"
    world.write({path: text})
    world.commit()
    code, guard = world.guard()
    assert code == 1, text
    assert ("PROTECTED_PATH", path) in rules_of(guard)


@pytest.mark.parametrize(
    "text",
    ['[project.entry-points.console_scripts]\nrun = "x:main"\n', '[project]\nname = "x"\ndynamic = ["version"]\n'],
    ids=["another-group", "another-dynamic"],
)
def test_other_entry_points_and_dynamic_fields_are_not_refused(world, text):
    world.write({"sub/pyproject.toml": text})
    world.commit()
    code, guard = world.guard()
    assert code == 0, guard["violations"]


