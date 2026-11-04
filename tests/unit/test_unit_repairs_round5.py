"""What review round 5 found: what Python runs must be what the guard read.

Where a test says an attack works, it first shows real pytest going green on a broken module,
or the rule would prove nothing. Links and odd names are built with git's plumbing.
"""

from __future__ import annotations

import ast
import py_compile
import subprocess
import sys
from pathlib import Path

import pytest
from test_unit_repairs_round4 import BAD, GOOD, PLUGIN, TEST, World, rules_of

pytestmark = pytest.mark.req("G-1d", "G-1e", "G-1f", "G-1g", "G-1h", "G-1i", "G-4", "R-12", "X-0a", "X-0b")


@pytest.fixture
def world(gate, tmp_path):
    return World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": TEST})


def refused(world: World, path: str) -> None:
    code, guard = world.guard()
    assert code == 1
    assert ("PROTECTED_PATH", path) in rules_of(guard)


def clean(world: World) -> dict:
    code, guard = world.guard()
    assert code == 0, guard["violations"]
    return guard


def index_info(world: World, mode: str, path: bytes, text: bytes = b"x") -> None:
    """Add an entry whose name need not be valid UTF-8, or valid on Windows, on any machine."""
    world.gate.git(world.repo, "config", "core.protectNTFS", "false")
    sha = "1" * 40
    if mode != "160000":
        sha = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=world.repo, input=text, capture_output=True, check=True).stdout.decode().strip()
    subprocess.run(["git", "update-index", "-z", "--index-info"], cwd=world.repo, input=f"{mode} {sha}\t".encode() + path + b"\0", check=True)


# G-1d: any path name, and no way to hide a submodule.


@pytest.mark.parametrize("mode", ["120000", "160000"], ids=["link", "submodule"])
@pytest.mark.parametrize("path", [b":colon", b":/tox.ini", b":(top)x", b"a*b", b"dir/:x"], ids=["colon", "colon-slash", "magic", "glob", "sub-colon"])
def test_any_spelling_of_a_path_is_seen(world, mode, path):
    index_info(world, mode, path)
    world.commit(stage_all=False)
    refused(world, path.decode())


@pytest.mark.parametrize("mode", ["120000", "160000"], ids=["link", "submodule"])
def test_a_name_that_is_not_utf8_is_seen(world, mode):
    index_info(world, mode, b"bad\xffname")
    world.commit(stage_all=False)
    code, guard = world.guard()
    assert code == 1
    assert any(item["rule"] == "PROTECTED_PATH" and "bad" in item["path"] for item in guard["violations"])


def test_a_plain_file_named_like_a_pathspec_is_ordinary(world):
    index_info(world, "100644", b":!x")
    index_info(world, "100644", b":(glob)x")
    world.commit(stage_all=False)
    clean(world)


def test_gitmodules_cannot_hide_a_submodule(world):
    world.write({".gitmodules": '[submodule "x"]\n\tpath = hidden\n\turl = https://example.invalid/x.git\n\tignore = all\n'})
    world.gate.git(world.repo, "add", ".gitmodules")
    index_info(world, "160000", b"hidden")
    world.commit(stage_all=False)
    refused(world, "hidden")


# G-1e: encoding.


@pytest.mark.parametrize(
    "first",
    ["# coding: utf-7\n", "# -*- coding: latin-1 -*-\n", "# vim: set fileencoding=cp1252 :\n", "#!/bin/python\n# coding: utf-7\n", "#!/bin/python\r# coding: utf-7\r", "# coding: nothing-of-this-name\n", "\ufeff# coding: latin-1\n"],
    ids=["utf-7", "latin-1", "vim", "second-line", "after-a-lone-cr", "unknown", "bom-and-another"],
)
@pytest.mark.parametrize("path", ["tests/test_a.py", "app.py", "new/module.py"], ids=["a-test", "the-application", "a-new-file"])
def test_another_encoding_is_refused(world, first, path):
    world.write({path: f"{first}VALUE = 1\n".encode("utf-8", "surrogatepass")})
    world.commit()
    refused(world, path)


@pytest.mark.parametrize(
    "first",
    ["# coding: utf-8\n", "# -*- coding: UTF8 -*-\n", "\ufeff# coding: utf-8\n", "\n\n# coding: utf-7\n", "VALUE = 1\n# coding: utf-7\n", ""],
    ids=["utf-8", "utf8", "bom", "on-line-three", "after-code", "none"],
)
def test_utf8_or_no_declaration_is_ordinary(world, first):
    world.write({"new/module.py": f"{first}OTHER = 2\n"})
    world.commit()
    clean(world)


def test_a_cookie_in_a_file_that_is_not_python_is_ordinary(world):
    world.write({"notes.txt": "# coding: utf-7\n"})
    world.commit()
    clean(world)


UTF7 = "# coding: utf-7\nfrom app import add\n\n\ndef test_add():\n    #+AAo-    return\n    assert add(1, 2) == 3\n"


def test_a_cookie_turns_a_failure_green_and_is_refused(world):
    world.write({"app.py": BAD, "tests/test_a.py": UTF7})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    refused(world, "tests/test_a.py")


# G-1f: no source to read.


@pytest.mark.parametrize(
    "path",
    ["__pycache__/app.cpython-313.pyc", "x.pyc", "pkg/x.PYC", "x.pyo", "ext.so", "ext.pyd", "__pycache__/notes.txt", "evil-1.0.dist-info/METADATA", "sub/evil-1.0.dist-info/entry_points.txt", "evil.egg-info/PKG-INFO", "evil.egg/x.py"],
)
def test_bytecode_and_metadata_are_refused(world, path):
    world.write({path: "x\n"})
    world.commit()
    refused(world, path)


@pytest.mark.parametrize("path", ["pkg/egg.py", "docs/dist-info.txt", "pycache_notes.md", "pkg/pyc.py", "so.txt"])
def test_names_that_only_look_like_them_are_ordinary(world, path):
    world.write({path: "x = 1\n"})
    world.commit()
    clean(world)


def test_deleting_bytecode_is_no_violation(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "old.pyc": "x\n"})
    (world.repo / "old.pyc").unlink()
    world.commit()
    clean(world)


def test_metadata_as_plain_files_turns_a_failure_green_and_is_refused(world):
    world.write(
        {
            "app.py": BAD,
            "evilplug.py": PLUGIN,
            "evil-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n",
            "evil-1.0.dist-info/entry_points.txt": "[pytest11]\nevil = evilplug\n",
        }
    )
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    refused(world, "evil-1.0.dist-info/entry_points.txt")


def test_committed_bytecode_turns_a_failure_green_and_is_refused(world, tmp_path):
    source = tmp_path / "good_app.py"
    source.write_text(GOOD, encoding="utf-8")
    compiled = tmp_path / "app.pyc"
    py_compile.compile(str(source), cfile=str(compiled), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH, dfile="app.py")
    path = f"__pycache__/app.{sys.implementation.cache_tag}.pyc"
    world.write({"app.py": BAD, path: compiled.read_bytes()})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    refused(world, path)


# G-1g: new top-level names.


@pytest.mark.parametrize(
    ("path", "reported"),
    [
        ("argparse.py", "argparse.py"),
        ("iniconfig.py", "iniconfig.py"),
        ("pluggy.py", "pluggy.py"),
        ("_pytest.py", "_pytest.py"),
        ("packaging/__init__.py", "packaging/__init__.py"),
        ("json/__init__.py", "json/__init__.py"),
    ],
)
def test_a_new_top_level_name_that_stands_in_is_refused(world, path, reported):
    world.write({path: "VALUE = 1\n"})
    world.commit()
    refused(world, reported)


@pytest.mark.parametrize(
    ("before", "after"),
    [("calendar.py", "calendar/__init__.py"), ("email/__init__.py", "email.py"), ("queue/notes.txt", "queue.py")],
    ids=["module-to-package", "package-to-module", "folder-gains-a-module"],
)
def test_a_name_the_base_has_may_change_its_shape(gate, tmp_path, before, after):
    world = World(gate, tmp_path, {"app.py": GOOD, before: "A = 1\n"})
    (world.repo / before).unlink()
    world.write({after: "A = 1\n"})
    world.commit()
    clean(world)


def test_a_top_level_name_the_base_has_may_change(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "logging/__init__.py": "A = 1\n", "queue.py": "B = 1\n"})
    world.write({"logging/__init__.py": "A = 2\n", "queue.py": "B = 2\n"})
    world.commit()
    clean(world)


@pytest.mark.parametrize("path", ["html/index.html", "email/readme.txt", "myapp.py", "test/test_x.py", "mypkg/__init__.py"], ids=["static-html", "folder-no-init", "another-name", "a-test-folder", "another-package"])
def test_other_new_top_level_names_are_ordinary(world, path):
    world.write({path: "VALUE = 1\n"})
    world.commit()
    clean(world)


# G-1h: standing in, in a folder holding tests.


@pytest.mark.parametrize(
    "path",
    ["tests/app.py", "tests/app/__init__.py", "tests/argparse.py", "tests/pluggy.py"],
    ids=["the-application", "as-a-package", "the-standard-library", "a-tool"],
)
def test_a_module_in_a_test_folder_that_stands_in_is_refused(world, path):
    world.write({path: "VALUE = 1\n"})
    world.commit()
    refused(world, path)


def test_a_src_layouts_module_is_known(gate, tmp_path):
    world = World(gate, tmp_path, {"src/lib.py": GOOD, "tests/test_a.py": TEST})
    world.write({"tests/lib.py": GOOD})
    world.commit()
    refused(world, "tests/lib.py")


def test_a_module_standing_in_turns_a_failure_green_and_is_refused(world):
    world.write({"app.py": BAD, "tests/app.py": GOOD})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    refused(world, "tests/app.py")


def test_a_spec_pr_may_not_shadow_the_application(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "acceptance/test_status.py": TEST}, branch="spec/x")
    world.write({"acceptance/app.py": GOOD})
    world.commit()
    refused(world, "acceptance/app.py")


@pytest.mark.parametrize("path", ["tests/helpers.py", "pkg/app.py", "docs/argparse.py"], ids=["another-name", "a-folder-with-no-tests", "docs"])
def test_other_new_modules_are_ordinary(world, path):
    world.write({path: "VALUE = 1\n"})
    world.commit()
    clean(world)


@pytest.mark.parametrize(
    ("base_files", "new"),
    [
        ({"src/app/__init__.py": "", "src/app/test_core.py": TEST}, "src/app/types.py"),
        ({"src/app/__init__.py": "", "src/app/test_core.py": TEST}, "src/app/http/__init__.py"),
        ({"tests/__init__.py": "", "tests/test_a.py": TEST, "utils.py": "A = 1\n"}, "tests/utils.py"),
        ({"tests/__init__.py": "", "tests/test_a.py": TEST}, "tests/random.py"),
    ],
    ids=["module-in-a-package", "package-in-a-package", "named-like-a-root-module", "named-like-the-standard-library"],
)
def test_a_module_inside_a_package_stands_in_for_nothing(gate, tmp_path, base_files, new):
    world = World(gate, tmp_path, {"app.py": GOOD, **base_files})
    world.write({new: "A = 1\n"})
    world.commit()
    clean(world)


def test_in_a_package_a_module_really_does_not_shadow(gate, tmp_path):
    """Real pytest: with __init__.py the standard library's module is the one imported."""
    test = "import wave\n\n\ndef test_real_module():\n    assert hasattr(wave, 'open')\n"
    world = World(gate, tmp_path, {"tests/__init__.py": "", "tests/test_w.py": test})
    world.write({"tests/wave.py": "VALUE = 1\n"})
    world.commit()
    assert world.real_pytest("tests") == 0


def test_a_conftest_in_a_test_folder_stays_marked_not_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "conftest.py": "A = 1\n", "tests/test_a.py": TEST})
    world.write({"tests/conftest.py": "B = 1\n"})
    world.commit()
    guard = clean(world)
    assert "tests/conftest.py" in guard["needs_code_owner"]


def test_a_shadow_the_base_already_has_may_change(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": TEST, "tests/app.py": GOOD})
    world.write({"tests/app.py": GOOD + "\n\nVALUE = 1\n"})
    world.commit()
    clean(world)


# G-1i: plugins by name.


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("tests/test_new.py", "pytest_plugins = ['zzplug']\n"),
        ("tests/test_a.py", TEST + "\n\npytest_plugins = ('zzplug',)\n"),
        ("tests/test_new.py", "from zz import pytest_plugins\n"),
        ("tests/test_new.py", "from zz import *\n"),
        ("pkg/__init__.py", "pytest_plugins = ['zzplug']\n"),
    ],
    ids=["a-new-test", "an-existing-test", "imported", "star", "a-package"],
)
def test_a_plugin_line_is_refused(world, path, text):
    world.write({path: text})
    world.commit()
    refused(world, path)


def test_a_plugin_line_in_a_spec_pr_is_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "acceptance/test_status.py": TEST}, branch="spec/x")
    world.write({"acceptance/__init__.py": "pytest_plugins = ['acceptance.zzplug']\n"})
    world.commit()
    refused(world, "acceptance/__init__.py")


def test_changing_a_plugin_list_the_base_has_is_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": TEST + "\n\npytest_plugins = ['a']\n"})
    world.write({"tests/test_a.py": TEST + "\n\npytest_plugins = ['a', 'b']\n"})
    world.commit()
    refused(world, "tests/test_a.py")


def test_a_plugin_line_turns_a_failure_green_and_is_refused(world):
    world.write({"app.py": BAD, "tests/test_zz.py": "pytest_plugins = ['zzplug']\n\n\ndef test_zz():\n    assert len('a') == 1\n", "tests/zzplug.py": PLUGIN})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    refused(world, "tests/test_zz.py")


@pytest.mark.parametrize(
    ("path", "text"),
    [
        ("tests/test_new.py", "# pytest_plugins = ['x'] was here\nVALUE = 'pytest_plugins'\n"),
        ("pkg/__init__.py", "from .inner import *\n"),
    ],
    ids=["a-comment-and-a-string", "a-star-in-application-code"],
)
def test_other_mentions_are_ordinary(world, path, text):
    world.write({path: text})
    world.commit()
    clean(world)


def test_a_plugin_list_the_base_has_may_stay(gate, tmp_path):
    source = TEST + "\n\npytest_plugins = ['a']\n"
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": source})
    world.write({"tests/test_a.py": source + "\n\nVALUE = 1\n"})
    world.commit()
    clean(world)


# G-4: every static way of binding a test's name again.


@pytest.mark.parametrize(
    "added",
    [
        "from os.path import *",
        "class Other:\n    global test_add\n    test_add = print",
        "def _f():\n    global test_add\n    test_add = print\n\n\n_f()",
        "[(test_add := print) for _ in [0]]",
        "{(test_add := print) for _ in [0]}",
        "def _g(a=(test_add := print)):\n    pass",
        "_l = lambda a=(test_add := print): a",
        "_d = lambda f: f\n\n\n@((test_add := print) and _d)\ndef _h():\n    pass",
        "class _C((test_add := print) and object):\n    pass",
        "match print:\n    case test_add:\n        pass",
        "match [print]:\n    case [test_add]:\n        pass",
        "match [print]:\n    case [*test_add]:\n        pass",
        "match {}:\n    case {**test_add}:\n        pass",
        "test_add.__code__ = (lambda: None).__code__",
        "del test_add.__code__",
    ],
    ids=["star", "global-in-class", "global-in-function", "walrus-list", "walrus-set", "default", "lambda-default", "decorator", "class-base", "match-as", "match-sequence", "match-star", "match-rest", "code-attribute", "del-attribute"],
)
def test_binding_a_tests_name_again_is_refused(world, added):
    world.write({"tests/test_a.py": f"{TEST}\n\n{added}\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_a.py") in rules_of(guard)


CLASS_TEST = "class TestA:\n    class TestIn:\n        def test_x(self):\n            assert work() == 1\n\n    def test_y(self):\n        assert work() == 1\n"


@pytest.mark.parametrize(
    "added",
    [
        "\nclass Other:\n    TestA.test_y = None\n",
        "\nTestA.test_y.__code__ = None\n",
        "\nTestA.TestIn.test_x = None\n",
        "    test_y.__test__ = False\n",
        "    match None:\n        case test_y:\n            pass\n",
    ],
    ids=["from-another-class", "code-attribute", "nested-class", "attribute-in-its-own-class", "match-in-class-body"],
)
def test_binding_a_method_again_is_refused(gate, tmp_path, added):
    world = World(gate, tmp_path, {"tests/test_c.py": CLASS_TEST})
    world.write({"tests/test_c.py": CLASS_TEST + added})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_c.py") in rules_of(guard)


def test_a_binding_replaced_by_another_counts(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": TEST + "\n\ntest_add = mark(test_add)\n"})
    world.write({"tests/test_a.py": TEST + "\n\ntest_add = lambda: None\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_a.py") in rules_of(guard)


@pytest.mark.parametrize(
    "added",
    [
        "class TestNew:\n    def test_z(self):\n        assert 1 + 1 == 2",
        "OTHER = {k: 1 for k in [1]}",
        "def _g(a=(other := 1)):\n    pass",
        "def _f():\n    global other\n    other = 1",
        "match 1:\n    case other:\n        pass",
    ],
    ids=["a-new-class", "a-comprehension", "another-default", "another-global", "another-pattern"],
)
def test_bindings_of_other_names_are_not_refused(world, added):
    world.write({"tests/test_a.py": f"{TEST}\n\n{added}\n"})
    world.commit()
    clean(world)


def test_another_attribute_of_a_class_that_holds_tests_is_not_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"tests/test_c.py": CLASS_TEST})
    world.write({"tests/test_c.py": CLASS_TEST + "\nTestA.limit = 1\n"})
    world.commit()
    clean(world)


def test_a_new_method_in_a_class_of_the_base_is_not_refused(gate, tmp_path):
    world = World(gate, tmp_path, {"tests/test_c.py": CLASS_TEST})
    world.write({"tests/test_c.py": CLASS_TEST + "\n    def test_new(self):\n        assert work() == 1\n"})
    world.commit()
    clean(world)


def test_rebinding_with_a_star_import_turns_a_failure_green_and_is_refused(world):
    world.write({"app.py": BAD, "tests/test_a.py": TEST + "\n\nfrom helpers import *\n", "tests/helpers.py": "def test_add():\n    pass\n"})
    world.commit()
    assert world.real_pytest("tests") == 0, "this attack must work, or the test proves nothing"
    code, _guard = world.guard()
    assert code == 1


# C-2: the guard reads ordinary test code without a traceback (R6-M1).


@pytest.mark.parametrize(
    "call",
    ['",".join(["a"])', "make().value()", "items[0].run()", "make()()", 'Path("x").read_text()', 'self.client.get("/").json()', "(a or b).c()", "x.y.z()", "plain()"],
)
def test_a_changed_test_with_any_form_of_a_call_gets_an_answer(gate, tmp_path, call):
    source = f"def test_a():\n    assert {call} == 1\n"
    world = World(gate, tmp_path, {"tests/test_a.py": source})
    world.write({"tests/test_a.py": source + "\n\ndef test_b():\n    assert 1 + 1 == 2\n"})
    world.commit()
    clean(world)


def test_a_weakened_test_with_a_chained_call_is_still_seen(gate, tmp_path):
    world = World(gate, tmp_path, {"tests/test_a.py": 'def test_a():\n    assert ",".join(["a"]) == "a"\n'})
    world.write({"tests/test_a.py": 'def test_a():\n    ",".join(["a"])\n'})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_a.py") in rules_of(guard)


def test_the_guard_reads_every_test_file_of_this_repository(gate):
    """Ordinary code, far more varied than any list above. A crash here once hit 29 of 42 files."""
    sys.path.insert(0, str(gate.root))
    try:
        from gate.guard import collect_functions, rebound_names
    finally:
        sys.path.remove(str(gate.root))
    files = sorted((gate.root / "tests").rglob("*.py"))
    assert len(files) > 40
    for path in files:
        source = path.read_text(encoding="utf-8")
        collect_functions(source)
        rebound_names(source)


def test_no_module_of_the_gate_defines_a_function_twice(gate):
    """A second definition silently replaces the first for the whole module, as R6-M1 did."""
    for path in sorted((gate.root / "gate").glob("*.py")):
        names = [node.name for node in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        assert len(names) == len(set(names)), f"{path.name}: {sorted(name for name in names if names.count(name) > 1)}"


# G-4: a byte-order mark.

BOM = "\ufeff"


def test_a_test_file_with_a_mark_stays_under_the_rules(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": BOM + TEST})
    world.write({"tests/test_a.py": BOM + "from app import add\n\n\ndef test_add():\n    pass\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_WEAKENED", "tests/test_a.py") in rules_of(guard)


def test_a_test_taken_from_a_file_with_a_mark_is_seen(gate, tmp_path):
    world = World(gate, tmp_path, {"app.py": GOOD, "tests/test_a.py": BOM + TEST})
    world.write({"tests/test_a.py": BOM + "x = 1\n"})
    world.commit()
    code, guard = world.guard()
    assert code == 1
    assert ("TEST_DELETED", "tests/test_a.py") in rules_of(guard)


def test_adding_a_mark_to_a_clean_file_is_no_refusal(world):
    world.write({"tests/test_a.py": BOM + TEST})
    world.commit()
    clean(world)


def test_the_collected_ids_read_a_file_with_a_mark(gate):
    sys.path.insert(0, str(gate.root))
    try:
        from gate.collected import ids_in_source
    finally:
        sys.path.remove(str(gate.root))
    assert ids_in_source(BOM + TEST, "tests/test_a.py") == ids_in_source(TEST, "tests/test_a.py") != set()


# R-12: the JUnit file decides too.

PASSED = '<testsuite><testcase classname="tests.test_a" name="test_add"/></testsuite>'
FAILED = '<testsuite><testcase classname="tests.test_a" name="test_add"><failure message="x"/></testcase></testsuite>'
ERRORED = '<testsuite><testcase classname="tests.test_a" name="test_add"><error message="x"/></testcase></testsuite>'
SKIPPED = '<testsuite><testcase classname="tests.test_a" name="test_add"><skipped message="x"/></testcase></testsuite>'


def run_check(gate, tmp_path: Path, command: list[str]) -> subprocess.CompletedProcess:
    quoted = ", ".join(f"'''{part}'''" for part in command)
    config = tmp_path / "quality.toml"
    config.write_text(f'[checks."gate/tests"]\nclass = "mandatory"\ncommands = [[{quoted}]]\njunit = "junit.xml"\n', encoding="utf-8")
    return gate.run("run_checks", "--config", config, "--check", "gate/tests", "--out", tmp_path / "out", "--workdir", tmp_path)


@pytest.mark.parametrize(("xml", "expected"), [(PASSED, 0), (SKIPPED, 0), (FAILED, 1), (ERRORED, 1)], ids=["passed", "skipped", "failed", "error"])
def test_the_junit_file_decides_when_the_command_exits_0(gate, tmp_path, xml, expected):
    source = tmp_path / "given.xml"
    source.write_text(xml, encoding="utf-8")
    process = run_check(gate, tmp_path, [sys.executable, "-c", "import shutil,sys; shutil.copy(sys.argv[1], sys.argv[2])", str(source), "{raw}/junit.xml"])
    assert process.returncode == expected, process.stdout + process.stderr


def test_pytest_exit_with_code_0_cannot_turn_a_check_green(gate, tmp_path):
    write_tests = tmp_path / "tests"
    write_tests.mkdir()
    (tmp_path / "app.py").write_text(BAD, encoding="utf-8")
    (write_tests / "test_a.py").write_text(TEST, encoding="utf-8")
    (write_tests / "test_zzz.py").write_text("import pytest\n\n\ndef test_zzz():\n    pytest.exit('done', returncode=0)\n", encoding="utf-8")
    bare = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"], cwd=tmp_path, capture_output=True, check=False)
    assert bare.returncode == 0, "this attack must work, or the test proves nothing"
    process = run_check(gate, tmp_path, [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests", "--junitxml={raw}/junit.xml"])
    assert process.returncode == 1, process.stdout + process.stderr


# X-0a and X-0b: a rerun takes no secrets.


def load_reproduce(gate):
    sys.path.insert(0, str(gate.root))
    try:
        from gate import reproduce
    finally:
        sys.path.remove(str(gate.root))
    return reproduce


@pytest.mark.parametrize(
    "url",
    [
        "https://x-access-token:SECRET-VALUE@github.com/o/n.git",
        "https://SECRET-VALUE@github.com/o/n.git",
        "HTTP://u:SECRET-VALUE@example.com/o/n",
        "ssh://u:SECRET-VALUE@example.com/o/n",
        "ftp://u:SECRET-VALUE@example.com/o/n",
        "https://example.com/o/n?token=SECRET-VALUE",
    ],
)
def test_a_credential_in_the_url_exits_2_before_anything_runs(gate, tmp_path, url):
    out = tmp_path / "out"
    process = gate.run("reproduce", "--repo", url, "--sha", "1" * 40, "--out", out)
    assert process.returncode == 2
    assert "credential" in process.stderr
    assert "SECRET-VALUE" not in process.stdout + process.stderr
    assert not out.exists()


@pytest.mark.parametrize(
    "url",
    ["https://github.com/o/n.git", "git@github.com:o/n.git", "ssh://git@github.com/o/n.git", "/srv/git/o/n.git", r"C:\repos\n", "file:///srv/git/n.git"],
)
def test_a_url_with_no_credential_is_taken(gate, url):
    assert load_reproduce(gate).holds_a_credential(url) is False


def test_a_url_that_cannot_be_read_counts_as_holding_one(gate):
    assert load_reproduce(gate).holds_a_credential("https://[bad/o/n") is True


def test_an_empty_secret_variable_is_no_secret(gate, tmp_path):
    process = gate.run("reproduce", "--repo", tmp_path / "missing", "--sha", "1" * 40, "--out", tmp_path / "out", env=gate.env(GATE_TOKEN=""))
    assert process.returncode == 2
    assert "unset" not in process.stderr


def test_make_reproduce_passes_no_token_into_the_container(gate):
    assert "GATE_TOKEN" not in (gate.root / "Makefile").read_text(encoding="utf-8")
