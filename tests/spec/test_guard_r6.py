"""gate.guard after the CEO's answer of round 5 (HQ-ANSWERS-07): G-1d (any spelling of a path name, a `.gitmodules` that hides
nothing), G-1e (encoding), G-1f (no source to read), G-1g (new top-level names), G-1h (standing in for the application), G-1i
(plugins by name) and the longer G-4.

One case per way of breaking a rule, and a control for each family. Where many ways differ only by a name from a list, they go
into one commit and the test says which names were not reported.

Entries that must have an odd name, a mode of their own, or no working-tree file are written with git plumbing:
`git hash-object -w --stdin` and `git update-index -z --index-info` (bytes that are not UTF-8 cannot be given on a command line
here). This machine's git has `core.protectNTFS=true`, which refuses a path such as `:colon` without a word, so every
repository of this file sets `core.protectNTFS=false` and `core.protectHFS=false`, and each helper checks that the entry is in
the index. The guard reads git's objects, so the working tree does not matter.
"""
from __future__ import annotations

import sys

import pytest

from gatekit import assert_no_traceback, assert_rc, run_git
from guardkit import Case, assert_clean, assert_fires, of, rules
from test_guard_r5 import (AI, BIND, BIND_BASE, EXCEPT_AS, GITLINK, SHA_ONE, SHA_TWO, SPEC, at_the_end, bound_case,
                           in_the_class, spec_bound_case, submodule, symlink)

ZERO = "0" * 40
TESTFILE = "def test_one():\n    assert 1 + 1 == 2\n"
VALUE_PY = "VALUE = 1\n"


# ----------------------------------------------------------------------------- git plumbing helpers


def as_bytes(path):
    return path if isinstance(path, bytes) else path.encode("utf-8")


def plain(content, mode="100644"):
    return (mode, content if isinstance(content, bytes) else content.encode("utf-8"))


def plumb(repo, entries, deletes=()):
    """Write index entries, `{path: (mode, payload)}`, in one `update-index -z --index-info`, then check that each is there."""
    blobs, records = {}, []
    for path, (mode, payload) in entries.items():
        if mode == GITLINK:
            sha = payload
        else:
            if payload not in blobs:
                blobs[payload] = run_git(repo.path, "hash-object", "-w", "--stdin", input_bytes=payload).stdout.decode().strip()
            sha = blobs[payload]
        records.append(f"{mode} {sha}\t".encode() + as_bytes(path) + b"\0")
    for path in deletes:
        records.append(f"0 {ZERO}\t".encode() + as_bytes(path) + b"\0")
    if records:
        run_git(repo.path, "update-index", "--add", "-z", "--index-info", input_bytes=b"".join(records))
    listed = run_git(repo.path, "ls-files", "-z", "--stage").stdout
    for path in entries:
        assert b"\t" + as_bytes(path) + b"\0" in listed, f"test setup: git did not take the path {path!r}"
    for path in deletes:
        assert b"\t" + as_bytes(path) + b"\0" not in listed, f"test setup: git kept the path {path!r}"


def start(tmp_path, baseline, branch, *, files=None, entries=None, writes=None):
    """A case whose base already holds `files` (index only), `entries` (any mode) and `writes` (also in the working tree)."""
    case = Case(tmp_path, baseline, branch=branch)
    case.repo.git("config", "core.protectNTFS", "false")
    case.repo.git("config", "core.protectHFS", "false")
    if files or entries or writes:
        for path, content in (writes or {}).items():
            case.repo.write(path, content)
            case.repo.git("add", "--", path)
        plumb(case.repo, {**{p: plain(c) for p, c in (files or {}).items()}, **(entries or {})})
        case.repo.commit("base", stage_all=False)
        case.base = case.head = case.repo.sha()
    return case


def change(case, *, files=None, entries=None, deletes=(), writes=None):
    for path, content in (writes or {}).items():
        case.repo.write(path, content)
        case.repo.git("add", "--", path)
    plumb(case.repo, {**{p: plain(c) for p, c in (files or {}).items()}, **(entries or {})}, deletes)
    case.head = case.repo.commit("change", stage_all=False)


def paths_of(d, rule="PROTECTED_PATH"):
    return [v["path"] for v in of(d, rule)]


def assert_refused_paths(res, d, paths):
    assert_rc(res, 1)
    assert_no_traceback(res)
    got = set(paths_of(d))
    missing = [p for p in paths if p not in got]
    assert not missing, f"PROTECTED_PATH not reported for {missing}; reported {sorted(got)[:12]}"


def assert_refused_like(res, d, *fragments):
    """For a name whose spelling in the report is not fixed by the contract: some reported path holds each fragment."""
    assert_rc(res, 1)
    assert_no_traceback(res)
    got = paths_of(d)
    missing = [f for f in fragments if not any(f in p for p in got)]
    assert not missing, f"no PROTECTED_PATH for a path with {missing}; reported {got}"


# ----------------------------------------------------------------------------- G-1d: any spelling of a path name

LINK_ENTRY = symlink("app.py")
ENTRY_OF = {"link": LINK_ENTRY, "submodule": submodule()}
ODD_SINGLE = {
    "a-leading-colon": (":colon.py", "colon.py"),
    "bytes-that-are-not-utf8": (b"src/caf\xe9.py", "caf"),
    "a-newline-in-the-name": ("src/line\nbreak.py", "break.py"),
}
ODD_GROUP = {   # name -> a fragment that the reported path must hold
    ":(top)magic.py": "magic",
    "src/café.py": "caf",
    'src/quo"te.py': "quo",
    "src/with space.py": "with space",
    "-dash.py": "dash",
    "src/glob[1]*.py": "glob",
}


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("kind", ["link", "submodule"])
@pytest.mark.parametrize("name", list(ODD_SINGLE))
def test_g1d_a_link_or_a_submodule_under_an_odd_path_name_is_refused(tmp_path, baseline, name, kind):
    path, fragment = ODD_SINGLE[name]
    case = start(tmp_path, baseline, AI)
    change(case, entries={path: ENTRY_OF[kind]})
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_refused_like(res, d, fragment)


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("kind", ["link", "submodule"])
def test_g1d_the_other_odd_spellings_of_a_path_name_are_seen_too(tmp_path, baseline, kind):
    case = start(tmp_path, baseline, AI)
    change(case, entries={path: ENTRY_OF[kind] for path in ODD_GROUP})
    res, d = case.run()
    assert_refused_like(res, d, *ODD_GROUP.values())


SPEC_ODD = {"acceptance/raw\xe9.dat".encode("latin-1"): "raw", "acceptance/line\nbreak": "break", "acceptance/unié": "uni"}


@pytest.mark.req("G-1d")
@pytest.mark.parametrize("kind", ["link", "submodule"])
def test_g1d_odd_path_names_under_acceptance_are_seen_in_a_spec_pr(tmp_path, baseline, kind):
    case = start(tmp_path, baseline, SPEC)
    change(case, entries={path: ENTRY_OF[kind] for path in SPEC_ODD})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_refused_like(res, d, *SPEC_ODD.values())


GITMODULES_HIDING = '[submodule "lib"]\n\tpath = vendor/lib\n\turl = https://example.invalid/lib.git\n\tignore = all\n'


@pytest.mark.req("G-1d")
def test_g1d_a_gitmodules_with_ignore_all_in_the_same_pr_does_not_hide_a_submodule(tmp_path, baseline):
    # git's own diff leaves such a submodule out of its output when .gitmodules says ignore = all
    case = start(tmp_path, baseline, AI)
    change(case, writes={".gitmodules": GITMODULES_HIDING}, entries={"vendor/lib": submodule()})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "vendor/lib")


@pytest.mark.req("G-1d")
def test_g1d_a_gitmodules_with_ignore_all_that_the_base_has_does_not_hide_a_new_submodule(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, writes={".gitmodules": GITMODULES_HIDING})
    change(case, entries={"vendor/lib": submodule()})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "vendor/lib")


@pytest.mark.req("G-1d")
def test_g1d_a_gitmodules_with_ignore_all_does_not_hide_a_submodule_that_is_pointed_somewhere_else(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, writes={".gitmodules": GITMODULES_HIDING}, entries={"vendor/lib": submodule(SHA_ONE)})
    change(case, entries={"vendor/lib": submodule(SHA_TWO)})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "vendor/lib")


@pytest.mark.req("G-1d")
def test_g1d_control_a_submodule_beside_a_gitmodules_with_ignore_all_that_the_pr_leaves_alone_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, writes={".gitmodules": GITMODULES_HIDING}, entries={"vendor/lib": submodule()})
    change(case, files={"README.md": "# changed\n"})
    res, d = case.run()
    assert_clean(res, d)


ODD_IN_THE_BASE = {":colon.py": LINK_ENTRY, b"src/caf\xe9.py": LINK_ENTRY, "src/line\nbreak.py": LINK_ENTRY, "vendor/lib": submodule()}


@pytest.mark.req("G-1d")
def test_g1d_control_odd_named_links_and_submodules_already_in_the_base_and_left_alone_are_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, entries=ODD_IN_THE_BASE)
    change(case, files={"README.md": "# changed\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1d")
def test_g1d_control_deleting_odd_named_links_and_submodules_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, entries=ODD_IN_THE_BASE)
    change(case, deletes=list(ODD_IN_THE_BASE))
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1d")
def test_g1d_control_plain_files_under_the_same_odd_names_are_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={":colon.py": VALUE_PY, b"src/caf\xe9.py": VALUE_PY, "src/line\nbreak.py": VALUE_PY, "src/café.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-1e: an encoding other than UTF-8

BODY = b"VALUE = 1\n"
TEST_BODY = b"def test_enc():\n    assert 1 + 1 == 2\n"


def committed(tmp_path, baseline, files, branch=AI, base=None):
    case = Case(tmp_path, baseline, branch=branch, base_edits=base)
    case.change(files)
    return case.run()


@pytest.mark.req("G-1e")
def test_g1e_another_encoding_on_the_first_line_is_refused_in_application_code_and_in_a_test_file(tmp_path, baseline):
    files = {"src/enc.py": b"# -*- coding: latin-1 -*-\n" + BODY, "tests/test_enc.py": b"# coding: latin-1\n" + TEST_BODY}
    res, d = committed(tmp_path, baseline, files)
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1e")
def test_g1e_another_encoding_on_the_second_line_is_refused(tmp_path, baseline):
    # python reads the second line when the first is blank or a comment: a shebang, or any comment
    files = {"src/enc.py": b"#!/usr/bin/env python\n# coding: cp1252\n" + BODY,
             "tests/test_enc.py": b"# header\n# -*- coding: iso-8859-15 -*-\n" + TEST_BODY}
    res, d = committed(tmp_path, baseline, files)
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1e")
def test_g1e_an_encoding_python_does_not_know_is_refused_on_either_line(tmp_path, baseline):
    files = {"src/enc.py": b"# coding: no-such-codec\n" + BODY, "tests/test_enc.py": b"#!/usr/bin/env python\n# coding=made-up-8\n" + TEST_BODY}
    res, d = committed(tmp_path, baseline, files)
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1e")
def test_g1e_other_spellings_of_a_declaration_and_real_bytes_of_another_encoding_are_refused(tmp_path, baseline):
    files = {
        "src/modeline.py": b"# vim: set fileencoding=utf-16 :\n" + BODY,                       # not utf-8, in a modeline
        "src/with_bom.py": b"\xef\xbb\xbf# coding: latin-1\n" + BODY,                           # a BOM and another encoding: python refuses
        "src/real_bytes.py": b"# coding: latin-1\nNAME = 'caf\xe9'\n",                          # the bytes really are latin-1
    }
    res, d = committed(tmp_path, baseline, files)
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1e")
def test_g1e_a_changed_file_that_declares_another_encoding_is_refused_even_if_it_declared_it_before(tmp_path, baseline):
    path = "src/enc.py"
    res, d = committed(tmp_path, baseline, {path: b"# coding: latin-1\nVALUE = 2\n"}, base={path: b"# coding: latin-1\nVALUE = 1\n"})
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1e", "G-11a")
def test_g1e_an_acceptance_test_that_declares_another_encoding_is_refused_in_a_spec_pr(tmp_path, baseline):
    path = "acceptance/test_enc.py"
    res, d = committed(tmp_path, baseline, {path: b"# coding: latin-1\n" + TEST_BODY}, branch=SPEC)
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", path)


USUAL_UTF8 = [
    b"# -*- coding: utf-8 -*-", b"# coding=utf-8", b"# coding: UTF-8", b"# coding: utf8", b"# coding: utf_8",
    b"# vim: set fileencoding=utf-8 :", b"#!/usr/bin/env python\n# coding: utf-8",
]


@pytest.mark.req("G-1e")
def test_g1e_control_utf8_in_its_usual_spellings_is_no_violation(tmp_path, baseline):
    files = {f"src/utf8_{i}.py": decl + b"\nNAME = 'caf\xc3\xa9'\n" for i, decl in enumerate(USUAL_UTF8)}
    files["src/utf8_bom.py"] = b"\xef\xbb\xbf# coding: utf-8\n" + BODY
    res, d = committed(tmp_path, baseline, files)
    assert_clean(res, d)


UNREAD = {   # python reads a declaration only on the first line, or on the second when the first is blank or a comment
    "src/third_line.py": b"\n\n# coding: latin-1\n" + BODY,
    "src/after_code.py": b"VALUE = 1\n# coding: latin-1\n",
    "src/trailing_comment.py": b"VALUE = 1  # coding: latin-1\n",
    "src/in_a_docstring.py": b'"""\ncoding: latin-1\n"""\nVALUE = 1\n',
    "src/no_colon.py": b"# coding latin-1\n" + BODY,
}


@pytest.mark.req("G-1e")
def test_g1e_control_a_declaration_that_python_would_not_read_is_no_violation(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, UNREAD)
    assert_clean(res, d)


@pytest.mark.req("G-1e")
def test_g1e_control_a_file_that_is_not_python_may_say_anything_about_encodings(tmp_path, baseline):
    text = b"# coding: latin-1\nplain text\n"
    res, d = committed(tmp_path, baseline, {"docs/notes.txt": text, "docs/readme.md": text, "config/settings.cfg": text, "data/cases.json": b"{}\n"})
    assert_clean(res, d)


@pytest.mark.req("G-1e")
def test_g1e_control_a_file_that_declared_another_encoding_in_the_base_and_is_left_alone_is_no_violation(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, {"README.md": "# changed\n"}, base={"src/enc.py": b"# coding: latin-1\nVALUE = 1\n"})
    assert_clean(res, d)


@pytest.mark.req("G-1e")
def test_g1e_control_a_file_whose_head_declares_nothing_other_than_utf8_is_no_violation(tmp_path, baseline):
    path = "src/enc.py"
    res, d = committed(tmp_path, baseline, {path: b"# coding: utf-8\nVALUE = 2\n"}, base={path: b"# coding: latin-1\nVALUE = 1\n"})
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-1f: no source to read

SUFFIXES = ["x.pyc", "x.pyo", "x.so", "x.pyd"]
FOLDERS = {
    "pycache": "__pycache__/x.txt",
    "dist-info": "pkg.dist-info/METADATA",
    "egg-info": "pkg.egg-info/entry_points.txt",
    "egg": "pkg.egg/EGG-INFO/PKG-INFO",
}
BINARY = b"\x00\x01binary\x02"


@pytest.mark.req("G-1f")
@pytest.mark.parametrize("name", SUFFIXES)
def test_g1f_a_file_with_a_compiled_suffix_is_refused_in_the_root_and_in_a_subfolder(tmp_path, baseline, name):
    paths = [name, "sub/" + name, "src/deep/" + name]
    res, d = committed(tmp_path, baseline, {p: BINARY for p in paths})
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1f")
@pytest.mark.parametrize("folder", list(FOLDERS))
def test_g1f_a_file_under_a_cache_or_metadata_folder_is_refused_in_the_root_and_in_a_subfolder(tmp_path, baseline, folder):
    paths = [FOLDERS[folder], "sub/" + FOLDERS[folder]]
    res, d = committed(tmp_path, baseline, {p: BINARY for p in paths})
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1f")
def test_g1f_a_changed_compiled_file_is_refused(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, {"build/x.pyc": BINARY + b"2"}, base={"build/x.pyc": BINARY})
    assert_fires(res, d, "PROTECTED_PATH", "build/x.pyc")


@pytest.mark.req("G-1f", "G-11a")
def test_g1f_compiled_files_and_caches_under_acceptance_are_refused_in_a_spec_pr(tmp_path, baseline):
    paths = ["acceptance/x.pyc", "acceptance/__pycache__/test_x.cpython-313.pyc", "acceptance/pkg.dist-info/METADATA"]
    res, d = committed(tmp_path, baseline, {p: BINARY for p in paths}, branch=SPEC)
    assert d["kind"] == "spec"
    assert_refused_paths(res, d, paths)


LOOK_ALIKES = ["pyc", "x.pyc.txt", "data.pycx", "lib.sox", "x.pydx", "soup.py", "__pycache__x/file.txt", "my__pycache__/file.txt",
               "dist-info/METADATA", "pkg.dist-infos/x.txt", "egg/x.txt", "pkg.eggs/x.txt", "pkg.egg-info.bak/x.txt"]


@pytest.mark.req("G-1f")
def test_g1f_control_names_that_only_look_like_the_named_ones_are_no_violation(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, {p: BINARY for p in LOOK_ALIKES})
    assert_clean(res, d)


@pytest.mark.req("G-1f")
def test_g1f_control_deleting_compiled_files_and_metadata_is_no_violation(tmp_path, baseline):
    base = {"build/x.pyc": BINARY, "pkg.egg-info/PKG-INFO": BINARY, "src/__pycache__/app.cpython-313.pyc": BINARY}
    res, d = committed(tmp_path, baseline, {p: None for p in base}, base=base)
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-1g: new top-level names

STDLIB = sorted(sys.stdlib_module_names)    # the pinned Python is the one that runs these tests
TOOLS = ["pytest", "_pytest", "pluggy", "iniconfig", "packaging", "pygments", "colorama", "tomli", "exceptiongroup"]


@pytest.mark.req("G-1g")
def test_g1g_a_new_top_level_file_named_like_a_module_of_the_standard_library_is_refused_for_every_such_module(tmp_path, baseline):
    paths = [f"{name}.py" for name in STDLIB]
    case = start(tmp_path, baseline, AI)
    change(case, files={p: VALUE_PY for p in paths})
    res, d = case.run()
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1g")
def test_g1g_a_new_top_level_package_named_like_a_module_of_the_standard_library_is_refused_for_every_such_module(tmp_path, baseline):
    paths = [f"{name}/__init__.py" for name in STDLIB]
    case = start(tmp_path, baseline, AI)
    change(case, files={p: "" for p in paths})
    res, d = case.run()
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1g")
@pytest.mark.parametrize("shape", ["file", "package"])
def test_g1g_a_new_top_level_name_of_a_tool_the_gate_runs_is_refused(tmp_path, baseline, shape):
    paths = [f"{name}.py" if shape == "file" else f"{name}/__init__.py" for name in TOOLS]
    case = start(tmp_path, baseline, AI)
    change(case, files={p: VALUE_PY for p in paths})
    res, d = case.run()
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1g", "G-11")
def test_g1g_a_new_top_level_stand_in_is_refused_in_a_spec_pr_too(tmp_path, baseline):
    case = start(tmp_path, baseline, SPEC)
    change(case, files={"os.py": VALUE_PY})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", "os.py")


@pytest.mark.req("G-1g")
def test_g1g_control_a_top_level_name_that_the_base_already_has_is_no_violation(tmp_path, baseline):
    base = {"json.py": VALUE_PY, "logging/__init__.py": "", "tomli.py": VALUE_PY}
    case = start(tmp_path, baseline, AI, files=base)
    change(case, files={"json.py": "VALUE = 2\n", "logging/__init__.py": "VALUE = 2\n", "tomli.py": "VALUE = 2\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
def test_g1g_control_a_folder_with_no_init_py_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={"os/readme.txt": "x\n", "json/data.py": VALUE_PY, "pluggy/notes.txt": "x\n", "logging/config_data.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
def test_g1g_control_other_top_level_names_are_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={"requests.py": VALUE_PY, "yaml.py": VALUE_PY, "numpy/__init__.py": "", "myapp.py": VALUE_PY, "six.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
def test_g1g_control_a_module_that_is_not_top_level_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={"app/os.py": VALUE_PY, "app/json/__init__.py": "", "docs/pluggy.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
@pytest.mark.parametrize("direction", ["a-file-turned-into-a-package", "a-package-turned-into-a-file"])
def test_g1g_control_a_module_the_base_has_in_the_other_shape_is_no_violation(tmp_path, baseline, direction):
    # "a module's name the base already has at the top level, as a file or as a package": the name is what counts
    if direction == "a-file-turned-into-a-package":
        case = start(tmp_path, baseline, AI, files={"json.py": VALUE_PY})
        change(case, files={"json/__init__.py": ""}, deletes=["json.py"])
    else:
        case = start(tmp_path, baseline, AI, files={"logging/__init__.py": ""})
        change(case, files={"logging.py": VALUE_PY}, deletes=["logging/__init__.py"])
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
def test_g1g_control_a_package_added_beside_a_file_of_the_same_name_the_base_has_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"json.py": VALUE_PY})
    change(case, files={"json/__init__.py": ""})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1g")
def test_g1g_the_name_the_base_has_excuses_only_that_name(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"json.py": VALUE_PY})
    change(case, files={"json/__init__.py": "", "logging/__init__.py": ""})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "logging/__init__.py")
    assert "json/__init__.py" not in paths_of(d)


# ----------------------------------------------------------------------------- G-1h: standing in for the application

H_FIRE = {   # base files, head files, the path that must be reported
    "a-module-named-like-a-module-under-src": ({}, {"tests/app.py": VALUE_PY}, "tests/app.py"),
    "a-package-named-like-a-module-under-src": ({}, {"tests/app/__init__.py": ""}, "tests/app/__init__.py"),
    "a-module-named-like-a-module-in-the-root": ({"rootmod.py": VALUE_PY}, {"tests/rootmod.py": VALUE_PY}, "tests/rootmod.py"),
    "a-module-named-like-a-package-under-src": ({"src/appkg/__init__.py": ""}, {"tests/appkg.py": VALUE_PY}, "tests/appkg.py"),
    "a-module-of-the-standard-library": ({}, {"tests/os.py": VALUE_PY}, "tests/os.py"),
    "a-package-of-the-standard-library": ({}, {"tests/json/__init__.py": ""}, "tests/json/__init__.py"),
    "pytest-itself": ({}, {"tests/pytest.py": VALUE_PY}, "tests/pytest.py"),
    "a-package-of-a-tool": ({}, {"tests/tomli/__init__.py": ""}, "tests/tomli/__init__.py"),
    "a-deeper-test-folder": ({"tests/unit/test_unit.py": TESTFILE}, {"tests/unit/app.py": VALUE_PY}, "tests/unit/app.py"),
    "a-folder-that-holds-a-test-file-and-is-not-called-tests": ({"checks/test_foo.py": TESTFILE}, {"checks/util.py": VALUE_PY}, "checks/util.py"),
    "a-module-that-the-same-pr-adds-to-the-application": ({}, {"src/newmod.py": VALUE_PY, "tests/newmod.py": VALUE_PY}, "tests/newmod.py"),
}


@pytest.mark.req("G-1h")
@pytest.mark.parametrize("what", list(H_FIRE))
def test_g1h_a_new_module_in_a_test_folder_that_stands_in_for_another_is_refused(tmp_path, baseline, what):
    base, head, flagged = H_FIRE[what]
    case = start(tmp_path, baseline, AI, files=base)
    change(case, files=head)
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_fires(res, d, "PROTECTED_PATH", flagged)


H_SPEC = {
    "a-module-named-like-a-module-under-src": "acceptance/app.py",
    "a-module-of-the-standard-library-in-a-folder-under-acceptance": "acceptance/sub/os.py",
    "a-package-named-like-a-module-under-src": "acceptance/app/__init__.py",
}


@pytest.mark.req("G-1h", "G-11a")
def test_g1h_a_module_under_acceptance_that_stands_in_for_another_is_refused_in_a_spec_pr(tmp_path, baseline):
    case = start(tmp_path, baseline, SPEC)
    change(case, files={path: VALUE_PY for path in H_SPEC.values()})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_refused_paths(res, d, list(H_SPEC.values()))


@pytest.mark.req("G-1h")
def test_g1h_control_other_names_in_a_test_folder_are_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    # (no tests/__init__.py here: a package is never stood in for, so it would make this control pass whatever the names)
    change(case, files={"tests/helpers_extra.py": VALUE_PY, "tests/mytools/__init__.py": ""})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_control_a_folder_that_holds_no_tests_is_no_violation(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={"docs/app.py": VALUE_PY, "tools/os.py": VALUE_PY, "tools/pytest.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h", "G-1c")
def test_g1h_control_conftest_is_no_such_name(tmp_path, baseline):
    case = start(tmp_path, baseline, AI)
    change(case, files={"tests/conftest.py": "import pytest\n", "tests/unit/conftest.py": "import pytest\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_control_a_shadow_that_the_base_already_has_and_the_pr_changes_is_no_new_file(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"tests/app.py": VALUE_PY})
    change(case, files={"tests/app.py": "VALUE = 2\n"})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_control_the_root_and_src_are_not_the_folders_the_rule_means_even_when_they_hold_a_test(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"test_root.py": TESTFILE, "src/test_inline.py": TESTFILE})
    change(case, files={"rootmod2.py": VALUE_PY, "src/newmod2.py": VALUE_PY, "app.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_control_a_module_of_the_application_that_is_not_top_level_cannot_be_stood_in_for_by_name(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"src/pkg/inner.py": VALUE_PY})
    change(case, files={"tests/inner.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


PACKAGE_MODULES = {"the application": "app", "the standard library": "os", "a tool": "pluggy"}


@pytest.mark.req("G-1h")
@pytest.mark.parametrize("shape", ["module", "package"])
def test_g1h_control_a_test_folder_that_is_a_package_cannot_be_stood_in_for_by_a_new_module_or_package(tmp_path, baseline, shape):
    # pytest puts a test's folder first on the path unless the folder is a package
    case = start(tmp_path, baseline, AI, files={"pack/__init__.py": "", "pack/test_pack.py": TESTFILE})
    change(case, files={f"pack/{name}.py" if shape == "module" else f"pack/{name}/__init__.py": VALUE_PY
                        for name in PACKAGE_MODULES.values()})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_control_an_init_py_that_the_same_pr_adds_makes_the_folder_a_package_in_the_head(tmp_path, baseline):
    # a reading: "has no __init__.py" is judged on the head, like the application's modules
    case = start(tmp_path, baseline, AI, files={"pack/test_pack.py": TESTFILE})
    change(case, files={"pack/__init__.py": "", "pack/app.py": VALUE_PY})
    res, d = case.run()
    assert_clean(res, d)


@pytest.mark.req("G-1h")
def test_g1h_the_same_new_module_is_refused_in_a_folder_with_no_init_py_and_not_in_one_with_it(tmp_path, baseline):
    case = start(tmp_path, baseline, AI, files={"pack/__init__.py": "", "pack/test_pack.py": TESTFILE, "plain/test_plain.py": TESTFILE})
    change(case, files={"pack/app.py": VALUE_PY, "plain/app.py": VALUE_PY})
    res, d = case.run()
    assert_fires(res, d, "PROTECTED_PATH", "plain/app.py")
    assert "pack/app.py" not in paths_of(d)


@pytest.mark.req("G-1h", "G-11a")
def test_g1h_acceptance_is_a_package_in_the_base_so_only_the_folder_without_init_py_below_it_is_refused(tmp_path, baseline):
    case = start(tmp_path, baseline, SPEC, files={"acceptance/__init__.py": ""})
    change(case, files={"acceptance/app.py": VALUE_PY, "acceptance/sub/os.py": VALUE_PY})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", "acceptance/sub/os.py")
    assert "acceptance/app.py" not in paths_of(d)


# ----------------------------------------------------------------------------- G-1i: plugins by name

STAR = "from os.path import *"
PLUGIN_WAYS = {
    "an-assignment-of-a-list": 'pytest_plugins = ["example.plugin"]',
    "an-assignment-of-a-string": 'pytest_plugins = "example.plugin"',
    "an-annotated-assignment": 'pytest_plugins: list = ["example.plugin"]',
    "an-import": "from example_plugins import pytest_plugins",
    "an-import-as": "from example_plugins import plugins as pytest_plugins",
    "a-loop": 'for pytest_plugins in [["example.plugin"]]:\n    pass',
    "a-class": "class pytest_plugins:\n    pass",
    "except-as": EXCEPT_AS.format(name="pytest_plugins"),
    "a-match-pattern": 'match ["example.plugin"]:\n    case pytest_plugins:\n        pass',
    "a-walrus-in-a-comprehension": 'values = [(pytest_plugins := ["example.plugin"]) for _ in range(1)]',
    "a-global-in-a-function": 'def setup():\n    global pytest_plugins\n    pytest_plugins = ["example.plugin"]',
    "an-assignment-inside-an-if": 'if True:\n    pytest_plugins = ["example.plugin"]',
}


@pytest.mark.req("G-1i")
def test_g1i_pytest_plugins_added_in_any_way_g4_lists_is_refused(tmp_path, baseline):
    files = {f"src/plug_{i}.py": VALUE_PY + snippet + "\n" for i, snippet in enumerate(PLUGIN_WAYS.values())}
    case = start(tmp_path, baseline, AI)
    change(case, files=files)
    res, d = case.run()
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1i")
def test_g1i_pytest_plugins_extended_in_place_is_a_changed_binding(tmp_path, baseline):
    path = "src/plug.py"
    res, d = committed(tmp_path, baseline, {path: b'pytest_plugins = []\npytest_plugins += ["example.plugin"]\n'},
                       base={path: b"pytest_plugins = []\n"})
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1i")
def test_g1i_pytest_plugins_changed_is_refused(tmp_path, baseline):
    path = "src/plug.py"
    res, d = committed(tmp_path, baseline, {path: b'pytest_plugins = ["a", "b"]\n'}, base={path: b'pytest_plugins = ["a"]\n'})
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1i", "G-1c")
def test_g1i_pytest_plugins_in_a_new_conftest_is_refused_although_a_conftest_alone_is_only_marked(tmp_path, baseline):
    path = "tests/conftest.py"
    res, d = committed(tmp_path, baseline, {path: b'pytest_plugins = ["example.plugin"]\n'})
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1i", "G-11a")
def test_g1i_pytest_plugins_in_an_init_py_under_acceptance_is_refused_in_a_spec_pr(tmp_path, baseline):
    paths = ["acceptance/__init__.py", "acceptance/sub/__init__.py"]
    res, d = committed(tmp_path, baseline, {p: b'pytest_plugins = ["example.plugin"]\n' for p in paths}, branch=SPEC)
    assert d["kind"] == "spec"
    assert_refused_paths(res, d, paths)


@pytest.mark.req("G-1i")
def test_g1i_a_new_star_import_in_a_test_file_is_refused(tmp_path, baseline):
    files = {"tests/test_star.py": STAR + "\n\n\n" + TESTFILE, "tests/helpers.py": STAR + "\n", "tests/test_relative.py": "from .helpers import *\n"}
    res, d = committed(tmp_path, baseline, files)
    assert_refused_paths(res, d, list(files))


@pytest.mark.req("G-1i", "G-11a")
def test_g1i_a_new_star_import_under_acceptance_is_refused_in_a_spec_pr_even_in_a_helper(tmp_path, baseline):
    path = "acceptance/helper.py"
    res, d = committed(tmp_path, baseline, {path: (STAR + "\n").encode()}, branch=SPEC)
    assert d["kind"] == "spec"
    assert_fires(res, d, "PROTECTED_PATH", path)


@pytest.mark.req("G-1i")
def test_g1i_control_a_mention_in_a_comment_a_string_or_a_docstring_is_no_violation(tmp_path, baseline):
    text = ('"""Notes: pytest_plugins = ["example.plugin"] would load a plugin."""\n'
            '# pytest_plugins = ["example.plugin"]\n'
            "NOTE = \"pytest_plugins = ['example.plugin']\"\n")
    res, d = committed(tmp_path, baseline, {"src/plug.py": text.encode()})
    assert_clean(res, d)


@pytest.mark.req("G-1i")
def test_g1i_control_a_list_that_the_base_has_and_the_pr_leaves_alone_is_no_violation(tmp_path, baseline):
    path = "src/plug.py"
    res, d = committed(tmp_path, baseline, {path: b'pytest_plugins = ["a"]\nVALUE = 2\n'}, base={path: b'pytest_plugins = ["a"]\nVALUE = 1\n'})
    assert_clean(res, d)


@pytest.mark.req("G-1i")
def test_g1i_control_a_star_import_in_application_code_is_no_violation(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, {"src/star_app.py": (STAR + "\n").encode()})
    assert_clean(res, d)


@pytest.mark.req("G-1i")
def test_g1i_control_a_star_import_that_a_test_file_has_in_the_base_and_the_pr_leaves_alone_is_no_violation(tmp_path, baseline):
    res, d = committed(tmp_path, baseline, {"README.md": "# changed\n"}, base={"tests/test_star_base.py": (STAR + "\n\n\n" + TESTFILE).encode()})
    assert_clean(res, d)


@pytest.mark.req("G-1i")
def test_g1i_control_a_local_name_and_look_alike_names_are_no_violation(tmp_path, baseline):
    text = "def make():\n    pytest_plugins = []\n    return pytest_plugins\n\n\npytest_plugin = ['x']\nplugins = ['x']\n"
    res, d = committed(tmp_path, baseline, {"src/plug.py": text.encode()})
    assert_clean(res, d)


# ----------------------------------------------------------------------------- G-4: the longer list


def rebound(tmp_path, baseline, head, base=BIND_BASE):
    res, d = bound_case(tmp_path, baseline, head, base=base)
    assert d["kind"] == "ai"
    return res, d


NEW_FUNCTION = {
    "a-match-capture-pattern": "match 1:\n    case test_alpha:\n        pass",
    "a-match-as-pattern": "match 1:\n    case 1 as test_alpha:\n        pass",
    "a-walrus-in-a-comprehension": "values = [(test_alpha := i) for i in range(2)]",
    "a-walrus-in-a-default": "def helper(arg=(test_alpha := None)):\n    pass",
    "a-walrus-in-a-decorator": "@(test_alpha := staticmethod)\ndef helper():\n    pass",
    "a-walrus-in-a-classs-bases": "class Helper((test_alpha := object)):\n    pass",
    "a-global-in-a-function": "def helper():\n    global test_alpha\n    test_alpha = None",
    "a-new-star-import": STAR,
    "the-code-of-the-test-replaced": "test_alpha.__code__ = (lambda: None).__code__",
    "an-attribute-of-the-test-set": "test_alpha.__test__ = False",
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(NEW_FUNCTION))
def test_g4_a_test_function_whose_name_is_bound_in_one_of_the_newly_listed_ways_is_a_weakening(tmp_path, baseline, way):
    res, d = rebound(tmp_path, baseline, at_the_end(NEW_FUNCTION[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


NEW_CLASS = {
    "a-match-capture-pattern": "match 1:\n    case TestBeta:\n        pass",
    "a-global-in-a-function": "def helper():\n    global TestBeta\n    TestBeta = None",
    "a-walrus-in-a-comprehension": "values = [(TestBeta := i) for i in range(2)]",
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(NEW_CLASS))
def test_g4_the_name_of_the_class_a_test_stands_in_bound_in_a_newly_listed_way_is_a_weakening(tmp_path, baseline, way):
    res, d = rebound(tmp_path, baseline, at_the_end(NEW_CLASS[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


NEW_METHOD_IN_CLASS = {
    "a-match-capture-pattern-in-the-class": "match 1:\n    case test_one:\n        pass",
    "a-walrus-in-a-default-in-the-class": "def helper(self, arg=(test_one := None)):\n    pass",
    "an-attribute-of-the-test-set-in-the-class": "test_one.__test__ = False",
}


@pytest.mark.req("G-4")
@pytest.mark.parametrize("way", list(NEW_METHOD_IN_CLASS))
def test_g4_a_methods_name_bound_in_a_newly_listed_way_in_its_own_class_is_a_weakening(tmp_path, baseline, way):
    res, d = rebound(tmp_path, baseline, in_the_class(NEW_METHOD_IN_CLASS[way]))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
def test_g4_the_code_of_a_method_replaced_from_outside_its_class_is_a_weakening(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, at_the_end("TestBeta.test_one.__code__ = (lambda self: None).__code__"))
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
@pytest.mark.parametrize("what,old,new", [
    ("an-assignment-replaced-by-another", "test_gamma = pytest.mark.slow(test_gamma)", "test_gamma = None"),
    ("an-import-replaced-by-another", "from os import getcwd as test_gamma", "from os import getpid as test_gamma"),
])
def test_g4_a_binding_that_the_base_has_replaced_by_another_counts_although_the_number_stays_the_same(tmp_path, baseline, what, old, new):
    base = at_the_end(old)
    res, d = rebound(tmp_path, baseline, base.replace(old, new), base=base)
    assert_fires(res, d, "TEST_WEAKENED", BIND)


BOM = b"\xef\xbb\xbf"


@pytest.mark.req("G-4")
def test_g4_a_byte_order_mark_in_the_base_does_not_take_the_file_out_of_the_rules_for_a_new_binding(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, BOM + at_the_end("test_alpha = None").encode(), base=BOM + BIND_BASE.encode())
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
def test_g4_a_byte_order_mark_in_the_base_does_not_take_the_file_out_of_the_rules_for_an_always_true_assert(tmp_path, baseline):
    weakened = BIND_BASE.replace("assert add(0, 0) == 0", "assert True")
    assert weakened != BIND_BASE
    res, d = rebound(tmp_path, baseline, BOM + weakened.encode(), base=BOM + BIND_BASE.encode())
    assert_fires(res, d, "TEST_WEAKENED", BIND)


@pytest.mark.req("G-4")
def test_g4_a_byte_order_mark_that_only_the_head_has_does_not_hide_a_new_binding(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, BOM + at_the_end("test_alpha = None").encode())
    assert_fires(res, d, "TEST_WEAKENED", BIND)


OTHER_NAMES_IN_THE_SAME_FORMS = "\n".join([
    "match 1:\n    case other_name:\n        pass",
    "values = [(other_walrus := i) for i in range(2)]",
    "def helper(arg=(other_default := None)):\n    pass",
    "@(other_decorator := staticmethod)\ndef helper_two():\n    pass",
    "class HelperThree((other_base := object)):\n    pass",
    "def helper_four():\n    global other_global\n    other_global = None",
    "helper_five = lambda: None\nhelper_five.__code__ = (lambda: 1).__code__\nhelper_five.__test__ = False",
])


@pytest.mark.req("G-4")
def test_g4_control_other_names_in_the_newly_listed_forms_are_no_weakening(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, at_the_end(OTHER_NAMES_IN_THE_SAME_FORMS))
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_another_attribute_of_a_class_that_holds_tests_is_no_binding_of_a_test(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, at_the_end("TestBeta.limit = 1"))
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_a_new_method_in_a_class_of_the_base_is_no_weakening(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, in_the_class("def test_three(self):\n    assert add(3, 3) == 6"))
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_a_byte_order_mark_added_to_a_clean_file_is_no_weakening(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, BOM + BIND_BASE.encode())
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4")
def test_g4_control_a_byte_order_mark_in_the_base_does_not_make_a_new_test_a_weakening(tmp_path, baseline):
    res, d = rebound(tmp_path, baseline, BOM + at_the_end("def test_delta():\n    assert add(3, 3) == 6").encode(), base=BOM + BIND_BASE.encode())
    assert "TEST_WEAKENED" not in rules(d), d["violations"]
    assert_clean(res, d)


@pytest.mark.req("G-4", "G-11a")
def test_g4_a_spec_pr_cannot_bind_a_test_name_in_a_newly_listed_way_either(tmp_path, baseline):
    res, d = spec_bound_case(tmp_path, baseline, at_the_end("match 1:\n    case test_alpha:\n        pass"))
    assert d["kind"] == "spec"
    assert_fires(res, d, "TEST_WEAKENED", "acceptance/test_bind.py")


# ----------------------------------------------------------------------------- C-2: a call in any ordinary form is no crash
#
# An expected failure prints a short message and no traceback. The guard reads the code of a test that a PR changes, and a call
# in it can have any ordinary shape: a method of a literal, of a call's result, of a subscript, a call of a call's result, a
# chain that starts at a name, a chain that starts at `self`.

FORMS = "tests/test_forms.py"
CALL_FORMS = {
    "a-method-of-a-literal": '",".join(x)',
    "a-method-of-a-call-result": "make().value()",
    "a-method-of-a-subscript": "items[0].run()",
    "a-call-of-a-call-result": "make()()",
    "a-chain-that-starts-at-a-name": 'Path("x").read_text()',
    "a-chain-that-starts-at-self": 'self.client.get("/").json()',
}
FORMS_TEMPLATE = '''from pathlib import Path


class TestForms:
    def test_form(self):
        x = ["a", "b"]
        items = [object()]
        make = lambda: x
        {call}
        value = {call}
        assert value == {expected}
        assert {call} is not None
'''


def forms(call, expected=1):
    return FORMS_TEMPLATE.format(call=call, expected=expected)


@pytest.mark.req("C-2", "G-4a")
@pytest.mark.parametrize("form", list(CALL_FORMS))
def test_c2_changing_a_test_that_holds_a_call_in_any_ordinary_form_gets_a_normal_answer(tmp_path, baseline, form):
    call = CALL_FORMS[form]
    case = Case(tmp_path, baseline, base_edits={FORMS: forms(call, 1)})
    case.change({FORMS: forms(call, 2)})
    res, d = case.run()
    assert d["kind"] == "ai"
    assert_clean(res, d)    # exit 0, the --out file written, no traceback
    assert any(m["path"] == FORMS and m["name"].endswith("test_form") for m in d["marked_tests"]), d["marked_tests"]


@pytest.mark.req("C-2", "G-11a")
def test_c2_the_same_in_a_spec_pr_under_acceptance_gets_a_normal_answer(tmp_path, baseline):
    path = "acceptance/test_forms.py"
    call = CALL_FORMS["a-chain-that-starts-at-self"]
    case = Case(tmp_path, baseline, branch=SPEC, base_edits={path: forms(call, 1)})
    case.change({path: forms(call, 2)})
    res, d = case.run()
    assert d["kind"] == "spec"
    assert_clean(res, d)
    assert any(m["path"] == path for m in d["marked_tests"]), d["marked_tests"]


@pytest.mark.req("C-2", "G-4")
def test_c2_a_weakened_test_that_holds_such_a_call_still_gets_test_weakened_and_no_traceback(tmp_path, baseline):
    call = CALL_FORMS["a-chain-that-starts-at-self"]
    weakened = forms(call, 1).replace("assert value == 1", "assert True")
    assert weakened != forms(call, 1)
    case = Case(tmp_path, baseline, base_edits={FORMS: forms(call, 1)})
    case.change({FORMS: weakened})
    res, d = case.run()
    assert_fires(res, d, "TEST_WEAKENED", FORMS)
