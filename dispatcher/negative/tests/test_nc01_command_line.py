"""NC-1: the command line. Every usage error exits 2 before any file is read, the log is opened or a request made."""

from __future__ import annotations

import subprocess
import sys

import pytest

from conftest import TOOL_DIR

OPTIONS = ["--case", "--key-file", "--app-file", "--repo", "--base", "--branch", "--log"]


def assert_usage_nothing_done(world, result):
    assert result.code == 2, result.out
    assert result.stop_line.startswith("NEGATIVE USAGE: "), result.out
    assert world.fake.calls == []
    assert not world.log.exists()
    assert not world.log.parent.exists()


def test_nc1_valid_command_line_runs(world):
    result = world.run("N1")
    assert result.code == 0, result.out


@pytest.mark.parametrize("missing", OPTIONS)
def test_nc1_each_option_is_required(world, missing):
    argv = world.argv("N1")
    index = argv.index(missing)
    del argv[index:index + 2]
    assert_usage_nothing_done(world, world.run(argv=argv))


@pytest.mark.parametrize("option", OPTIONS)
def test_nc1_each_option_only_once(world, option):
    argv = world.argv("N1")
    argv += [option, argv[argv.index(option) + 1]]
    assert_usage_nothing_done(world, world.run(argv=argv))


@pytest.mark.parametrize("extra", [["--help"], ["N1"], ["--verbose", "1"], ["--cas", "N1"]])
def test_nc1_no_other_option_or_positional(world, extra):
    assert_usage_nothing_done(world, world.run(argv=world.argv("N1") + extra))


def test_nc1_no_equals_form(world):
    argv = world.argv("N1")
    index = argv.index("--case")
    argv[index:index + 2] = ["--case=N1"]
    assert_usage_nothing_done(world, world.run(argv=argv))


def test_nc1_option_without_value(world):
    argv = world.argv("N1")
    argv.remove(argv[argv.index("--log") + 1])
    assert_usage_nothing_done(world, world.run(argv=argv))


@pytest.mark.parametrize("case", ["N4", "n1", "", "N1 ", "1"])
def test_nc1_case_values(world, case):
    assert_usage_nothing_done(world, world.run("N1", case=case))


@pytest.mark.parametrize("repo", ["demo-stand", "ExampleOrg/", "/demo", "Example Org/demo", "a/b/c", "Org/de mo",
                                  "Org/demo;x"])
def test_nc1_repo_form(world, repo):
    assert_usage_nothing_done(world, world.run("N1", repo=repo))


BAD_REFS = ["", "a" * 201, "has space", "a..b", "/leading", "-leading", "trailing/", "trailing.", "x.lock",
            "double//slash", "semi;colon", "tilde~1", "caret^", "colon:x", "back\\slash", "star*", "q?"]


@pytest.mark.parametrize("value", BAD_REFS)
def test_nc1_branch_form(world, value):
    assert_usage_nothing_done(world, world.run("N1", branch=value))


@pytest.mark.parametrize("value", BAD_REFS)
def test_nc1_base_form(world, value):
    assert_usage_nothing_done(world, world.run("N1", base=value))


@pytest.mark.parametrize("value", ["a" * 200, "ai/90-x_y.z", "A-b/C.d_e"])
def test_nc1_branch_good_forms(world, value):
    result = world.run("N1", branch=value)
    assert result.code == 0, result.out
    assert world.fake.calls_to("POST", r"/git/refs$")


def test_nc1_branch_differs_from_base(world):
    assert_usage_nothing_done(world, world.run("N1", branch="candidate/a"))


@pytest.mark.parametrize("option", ["key_file", "app_file", "log"])
def test_nc1_paths_absolute(world, option):
    assert_usage_nothing_done(world, world.run("N1", **{option: "relative/file.txt"}))


def test_nc1_command_line_usage_exit_code(world, tmp_path):
    """The real command line, with -I, gives exit 2 and the stop line on stdout."""
    argv = world.argv("N9")
    completed = subprocess.run([sys.executable, "-I", str(TOOL_DIR / "xtl_negative.py"), *argv],
                               capture_output=True, text=True, timeout=120, cwd=str(tmp_path))
    assert completed.returncode == 2, completed.stdout + completed.stderr
    assert completed.stdout.strip().splitlines()[-1].startswith("NEGATIVE USAGE: ")
    assert not world.log.exists()
