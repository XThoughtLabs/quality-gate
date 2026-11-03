"""Common rules C-1, C-2, C-6 (C-3, C-4, C-5 are checked where the scripts print or post)."""
from __future__ import annotations

import subprocess
import sys

import pytest

from gatekit import (Repo, assert_no_traceback, assert_rc, assert_refused, base_env, junit_xml, make_bare, make_config,
                     push_to, py_cmd, read_json, remote_url, run_gate, write_bytes, write_json, write_script,
                     write_text)

MODULES = ["env_check", "run_checks", "acceptance", "guard", "security_check", "concurrency_harness", "report",
           "archive", "feedback", "review_local", "publish", "reproduce"]


# ----------------------------------------------------------------------------- C-1


@pytest.mark.req("C-1")
def test_c1_minus_P_keeps_the_working_folder_off_the_path_so_a_judged_repository_cannot_shadow_a_module(tmp_path):
    shadow = tmp_path / "judged-repo"
    marker = tmp_path / "shadow-ran.txt"
    write_text(shadow / "gate" / "__init__.py", "")
    write_text(shadow / "gate" / "env_check.py",
               f"open({str(marker)!r}, 'w').write('SHADOW')\nraise SystemExit(0)\n")
    # control: without -P the shadow wins, so the setup really is able to shadow the module
    run_gate("env_check", "--role", "executor", cwd=shadow, pyflags=())
    assert marker.exists(), "test setup error: the shadow module did not run even without -P"
    marker.unlink()
    res = run_gate("env_check", "--role", "no-such-role", cwd=shadow)
    assert not marker.exists(), "a module of the judged repository ran in place of the gate's"
    assert_rc(res, 2)
    assert_no_traceback(res)


@pytest.mark.req("C-1", "C-2")
@pytest.mark.parametrize("module", MODULES)
def test_c1_c2_every_script_is_a_module_and_a_usage_error_exits_2_without_a_traceback(tmp_path, module):
    for args in ([], ["--no-such-option-xyz"]):
        res = run_gate(module, *args, cwd=tmp_path)
        assert "No module named" not in res.err, f"gate.{module} cannot be run with python -P -m\n{res.describe()}"
        assert_refused(res, 2)
        assert res.both.strip(), "a usage error prints a short message"


# ----------------------------------------------------------------------------- C-6 (standard library only, apart from two scripts)


def scenario_acceptance(tmp):
    junit = write_text(tmp / "j.xml", junit_xml([("a.t", "test_x", "pass")]))
    known = write_text(tmp / "k.txt", "")
    return "acceptance", ["--junit", junit, "--known-failing", known, "--out", tmp / "o.json"], base_env(), 0


def scenario_env_check(tmp):
    env = base_env({"CLAUDE_CODE_OAUTH_TOKEN": "SENTINEL-VALUE-1", "EXECUTOR_APP_ID": "42",
                    "EXECUTOR_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nSENTINEL-VALUE-2\n-----END PRIVATE KEY-----\n"})
    return "env_check", ["--role", "executor", "--out", tmp / "o.json"], env, 0


def scenario_run_checks(tmp):
    cfg = make_config(tmp / "quality.toml", checks={"gate/env": {"class": "mandatory", "commands": [py_cmd(write_script(tmp / "ok.py", "pass"))],
                                                               "timeout_seconds": 60}})
    return "run_checks", ["--config", cfg, "--check", "gate/env", "--out", tmp / "out"], base_env(), 0


def scenario_security_check(tmp):
    repo = Repo(tmp / "repo")
    repo.write("a.py", "x = 1\n")
    base = repo.commit("base")
    repo.write("a.py", "x = 2\n")
    head = repo.commit("head")
    files = {"bandit.json": {"results": []}, "pip.json": {"dependencies": []}, "leaks.json": []}
    for name, data in files.items():
        write_json(tmp / name, data)
    return "security_check", ["--bandit", tmp / "bandit.json", "--pip-audit", tmp / "pip.json", "--gitleaks",
                              tmp / "leaks.json", "--review", tmp / "none.md", "--repo", repo.path, "--base", base,
                              "--head", head, "--out", tmp / "o.json"], base_env(), 0


def scenario_concurrency(tmp):
    return "concurrency_harness", ["--rounds", "1", "--workers", "2", "--timeout", "60", "--out", tmp / "o.json", "--",
                                   sys.executable, "-c", "pass"], base_env(), 0


def scenario_feedback(tmp):
    cfg = make_config(tmp / "quality.toml")
    event = write_json(tmp / "event.json", {"workflow_run": {"id": 1, "run_attempt": 1, "path": "x.yml", "event": "push"}})
    pulls = write_json(tmp / "pulls.json", [])
    (tmp / "reports").mkdir()
    return "feedback", ["decide", "--event-name", "workflow_run", "--event", event, "--pulls", pulls, "--reports-dir",
                        tmp / "reports", "--config", cfg, "--out", tmp / "o.json"], base_env(), 0


def scenario_guard(tmp):
    repo = Repo(tmp / "repo")
    repo.write("src/a.py", "x = 1\n")
    base = repo.commit("base")
    repo.branch("pr")
    repo.write("src/a.py", "x = 2\n")
    head = repo.commit("head")
    cfg = make_config(tmp / "quality.toml")
    return "guard", ["--repo", repo.path, "--base", base, "--head", head, "--branch", "ai/1-x", "--config", cfg,
                     "--out", tmp / "o.json"], base_env(), 0


def scenario_archive(tmp):
    seed = Repo(tmp / "seed")
    seed.write("README.md", "seed\n")
    seed.commit("seed")
    bare = make_bare(tmp / "remote.git")
    push_to(seed, bare, "main")
    write_bytes(tmp / "artifact" / "meta.json", b"{}")
    write_bytes(tmp / "publish" / "report.json", b"{}")
    ctx = write_json(tmp / "context.json", {"pr": 1})
    return "archive", ["store", "--remote", remote_url(bare), "--branch", "reports", "--pr", "1", "--run-id", "2",
                       "--attempt", "1", "--artifact", tmp / "artifact", "--publish", tmp / "publish", "--context", ctx,
                       "--out", tmp / "o.json"], base_env(), 0


def scenario_reproduce(tmp):
    repo = Repo(tmp / "app")
    repo.write("a.py", "x = 1\n")
    sha = repo.commit("app")
    return "reproduce", ["--repo", repo.path, "--sha", sha, "--out", tmp / "rerun"], base_env(), 2  # no evidence is stored


SCENARIOS = [scenario_acceptance, scenario_env_check, scenario_run_checks, scenario_security_check,
             scenario_concurrency, scenario_feedback, scenario_guard, scenario_archive, scenario_reproduce]


@pytest.mark.req("C-6")
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.__name__.replace("scenario_", "") for s in SCENARIOS])
def test_c6_every_script_but_report_and_review_local_runs_on_the_standard_library_alone(tmp_path, scenario):
    for lib in ("jsonschema", "cryptography", "yaml", "pytest"):  # control: python -S really hides them
        cp = subprocess.run([sys.executable, "-S", "-c", f"import {lib}"], capture_output=True, text=True, env=base_env())
        assert cp.returncode != 0, f"test setup error: {lib} is importable under python -S"
    normal = tmp_path / "normal"
    normal.mkdir()
    module, args, env, expected = scenario(normal)
    res = run_gate(module, *args, env=env, cwd=normal)
    assert_rc(res, expected)  # the scenario itself is sound
    bare = tmp_path / "stdlib-only"
    bare.mkdir()
    module, args, env, expected = scenario(bare)
    res = run_gate(module, *args, env=env, cwd=bare, pyflags=("-S", "-P"))
    assert "ModuleNotFoundError" not in res.err and "ImportError" not in res.err, \
        f"gate.{module} needs a third-party library, which C-6 forbids\n{res.describe()}"
    assert_rc(res, expected)
