"""Section 1 (entrances, exit codes, default config) and section 2 (LR-1,
LR-2): usage and configuration errors exit 2 with `CONFIG: ...` before any
network use, clone, token or run folder."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

import launcher_world as W

REQUIRED_CONFIG_KEYS = ["key_file", "app_file", "runs_dir", "claude_command", "app_python",
                        "deny_read_paths", "must_not_open"]
REQUIRED_APP_KEYS = ["app_id", "installation_id", "slug", "repository", "executor_user",
                     "executor_sid", "ceo_sid"]


def stop_at_admin(world):
    """Make the preflight stop at LR-5, so a control proves the arguments
    and the config were accepted without starting a real run."""
    world.seams.admin = True


# ---------------------------------------------------------------- section 1
def test_entrance_main_returns_the_exit_code_instead_of_raising(world, check):
    res = world.run("frobnicate")
    assert not res.raised_system_exit, "main() raised SystemExit instead of returning 2"
    check.config_error(res)
    res = world.run("check")
    assert not res.raised_system_exit
    assert res.code == 0, res.describe()


def test_entrance_command_line_gives_config_error(tmp_path, launcher):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    res = subprocess.run([sys.executable, "-I", launcher.__file__, "--config",
                          str(tmp_path / "missing.toml"), "check"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert res.returncode == 2
    assert W.last_line(res.stdout).startswith("CONFIG: "), res.stdout + res.stderr


def test_entrance_command_line_unknown_command(tmp_path, launcher):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    res = subprocess.run([sys.executable, "-I", launcher.__file__, "frobnicate"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert res.returncode == 2
    assert W.last_line(res.stdout).startswith("CONFIG: "), res.stdout + res.stderr


@pytest.mark.parametrize("with_toml", [False, True])
def test_entrance_default_config_is_launcher_toml_beside_the_launcher(tmp_path, launcher, world,
                                                                      with_toml):
    """Without --config the file is launcher.toml beside xtl_launcher.py. The
    launcher is copied, unread, into a folder of the test's own, so the real
    folder is never touched; it runs with the machine's real seams, so only
    "the config was read or not" is checked: a real machine stops in the
    preflight (this user owns the key file the test made), never with CONFIG."""
    folder = tmp_path / "copy"
    folder.mkdir()
    shutil.copy2(launcher.__file__, folder / "xtl_launcher.py")
    if with_toml:
        cfg = dict(world.config)
        cfg["api_url"] = "http://127.0.0.1:9"  # nothing listens there
        lines = ["[launcher]"] + [f"{k} = {W.toml_value(v)}" for k, v in cfg.items()]
        (folder / "launcher.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    res = subprocess.run([sys.executable, "-I", str(folder / "xtl_launcher.py"), "check"],
                         capture_output=True, text=True, env=env, timeout=120)
    last = W.last_line(res.stdout)
    if with_toml:
        assert res.returncode in (0, 1), res.stdout + res.stderr
        assert last.startswith("STOPPED ") or last == "PREFLIGHT OK", res.stdout + res.stderr
    else:
        assert res.returncode == 2, res.stdout + res.stderr
        assert last.startswith("CONFIG: ")


# ---------------------------------------------------------------- LR-1
def test_lr1_missing_config_file(world, check):
    world.config_path.unlink()
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_unreadable_config_file(world, check):
    world.write_files(raw_config="[launcher\nkey_file = 'x'\n")
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_config_without_launcher_table(world, check):
    world.write_files(raw_config='[other]\nx = 1\n')
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("key", REQUIRED_CONFIG_KEYS)
def test_lr1_missing_config_key(world, check, key):
    cfg = dict(world.config)
    del cfg[key]
    world.write_files(config=cfg)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("key, value", [
    ("claude_command", "claude"),
    ("claude_command", [1, 2]),
    ("deny_read_paths", r"C:\Users\Public"),
    ("must_not_open", 5),
    ("runs_dir", 3),
    ("key_file", ["a.pem"]),
    ("app_python", True),
    ("api_url", 1),
])
def test_lr1_config_value_of_the_wrong_type(world, check, key, value):
    cfg = dict(world.config)
    cfg[key] = value
    world.write_files(config=cfg)
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_missing_app_file(world, check):
    world.app_file.unlink()
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_unreadable_app_file(world, check):
    world.write_files(raw_app='{"app_id": 1, ')
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_a6_missing_key_file(world, check):
    """Amendment 1, A6: "a missing key" is a key file that does not exist."""
    world.key_file.unlink()
    check.config_error(world.run("task", "--issue", "5"))


def test_lr1_a6_executor_user_must_be_a_non_empty_string(world, check):
    app = dict(world.app)
    app["executor_user"] = ""
    world.write_files(app=app)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("key", REQUIRED_APP_KEYS)
def test_lr1_missing_app_key(world, check, key):
    app = dict(world.app)
    del app[key]
    world.write_files(app=app)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("key, value", [
    ("app_id", "424242"),
    ("app_id", True),          # a bool is an int in Python; it is not an app id
    ("installation_id", 5.5),
    ("repository", 5),
    ("executor_sid", None),
    ("ceo_sid", ["S-1-5-21-1"]),
    ("slug", {"x": 1}),
])
def test_lr1_app_value_of_the_wrong_type(world, check, key, value):
    app = dict(world.app)
    app[key] = value
    world.write_files(app=app)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("argv", [
    [],
    ["frobnicate"],
    ["task"],
    ["task", "--issue"],
    ["task", "--issue", "0"],
    ["task", "--issue", "-3"],
    ["task", "--issue", "abc"],
    ["task", "--issue", "1.5"],
    ["fix"],
    ["fix", "--pr", "0"],
    ["fix", "--pr", "seven"],
    ["spec"],
    ["spec", "--slug", ""],
    ["spec", "--slug", "Bad"],
    ["spec", "--slug", "-lead"],
    ["spec", "--slug", "a_b"],
    ["spec", "--slug", "a" * 41],
    ["spec", "--slug", "a/b"],
    ["spec", "--slug", "abc\n"],
])
def test_lr1_usage_errors(world, check, argv):
    check.config_error(world.run(*argv))


@pytest.mark.parametrize("argv", [
    ["check"],
    ["task", "--issue", "1"],
    ["fix", "--pr", "12"],
    ["spec", "--slug", "a"],
    ["spec", "--slug", "0-a"],
    ["spec", "--slug", "a" + "-" * 39],
    ["spec", "--slug", "a" * 40],
])
def test_lr1_control_valid_arguments_reach_the_preflight(world, check, argv):
    stop_at_admin(world)
    res = world.run(*argv)
    check.preflight_stop(res, "ADMIN")


# ---------------------------------------------------------------- LR-2
@pytest.mark.parametrize("value", [
    "https://api.github.com/",
    "http://api.github.com",
    "https://api.github.com.evil.example",
    "https://evil.example",
    "HTTPS://API.GITHUB.COM",
    " https://api.github.com",
    "http://localhost:8080",
    "http://127.0.0.1",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8080/api",
    "https://127.0.0.1:8080",
    "http://127.0.0.2:8080",
    "http://127.0.0.1:abc",
    "http://user@127.0.0.1:8080",
    "http://127.0.0.1:8080?x=1",
])
def test_lr2_api_url_refused(world, check, value):
    world.set_config(api_url=value)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("value", ["https://api.github.com", "http://127.0.0.1:8080", None])
def test_lr2_api_url_control(world, value):
    if value is None:
        cfg = dict(world.config)
        del cfg["api_url"]  # optional: the default is allowed
        world.write_files(config=cfg)
    else:
        world.set_config(api_url=value)
    res = world.run("check")
    assert res.code == 0, res.describe()


def bad_repo_urls(world):
    a_file = world.root / "a-file.txt"
    a_file.write_text("x", encoding="utf-8")
    return {
        "other-repo": "https://github.com/XThoughtLabs/other.git",
        "no-dot-git": "https://github.com/XThoughtLabs/gate-practice-app",
        "http": "http://github.com/XThoughtLabs/gate-practice-app.git",
        "ssh": "git@github.com:XThoughtLabs/gate-practice-app.git",
        "credential": "https://x-access-token:abc@github.com/XThoughtLabs/gate-practice-app.git",
        "trailing-slash": "https://github.com/XThoughtLabs/gate-practice-app.git/",
        "case": "https://github.com/xthoughtlabs/gate-practice-app.git",
        "missing-folder": str(world.root / "no-such-folder"),
        "a-file": str(a_file),
    }


@pytest.mark.parametrize("which", ["other-repo", "no-dot-git", "http", "ssh", "credential",
                                   "trailing-slash", "case", "missing-folder", "a-file"])
def test_lr2_repo_url_refused(world, check, which):
    world.set_config(repo_url=bad_repo_urls(world)[which])
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("which", ["github", "folder"])
def test_lr2_repo_url_control(world, which):
    value = ("https://github.com/XThoughtLabs/gate-practice-app.git" if which == "github"
             else str(world.remote))
    world.set_config(repo_url=value)
    res = world.run("check")
    assert res.code == 0, res.describe()


@pytest.mark.parametrize("which", ["evil", "no-dot-git", "file-url", "missing-folder"])
def test_lr2_gate_url_refused(world, check, which):
    value = {"evil": "https://github.com/evil/quality-gate.git",
             "no-dot-git": "https://github.com/XThoughtLabs/quality-gate",
             "file-url": "file:///C:/Users/<operator>/GitHub/quality-gate",
             "missing-folder": str(world.root / "no-gate")}[which]
    world.set_config(gate_url=value)
    check.config_error(world.run("task", "--issue", "5"))


@pytest.mark.parametrize("value", ["https://github.com/XThoughtLabs/quality-gate.git", W.GATE_URL])
def test_lr2_gate_url_control(world, value):
    world.set_config(gate_url=value)
    res = world.run("check")
    assert res.code == 0, res.describe()


def test_lr2_refusal_comes_before_any_token_even_with_a_working_api(world, check):
    """A bad repo_url with a working fake API: no request, no token."""
    world.set_config(repo_url="https://github.com/XThoughtLabs/other.git")
    res = world.run("task", "--issue", "5")
    check.config_error(res)
    assert world.api.tokens_issued == []
