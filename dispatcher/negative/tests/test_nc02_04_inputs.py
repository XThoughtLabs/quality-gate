"""NC-2 the key file, NC-3 the app file, NC-4 the log file."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from conftest import REPOSITORY, app_data


def assert_usage_logged_nothing_requested(world, result):
    assert result.code == 2, result.out
    assert result.stop_line.startswith("NEGATIVE USAGE: "), result.out
    assert world.fake.calls == []
    assert len(result.log_lines) == 1
    record = result.record
    assert record["outcome"] == "USAGE" and record["exit_code"] == 2
    assert record["created"] == []


# ---------------------------------------------------------------- NC-2

def test_nc2_missing_key_file(world):
    world.key_file.unlink()
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc2_key_file_is_a_folder(world):
    folder = world.keys / "folder.pem"
    folder.mkdir()
    assert_usage_logged_nothing_requested(world, world.run("N1", key_file=str(folder)))


def test_nc2_key_file_symbolic_link(world):
    link = world.keys / "link.pem"
    try:
        os.symlink(world.key_file, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"this user cannot create symbolic links here: {type(error).__name__}")
    assert_usage_logged_nothing_requested(world, world.run("N1", key_file=str(link)))


def test_nc2_empty_key_file(world):
    world.key_file.write_bytes(b"")
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc2_key_file_too_big(world):
    world.key_file.write_bytes(world.key.pem + b"\n" * (64 * 1024))
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc2_key_file_not_a_key(world):
    world.key_file.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nnot a key\n-----END RSA PRIVATE KEY-----\n")
    result = world.run("N1")
    assert_usage_logged_nothing_requested(world, result)
    assert "not a key" not in result.out


def test_nc2_key_never_printed_or_logged(world):
    result = world.run("N3")
    assert result.code == 0, result.out
    text = result.out + result.err + "\n".join(result.log_lines)
    for line in world.key.lines:
        assert line not in text


def test_nc2_key_file_read_at_run_time(world, neg):
    """The key is read by the run, not at import: a key file changed between runs is what the next run uses."""
    first = world.run("N1")
    assert first.code == 0, first.out
    world.key_file.write_bytes(b"garbage")
    second = world.run("N1", branch="ai/91-other")
    assert second.code == 2, second.out


# ---------------------------------------------------------------- NC-3

def write_app(world, data) -> None:
    world.app_file.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")


@pytest.mark.parametrize("change", [
    {"app_id": True}, {"app_id": 0}, {"app_id": "1"}, {"installation_id": -3}, {"installation_id": None},
    {"slug": "Bad_Slug"}, {"repository": "no-owner"}, {"executor_user": ""}, {"executor_sid": "S-1"},
    {"ceo_sid": "user"},
])
def test_nc3_app_file_shape(world, change):
    write_app(world, app_data(**change))
    assert_usage_logged_nothing_requested(world, world.run("N1"))


@pytest.mark.parametrize("text", ["", "[]", "{not json", '"text"'])
def test_nc3_app_file_not_an_object(world, text):
    write_app(world, text)
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc3_app_file_missing(world):
    world.app_file.unlink()
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc3_app_file_too_big(world):
    write_app(world, json.dumps(app_data()) + " " * (64 * 1024))
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc3_repository_must_equal_repo(world):
    write_app(world, app_data(repository="ExampleOrg/other-repo"))
    assert_usage_logged_nothing_requested(world, world.run("N1"))


def test_nc3_repo_option_must_equal_app_file(world):
    assert_usage_logged_nothing_requested(world, world.run("N1", repo="ExampleOrg/other-repo"))


APP_FILE_CASES = [
    app_data(),
    app_data(app_id=True),
    app_data(app_id=1.0),
    app_data(installation_id=0),
    app_data(slug="-bad"),
    app_data(slug="ok-slug-2"),
    app_data(repository="Org/repo.name_x-y"),
    app_data(repository="Org//repo"),
    app_data(executor_user=5),
    app_data(executor_sid="S-1-5-21-9"),
    app_data(ceo_sid="S-1-5"),
    {k: v for k, v in app_data().items() if k != "ceo_sid"},
    [1, 2],
]


@pytest.mark.parametrize("index", range(len(APP_FILE_CASES)))
def test_nc3_load_app_file_agrees_with_launcher(neg, launcher_ref, tmp_path, index):
    path = tmp_path / "app.json"
    path.write_text(json.dumps(APP_FILE_CASES[index]), encoding="utf-8")
    try:
        theirs = launcher_ref.load_app_file(Path(path))
    except launcher_ref.ConfigError:
        theirs = None
    try:
        ours = neg.load_app_file(Path(path))
    except neg.UsageError:
        ours = None
    assert ours == theirs


# ---------------------------------------------------------------- NC-4

def test_nc4_log_folder_created(world):
    assert not world.log.parent.exists()
    result = world.run("N1")
    assert result.code == 0, result.out
    assert len(result.log_lines) == 1


def test_nc4_log_unopenable(world):
    blocker = world.root / "blocker"
    blocker.write_text("a file, not a folder", encoding="ascii")
    result = world.run("N1", log=str(blocker / "negative.jsonl"))
    assert result.code == 2, result.out
    assert result.stop_line.startswith("NEGATIVE USAGE: ")
    assert world.fake.calls == []


def test_nc4_log_opened_before_app_file(world):
    """An app-file error is recorded: the log was opened first."""
    world.app_file.unlink()
    result = world.run("N2")
    assert result.code == 2
    assert result.record["case"] == "N2" and result.record["repository"] == REPOSITORY
