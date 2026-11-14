"""CR-1, CR-1a, CR-1b: the command line, the configuration and the queue. Every refusal here is exit 2 with nothing
requested from GitHub."""

from __future__ import annotations

import json

import pytest

import fake_github as F
from conftest import queue_document


def usage(world, result, word="USAGE"):
    assert result.code == 2, result.out
    assert result.stop.startswith(f"CONTROLLER {word}"), result.out
    assert world.gh.calls == []


@pytest.mark.cr("CR-1")
@pytest.mark.parametrize("change", [
    {"--pr": None}, {"--repo": None}, {"--config": None}, {"--queue": None}, {"--queue-sha256": None},
    {"--pr": "0"}, {"--pr": "-3"}, {"--pr": "7a"}, {"--pr": "+7"},
    {"--queue-sha256": "A" * 64}, {"--queue-sha256": "a" * 63}, {"--queue-sha256": "g" * 64},
    {"--repo": "acme"}, {"--repo": "acme/demo/x"}, {"--repo": "ac me/demo"}, {"--repo": "acme/"},
])
def test_bad_command_line_is_usage(world, change):
    usage(world, world.run(world.argv(**change)))


@pytest.mark.cr("CR-1")
def test_option_given_twice_is_usage(world):
    usage(world, world.run(world.argv() + ["--pr", "8"]))


@pytest.mark.cr("CR-1")
def test_unknown_option_is_usage(world):
    usage(world, world.run(world.argv() + ["--merge-anyway", "yes"]))


@pytest.mark.cr("CR-1a")
@pytest.mark.parametrize("override", [
    {"app_id": "true"}, {"app_id": "0"}, {"app_id": '"111"'}, {"installation_id": "-1"},
    {"exec_bot": "false"}, {"rev_bot": "1.5"}, {"actions": '"15368"'},
    {"key_file": "'keys/controller.pem'"}, {"log_file": "'log.jsonl'"},
    {"checks": "[]"}, {"checks": '["gate/env", "gate/env"]'}, {"checks": '["Gate/env"]'}, {"checks": '["gate/e2e"]'},
    {"code_folders": '["workflow"]'}, {"code_folders": "[]"}, {"test_folder": '"tests"'},
    {"policy": "7"}, {"base_branch": '""'},
])
def test_bad_configuration_value_is_usage(world, override):
    world.set_config(**override)
    usage(world, world.run())


@pytest.mark.cr("CR-1a")
def test_unknown_key_is_usage(world):
    text = world.config_file.read_text(encoding="utf-8").replace("[gate]\n", "[gate]\nbypass = true\n")
    world.config_file.write_text(text, encoding="utf-8")
    usage(world, world.run())


@pytest.mark.cr("CR-1a")
def test_missing_key_is_usage(world):
    text = world.config_file.read_text(encoding="utf-8")
    text = "\n".join(line for line in text.splitlines() if not line.startswith("reports_branch"))
    world.config_file.write_text(text, encoding="utf-8")
    usage(world, world.run())


@pytest.mark.cr("CR-1a")
def test_unknown_table_is_usage(world):
    with world.config_file.open("a", encoding="utf-8") as handle:
        handle.write("\n[extra]\nx = 1\n")
    usage(world, world.run())


@pytest.mark.cr("CR-1a")
def test_missing_configuration_file_is_usage(world):
    usage(world, world.run(world.argv(**{"--config": str(world.tmp / "absent.toml")})))


@pytest.mark.cr("CR-1b")
def test_queue_changed_after_approval(world):
    recorded = world.queue_sha
    world.queue_file.write_bytes(world.queue_file.read_bytes() + b" ")
    result = world.run(world.argv(**{"--queue-sha256": recorded}))
    usage(world, result, "USAGE")
    assert "QUEUE_CHANGED" in result.stop


@pytest.mark.cr("CR-1b")
@pytest.mark.parametrize("doc", [
    queue_document(format="xtl-stage-a-queue/2"),
    queue_document(repository="acme/other"),
    queue_document(integration_branch="main"),
    queue_document(base_sha="B" * 40),
    queue_document(defects_sha="f" * 39),
    queue_document(tasks=[]),
    queue_document(tasks=[("SA1-T1", "SA1-T1 One"), ("SA1-T1", "SA1-T1 Two")]),
    queue_document(tasks=[("sa1-t1", "sa1-t1 Lower case id")]),
    queue_document(tasks=[("SA1-T0", "SA1-T0 Zero")]),
    queue_document(tasks=[("SA1-T1", "Fix the overdue filter")]),
    queue_document(tasks=[("SA1-T1", "SA1-T1Overdue")]),
    queue_document(tasks=[("SA1-T1", "SA1-T1 Same"), ("SA1-T2", "SA1-T1 Same")]),
])
def test_invalid_queue(world, doc):
    world.set_queue(doc)
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1b")
def test_queue_task_with_a_dependency_is_invalid(world):
    doc = queue_document()
    doc["tasks"][1]["depends_on"] = ["SA1-T1"]
    world.set_queue(doc)
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1b")
def test_queue_task_without_text_is_invalid(world):
    doc = queue_document()
    del doc["tasks"][0]["expected"]
    world.set_queue(doc)
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1b")
def test_queue_with_duplicate_keys_is_invalid(world):
    text = json.dumps(queue_document())
    raw = text.replace('"format": "xtl-stage-a-queue/1"',
                       '"format": "xtl-stage-a-queue/1", "format": "xtl-stage-a-queue/1"', 1).encode()
    world.set_queue(raw=raw)
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1b")
def test_queue_with_nan_is_invalid(world):
    raw = json.dumps(queue_document()).replace('"queue_id": "SA1"', '"queue_id": NaN').encode()
    world.set_queue(raw=raw)
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1b")
def test_queue_not_json_is_invalid(world):
    world.set_queue(raw=b"\xff\xfe not json")
    result = world.run()
    usage(world, result)
    assert "QUEUE_INVALID" in result.stop


@pytest.mark.cr("CR-1")
def test_a_good_run_needs_every_input(world):
    """Control: the same world with every input right merges (so the refusals above are about the input)."""
    result = world.run()
    assert result.code == 0, result.out
    assert result.stop.startswith("CONTROLLER MERGED"), result.out
    assert F.MERGE_SHA in result.stop
