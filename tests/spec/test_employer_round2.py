"""Employer audit of the round-2 finalization boundary, on a disposable copy."""
import pytest
from test_final_after_review import HEAD, Ready, check_run, hub, ran
pytestmark = pytest.mark.req("FN-1")

@pytest.mark.parametrize("path", ["archive", "finalize"])
def test_a_new_failed_mandatory_check_prevents_a_later_success_post(tmp_path, hub, path):
    world = Ready(tmp_path, hub)
    changed = []
    def after_status_read(number):
        # Read #1 supplies the decision, read #2 is the pre-post review refresh.
        # A new mandatory failure is published before that refresh returns.
        if number == 2:
            failed = check_run("gate/tests", conclusion="failure")
            hub.runs[HEAD].append(failed)
            changed.append(failed["id"])
    hub.after_read = after_status_read
    if path == "archive":
        ran(world.archive_post(world.archive_read()))
    else:
        ran(world.finalize(world.first, "mandatory-rerun"))
    assert changed, "the schedule did not reach the intended boundary"
    latest = max((r for r in hub.runs[HEAD] if r["name"] == "gate/tests"), key=lambda r:r["id"])
    assert latest["conclusion"] == "failure"
    result = hub.posted()[-1]
    assert result.get("conclusion") != "success", (
        "gate/final success was posted after a newer gate/tests failure on the same SHA"
    )
