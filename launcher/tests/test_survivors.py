"""Tests for the two broken copies of the launcher that survived the run of 2026-11-06.

Written by the implementer, not by the spec-only author, at HQ's request of 2026-11-07
(HQ-ANSWERS-11): M37-pin-unknown and M39-log-secret. They use the author's harness unchanged.
"""

import sys

import launcher_world as W

# A real commit of quality-gate, older than the pin, present in the local clone the tests use.
EARLIER_GATE_SHA = "f0988c39d13b791322540e39e31221ba7c32080d"
STEP_MARKER = "STEP-ERROR-MARKER-39"


def judge_with(*shas: str) -> str:
    lines = [f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{shas[0]}"]
    for index, sha in enumerate(shas[1:], start=2):
        lines += [f"  judge{index}:", f"    uses: XThoughtLabs/quality-gate/.github/workflows/judge.yml@{sha}"]
    return W.judge_yml("\n".join(lines))


# ---------------------------------------------------------------- M37: LR-19, exactly one pin


def test_lr19_two_known_quality_gate_shas_stop_with_pin_unknown(world, check):
    """judge.yml names quality-gate by two different full SHAs, and both exist in quality-gate.
    No checkout can fail here, so only LR-19's 'exactly one' can stop the run (M37)."""
    world.remote_commit(W.INTEGRATION, {".github/workflows/judge.yml": judge_with(W.GATE_PIN, EARLIER_GATE_SHA)})
    res = world.run("spec", "--slug", "two-pins", steps=[{"op": "commit", "path": "acceptance/test_a.py"}])
    check.stopped(res, "PIN_UNKNOWN")
    assert res.model is None and not res.pushed


def test_lr19_control_the_earlier_sha_alone_is_accepted(world, check):
    """Control: the earlier SHA on its own is a pin the launcher accepts and checks out, so the
    stop above comes from there being two pins, not from that SHA."""
    world.remote_commit(W.INTEGRATION, {".github/workflows/judge.yml": judge_with(EARLIER_GATE_SHA)})
    res = world.run("spec", "--slug", "one-earlier-pin", steps=[{"op": "commit", "path": "acceptance/test_a.py"}])
    check.success(res)
    assert f"quality-gate at {EARLIER_GATE_SHA}" in res.log_text


# ---------------------------------------------------------------- M39: LR-50, the log's own scrub


def test_lr50_a_failing_steps_error_output_never_carries_the_token_into_the_log(world, check, tmp_path):
    """A step run after the token is minted prints the token on its error output and fails.
    The launcher logs the end of a failing step's error output; the token must not reach the log.
    The step here is the venv step: app_python is a script that reads the token the fake API
    issued and prints it beside a marker, then exits 1 (M39)."""
    token_file = tmp_path / "issued-token.txt"
    world.api.after("POST", r"^/app/installations/\d+/access_tokens$",
                    lambda: token_file.write_text(world.api.tokens_issued[-1], encoding="ascii"))
    script = tmp_path / "print_token.py"
    script.write_text(
        "import sys\n"
        f"token = open({str(token_file)!r}, encoding='ascii').read()\n"
        f"print({STEP_MARKER!r}, token, file=sys.stderr)\n"
        "sys.exit(1)\n", encoding="utf-8")
    fake_python = tmp_path / "fake-python.cmd"
    fake_python.write_text(f'@"{sys.executable}" -I "{script}" %*\r\n', encoding="ascii")
    world.set_config(app_python=str(fake_python))

    res = world.run("task", "--issue", str(W.ISSUE_NUMBER), steps=[{"op": "commit", "path": "app/x.py"}])

    check.stopped(res, "VENV_FAILED")  # includes LR-50's check of stdout, stderr and the log
    token = world.api.tokens_issued[-1]
    assert token_file.read_text(encoding="ascii") == token, "the step did not hold the token"
    assert f"{STEP_MARKER} [removed]" in res.log_text, "the step's error line did not reach the log"
    assert token not in res.log_text
    assert res.model is None and not res.pushed
