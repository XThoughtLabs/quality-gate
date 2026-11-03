"""gate.report generate: rules V-1 to V-8, B-1, M-1, the report.json fields, and the named task behaviours."""
from __future__ import annotations

import json

import pytest

from gatekit import assert_no_traceback, assert_rc, assert_refused, bare_mentions, sha256_bytes, write_text
from reportkit import DIAG, H1, H2, H3, MANDATORY, World, schema_errors, slug

SIX = MANDATORY + ["gate/report"]


def world(tmp_path, **kw):
    return World(tmp_path, **kw)


def done(o, verdict, *codes):
    """generate exits 0 whatever the verdict, and writes the three files."""
    assert_rc(o.res, 0)
    assert_no_traceback(o.res)
    for name in ("report.json", "verdict.json", "report.md"):
        assert (o.out_dir / name).exists(), f"{name} was not written\n{o.describe()}"
    assert o.verdict["verdict"] == verdict, o.describe()
    assert set(o.verdict["checks"].values()) <= {"success", "failure"}, \
        "a check is never neutral or skipped: GitHub counts those as success"
    for code in codes:
        assert code in o.codes, f"expected reason {code}\n{o.describe()}"


# ----------------------------------------------------------------------------- V-5 and the shape of verdict.json


@pytest.mark.req("V-5", "V-6")
def test_v5_everything_green_is_ready_for_human(tmp_path):
    o = world(tmp_path).run()
    done(o, "ready-for-human")
    assert o.verdict["reasons"] == []
    assert set(o.verdict) >= {"verdict", "reasons", "checks"}
    assert set(o.verdict["checks"]) >= set(SIX)
    assert all(o.verdict["checks"][c] == "success" for c in SIX)
    assert set(o.verdict["checks"].values()) <= {"success", "failure"}


@pytest.mark.req("V-5")
def test_v5_control_job_named_with_a_workflow_prefix_is_still_the_run_job(tmp_path):
    w = world(tmp_path)
    w.run_job_name = "judge / run"
    done(w.run(), "ready-for-human")


# ----------------------------------------------------------------------------- V-1


def m_fork(w):
    w.ctx["head_repository"] = "other-org/fork-of-app"


def m_head_sha(w):
    w.meta["head_sha"] = "9" * 40


def m_run_id(w):
    w.meta["run_id"] = 2002


def m_attempt(w):
    w.meta["run_attempt"] = 2


def m_success_with_nonzero_row(w):
    w.set_rows("gate/tests", [0, 3])


def m_failure_with_all_zero_rows(w):
    w.set_step("gate/tests", "failure")
    w.set_rows("gate/tests", [0, 0])


def m_exit_not_integer(w):
    w.set_rows("gate/tests", ["abc"])


def m_exit_empty(w):
    w.set_rows("gate/tests", [""])


def m_exit_float(w):
    w.set_rows("gate/tests", ["1.5"])


def m_checksum_raw(w):
    w.tamper_after_sums["raw/gate-tests/0.log"] = b"tampered after the sums were made\n"


def m_checksum_environment(w):
    w.tamper_after_sums["environment.json"] = b'{"tampered": true}'


def m_claim_on_failed_step(w):
    w.fail("gate/tests")
    w.meta["claimed_verdict"] = "ready-for-human"


V1_CASES = [
    ("fork", m_fork, "FORK_PR"),
    ("other-head-sha", m_head_sha, "SHA_MISMATCH"),
    ("other-run-id", m_run_id, "SHA_MISMATCH"),
    ("other-run-attempt", m_attempt, "SHA_MISMATCH"),
    ("success-with-a-nonzero-row", m_success_with_nonzero_row, "EXIT_CODE_MISMATCH"),
    ("failure-with-all-rows-zero", m_failure_with_all_zero_rows, "EXIT_CODE_MISMATCH"),
    ("exit-code-not-an-integer", m_exit_not_integer, "EXIT_CODE_MISMATCH"),
    ("exit-code-empty", m_exit_empty, "EXIT_CODE_MISMATCH"),
    ("exit-code-a-float", m_exit_float, "EXIT_CODE_MISMATCH"),
    ("checksum-of-a-log", m_checksum_raw, "CHECKSUM_MISMATCH"),
    ("checksum-of-environment-json", m_checksum_environment, "CHECKSUM_MISMATCH"),
    ("success-claimed-on-a-failed-step", m_claim_on_failed_step, "CLAIM_MISMATCH"),
]


@pytest.mark.req("V-1")
@pytest.mark.parametrize("name,mutate,code", V1_CASES, ids=[c[0] for c in V1_CASES])
def test_v1_a_contradiction_gives_blocked(tmp_path, name, mutate, code):
    w = world(tmp_path)
    mutate(w)
    done(w.run(), "blocked", code)


@pytest.mark.req("V-1")
def test_v1_control_a_failed_step_with_a_mix_of_rows_is_consistent(tmp_path):
    w = world(tmp_path)
    w.set_step("gate/tests", "failure")
    w.set_rows("gate/tests", [0, 3])
    o = w.run()
    done(o, "blocked", "FAILED_CHECK")
    assert "EXIT_CODE_MISMATCH" not in o.codes


@pytest.mark.req("V-1")
@pytest.mark.parametrize("claim", ["ready-for-human", "needs-human", "blocked"])
def test_v1_control_a_claim_on_an_all_green_run_is_no_contradiction_and_changes_nothing(tmp_path, claim):
    w = world(tmp_path)
    w.meta["claimed_verdict"] = claim
    o = w.run()
    done(o, "ready-for-human")
    assert "CLAIM_MISMATCH" not in o.codes


@pytest.mark.req("V-1", "V-2")
def test_v1_comes_before_v2_when_both_apply(tmp_path):
    w = world(tmp_path)
    m_checksum_raw(w)
    w.unfinish("gate/security")
    done(w.run(), "blocked", "CHECKSUM_MISMATCH")


@pytest.mark.req("V-1")
def test_v1_a_claim_of_ready_with_a_step_that_did_not_succeed_is_a_claim_mismatch(tmp_path):
    w = world(tmp_path)
    w.unfinish("gate/security")
    w.meta["claimed_verdict"] = "ready-for-human"
    done(w.run(), "blocked", "CLAIM_MISMATCH")


# ----------------------------------------------------------------------------- V-2


@pytest.mark.req("V-2")
@pytest.mark.parametrize("cid", MANDATORY)
def test_v2_absent_mandatory_step_is_unfinished(tmp_path, cid):
    w = world(tmp_path)
    w.drop_step(cid)
    o = w.run()
    done(o, "incomplete", "UNFINISHED_STAGE")
    assert o.verdict["checks"][cid] != "success"


@pytest.mark.req("V-2")
@pytest.mark.parametrize("status,conclusion", [
    ("in_progress", None), ("queued", None), ("completed", "cancelled"), ("completed", "skipped"),
    ("completed", None), ("completed", "neutral"), ("completed", "timed_out"),
])
def test_v2_step_not_completed_with_success_or_failure_is_unfinished(tmp_path, status, conclusion):
    w = world(tmp_path)
    w.unfinish("gate/tests", status=status, conclusion=conclusion)
    done(w.run(), "incomplete", "UNFINISHED_STAGE")


@pytest.mark.req("V-2")
def test_v2_run_job_absent(tmp_path):
    w = world(tmp_path)
    w.drop_run_job = True
    done(w.run(), "incomplete", "UNFINISHED_STAGE")


@pytest.mark.req("V-2")
def test_v2_run_job_not_completed(tmp_path):
    w = world(tmp_path)
    w.run_status = "in_progress"
    done(w.run(), "incomplete", "UNFINISHED_STAGE")


@pytest.mark.req("V-2")
def test_v2_a_step_with_the_right_name_in_another_job_does_not_count(tmp_path):
    w = world(tmp_path)
    w.drop_step("gate/tests")
    w.publish_steps_extra = [{"name": "gate/tests", "status": "completed", "conclusion": "success", "number": 2}]
    done(w.run(), "incomplete", "UNFINISHED_STAGE")


@pytest.mark.req("V-2")
def test_v2_no_artifact_folder(tmp_path):
    w = world(tmp_path)
    w.omit_artifact = True
    o = w.run()
    done(o, "incomplete", "NO_ARTIFACT")
    assert o.report["environment"] == "unknown" and o.report["coverage"] == "unknown"
    assert o.report["mutation"] == "unknown" and o.report["known_failing"] == "unknown"
    assert schema_errors(o.report) == []


@pytest.mark.req("V-2")
@pytest.mark.parametrize("name,setup", [
    ("exit-codes.tsv-missing", lambda w: w.omit_files.add("exit-codes.tsv")),
    ("SHA256SUMS-missing", lambda w: w.omit_files.add("SHA256SUMS")),
    ("meta.json-missing", lambda w: w.omit_files.add("meta.json")),
    ("file-named-in-SHA256SUMS-missing", lambda w: w.drop_after_sums.add("raw/gate-tests/0.log")),
    ("mandatory-step-has-no-row", lambda w: w.rows.pop("gate/acceptance")),
])
def test_v2_missing_output(tmp_path, name, setup):
    w = world(tmp_path)
    setup(w)
    done(w.run(), "incomplete", "MISSING_OUTPUT")


# ----------------------------------------------------------------------------- V-3


@pytest.mark.req("V-3")
def test_v3_repeated_fix_gives_needs_human(tmp_path):
    w = world(tmp_path)
    w.guard["repeated_fix"] = True
    w.guard["violations"] = [{"rule": "REPEATED_FIX", "path": "", "detail": "same diff as an earlier round"}]
    w.fail("gate/guard")
    done(w.run(), "needs-human", "REPEATED_FIX")


@pytest.mark.req("V-3")
def test_v3_round_cap_when_a_mandatory_step_failed(tmp_path):
    w = world(tmp_path)
    w.fail("gate/tests")
    w.extras = {"rounds": [{"head_sha": h, "round": "r" * 64, "cumulative": "c" * 64} for h in (H1, H2, "5" * 40)]}
    done(w.run(), "needs-human", "ROUND_CAP")


@pytest.mark.req("V-3")
@pytest.mark.parametrize("name,heads", [
    ("two-earlier-heads", [H1, H2]),
    ("this-head-already-in-the-list", [H1, H2, H3]),
    ("duplicates-do-not-count-twice", [H1, H1, H2, H2]),
])
def test_v3_control_below_the_cap_it_is_an_ordinary_failure(tmp_path, name, heads):
    w = world(tmp_path)
    w.fail("gate/tests")
    w.extras = {"rounds": [{"head_sha": h, "round": "r" * 64, "cumulative": "c" * 64} for h in heads]}
    o = w.run()
    done(o, "blocked", "FAILED_CHECK")
    assert "ROUND_CAP" not in o.codes


@pytest.mark.req("V-3")
def test_v3_control_the_cap_needs_a_failed_mandatory_step(tmp_path):
    w = world(tmp_path)
    w.extras = {"rounds": [{"head_sha": h, "round": "r" * 64, "cumulative": "c" * 64} for h in (H1, H2, "5" * 40, "6" * 40)]}
    done(w.run(), "ready-for-human")


@pytest.mark.req("V-3")
@pytest.mark.parametrize("cap,heads,verdict", [(2, [H1], "blocked"), (2, [H1, H2], "needs-human")])
def test_v3_the_cap_comes_from_limits_max_fix_rounds(tmp_path, cap, heads, verdict):
    w = world(tmp_path)
    w.config_limits = {"max_turns": 40, "timeout_minutes": 60, "max_fix_rounds": cap}
    w.fail("gate/tests")
    w.extras = {"rounds": [{"head_sha": h, "round": "r" * 64, "cumulative": "c" * 64} for h in heads]}
    done(w.run(), verdict)


@pytest.mark.req("V-3", "V-4")
def test_v3_comes_before_v4(tmp_path):
    w = world(tmp_path)
    w.guard["repeated_fix"] = True
    w.fail("gate/guard")
    w.fail("gate/tests")
    done(w.run(), "needs-human", "REPEATED_FIX")


@pytest.mark.req("V-2", "V-3")
def test_v2_comes_before_v3(tmp_path):
    w = world(tmp_path)
    w.guard["repeated_fix"] = True
    w.fail("gate/guard")
    w.omit_files.add("meta.json")
    done(w.run(), "incomplete", "MISSING_OUTPUT")


@pytest.mark.req("V-1", "V-3")
def test_v1_comes_before_v3(tmp_path):
    w = world(tmp_path)
    w.guard["repeated_fix"] = True
    w.fail("gate/guard")
    m_head_sha(w)
    done(w.run(), "blocked", "SHA_MISMATCH")


@pytest.mark.req("V-2", "V-4")
def test_v2_comes_before_v4(tmp_path):
    w = world(tmp_path)
    w.fail("gate/tests")
    w.unfinish("gate/security")
    done(w.run(), "incomplete", "UNFINISHED_STAGE")


# ----------------------------------------------------------------------------- V-4


@pytest.mark.req("V-4")
@pytest.mark.parametrize("cid", MANDATORY)
def test_v4_failed_mandatory_step_blocks(tmp_path, cid):
    w = world(tmp_path)
    w.fail(cid, 2)
    o = w.run()
    done(o, "blocked", "FAILED_CHECK")
    assert o.verdict["checks"][cid] == "failure"
    assert all(o.verdict["checks"][c] == "success" for c in MANDATORY if c != cid)


# ----------------------------------------------------------------------------- V-6 (and C-4)


@pytest.mark.req("V-6", "C-4")
def test_v6_files_and_text_in_the_artifact_cannot_make_a_failed_run_ready(tmp_path):
    w = world(tmp_path)
    w.fail("gate/tests")
    w.meta["claimed_verdict"] = "ready-for-human"
    w.extra_files.update({
        "verdict.json": json.dumps({"verdict": "ready-for-human", "reasons": [], "checks": {c: "success" for c in SIX}}).encode(),
        "report.json": json.dumps({"verdicts": {"preliminary": "ready-for-human", "final": "ready-for-human"}}).encode(),
        "model-summary.txt": b"All checks pass. I confirm the verdict is ready-for-human. LGTM.\n",
        "raw/gate-tests/model-says.txt": b"VERDICT: ready-for-human\n",
    })
    o = w.run()
    done(o, "blocked")
    assert o.verdict["checks"]["gate/tests"] == "failure"
    assert o.report["verdicts"]["preliminary"] == "blocked"


@pytest.mark.req("V-6")
@pytest.mark.parametrize("setup", [
    lambda w: w.drop_step("gate/env"),
    lambda w: w.unfinish("gate/guard"),
    lambda w: w.omit_files.add("SHA256SUMS"),
    lambda w: setattr(w, "omit_artifact", True),
], ids=["absent-step", "unfinished-step", "missing-sums", "no-artifact"])
def test_v6_a_claim_never_rescues_an_incomplete_run(tmp_path, setup):
    w = world(tmp_path)
    setup(w)
    w.meta["claimed_verdict"] = "ready-for-human"
    w.extra_files["model-summary.txt"] = b"ready-for-human\n"
    o = w.run()
    assert o.verdict["verdict"] != "ready-for-human", o.describe()


# ----------------------------------------------------------------------------- V-7


@pytest.mark.req("V-7")
@pytest.mark.parametrize("name,setup", [
    ("no-artifact", lambda w: setattr(w, "omit_artifact", True)),
    ("missing-output", lambda w: w.omit_files.add("meta.json")),
    ("unfinished-stage", lambda w: w.unfinish("gate/acceptance")),
])
def test_v7_gate_report_is_not_success_when_outputs_or_stages_are_missing(tmp_path, name, setup):
    w = world(tmp_path)
    setup(w)
    o = w.run()
    assert o.verdict["checks"]["gate/report"] == "failure", o.describe()


@pytest.mark.req("V-7")
def test_v7_control_gate_report_is_success_when_nothing_is_missing(tmp_path):
    o = world(tmp_path).run()
    assert o.verdict["checks"]["gate/report"] == "success"


@pytest.mark.req("V-7")
@pytest.mark.parametrize("name,setup", [
    ("failed-check", lambda w: w.fail("gate/tests")),
    ("sha-mismatch", m_head_sha),
])
def test_v7_control_a_bad_verdict_with_all_outputs_present_leaves_gate_report_success(tmp_path, name, setup):
    # Assumption: V-7 is read as "if and only if"; CONTRACTS.md words it only one way.
    w = world(tmp_path)
    setup(w)
    o = w.run()
    assert o.verdict["verdict"] == "blocked"
    assert o.verdict["checks"]["gate/report"] == "success"


# ----------------------------------------------------------------------------- V-8


@pytest.mark.req("V-8")
def test_v8_failed_diagnostic_changes_no_verdict_and_is_listed_with_its_exit_code(tmp_path):
    w = world(tmp_path)
    w.fail("diag/coverage", 2)
    w.fail("diag/mypy", 1)
    o = w.run()
    done(o, "ready-for-human")
    assert "FAILED_CHECK" not in o.codes
    by_id = {c["id"]: c for c in o.report["checks"]}
    cov = by_id["diag/coverage"]
    assert cov["class"] == "diagnostic" and cov["conclusion"] == "failure"
    assert cov["commands"][0]["exit_code"] == 2 and type(cov["commands"][0]["exit_code"]) is int
    assert by_id["diag/mypy"]["commands"][0]["exit_code"] == 1


@pytest.mark.req("V-8")
@pytest.mark.parametrize("how", ["absent", "cancelled"])
def test_v8_control_a_diagnostic_that_never_finished_changes_nothing(tmp_path, how):
    w = world(tmp_path)
    if how == "absent":
        w.drop_step("diag/mypy")
    else:
        w.unfinish("diag/mypy", status="completed", conclusion="cancelled")
    done(w.run(), "ready-for-human")


# ----------------------------------------------------------------------------- report.json fields


def full_world(tmp_path):
    w = world(tmp_path)
    w.set_rows("gate/tests", [0, 0])
    w.guard["dependency_changes"] = [{"name": "examplelib", "old": "1.0", "new": "2.0",
                                      "changelog": "https://pypi.org/project/examplelib/2.0/"}]
    w.extras = {
        "rounds": [{"head_sha": H1, "round": "r" * 64, "cumulative": "c" * 64},
                   {"head_sha": H2, "round": "s" * 64, "cumulative": "d" * 64}],
        "human": [{"minutes": 5}, {"minutes": 7}],
        "resources": {"executor_runs": 2, "executor_turns": 17},
        "semi_automatic_steps": ["issue labelled by the operator", "independent review started on the laptop"],
    }
    return w


@pytest.mark.req("R-JSON")
def test_report_json_validates_against_the_schema_and_the_schema_is_not_vacuous(tmp_path):
    o = full_world(tmp_path).run()
    done(o, "ready-for-human")
    assert schema_errors(o.report) == [], "report.json must validate against gate/schema/report.schema.json"
    assert schema_errors({}) != [] and schema_errors([]) != [], "the schema must reject things that are not reports"


@pytest.mark.req("R-JSON", "V-5")
def test_report_json_verification_holds_every_sha_and_configuration_hash(tmp_path):
    w = full_world(tmp_path)
    o = w.run()
    ver = o.report["verification"]
    for key, value in w.ctx.items():
        assert ver[key] == value, f"verification.{key}"
    for key in ("baseline_sha", "base_sha", "head_sha", "gate_sha"):
        assert len(ver[key]) == 40
    assert ver["config_hashes"] == {"quality.toml": "5" * 64, ".github/workflows/judge.yml": "6" * 64}


@pytest.mark.req("R-JSON")
def test_report_json_checks_carry_command_exit_code_duration_raw_path_and_raw_hash(tmp_path):
    w = full_world(tmp_path)
    o = w.run()
    by_id = {c["id"]: c for c in o.report["checks"]}
    assert set(MANDATORY) <= set(by_id)
    entry = by_id["gate/tests"]
    assert entry["class"] == "mandatory" and entry["conclusion"] == "success"
    assert len(entry["commands"]) == 2
    for i, c in enumerate(entry["commands"]):
        assert c["argv"] == ["python", "-m", "check", "gate/tests"]
        assert type(c["exit_code"]) is int and c["exit_code"] == 0
        assert c["duration_seconds"] == pytest.approx(0.25)
        assert c["raw_path"].replace("\\", "/").endswith(f"raw/gate-tests/{i}.log")
        data = (w.tmp / "artifact" / f"raw/{slug('gate/tests')}/{i}.log").read_bytes()
        assert c["raw_sha256"] == sha256_bytes(data)
    assert entry["counts"] == {"tests": 12, "failures": 0, "errors": 0, "skipped": 0}
    assert by_id["diag/coverage"]["class"] == "diagnostic"


@pytest.mark.req("R-JSON")
def test_report_json_environment_coverage_mutation_and_known_failing_come_from_the_artifact(tmp_path):
    w = full_world(tmp_path)
    o = w.run()
    assert o.report["environment"] == w.environment
    assert o.report["coverage"] == w.coverage
    assert o.report["mutation"] == w.mutation
    assert o.report["known_failing"] == {"size": 2, "remove_from_list": ["acceptance.test_status::test_permissions"]}


@pytest.mark.req("R-JSON")
def test_report_json_unknown_when_the_artifact_has_no_such_file(tmp_path):
    w = full_world(tmp_path)
    w.environment = None
    w.coverage = None
    w.mutation = None
    w.acceptance = None
    o = w.run()
    assert o.report["environment"] == "unknown"
    assert o.report["coverage"] == "unknown" and o.report["mutation"] == "unknown"
    assert o.report["known_failing"] == "unknown"


@pytest.mark.req("R-JSON")
def test_report_json_dependency_changes_rounds_human_and_semi_automatic_steps(tmp_path):
    w = full_world(tmp_path)
    o = w.run()
    assert o.report["dependency_changes"] == w.guard["dependency_changes"]
    got = [(r["head_sha"], r["round"], r["cumulative"]) for r in o.report["rounds"]]
    for r in w.extras["rounds"]:  # the rounds that were given are all there (this run's own may be added)
        assert (r["head_sha"], r["round"], r["cumulative"]) in got
    assert o.report["human"] == {"interventions": 2, "minutes": 12}
    assert o.report["semi_automatic_steps"] == w.extras["semi_automatic_steps"]
    assert "findings" in o.report and "bypass_merges" in o.report
    assert o.report["bypass_merges"] == []


@pytest.mark.req("R-JSON")
def test_report_json_resources_say_unknown_for_what_was_not_given_never_zero(tmp_path):
    w = full_world(tmp_path)
    r = w.run().report["resources"]
    assert r["executor_runs"] == 2 and r["executor_turns"] == 17
    for name in ("codex_runs", "codex_tokens", "actions_minutes"):
        assert r[name] == "unknown", f"{name} was not given, so it is unknown and not 0"


@pytest.mark.req("R-JSON")
def test_report_json_resources_without_any_extras_are_all_unknown(tmp_path):
    r = world(tmp_path).run().report["resources"]
    for name in ("executor_runs", "executor_turns", "codex_runs", "codex_tokens", "actions_minutes"):
        assert r[name] == "unknown"


@pytest.mark.req("R-JSON")
def test_report_json_resources_a_cost_that_was_given_as_zero_stays_zero(tmp_path):
    # Assumption: "never 0" is about costs that were not given; a given 0 is a value.
    w = world(tmp_path)
    w.extras = {"resources": {"codex_runs": 0}}
    r = w.run().report["resources"]
    assert r["codex_runs"] == 0 and type(r["codex_runs"]) is int
    assert r["codex_tokens"] == "unknown"


@pytest.mark.req("R-JSON")
def test_report_json_verdicts_hold_the_preliminary_verdict_and_a_null_final(tmp_path):
    w = world(tmp_path)
    w.fail("gate/tests")
    o = w.run()
    v = o.report["verdicts"]
    assert v["preliminary"] == "blocked" and v["final"] is None
    assert v["reasons"] == o.verdict["reasons"]
    assert isinstance(o.report["generated_at"], str) and o.report["generated_at"].strip()


# ----------------------------------------------------------------------------- B-1


def merge(sha_char, **kw):
    base = {"pr": 7, "merge_sha": sha_char * 40, "merged_by": "owner-login", "head_sha": "7" * 40,
            "final_conclusion": "success", "approvals": 1, "via_pr": True}
    base.update(kw)
    return base


@pytest.mark.req("B-1")
@pytest.mark.parametrize("name,kw", [
    ("not-via-a-pr", {"via_pr": False}),
    ("no-approval", {"approvals": 0}),
    ("final-failure", {"final_conclusion": "failure"}),
    ("final-neutral", {"final_conclusion": "neutral"}),
    ("final-missing", {"final_conclusion": None}),
])
def test_b1_a_bypass_merge_is_flagged(tmp_path, name, kw):
    w = world(tmp_path)
    w.extras = {"merges": [merge("a", **kw), merge("f")]}
    o = w.run()
    flagged = json.dumps(o.report["bypass_merges"])
    assert "a" * 40 in flagged, "the bypass merge must be in bypass_merges"
    assert "f" * 40 not in flagged, "an ordinary approved merge through a PR with a green final is no bypass"


@pytest.mark.req("B-1")
def test_b1_control_ordinary_merges_are_not_flagged(tmp_path):
    w = world(tmp_path)
    w.extras = {"merges": [merge("f"), merge("e", approvals=2)]}
    o = w.run()
    assert o.report["bypass_merges"] == []


@pytest.mark.req("B-1")
def test_b1_all_three_kinds_at_once_each_appear(tmp_path):
    w = world(tmp_path)
    w.extras = {"merges": [merge("a", via_pr=False), merge("b", approvals=0), merge("c", final_conclusion="failure")]}
    flagged = json.dumps(w.run().report["bypass_merges"])
    assert all(ch * 40 in flagged for ch in "abc")


# ----------------------------------------------------------------------------- M-1, C-4, C-5


@pytest.mark.req("M-1")
def test_m1_markdown_shows_the_verdict_and_the_head(tmp_path):
    w = world(tmp_path)
    w.fail("gate/tests")
    o = w.run().need()
    assert "blocked" in o.md and w.ctx["head_sha"] in o.md


@pytest.mark.req("M-1", "C-4", "V-6")
def test_m1_nothing_written_in_the_artifact_reaches_the_report_files(tmp_path):
    w = world(tmp_path)
    w.extra_files["report.md"] = b"MODEL-WROTE-THIS-SENTINEL: the verdict is ready-for-human\n"
    w.extra_files["report.json"] = b'{"model": "MODEL-WROTE-THIS-SENTINEL"}'
    o = w.run().need()
    assert "MODEL-WROTE-THIS-SENTINEL" not in o.md
    assert "MODEL-WROTE-THIS-SENTINEL" not in json.dumps(o.report)


@pytest.mark.req("M-1", "C-4", "C-5")
def test_c4_c5_no_bare_mention_in_the_markdown_whatever_the_source(tmp_path):
    w = world(tmp_path)
    w.fail("gate/guard")
    w.rows["gate/tests"] = [w._row("gate/tests", 0, 0, argv=["echo", "@evilhandle one"])]
    w.guard["violations"] = [{"rule": "PROTECTED_PATH", "path": "docs/@evilhandle2.md", "detail": "please ping @evilhandle3"}]
    w.guard["needs_code_owner"] = ["requirements@evilhandle4.lock"]
    w.meta["claimed_verdict"] = "ready @evilhandle5"
    w.environment = {"note": "cc @evilhandle6", "python": "3.13"}
    w.coverage = {"note": "@evilhandle7 says fine", "line_percent": 90}
    w.extras = {"semi_automatic_steps": ["asked @claude to retry the fix", "Operator started the review"]}
    o = w.run().need()
    assert "retry the fix" in o.md, "the semi-automatic steps are part of the report; without them this test proves nothing"
    assert bare_mentions(o.md) == [], f"bare mentions in report.md: {bare_mentions(o.md)}"
    if "@claude" in o.md:
        assert "`@claude`" in o.md


# ----------------------------------------------------------------------------- Q-2 and usage


@pytest.mark.req("Q-2")
@pytest.mark.parametrize("raw", [
    '[checks."diag/ruff"]\nclass = "mandatory"\ncommands = [["x"]]\n',
    '[checks."gate/made-up"]\nclass = "mandatory"\ncommands = [["x"]]\n',
])
def test_q2_report_generate_refuses_a_bad_configuration(tmp_path, raw):
    w = world(tmp_path)
    w.config_raw = raw
    o = w.run()
    assert_rc(o.res, 2)
    assert_no_traceback(o.res)
    assert not (o.out_dir / "report.json").exists() and not (o.out_dir / "verdict.json").exists()


@pytest.mark.req("C-2")
def test_usage_error_exits_2_and_writes_nothing(tmp_path):
    from gatekit import run_gate

    out = tmp_path / "out"
    res = run_gate("report", "generate", "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out / "report.json")
    res = run_gate("report", "no-such-subcommand", cwd=tmp_path)
    assert_refused(res, 2)


# ----------------------------------------------------------------------------- V-9


@pytest.mark.req("V-9", "V-4")
def test_v9_a_job_whose_own_env_check_failed_adds_failed_check_and_fails_gate_env(tmp_path):
    w = world(tmp_path)
    w.extras = {"env_failures": ["publish"]}
    o = w.run()
    done(o, "blocked", "FAILED_CHECK")
    assert o.verdict["checks"]["gate/env"] == "failure"
    assert all(o.verdict["checks"][c] == "success" for c in SIX if c != "gate/env"), \
        "only gate/env is made a failure"


@pytest.mark.req("V-9")
def test_v9_several_jobs_still_give_the_reason_and_the_failure(tmp_path):
    w = world(tmp_path)
    w.extras = {"env_failures": ["publish", "archive"]}
    o = w.run()
    done(o, "blocked", "FAILED_CHECK")
    assert o.verdict["checks"]["gate/env"] == "failure"


@pytest.mark.req("V-9")
def test_v9_control_an_empty_list_changes_nothing(tmp_path):
    w = world(tmp_path)
    w.extras = {"env_failures": []}
    o = w.run()
    done(o, "ready-for-human")
    assert o.verdict["checks"]["gate/env"] == "success"


@pytest.mark.req("V-9", "V-1")
def test_v9_comes_after_the_contradictions(tmp_path):
    w = world(tmp_path)
    w.extras = {"env_failures": ["publish"]}
    m_head_sha(w)
    done(w.run(), "blocked", "SHA_MISMATCH")
