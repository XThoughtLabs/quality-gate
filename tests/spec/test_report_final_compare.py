"""gate.report final (F-1, F-1a, F-2, F-2a, F-3, F-4) and compare (K-1), and the chain generate -> final."""
from __future__ import annotations

import copy
import json

import pytest

from gatekit import assert_no_traceback, assert_rc, load_out, run_gate, sha256_file, write_json, write_text
from reportkit import MANDATORY, World

SIX = MANDATORY + ["gate/report"]
ARCH_OK = {"stored": True, "sha256sums_match": True, "path": "reports/7/1001-1", "commit": "a" * 40, "reason": None,
           "artifact_present": True, "skipped_unsafe": [], "actors_ok": True}
REASONS = {
    "ready-for-human": [],
    "blocked": [{"code": "FAILED_CHECK", "detail": "gate/tests failed"}],
    "needs-human": [{"code": "REPEATED_FIX", "detail": "same diff as an earlier round"}],
    "incomplete": [{"code": "MISSING_OUTPUT", "detail": "meta.json is missing"}],
}
NOT_READY = ["blocked", "needs-human", "incomplete"]
MISSING = object()


def verdict_obj(verdict, **extra):
    failed = verdict == "blocked"
    checks = {c: "success" for c in SIX}
    if failed:
        checks["gate/tests"] = "failure"
    obj = {"verdict": verdict, "reasons": copy.deepcopy(REASONS[verdict]), "checks": checks}
    obj.update(extra)
    return obj


def final(tmp_path, verdict, archive, *, extra=(), verdict_text=None):
    """verdict: a dict, or MISSING for a verdict file that does not exist; verdict_text: raw (unreadable) content."""
    v = tmp_path / "verdict.json"
    if verdict is MISSING:
        pass
    elif verdict_text is not None:
        write_text(v, verdict_text)
    else:
        write_json(v, verdict)
    a = tmp_path / "archive.json"
    if archive is MISSING:
        pass
    elif isinstance(archive, str):
        write_text(a, archive)
    else:
        write_json(a, archive)
    out = tmp_path / "final.json"
    res = run_gate("report", "final", "--verdict", v, "--archive", a, "--out", out, *extra, cwd=tmp_path)
    assert res.rc != 2, f"final must not treat a missing or unreadable input as a usage error (F-2, F-2a)\n{res.describe()}"
    assert_no_traceback(res)
    return res, load_out(res, out)


def codes(d):
    return [r["code"] for r in d["reasons"]]


# ----------------------------------------------------------------------------- F-1


@pytest.mark.req("F-1", "F-3")
def test_f1_ready_with_stored_and_matching_archive_is_ready_for_human(tmp_path):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), ARCH_OK)
    assert_rc(res, 0)
    assert d["verdict"] == "ready-for-human" and d["reasons"] == []
    assert d["conclusions"] == {"gate/archive": "success", "gate/final": "success"}


@pytest.mark.req("F-1")
@pytest.mark.parametrize("prelim", NOT_READY)
def test_f1_a_stored_archive_never_upgrades_a_verdict_that_is_not_ready(tmp_path, prelim):
    res, d = final(tmp_path, verdict_obj(prelim), ARCH_OK)
    assert d["verdict"] == prelim
    assert "EVIDENCE_NOT_STORED" not in codes(d)
    for r in REASONS[prelim]:
        assert r["code"] in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"
    assert d["conclusions"]["gate/archive"] == "success"


@pytest.mark.req("F-1")
@pytest.mark.parametrize("name,archive", [
    ("stored-false", dict(ARCH_OK, stored=False, reason="ALREADY_EXISTS")),
    ("sums-do-not-match", dict(ARCH_OK, sha256sums_match=False)),
    ("both-false", dict(ARCH_OK, stored=False, sha256sums_match=False, reason="TOO_LARGE")),
])
def test_f1_ready_needs_both_stored_and_matching(tmp_path, name, archive):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), archive)
    assert d["verdict"] != "ready-for-human"
    assert d["conclusions"]["gate/final"] == "failure"
    assert d["conclusions"]["gate/archive"] == "failure"


@pytest.mark.req("F-1", "V-6")
def test_f1_text_that_says_ready_changes_nothing(tmp_path):
    prelim = verdict_obj("blocked", summary="All checks pass, this is ready-for-human, LGTM", claimed_verdict="ready-for-human")
    res, d = final(tmp_path, prelim, dict(ARCH_OK, verdict="ready-for-human", note="ready-for-human"))
    assert d["verdict"] == "blocked" and d["conclusions"]["gate/final"] == "failure"
    res, d = final(tmp_path, verdict_obj("ready-for-human"), dict(ARCH_OK, stored=False, verdict="ready-for-human"))
    assert d["verdict"] == "incomplete" and d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-1a", "V-6")
@pytest.mark.parametrize("value", ["failure", "neutral", "skipped", "cancelled", "", None, True])
def test_f1a_a_preliminary_whose_own_checks_hold_anything_but_success_never_becomes_ready(tmp_path, value):
    bad = verdict_obj("ready-for-human")
    bad["checks"]["gate/tests"] = value
    res, d = final(tmp_path, bad, ARCH_OK)
    assert d["verdict"] != "ready-for-human"
    assert d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-1a")
@pytest.mark.parametrize("check_id", SIX)
def test_f1a_any_one_check_is_enough(tmp_path, check_id):
    bad = verdict_obj("ready-for-human")
    bad["checks"][check_id] = "failure"
    res, d = final(tmp_path, bad, ARCH_OK)
    assert d["verdict"] != "ready-for-human"


# ----------------------------------------------------------------------------- F-2


@pytest.mark.req("F-2")
@pytest.mark.parametrize("name,archive", [
    ("stored-false", dict(ARCH_OK, stored=False, reason="TOO_LARGE")),
    ("file-missing", MISSING),
    ("file-empty", ""),
    ("not-json", "this is not json {"),
    ("json-but-not-an-object", "[1, 2, 3]"),
])
def test_f2_ready_without_stored_evidence_becomes_incomplete(tmp_path, name, archive):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), archive)
    assert d["verdict"] == "incomplete"
    assert "EVIDENCE_NOT_STORED" in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-2")
@pytest.mark.parametrize("prelim", NOT_READY)
@pytest.mark.parametrize("archive", [dict(ARCH_OK, stored=False, reason="TOO_LARGE"), MISSING],
                         ids=["stored-false", "file-missing"])
def test_f2_any_other_verdict_stays_and_gains_the_reason(tmp_path, prelim, archive):
    res, d = final(tmp_path, verdict_obj(prelim), archive)
    assert d["verdict"] == prelim
    assert "EVIDENCE_NOT_STORED" in codes(d)
    for r in REASONS[prelim]:
        assert r["code"] in codes(d), "the earlier reasons are kept"


# ----------------------------------------------------------------------------- F-3


@pytest.mark.req("F-3")
@pytest.mark.parametrize("prelim", ["ready-for-human"] + NOT_READY)
@pytest.mark.parametrize("name,archive,archive_ok", [
    ("stored-and-matching", ARCH_OK, True),
    ("not-stored", dict(ARCH_OK, stored=False), False),
    ("not-matching", dict(ARCH_OK, sha256sums_match=False), False),
    ("missing", MISSING, False),
])
def test_f3_conclusions_are_only_success_or_failure_and_follow_the_rules(tmp_path, prelim, name, archive, archive_ok):
    res, d = final(tmp_path, verdict_obj(prelim), archive)
    assert set(d["conclusions"]) >= {"gate/archive", "gate/final"}
    assert d["conclusions"]["gate/archive"] == ("success" if archive_ok else "failure")
    expected_final = "success" if (prelim == "ready-for-human" and archive_ok) else "failure"
    assert d["conclusions"]["gate/final"] == expected_final
    assert d["conclusions"]["gate/final"] in ("success", "failure"), "never neutral or skipped: GitHub counts those as success"
    assert (d["verdict"] == "ready-for-human") == (expected_final == "success")


# ----------------------------------------------------------------------------- the chain generate -> final


def chain(tmp_path, world, archive):
    o = world.run()
    assert_rc(o.res, 0)
    res, d = final(tmp_path, o.verdict, archive)
    return o, res, d


@pytest.mark.req("F-1", "V-6")
def test_chain_a_failed_mandatory_check_is_blocked_even_if_the_executor_text_says_ready(tmp_path):
    w = World(tmp_path)
    w.fail("gate/tests")
    w.meta["claimed_verdict"] = "ready-for-human"
    w.extra_files["executor-summary.txt"] = b"The work is done and tested. Verdict: ready-for-human.\n"
    o, res, d = chain(tmp_path, w, ARCH_OK)
    assert o.verdict["verdict"] == "blocked"
    assert d["verdict"] == "blocked" and d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-1", "F-2")
def test_chain_a_green_run_is_not_ready_without_stored_evidence(tmp_path):
    w = World(tmp_path)
    o, res, d = chain(tmp_path, w, dict(ARCH_OK, stored=False, reason="ALREADY_EXISTS"))
    assert o.verdict["verdict"] == "ready-for-human"
    assert d["verdict"] == "incomplete" and "EVIDENCE_NOT_STORED" in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-1")
def test_chain_control_a_green_run_with_stored_evidence_is_ready(tmp_path):
    o, res, d = chain(tmp_path, World(tmp_path), ARCH_OK)
    assert d["verdict"] == "ready-for-human" and d["conclusions"] == {"gate/archive": "success", "gate/final": "success"}


@pytest.mark.req("F-3", "V-1", "V-2", "V-3", "V-4")
@pytest.mark.parametrize("name,setup,expected", [
    ("blocked", lambda w: w.fail("gate/security"), "blocked"),
    ("incomplete", lambda w: w.unfinish("gate/security"), "incomplete"),
    ("needs-human", lambda w: (w.fail("gate/guard"), w.guard.update(repeated_fix=True)), "needs-human"),
])
def test_chain_every_verdict_other_than_ready_publishes_failure(tmp_path, name, setup, expected):
    w = World(tmp_path)
    setup(w)
    o, res, d = chain(tmp_path, w, ARCH_OK)
    assert d["verdict"] == expected
    assert d["conclusions"]["gate/final"] == "failure"


# ----------------------------------------------------------------------------- K-1


def two_reports(tmp_path):
    a = World(tmp_path / "a")
    a.fail("diag/coverage", 2)
    a.extras = {"rounds": [{"head_sha": "1" * 40, "round": "r" * 64, "cumulative": "c" * 64}],
                "resources": {"executor_runs": 2}}
    b = World(tmp_path / "b")
    b.fail("diag/coverage", 2)
    b.extras = copy.deepcopy(a.extras)
    oa, ob = a.run().need(), b.run().need()
    return oa.out_dir / "report.json", ob.out_dir / "report.json"


def compare(a, b):
    return run_gate("report", "compare", a, b)


def tweak(src, dst, fn):
    data = json.loads(src.read_text(encoding="utf-8"))
    fn(data)
    write_text(dst, json.dumps(data, indent=2))
    return dst


@pytest.mark.req("K-1")
def test_k1_two_runs_on_the_same_inputs_are_equal(tmp_path):
    a, b = two_reports(tmp_path)
    res = compare(a, b)
    assert_rc(res, 0)
    assert_no_traceback(res)


@pytest.mark.req("K-1")
def test_k1_the_excluded_fields_may_differ(tmp_path):
    a, b = two_reports(tmp_path)

    def fn(r):
        r["generated_at"] = "1999-01-01T00:00:00Z"
        r["verification"]["run_id"] = 999999
        r["verification"]["run_attempt"] = 9
        r["verification"]["execution_environment"] = "the pinned container"
        r["environment"] = {"python": "3.99.0", "image_os": "somewhere else"}
        for check in r["checks"]:
            for c in check["commands"]:
                c["duration_seconds"] = 12345.678
                c["raw_sha256"] = "f" * 64

    assert_rc(compare(a, tweak(a, tmp_path / "b2.json", fn)), 0)


@pytest.mark.req("K-1")
def test_k1_execution_environment_may_differ_between_two_runs(tmp_path):
    a, b = two_reports(tmp_path)
    a2 = tweak(a, tmp_path / "a2.json", lambda r: r["verification"].__setitem__("execution_environment", "runner"))
    b2 = tweak(b, tmp_path / "b2.json", lambda r: r["verification"].__setitem__("execution_environment", "container"))
    assert_rc(compare(a2, b2), 0)


@pytest.mark.req("K-1")
@pytest.mark.parametrize("name,fn,needle", [
    ("head_sha", lambda r: r["verification"].__setitem__("head_sha", "9" * 40), "head_sha"),
    ("pr", lambda r: r["verification"].__setitem__("pr", 99), "pr"),
    ("conclusion", lambda r: r["checks"][0].__setitem__("conclusion", "failure"), "conclusion"),
    ("preliminary", lambda r: r["verdicts"].__setitem__("preliminary", "blocked"), "preliminary"),
    ("resource", lambda r: r["resources"].__setitem__("executor_runs", 3), "executor_runs"),
    ("raw_path", lambda r: r["checks"][0]["commands"][0].__setitem__("raw_path", "raw/elsewhere.log"), "raw_path"),
    ("exit_code", lambda r: r["checks"][0]["commands"][0].__setitem__("exit_code", 4), "exit_code"),
    ("removed-key", lambda r: r.pop("bypass_merges"), "bypass_merges"),
])
def test_k1_any_other_difference_exits_1_and_names_the_path(tmp_path, name, fn, needle):
    a, b = two_reports(tmp_path)
    res = compare(a, tweak(a, tmp_path / "b2.json", fn))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert needle in res.both, f"the differing path ({needle}) must be named\n{res.describe()}"


@pytest.mark.req("K-1")
def test_k1_every_differing_path_is_named(tmp_path):
    a, b = two_reports(tmp_path)

    def fn(r):
        r["verification"]["head_sha"] = "9" * 40
        r["resources"]["executor_runs"] = 5
        r["verdicts"]["preliminary"] = "blocked"

    res = compare(a, tweak(a, tmp_path / "b2.json", fn))
    assert_rc(res, 1)
    for needle in ("head_sha", "executor_runs", "preliminary"):
        assert needle in res.both


@pytest.mark.req("K-1")
def test_k1_a_difference_hidden_next_to_an_excluded_field_is_still_found(tmp_path):
    a, b = two_reports(tmp_path)

    def fn(r):
        r["generated_at"] = "1999-01-01T00:00:00Z"
        r["checks"][0]["commands"][0]["raw_sha256"] = "f" * 64
        r["checks"][0]["commands"][0]["argv"] = ["python", "-m", "other"]

    res = compare(a, tweak(a, tmp_path / "b2.json", fn))
    assert_rc(res, 1)
    assert "argv" in res.both


# ----------------------------------------------------------------------------- F-2a


@pytest.mark.req("F-2a")
@pytest.mark.parametrize("name,kw", [
    ("file-missing", {"verdict": MISSING}),
    ("not-json", {"verdict": {}, "verdict_text": "this is not json {"}),
    ("empty-file", {"verdict": {}, "verdict_text": ""}),
])
def test_f2a_a_missing_or_unreadable_preliminary_verdict_gives_incomplete(tmp_path, name, kw):
    res, d = final(tmp_path, kw["verdict"], ARCH_OK, verdict_text=kw.get("verdict_text"))
    assert d["verdict"] == "incomplete"
    assert "NO_PRELIMINARY" in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"


def hashed_verdict(tmp_path, obj):
    path = write_json(tmp_path / "verdict.json", obj)
    return sha256_file(path)


@pytest.mark.req("F-2a")
def test_f2a_a_verdict_file_that_matches_the_publish_jobs_hash_is_trusted(tmp_path):
    obj = verdict_obj("ready-for-human")
    digest = hashed_verdict(tmp_path, obj)
    res, d = final(tmp_path, obj, ARCH_OK, extra=["--expect-verdict-sha256", digest])
    assert d["verdict"] == "ready-for-human" and d["conclusions"]["gate/final"] == "success"
    assert "PUBLISH_OUTPUT_MISMATCH" not in codes(d)


@pytest.mark.req("F-2a")
@pytest.mark.parametrize("name,value", [("another-hash", "0" * 64), ("empty-value", ""), ("not-a-hash", "nonsense")])
def test_f2a_a_difference_or_an_empty_value_gives_blocked(tmp_path, name, value):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), ARCH_OK, extra=["--expect-verdict-sha256", value])
    assert d["verdict"] == "blocked"
    assert "PUBLISH_OUTPUT_MISMATCH" in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-2a")
def test_f2a_a_verdict_edited_after_the_hash_was_taken_is_caught(tmp_path):
    original = verdict_obj("blocked")
    digest = hashed_verdict(tmp_path, original)
    forged = verdict_obj("ready-for-human")  # what a job that ran PR code might have written instead
    res, d = final(tmp_path, forged, ARCH_OK, extra=["--expect-verdict-sha256", digest])
    assert d["verdict"] == "blocked" and "PUBLISH_OUTPUT_MISMATCH" in codes(d)


@pytest.mark.req("F-2a")
def test_f2a_env_result_that_is_not_ok_adds_failed_check_and_a_ready_verdict_becomes_blocked(tmp_path):
    env_result = write_json(tmp_path / "env-result.json", {"role": "publish", "ok": False, "items": []})
    res, d = final(tmp_path, verdict_obj("ready-for-human"), ARCH_OK, extra=["--env-result", env_result])
    assert d["verdict"] == "blocked" and "FAILED_CHECK" in codes(d)
    assert d["conclusions"]["gate/final"] == "failure"


@pytest.mark.req("F-2a")
def test_f2a_env_result_without_ok_true_counts_as_not_ok(tmp_path):
    env_result = write_json(tmp_path / "env-result.json", {"role": "publish", "items": []})
    res, d = final(tmp_path, verdict_obj("ready-for-human"), ARCH_OK, extra=["--env-result", env_result])
    assert d["verdict"] == "blocked" and "FAILED_CHECK" in codes(d)


@pytest.mark.req("F-2a")
def test_f2a_env_result_that_is_ok_changes_nothing(tmp_path):
    env_result = write_json(tmp_path / "env-result.json", {"role": "publish", "ok": True, "items": []})
    res, d = final(tmp_path, verdict_obj("ready-for-human"), ARCH_OK, extra=["--env-result", env_result])
    assert d["verdict"] == "ready-for-human" and "FAILED_CHECK" not in codes(d)


@pytest.mark.req("F-2a")
@pytest.mark.parametrize("prelim", ["needs-human", "incomplete"])
def test_f2a_a_bad_env_result_adds_the_reason_to_another_verdict_and_leaves_the_verdict(tmp_path, prelim):
    env_result = write_json(tmp_path / "env-result.json", {"role": "publish", "ok": False, "items": []})
    res, d = final(tmp_path, verdict_obj(prelim), ARCH_OK, extra=["--env-result", env_result])
    assert d["verdict"] == prelim and "FAILED_CHECK" in codes(d)


# ----------------------------------------------------------------------------- F-4


@pytest.mark.req("F-4", "F-3")
def test_f4_actors_not_ok_fails_the_archive_and_turns_a_ready_verdict_into_blocked(tmp_path):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), dict(ARCH_OK, actors_ok=False))
    assert d["verdict"] == "blocked"
    assert "REPORTS_WRITTEN_BY_ANOTHER_ACTOR" in codes(d)
    assert d["conclusions"] == {"gate/archive": "failure", "gate/final": "failure"}


@pytest.mark.req("F-4")
@pytest.mark.parametrize("prelim", NOT_READY)
def test_f4_for_any_other_verdict_the_code_is_added_and_the_verdict_stays(tmp_path, prelim):
    res, d = final(tmp_path, verdict_obj(prelim), dict(ARCH_OK, actors_ok=False))
    assert d["verdict"] == prelim
    assert "REPORTS_WRITTEN_BY_ANOTHER_ACTOR" in codes(d)
    assert d["conclusions"]["gate/archive"] == "failure"
    for r in REASONS[prelim]:
        assert r["code"] in codes(d)


@pytest.mark.req("F-4")
def test_f4_control_actors_ok_true_is_no_reason(tmp_path):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), dict(ARCH_OK, actors_ok=True))
    assert d["verdict"] == "ready-for-human"
    assert "REPORTS_WRITTEN_BY_ANOTHER_ACTOR" not in codes(d)


@pytest.mark.req("F-4", "F-1")
def test_f4_a_stored_and_matching_archive_is_still_not_enough_when_another_actor_wrote(tmp_path):
    res, d = final(tmp_path, verdict_obj("ready-for-human"), dict(ARCH_OK, stored=True, sha256sums_match=True,
                                                               actors_ok=False, foreign_commits=["f" * 40]))
    assert d["verdict"] != "ready-for-human"
