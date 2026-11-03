"""gate.security_check: rules S-1 to S-6."""
from __future__ import annotations

import json

import pytest

from gatekit import Repo, assert_no_traceback, assert_rc, assert_refused, load_out, run_gate, write_json, write_text

EMPTY_BANDIT = {"errors": [], "metrics": {}, "results": []}
EMPTY_PIP = {"dependencies": [], "fixes": []}
EMPTY_LEAKS: list = []
MISSING = object()

BANDIT_ONE = {"errors": [], "results": [
    {"test_id": "B608", "filename": "workflow/store.py", "line_number": 121, "issue_text": "sql", "issue_severity": "MEDIUM"}]}
PIP_ONE = {"dependencies": [
    {"name": "examplelib", "version": "1.0", "vulns": [{"id": "PYSEC-2024-0001", "fix_versions": ["1.1"], "description": "x"}]},
    {"name": "cleanlib", "version": "2.0", "vulns": []}]}
LEAKS_ONE = [{"RuleID": "generic-api-key", "File": "src/config.py", "StartLine": 7, "Description": "key"}]


def review_md(rows):
    lines = ["# Security review", "", "| tool | rule | path | reason |", "|---|---|---|---|"]
    lines += [f"| {t} | {r} | {p} | {why} |" for t, r, p, why in rows]
    return "\n".join(lines) + "\n"


def norm_tool(t):
    return t.lower().replace("_", "-")


def make_repo(tmp_path, head_files=None, base_files=None):
    repo = Repo(tmp_path / "repo")
    repo.write("src/app.py", "def f():\n    return 1\n")
    for p, c in (base_files or {}).items():
        repo.write(p, c)
    base = repo.commit("base")
    repo.branch("pr")
    for p, c in (head_files or {"src/app.py": "def f():\n    return 2\n"}).items():
        repo.write(p, c)
    head = repo.commit("head")
    return repo, base, head


def _tool_file(tmp_path, name, value):
    path = tmp_path / name
    if value is MISSING:
        return path
    if isinstance(value, str):
        write_text(path, value)
    else:
        write_json(path, value)
    return path


def sec(tmp_path, *, bandit=EMPTY_BANDIT, pip=EMPTY_PIP, leaks=EMPTY_LEAKS, review=MISSING, head_files=None,
        base_files=None):
    repo, base, head = make_repo(tmp_path, head_files, base_files)
    review_path = tmp_path / "security-review.md"
    if review is not MISSING:
        write_text(review_path, review if isinstance(review, str) else review_md(review))
    out = tmp_path / "security.json"
    res = run_gate("security_check",
                   "--bandit", _tool_file(tmp_path, "bandit.json", bandit),
                   "--pip-audit", _tool_file(tmp_path, "pip-audit.json", pip),
                   "--gitleaks", _tool_file(tmp_path, "gitleaks.json", leaks),
                   "--review", review_path, "--repo", repo.path, "--base", base, "--head", head, "--out", out,
                   cwd=tmp_path)
    return res, load_out(res, out), out


def finding(d, tool, rule=None):
    return [f for f in d["findings"] if norm_tool(f["tool"]) == tool and (rule is None or f["rule"] == rule)]


# ----------------------------------------------------------------------------- S-1


@pytest.mark.req("S-1", "S-3")
def test_s1_bandit_finding_is_read_with_rule_path_and_line(tmp_path):
    res, d, _ = sec(tmp_path, bandit=BANDIT_ONE)
    f = finding(d, "bandit", "B608")
    assert len(f) == 1 and f[0]["path"] == "workflow/store.py" and f[0]["line"] == 121 and f[0]["reviewed"] is False
    assert_rc(res, 1)


@pytest.mark.req("S-1", "S-3")
def test_s1_pip_audit_finding_uses_the_package_name_as_the_path(tmp_path):
    res, d, _ = sec(tmp_path, pip=PIP_ONE)
    f = finding(d, "pip-audit", "PYSEC-2024-0001")
    assert len(f) == 1 and f[0]["path"] == "examplelib" and f[0]["reviewed"] is False
    assert not [x for x in d["findings"] if x["path"] == "cleanlib"], "a package without vulnerabilities is no finding"
    assert_rc(res, 1)


@pytest.mark.req("S-1", "S-3")
def test_s1_gitleaks_finding_is_read_with_rule_file_and_start_line(tmp_path):
    res, d, _ = sec(tmp_path, leaks=LEAKS_ONE)
    f = finding(d, "gitleaks", "generic-api-key")
    assert len(f) == 1 and f[0]["path"] == "src/config.py" and f[0]["line"] == 7 and f[0]["reviewed"] is False
    assert_rc(res, 1)


@pytest.mark.req("S-1", "S-2")
def test_s1_control_no_findings_anywhere_is_ok(tmp_path):
    res, d, _ = sec(tmp_path)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert d["ok"] is True and d["findings"] == [] and d["reason_codes"] == []
    assert isinstance(d["suppressions"], list)


@pytest.mark.req("S-1", "S-2")
def test_s1_several_findings_from_all_three_tools_are_all_listed(tmp_path):
    res, d, _ = sec(tmp_path, bandit=BANDIT_ONE, pip=PIP_ONE, leaks=LEAKS_ONE)
    assert {norm_tool(f["tool"]) for f in d["findings"]} == {"bandit", "pip-audit", "gitleaks"}
    assert len(d["findings"]) == 3


# ----------------------------------------------------------------------------- S-2


ALL_REVIEWED = [
    ("bandit", "B608", "workflow/store.py", "table name is a constant"),
    ("pip-audit", "PYSEC-2024-0001", "examplelib", "not reachable from our code"),
    ("gitleaks", "generic-api-key", "src/config.py", "a documented placeholder"),
]


@pytest.mark.req("S-2")
def test_s2_matching_rows_with_a_reason_make_every_finding_reviewed(tmp_path):
    res, d, _ = sec(tmp_path, bandit=BANDIT_ONE, pip=PIP_ONE, leaks=LEAKS_ONE, review=ALL_REVIEWED)
    assert_rc(res, 0)
    assert d["ok"] is True and d["reason_codes"] == []
    assert len(d["findings"]) == 3 and all(f["reviewed"] is True for f in d["findings"])


@pytest.mark.req("S-2")
def test_s2_a_row_does_not_depend_on_the_line_number(tmp_path):
    moved = {"errors": [], "results": [dict(BANDIT_ONE["results"][0], line_number=999)]}
    res, d, _ = sec(tmp_path, bandit=moved, review=[ALL_REVIEWED[0]])
    assert_rc(res, 0)
    assert finding(d, "bandit")[0]["reviewed"] is True


@pytest.mark.req("S-2", "S-3")
@pytest.mark.parametrize("variant,row", [
    ("blank-reason", ("bandit", "B608", "workflow/store.py", "")),
    ("other-rule", ("bandit", "B101", "workflow/store.py", "reason")),
    ("other-path", ("bandit", "B608", "workflow/other.py", "reason")),
    ("other-tool", ("gitleaks", "B608", "workflow/store.py", "reason")),
])
def test_s2_a_row_that_does_not_match_or_has_no_reason_does_not_review(tmp_path, variant, row):
    res, d, _ = sec(tmp_path, bandit=BANDIT_ONE, review=[row])
    assert_rc(res, 1)
    assert finding(d, "bandit", "B608")[0]["reviewed"] is False
    assert "UNREVIEWED_FINDING" in d["reason_codes"]


@pytest.mark.req("S-2")
def test_s2_only_the_matching_finding_is_reviewed(tmp_path):
    two = {"errors": [], "results": [
        BANDIT_ONE["results"][0],
        {"test_id": "B105", "filename": "workflow/auth.py", "line_number": 5, "issue_text": "pw", "issue_severity": "LOW"}]}
    res, d, _ = sec(tmp_path, bandit=two, review=[ALL_REVIEWED[0]])
    assert_rc(res, 1)
    assert finding(d, "bandit", "B608")[0]["reviewed"] is True
    assert finding(d, "bandit", "B105")[0]["reviewed"] is False


# ----------------------------------------------------------------------------- S-3


@pytest.mark.req("S-3")
def test_s3_unreviewed_finding_exits_1_with_its_code_and_a_short_message(tmp_path):
    res, d, _ = sec(tmp_path, leaks=LEAKS_ONE, review=[ALL_REVIEWED[0]])
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert res.both.strip()
    assert d["ok"] is False and "UNREVIEWED_FINDING" in d["reason_codes"]


# ----------------------------------------------------------------------------- S-4


@pytest.mark.req("S-4")
@pytest.mark.parametrize("tool", ["bandit", "pip", "leaks"])
@pytest.mark.parametrize("how,value", [("missing", MISSING), ("unparsable", "this is not json {"), ("empty-file", "")])
def test_s4_missing_or_unparsable_tool_output_is_never_a_pass(tmp_path, tool, how, value):
    res, d, _ = sec(tmp_path, **{tool: value})
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["ok"] is False and "MISSING_TOOL_OUTPUT" in d["reason_codes"]


# ----------------------------------------------------------------------------- S-5


NOSEC_HEAD = {"src/app.py": "def f():\n    return eval('1')  # nosec\n"}
ALLOW_HEAD = {"src/config.py": "KEY = 'placeholder'  # gitleaks:allow\n"}


@pytest.mark.req("S-5")
@pytest.mark.parametrize("head_files,path", [(NOSEC_HEAD, "src/app.py"), (ALLOW_HEAD, "src/config.py")],
                         ids=["nosec", "gitleaks-allow"])
def test_s5_added_suppression_without_a_row_exits_1(tmp_path, head_files, path):
    res, d, _ = sec(tmp_path, head_files=head_files)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["ok"] is False and "SUPPRESSION_WITHOUT_ENTRY" in d["reason_codes"]
    assert path in json.dumps(d["suppressions"]), "the suppression and its path are listed"


@pytest.mark.req("S-5")
@pytest.mark.parametrize("head_files,row", [
    (NOSEC_HEAD, ("bandit", "B307", "src/app.py", "eval of a literal, reviewed")),
    (ALLOW_HEAD, ("gitleaks", "generic-api-key", "src/config.py", "documented placeholder")),
], ids=["nosec", "gitleaks-allow"])
def test_s5_control_a_row_for_that_tool_and_path_allows_the_suppression(tmp_path, head_files, row):
    res, d, _ = sec(tmp_path, head_files=head_files, review=[row])
    assert_rc(res, 0)
    assert d["ok"] is True and "SUPPRESSION_WITHOUT_ENTRY" not in d["reason_codes"]


@pytest.mark.req("S-5")
@pytest.mark.parametrize("row", [
    ("gitleaks", "B307", "src/app.py", "wrong tool"),
    ("bandit", "B307", "src/other.py", "wrong path"),
], ids=["wrong-tool", "wrong-path"])
def test_s5_a_row_for_another_tool_or_path_does_not_allow_it(tmp_path, row):
    res, d, _ = sec(tmp_path, head_files=NOSEC_HEAD, review=[row])
    assert_rc(res, 1)
    assert "SUPPRESSION_WITHOUT_ENTRY" in d["reason_codes"]


@pytest.mark.req("S-5")
def test_s5_control_a_suppression_that_was_already_in_the_base_is_not_added(tmp_path):
    base = {"src/app.py": "def f():\n    return eval('1')  # nosec\n"}
    res, d, _ = sec(tmp_path, base_files=base, head_files={"src/app.py": "def f():\n    return eval('1')  # nosec\n\n\ndef g():\n    return 1\n"})
    assert_rc(res, 0)
    assert "SUPPRESSION_WITHOUT_ENTRY" not in d["reason_codes"]


# ----------------------------------------------------------------------------- S-6


@pytest.mark.req("S-6")
def test_s6_missing_review_file_means_no_reviewed_findings(tmp_path):
    res, d, _ = sec(tmp_path, bandit=BANDIT_ONE, review=MISSING)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert "UNREVIEWED_FINDING" in d["reason_codes"] and "MISSING_TOOL_OUTPUT" not in d["reason_codes"]
    assert finding(d, "bandit")[0]["reviewed"] is False


@pytest.mark.req("S-6")
def test_s6_control_missing_review_file_and_no_findings_is_ok(tmp_path):
    res, d, _ = sec(tmp_path, review=MISSING)
    assert_rc(res, 0)
    assert d["ok"] is True


@pytest.mark.req("C-2")
def test_usage_error_exits_2(tmp_path):
    out = tmp_path / "o.json"
    res = run_gate("security_check", "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out)
