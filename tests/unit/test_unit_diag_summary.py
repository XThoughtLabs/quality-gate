"""The summaries of diagnostic tools. Their real outputs are first seen in the real proofs."""

from __future__ import annotations

import json


def test_coverage_counts_only_changed_lines_that_can_be_measured(gate, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    gate.git(repo, "init", "--quiet")
    (repo / "app.py").write_text("a = 1\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "base")
    base = gate.git(repo, "rev-parse", "HEAD")
    (repo / "app.py").write_text("a = 1\nb = 2\n# a comment\nc = 3\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "change")
    head = gate.git(repo, "rev-parse", "HEAD")
    coverage = tmp_path / "coverage.json"
    coverage.write_text(
        json.dumps({"totals": {"percent_covered": 75.0}, "files": {"app.py": {"executed_lines": [1, 2], "missing_lines": [4]}}}),
        encoding="utf-8",
    )
    out = tmp_path / "summary.json"
    process = gate.run("diag_summary", "coverage", "--coverage-json", coverage, "--repo", repo, "--base", base, "--head", head, "--out", out)
    assert process.returncode == 0, process.stderr
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["whole_percent"] == 75.0
    assert summary["changed_lines"] == 2
    assert summary["changed_lines_covered"] == 1
    assert summary["changed_percent"] == 50.0


def test_no_changed_lines_is_unknown_never_zero(gate, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    gate.git(repo, "init", "--quiet")
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    gate.git(repo, "add", "-A")
    gate.git(repo, "commit", "--quiet", "-m", "base")
    sha = gate.git(repo, "rev-parse", "HEAD")
    coverage = tmp_path / "coverage.json"
    coverage.write_text(json.dumps({"totals": {"percent_covered": 10.0}, "files": {}}), encoding="utf-8")
    out = tmp_path / "summary.json"
    assert gate.run("diag_summary", "coverage", "--coverage-json", coverage, "--repo", repo, "--base", sha, "--head", sha, "--out", out).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["changed_percent"] == "unknown"


def test_a_missing_coverage_file_exits_two(gate, tmp_path):
    process = gate.run("diag_summary", "coverage", "--coverage-json", tmp_path / "absent", "--repo", tmp_path, "--base", "x", "--head", "y", "--out", tmp_path / "o.json")
    assert process.returncode == 2


def test_the_mutation_score_is_killed_over_killed_and_survived(gate, tmp_path):
    results = tmp_path / "results.txt"
    results.write_text("m.x__mutmut_1: killed\nm.x__mutmut_2: killed\nm.x__mutmut_3: survived\nm.x__mutmut_4: no tests\nnoise\n", encoding="utf-8")
    out = tmp_path / "summary.json"
    assert gate.run("diag_summary", "mutation", "--results", results, "--out", out).returncode == 0
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["counts"] == {"killed": 2, "survived": 1, "no tests": 1}
    assert summary["score_percent"] == 66.67


def test_no_mutants_is_unknown_never_zero(gate, tmp_path):
    results = tmp_path / "results.txt"
    results.write_text("", encoding="utf-8")
    out = tmp_path / "summary.json"
    assert gate.run("diag_summary", "mutation", "--results", results, "--out", out).returncode == 0
    assert json.loads(out.read_text(encoding="utf-8"))["score_percent"] == "unknown"
