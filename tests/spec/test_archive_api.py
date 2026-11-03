"""gate.archive through the API (--api-repo): W-12 to W-15 and the route table of section 9, against an in-memory stand-in."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from archivekit import ART, PUB, RESULT_KEYS, folder, make_inputs, sums_of
from gatekit import (assert_no_traceback, assert_rc, base_env, load_out, make_config, run_gate, sha256_bytes,
                     write_bytes, write_text)
from gitapi import BOT, FakeGitApi

ANOTHER_ACTOR_REASON = "reports written by another actor"


@pytest.fixture
def api(stub):
    return FakeGitApi(stub)


def api_env(api, **extra):
    return base_env({"GITHUB_API_URL": api.stub.url, "GATE_TOKEN": api.token, **extra})


def api_args(api, inp, out, *, pr=7, run_id=1001, attempt=1, branch="reports", max_bytes=None):
    args = ["store", "--api-repo", api.repo, "--branch", branch, "--pr", pr, "--run-id", run_id, "--attempt", attempt,
            "--artifact", inp.artifact, "--publish", inp.publish, "--context", inp.context, "--out", out]
    if max_bytes is not None:
        args += ["--max-bytes", max_bytes]
    return args


def store_api(tmp_path, api, inp, *, out_name="api-out.json", env=None, **kw):
    out = Path(tmp_path) / out_name
    if out.exists():
        out.unlink()
    res = run_gate("archive", *api_args(api, inp, out, **kw), env=env or api_env(api), cwd=tmp_path)
    return res, load_out(res, out)


def seed_other_run(api, **kw):
    return api.seed({"reports/6/900-1/context.json": b'{"pr": 6}\n'}, **kw)


# ----------------------------------------------------------------------------- the layout, byte for byte


@pytest.mark.req("W-0", "W-5", "W-13")
def test_api_store_writes_the_documented_layout_and_keeps_binary_bytes(tmp_path, api):
    files = dict(ART)
    files["all-bytes.bin"] = bytes(range(256)) * 5
    files["crlf.txt"] = b"a\r\nb\r\n"
    inp = make_inputs(tmp_path, artifact_files=files)
    res, d = store_api(tmp_path, api, inp)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert RESULT_KEYS <= set(d)
    assert d["stored"] is True and d["sha256sums_match"] is True and d["actors_ok"] is True
    assert d["artifact_present"] is True and d["skipped_unsafe"] == []
    assert d["path"].replace("\\", "/").strip("/").endswith("reports/7/1001-1")
    assert d["commit"] == api.head()
    f = folder(api.files())
    assert f["context.json"] == inp.context.read_bytes()
    for name, data in inp.pub_files.items():
        assert f[name] == data
    for name, data in inp.art_files.items():
        assert f[f"artifact/{name}"] == data, f"artifact/{name} must survive the API byte for byte"
    assert f["guard.json"] == files["guard.json"] and f["acceptance.json"] == files["acceptance.json"]
    listed = sums_of(f)
    expected = set(f) - {"SHA256SUMS"}
    assert set(listed) == expected
    for path, digest in listed.items():
        assert digest == sha256_bytes(f[path])
    assert api.bad_auth == [], "every call carries the token"


@pytest.mark.req("W-13")
def test_w13_a_commit_body_holds_exactly_message_tree_and_parents(tmp_path, api):
    seed_other_run(api)
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert api.commit_bodies, "the gate must write its commit through POST /git/commits"
    for body in api.commit_bodies:
        assert set(body) == {"message", "tree", "parents"}, f"no author, committer or signature: {sorted(body)}"
        assert isinstance(body["message"], str) and body["message"].strip()
    assert d["actors_ok"] is True, "a commit without an author is signed by GitHub, so it passes W-12"


@pytest.mark.req("W-1", "W-13")
def test_w1_the_branch_is_created_with_no_parent_through_post_refs(tmp_path, api):
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert [b["parents"] for b in api.commit_bodies] == [[]]
    assert [(m["method"], m["body"]) for m in api.moves] == [("POST", {"ref": "refs/heads/reports", "sha": api.head()})]
    assert all("base_tree" not in b or b["base_tree"] is None for b in api.tree_bodies), "a new branch has no base tree"
    assert len(api.reachable()) == 1


@pytest.mark.req("W-4", "W-8")
def test_w4_an_existing_branch_is_moved_with_patch_and_force_false_on_top_of_its_head(tmp_path, api):
    first = seed_other_run(api)
    first_tree = api.commits[first]["tree"]
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert [b["parents"] for b in api.commit_bodies] == [[first]]
    assert [b.get("base_tree") for b in api.tree_bodies] == [first_tree], "base_tree is the tree of the branch's head"
    moves = [m for m in api.moves if m["status"] in (200, 201)]
    assert len(moves) == 1 and moves[0]["method"] == "PATCH" and moves[0]["body"]["sha"] == api.head()
    assert all(m["body"].get("force") is False for m in api.moves), "force is false, never omitted and never true"
    files = api.files()
    assert files["reports/6/900-1/context.json"] == b'{"pr": 6}\n', "earlier attempts are untouched (W-8)"
    assert folder(files)["context.json"]
    for entry in api.tree_bodies[0]["tree"]:
        assert {"path", "mode", "type", "sha"} <= set(entry) and entry["type"] == "blob" and entry["mode"] == "100644"


@pytest.mark.req("W-3")
def test_w3_a_second_store_of_the_same_attempt_changes_nothing(tmp_path, api):
    r1, _ = store_api(tmp_path, api, make_inputs(tmp_path, tag="in1"))
    assert_rc(r1, 0)
    head, commits, moves = api.head(), len(api.commits), len(api.moves)
    changed = make_inputs(tmp_path, tag="in2", publish_files={"report.json": b'{"report": "DIFFERENT"}\n'})
    r2, d2 = store_api(tmp_path, api, changed, out_name="out2.json")
    assert_rc(r2, 1)
    assert d2["stored"] is False and d2["reason"] == "ALREADY_EXISTS"
    assert api.head() == head and len(api.commits) == commits and len(api.moves) == moves
    assert api.files()["reports/7/1001-1/report.json"] == PUB["report.json"]


@pytest.mark.req("W-2")
def test_w2_a_missing_artifact_folder_still_stores_the_rest(tmp_path, api):
    res, d = store_api(tmp_path, api, make_inputs(tmp_path, artifact=False))
    assert_rc(res, 0)
    assert d["stored"] is True and d["artifact_present"] is False
    f = folder(api.files())
    assert not [p for p in f if p.startswith("artifact/")] and {"context.json", "SHA256SUMS", *PUB} == set(f)


@pytest.mark.req("W-7")
def test_w7_too_large_writes_nothing_at_all(tmp_path, api):
    inp = make_inputs(tmp_path, artifact_files={"big.bin": b"x" * 1001})
    res, d = store_api(tmp_path, api, inp, max_bytes=1000)
    assert_rc(res, 1)
    assert d["stored"] is False and d["reason"] == "TOO_LARGE"
    assert api.blobs == {} and api.commits == {} and api.moves == [], "nothing may be written"


@pytest.mark.req("W-6")
def test_w6_git_folders_are_skipped_and_everything_else_is_stored_byte_for_byte(tmp_path, api):
    files = dict(ART)
    files[".gitignore"] = b"*\n!.gitignore\n"
    files[".gitattributes"] = b"* text eol=lf\n"
    files["crlf.txt"] = b"a\r\nb\r\n"
    inp = make_inputs(tmp_path, artifact_files=files)
    write_bytes(inp.artifact / "sub" / ".git" / "HEAD", b"ref: refs/heads/evil\n")
    res, d = store_api(tmp_path, api, inp)
    assert_rc(res, 0)
    assert d["stored"] is True and d["sha256sums_match"] is True
    f = folder(api.files())
    for name, data in files.items():
        assert f[f"artifact/{name}"] == data, f"{name} must be stored exactly as it was"
    assert not [p for p in f if ".git/" in p or p.endswith("/.git")]
    assert ".git" in json.dumps(d["skipped_unsafe"])


# ----------------------------------------------------------------------------- retries and races (W-4)


@pytest.mark.req("W-4")
def test_w4_a_409_or_422_on_moving_the_branch_is_retried_and_never_forced(tmp_path, api):
    seed_other_run(api)
    api.fail_moves = [409, 422]
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert d["stored"] is True and d["sha256sums_match"] is True
    assert [m["status"] for m in api.moves] == [409, 422, 200]
    assert all(m["body"].get("force") is False for m in api.moves)
    assert folder(api.files())["context.json"]


@pytest.mark.req("W-4")
def test_w4_a_competing_commit_that_lands_first_is_built_upon_and_nothing_is_lost(tmp_path, api):
    first = seed_other_run(api)
    api.interfere.append({"files": {"reports/9/1-1/context.json": b'{"pr": 9}\n'}})
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert d["stored"] is True and d["actors_ok"] is True
    files = api.files()
    assert files["reports/9/1-1/context.json"] == b'{"pr": 9}\n', "the competing run's folder is still there"
    assert folder(files)["context.json"], "and so is ours"
    assert len(api.reachable()) == 3 and first in api.reachable()
    assert any(m["status"] == 422 for m in api.moves) and api.moves[-1]["status"] == 200
    assert all(m["body"].get("force") is False for m in api.moves)


@pytest.mark.req("W-4", "W-1")
def test_w4_two_runs_creating_the_branch_at_once_both_end_stored(tmp_path, api):
    api.interfere.append({"files": {"reports/9/1-1/context.json": b'{"pr": 9}\n'}})
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))   # the branch is missing when we start
    assert_rc(res, 0)
    assert d["stored"] is True
    files = api.files()
    assert "reports/9/1-1/context.json" in files and folder(files)["context.json"]
    assert [m["method"] for m in api.moves][:1] == ["POST"] and api.moves[-1]["method"] == "PATCH"


# ----------------------------------------------------------------------------- W-5


@pytest.mark.req("W-5")
def test_w5_read_back_notices_when_the_branch_changed_after_the_write(tmp_path, api):
    api.tamper_after_move = True
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert api._tampered, "precondition: the branch was changed after the write"
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["sha256sums_match"] is False


@pytest.mark.req("W-5")
def test_w5_a_truncated_tree_listing_is_an_error_and_nothing_is_written(tmp_path, api):
    seed_other_run(api)
    api.truncated = True
    head = api.head()
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert any("/git/trees/" in r.path for r in api.stub.requests), "precondition: the gate read the listing"
    assert res.rc != 0
    assert_no_traceback(res)
    assert api.head() == head and api.moves == [], "a listing that is cut short must never be trusted"


# ----------------------------------------------------------------------------- W-12


def assert_another_actor(res, d, api, foreign_sha=None):
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["actors_ok"] is False
    assert d["reason"] == ANOTHER_ACTOR_REASON
    assert d["stored"] is True, "the evidence stays stored"
    assert folder(api.files())["context.json"], "and it is on the branch"
    if foreign_sha:
        assert foreign_sha in json.dumps(d["foreign_commits"]), "foreign_commits lists the commit"


@pytest.mark.req("W-12")
def test_w12_a_commit_by_another_author_is_found(tmp_path, api):
    foreign = seed_other_run(api, author="example-executor[bot]", verified=True)
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api, foreign)
    assert d["sha256sums_match"] is True


@pytest.mark.req("W-12")
def test_w12_an_unsigned_commit_is_found(tmp_path, api):
    foreign = seed_other_run(api, author=BOT, verified=False)
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api, foreign)


@pytest.mark.req("W-12")
def test_w12_a_foreign_commit_deep_in_the_history_is_found_on_a_later_page(tmp_path, api):
    foreign = api.seed({"reports/1/1-1/x.txt": b"x"}, author="someone-else[bot]")
    for i in range(2, 125):   # more than one page of 100 clean commits on top of it
        api.seed({f"reports/1/{i}-1/x.txt": b"x"})
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api, foreign)
    pages = sorted(int(r.q("page") or 1) for r in api.stub.reqs("GET", r".*/commits"))
    assert pages[0] == 1 and max(pages) >= 2, "every page of the branch's commits is read"
    assert all(r.q("per_page") == "100" and r.q("sha") == "reports" for r in api.stub.reqs("GET", r".*/commits"))


@pytest.mark.req("W-12", "W-13")
def test_w12_our_own_commit_counts_too_when_github_does_not_sign_it(tmp_path, api):
    api.sign_new = False
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api, api.head())


@pytest.mark.req("W-12", "W-13")
def test_w12_our_own_commit_counts_too_when_it_has_another_author(tmp_path, api):
    api.new_author = "someone-else[bot]"
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api, api.head())


@pytest.mark.req("W-12")
def test_w12_control_only_signed_commits_of_the_actions_bot_pass(tmp_path, api):
    seed_other_run(api, author=BOT, verified=True)
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 0)
    assert d["actors_ok"] is True and d["stored"] is True
    assert not d.get("foreign_commits"), "foreign_commits is only there when some exist"
    assert d["reason"] != ANOTHER_ACTOR_REASON


@pytest.mark.req("W-12")
def test_w12_the_check_is_run_after_the_write_so_a_late_foreign_commit_is_seen(tmp_path, api):
    api.interfere.append({"files": {"reports/9/1-1/context.json": b"{}"}, "author": "example-executor[bot]"})
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_another_actor(res, d, api)
    assert d["foreign_commits"]


@pytest.mark.req("W-12")
@pytest.mark.parametrize("status", [404, 500])
def test_w12_commits_that_cannot_be_read_give_actors_ok_false(tmp_path, api, status):
    api.commits_status = status
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["actors_ok"] is False
    assert d["stored"] is True and folder(api.files())["context.json"], "the evidence stays stored"


# ----------------------------------------------------------------------------- C-3: the token


@pytest.mark.req("C-3", "W-12")
@pytest.mark.parametrize("how", ["normal", "foreign-commit", "commits-unreadable"])
def test_c3_the_token_never_appears_in_stdout_stderr_or_out(tmp_path, api, how):
    if how == "foreign-commit":
        seed_other_run(api, author="someone-else[bot]")
    if how == "commits-unreadable":
        api.commits_status = 500
    res, d = store_api(tmp_path, api, make_inputs(tmp_path))
    assert d["stored"] is True, "the script really ran"
    out_text = (tmp_path / "api-out.json").read_text(encoding="utf-8")
    for where, text in {"stdout": res.out, "stderr": res.err, "--out": out_text}.items():
        assert api.token not in text, f"the token leaked into {where}"


@pytest.mark.req("C-3")
def test_c3_a_rejected_token_is_not_printed_either(tmp_path, api):
    wrong = "SENTINEL-VALUE-WRONGTOKEN"
    out = tmp_path / "api-out.json"
    res = run_gate("archive", *api_args(api, make_inputs(tmp_path), out), env=api_env(api, GATE_TOKEN=wrong), cwd=tmp_path)
    assert api.bad_auth, "precondition: the gate really called the API, and the API rejected its token"
    assert res.rc != 0
    assert_no_traceback(res)
    texts = [res.out, res.err] + ([out.read_text(encoding="utf-8")] if out.exists() else [])
    assert all(wrong not in t and api.token not in t for t in texts)
    assert api.head() is None, "nothing was written with a token the API rejected"


# ----------------------------------------------------------------------------- append through the API


def append_api(tmp_path, api, path, file, *, out_name="append-out.json"):
    out = Path(tmp_path) / out_name
    if out.exists():
        out.unlink()
    res = run_gate("archive", "append", "--api-repo", api.repo, "--branch", "reports", "--path", path, "--file", file,
                   "--out", out, env=api_env(api), cwd=tmp_path)
    return res, load_out(res, out)


@pytest.mark.req("W-9")
def test_append_adds_one_new_file_through_the_api_and_leaves_the_rest(tmp_path, api):
    r1, _ = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(r1, 0)
    before_head, before = api.head(), api.files()
    final = write_text(tmp_path / "final.json", '{"verdict": "ready-for-human"}\n')
    res, d = append_api(tmp_path, api, "reports/7/1001-1/final.json", final)
    assert_rc(res, 0)
    assert RESULT_KEYS <= set(d)
    assert d["stored"] is True and d["sha256sums_match"] is True and d["actors_ok"] is True
    after = api.files()
    assert after["reports/7/1001-1/final.json"] == final.read_bytes()
    assert {p: b for p, b in after.items() if p != "reports/7/1001-1/final.json"} == before
    assert api.commits[api.head()]["parents"] == [before_head]
    assert set(api.commit_bodies[-1]) == {"message", "tree", "parents"}


@pytest.mark.req("W-9", "W-3")
def test_append_to_an_existing_file_through_the_api_is_refused(tmp_path, api):
    r1, _ = store_api(tmp_path, api, make_inputs(tmp_path))
    assert_rc(r1, 0)
    head, files = api.head(), api.files()
    other = write_text(tmp_path / "other.json", '{"replaced": true}\n')
    res, d = append_api(tmp_path, api, "reports/7/1001-1/report.json", other)
    assert_rc(res, 1)
    assert d["stored"] is False and d["reason"] == "ALREADY_EXISTS"
    assert api.head() == head and api.files() == files


# ----------------------------------------------------------------------------- W-14: the recovery of reports (decision V)

OTHER_ACTOR = "someone-else[bot]"


def accepted_config(tmp_path, entries, name="quality.toml"):
    return make_config(Path(tmp_path) / name, archive_accepted=entries)


def entry(listed_sha, **change):
    e = {"sha": listed_sha, "reason": "a recovery commit that only added records", "date": "2026-11-03"}
    e.update(change)
    return {k: v for k, v in e.items() if v is not None}


def store_with(tmp_path, api, entries, **kw):
    cfg = accepted_config(tmp_path, entries)
    out = Path(tmp_path) / "api-out.json"
    if out.exists():
        out.unlink()
    res = run_gate("archive", *api_args(api, make_inputs(tmp_path), out), "--config", cfg, env=api_env(api), cwd=tmp_path)
    return res, load_out(res, out)


@pytest.mark.req("W-14")
def test_w14_a_listed_commit_that_only_adds_under_reports_with_one_parent_is_accepted(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}", "reports/9/5-1/report.json": b"{}"}, author=OTHER_ACTOR)
    res, d = store_with(tmp_path, api, [entry(foreign)])
    assert_rc(res, 0)
    assert d["actors_ok"] is True and d["stored"] is True
    assert foreign in json.dumps(d["accepted_commits"]), "accepted commits go into accepted_commits"
    assert not d.get("foreign_commits")


@pytest.mark.req("W-14")
def test_w14_control_the_same_commit_unlisted_stays_foreign(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    res, d = store_with(tmp_path, api, [entry("c" * 40)])   # another SHA is listed
    assert_rc(res, 1)
    assert d["actors_ok"] is False and d["reason"] == ANOTHER_ACTOR_REASON
    assert foreign in json.dumps(d["foreign_commits"])
    assert not d.get("accepted_commits")


def foreign_modifying(api):
    seed_other_run(api)
    api.seed({"reports/9/5-1/context.json": b"{}"})
    return api.seed({"reports/9/5-1/context.json": b'{"changed": true}'}, author=OTHER_ACTOR)


def foreign_deleting(api):
    seed_other_run(api)
    api.seed({"reports/9/5-1/context.json": b"{}", "reports/9/5-1/report.json": b"{}"})
    return api.seed({}, author=OTHER_ACTOR, delete=["reports/9/5-1/report.json"])


def foreign_adding_outside(api):
    seed_other_run(api)
    return api.seed({"README.md": b"outside the records"}, author=OTHER_ACTOR)


def foreign_adding_inside_and_outside(api):
    seed_other_run(api)
    return api.seed({"reports/9/5-1/context.json": b"{}", "elsewhere/file.txt": b"x"}, author=OTHER_ACTOR)


def foreign_adding_under_a_lookalike_folder(api):
    seed_other_run(api)
    return api.seed({"reportsx/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)


def foreign_with_two_parents(api):
    seed_other_run(api)
    side = api.seed({"reports/8/1-1/context.json": b"{}"}, branch="side")
    return api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR, extra_parents=[side])


STAYS_FOREIGN = [foreign_modifying, foreign_deleting, foreign_adding_outside, foreign_adding_inside_and_outside,
                 foreign_adding_under_a_lookalike_folder, foreign_with_two_parents]


@pytest.mark.req("W-14")
@pytest.mark.parametrize("make", STAYS_FOREIGN, ids=[f.__name__ for f in STAYS_FOREIGN])
def test_w14_a_listed_commit_that_changes_deletes_adds_elsewhere_or_merges_stays_foreign(tmp_path, api, make):
    foreign = make(api)
    res, d = store_with(tmp_path, api, [entry(foreign)])
    assert_rc(res, 1)
    assert d["actors_ok"] is False and d["reason"] == ANOTHER_ACTOR_REASON
    assert foreign in json.dumps(d["foreign_commits"]), "listed or not, it blocks"
    assert d["stored"] is True


@pytest.mark.req("W-14")
@pytest.mark.parametrize("change", [
    {"reason": None}, {"date": None}, {"reason": ""}, {"date": ""}, {"sha": "SHORT"}, {"sha": None},
], ids=["no-reason", "no-date", "empty-reason", "empty-date", "short-sha", "no-sha"])
def test_w14_an_entry_without_a_full_sha_a_reason_and_a_date_is_ignored(tmp_path, api, change):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    if change.get("sha") == "SHORT":
        change = {"sha": foreign[:12]}
    res, d = store_with(tmp_path, api, [entry(foreign, **change)])
    assert_rc(res, 1)
    assert d["actors_ok"] is False
    assert foreign in json.dumps(d["foreign_commits"])


@pytest.mark.req("W-14")
def test_w14_control_a_complete_entry_among_broken_ones_still_counts(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    res, d = store_with(tmp_path, api, [entry("d" * 40, reason=None), entry(foreign)])
    assert_rc(res, 0)
    assert d["actors_ok"] is True


@pytest.mark.req("W-14")
def test_w14_one_listed_and_one_unlisted_foreign_commit_still_block_and_name_only_the_unlisted(tmp_path, api):
    seed_other_run(api)
    listed = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    unlisted = api.seed({"reports/9/6-1/context.json": b"{}"}, author="third-party[bot]")
    res, d = store_with(tmp_path, api, [entry(listed)])
    assert_rc(res, 1)
    assert unlisted in json.dumps(d["foreign_commits"]) and listed not in json.dumps(d["foreign_commits"])
    assert listed in json.dumps(d["accepted_commits"])


@pytest.mark.req("W-14")
def test_w14_a_listed_commit_whose_files_cannot_be_read_is_not_accepted(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    api.one_commit_status = 500
    res, d = store_with(tmp_path, api, [entry(foreign)])
    assert_rc(res, 1)
    assert d["actors_ok"] is False


@pytest.mark.req("W-14")
def test_w14_no_history_is_rewritten_and_nothing_is_forced(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    before = set(api.reachable())
    res, d = store_with(tmp_path, api, [entry(foreign)])
    assert_rc(res, 0)
    assert before <= set(api.reachable()), "every commit that was on the branch still is"
    assert foreign in api.reachable()
    assert all(m["body"].get("force") is False for m in api.moves)


@pytest.mark.req("W-14", "W-12")
def test_w14_the_listed_commit_must_still_be_signed_or_the_actor_rule_for_our_own_commits_stands(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    api.sign_new = False   # our own new commit is not signed, which no list can excuse
    res, d = store_with(tmp_path, api, [entry(foreign)])
    assert_rc(res, 1)
    assert d["actors_ok"] is False and api.head() in json.dumps(d["foreign_commits"])


# ----------------------------------------------------------------------------- W-15: check-actors


def check_actors(tmp_path, api, *, config=None, branch="reports", env=None):
    out = Path(tmp_path) / "actors.json"
    if out.exists():
        out.unlink()
    args = ["check-actors", "--api-repo", api.repo, "--branch", branch, "--out", out]
    if config is not None:
        args += ["--config", config]
    res = run_gate("archive", *args, env=env or api_env(api), cwd=tmp_path)
    return res, load_out(res, out)


@pytest.mark.req("W-15")
def test_w15_a_clean_branch_is_actors_ok(tmp_path, api):
    seed_other_run(api)
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert {"actors_ok", "foreign_commits", "accepted_commits", "reason"} <= set(d)
    assert d["actors_ok"] is True and not d["foreign_commits"] and not d["accepted_commits"]


@pytest.mark.req("W-15")
def test_w15_a_foreign_commit_is_found_and_the_exit_code_is_1(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 1)
    assert d["actors_ok"] is False and foreign in json.dumps(d["foreign_commits"])
    assert d["reason"] == ANOTHER_ACTOR_REASON


@pytest.mark.req("W-15")
@pytest.mark.parametrize("kind", ["unsigned", "other-author"])
def test_w15_unsigned_and_foreign_authors_are_both_found(tmp_path, api, kind):
    seed_other_run(api)
    if kind == "unsigned":
        foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=BOT, verified=False)
    else:
        foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author="third-party[bot]")
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 1)
    assert foreign in json.dumps(d["foreign_commits"])


@pytest.mark.req("W-15", "W-14")
def test_w15_the_list_of_accepted_commits_is_honoured(tmp_path, api):
    seed_other_run(api)
    foreign = api.seed({"reports/9/5-1/context.json": b"{}"}, author=OTHER_ACTOR)
    res, d = check_actors(tmp_path, api, config=accepted_config(tmp_path, [entry(foreign)]))
    assert_rc(res, 0)
    assert d["actors_ok"] is True and foreign in json.dumps(d["accepted_commits"]) and not d["foreign_commits"]
    api2_foreign = api.seed({"reports/9/5-1/context.json": b'{"changed": true}'}, author=OTHER_ACTOR)
    res, d = check_actors(tmp_path, api, config=accepted_config(tmp_path, [entry(foreign), entry(api2_foreign)]))
    assert_rc(res, 1)
    assert api2_foreign in json.dumps(d["foreign_commits"]), "a commit that changes a record stays foreign even when listed"


@pytest.mark.req("W-15")
def test_w15_a_branch_that_does_not_exist_yet_is_actors_ok(tmp_path, api):
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 0)
    assert d["actors_ok"] is True and not d["foreign_commits"]


@pytest.mark.req("W-15")
def test_w15_makes_only_the_check_and_writes_nothing(tmp_path, api):
    seed_other_run(api)
    head = api.head()
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 0)
    assert [r for r in api.stub.requests if r.method != "GET"] == [], "check-actors only reads"
    assert api.head() == head and api.moves == []


@pytest.mark.req("W-15", "W-12")
@pytest.mark.parametrize("status", [404, 500])
def test_w15_commits_that_cannot_be_read_are_not_actors_ok(tmp_path, api, status):
    seed_other_run(api)
    api.commits_status = status
    res, d = check_actors(tmp_path, api)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert d["actors_ok"] is False


@pytest.mark.req("W-15", "C-3")
def test_w15_never_prints_the_token(tmp_path, api):
    seed_other_run(api, author=OTHER_ACTOR)
    res, d = check_actors(tmp_path, api)
    assert d["actors_ok"] is False
    texts = [res.out, res.err, (tmp_path / "actors.json").read_text(encoding="utf-8")]
    assert all(api.token not in t for t in texts)
