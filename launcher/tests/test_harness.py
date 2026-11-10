"""Checks of the test harness itself, without the launcher: the fake API
against the pinned gate's real commands, the fake's JWT check, the fake
`claude`, and the observation tools. When a launcher test fails, these say
whether the fixtures can be trusted."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import fake_github
import launcher_world as W
from conftest import make_world


def gate_env(gate_dir, api, token):
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    env.update(PYTHONPATH=str(gate_dir), GATE_TOKEN=token, GITHUB_API_URL=api.url,
               GITHUB_REPOSITORY=W.REPOSITORY)
    return env


def gate(gate_dir, api, token, *args):
    with W.quiet_audit():
        return subprocess.run([sys.executable, "-P", "-m", *args], cwd=gate_dir,
                              env=gate_env(gate_dir, api, token), capture_output=True, text=True)


@pytest.fixture
def api_world(tmp_path, template, test_key):
    remote_src, facts = template
    remote = tmp_path / "remote.git"
    shutil.copytree(remote_src, remote)
    api = fake_github.FakeGitHub(test_key.public_key, app_id=W.APP_ID,
                                 installation_id=W.INSTALLATION_ID, account=W.OWNER,
                                 repository=W.REPOSITORY, bare_repo=str(remote)).start()
    token = "ghs_" + "h" * 36
    api.tokens_issued.append(token)
    yield api, remote, facts, token
    api.stop()


def jwt_for(key_pem: bytes, claims: dict) -> str:
    key = serialization.load_pem_private_key(key_pem, password=None)

    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    head = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{head}.{body}.{b64(sig)}"


def get(url, auth):
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


def test_harness_fake_checks_the_jwt_signature(api_world, test_key):
    api = api_world[0]
    now = int(time.time())
    good = jwt_for(test_key.pem, {"iss": W.APP_ID, "iat": now - 60, "exp": now + 540})
    assert get(f"{api.url}/app/installations", f"Bearer {good}")[0] == 200
    bad = good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB")
    assert get(f"{api.url}/app/installations", f"Bearer {bad}")[0] == 401
    expired = jwt_for(test_key.pem, {"iss": W.APP_ID, "iat": now - 700, "exp": now - 100})
    assert get(f"{api.url}/app/installations", f"Bearer {expired}")[0] == 401


def test_harness_gate_opens_a_pr_and_posts_a_proposal_through_the_fake(api_world, gate_at_pin,
                                                                       tmp_path):
    api, remote, facts, token = api_world
    api.issues[5] = {"number": 5, "state": "open", "title": "Add a thing!", "body": "b"}
    with W.quiet_audit():
        W.fast_import(remote, [{"ref": f"refs/heads/{W.ISSUE_BRANCH}", "message": "x",
                                "parent": f"refs/heads/{W.INTEGRATION}^0",
                                "files": {"app/f.py": "x = 1\n"}}])
    res = gate(gate_at_pin, api, token, "gate.publish", "create-pull-request", "--branch",
               W.ISSUE_BRANCH, "--prefix", "ai/5-", "--base", W.INTEGRATION, "--issue", "5")
    assert res.returncode == 0, res.stderr
    assert api.requests_to("POST", r"/pulls$")
    proposal = tmp_path / "p.md"
    proposal.write_text("| bandit | B101 | app/f.py | reason |\n", encoding="utf-8")
    res = gate(gate_at_pin, api, token, "gate.publish", "post-proposal", "--file", str(proposal),
               "--branch", W.ISSUE_BRANCH)
    assert res.returncode == 0, res.stderr
    assert api.requests_to("POST", r"/issues/41/comments$")
    assert W.disallowed_requests(api.requests) == []


def test_harness_gate_check_actors_through_the_fake(api_world, gate_at_pin, tmp_path):
    api, remote, facts, token = api_world
    cfg = tmp_path / "quality.toml"
    cfg.write_text(W.quality_toml(), encoding="utf-8")
    out = tmp_path / "a.json"
    args = ("gate.archive", "check-actors", "--api-repo", W.REPOSITORY, "--branch", "reports",
            "--config", str(cfg), "--out", str(out))
    assert gate(gate_at_pin, api, token, *args).returncode == 0  # no branch yet
    with W.quiet_audit():
        W.fast_import(remote, W.default_records(facts.pr_head, facts.old_head, facts.other_head,
                                                facts.base_head))
    assert gate(gate_at_pin, api, token, *args).returncode == 0
    shas = W.git("--git-dir", str(remote), "rev-list", "reports").split()
    api.foreign_report_commits.add(shas[0])
    assert gate(gate_at_pin, api, token, *args).returncode == 1
    assert json.loads(out.read_text(encoding="utf-8"))["actors_ok"] is False
    assert W.disallowed_requests(api.requests) == []


@pytest.mark.parametrize("variant, event_id, expected", [
    ({}, (100, 10), None),
    ({}, (100, 9), "NOT_A_FAILURE"),
    ({}, (99, 1), "NOT_A_FAILURE"),
    ({}, (200, 1), "SHA_NOT_CURRENT_HEAD"),
    ({"newest_repeated": True}, (100, 10), "REPEATED_FIX"),
    ({"newest_verdict": "ready-for-human"}, (100, 10), "NOT_A_FAILURE"),
])
def test_harness_gate_decides_on_the_records(template, gate_at_pin, tmp_path, variant, event_id,
                                             expected):
    remote_src, facts = template
    remote = tmp_path / "remote.git"
    shutil.copytree(remote_src, remote)
    with W.quiet_audit():
        W.fast_import(remote, W.default_records(facts.pr_head, facts.old_head, facts.other_head,
                                                facts.base_head, **variant))
    reports = W.stored_reports(remote, tmp_path / "stored")
    event = {"workflow_run": {"id": event_id[0], "run_attempt": event_id[1],
                              "path": ".github/workflows/judge.yml",
                              "event": "pull_request_target", "conclusion": "completed"}}
    out = W.run_decide(gate_at_pin, tmp_path / "d", "workflow_run", event, W.pulls_entry(facts), reports)
    assert out["reason_code"] == expected, out


PR_URL = {"url": f"http://127.0.0.1:1/repos/{W.REPOSITORY}/pulls/7"}


@pytest.mark.parametrize("pull_request, verdict, expected", [
    ({}, "changes_requested", "NOT_A_REVIEW"),
    (PR_URL, "changes_requested", None),
    (PR_URL, "pass", "NOT_A_FAILURE"),
], ids=["empty_object", "url_changes_requested", "url_pass"])
def test_harness_lr46a_review_event_for_the_pinned_gate(template, gate_at_pin, tmp_path,
                                                        pull_request, verdict, expected):
    """Evidence for amendment 1, A1: with `"pull_request": {}` the pinned gate
    answers NOT_A_REVIEW; with the PR's URL a `changes_requested` marker acts
    and a `pass` marker adds nothing (the control of the reviewer's test)."""
    remote_src, facts = template
    remote = tmp_path / "remote.git"
    shutil.copytree(remote_src, remote)
    with W.quiet_audit():
        W.fast_import(remote, W.default_records(facts.pr_head, facts.old_head, facts.other_head,
                                                facts.base_head))
    reports = W.stored_reports(remote, tmp_path / "stored")
    c = W.review_comments(facts.pr_head, facts.old_head, verdict)[102]
    event = {"action": "created", "issue": {"number": 7, "pull_request": pull_request},
             "comment": {"body": c["body"], "user": {"login": c["user"]["login"]}},
             "sender": {"login": c["user"]["login"]}}
    out = W.run_decide(gate_at_pin, tmp_path / "d", "issue_comment", event, W.pulls_entry(facts),
                     reports, statuses=W.review_statuses())
    assert out["reason_code"] == expected, out


def test_harness_pr_head_follows_the_branch_and_races_land(api_world, tmp_path):
    """The race machinery of LR-38/LR-48's tests: the fake's PR head follows
    the remote branch; a forced race lands; an unforced race onto an existing
    branch fails as a harness fault (exit 97), never as a model failure."""
    api, remote, facts, token = api_world
    api.pulls[7] = {"number": 7, "state": "open",
                    "head": {"ref": W.PR_BRANCH, "sha": facts.pr_head,
                             "repo": {"full_name": W.REPOSITORY}},
                    "base": {"ref": W.INTEGRATION, "repo": {"full_name": W.REPOSITORY}},
                    "user": {"login": W.BOT_LOGIN}}
    url = f"{api.url}/repos/{W.REPOSITORY}/pulls/7"
    assert get(url, f"Bearer {token}")[1]["head"]["sha"] == facts.pr_head
    clone = tmp_path / "clone"
    with W.quiet_audit():
        W.git("clone", "-q", "--branch", W.PR_BRANCH, str(remote), str(clone))
    for force, code in ((False, 97), (True, 0)):
        out = tmp_path / f"rec-{force}.json"
        record = tmp_path / f"race-{force}.txt"
        env = dict(os.environ, FAKE_CLAUDE_OUT=str(out), FAKE_CLAUDE_MODE=json.dumps(
            [{"op": "push_race", "remote": str(remote), "ref": f"refs/heads/{W.PR_BRANCH}",
              "record": str(record), "force": force}]))
        with W.quiet_audit():
            res = subprocess.run([sys.executable, str(W.FAKE_CLAUDE), "-p"], cwd=clone, env=env,
                                 input=b"", capture_output=True)
        assert res.returncode == code, res.stderr
        assert (tmp_path / f"rec-{force}.json.error").exists() == (code == 97)
    racing = (tmp_path / "race-True.txt").read_text(encoding="utf-8").strip()
    assert get(url, f"Bearer {token}")[1]["head"]["sha"] == racing


def test_harness_gate_limits_output(gate_at_pin, tmp_path):
    cfg = tmp_path / "quality.toml"
    cfg.write_text(W.quality_toml(), encoding="utf-8")
    out = tmp_path / "limits.txt"
    env = {k: v for k, v in os.environ.items() if not k.startswith("CLAUDE")}
    env["PYTHONPATH"] = str(gate_at_pin)
    with W.quiet_audit():
        subprocess.run([sys.executable, "-P", "-m", "gate.publish", "limits", "--config", str(cfg),
                        "--output", str(out)], cwd=gate_at_pin, env=env, check=True)
    text = out.read_text(encoding="utf-8")
    assert f"max-turns={W.MAX_TURNS}" in text and "integration-branch=candidate/a" in text
    assert "Read(workflow/**)" in text


def test_harness_fake_claude_records_and_commits(tmp_path):
    repo = tmp_path / "repo"
    with W.quiet_audit():
        W.git("init", "-q", "-b", "main", str(repo))
        W.git("-C", str(repo), "config", "user.name", W.BOT_LOGIN)
        W.git("-C", str(repo), "config", "user.email", W.BOT_EMAIL)
        W.git("-C", str(repo), "commit", "-q", "--allow-empty", "-m", "start")
        settings = tmp_path / "s.json"
        settings.write_text('{"permissions": {"deny": ["WebFetch"]}}', encoding="utf-8")
        out = tmp_path / "rec.json"
        env = dict(os.environ, FAKE_CLAUDE_OUT=str(out), FAKE_CLAUDE_MODE=json.dumps(
            [{"op": "commit", "path": "a/b.py"}, {"op": "proposal", "text": "p"}]))
        res = subprocess.run([sys.executable, str(W.FAKE_CLAUDE), "-p", "--settings", str(settings),
                              "--output-format", "json"], cwd=repo, env=env, input=b"PROMPT\n",
                             capture_output=True)
    assert res.returncode == 0, res.stderr
    rec = json.loads(out.read_text(encoding="utf-8"))
    assert rec["stdin"] == "PROMPT\n" and rec["git"]["branch"] == "main"
    assert json.loads(rec["settings"])["permissions"]["deny"] == ["WebFetch"]
    assert json.loads(res.stdout)["num_turns"] == 13
    assert (repo / W.PROPOSAL_FILE).exists()
    assert W.git("-C", str(repo), "log", "-1", "--format=%s") == "Add a/b.py"


def test_harness_pre_receive_hook_refuses_a_push(tmp_path, template):
    remote = tmp_path / "remote.git"
    shutil.copytree(template[0], remote)
    (remote / "hooks" / "pre-receive").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8",
                                                  newline="\n")
    clone = tmp_path / "clone"
    with W.quiet_audit():
        W.git("clone", "-q", str(remote), str(clone))
        W.git("-C", str(clone), "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-q",
              "--allow-empty", "-m", "x")
        res = subprocess.run(["git", "-C", str(clone), "push", "origin", "HEAD:refs/heads/new"],
                             capture_output=True)
    assert res.returncode != 0


def test_harness_world_observes_a_dummy_run(tmp_path, monkeypatch, test_key, template):
    """The observation tools, on a dummy module that is not the launcher."""
    dummy = types.ModuleType("dummy_launcher")
    for name in ("current_sid", "is_admin", "gh_login_present", "git_credential_present",
                 "acl_of", "can_write", "folder_openable"):
        setattr(dummy, name, lambda *a: None)

    def main(argv):
        print("first line")
        subprocess.run(["git", "--version"], capture_output=True)
        subprocess.run([sys.executable, "-c", "pass", "a b", "", 'q"uote'], capture_output=True)
        os.write(1, b"from the file descriptor\n")
        print("STOPPED DUMMY_CODE: a plain message")
        return 1

    dummy.main = main
    w = make_world(tmp_path / "w", monkeypatch, dummy, test_key, template)
    try:
        res = w.run("check")
    finally:
        w.close()
    assert res.code == 1 and res.stop_code == "DUMMY_CODE", res.describe()
    assert res.git_commands("--version")
    py = [e for e in res.events if e.get("argv") and "a b" in e["argv"]]
    assert py and py[0]["argv"][1:] == ["-c", "pass", "a b", "", 'q"uote'], py
    assert W.same_path(py[0]["argv"][0], sys.executable)
    assert "from the file descriptor" in res.stdout
    assert res.requests == [] and res.run_dirs == []
