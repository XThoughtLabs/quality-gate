"""gate.review_local: rules L-1 to L-8. A local stub plays the GitHub API; a small Python fake plays the model."""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

from gatekit import (SENTINEL_PREFIX, assert_no_traceback, assert_rc, assert_refused, bare_mentions, base_env,
                     load_out, read_json, run_gate, write_text)

REPO = "example-org/example-app"
PR_N, ISSUE_N, INSTALL_ID, APP_ID = 7, 3, "555", "424242"
SHA = "3" * 40
MOVED = "9" * 40
INSTALL_TOKEN = "SENTINEL-VALUE-INSTALLTOKEN"
SPEC_TEXT = "SPEC-MARKER-ALPHA: the application keeps a status history.\n"
ISSUE = {"title": "ISSUE-TITLE-MARKER", "body": "ISSUE-BODY-MARKER please fix the history bug"}
DIFF_TEXT = "diff --git a/src/app.py b/src/app.py\n+DIFF-MARKER-GAMMA = 1\n"
FINDING_WHAT = "FINDING-WHAT-MARKER a check is missing, cc @evilhandle and @claude please fix it"

FAKE = r'''
import json, os, sys
REC = __REC__
MODE = __MODE__
args = sys.argv[1:]
stdin = sys.stdin.read()
schema = out = None
for i, a in enumerate(args):
    if a == "--output-schema" and i + 1 < len(args):
        schema = args[i + 1]
    if a == "-o" and i + 1 < len(args):
        out = args[i + 1]
rec = {"argv": args, "cwd": os.getcwd(), "listing": sorted(os.listdir(".")), "env": dict(os.environ),
       "schema": schema, "out": out}
try:
    rec["schema_text"] = open(schema).read()
except Exception:
    rec["schema_text"] = None
open(os.path.join(REC, "record.json"), "w").write(json.dumps(rec))
open(os.path.join(REC, "stdin.txt"), "w", encoding="utf-8").write(stdin)
sys.stdout.write("FAKE-MODEL-STDOUT\n")
if out is None or MODE == "missing":
    sys.exit(0)
if MODE == "pass":
    body = {"verdict": "pass", "findings": []}
elif MODE == "changes":
    body = {"verdict": "changes_requested",
            "findings": [{"severity": "high", "where": "src/app.py:10", "what": __WHAT__}]}
elif MODE == "invalid_json":
    open(out, "w").write("this is { not json")
    sys.exit(0)
elif MODE == "empty":
    open(out, "w").write("")
    sys.exit(0)
elif MODE == "not_object":
    open(out, "w").write("[1, 2]")
    sys.exit(0)
elif MODE == "bad_verdict":
    body = {"verdict": "approve", "findings": []}
else:
    raise SystemExit("unknown mode")
open(out, "w").write(json.dumps(body))
'''


def b64u(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@pytest.fixture(scope="session")
def rsa_key(tmp_path_factory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    path = tmp_path_factory.mktemp("reviewer-key") / "reviewer-app.pem"
    path.write_bytes(pem)
    text = pem.decode()
    return type("K", (), {"path": path, "public": key.public_key(), "text": text,
                          "marker": text.splitlines()[1]})()


def report_text(sha, marker):
    return json.dumps({"verification": {"head_sha": sha, "pr": PR_N}, "marker": marker})


class RL:
    def __init__(self, tmp_path, stub, key):
        self.tmp, self.stub, self.key = Path(tmp_path), stub, key
        self.rec_dir = self.tmp / "model-record"
        self.rec_dir.mkdir()
        self.out = self.tmp / "review-out.json"
        self.token_calls: list[bool] = []
        self.bad_auth: list[str] = []
        self.spec_status = 200
        self.issue_status = 200
        self.diff_status = 200
        self.head_always = None
        self.move_after_model = False
        self.reports = {f"reports/{PR_N}/1001-1/report.json": report_text(SHA, "JUDGE-REPORT-MARKER-DELTA")}
        self._routes()

    # ------------------------------------------------------------------ stub
    def _auth_ok(self, req):
        ok = INSTALL_TOKEN in req.header("authorization")
        if not ok:
            self.bad_auth.append(f"{req.method} {req.path}")
        return ok

    def _verify_jwt(self, req):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        auth = req.header("authorization")
        token = auth.split(" ", 1)[1] if " " in auth else ""
        try:
            h, p, s = token.split(".")
            header, payload = json.loads(b64u(h)), json.loads(b64u(p))
            self.key.public.verify(b64u(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
            ok = header.get("alg") == "RS256" and str(payload.get("iss")) == APP_ID
        except Exception:
            ok = False
        self.token_calls.append(ok)
        return ok

    def _routes(self):
        s = self.stub
        repo = re.escape(f"/repos/{REPO}")

        def token(req):
            if not self._verify_jwt(req):
                return 401, {"message": "invalid app JWT"}
            return 201, {"token": INSTALL_TOKEN, "expires_at": "2099-01-01T00:00:00Z"}

        def pull(req):
            if not self._auth_ok(req):
                return 401, {"message": "Bad credentials"}
            if "diff" in req.header("accept"):
                return (200, DIFF_TEXT) if self.diff_status == 200 else (self.diff_status, {"message": "no diff"})
            head = self.head_always or SHA
            if self.move_after_model and (self.rec_dir / "record.json").exists():
                head = MOVED
            return 200, {"number": PR_N, "state": "open", "title": "PR-TITLE-MARKER", "body": "PR-BODY-MARKER",
                         "head": {"sha": head}, "base": {"ref": "candidate/a"}}

        def spec(req):
            if not self._auth_ok(req):
                return 401, {"message": "Bad credentials"}
            return (200, SPEC_TEXT) if self.spec_status == 200 else (self.spec_status, {"message": "Not Found"})

        def issue(req):
            if not self._auth_ok(req):
                return 401, {"message": "Bad credentials"}
            return (200, ISSUE) if self.issue_status == 200 else (self.issue_status, {"message": "Not Found"})

        def tree(req):
            if not self._auth_ok(req):
                return 401, {"message": "Bad credentials"}
            entries = [{"path": p, "type": "blob", "mode": "100644", "sha": "e" * 40} for p in self.reports]
            entries += [{"path": p.rsplit("/", 1)[0] + "/context.json", "type": "blob", "mode": "100644", "sha": "f" * 40}
                        for p in self.reports]
            entries.append({"path": "README.md", "type": "blob", "mode": "100644", "sha": "d" * 40})
            return 200, {"sha": "c" * 40, "tree": entries, "truncated": False}

        def contents(req):
            if not self._auth_ok(req):
                return 401, {"message": "Bad credentials"}
            path = req.path.split("/contents/", 1)[1]
            return (200, self.reports[path]) if path in self.reports else (404, {"message": "Not Found"})

        s.route("POST", re.escape(f"/app/installations/{INSTALL_ID}/access_tokens"), token)
        s.route("GET", repo + f"/pulls/{PR_N}", pull)
        s.route("GET", repo + "/contents/SPEC.md", spec)
        s.route("GET", repo + f"/issues/{ISSUE_N}", issue)
        s.route("GET", repo + "/git/trees/reports", tree)
        s.route("GET", repo + "/contents/(reports/.+)", contents)
        s.route("POST", repo + r"/statuses/[0-9a-f]+", lambda req: (201, {"id": 1}) if self._auth_ok(req) else (401, {}))
        s.route("POST", repo + rf"/issues/{PR_N}/comments", lambda req: (201, {"id": 2}) if self._auth_ok(req) else (401, {}))

    # ------------------------------------------------------------------ running
    def write_fake(self, mode, path=None, shebang=False):
        code = FAKE.replace("__REC__", repr(str(self.rec_dir))).replace("__MODE__", repr(mode)).replace("__WHAT__", repr(FINDING_WHAT))
        path = Path(path or self.tmp / "fake_codex.py")
        if shebang:
            code = f"#!{sys.executable}\n" + code
        write_text(path, code)
        return path

    def command(self, mode):
        fake = self.write_fake(mode)

        def q(p):
            s = Path(p).as_posix()
            return f'"{s}"' if " " in s else s

        return f"{q(sys.executable)} {q(fake)}"

    def env(self, **change):
        e = {"REVIEWER_APP_ID": APP_ID, "REVIEWER_APP_INSTALLATION_ID": INSTALL_ID,
             "REVIEWER_APP_PRIVATE_KEY_PATH": str(self.key.path)}
        e.update(change)
        return base_env(e)

    def run(self, mode="pass", *, sha=SHA, env=None, codex="auto", cwd=None):
        cmd = self.command(mode) if codex == "auto" else codex
        args = ["--repo", REPO, "--pr", PR_N, "--sha", sha, "--issue", ISSUE_N, "--api-url", self.stub.url, "--out", self.out]
        if cmd is not None:
            args += ["--codex", cmd]
        res = run_gate("review_local", *args, env=env if env is not None else self.env(), cwd=cwd or self.tmp)
        return res, load_out(res, self.out)

    # ------------------------------------------------------------------ observations
    @property
    def record(self):
        p = self.rec_dir / "record.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    @property
    def stdin(self):
        p = self.rec_dir / "stdin.txt"
        return p.read_text(encoding="utf-8") if p.exists() else None

    def statuses(self):
        return [r for r in self.stub.reqs("POST") if re.fullmatch(r"/repos/.+/statuses/.+", r.path)]

    def comments(self):
        return [r for r in self.stub.reqs("POST") if r.path.endswith("/comments")]

    def nothing_posted(self):
        assert self.statuses() == [] and self.comments() == [], "nothing may be posted"


@pytest.fixture
def rl(tmp_path, stub, rsa_key):
    return RL(tmp_path, stub, rsa_key)


def assert_out(out, *, posted, state, code, sha=SHA):
    assert out is not None, "--out must be written"
    assert set(out) >= {"posted", "state", "code", "sha"}
    assert out["posted"] is posted and out["sha"] == sha
    if state is None:
        assert not out["state"]
    else:
        assert out["state"] == state
    if code is None:
        assert not out["code"]
    else:
        assert out["code"] == code


# ----------------------------------------------------------------------------- L-3 and L-8


@pytest.mark.req("L-3", "L-8")
def test_l3_pass_posts_success_on_exactly_the_sha(rl):
    res, out = rl.run("pass")
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert rl.stub.reqs("POST", r"/app/installations/.+/access_tokens") and rl.token_calls[0] is True, \
        "the app token is asked for with a valid RS256 JWT whose iss is the app id"
    sts = rl.statuses()
    assert len(sts) >= 1 and all(r.path == f"/repos/{REPO}/statuses/{SHA}" for r in sts)
    body = sts[-1].json()
    assert body["state"] == "success" and body["context"] == "independent-review"
    assert all(r.json()["state"] != "failure" for r in sts)
    assert isinstance(body.get("description", ""), str)
    assert_out(out, posted=True, state="success", code=None)
    assert rl.bad_auth == [], f"every call after the token must carry the installation token: {rl.bad_auth}"


@pytest.mark.req("L-3", "L-8", "C-4", "C-5")
def test_l3_changes_requested_posts_failure_and_a_comment_with_the_findings(rl):
    res, out = rl.run("changes")
    assert_rc(res, 0)
    sts = rl.statuses()
    assert sts and sts[-1].json()["state"] == "failure" and sts[-1].json()["context"] == "independent-review"
    assert all(r.json()["state"] != "success" for r in sts)
    assert all(r.path == f"/repos/{REPO}/statuses/{SHA}" for r in sts)
    comments = rl.comments()
    assert len(comments) == 1 and comments[0].path == f"/repos/{REPO}/issues/{PR_N}/comments"
    body = comments[0].json()["body"]
    assert "FINDING-WHAT-MARKER" in body and "src/app.py" in body, "the comment carries the findings"
    assert bare_mentions(body) == [], f"bare mention in the comment: {bare_mentions(body)}"
    for r in sts:
        assert bare_mentions(r.json().get("description", "")) == []
    assert_out(out, posted=True, state="failure", code=None)


# ----------------------------------------------------------------------------- L-1


@pytest.mark.req("L-1")
def test_l1_the_model_gets_exactly_the_four_inputs_on_stdin_and_nothing_else(rl):
    res, _ = rl.run("pass")
    assert_rc(res, 0)
    stdin = rl.stdin
    assert stdin is not None, "the model was not run"
    for marker in ("SPEC-MARKER-ALPHA", "ISSUE-TITLE-MARKER", "ISSUE-BODY-MARKER", "DIFF-MARKER-GAMMA", "JUDGE-REPORT-MARKER-DELTA"):
        assert marker in stdin, f"{marker} must be given to the model"
    for marker in ("PR-TITLE-MARKER", "PR-BODY-MARKER"):
        assert marker not in stdin, f"{marker}: the pull request's own text is not one of the four inputs"
    for secret in (INSTALL_TOKEN, rl.key.marker, "BEGIN RSA PRIVATE KEY", str(rl.key.path), "REVIEWER_"):
        assert secret not in stdin, "secrets and settings must not reach the model"


@pytest.mark.req("L-1", "C-3", "L-7")
def test_l1_the_models_environment_has_no_reviewer_variables_and_no_secret(rl):
    res, _ = rl.run("pass")
    rec = rl.record
    assert rec is not None, "the model was not run"
    assert rec is not None
    assert not [k for k in rec["env"] if k.upper().startswith("REVIEWER_")], "no REVIEWER_* variable may reach the model"
    for k, v in rec["env"].items():
        assert INSTALL_TOKEN not in v and rl.key.marker not in v and str(rl.key.path) not in v, f"{k} leaks a secret"
    assert not [a for a in rec["argv"] if INSTALL_TOKEN in a or rl.key.marker in a]


@pytest.mark.req("L-1")
def test_l1_the_model_runs_in_an_empty_temporary_folder(rl):
    res, _ = rl.run("pass")
    rec = rl.record
    assert rec is not None, "the model was not run"
    cwd = Path(rec["cwd"]).resolve()
    assert cwd != rl.tmp.resolve() and rl.tmp.resolve() not in cwd.parents, "not in the caller's folder"
    assert Path(tempfile.gettempdir()).resolve() in cwd.parents, f"{cwd} is not a temporary folder"
    ours = {Path(p).name for p in (rec["schema"], rec["out"]) if p and Path(p).parent.resolve() == cwd}
    assert [f for f in rec["listing"] if f not in ours] == [], "the folder holds nothing but the files named in the arguments"


@pytest.mark.req("L-1", "C-3", "L-7")
def test_the_key_and_the_installation_token_never_reach_a_log_or_the_out_file_or_a_post(rl):
    res, out = rl.run("changes")
    assert_rc(res, 0)
    seen = {"stdout": res.out, "stderr": res.err, "--out": rl.out.read_text(encoding="utf-8")}
    for r in rl.stub.reqs("POST"):
        if not r.path.startswith("/app/"):
            seen[f"POST {r.path}"] = r.body.decode("utf-8", "replace")
    for where, text in seen.items():
        assert rl.key.marker not in text and "BEGIN RSA PRIVATE KEY" not in text, f"the key leaked into {where}"
        assert INSTALL_TOKEN not in text, f"the installation token leaked into {where}"


# ----------------------------------------------------------------------------- L-2


@pytest.mark.req("L-2")
def test_l2_codex_override_gets_the_schema_and_output_arguments_and_the_result_is_read_from_the_file(rl):
    res, out = rl.run("pass")
    assert_rc(res, 0)
    rec = rl.record
    assert rec is not None, "the model was not run"
    args = rec["argv"]
    assert "--output-schema" in args and "-o" in args, f"always passed: {args}"
    assert args[args.index("--output-schema") + 1] == rec["schema"] and rec["schema"]
    assert args[args.index("-o") + 1] == rec["out"] and rec["out"]
    schema = json.loads(rec["schema_text"])
    import jsonschema

    validator = jsonschema.validators.validator_for(schema)(schema)
    good_pass = {"verdict": "pass", "findings": []}
    good_changes = {"verdict": "changes_requested", "findings": [{"severity": "high", "where": "src/app.py:1", "what": "x"}]}
    assert list(validator.iter_errors(good_pass)) == [], "the schema must accept a pass result"
    assert list(validator.iter_errors(good_changes)) == [], "the schema must accept a changes_requested result"
    assert list(validator.iter_errors({"verdict": "approve", "findings": []})) != [], "the schema must reject another verdict"
    assert rl.statuses() and rl.statuses()[-1].json()["state"] == "success", "the result comes from the -o file"


@pytest.mark.req("L-2")
def test_l2_the_default_command_is_codex_exec_with_the_documented_flags(rl, tmp_path):
    if sys.platform.startswith("win"):
        pytest.skip("the default command needs a fake 'codex' on PATH, which needs an executable launcher; "
                    "not checked on Windows (see the report)")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = rl.write_fake("pass", bin_dir / "codex", shebang=True)
    os.chmod(shim, 0o755)
    env = rl.env(PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    res, out = rl.run("pass", env=env, codex=None)
    assert_rc(res, 0)
    assert rl.record is not None, "the model was not run"
    args = rl.record["argv"]
    assert args[:1] == ["exec"]
    for flag in ("--sandbox", "--skip-git-repo-check", "--ephemeral", "--output-schema", "-o"):
        assert flag in args, f"{flag} missing from {args}"
    assert args[args.index("--sandbox") + 1] == "read-only"
    assert args[-1] == "-", "the prompt is read from stdin"


# ----------------------------------------------------------------------------- the routes


@pytest.mark.req("L-0")
def test_the_documented_routes_headers_and_query_strings_are_used(rl):
    res, _ = rl.run("pass")
    assert_rc(res, 0)
    reqs = rl.stub.requests
    spec = [r for r in reqs if r.path.endswith("/contents/SPEC.md")]
    assert spec and spec[0].q("ref") == SHA and "application/vnd.github.raw" in spec[0].header("accept")
    diff = [r for r in reqs if r.path.endswith(f"/pulls/{PR_N}") and "diff" in r.header("accept")]
    assert diff and "application/vnd.github.v3.diff" in diff[0].header("accept")
    assert [r for r in reqs if r.path.endswith(f"/pulls/{PR_N}") and "diff" not in r.header("accept")], "the PR itself is read"
    assert [r for r in reqs if r.path.endswith(f"/issues/{ISSUE_N}")]
    tree = [r for r in reqs if r.path.endswith("/git/trees/reports")]
    assert tree and tree[0].q("recursive") == "1"
    rep = [r for r in reqs if "/contents/reports/" in r.path]
    assert rep and rep[0].q("ref") == "reports" and "application/vnd.github.raw" in rep[0].header("accept")


@pytest.mark.req("L-6")
def test_l6_the_newest_report_for_this_sha_is_the_one_the_model_gets(rl):
    rl.reports = {
        f"reports/{PR_N}/99-1/report.json": report_text(SHA, "OLD-NINETY-NINE"),
        f"reports/{PR_N}/100-1/report.json": report_text(SHA, "OLDER-ATTEMPT"),
        f"reports/{PR_N}/100-2/report.json": report_text(SHA, "NEWEST-ATTEMPT-TWO"),
        f"reports/{PR_N}/101-1/report.json": report_text(MOVED, "WRONG-SHA-REPORT"),
        "reports/8/500-1/report.json": report_text(SHA, "OTHER-PR-REPORT"),
    }
    res, _ = rl.run("pass")
    assert_rc(res, 0)
    stdin = rl.stdin
    assert "NEWEST-ATTEMPT-TWO" in stdin
    for marker in ("OLD-NINETY-NINE", "OLDER-ATTEMPT", "WRONG-SHA-REPORT", "OTHER-PR-REPORT"):
        assert marker not in stdin, f"{marker} must not be given to the model"


# ----------------------------------------------------------------------------- L-4


@pytest.mark.req("L-4", "L-8")
def test_l4_sha_that_is_not_the_head_posts_nothing_and_never_starts_the_model(rl):
    rl.head_always = MOVED
    res, out = rl.run("pass")
    assert_rc(res, 1)
    assert_no_traceback(res)
    rl.nothing_posted()
    assert rl.record is None, "the model must not be run for a stale sha"
    assert_out(out, posted=False, state=None, code="HEAD_MOVED")


@pytest.mark.req("L-4", "L-8")
def test_l4_head_that_moves_while_the_model_runs_posts_nothing(rl):
    rl.move_after_model = True
    res, out = rl.run("pass")
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert rl.record is not None, "precondition: the model ran"
    rl.nothing_posted()
    assert_out(out, posted=False, state=None, code="HEAD_MOVED")


@pytest.mark.req("L-4")
def test_l4_control_head_that_stays_is_posted(rl):
    res, out = rl.run("pass")
    assert_rc(res, 0)
    assert rl.statuses()


# ----------------------------------------------------------------------------- L-5


@pytest.mark.req("L-5", "L-8")
@pytest.mark.parametrize("mode", ["missing", "invalid_json", "empty", "not_object", "bad_verdict"])
def test_l5_invalid_model_output_posts_nothing_and_fails_closed(rl, mode):
    res, out = rl.run(mode)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert rl.record is not None, "precondition: the model ran"
    rl.nothing_posted()
    assert_out(out, posted=False, state=None, code="MODEL_OUTPUT_INVALID")


# ----------------------------------------------------------------------------- L-6


@pytest.mark.req("L-6", "L-8")
@pytest.mark.parametrize("name,setup", [
    ("spec-missing", lambda rl: setattr(rl, "spec_status", 404)),
    ("issue-missing", lambda rl: setattr(rl, "issue_status", 404)),
    ("diff-missing", lambda rl: setattr(rl, "diff_status", 404)),
    ("no-judge-report-at-all", lambda rl: setattr(rl, "reports", {})),
    ("judge-report-only-for-another-sha", lambda rl: setattr(
        rl, "reports", {f"reports/{PR_N}/1001-1/report.json": report_text(MOVED, "OTHER-SHA")})),
    ("judge-report-only-for-another-pr", lambda rl: setattr(
        rl, "reports", {"reports/8/1001-1/report.json": report_text(SHA, "OTHER-PR")})),
])
def test_l6_a_missing_input_runs_no_model_and_posts_nothing(rl, name, setup):
    setup(rl)
    res, out = rl.run("pass")
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert rl.record is None, "no model may run when an input is missing"
    rl.nothing_posted()
    assert_out(out, posted=False, state=None, code="MISSING_INPUT")


# ----------------------------------------------------------------------------- L-7


@pytest.mark.req("L-7", "C-3")
def test_l7_key_path_variable_missing_exits_2_and_names_the_variable(rl):
    res, out = rl.run("pass", env=rl.env(REVIEWER_APP_PRIVATE_KEY_PATH=None))
    assert_refused(res, 2)
    assert "REVIEWER_APP_PRIVATE_KEY_PATH" in res.both
    rl.nothing_posted()
    assert rl.record is None


@pytest.mark.req("L-7", "C-3")
def test_l7_key_path_that_does_not_exist_exits_2_and_names_the_variable(rl):
    res, out = rl.run("pass", env=rl.env(REVIEWER_APP_PRIVATE_KEY_PATH=str(rl.tmp / "no-such-key.pem")))
    assert_refused(res, 2)
    assert "REVIEWER_APP_PRIVATE_KEY_PATH" in res.both
    rl.nothing_posted()


@pytest.mark.req("L-7", "C-3")
def test_l7_key_path_that_is_a_folder_exits_2(rl):
    res, out = rl.run("pass", env=rl.env(REVIEWER_APP_PRIVATE_KEY_PATH=str(rl.tmp)))
    assert_refused(res, 2)
    assert "REVIEWER_APP_PRIVATE_KEY_PATH" in res.both
    rl.nothing_posted()


@pytest.mark.req("L-7", "C-3")
@pytest.mark.parametrize("content", [f"{SENTINEL_PREFIX}-1234 this is not a key", "",
                                     f"-----BEGIN RSA PRIVATE KEY-----\n{SENTINEL_PREFIX}-5678\n-----END RSA PRIVATE KEY-----\n"],
                         ids=["garbage", "empty", "pem-envelope-with-garbage"])
def test_l7_unreadable_key_exits_2_names_the_variable_and_never_prints_the_content(rl, content):
    bad = write_text(rl.tmp / "bad-key.pem", content)
    res, out = rl.run("pass", env=rl.env(REVIEWER_APP_PRIVATE_KEY_PATH=str(bad)))
    assert_refused(res, 2)
    assert "REVIEWER_APP_PRIVATE_KEY_PATH" in res.both
    assert SENTINEL_PREFIX not in res.both, "the content of the key file must never be printed"
    if rl.out.exists():
        assert SENTINEL_PREFIX not in rl.out.read_text(encoding="utf-8")
    rl.nothing_posted()
    assert rl.record is None


# ----------------------------------------------------------------------------- C-2


@pytest.mark.req("C-2")
def test_usage_error_exits_2(tmp_path):
    out = tmp_path / "o.json"
    res = run_gate("review_local", "--repo", REPO, "--out", out, cwd=tmp_path)
    assert_refused(res, 2, out)
