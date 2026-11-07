"""gate.env_check: rules E-1 to E-5 (and the parts of C-2, C-3, Q-2 that show here)."""
from __future__ import annotations

import re
import sys

import pytest

from gatekit import (SENTINEL_PREFIX, assert_no_traceback, assert_rc, assert_refused, base_env, closed_port_url,
                     load_out, make_config, run_gate)

REPO = "example-org/example-app"
TOKEN_V = "SENTINEL-VALUE-1111"
KEY_V = "SENTINEL-VALUE-2222"
APP_ID_V = "7391824"
PROBE_V = "SENTINEL-VALUE-4321"
NOTE_V = "SENTINEL-VALUE-3456"
GOOD_KEY = f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_V}\n-----END RSA PRIVATE KEY-----\n"

SECRET_ITEMS = ["secret:CLAUDE_CODE_OAUTH_TOKEN", "secret:EXECUTOR_APP_PRIVATE_KEY", "variable:EXECUTOR_APP_ID"]


def executor_env(**override):
    env = {"CLAUDE_CODE_OAUTH_TOKEN": TOKEN_V, "EXECUTOR_APP_PRIVATE_KEY": GOOD_KEY, "EXECUTOR_APP_ID": APP_ID_V}
    env.update(override)
    return env


def run_env(tmp_path, role, env_extra=None, *, config=None, with_out=True, cwd=None):
    out = tmp_path / "env-out.json"
    args = ["--role", role]
    if config:
        args += ["--config", config]
    if with_out:
        args += ["--out", out]
    res = run_gate("env_check", *args, env=base_env(env_extra), cwd=cwd or tmp_path)
    return res, (load_out(res, out) if with_out else None), out


def line_for(res, item):
    """The printed line for an item: ('OK', None) or ('BROKEN', reason)."""
    for line in res.both.splitlines():
        if line == f"OK {item}":
            return "OK", None
        if line.startswith(f"BROKEN {item}: "):
            return "BROKEN", line[len(f"BROKEN {item}: "):]
    return None, None


def items_by_name(data):
    return {i["item"]: i for i in data["items"]}


def assert_item(res, data, item, ok):
    state, reason = line_for(res, item)
    assert state == ("OK" if ok else "BROKEN"), f"no {'OK' if ok else 'BROKEN'} line for {item}\n{res.describe()}"
    entry = items_by_name(data)[item]
    assert entry["ok"] is ok
    if not ok:
        assert isinstance(entry["reason"], str) and entry["reason"].strip(), f"broken item {item} has no reason"
        assert reason.strip()


# ----------------------------------------------------------------------------- API permission stub

ROUTES = {
    ("checks", "write"): ("POST", "/repos/{repo}/check-runs"),
    ("contents", "write"): ("POST", "/repos/{repo}/git/refs"),
    ("pull-requests", "write"): ("POST", "/repos/{repo}/pulls"),
    ("actions", "read"): ("GET", "/repos/{repo}/actions/runs"),
    ("contents", "read"): ("GET", "/repos/{repo}"),
}
ROLE_PERMS = {
    "run": {"allowed": [("contents", "read")],
            "denied": [("contents", "write"), ("checks", "write"), ("pull-requests", "write")]},
    "publish": {"allowed": [("checks", "write"), ("pull-requests", "write"), ("actions", "read"), ("contents", "read")],
                "denied": [("contents", "write")]},
    "archive": {"allowed": [("contents", "write"), ("checks", "write")], "denied": [("pull-requests", "write")]},
    "feedback": {"allowed": [("pull-requests", "write"), ("contents", "read")],
                 "denied": [("contents", "write"), ("checks", "write")]},
}
API_ROLES = list(ROLE_PERMS)


def correct_status(perm, role):
    if perm in ROLE_PERMS[role]["denied"]:
        return 403
    return 200 if perm[1] == "read" else 422


def configure_stub(stub, role, overrides=None):
    overrides = overrides or {}
    every = ROLE_PERMS[role]["allowed"] + ROLE_PERMS[role]["denied"]
    for perm in every:
        method, template = ROUTES[perm]
        status = overrides.get(perm, correct_status(perm, role))
        stub.route(method, re.escape(template.format(repo=REPO)), (status, {"message": "probe"}))


def api_env(stub_url, role, **extra):
    env = {"GITHUB_API_URL": stub_url, "GITHUB_REPOSITORY": REPO, "GATE_PROBE_TOKEN": PROBE_V,
           "UNRELATED_NOTE": NOTE_V}
    env.update(extra)
    return env


def perm_name(role, perm):
    """The exact item name of E-3: permission:<name>-<read|write>:<the state that is required>."""
    state = "denied" if perm in ROLE_PERMS[role]["denied"] else "allowed"
    return f"permission:{perm[0]}-{perm[1]}:{state}"


def perm_item(data, role, perm):
    name = perm_name(role, perm)
    found = [it for it in data["items"] if it["item"] == name]
    assert len(found) == 1, f"expected exactly one item {name!r}, got {[i['item'] for i in data['items']]}"
    return found[0]


# ----------------------------------------------------------------------------- E-1


@pytest.mark.req("E-1")
@pytest.mark.parametrize("role", ["executor", "spec-tests"])
def test_e1_all_present_is_ok(tmp_path, role):
    res, data, _ = run_env(tmp_path, role, executor_env())
    assert_rc(res, 0)
    assert_no_traceback(res)
    assert data["role"] == role and data["ok"] is True
    assert {i["item"] for i in data["items"]} >= set(SECRET_ITEMS)
    for item in SECRET_ITEMS:
        assert_item(res, data, item, True)


@pytest.mark.req("E-1")
@pytest.mark.parametrize("role", ["executor", "spec-tests"])
@pytest.mark.parametrize("broken", SECRET_ITEMS)
@pytest.mark.parametrize("how", ["missing", "empty"])
def test_e1_missing_or_empty_names_the_part(tmp_path, role, broken, how):
    name = broken.split(":", 1)[1]
    res, data, _ = run_env(tmp_path, role, executor_env(**{name: None if how == "missing" else ""}))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert data["ok"] is False
    assert_item(res, data, broken, False)
    for other in SECRET_ITEMS:
        if other != broken:
            assert_item(res, data, other, True)


@pytest.mark.req("E-1")
@pytest.mark.parametrize("header", ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"])
def test_e1_pem_header_line_is_accepted(tmp_path, header):
    key = f"{header}\n{KEY_V}\n{header.replace('BEGIN', 'END')}\n"
    res, data, _ = run_env(tmp_path, "executor", executor_env(EXECUTOR_APP_PRIVATE_KEY=key))
    assert_rc(res, 0)
    assert_item(res, data, "secret:EXECUTOR_APP_PRIVATE_KEY", True)


@pytest.mark.req("E-1")
@pytest.mark.parametrize("value", [KEY_V, f"just text {KEY_V}", "MIIEvQIBADANBgkqhkiG9w0BAQEF"])
def test_e1_private_key_without_pem_header_is_broken(tmp_path, value):
    res, data, _ = run_env(tmp_path, "executor", executor_env(EXECUTOR_APP_PRIVATE_KEY=value))
    assert_rc(res, 1)
    assert_item(res, data, "secret:EXECUTOR_APP_PRIVATE_KEY", False)
    assert_item(res, data, "secret:CLAUDE_CODE_OAUTH_TOKEN", True)
    assert_item(res, data, "variable:EXECUTOR_APP_ID", True)


@pytest.mark.req("E-1")
@pytest.mark.parametrize("value", ["1", "7391824", "42"])
def test_e1_app_id_positive_integer_is_ok(tmp_path, value):
    res, data, _ = run_env(tmp_path, "executor", executor_env(EXECUTOR_APP_ID=value))
    assert_rc(res, 0)
    assert_item(res, data, "variable:EXECUTOR_APP_ID", True)


@pytest.mark.req("E-1")
@pytest.mark.parametrize("value", ["0", "-5", "abc", "12.5", "12abc", "1e3", SENTINEL_PREFIX + "-1234", " "])
def test_e1_app_id_not_positive_integer_is_broken(tmp_path, value):
    res, data, _ = run_env(tmp_path, "executor", executor_env(EXECUTOR_APP_ID=value))
    assert_rc(res, 1)
    assert_item(res, data, "variable:EXECUTOR_APP_ID", False)
    assert_item(res, data, "secret:CLAUDE_CODE_OAUTH_TOKEN", True)
    assert_item(res, data, "secret:EXECUTOR_APP_PRIVATE_KEY", True)


# ----------------------------------------------------------------------------- E-2


def run_role_env(tmp_path, stub, env_extra):
    configure_stub(stub, "run")
    return run_env(tmp_path, "run", api_env(stub.url, "run", **env_extra))


@pytest.mark.req("E-2")
def test_e2_run_without_any_secret_is_ok(tmp_path, stub):
    res, data, _ = run_role_env(tmp_path, stub, {"PUBLIC_KEY": "x", "MY_SETTING": "y", "EMPTY_API_KEY": ""})
    assert_rc(res, 0)
    assert data["ok"] is True
    assert not [i for i in data["items"] if i["item"].startswith("secret-present:")], \
        "GATE_PROBE_TOKEN, an empty value and names without a listed word must not be flagged"


@pytest.mark.req("E-2")
@pytest.mark.parametrize("name", ["DEPLOY_TOKEN", "SOME_SECRET", "DB_PASSWORD", "SIGNING_PRIVATE_KEY",
                                  "CLOUD_CREDENTIAL", "MAPS_API_KEY"])
def test_e2_each_listed_word_is_flagged(tmp_path, stub, name):
    res, data, _ = run_role_env(tmp_path, stub, {name: "SENTINEL-VALUE-5555", "PUBLIC_KEY": "x"})
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert_item(res, data, f"secret-present:{name}", False)
    flagged = [i["item"] for i in data["items"] if i["item"].startswith("secret-present:") and not i["ok"]]
    assert flagged == [f"secret-present:{name}"], "only the planted secret may be flagged"
    assert "SENTINEL-VALUE-5555" not in res.both


@pytest.mark.req("E-2")
def test_e2_name_match_is_case_insensitive(tmp_path, stub):
    res, data, _ = run_role_env(tmp_path, stub, {"my_Secret_thing": "SENTINEL-VALUE-6666"})
    assert_rc(res, 1)
    flagged = [i["item"].lower() for i in data["items"] if i["item"].startswith("secret-present:") and not i["ok"]]
    assert flagged == ["secret-present:my_secret_thing"]


@pytest.mark.req("E-2")
def test_e2_all_secrets_are_listed_not_just_the_first(tmp_path, stub):
    names = ["A_TOKEN", "B_SECRET", "C_PASSWORD"]
    res, data, _ = run_role_env(tmp_path, stub, {n: "SENTINEL-VALUE-7777" for n in names})
    assert_rc(res, 1)
    for n in names:
        assert_item(res, data, f"secret-present:{n}", False)


# ----------------------------------------------------------------------------- E-3


@pytest.mark.req("E-3")
@pytest.mark.parametrize("role", API_ROLES)
def test_e3_correct_permissions_are_ok_and_probes_are_the_documented_ones(tmp_path, stub, role):
    configure_stub(stub, role)
    res, data, _ = run_env(tmp_path, role, api_env(stub.url, role))
    assert_rc(res, 0)
    assert data["role"] == role and data["ok"] is True
    perms = ROLE_PERMS[role]["allowed"] + ROLE_PERMS[role]["denied"]
    for perm in perms:
        assert perm_item(data, role, perm)["ok"] is True, f"{perm} should be fine for role {role}"
        assert_item(res, data, perm_name(role, perm), True)  # printed as: OK permission:<name>-<read|write>:<state>
    seen = {(r.method, r.path) for r in stub.requests}
    for perm in perms:
        method, template = ROUTES[perm]
        assert (method, template.format(repo=REPO)) in seen, f"probe {method} {template} was not sent"
    for r in stub.requests:
        assert (r.method, r.path) in {(m, t.format(repo=REPO)) for m, t in ROUTES.values()}, \
            f"unexpected call {r.method} {r.path}: a probe must change nothing"
        assert PROBE_V in r.header("authorization"), "the probe must carry GATE_PROBE_TOKEN"
        if r.method == "POST":
            if r.path.endswith("/git/refs"):
                body = r.json()
                assert set(body) == {"ref", "sha"} and body["ref"].startswith("refs/heads/gate-probe-") \
                    and body["sha"] == "0" * 40, \
                    "the contents write probe sends a well-formed request that can never succeed"
            else:
                assert r.json() == {}, "the other write probes send the invalid body {}"
        if r.path.endswith("/actions/runs"):
            assert r.q("per_page") == "1"


@pytest.mark.req("E-3")
def test_e3_contents_write_probe_is_well_formed_and_doomed_not_empty(tmp_path, stub):
    """The contents write probe must not send the empty body {}: a real API answers 422 to an
    empty POST /git/refs before checking the permission, so a read-only token would read as
    'allowed' (the false positive of run 42361091565). It sends an unused branch at an all-zero,
    non-existent object instead, so a denied token answers 403. Fails on the old probe."""
    configure_stub(stub, "run")  # for role run, contents write is denied; the stub answers 403
    res, data, _ = run_env(tmp_path, "run", api_env(stub.url, "run"))
    assert_rc(res, 0)
    assert perm_item(data, "run", ("contents", "write"))["ok"] is True  # 403 read as denied
    posts = [r for r in stub.requests if r.method == "POST" and r.path.endswith("/git/refs")]
    assert len(posts) == 1, "exactly one contents write probe is sent"
    body = posts[0].json()
    assert body != {}, "the contents write probe must not send the empty body {}"
    assert set(body) == {"ref", "sha"}
    assert body["ref"].startswith("refs/heads/gate-probe-") and len(body["ref"]) > len("refs/heads/gate-probe-")
    assert body["sha"] == "0" * 40


def _flip(role, perm):
    if perm in ROLE_PERMS[role]["denied"]:
        return 422  # the write would be allowed
    return 403  # the permission is missing


_FLIPS = [(role, perm) for role in API_ROLES for perm in ROLE_PERMS[role]["allowed"] + ROLE_PERMS[role]["denied"]]


@pytest.mark.req("E-3")
@pytest.mark.parametrize("role,perm", _FLIPS, ids=[f"{r}-{p[0]}-{p[1]}" for r, p in _FLIPS])
def test_e3_wrong_permission_breaks_exactly_that_item(tmp_path, stub, role, perm):
    configure_stub(stub, role, {perm: _flip(role, perm)})
    res, data, _ = run_env(tmp_path, role, api_env(stub.url, role))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert data["ok"] is False
    assert perm_item(data, role, perm)["ok"] is False
    assert_item(res, data, perm_name(role, perm), False)
    broken = [i for i in data["items"] if not i["ok"]]
    assert len(broken) == 1, f"only {perm} should be broken, got {[b['item'] for b in broken]}"
    assert any(line.startswith("BROKEN permission:") for line in res.both.splitlines())


@pytest.mark.req("E-3")
@pytest.mark.parametrize("status", [200, 401, 404, 500])
def test_e3_write_expected_denied_other_statuses_are_broken(tmp_path, stub, status):
    configure_stub(stub, "run", {("contents", "write"): status})
    res, data, _ = run_env(tmp_path, "run", api_env(stub.url, "run"))
    assert_rc(res, 1)
    assert perm_item(data, "run", ("contents", "write"))["ok"] is False


@pytest.mark.req("E-3")
@pytest.mark.parametrize("status", [200, 401, 404, 500])
def test_e3_write_expected_allowed_other_statuses_are_broken(tmp_path, stub, status):
    configure_stub(stub, "archive", {("contents", "write"): status})
    res, data, _ = run_env(tmp_path, "archive", api_env(stub.url, "archive"))
    assert_rc(res, 1)
    assert perm_item(data, "archive", ("contents", "write"))["ok"] is False


@pytest.mark.req("E-3")
@pytest.mark.parametrize("status", [201, 204, 401, 404, 500])
def test_e3_read_probe_expects_exactly_200(tmp_path, stub, status):
    configure_stub(stub, "run", {("contents", "read"): status})
    res, data, _ = run_env(tmp_path, "run", api_env(stub.url, "run"))
    assert_rc(res, 1)
    assert perm_item(data, "run", ("contents", "read"))["ok"] is False


@pytest.mark.req("E-3")
@pytest.mark.parametrize("role", API_ROLES)
def test_e3_no_token_is_broken_never_a_pass(tmp_path, stub, role):
    configure_stub(stub, role)
    env = api_env(stub.url, role)
    env["GATE_PROBE_TOKEN"] = None
    res, data, _ = run_env(tmp_path, role, env)
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert data["ok"] is False
    for perm in ROLE_PERMS[role]["allowed"] + ROLE_PERMS[role]["denied"]:
        assert perm_item(data, role, perm)["ok"] is False


@pytest.mark.req("E-3")
@pytest.mark.parametrize("role", API_ROLES)
def test_e3_network_error_is_broken_never_a_pass(tmp_path, role):
    res, data, _ = run_env(tmp_path, role, api_env(closed_port_url(), role))
    assert_rc(res, 1)
    assert_no_traceback(res)
    assert data["ok"] is False
    for perm in ROLE_PERMS[role]["allowed"] + ROLE_PERMS[role]["denied"]:
        assert perm_item(data, role, perm)["ok"] is False


# ----------------------------------------------------------------------------- E-4


def env_config(tmp_path, **environment):
    return make_config(tmp_path / "quality.toml", environment=environment)


@pytest.mark.req("E-4")
@pytest.mark.parametrize("role", ["executor", "spec-tests"])
def test_e4_matching_environment_is_ok(tmp_path, role):
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    cfg = env_config(tmp_path, python=py, image_os="ubuntu24")
    res, data, _ = run_env(tmp_path, role, executor_env(ImageOS="ubuntu24"), config=cfg)
    assert_rc(res, 0)
    assert_item(res, data, "environment:python", True)
    assert_item(res, data, "environment:image_os", True)


@pytest.mark.req("E-4")
def test_e4_python_mismatch_names_expected_and_found(tmp_path):
    found = f"{sys.version_info.major}.{sys.version_info.minor}"
    cfg = env_config(tmp_path, python="3.12", image_os="ubuntu24")
    res, data, _ = run_env(tmp_path, "executor", executor_env(ImageOS="ubuntu24"), config=cfg)
    assert_rc(res, 1)
    assert_item(res, data, "environment:python", False)
    reason = items_by_name(data)["environment:python"]["reason"]
    assert "3.12" in reason and found in reason, f"both the expected and the found value must be named: {reason!r}"
    assert_item(res, data, "environment:image_os", True)


@pytest.mark.req("E-4")
def test_e4_image_os_mismatch_names_expected_and_found(tmp_path):
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    cfg = env_config(tmp_path, python=py, image_os="ubuntu24")
    res, data, _ = run_env(tmp_path, "executor", executor_env(ImageOS="ubuntu22"), config=cfg)
    assert_rc(res, 1)
    assert_item(res, data, "environment:image_os", False)
    reason = items_by_name(data)["environment:image_os"]["reason"]
    assert "ubuntu24" in reason and "ubuntu22" in reason, reason
    assert_item(res, data, "environment:python", True)


@pytest.mark.req("E-4")
def test_e4_image_os_variable_missing_is_broken(tmp_path):
    py = f"{sys.version_info.major}.{sys.version_info.minor}"
    cfg = env_config(tmp_path, python=py, image_os="ubuntu24")
    res, data, _ = run_env(tmp_path, "executor", executor_env(ImageOS=None), config=cfg)
    assert_rc(res, 1)
    assert_item(res, data, "environment:image_os", False)


@pytest.mark.req("E-4")
def test_e4_without_environment_section_no_environment_items(tmp_path):
    cfg = make_config(tmp_path / "quality.toml")
    res, data, _ = run_env(tmp_path, "executor", executor_env(), config=cfg)
    assert_rc(res, 0)
    assert not [i for i in data["items"] if i["item"].startswith("environment:")]


@pytest.mark.req("E-6", "E-4")
@pytest.mark.parametrize("role", ["executor", "spec-tests", "reproduce"])
def test_e6_without_config_a_quality_toml_in_the_working_folder_is_never_read(tmp_path, role):
    # The working folder can be a judged repository's: its quality.toml is untrusted and must not be read.
    make_config(tmp_path / "quality.toml", environment={"python": "3.12", "image_os": "ubuntu99"})
    env = {"ImageOS": "ubuntu24"} if role == "reproduce" else executor_env(ImageOS="ubuntu24")  # reproduce runs E-2
    res, data, _ = run_env(tmp_path, role, env, cwd=tmp_path)
    assert_rc(res, 0)
    assert not [i for i in data["items"] if i["item"].startswith("environment:")],         "no environment:* item may appear without --config"
    assert "3.12" not in res.both and "ubuntu99" not in res.both, "the file in the working folder was read"


@pytest.mark.req("E-6", "E-4")
def test_e6_control_the_same_file_given_with_config_is_used(tmp_path):
    cfg = make_config(tmp_path / "quality.toml", environment={"python": "3.12", "image_os": "ubuntu99"})
    res, data, _ = run_env(tmp_path, "executor", executor_env(ImageOS="ubuntu24"), config=cfg, cwd=tmp_path)
    assert_rc(res, 1)
    assert_item(res, data, "environment:python", False)
    assert_item(res, data, "environment:image_os", False)


# ----------------------------------------------------------------------------- E-4a (role reproduce)


def py_version():
    return f"{sys.version_info.major}.{sys.version_info.minor}"


@pytest.mark.req("E-4a")
def test_e4a_reproduce_checks_python_but_not_image_os_and_needs_no_api(tmp_path):
    cfg = env_config(tmp_path, python=py_version(), image_os="ubuntu99")
    res, data, _ = run_env(tmp_path, "reproduce", {"ImageOS": "ubuntu24"}, config=cfg)
    assert_rc(res, 0)
    assert data["role"] == "reproduce" and data["ok"] is True
    assert_item(res, data, "environment:python", True)
    names = [i["item"] for i in data["items"]]
    assert "environment:image_os" not in names, "of E-4 the role reproduce runs only environment:python"
    assert not [n for n in names if n.startswith("permission:")], "reproduce probes no permission"


@pytest.mark.req("E-4a", "E-4")
def test_e4a_reproduce_python_mismatch_names_both_values(tmp_path):
    cfg = env_config(tmp_path, python="3.12")
    res, data, _ = run_env(tmp_path, "reproduce", {}, config=cfg)
    assert_rc(res, 1)
    assert_item(res, data, "environment:python", False)
    reason = items_by_name(data)["environment:python"]["reason"]
    assert "3.12" in reason and py_version() in reason


@pytest.mark.req("E-4a", "E-2", "E-5")
def test_e4a_reproduce_runs_the_secret_check_of_e2(tmp_path):
    res, data, out = run_env(tmp_path, "reproduce", {"DEPLOY_TOKEN": "SENTINEL-VALUE-7001", "PUBLIC_KEY": "x",
                                                      "GATE_PROBE_TOKEN": "SENTINEL-VALUE-7002"})
    assert_rc(res, 1)
    assert_item(res, data, "secret-present:DEPLOY_TOKEN", False)
    flagged = [i["item"] for i in data["items"] if i["item"].startswith("secret-present:")]
    assert flagged == ["secret-present:DEPLOY_TOKEN"], "GATE_PROBE_TOKEN stays exempt, PUBLIC_KEY is not a listed word"
    for where, text in all_outputs(res, out).items():
        assert SENTINEL_PREFIX not in text, f"a value leaked into {where}"


@pytest.mark.req("E-4a")
def test_e4a_control_reproduce_with_a_clean_environment_is_ok(tmp_path):
    res, data, _ = run_env(tmp_path, "reproduce", {})
    assert_rc(res, 0)
    assert data["ok"] is True


# ----------------------------------------------------------------------------- E-5 and C-3


def all_outputs(res, out_path):
    return {"stdout": res.out, "stderr": res.err, "--out file": out_path.read_text(encoding="utf-8") if out_path.exists() else ""}


@pytest.mark.req("E-5", "C-3")
@pytest.mark.parametrize("role", ["executor", "spec-tests"])
def test_e5_malformed_secrets_are_never_printed(tmp_path, role):
    env = executor_env(CLAUDE_CODE_OAUTH_TOKEN="", EXECUTOR_APP_PRIVATE_KEY=f"{KEY_V} no header at all",
                       EXECUTOR_APP_ID=f"{SENTINEL_PREFIX}-8888", UNRELATED_NOTE=NOTE_V)
    res, data, out = run_env(tmp_path, role, env)
    assert_rc(res, 1)
    assert_item(res, data, "secret:EXECUTOR_APP_PRIVATE_KEY", False)
    assert_item(res, data, "variable:EXECUTOR_APP_ID", False)
    texts = all_outputs(res, out)
    assert texts["--out file"], "the --out file must be written for a broken environment"
    for where, text in texts.items():
        assert SENTINEL_PREFIX not in text, f"a secret value leaked into {where}"
        assert APP_ID_V not in text


@pytest.mark.req("E-5", "C-3")
@pytest.mark.parametrize("role", ["executor", "spec-tests"])
def test_e5_valid_secrets_are_never_printed_either(tmp_path, role):
    res, data, out = run_env(tmp_path, role, executor_env(UNRELATED_NOTE=NOTE_V))
    assert_rc(res, 0)
    for where, text in all_outputs(res, out).items():
        assert SENTINEL_PREFIX not in text, f"a value leaked into {where}"
        assert APP_ID_V not in text, f"the app id value leaked into {where}"


@pytest.mark.req("E-5", "C-3", "E-2")
def test_e5_run_role_names_secrets_but_not_their_values(tmp_path, stub):
    envx = {n: f"{SENTINEL_PREFIX}-{i}" for i, n in enumerate(
        ["A_TOKEN", "B_SECRET", "C_PASSWORD", "D_PRIVATE_KEY", "E_CREDENTIAL", "F_API_KEY"])}
    res, data, out = run_role_env(tmp_path, stub, envx)
    assert_rc(res, 1)
    for n in envx:
        assert_item(res, data, f"secret-present:{n}", False)
    for where, text in all_outputs(res, out).items():
        assert SENTINEL_PREFIX not in text, f"a secret value leaked into {where}"


@pytest.mark.req("E-5", "C-3")
@pytest.mark.parametrize("role", API_ROLES)
@pytest.mark.parametrize("state", ["good", "denied-everywhere", "no-network"])
def test_e5_api_roles_never_print_the_probe_token_or_other_values(tmp_path, stub, role, state):
    if state == "good":
        configure_stub(stub, role)
        url = stub.url
    elif state == "denied-everywhere":
        for method, template in ROUTES.values():
            stub.route(method, re.escape(template.format(repo=REPO)), (401, {"message": "Bad credentials"}))
        url = stub.url
    else:
        url = closed_port_url()
    res, data, out = run_env(tmp_path, role, api_env(url, role))
    assert_rc(res, 0 if state == "good" else 1)  # the script really ran and judged the permissions
    assert_no_traceback(res)
    assert data["role"] == role
    for where, text in all_outputs(res, out).items():
        assert SENTINEL_PREFIX not in text, f"a value leaked into {where} ({role}, {state})"
        # E-5: no value of any variable; the only exception is E-4 (the Python version and ImageOS)
        assert REPO not in text, f"the value of GITHUB_REPOSITORY appears in {where}"
        assert url not in text, f"the value of GITHUB_API_URL appears in {where}"


# ----------------------------------------------------------------------------- C-2, Q-2


@pytest.mark.req("C-2")
def test_usage_errors_exit_2_and_write_nothing(tmp_path):
    out = tmp_path / "o.json"
    for args in (["--out", out], ["--role", "no-such-role", "--out", out]):
        res = run_gate("env_check", *args, env=base_env(executor_env()), cwd=tmp_path)
        assert_rc(res, 2)
        assert_no_traceback(res)
        assert not out.exists()


@pytest.mark.req("Q-2", "C-2")
@pytest.mark.parametrize("bad", [
    '[checks."gate/tests"]\nclass = "diagnostic"\ncommands = [["x"]]\n',
    '[checks."diag/coverage"]\nclass = "mandatory"\ncommands = [["x"]]\n',
    '[checks."gate/not-a-check"]\nclass = "mandatory"\ncommands = [["x"]]\n',
])
def test_q2_env_check_refuses_a_configuration_that_reclassifies_or_invents_a_check(tmp_path, bad):
    cfg = make_config(tmp_path / "quality.toml", raw_text=bad)
    res, _, out = run_env(tmp_path, "executor", executor_env(), config=cfg)
    assert_refused(res, 2, out)

