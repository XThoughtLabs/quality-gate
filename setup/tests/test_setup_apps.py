"""Offline tests of setup/setup_apps.py: the configuration, the refusal of extra permissions, the name
check that closes the pilot's O-14, the manifest, the installation check and the key files' access.

GitHub is a fake (a gh runner and an API callable); Windows is a fake of the script's one seam, the
`Windows` class, with a small model of file permissions. No network, no key, no Windows call: these run
on Windows and on Linux alike."""

from __future__ import annotations

import copy
import re
import subprocess
import sys
from pathlib import Path

import pytest

SETUP_DIR = Path(__file__).resolve().parents[1]
if str(SETUP_DIR) not in sys.path:
    sys.path.insert(0, str(SETUP_DIR))

import setup_apps as S  # noqa: E402

OPERATOR = "S-1-5-21-1111111111-2222222222-3333333333-1001"
EXECUTOR = "S-1-5-21-1111111111-2222222222-3333333333-1002"
OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1003"
MODIFY = 0x1301BF
READ = 0x120089
# The functions under test treat the key as opaque bytes, so the stand-in has no key's shape at all.
PEM = b"STAND-IN-KEY-BYTES 0123456789 not a key\n" * 3

GOOD = """
[setup]
owner = "ExampleOrg"
repository = "workflow-dispatcher-stage-a"

[executor]
app_name = "xtl-stage-a-executor"
windows_user = "stage-a-runner"
key_folder = 'D:\\stage-a-keys'

[reviewer]
app_name = "xtl-stage-a-reviewer"
key_file = 'D:\\operator-keys\\reviewer.pem'

[controller]
app_name = "xtl-stage-a-controller"
key_file = 'D:\\operator-keys\\controller.pem'
"""


def write_config(tmp_path, text):
    path = tmp_path / "setup.toml"
    path.write_text(text, encoding="utf-8")
    return path


def good(tmp_path, text=GOOD):
    return S.load_config(write_config(tmp_path, text))


def stop_message(call) -> str:
    with pytest.raises(S.Stop) as raised:
        call()
    assert type(raised.value) is S.Stop
    return str(raised.value)


# ---------------------------------------------------------------- the configuration
def test_config_the_example_loads_once_its_placeholders_are_filled(tmp_path):
    text = (SETUP_DIR / "setup.example.toml").read_text(encoding="utf-8")
    assert "<" in text, "the example holds no placeholders"
    values = {
        "owner": "ExampleOrg", "repository": "demo-repo", "executor app name": "demo-executor",
        "the separate standard Windows user": "demo-exec", "reviewer app name": "demo-reviewer",
        "controller app name": "demo-controller"}
    filled = []
    for line in text.splitlines():
        if line.startswith("owner"):
            line = 'owner = "ExampleOrg"'
        elif line.startswith("repository"):
            line = 'repository = "demo-repo"'
        elif line.startswith("app_name"):
            role = "executor" if "executor" in line else "reviewer" if "reviewer" in line else "controller"
            line = f'app_name = "{values[role + " app name"]}"'
        elif line.startswith("windows_user"):
            line = 'windows_user = "demo-exec"'
        elif line.startswith("key_folder"):
            line = "key_folder = 'D:\\demo-keys'"
        elif line.startswith("key_file"):
            line = "key_file = 'D:\\operator\\" + ("reviewer" if "reviewer" in line else "controller") + ".pem'"
        filled.append(line)
    config = good(tmp_path, "\n".join(filled))
    assert set(config["roles"]) == {"executor", "reviewer", "controller"}
    assert config["roles"]["executor"]["key_file"] == Path("D:\\demo-keys") / "demo-executor.pem"
    assert config["homepage"] == "https://github.com/ExampleOrg/demo-repo"


def test_config_the_example_names_no_real_value():
    text = (SETUP_DIR / "setup.example.toml").read_text(encoding="utf-8")
    for value in ("mp-claude", "gate-practice-app", "xtl-gate-executor", "xtl-gate-reviewer",
                  "C:\\xtl-gate-executor"):
        assert value not in text, value


def test_config_good_values(tmp_path):
    config = good(tmp_path)
    assert config["full_name"] == "ExampleOrg/workflow-dispatcher-stage-a"
    executor = config["roles"]["executor"]
    assert executor["key_file"] == Path("D:\\stage-a-keys") / "xtl-stage-a-executor.pem"
    assert executor["app_file"] == Path("D:\\stage-a-keys") / "xtl-stage-a-executor.app.json"
    assert config["roles"]["reviewer"]["key_file"] == Path("D:\\operator-keys\\reviewer.pem")


def test_config_a_role_may_be_left_out(tmp_path):
    text = GOOD.split("[controller]")[0]
    assert set(good(tmp_path, text)["roles"]) == {"executor", "reviewer"}


REFUSALS = {
    "unknown-table": (GOOD + "\n[admin]\napp_name = 'x'\n", "unknown tables"),
    "unknown-setup-key": (GOOD.replace('owner = "ExampleOrg"', 'owner = "ExampleOrg"\ntoken = "x"'), "unknown keys"),
    "permissions-table": (GOOD.replace("[reviewer]\n", "[reviewer]\npermissions = {administration = 'write'}\n"),
                          "may not have: permissions"),
    "extra-permission-key": (GOOD.replace("[executor]\n", "[executor]\nchecks = 'write'\n"), "may not have: checks"),
    "issues-for-the-reviewer": (GOOD.replace("[reviewer]\n", "[reviewer]\nissues = true\n"), "may not have: issues"),
    "issues-not-boolean": (GOOD.replace("[controller]\n", "[controller]\nissues = 'yes'\n"), "true or false"),
    "bad-owner": (GOOD.replace("ExampleOrg", "Example Org"), "owner"),
    "bad-repository": (GOOD.replace("workflow-dispatcher-stage-a", "a/b"), "repository"),
    "upper-case-app-name": (GOOD.replace("xtl-stage-a-reviewer", "XTL-Reviewer"), "app_name"),
    "too-long-app-name": (GOOD.replace("xtl-stage-a-reviewer", "r" * 35), "app_name"),
    "one-name-twice": (GOOD.replace("xtl-stage-a-reviewer", "xtl-stage-a-controller"), "used by another role"),
    "one-key-twice": (GOOD.replace("controller.pem", "reviewer.pem"), "used by another role"),
    # GOOD's TOML text holds single backslashes: 'D:\stage-a-keys'.
    "key-folder-in-users": (GOOD.replace("D:\\stage-a-keys", "C:\\Users\\Public\\keys"), "outside C:\\Users"),
    "key-folder-in-onedrive": (GOOD.replace("D:\\stage-a-keys", "D:\\OneDrive\\keys"), "OneDrive"),
    "key-file-in-a-repository": (GOOD.replace("D:\\operator-keys\\reviewer.pem", "D:\\repo\\.git\\r.pem"),
                                 "outside every repository"),
    "key-file-relative": (GOOD.replace("D:\\operator-keys\\reviewer.pem", "keys\\reviewer.pem"), "full local"),
    "key-file-unc": (GOOD.replace("D:\\operator-keys\\reviewer.pem", "\\\\server\\share\\r.pem"), "full local"),
    "key-file-not-pem": (GOOD.replace("reviewer.pem", "reviewer.txt"), ".pem"),
    "key-file-climbs": (GOOD.replace("D:\\operator-keys\\reviewer.pem", "D:\\a\\..\\r.pem"), "outside"),
    "bad-windows-user": (GOOD.replace("stage-a-runner", "a/b"), "windows_user"),
    "no-role": ('[setup]\nowner = "ExampleOrg"\nrepository = "r"\n', "names no role"),
    "homepage-not-https": (GOOD.replace('repository = "workflow-dispatcher-stage-a"',
                                        'repository = "workflow-dispatcher-stage-a"\nhomepage = "http://x"'), "https"),
}


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_config_refusals(tmp_path, name):
    text, expected = REFUSALS[name]
    message = stop_message(lambda: good(tmp_path, text))
    assert expected in message, message


def test_config_a_missing_file_is_refused(tmp_path):
    assert "Cannot read" in stop_message(lambda: S.load_config(tmp_path / "absent.toml"))


# ---------------------------------------------------------------- permissions
EXPECTED = {
    ("executor", False): {"contents": "write", "pull_requests": "write", "metadata": "read"},
    ("executor", True): {"contents": "write", "pull_requests": "write", "issues": "write", "metadata": "read"},
    ("reviewer", False): {"contents": "read", "pull_requests": "write", "statuses": "write", "metadata": "read"},
    ("controller", False): {"contents": "write", "checks": "write", "pull_requests": "read", "statuses": "read",
                            "metadata": "read"},
    ("controller", True): {"contents": "write", "checks": "write", "pull_requests": "read", "statuses": "read",
                           "issues": "read", "metadata": "read"},
}


@pytest.mark.parametrize("role, issues", sorted(EXPECTED))
def test_permissions_each_roles_fixed_set(role, issues):
    assert S.role_permissions(role, issues) == EXPECTED[(role, issues)]


def test_permissions_the_ceilings_are_the_letters_table():
    assert S.most_for_role("executor") == EXPECTED[("executor", True)]
    assert S.most_for_role("reviewer") == EXPECTED[("reviewer", False)]
    assert S.most_for_role("controller") == EXPECTED[("controller", True)]


def test_permissions_the_issues_flag_reaches_the_roles(tmp_path):
    text = GOOD.replace("[executor]\n", "[executor]\nissues = true\n").replace("[controller]\n",
                                                                               "[controller]\nissues = true\n")
    config = good(tmp_path, text)
    assert config["roles"]["executor"]["permissions"]["issues"] == "write"
    assert config["roles"]["controller"]["permissions"]["issues"] == "read"
    assert "issues" not in good(tmp_path)["roles"]["executor"]["permissions"]


def test_permissions_the_reviewer_cannot_have_issues():
    assert "cannot have issues" in stop_message(lambda: S.role_permissions("reviewer", True))


@pytest.mark.parametrize("role, extra", [
    ("executor", {"checks": "write"}),
    ("executor", {"statuses": "write"}),
    ("executor", {"administration": "write"}),
    ("executor", {"workflows": "write"}),
    ("reviewer", {"contents": "write"}),
    ("reviewer", {"checks": "write"}),
    ("reviewer", {"issues": "read"}),
    ("controller", {"statuses": "write"}),
    ("controller", {"pull_requests": "write"}),
    ("controller", {"issues": "write"}),
    ("controller", {"administration": "read"}),
    ("executor", {"contents": "admin"}),
    ("controller", {"metadata": "write"}),
])
def test_permissions_anything_outside_the_role_is_refused(role, extra):
    permissions = {**S.most_for_role(role), **extra}
    message = stop_message(lambda: S.check_within_role(role, permissions))
    assert list(extra)[0] in message


@pytest.mark.parametrize("role", sorted(S.ROLES))
def test_permissions_the_ceiling_itself_and_less_pass(role):
    S.check_within_role(role, S.most_for_role(role))
    S.check_within_role(role, {"metadata": "read"})
    S.check_within_role(role, {name: "read" for name in S.most_for_role(role)})


def test_permissions_not_a_mapping_is_refused():
    stop_message(lambda: S.check_within_role("executor", ["contents"]))


# ---------------------------------------------------------------- the manifest
@pytest.mark.parametrize("role", ["executor", "reviewer", "controller"])
def test_manifest_content(tmp_path, role):
    config = good(tmp_path)
    manifest = S.build_manifest(config, role)
    assert set(manifest) == {"name", "url", "description", "public", "hook_attributes", "default_events",
                             "default_permissions", "request_oauth_on_install", "setup_on_update"}
    assert manifest["name"] == config["roles"][role]["app_name"]
    assert manifest["public"] is False
    assert manifest["hook_attributes"]["active"] is False
    assert manifest["default_events"] == []
    assert manifest["default_permissions"] == EXPECTED[(role, False)]
    assert manifest["request_oauth_on_install"] is False and manifest["setup_on_update"] is False
    assert manifest["url"] == "https://github.com/ExampleOrg/workflow-dispatcher-stage-a"
    assert config["full_name"] in manifest["description"]


def test_manifest_refuses_a_permission_slipped_into_the_role(tmp_path):
    config = good(tmp_path)
    config["roles"]["reviewer"]["permissions"]["administration"] = "write"
    assert "administration" in stop_message(lambda: S.build_manifest(config, "reviewer"))


# ---------------------------------------------------------------- the name check (O-14)
def answer(code, stderr=b"", stdout=b""):
    return subprocess.CompletedProcess(["gh"], code, stdout, stderr)


class Asked:
    def __init__(self, reply):
        self.reply, self.questions = reply, []

    def __call__(self, question):
        self.questions.append(question)
        return self.reply


def test_name_an_existing_app_stops_without_asking():
    asked = Asked("xtl-stage-a-reviewer")
    message = stop_message(lambda: S.check_name_is_new("xtl-stage-a-reviewer", lambda a: answer(0, stdout=b"x"), asked))
    assert "already exists" in message and asked.questions == []


@pytest.mark.parametrize("stderr", [b"gh: Not Found (HTTP 404)", b"HTTP 404: Not Found (https://api.github.com/apps/x)"])
def test_name_not_found_confirmed_by_the_operator_passes(stderr):
    asked = Asked("xtl-stage-a-reviewer\n")
    S.check_name_is_new("xtl-stage-a-reviewer", lambda a: answer(1, stderr), asked)
    assert len(asked.questions) == 1 and "xtl-stage-a-reviewer" in asked.questions[0]


@pytest.mark.parametrize("reply", ["", "y", "yes", "xtl-stage-a-reviewe", "XTL-STAGE-A-REVIEWER"])
def test_name_not_found_without_the_operators_confirmation_stops(reply):
    """GitHub's 404 for a private app is the same answer: without the operator's word, nothing is created."""
    message = stop_message(lambda: S.check_name_is_new("xtl-stage-a-reviewer",
                                                       lambda a: answer(1, b"gh: Not Found (HTTP 404)"), Asked(reply)))
    assert "not confirmed" in message


@pytest.mark.parametrize("code, stderr", [(1, b"gh: Server Error (HTTP 500)"), (1, b"gh: Forbidden (HTTP 403)"),
                                          (4, b"error connecting to api.github.com"), (1, b"")])
def test_name_any_other_answer_stops_without_asking(code, stderr):
    asked = Asked("xtl-stage-a-reviewer")
    message = stop_message(lambda: S.check_name_is_new("xtl-stage-a-reviewer", lambda a: answer(code, stderr), asked))
    assert "Could not check" in message and asked.questions == []


def test_name_the_check_asks_github_for_that_name():
    seen = []
    S.check_name_is_new("xtl-stage-a-reviewer", lambda a: seen.append(a) or answer(1, b"(HTTP 404)"),
                        Asked("xtl-stage-a-reviewer"))
    assert seen == [["api", "apps/xtl-stage-a-reviewer", "--jq", ".slug"]]


def test_name_github_secrets_of_the_executor_stop():
    def fake(args):
        return answer(0, stdout=b"OTHER\nEXECUTOR_APP_PRIVATE_KEY\n" if args[0] == "secret" else b"")
    assert "EXECUTOR_APP_PRIVATE_KEY" in stop_message(lambda: S.github_holds_no_executor_secret("o/r", fake))


# ---------------------------------------------------------------- the installation check
class FakeApi:
    """GitHub's answers to the app, with each answer replaceable."""

    def __init__(self, config, role, app_id=4242, slug=None, installation_id=777):
        self.permissions = copy.deepcopy(config["roles"][role]["permissions"])
        self.slug = slug or config["roles"][role]["app_name"]
        self.app = {"id": app_id, "slug": self.slug, "permissions": dict(self.permissions), "events": []}
        self.installations = [{"id": installation_id, "account": {"login": config["owner"]},
                               "repository_selection": "selected", "permissions": dict(self.permissions)}]
        self.repositories = {"total_count": 1, "repositories": [{"full_name": config["full_name"]}]}
        self.calls = []
        self.tokens = []
        self.revoked = []

    def __call__(self, method, route, bearer, what, expect=200):
        self.calls.append((method, route.split("?")[0]))
        if (method, route) == ("GET", "/app"):
            return self.app
        if (method, route) == ("GET", "/app/installations"):
            return self.installations
        if method == "POST" and route.endswith("/access_tokens"):
            token = f"ghs_{'T' * 36}{len(self.tokens)}"
            self.tokens.append(token)
            return {"token": token}
        if (method, route) == ("GET", "/installation/repositories?per_page=100"):
            assert bearer in self.tokens
            return self.repositories
        if (method, route) == ("DELETE", "/installation/token"):
            self.revoked.append(bearer)
            return None
        raise AssertionError(f"unexpected request {method} {route}")


@pytest.mark.parametrize("role", ["executor", "reviewer", "controller"])
def test_installation_exactly_right_passes_and_revokes_its_token(tmp_path, role):
    config = good(tmp_path)
    fake = FakeApi(config, role)
    assert S.check_installation(config, role, 4242, fake.slug, "jwt", "777", api_call=fake) == 777
    assert fake.revoked == fake.tokens and len(fake.tokens) == 1


def _break(fake, what):
    if what == "two-installations":
        fake.installations.append(copy.deepcopy(fake.installations[0]))
    elif what == "no-installation":
        fake.installations.clear()
    elif what == "other-account":
        fake.installations[0]["account"]["login"] = "Someone"
    elif what == "all-repositories":
        fake.installations[0]["repository_selection"] = "all"
    elif what == "installation-extra-permission":
        fake.installations[0]["permissions"]["administration"] = "write"
    elif what == "installation-missing-permission":
        fake.installations[0]["permissions"].pop("contents")
    elif what == "app-extra-permission":
        fake.app["permissions"]["workflows"] = "write"
    elif what == "app-events":
        fake.app["events"] = ["push"]
    elif what == "app-other-id":
        fake.app["id"] = 1
    elif what == "app-other-slug":
        fake.app["slug"] = "someone-else"
    elif what == "two-repositories":
        fake.repositories = {"total_count": 2, "repositories": [{"full_name": "ExampleOrg/workflow-dispatcher-stage-a"},
                                                                {"full_name": "ExampleOrg/other"}]}
    elif what == "other-repository":
        fake.repositories = {"total_count": 1, "repositories": [{"full_name": "ExampleOrg/other"}]}
    elif what == "installation-id-not-int":
        fake.installations[0]["id"] = "777"


BREAKS = ["two-installations", "no-installation", "other-account", "all-repositories",
          "installation-extra-permission", "installation-missing-permission", "app-extra-permission", "app-events",
          "app-other-id", "app-other-slug", "two-repositories", "other-repository", "installation-id-not-int"]


@pytest.mark.parametrize("what", BREAKS)
def test_installation_anything_else_stops(tmp_path, what):
    config = good(tmp_path)
    fake = FakeApi(config, "reviewer")
    _break(fake, what)
    stop_message(lambda: S.check_installation(config, "reviewer", 4242, fake.slug, "jwt", "", api_call=fake))
    assert fake.revoked == fake.tokens, "a check token was left unrevoked"


def test_installation_the_browsers_hint_must_match(tmp_path):
    config = good(tmp_path)
    fake = FakeApi(config, "controller")
    assert "reported to the browser" in stop_message(
        lambda: S.check_installation(config, "controller", 4242, fake.slug, "jwt", "778", api_call=fake))


def test_installation_messages_never_hold_the_token(tmp_path, capsys):
    config = good(tmp_path)
    fake = FakeApi(config, "reviewer")
    _break(fake, "two-repositories")
    message = stop_message(lambda: S.check_installation(config, "reviewer", 4242, fake.slug, "jwt", "", api_call=fake))
    out = capsys.readouterr()
    for token in fake.tokens:
        assert token not in message + out.out + out.err


# ---------------------------------------------------------------- the key files' access (the Windows seam faked)
RIGHTS = {"F": S.FULL_CONTROL, "M": MODIFY, "R": READ}


class FakeWindows:
    """A model of the few Windows calls: the current user, users, icacls and ACLs, owner, readability."""

    def __init__(self, me=OPERATOR):
        self.me = me
        self.acl: dict[str, dict] = {}
        self.owner: dict[str, str] = {}
        self.users = {"stage-a-runner": (EXECUTOR, True)}
        self.admins = {OPERATOR}
        self.ignore = set()  # icacls arguments that silently do nothing
        self.after_icacls = None  # a hook that changes the ACL after a call
        self.readable_anyway = False  # readable by us through something the rules do not show
        self.first_seen: dict[str, tuple] = {}  # each file's permissions when the model first saw it (R7)

    def _remember(self, path):
        state = self._state(path)
        self.first_seen.setdefault(str(path), (state["protected"], dict(state["rules"])))

    def create_with_acl(self, path, sddl):
        """Create the file new, with the access the SDDL gives (amendment A2, R7). The same faults as icacls can be
        played: `ignore` holding "/inheritance:r" keeps the folder's inherited rules, and `after_icacls` changes the
        rules afterwards."""
        import os as _os
        flags = _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | getattr(_os, "O_BINARY", 0)
        try:
            _os.close(_os.open(path, flags, 0o600))
        except OSError:
            raise S.Stop(f"Could not create {path}. Nothing is overwritten.") from None
        rights = {"FA": S.FULL_CONTROL, "FR": READ}
        rules = {sid: rights[right] for right, sid in re.findall(r"\(A;;(FA|FR);;;(S-[0-9-]+)\)", sddl)}
        state = {"protected": sddl.startswith("D:P"), "rules": rules}
        if "/inheritance:r" in self.ignore:
            state = {"protected": False, "rules": {"S-1-5-32-544": S.FULL_CONTROL, self.me: S.FULL_CONTROL, **rules}}
        self.acl[str(path)] = state
        self._remember(path)
        if self.after_icacls:
            self.after_icacls(state)

    def current_sid(self):
        return self.me

    def resolve_local_user(self, name):
        return self.users.get(name, ("", False))

    def local_admin_sids(self):
        return set(self.admins)

    def _state(self, path):
        return self.acl.setdefault(str(path), {"protected": False,
                                               "rules": {"S-1-5-32-544": S.FULL_CONTROL, self.me: S.FULL_CONTROL}})

    def icacls(self, path, *args):
        self._remember(path)
        state = self._state(path)
        items = list(args)
        i = 0
        while i < len(items):
            item = items[i]
            if item in self.ignore:
                i += 1
                continue
            if item == "/inheritance:r":
                state["protected"] = True
                state["rules"] = {}
            elif item in ("/grant:r", "/grant"):
                i += 1
                while i < len(items) and not items[i].startswith("/"):
                    sid, right = re.fullmatch(r"\*(S-[0-9-]+):\((\w)\)", items[i]).groups()
                    state["rules"][sid] = RIGHTS[right]
                    i += 1
                continue
            elif item == "/remove:g":
                i += 1
                state["rules"].pop(items[i].lstrip("*"), None)
            i += 1
        if self.after_icacls:
            self.after_icacls(state)
        return True

    def acl_of(self, path):
        state = self._state(path)
        return state["protected"], [(sid, rights, "Allow", "False") for sid, rights in state["rules"].items()]

    def owner_of(self, path):
        return self.owner.get(str(path), self.me)

    def can_read(self, path):
        return self.readable_anyway or bool(self._state(path)["rules"].get(self.me, 0) & S.READ_DATA)


def test_keys_the_operators_key_is_readable_by_the_operator_alone(tmp_path, capsys):
    win = FakeWindows()
    path = tmp_path / "reviewer.pem"
    S.write_operator_key(win, path, PEM, EXECUTOR)
    assert path.read_bytes() == PEM
    assert win.acl_of(path) == (True, [(OPERATOR, S.FULL_CONTROL, "Allow", "False")])
    out = capsys.readouterr()
    assert "STAND-IN-KEY-BYTES" not in out.out + out.err


def test_keys_an_operators_key_the_executor_could_read_is_refused_and_removed(tmp_path):
    win = FakeWindows()
    win.after_icacls = lambda state: state["rules"].__setitem__(EXECUTOR, READ)
    path = tmp_path / "controller.pem"
    assert "executor's user" in stop_message(lambda: S.write_operator_key(win, path, PEM, EXECUTOR))
    assert not path.exists()


@pytest.mark.parametrize("variant", ["inherited-rules-kept", "a-second-user", "less-than-full-control"])
def test_keys_an_operators_key_with_other_rules_is_refused_and_removed(tmp_path, variant):
    win = FakeWindows()
    if variant == "inherited-rules-kept":
        win.ignore.add("/inheritance:r")
    elif variant == "a-second-user":
        win.after_icacls = lambda state: state["rules"].__setitem__(OTHER, READ)
    else:
        win.after_icacls = lambda state: state["rules"].__setitem__(OPERATOR, MODIFY)
    path = tmp_path / "reviewer.pem"
    stop_message(lambda: S.write_operator_key(win, path, PEM, EXECUTOR))
    assert not path.exists()


def test_keys_an_existing_file_is_never_overwritten(tmp_path):
    path = tmp_path / "reviewer.pem"
    path.write_bytes(b"older")
    assert "Nothing is overwritten" in stop_message(lambda: S.write_operator_key(FakeWindows(), path, PEM, EXECUTOR))
    assert path.read_bytes() == b"older"


def test_keys_the_executors_key_is_readable_by_the_executor_alone(tmp_path):
    win = FakeWindows()
    path = tmp_path / "executor.pem"
    S.write_for_executor(win, path, PEM, EXECUTOR)
    assert path.read_bytes() == PEM
    assert win.acl_of(path) == (True, [(EXECUTOR, READ, "Allow", "False")])
    assert win.can_read(path) is False


@pytest.mark.parametrize("variant", ["operator-keeps-access", "executor-may-write", "inheritance-kept",
                                     "other-owner", "a-second-reader"])
def test_keys_an_executors_key_with_other_access_is_refused_and_removed(tmp_path, variant):
    win = FakeWindows()
    if variant == "operator-keeps-access":
        win.ignore.add("/remove:g")
    elif variant == "executor-may-write":
        win.after_icacls = lambda state: state["rules"].__setitem__(EXECUTOR, MODIFY) if EXECUTOR in state["rules"] else None
    elif variant == "inheritance-kept":
        win.ignore.add("/inheritance:r")
    elif variant == "other-owner":
        win.owner[str(tmp_path / "executor.pem")] = OTHER
    else:
        win.after_icacls = lambda state: state["rules"].__setitem__(OTHER, READ)
    path = tmp_path / "executor.pem"
    stop_message(lambda: S.write_for_executor(win, path, PEM, EXECUTOR))
    assert not path.exists()


def test_keys_the_check_of_an_executors_key_alone(tmp_path):
    """check_executor_only on its own: exactly one rule, the executor's, reading, and we cannot read."""
    win = FakeWindows()
    path = tmp_path / "k.pem"
    path.write_bytes(PEM)
    win.acl[str(path)] = {"protected": True, "rules": {EXECUTOR: READ}}
    S.check_executor_only(win, path, EXECUTOR)
    win.acl[str(path)] = {"protected": True, "rules": {EXECUTOR: READ | 0x2}}
    stop_message(lambda: S.check_executor_only(win, path, EXECUTOR))
    win.acl[str(path)] = {"protected": True, "rules": {OTHER: READ}}
    stop_message(lambda: S.check_executor_only(win, path, EXECUTOR))
    win.acl[str(path)] = {"protected": True, "rules": {EXECUTOR: 0x80}}  # no ReadData
    stop_message(lambda: S.check_executor_only(win, path, EXECUTOR))
    win.acl[str(path)] = {"protected": True, "rules": {EXECUTOR: READ}}
    win.readable_anyway = True  # the rules look right, yet our own user can open it
    assert "can still read" in stop_message(lambda: S.check_executor_only(win, path, EXECUTOR))


@pytest.mark.parametrize("variant, expected", [
    ("the-operator", "your own user"), ("disabled", "disabled"), ("an-administrator", "Administrators"),
    ("not-local", "not a local account")])
def test_keys_the_executors_user_must_be_a_separate_standard_local_user(variant, expected):
    win = FakeWindows()
    if variant == "the-operator":
        win.users["stage-a-runner"] = (OPERATOR, True)
    elif variant == "disabled":
        win.users["stage-a-runner"] = (EXECUTOR, False)
    elif variant == "an-administrator":
        win.admins.add(EXECUTOR)
    else:
        win.users["stage-a-runner"] = ("S-1-5-32-545", True)
    assert expected in stop_message(lambda: S.check_executor_user(win, "stage-a-runner", OPERATOR))


def test_keys_a_separate_standard_user_passes():
    assert S.check_executor_user(FakeWindows(), "stage-a-runner", OPERATOR) == EXECUTOR


def test_keys_places_must_be_free(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "inside_a_repository", lambda folder: False)
    folder = tmp_path / "keys"
    folder.mkdir()
    config = good(tmp_path)
    entry = config["roles"]["executor"]
    entry["key_folder"], entry["key_file"], entry["app_file"] = folder, folder / "e.pem", folder / "e.app.json"
    config["roles"]["reviewer"]["key_file"] = tmp_path / "r.pem"
    S.check_key_places(config, ["executor", "reviewer"], FakeWindows(), EXECUTOR)
    (tmp_path / "r.pem").write_bytes(b"x")
    assert "already exists" in stop_message(lambda: S.check_key_places(config, ["reviewer"], FakeWindows(), EXECUTOR))
    (folder / "e.app.json").write_bytes(b"x")
    assert "already exists" in stop_message(lambda: S.check_key_places(config, ["executor"], FakeWindows(), EXECUTOR))
    monkeypatch.setattr(S, "inside_a_repository", lambda f: True)
    (tmp_path / "r.pem").unlink()
    assert "inside a git repository" in stop_message(lambda: S.check_key_places(config, ["reviewer"], FakeWindows(), EXECUTOR))


# ---------------------------------------------------------------- amendment A2: R7 and R8
USERS, AUTHENTICATED = "S-1-5-32-545", "S-1-5-11"


def test_r7_an_operators_key_never_exists_with_inherited_access(tmp_path):
    win = FakeWindows()
    path = tmp_path / "reviewer.pem"
    S.write_operator_key(win, path, PEM, EXECUTOR)
    protected, rules = win.first_seen[str(path)]
    assert protected is True and rules == {OPERATOR: S.FULL_CONTROL}, "the file existed with inherited access"


def test_r7_an_executors_key_never_exists_with_inherited_access(tmp_path):
    win = FakeWindows()
    path = tmp_path / "executor.pem"
    S.write_for_executor(win, path, PEM, EXECUTOR)
    protected, rules = win.first_seen[str(path)]
    assert protected is True and set(rules) == {OPERATOR, EXECUTOR}, "the file existed with inherited access"
    assert win.acl_of(path) == (True, [(EXECUTOR, READ, "Allow", "False")])


@pytest.mark.parametrize("sid", [USERS, AUTHENTICATED, EXECUTOR])
def test_r7_a_key_folder_open_to_others_is_refused(tmp_path, sid):
    win = FakeWindows()
    folder = tmp_path / "keys"
    folder.mkdir()
    win.acl[str(folder)] = {"protected": False, "rules": {OPERATOR: S.FULL_CONTROL, sid: READ}}
    assert "folder" in stop_message(lambda: S.check_key_folder(win, folder, EXECUTOR))


@pytest.mark.parametrize("sid", ["S-1-5-4", "S-1-5-113", "S-1-5-21-1111111111-2222222222-3333333333-1013"])
def test_s10_a_key_folder_open_to_interactive_local_accounts_or_another_user_is_refused(tmp_path, sid):
    """S10: only the operator, SYSTEM and Administrators may have access (INTERACTIVE and Local account include
    the executor)."""
    win = FakeWindows()
    folder = tmp_path / "keys"
    folder.mkdir()
    win.acl[str(folder)] = {"protected": True, "rules": {OPERATOR: S.FULL_CONTROL, sid: READ}}
    assert "folder" in stop_message(lambda: S.check_key_folder(win, folder, EXECUTOR))


def test_r7_a_key_folder_of_the_operator_alone_passes(tmp_path):
    win = FakeWindows()
    folder = tmp_path / "keys"
    folder.mkdir()
    win.acl[str(folder)] = {"protected": True, "rules": {OPERATOR: S.FULL_CONTROL, "S-1-5-18": S.FULL_CONTROL,
                                                         "S-1-5-32-544": S.FULL_CONTROL}}
    S.check_key_folder(win, folder, EXECUTOR)


def test_r7_the_reviewers_folder_is_checked_before_anything(tmp_path, monkeypatch):
    monkeypatch.setattr(S, "inside_a_repository", lambda folder: False)
    win = FakeWindows()
    config = good(tmp_path)
    config["roles"]["reviewer"]["key_file"] = tmp_path / "r.pem"
    win.acl[str(tmp_path)] = {"protected": False, "rules": {OPERATOR: S.FULL_CONTROL, USERS: READ}}
    assert "folder" in stop_message(lambda: S.check_key_places(config, ["reviewer"], win, EXECUTOR))


class Opener:
    def __init__(self, body=b'{"id": 1, "slug": "x", "pem": "k"}', status=201):
        self.body, self.status, self.requests = body, status, []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        opener = self

        class Answer:
            status = opener.status

            def read(self):
                return opener.body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return Answer()


def test_r8_the_code_is_exchanged_by_the_script_itself():
    opener = Opener()
    answer = S.exchange_code("abc123", opener)
    assert answer == {"id": 1, "slug": "x", "pem": "k"}
    request = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == "https://api.github.com/app-manifests/abc123/conversions"
    assert not request.has_header("Authorization")


@pytest.mark.parametrize("body, status", [(b"[]", 201), (b"not json", 201), (b"{}", 200)])
def test_r8_a_bad_answer_to_the_exchange_stops(body, status):
    stop_message(lambda: S.exchange_code("abc123", Opener(body, status)))


def test_r8_the_code_never_reaches_a_command_line():
    text = (SETUP_DIR / "setup_apps.py").read_text(encoding="utf-8")
    assert "app-manifests" not in "".join(re.findall(r"gh\(\[[^\]]*\]", text)), "the code is passed to gh"
