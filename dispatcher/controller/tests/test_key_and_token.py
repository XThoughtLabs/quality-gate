"""CR-11: the key, the JWT, the installation token, the host and the timeout."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

import fake_github as F

USERS = "S-1-5-32-545"
EVERYONE = "S-1-1-0"
SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"


def key_unsafe(world, result):
    assert result.code == 2, result.out
    assert result.stop.startswith("CONTROLLER USAGE"), result.out
    assert "KEY_UNSAFE" in result.stop
    assert world.gh.calls == []


@pytest.mark.cr("CR-11")
@pytest.mark.parametrize("extra", [USERS, EVERYONE, "S-1-5-11", "S-1-5-4", "S-1-5-21-1000-2000-3000-1002"])
def test_key_file_open_to_someone_else(world, extra):
    world.win.rules[str(world.key_file)] = [(F.OPERATOR_SID, F.FULL, "Allow", "False"), (extra, 1179785, "Allow", "True")]
    key_unsafe(world, world.run())


@pytest.mark.cr("CR-11")
def test_key_folder_open_to_someone_else(world):
    world.win.rules[str(world.key_file.parent)] = [(F.OPERATOR_SID, F.FULL, "Allow", "False"), (USERS, 1179785, "Allow", "True")]
    key_unsafe(world, world.run())


@pytest.mark.cr("CR-11")
def test_system_and_administrators_are_allowed(world):
    rules = [(F.OPERATOR_SID, F.FULL, "Allow", "False"), (SYSTEM, F.FULL, "Allow", "True"), (ADMINS, F.FULL, "Allow", "True")]
    world.win.rules[str(world.key_file)] = rules
    world.win.rules[str(world.key_file.parent)] = rules
    assert world.run().code == 0


@pytest.mark.cr("CR-11")
def test_a_deny_rule_for_others_is_not_an_opening(world):
    world.win.rules[str(world.key_file)] = [(USERS, F.FULL, "Deny", "False"), (F.OPERATOR_SID, F.FULL, "Allow", "False")]
    assert world.run().code == 0


@pytest.mark.cr("CR-11")
def test_both_the_file_and_its_folder_are_checked(world):
    world.run()
    assert str(world.key_file) in world.win.asked
    assert str(world.key_file.parent) in world.win.asked


@pytest.mark.cr("CR-11")
def test_key_that_is_a_folder(world):
    world.set_config(key_file=f"'{world.key_file.parent}'")
    result = world.run()
    assert result.code == 2 and "KEY_UNSAFE" in result.stop, result.out
    assert world.gh.calls == []


@pytest.mark.cr("CR-11")
def test_missing_key_file(world):
    world.set_config(key_file=f"'{world.tmp / 'keys' / 'absent.pem'}'")
    result = world.run()
    assert result.code == 2 and "KEY_UNSAFE" in result.stop, result.out


@pytest.mark.cr("CR-11")
def test_key_that_is_a_symbolic_link(world):
    link = world.tmp / "keys" / "link.pem"
    try:
        os.symlink(world.key_file, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symbolic links cannot be made here: {error}")
    world.set_config(key_file=f"'{link}'")
    result = world.run()
    assert result.code == 2 and "KEY_UNSAFE" in result.stop, result.out


@pytest.mark.cr("CR-11")
@pytest.mark.parametrize("mode, attributes", [(stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o600, 0x400)])
def test_key_seen_as_a_link_or_reparse_point(world, monkeypatch, controller, mode, attributes):
    """The same rule as the skipped test above, without the privilege a real link needs (closes mutant M56)."""
    real_lstat = os.lstat

    def fake_lstat(path, *args, **kwargs):
        if str(path) == str(world.key_file):
            values = list(real_lstat(path))
            values[0] = mode
            result = os.stat_result(values)
            return FakeStat(result, attributes)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(controller.os, "lstat", fake_lstat)
    result = world.run()
    assert result.code == 2 and "KEY_UNSAFE" in result.stop, result.out
    assert world.gh.calls == []


class FakeStat:
    def __init__(self, base, attributes):
        self._base = base
        self.st_file_attributes = attributes

    def __getattr__(self, name):
        return getattr(self._base, name)


@pytest.mark.cr("CR-11")
def test_key_not_read_when_unsafe(world, monkeypatch, controller):
    world.win.rules[str(world.key_file)] = [(USERS, 1179785, "Allow", "True")]
    real_read = Path.read_bytes
    opened = []

    def watch(self):
        if self == world.key_file:
            opened.append(self)
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", watch)
    real_open = open

    def watch_open(file, *args, **kwargs):
        if str(file) == str(world.key_file):
            opened.append(file)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", watch_open)
    key_unsafe(world, world.run())
    assert opened == []


@pytest.mark.cr("CR-11")
def test_jwt_is_signed_and_timed(world):
    assert world.run().code == 0
    assert world.gh.jwt_claims["iss"] in (F.APP_ID, str(F.APP_ID))
    assert world.gh.jwt_claims["iat"] == F.NOW - 60
    assert world.gh.jwt_claims["exp"] == F.NOW + 540


@pytest.mark.cr("CR-11")
def test_token_is_narrowed_to_the_repository_and_four_permissions(world):
    world.run()
    assert world.gh.token_bodies == [{
        "repositories": ["demo-stand"],
        "permissions": {"contents": "write", "checks": "write", "pull_requests": "read", "statuses": "read"},
    }]


@pytest.mark.cr("CR-11")
def test_token_refused_is_a_github_error(world):
    world.gh.fail["token"] = (422, {"message": "The permissions requested are not granted to this installation."})
    result = world.run()
    assert result.code == 6, result.out
    assert world.gh.routes() == ["token"]


@pytest.mark.cr("CR-11")
def test_no_secret_in_output_or_record(world, rsa_key):
    world.gh.merge_answer = (405, {"message": "echo " + F.TOKEN})
    result = world.run()
    jwt = next(c.headers["Authorization"][7:] for c in world.gh.calls if c.route == "token")
    text = result.out + result.err + world.log_file.read_text(encoding="utf-8")
    for secret in (F.TOKEN, jwt, "PRIVATE KEY"):
        assert secret not in text


@pytest.mark.cr("CR-11")
def test_secrets_never_reach_the_environment(world, monkeypatch):
    seen = {}

    def snapshot(gh):
        seen.update(os.environ)
    world.gh.after["merge"] = snapshot
    world.run()
    assert F.TOKEN not in " ".join(seen.values())


class _Answer:
    status = 200

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.mark.cr("CR-11")
def test_default_transport_goes_to_github_with_a_timeout_no_proxy_no_redirect(controller, monkeypatch):
    """Amendment R4: an opener with an empty ProxyHandler and a handler that follows no redirect."""
    import urllib.request

    calls, handlers = [], []

    class Opener:
        def open(self, request, timeout=None):
            calls.append((request.full_url, timeout, request.get_method()))
            return _Answer()

    def fake_build_opener(*given):
        handlers.extend(given)
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: pytest.fail("the default opener must not be used"))
    status, body = controller.default_http("GET", F.API + "/repos/acme/demo-stand/pulls/7",
                                           {"Authorization": "Bearer x"}, None)
    assert status == 200 and body == b"{}"
    assert calls == [(F.API + "/repos/acme/demo-stand/pulls/7", 30, "GET")]
    proxies = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert len(proxies) == 1 and proxies[0].proxies == {}
    redirect = [h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler)
                or (isinstance(h, type) and issubclass(h, urllib.request.HTTPRedirectHandler))]
    assert len(redirect) == 1
    handler = redirect[0]() if isinstance(redirect[0], type) else redirect[0]
    request = urllib.request.Request(F.API + "/x", method="GET")
    assert handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/x") is None


@pytest.mark.cr("CR-11")
@pytest.mark.parametrize("url", ["http://api.github.com/x", "https://evil.example/x", "https://api.github.com.evil/x"])
def test_default_transport_refuses_another_host(controller, monkeypatch, url):
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: pytest.fail("no request may leave"))
    monkeypatch.setattr("urllib.request.build_opener", lambda *a, **k: pytest.fail("no request may leave"))
    with pytest.raises(controller.ControllerError):
        controller.default_http("GET", url, {}, None)


@pytest.mark.cr("CR-11")
def test_default_windows_is_the_setup_scripts(controller):
    windows = controller.default_windows()
    module = sys.modules[type(windows).__module__]
    assert Path(module.__file__).resolve() == (Path(controller.__file__).resolve().parents[2] / "setup" / "setup_apps.py")
    assert type(windows).__name__ == "Windows"
