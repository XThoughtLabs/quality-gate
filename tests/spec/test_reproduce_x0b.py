"""gate.reproduce, X-0b (HQ-ANSWERS-06), and the two refinements of X-0 that came with it.

X-0b: every check a rerun starts runs with no variable whose name `gate/env` counts as a secret (E-2), so PR code cannot read
GATE_TOKEN and `gate/env` gives what it gave in the run. `make reproduce` hands GATE_TOKEN to the container by name, when it is set.

What the public entrance can show, from the documents alone:
- A rerun starts the checks of the stored run. The tests store evidence for a SHA (`context.json`, `extras.json`, `SHA256SUMS`
  in `reports/<pr>/<run_id>-<attempt>/`), put `quality.toml` at the run's `trusted_sha`, and give mandatory checks whose commands
  write the environment they see into files that the test names by absolute path, so that nothing depends on where
  `gate.reproduce` puts its own output. CONTRACTS.md gives the stored layout only in part (see the report); if the rerun stops
  before it starts a check, the tests fail with that said, and the case is a spec gap to adjudicate, not a verdict on X-0b.
- `make reproduce` is a text check of the Makefile at GATE_ROOT.
"""
from __future__ import annotations

import json
import re
import sys

import pytest

from gatekit import (GATE_ROOT, Repo, assert_no_traceback, base_env, make_bare, make_config, push_to, run_gate, sha256_file,
                     write_json, write_script, write_text)
from test_reproduce_x0 import GITHUB_FORMS, Remote, assert_not_untrusted, assert_untrusted

# ----------------------------------------------------------------------------- the X-0 refinement: a newer commit on the API's side

NEWER = "e" * 40


@pytest.mark.req("X-0")
def test_x0_a_newer_commit_on_the_apis_side_is_no_failure(tmp_path, stub):
    # "a report may be stored meanwhile and its authors are checked too": the commit git read is among those the API lists
    remote = Remote(tmp_path, stub, evidence_for_sha=False)
    remote.api.mirror(remote.commits + [(NEWER, [remote.commits[-1][0]])])
    assert_not_untrusted(remote, remote.run(GITHUB_FORMS["https"]))


@pytest.mark.req("X-0")
def test_x0_a_newer_foreign_commit_on_the_apis_side_is_still_a_failure(tmp_path, stub):
    remote = Remote(tmp_path, stub, evidence_for_sha=True)
    remote.api.mirror(remote.commits + [(NEWER, [remote.commits[-1][0]])], foreign={NEWER: ("some-person", True)})
    assert_untrusted(remote, remote.run(GITHUB_FORMS["https"]))


# ----------------------------------------------------------------------------- X-0b: the rerun's checks see no secret

VALUE = "SENTINEL-VALUE-1234"
SECRET_VARIABLES = [
    "GATE_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "EXECUTOR_APP_PRIVATE_KEY",
    # one name for each word that E-2 counts, and one in lower case
    "EXAMPLE_SECRET_A", "EXAMPLE_PASSWORD_B", "EXAMPLE_CREDENTIAL_C", "EXAMPLE_API_KEY_D", "EXAMPLE_PRIVATE_KEY_E",
    "example_token_f",
]
DUMPED_CHECKS = ["gate/tests", "gate/acceptance", "gate/security", "gate/guard"]
DUMPER = '''
import json
import os
import sys

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(dict(os.environ), handle)
'''


class Rerun:
    def __init__(self, tmp, res, out, dumps, env_results):
        self.tmp, self.res, self.out, self.dumps, self.env_results = tmp, res, out, dumps, env_results

    def streams_and_files(self):
        parts = [self.res.both]
        if self.out.is_dir():
            parts += [p.read_bytes().decode("utf-8", "replace") for p in sorted(self.out.rglob("*")) if p.is_file()]
        return "\n".join(parts)

    def started(self):
        assert "No module named" not in self.res.err, "precondition: gate.reproduce exists and runs with python -P -m"
        assert self.dumps.get("gate/tests") is not None, (
            "the rerun started no check: the dump that gate/tests writes is missing, so nothing can be said about X-0b. "
            "The stored layout may differ from what the test assumed (see the report).\n" + self.res.describe())


def build_remote(tmp):
    """A bare repository with a trusted commit (the configuration), a head commit, and stored evidence for the head."""
    dump_dir = tmp / "dumps"
    dump_dir.mkdir()
    dumper = write_script(tmp / "dumper.py", DUMPER)
    checks = {}
    for cid in DUMPED_CHECKS:
        slug = cid.replace("/", "-")
        checks[cid] = {"class": "mandatory", "commands": [[sys.executable, str(dumper), str(dump_dir / f"{slug}.json")]]}
    env_json = dump_dir / "gate-env-role-reproduce.json"
    checks["gate/env"] = {"class": "mandatory",
                          "commands": [[sys.executable, "-P", "-m", "gate.env_check", "--role", "reproduce", "--out", str(env_json)]],
                          "env": {"PYTHONPATH": str(GATE_ROOT)}}
    work = Repo(tmp / "work")
    work.write("src/app.py", "x = 1\n")
    work.write("acceptance/test_status.py", "def test_history():\n    assert 2 + 2 == 4\n")
    make_config(work.path / "quality.toml", checks=checks)
    trusted = work.commit("trusted: the configuration and the acceptance tests")
    work.write("src/app.py", "x = 2\n")
    head = work.commit("the head that was judged")
    bare = make_bare(tmp / "remote" / "example-app.git")
    push_to(work, bare, "main")
    config_hash = sha256_file(work.path / "quality.toml")
    work.git("checkout", "-q", "--orphan", "reports")
    work.git("rm", "-rqf", ".")
    folder = work.path / "reports" / "7" / "1001-1"
    write_json(folder / "context.json", {
        "repository": "example-org/example-app", "head_repository": "example-org/example-app", "pr": 7, "run_id": 1001,
        "run_attempt": 1, "event": "pull_request_target", "baseline_sha": trusted, "base_sha": trusted, "head_sha": head,
        "gate_sha": "b" * 40, "head_ref": "ai/12-example", "config_hashes": {"quality.toml": config_hash}, "trusted_sha": trusted})
    write_json(folder / "extras.json", {})
    sums = "".join(f"{sha256_file(folder / name)}  {name}\n" for name in ("context.json", "extras.json"))
    write_text(folder / "SHA256SUMS", sums)
    work.commit("evidence for the head")
    push_to(work, bare, "reports")
    return bare, head, dump_dir, env_json


@pytest.fixture(scope="module")
def rerun(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("x0b")
    bare, head, dump_dir, env_json = build_remote(tmp)
    out = tmp / "rerun"
    env = base_env({name: f"{VALUE}-{name}" for name in SECRET_VARIABLES})
    res = run_gate("reproduce", "--repo", str(bare), "--sha", head, "--out", out, env=env, cwd=tmp, timeout=300)
    dumps = {}
    for cid in DUMPED_CHECKS:
        path = dump_dir / f"{cid.replace('/', '-')}.json"
        dumps[cid] = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None
    env_results = json.loads(env_json.read_text(encoding="utf-8")) if env_json.is_file() else None
    return Rerun(tmp, res, out, dumps, env_results)


@pytest.mark.req("X-0b", "X-2")
def test_x0b_control_the_rerun_starts_a_check_and_ends_without_a_traceback(rerun):
    rerun.started()
    assert_no_traceback(rerun.res)


@pytest.mark.req("X-0b")
@pytest.mark.parametrize("name", SECRET_VARIABLES)
def test_x0b_no_check_of_the_rerun_sees_a_variable_whose_name_is_a_secret(rerun, name):
    rerun.started()
    seen = {cid: sorted(k for k in dump if k.upper() == name.upper()) for cid, dump in rerun.dumps.items() if dump is not None}
    assert all(not names for names in seen.values()), f"a check of the rerun saw {name}: {seen}"


@pytest.mark.req("X-0b", "C-3")
def test_x0b_no_value_of_a_secret_reaches_a_check_a_message_or_a_file_under_out(rerun):
    rerun.started()
    seen = [cid for cid, dump in rerun.dumps.items() if dump and any(VALUE in str(v) for v in dump.values())]
    assert not seen, f"the value of a secret reached the check(s) {seen}"
    assert VALUE not in rerun.streams_and_files(), "the value of a secret was printed or written under --out"


@pytest.mark.req("X-0b", "E-2")
def test_x0b_gate_env_in_the_rerun_finds_no_secret_present(rerun):
    # if the rerun runs gate/env through the configuration, the role `reproduce` (E-4a) must find nothing (E-2)
    rerun.started()
    if rerun.env_results is None:
        pytest.skip("the rerun did not run gate/env through the configured command, so there is no result of it to read "
                    "(the contract does not say how gate/env is rerun)")
    broken = [i for i in rerun.env_results["items"] if not i["ok"]]
    assert not any(i["item"].startswith("secret-present:") for i in broken), f"gate/env found secrets in the rerun: {broken}"
    assert rerun.env_results["role"] == "reproduce"


# ----------------------------------------------------------------------------- make reproduce: GATE_TOKEN by name


def reproduce_recipe() -> str:
    """The recipe of the `reproduce` target, with the make variables that the file defines at its left edge filled in."""
    makefile = GATE_ROOT / "Makefile"
    assert makefile.is_file(), f"{makefile} does not exist"
    lines = makefile.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ").splitlines()
    definitions = {}
    for line in lines:
        found = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]*=\s*(.*)$", line)
        if found:
            definitions[found.group(1)] = found.group(2)
    recipe, inside = [], False
    for line in lines:
        if re.match(r"^reproduce\s*:(?!=)", line):
            inside = True
            recipe.append(line.split(":", 1)[1])
            continue
        if inside:
            if line.startswith(("\t", " ")) or not line.strip() or line.startswith("#"):
                recipe.append(line)
            else:
                break
    assert inside, "the Makefile has no `reproduce` target"
    text = "\n".join(recipe)
    for _ in range(3):   # a few rounds, for variables that name other variables
        text = re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]", lambda m: definitions.get(m.group(1), m.group(0)), text)
    return text


GATE_TOKEN_BY_NAME = re.compile(r"""(?:-e|--env)(?:\s+|=)["']?GATE_TOKEN["']?(?![=\w$])""")
GATE_TOKEN_WITH_A_VALUE = re.compile(r"""(?:-e|--env)(?:\s+|=)["']?GATE_TOKEN["']?\s*=""")


@pytest.mark.req("X-0b")
def test_x0b_make_reproduce_hands_gate_token_to_the_container_by_name():
    recipe = reproduce_recipe()
    assert GATE_TOKEN_BY_NAME.search(recipe), f"no `-e GATE_TOKEN` (or `--env GATE_TOKEN`) in the recipe:\n{recipe}"


@pytest.mark.req("X-0b", "C-3")
def test_x0b_make_reproduce_never_puts_the_value_of_gate_token_on_a_command_line():
    recipe = reproduce_recipe()
    assert not GATE_TOKEN_WITH_A_VALUE.search(recipe), f"the recipe gives GATE_TOKEN a value on the command line:\n{recipe}"
    assert "GATE_TOKEN" in recipe, "the recipe never names GATE_TOKEN"
