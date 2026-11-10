# Script contracts

The numbered rules every script must meet. Tests are written from this file and from the design, not from the code. A rule that a test cannot check from outside says so.

The pipeline names no application. Everything application-specific comes from `quality.toml` in the repository being judged.

## 0. Common rules

- **C-1 Entrance.** Each script is a module run as `python -P -m gate.<name>` with `PYTHONPATH` set to this repository's root. `-P` keeps the working directory off `sys.path`, so a judged repository cannot shadow the module.
- **C-2 Exit codes.** `0` success. `1` a rule failed. `2` a usage or configuration error. An expected failure prints a short message and no traceback.
- **C-3 Secrets.** No script prints, logs or writes the value of a secret, in any output file or message, including when the value is malformed.
- **C-4 Untrusted text.** Anything read from an artifact, a diff, a model or a comment is data. It never changes a verdict except through the checks named here. When it is posted, every `@word` from it appears inside backticks.
- **C-5 Mention.** Anything the gate posts writes `@claude` only in backticks.
- **C-6 Python.** Python 3.13. Standard library, plus `jsonschema` in `report generate` and `cryptography` in `review_local`.

## 1. `quality.toml`

```toml
[project]
baseline_sha = "<40 hex>"
integration_branch = "candidate/a"

[environment]              # optional
python = "3.13"            # compared to the running major.minor
image_os = "ubuntu24"      # compared to the ImageOS variable

[limits]
max_turns = 40
timeout_minutes = 60
max_fix_rounds = 3

[guard]
extra_protected = ["prompts/"]        # added to the fixed list, never replaces it
dependency_files = ["requirements.lock"]
dependency_sources = ["requirements.in"]
threshold_keys = ["fail_under"]       # added to the fixed list

[feedback]
judge_workflow_path = ".github/workflows/judge.yml"
reviewer_app = "example-reviewer"     # login without the [bot] suffix
executor_app = "example-executor"     # login without the [bot] suffix

[acceptance]
require_empty = false                 # the CEO sets it true before the final PR (A-10)

[[archive.accepted_foreign_commits]]  # the recovery of reports (W-14). Usually absent
sha = "<40 hex>"
reason = "why this commit was accepted"
date = "2026-11-03"

[spec_tests]
deny_read = ["src/**", "tests/**"]

[checks."gate/tests"]
class = "mandatory"
commands = [["python", "-m", "pytest", "-q", "--junitxml={raw}/junit.xml"]]
junit = "junit.xml"
forbid_skips = true
required_outputs = ["junit.xml"]
timeout_seconds = 1800
```

- **Q-1** `{raw}` in a command is replaced by the absolute path of the check's raw folder. `{env:NAME}` is replaced by that variable from the job's trusted context. A variable that is not set exits 2.
- **Q-1a** An optional `env` table gives a check's commands more variables, with the same placeholders. The gate's own `PYTHONPATH` never reaches them unless this table gives it. The optional `[setup]` table holds the commands that prepare the application, run as `--check setup`, outside the fixed classes.
- **Q-2 Fixed classes.** `gate/env`, `gate/tests`, `gate/acceptance`, `gate/guard`, `gate/security`, `gate/report`, `gate/archive`, `gate/final` are mandatory. `diag/coverage`, `diag/mypy`, `diag/ruff`, `diag/semgrep`, `diag/schemathesis`, `diag/mutation`, `diag/benchmark` are diagnostic. A configuration giving a known check another class, or naming an unknown check, is refused with exit 2.

## 2. `gate.env_check`

`python -P -m gate.env_check --role ROLE [--config quality.toml] [--out FILE]`

Roles: `executor`, `spec-tests`, `run`, `publish`, `archive`, `feedback`.

Prints one line per item: `OK <item>` or `BROKEN <item>: <reason>`. `--out` writes `{"role", "ok", "items": [{"item", "ok", "reason"}]}`. Exit 0 when all are OK, 1 otherwise.

- **E-1 executor and spec-tests.** Items `secret:CLAUDE_CODE_OAUTH_TOKEN`, `secret:EXECUTOR_APP_PRIVATE_KEY`, `variable:EXECUTOR_APP_ID`. Missing or empty is broken. A private key without a PEM header line is broken. An app ID that is not a positive integer is broken.
- **E-2 run.** Every environment variable with a non-empty value whose name contains `TOKEN`, `SECRET`, `PASSWORD`, `PRIVATE_KEY`, `CREDENTIAL` or `API_KEY` (case-insensitive) gives a broken item `secret-present:<NAME>`, except `GATE_PROBE_TOKEN`.
- **E-3 Permissions.** For `run`, `publish`, `archive` and `feedback`, permissions are probed against the API at `GITHUB_API_URL`, for `GITHUB_REPOSITORY`, with the token in `GATE_PROBE_TOKEN`. A write probe sends a request that changes nothing: status 422 means the write is allowed, 403 means it is denied. Two probes send a **well-formed but doomed** body, because a bare `{}` body is validated before the permission is checked and a read-only token would read as "allowed":
  - `contents` (`POST /git/refs`): a fresh unused branch at an all-zero, non-existent object (`{"ref": "refs/heads/gate-probe-<random>", "sha": "<40 zeros>"}`). The empty-body `{}` false positive was found on run 42361091565 (2026-11-07).
  - `pull-requests` (`PATCH /pulls/{pr}`): the open PR's base moved to a non-existent branch (`{"base": "gate-probe-<random>"}`). The PR number comes from the workflow event (`GITHUB_EVENT_PATH`: `pull_request.number`, `issue.number`, or `workflow_run.pull_requests[0].number`); with no PR number the item is broken, never a pass. This replaces `POST /pulls`, which the repository's "Allow GitHub Actions to create and approve pull requests" setting blocks (off by default) so that it returned 403 even for an allowed token (run 42368667062, publish job, 2026-11-07). The gate never needs `POST /pulls`: the launcher opens PRs with the app token, and `publish` only posts PR comments.

  The `checks` write probe keeps the empty `{}` body. A read probe expects 200.

  | Permission | Probe |
  |---|---|
  | `checks` write | `POST /repos/{repo}/check-runs` (body `{}`) |
  | `contents` write | `POST /repos/{repo}/git/refs` (well-formed, doomed) |
  | `pull-requests` write | `PATCH /repos/{repo}/pulls/{pr}` (well-formed, doomed; `{pr}` from the event) |
  | `actions` read | `GET /repos/{repo}/actions/runs?per_page=1` |
  | `contents` read | `GET /repos/{repo}` |

  | Role | Must be allowed | Write must be denied |
  |---|---|---|
  | `run` | contents read | contents, checks, pull-requests |
  | `publish` | checks write, pull-requests write, actions read, contents read | contents |
  | `archive` | contents write, checks write | pull-requests |
  | `feedback` | pull-requests write, contents read | contents, checks |

  Items are named `permission:<name>-<read|write>:<allowed|denied>`, for example `permission:contents-write:denied`: the permission as in the table, and the state that is required. Any other status, or no token, or a network error, is broken: never a pass.
- **E-4 Environment.** When `[environment]` is set, items `environment:python` and `environment:image_os` compare the values. A mismatch names both the expected and the found value.
- **E-4a** The role `reproduce` is for a rerun in the pinned container: it runs E-2, and of E-4 only `environment:python`.
- **E-5 Names, never values.** Each broken item names the broken part. No value of a variable appears in stdout, stderr or `--out`, for any role. The one exception is E-4: the Python version and `ImageOS`, which are not secret.
- **E-6** `--config` is optional, and has no default: without it, E-4 does not apply.

## 3. `gate.run_checks`

`python -P -m gate.run_checks --config quality.toml --check ID --out DIR [--workdir DIR]`

Runs every command of one check, in order, in the working directory.

- **R-1** Each command's stdout and stderr go to `DIR/raw/<slug>/<index>.log`. The slug is the check ID with `/` replaced by `-`. The index starts at 0.
- **R-2** Each command appends one row to `DIR/exit-codes.tsv`, which starts with the header `check	index	exit_code	duration_seconds	raw_path	argv_json`. `exit_code` is the numeric exit code.
- **R-3** Every command runs even when an earlier one failed. The script's own exit code is the first non-zero exit code of the commands, or 0. This holds over C-2, so 124 and 127 reach the caller.
- **R-4** A command not found records 127. A command past `timeout_seconds` is killed and records 124. Neither is a pass.
- **R-5** A check with `junit` set reads that file from its raw folder, relative to it, and writes `counts.json` there with `tests`, `failures`, `errors`, `skipped`. A missing or unparsable file is a failure. With `forbid_skips`, `skipped > 0` is a failure. Such a failure appends a row with index `post` and exit code 1, and the script exits non-zero.
- **R-6** `required_outputs` are relative to the raw folder. A missing one appends a row with index `post` and exit code 1, and the script exits non-zero.
- **R-7** An unknown check ID, or a configuration refused by Q-2, exits 2.
- **R-8** Rows are appended, never rewritten: running two checks leaves both.
- **R-9** `argv_json` holds the command as configured, with its placeholders, so that a rerun on another machine records the same text.
- **R-10** With `--if-configured`, a check that is not configured exits 0 and records nothing.
- **R-11 Each test of the base (decision W).** A check with `expected_tests_from_base = true` and `junit` also requires each test of the base in the JUnit file. The base is the merge base of `GATE_BASE_SHA` and `HEAD`, in the working directory's git repository. Its tests are read by parsing, without running, every file named `test_*.py` or `*_test.py`: top-level functions whose names start with `test`, and methods whose names start with `test` in classes whose names start with `Test` or that inherit from a `TestCase`. A test's ID is `<dotted path of the file without .py>[.<class>...]::<name>`, and a JUnit name's `[...]` part is ignored when comparing. A test that is absent appends a row with index `post` and exit code 1, the script exits non-zero, and `missing_tests.json` in the raw folder lists them. `GATE_BASE_SHA` not set, or a base that cannot be read, exits 2.
  - `acceptance/` is always left out: `gate/acceptance` has its own rule (A-11).
  - As pytest does, the parsing passes over: a function decorated as a fixture, a `Test*` class with its own `__init__`, and anything with `__test__ = False` (a module, a class, or `name.__test__ = False` on a function).
  - `expected_tests_ignore`, a trusted list of folders, files or test IDs, leaves out what pytest treats differently in one repository, such as a file outside `testpaths`.
  - `expected_tests_root` is the folder pytest counts IDs from, when a configuration file in it makes it the root.
- **R-12** A check with `junit` fails when the file records a failed test or an error, whatever the commands exited with. `pytest.exit` with code 0 stops a run with an exit code of 0.

## 4. `gate.acceptance` (decision O)

`python -P -m gate.acceptance --junit FILE --known-failing FILE [--mode subset|exact] [--require-empty] [--config FILE] [--tests-dir DIR] --out FILE`

The test ID is `<classname>::<name>` from the JUnit file. The list holds one entry per line: `<test id> <map id>`. The **map ID is the last whitespace-separated field, and the test ID is everything before it**, its own spaces kept — so a parametrized ID that holds a space (for example `...[GET /tasks/{task_id}/history-invalid]`) can be listed (this supersedes L17). Blank lines and lines starting with `#` are ignored. A map ID is `PUB-<2 digits>`, `SPEC-6.1`, `SPEC-6.2` or `DEF-<letters, digits, dashes>`. A line with no map ID, an invalid map ID, or a repeated test ID is refused (exit 2). A missing list file is an empty list.

`--out` writes `{"ok", "mode", "list_size", "failing_not_listed", "listed_failing", "remove_from_list", "missing_listed", "missing_tests", "passed", "reason_codes"}`, with sorted lists.

- **A-1** A listed test that fails does not fail the check. A failing or erroring test not on the list does, code `FAILING_NOT_LISTED`.
- **A-2** A skipped test not on the list counts as failing.
- **A-3** A listed test that passes goes into `remove_from_list` and does not fail the check in `subset` mode, the default.
- **A-4** A listed test absent from the JUnit file fails the check, code `MISSING_LISTED`. A JUnit file with no test cases fails, code `NO_TESTS`.
- **A-5** In `exact` mode, used on `spec/*` PRs, the failing set must equal the list. A listed test that passes fails the check, code `LIST_NOT_EXACT`.
- **A-6** With `--require-empty`, a non-empty list fails, code `LIST_NOT_EMPTY`.
- **A-7** An entry without a valid map ID, a duplicate entry or an unreadable JUnit file exits 2.
- **A-8** `list_size` and `remove_from_list` are always written.
- **A-9** A command after `--` runs first, and its exit code goes into `test_command_exit_code`. Exit codes 0, 1 and 5 are what pytest gives for passed, failed and no tests; any other fails the check, code `TEST_COMMAND_ERROR`. This keeps one exit code for the check: a listed failure makes pytest exit 1 and must not turn the check red.
- **A-10** `[acceptance] require_empty = true` in the file given by `--config` acts as `--require-empty`. The workflow gives the configuration from the default branch, which the executor cannot change. No label and no environment variable sets it.
- **A-11 Each acceptance test (decision W).** With `--tests-dir DIR`, each test found under `DIR` by the parsing of R-11, not on the list and absent from the JUnit file, fails the check, code `MISSING_TEST`, and goes into `missing_tests`. IDs are as in R-11, with paths relative to the working folder, or to `--tests-root` when given. `[acceptance] expected_tests_ignore` in the file given by `--config` works like `expected_tests_ignore`.

## 5. `gate.guard`

`python -P -m gate.guard --repo DIR --base SHA --head SHA --branch REF --author LOGIN --config FILE --out FILE [--reports-dir DIR] [--pr N]`

Reads git objects only and runs no code from the repository, nor any command that the repository's git settings name (an external diff, a textconv, an fsmonitor). It compares the merge base of `--base` and `--head` with `--head`, with renames shown as a delete and an add.

`--out` writes `{"kind", "head_sha", "violations": [{"rule", "path", "detail"}], "needs_code_owner": [path], "marked_tests": [{"path", "name"}], "security_review_changes": [{"change", "row"}], "dependency_changes": [{"name", "old", "new", "changelog"}], "fingerprint": {"round", "cumulative"}, "repeated_fix"}`.

Exit 1 when `violations` is non-empty, otherwise 0.

**The kind of a PR (decision V).** A branch name can only make the rules stricter, never looser.

- A PR is **strict** when any of these holds: `--author` is `<feedback.executor_app>[bot]`, or any login ending in `[bot]`; a commit between the merge base and the head has an author name or a committer name equal to `<feedback.executor_app>[bot]` or `claude[bot]`; the branch starts with `ai/` or `spec/`, in any letter case.
- A strict PR is `spec` when `--author` is `<feedback.executor_app>[bot]` and the branch starts with exactly `spec/`. Every other strict PR is `ai`.
- Anything else is `other`, which is for people only.

**Rules for `ai` PRs:**

- **G-1 `PROTECTED_PATH`.** Touching any of these, added, changed or deleted, in any letter case: `.github/`, `acceptance/`, `quality.toml`, `CODEOWNERS`, `SPEC.md`, `TASK.md`, `BASELINE.md`, `OPEN-ISSUES.md`, `SOURCE-MANIFEST.json`, `evidence/`, `security-review.md`, and everything in `guard.extra_protected`. A renamed file is checked under both names.
- **G-1a What controls the tests and the security tools (decisions W and X), also `PROTECTED_PATH`.** In any folder: `pytest.toml`, `.pytest.toml`, `pytest.ini`, `.pytest.ini`, `.bandit`, `bandit.yaml`, `bandit.yml`, `.gitleaks.toml`, `.gitleaksignore`, `.gitattributes`. In the root only: `conftest.py`, `pytest.py`, `pytest/`, `_pytest/`. The pytest names come from `CONFIG_LOADERS_BY_NAME` in `_pytest/config/findpaths.py` of pytest 9.2.0, the pinned version, which looks for them upwards from the common ancestor of its arguments and from each argument, so any folder a command names can hold one. A change of the pinned version means checking this list again. `.gitattributes` is here because it can make what is checked out differ from what git stores, and the guard reads what git stores.
- **G-1b Sections, also `PROTECTED_PATH`.** What pytest reads is refused, and what it does not read stays an ordinary change.
  - In any folder: a `tox.ini` or a `setup.cfg` that changed and mentions `pytest`, in any letter case, before or after the change. Their sections are not parsed for this, because pytest reads these files with its own parser, which cuts lines and section names differently.
  - In any folder, in a `pyproject.toml`: a changed `[tool.pytest]`, or any table under it such as `[tool.pytest.ini_options]`; a changed table named `pytest11` anywhere in the file, such as `[project.entry-points.pytest11]`, `[tool.poetry.plugins.pytest11]` or `[tool.flit.entrypoints.pytest11]`; a changed `project.dynamic` that names `entry-points`, before or after; a file that cannot be parsed and mentions `pytest`. The file is parsed with its newlines as pytest reads them: `\r\n` and a lone `\r` are newlines.
  - In the root only: a changed `[tool.coverage]`, `[tool.bandit]`, `[tool.tox]`, `[tool.semgrep]`, `[tool.gitleaks]`, `[tool.pip-audit]` or `[tool.pip_audit]`, or any table under them, in `pyproject.toml`; `[coverage:*]` or `[bandit]` in `setup.cfg`; `[tox*]`, `[testenv*]`, `[coverage:*]` or `[bandit]` in `tox.ini`; a root file of these three that cannot be parsed.
- **G-1b-mark** In the root, any other change to those three files, such as `[tool.ruff]`, `[tool.poetry]`, `[project]` or `[flake8]`, is no violation. Its path goes into `needs_code_owner`. In a subfolder, a change that the rules above do not name is ordinary, and is neither refused nor marked.
- **G-1d Plain files only, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** An added or changed path that is a symbolic link or a submodule in the head, whatever its name and its text, in any spelling of a path name, including a leading `:` and bytes that are not UTF-8. What git stores for a link is only its target's name, while pytest and every tool follow it. A `.gitmodules` setting cannot hide a submodule. A link or a submodule already in the base and not changed by the PR is no violation, and neither is deleting one.
- **G-1e Encoding, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** An added or changed `.py` file that declares an encoding other than UTF-8 by Python's own rule for the first two lines, or an encoding Python does not know. Python would read other code from those bytes than the guard read.
- **G-1f No source to read, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** An added or changed file named `*.pyc`, `*.pyo`, `*.so` or `*.pyd`, or under a folder named `__pycache__`, `*.dist-info`, `*.egg-info` or `*.egg`, in any folder. Python runs bytecode without its source, and scans the path for installed packages' entry points.
- **G-1g New top-level names, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** A top-level `X.py`, or a top-level package `X/__init__.py`, that is new in the PR, where `X` is a module of Python's standard library (`sys.stdlib_module_names` of the pinned Python) or `pytest`, `_pytest`, `pluggy`, `iniconfig`, `packaging`, `pygments`, `colorama`, `tomli` or `exceptiongroup`. A module's name the base already has at the top level, as a file or as a package, is no violation, so turning one into the other is allowed. Neither is a folder with no `__init__.py`.
- **G-1h Standing in, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** A new `.py` file `D/X.py` or `D/X/__init__.py`, where `D` is not the root or `src`, has no `__init__.py`, and holds a test file or is under `acceptance/`, and `X` is a top-level module of the application in the head (at the root or under `src/`) or a name G-1g lists. `conftest` is no such name. pytest puts a test's folder first on the path, unless the folder is a package.
- **G-1i Plugins by name, also `PROTECTED_PATH`, in `ai` and `spec` PRs.** A `.py` file whose module-level binding of `pytest_plugins` is added or changed, in any way G-4 lists. In a test file or under `acceptance/`, also a new `from x import *`. A mention in a comment or a string is no violation.
- **G-1c** A change to any other `conftest.py` is no violation. Its path goes into `needs_code_owner`.
- **G-2 `TEST_DELETED`.** A test file (`test_*.py`, `*_test.py`, or any `.py` under a `tests/` folder) deleted, or a test present in the base and absent in the head. A test is a function whose name starts with `test_`, or a method whose name starts with `test`.
- **G-3 `TEST_SKIPPED`.** A `test_*` function present in the base that gains `pytest.mark.skip`, `pytest.mark.skipif`, `pytest.mark.xfail`, `unittest.skip`, a `pytest.skip(` call or a `pytest.xfail(` call. A reason line does not excuse this.
- **G-4 `TEST_WEAKENED`.** A test present in the base whose count of checks drops, or that gains any of these: an always-true assert (`assert True`, `assert 1`, `assert x == x` with both sides the same, `assert a or True`); a `pytest.raises(Exception)`; a `return` as a direct statement of its body ahead of a later check; fewer cases in a `pytest.mark.parametrize`; its name, or the name of a class it stands in, bound at module or class level by something the base does not have, such as an assignment, `del`, a loop, an import, a new `from x import *` in the file, a `class`, `except ... as`, a `match` pattern, another `def` also inside an `if`, a `try` or a similar block, a `:=` in a comprehension, a default, a decorator or a class's bases, or a `global` of that name anywhere in the file; or the test itself, or an attribute of the test, set from anywhere at module or class level, such as `TestA.test_x = None` or `test_x.__code__ = ...`. Another attribute of a class that holds tests, such as `TestA.limit = 1`, is no binding of a test. A binding the base has, replaced by another, counts even though the number stays the same. A byte-order mark at the start of a test file changes nothing in these rules. A check is an `assert` statement, a `pytest.raises` call, a `self.assert*` call or a call to a function whose name starts with `assert_`. Adding checks is allowed.
- **G-4a Marked, not refused (decision U).** A test present in the base whose code changed in any other way, or any other changed function in a test file, is no violation. It goes into `marked_tests`, and its path into `needs_code_owner`. A changed expected value is a correction or a weakening that only a person can tell apart.
- **G-5 `SUPPRESSION_NO_REASON`.** An added line in a `.py` or `.pyi` file holding any of these, in code that G-3 does not cover, without `# reason: <text>` on the same line or the line above. In any letter case, with any spacing: `# noqa`, `# type: ignore`, `# ruff: noqa`, `# flake8: noqa`, `# mypy: ignore-errors`, `# pylint: disable`, `# pragma: no cover`, `pytest.skip(`.
- **G-6 `THRESHOLD_LOWERED`.** In a changed file, a numeric value lowered or removed for `fail_under`, `fail-under`, `cov-fail-under`, or a `guard.threshold_keys` entry. Letter case and `-` or `_` do not matter. The forms are `key = value`, `key=value`, `key: value`, `key value`, and a list form such as `"--key", "10"`. A key in a comment does not count, so commenting a threshold out removes it. With several values of one key, the lowest is compared. An added `--no-cov` also counts.
- **G-7 `DEPENDENCY_NO_HASH`.** A changed `guard.dependency_files` file with a requirement line lacking `--hash=sha256:`, including across `\` line continuations. Also a changed `guard.dependency_sources` file with no change to a dependency file.
- **G-8 Dependency approval.** A changed dependency file whose requirement lines all have hashes is no violation. Its path goes into `needs_code_owner`, and each changed package goes into `dependency_changes` with old and new versions (`null` when absent) and `changelog` as `https://pypi.org/project/<name>/<new or old version>/`.
- **G-9 `REPEATED_FIX`.** See below. Also sets `repeated_fix` to true.
- **G-10 `UNPINNED_ACTION`.** An added line in any `.yml` or `.yaml` file with `uses: owner/name@ref` where `ref` is not 40 hex digits. Local paths starting `./` and `docker://` references with `@sha256:` are allowed.

**Fingerprints (G-9).**

- The normalized diff drops `index` lines, reduces hunk headers to `@@`, strips trailing whitespace and carriage returns, and orders files by path. The fingerprint is its SHA-256.
- `cumulative` covers the merge base to the head. `round` covers the previous stored head to the head, or the merge base when no earlier run is stored.
- Earlier values come from `<reports-dir>/<pr>/*/guard.json`, using `head_sha` and `fingerprint`. Files with the same `head_sha` as this run are ignored, so a rerun of one commit is not a repeat.
- A fix is repeated when `round` equals any earlier `round`, or `cumulative` equals any earlier `cumulative`. A round whose new commits are only merge commits, a merge from the base, is not a repeat.
- A `.gitattributes` in the repository changes neither a fingerprint nor what G-5 sees.
- Without `--reports-dir` or `--pr` nothing is repeated.

**Rules for `spec` PRs:**

- **G-11 `SPEC_OUTSIDE_ACCEPTANCE`.** Touching anything outside `acceptance/`.
- **G-11a** G-2, G-3, G-4 and G-4a also apply to the test files under `acceptance/`: a spec PR adds tests, and it cannot take one away or weaken one unseen.
- **G-11b `PROTECTED_PATH`, in `spec` PRs.** Under `acceptance/`: a `conftest.py` in any folder, added, changed or deleted; a file named by G-1a; what G-1b refuses in a subfolder. What controls how every test runs stays with people: fixtures go in the test file, or in a person's maintenance PR.

**Rules for `other` PRs:** only G-12 to G-14 apply.

**For every kind of PR (decision X):** G-15: each table row of `security-review.md` that the PR adds or removes goes into `security_review_changes`. It is no violation by itself on `other` PRs: the report flags it.

**The known-failing list, for every kind of PR (decision O).** Stored passes are the `passed` lists in `<reports-dir>/*/*/acceptance.json`.

- **G-12 `KNOWN_FAILING_ADD_PASSED`.** An entry added for a test that has a stored pass.
- **G-13 `KNOWN_FAILING_ADD_NOT_ALLOWED`.** An entry added on a PR that is not `spec`. When the base already has a list, also: an added entry whose map ID is not `DEF-*`, or whose test function already exists in the base. A `spec` PR that introduces the first list may map entries to any valid ID.
- **G-14 `KNOWN_FAILING_REMOVED_NOT_PASSED`.** An entry removed without a stored pass.

G-1, G-1b-mark, G-1c and G-5 to G-9 do not apply to `spec` PRs; G-1d to G-1i, G-10, G-11a and G-11b do.

## 6. `gate.security_check`

`python -P -m gate.security_check --bandit FILE --pip-audit FILE --gitleaks FILE --review FILE --repo DIR --base SHA --head SHA --out FILE`

`--out` writes `{"ok", "findings": [{"tool", "rule", "path", "line", "reviewed"}], "suppressions": [...], "reason_codes": [...]}`.

- **S-1** Bandit JSON: `results[].test_id`, `filename`, `line_number`. pip-audit JSON: `dependencies[].name` and `vulns[].id`, with the package name as the path. gitleaks JSON: a list of `RuleID`, `File`, `StartLine`.
- **S-2** The review file holds a Markdown table with the columns `tool`, `rule`, `path`, `reason`. A finding is reviewed when a row matches its tool, rule and path and the reason is not blank.
- **S-3** Any unreviewed finding exits 1, code `UNREVIEWED_FINDING`.
- **S-4** A missing or unparsable tool output exits 1, code `MISSING_TOOL_OUTPUT`: absence is never a pass.
- **S-5** An added line holding `# nosec` or `gitleaks:allow`, in any letter case and with any spacing, with no row for that tool and path exits 1, code `SUPPRESSION_WITHOUT_ENTRY`.
- **S-6** A missing review file means no reviewed findings. On GitHub the file is always the default branch's (Y-16, decision W). Only the CEO adds a row, through a maintenance PR; the executor may propose one as text in its PR comment.
- **S-7** `--tool-command '<JSON list>'`, repeatable, runs a tool first and records its exit code in `tool_exit_codes`, a list of integers in the order given. A tool that finds something exits non-zero, so only its output decides.

## 7. `gate.concurrency_harness`

`python -P -m gate.concurrency_harness --rounds R --workers W --timeout SECONDS --out FILE -- COMMAND...`

Runs `W` copies of the command at once, `R` times over. Each copy gets `GATE_WORKER_INDEX`, `GATE_ROUND` and its own empty temporary folder in `GATE_WORKER_TMP`.

`--out` writes `{"rounds", "workers", "runs", "failures": [{"round", "worker", "exit_code", "reason"}], "ok"}`.

- **H-1** Exit 0 only when every copy of every round exits 0.
- **H-2** A copy past the timeout is killed and counts as a failure with reason `timeout`.
- **H-3** All copies of a round start together, not in sequence. A check: two copies that wait for each other finish within the timeout.
- **H-4** Library form: `gate.concurrency_harness.run_together(fn, workers, rounds, timeout)` calls `fn(worker, round)` on threads released by one barrier and returns the results. An exception or a hang raises `ConcurrencyFailure`.

## 8. `gate.report`

### 8.1 `generate`

`python -P -m gate.report generate --context FILE --jobs FILE --artifact DIR --config FILE --out DIR [--extras FILE]`

Exit 0 when the files were written, whatever the verdict. Exit 2 on a usage error. Writes `report.json`, `report.md`, `verdict.json` to `--out`. `--artifact` may point to a missing folder.

**Inputs.**

- `--context`, trusted: `repository`, `head_repository`, `pr`, `run_id`, `run_attempt`, `event`, `baseline_sha`, `base_sha`, `head_sha`, `gate_sha`, `head_ref`, `config_hashes` (path to SHA-256).
- `--jobs`, trusted, in the form of the GitHub API: `{"jobs": [{"name", "status", "conclusion", "steps": [{"name", "status", "conclusion", "number"}]}]}`. The `run` job is the one named `run`, or whose name ends in ` / run`. Its steps named after check IDs are the checks.
- `--artifact`, untrusted: `exit-codes.tsv`, `SHA256SUMS` (`<sha256>  <path>`), `meta.json` (`head_sha`, `run_id`, `run_attempt`, and possibly `claimed_verdict`), `raw/...`, `guard.json`, `acceptance.json`.
- `--extras`, trusted, all optional: `rounds` (`[{"head_sha", "round", "cumulative"}]`), `human` (`[{"minutes"}]`), `merges` (`[{"pr", "merge_sha", "merged_by", "head_sha", "final_conclusion", "approvals", "via_pr"}]`), `resources` (`executor_runs`, `executor_turns`, `codex_runs`, `codex_tokens`, `actions_minutes`), `independent_review`, `semi_automatic_steps`.

**Mandatory steps in the `run` job:** `gate/env`, `gate/guard`, `gate/tests`, `gate/acceptance`, `gate/security`.

**`verdict.json`:** `{"verdict", "reasons": [{"code", "detail"}], "checks": {<check id>: "success"|"failure"}}`. The verdict is one of `ready-for-human`, `blocked`, `needs-human`, `incomplete`. The `checks` hold the five mandatory steps above and `gate/report`.

**The rules, by priority: the first group that applies gives the verdict.**

- **V-1 `blocked`, a contradiction:**
  - `FORK_PR`: `head_repository` differs from `repository`;
  - `SHA_MISMATCH`: `meta.json` gives another `head_sha`, `run_id` or `run_attempt` than the context;
  - `EXIT_CODE_MISMATCH`: a step's conclusion disagrees with its rows, a success with any non-zero row or a failure with all rows zero, or an `exit_code` that is not an integer;
  - `CHECKSUM_MISMATCH`: a file's SHA-256 differs from `SHA256SUMS`;
  - `CLAIM_MISMATCH`: `claimed_verdict` is `ready-for-human` while a mandatory step did not succeed.
- **V-2 `incomplete`:**
  - `UNFINISHED_STAGE`: a mandatory step is absent or not completed with a conclusion of `success` or `failure`, or the `run` job is absent or not completed;
  - `NO_ARTIFACT`: the artifact folder is missing;
  - `MISSING_OUTPUT`: `exit-codes.tsv` or `SHA256SUMS` or `meta.json` is missing, or a file named in `SHA256SUMS` is missing, or a mandatory step has no row.
- **V-3 `needs-human`:** `REPEATED_FIX` when `guard.json` says `repeated_fix`, or `ROUND_CAP` when a mandatory step failed and the distinct head SHAs in `rounds`, counting this one, minus one, reach `limits.max_fix_rounds`.
- **V-4 `blocked`:** `FAILED_CHECK`: a mandatory step's conclusion is `failure`.
- **V-5 `ready-for-human`:** none of the above.

- **V-6** A claim, a model's text or any other file in the artifact can never produce `ready-for-human` when the rules above do not.
- **V-7** `gate/report` in `checks` is `success` only when no `MISSING_OUTPUT`, `NO_ARTIFACT` or `UNFINISHED_STAGE` reason exists.
- **V-8** A diagnostic check that failed changes no verdict and is listed in the report with its numeric exit code.
- **V-9** `extras.env_failures`, a list of job names whose own `env_check` failed, adds `FAILED_CHECK` and makes `gate/env` a failure.
- **V-11 (decision X).** `extras.reports_untrusted` true adds `REPORTS_UNTRUSTED`, in the group of V-1: `blocked`.
- **V-10 A failed setup (decision U).** A step named `setup` in the `run` job with a conclusion of `failure` adds `FAILED_CHECK`, and a verdict that would be ready is `blocked`.

**`report.json`** validates against `gate/schema/report.schema.json` and holds:

- `verification`: every field of the context, with `trusted_sha` and `execution_environment` when the context gives them, otherwise `"unknown"`;
- `setup`: `{"conclusion", "exit_codes"}`, or `"not-configured"`;
- `needs_code_owner`, `marked_tests`, `security_review_changes`: from `guard.json`, or empty lists;
- `accepted_foreign_commits`: the list in the configuration (W-14), shown on every report;
- `independent_review`: from `extras`, or `"unknown"`;
- `environment`: from `environment.json` in the artifact, or `"unknown"`;
- `checks`: `[{"id", "class", "conclusion", "commands": [{"argv", "exit_code", "duration_seconds", "raw_path", "raw_sha256"}], "counts"}]`;
- `coverage`, `mutation`: from `raw/diag-coverage/summary.json` and `raw/diag-mutation/summary.json`, or `"unknown"`;
- `dependency_changes`, `findings`, `rounds`. `rounds` holds this run's own fingerprint from `guard.json`, when `extras.rounds` lacks its head;
- `resources`: every named cost, with `"unknown"` for one not given, never 0;
- `human`: `{"interventions", "minutes"}`;
- `bypass_merges`;
- `known_failing`: `{"size", "remove_from_list"}`, from `acceptance.json`, or `"unknown"`;
- `verdicts`: `{"preliminary", "final", "reasons"}`, with `final` as `null` here;
- `semi_automatic_steps`;
- `generated_at`.

**Bypass.** **B-1** A merge in `extras.merges` goes into `bypass_merges` when `via_pr` is false, or `approvals` is 0, or `final_conclusion` is not `success`, or `security_review_changed` is true: every change to `security-review.md` is flagged, approved or not (decision X).

**Markdown.** **M-1** `report.md` is rendered from the JSON only and obeys C-4 and C-5.

### 8.2 `final`

`python -P -m gate.report final --verdict FILE --archive FILE --out FILE [--facts FILE]`

Writes `{"verdict", "gate_verdict", "gate_reasons", "reasons", "conclusions": {"gate/archive", "gate/final"}, "final_check": {"status", "conclusion"}, "review": {"state", "code"}, "reviewer"}`, where `reviewer` is the reviewer's account `{"login", "id"}` as `--facts` gave it, or null (FN-9). `gate_reasons` are the reasons of the gate's own verdict alone, which finalize reads back (FN-4); `reasons` also hold the review's. F-1 to F-4 give the gate's own verdict, `gate_verdict`. The final verdict, `verdict`, and `gate/final` follow section 8.5 (round 2), which supersedes F-1 and F-3 where they would make the final verdict `ready-for-human` without the independent review.

- **F-1** The gate's own verdict is `ready-for-human` only when the preliminary verdict is `ready-for-human` and the archive result says `stored` and `sha256sums_match` are both true. The rules below speak of "the verdict": they set `gate_verdict`, and a `gate_verdict` that is not `ready-for-human` is also the final `verdict` (FN-2).
- **F-2** With the evidence not stored or a missing or unreadable archive result, a preliminary `ready-for-human` becomes `incomplete` with code `EVIDENCE_NOT_STORED`. Any other preliminary verdict stays as it is and gains that reason.
- **F-2a** A missing or unreadable preliminary verdict gives `incomplete`, code `NO_PRELIMINARY`. `--expect-verdict-sha256 VALUE` compares the verdict file with the hash the publish job gave through its job output, which a job that ran PR code cannot change: a difference, or an empty value, gives `blocked`, code `PUBLISH_OUTPUT_MISMATCH`. `--env-result FILE` with `ok` not true adds `FAILED_CHECK`, and a ready verdict becomes `blocked`.
- **F-1a** A preliminary verdict file whose own `checks` hold anything but `success` never becomes ready.
- **F-4** An archive result with `actors_ok` false makes `gate/archive` a failure, turns a ready verdict into `blocked`, and adds the code `REPORTS_WRITTEN_BY_ANOTHER_ACTOR`.
- **F-3** `gate/final` is completed `success` only for a final verdict of `ready-for-human`, in progress (no conclusion) only for `awaiting-review`, and completed `failure` for every other verdict, never `neutral` or `skipped`, because GitHub counts those as success. `gate/archive` is `success` only when the evidence was stored and matches.

### 8.3 `compare`

`python -P -m gate.report compare A B`

- **K-1** Exit 0 when the two reports are equal except for `generated_at`, `duration_seconds`, `raw_sha256`, `verification.run_id`, `verification.run_attempt`, `verification.execution_environment` and `environment`. Otherwise exit 1, naming each differing path. The raw hashes are excluded because the tools print their own times into the logs. The environment fields are excluded because a rerun runs in the pinned container by design.

### 8.4 `seal`

`python -P -m gate.report seal --artifact DIR --head-sha SHA --run-id R --run-attempt A`

- **Z-1** Copies `raw/gate-guard/guard.json` and `raw/gate-acceptance/acceptance.json` to the artifact's top level when present, writes `environment.json` and `meta.json`, and writes `SHA256SUMS` over every other file.

### 8.5 The final verdict after the independent review (round 2)

The customer's finding of 2026-11-10 (run `42751543290`): `gate/final` became `success` at 03:50:50Z, before the mandatory independent review at 03:59:45Z. These rules make the final verdict wait for that review, on the same commit. In this section, **the head** is the PR head SHA the judge ran on; **the reviewer** is the bot account of `[feedback] reviewer_app`: login `<reviewer_app>[bot]`, type `Bot`, and the account id that `GET /users/<reviewer_app>%5Bbot%5D` gives; **the mandatory checks** are the mandatory classes of Q-2 other than `gate/final`: `gate/env`, `gate/tests`, `gate/acceptance`, `gate/guard`, `gate/security`, `gate/report`, `gate/archive`; **the newest review** is the first status with `context` `independent-review` in the API's list of the head's statuses, which GitHub returns newest first.

- **FN-1 Ready only after the review, on one commit.** No step of the judge sets `gate/final` to `success`, and none writes `ready-for-human` as a final verdict, unless at that moment and on the same head: the stored archive of this run is complete (stored, its sums matching, `actors_ok`); each mandatory check's newest check run on the head, among the runs of the GitHub Actions app (`app.id` 15368, the app the ruleset requires), is completed with `success`; and the newest review has `state` `success` and was created by the reviewer (`creator.login`, `creator.id` and `creator.type` all match). The app id of the reviewer is not on a status, which names only the app's bot account; the ruleset checks the app id itself at merge. Nothing in a status's `description`, a comment or any other text counts.
- **FN-2 Waiting is not ready.** In the archive job, when the gate's own verdict is `ready-for-human` and the newest review is missing, pending, unreadable or not by the reviewer, `gate/final` is posted **in progress**, with no conclusion and the title `gate/final: waiting for the independent review on <head>`, and the final verdict is `awaiting-review`, with the reason `REVIEW_MISSING`, `REVIEW_PENDING`, `REVIEW_UNREADABLE` or `REVIEW_NOT_BY_REVIEWER`. When the gate's own verdict is not `ready-for-human`, it is the final verdict and `gate/final` is completed `failure`, as before: `blocked`, `incomplete` or `needs-human`.
- **FN-3 finalize.** `.github/workflows/finalize.yml` is a reusable workflow (`on: workflow_call`), called by a thin caller on `status` events in the application's repository (part B). It acts only for a status with `context` `independent-review` created by the reviewer (superseded by FN-9: whoever created it), and only when that status's SHA is the head of an open PR into the integration branch. It runs no PR code and reads no PR file: it checks out only the gate at its own commit and the default branch's configuration. Every field of the event is untrusted: it takes only `context`, `sha` (40 lowercase hex) and `id` (a positive integer), and reads the creator of that status from the API's list of the SHA's statuses, never from the event.
- **FN-4 What finalize reads and decides.** For that PR and SHA it reads: the newest stored judge run of the PR whose `context.json` has this `head_sha` (the largest run id, then attempt), on `reports`, only after the check of W-12 and W-14 (decision V.4: the same trusted read as the judge's); that run's `verdict.json` (the preliminary verdict) and `final.json` (the gate's own verdict and `gate/archive`); the check runs on the SHA; and the newest review on the SHA. Then: review `success` and everything else as FN-1 gives `gate/final` completed `success`, final verdict `ready-for-human`, summary `Final verdict: ready-for-human`; review `failure` or `error` gives completed `failure`, verdict `blocked`, reason `REVIEW_FAILED`; review `pending` gives no change: nothing is posted (superseded by FN-9: `pending` gives `gate/final` in progress); anything missing or unreadable is never `success`: an unreadable or missing review keeps `gate/final` in progress, with its reason; a missing or inconsistent record (`NO_RECORD`, `RECORD_INCONSISTENT`), untrusted reports (`REPORTS_UNTRUSTED`), or a mandatory check run that is missing or unreadable (`MISSING_CHECK`, `CHECKS_UNREADABLE`) gives completed `failure`, verdict `incomplete`; a mandatory check run that is completed with anything but `success` gives completed `failure`, verdict `blocked`, `FAILED_CHECK`. A gate's own verdict that is not `ready-for-human` stays the final verdict, completed `failure`, with `REVIEW_FAILED` added after a failed review.
- **FN-5 Other commits and other creators change nothing.** A status for a SHA that is not the head of an open PR into the integration branch posts nothing. A status created by anyone but the reviewer (a person's account, the executor's app, any other app) posts nothing (superseded by FN-9: such a status starts a decision for the newest review, which a status by anyone but the reviewer can never make `success`). In the archive job, statuses are read for the head only, so a review of another commit is never seen; and a newest review created by anyone but the reviewer counts as no review (`REVIEW_NOT_BY_REVIEWER`).
- **FN-6 finalize's permissions.** Its job has exactly `checks: write`, `contents: read` and `pull-requests: read`; the workflow's own block is empty. No `contents: write`, no `actions: write`, no secret: neither a `secrets:` input nor any `secrets.` reference. Its `concurrency` group holds the status's SHA and `cancel-in-progress` is `false`, so a run that may already have posted is never cancelled.
- **FN-7 The preliminary texts.** When the preliminary verdict is `ready-for-human`, the PR comment (`report.md`) and the summaries of the checks posted by `post-checks` (`gate/report` among them) never say `ready-for-human`. They say that the gate's checks passed and that the final verdict waits for the independent review. Another preliminary verdict is named as before.
- **FN-8 A review already there.** When a review of the head already exists as the archive job finishes, for example on a rerun, the archive job applies FN-1 and FN-4 itself: `success` gives `gate/final` completed `success` and the final verdict `ready-for-human`; `failure` or `error` gives `blocked`, `REVIEW_FAILED`.
- **FN-9 The newest review decides last** (finding M-1 of round 2's review round 1, repaired before the merge by the CEO's decision of 2026-11-10). A completed `success` `gate/final` is never the newest `gate/final` on a SHA whose newest review is not a `success` created by the reviewer, in any order of events. Three rules hold it:
  - **A re-read around every success.** Every path that would post `gate/final` completed `success` (`post-final` in the archive job, and finalize) reads the newest review on that SHA again from the API immediately before the post, and again immediately after it. Before: when the newest review is not a `success` by the reviewer, it posts instead `gate/final` completed `failure`, verdict `blocked`, reason `REVIEW_FAILED` (a `failure` or `error` by the reviewer), or in progress with the title and summary of FN-2, verdict `awaiting-review`, reason `REVIEW_PENDING`, `REVIEW_MISSING`, `REVIEW_NOT_BY_REVIEWER` or `REVIEW_UNREADABLE` (anything else, an unreadable read among them); never `success`. After: when the newest review is then no longer a `success` by the reviewer, it posts the same `failure` or in-progress `gate/final` after its `success`, so that the `success` is not the newest. The archive job's `post-final` takes the reviewer's account from `final.json`'s `reviewer`, as `final-facts` read it (FN-8); without it the re-read finds no valid review, and nothing is `success`.
  - **finalize decides on the newest review, never on the status that started it.** Once the event's fields are valid (FN-3), the API holds that status with `context` `independent-review`, and the SHA is the head of an open PR into the integration branch, finalize decides by FN-4 on the newest review it reads, whoever created the status that started it. This supersedes FN-3's "created by the reviewer" and FN-5's "a status created by anyone but the reviewer posts nothing": such a status starts a decision for the newest review, and a newest review that is not the reviewer's is `REVIEW_NOT_BY_REVIEWER`, in progress, never `success`.
  - **A pending review is waiting, in finalize too.** A newest review that is `pending` gives `gate/final` in progress, verdict `awaiting-review`, `REVIEW_PENDING`, as FN-2 gives it in the archive job; a gate's own verdict that is not `ready-for-human` stays, completed `failure`. This supersedes FN-4's "review `pending` gives no change: nothing is posted", which let an earlier `success` stay newest.

  So the last finalize run to run posts the decision for the newest review, and no queued run is needed: a waiting run that GitHub's concurrency rule replaces (L18) is covered by the run that replaced it, which decides on the same or a newer review, and by the re-read after an earlier run's `success`. What FN-9 does not cover is in LIMITATIONS.md L53.

**One decision.** The rules live in one function, `gate.report.final_decision`, which both the archive job (`gate.report final`) and finalize (`gate.publish finalize`) call: `final_decision(mode=, head_sha=, gate_verdict=, gate_reasons=, archive_ok=, check_runs=, statuses=, reviewer=, own_checks=None)`, with `mode` `archive` or `finalize`, `check_runs` and `statuses` as the API returns them or `None` when unreadable, `reviewer` `{"login", "id"}` or `None`, and `own_checks` the archive job's own `gate/archive`. It returns `{"post", "status", "conclusion", "verdict", "reasons", "review": {"state", "code"}}`. Its order: in `finalize`, a pending review posts nothing (superseded by FN-9: `mode` no longer changes the decision, and `post` is always true; both stay so that callers and records keep their shape); a missing record is `incomplete`; a gate's own verdict that is not ready stays; a failed review is `blocked`; a successful review needs every mandatory check (FN-1); otherwise `gate/final` is in progress.

**The commands.**

- `python -P -m gate.publish final-facts --head-sha SHA --config FILE --out FILE` reads, with the token in `GATE_TOKEN`: the SHA's statuses (`GET /repos/{repo}/commits/{sha}/statuses`, every page), its check runs (`GET /repos/{repo}/commits/{sha}/check-runs?filter=all`, every page, key `check_runs`) and the reviewer's account (`GET /users/<reviewer_app>%5Bbot%5D`, `login`, `id`, `type`). It writes `{"head_sha", "statuses", "check_runs", "reviewer"}`, each part `null` when its read failed or, for the reviewer, when the answer is not that login with type `Bot` and a positive integer id. Exit 0 whatever it read; exit 2 for a SHA that is not 40 lowercase hex.
- `gate.report final --facts FILE` gives the facts to `final_decision` in mode `archive`, with `own_checks` `{"gate/archive": <this job's gate/archive>}`. Without `--facts`, or with a file that is missing or unreadable, every fact is unreadable.
- `gate.publish post-final --final FILE --head-sha SHA` posts `gate/archive` completed with its conclusion, then `gate/final` as `final_check` says: completed with its conclusion, the title `gate/final: <conclusion>` and the summary `Final verdict: <verdict>` with the reasons; or in progress with no conclusion, the title of FN-2 and a summary that says the checks passed and the final verdict waits for the independent review. A file with no readable `final_check` posts `gate/final` completed `failure`, with the reason `NO_FINAL_CHECK`: never `success`. A completed `success` is posted only through FN-9's re-read before and after it (`GET /repos/{repo}/commits/{sha}/statuses`, every page), with the reviewer's account taken from the file's `reviewer`.
- `python -P -m gate.publish finalize --event FILE --config FILE --reports-dir DIR --actors FILE --out FILE` makes FN-3 to FN-5. It writes `{"acted", "code", "pr", "sha", "decision"}`, where `code` is null when it decided, or one of `IGNORED_CONTEXT`, `IGNORED_SHA`, `IGNORED_EVENT` and `NOT_A_PR_HEAD` when it posts nothing by FN-3 and FN-5 (`IGNORED_CREATOR` is gone: FN-9). A `success` it decides is posted only through FN-9's re-read before and after it. A read it needs before it may decide (the reviewer's account, the SHA's statuses, the open PRs) that fails posts nothing, writes the code `READ_FAILED` and exits 1; a failed post exits 1; otherwise exit 0. The stored run's gate verdict and reasons come from `final.json`'s `gate_verdict` and `gate_reasons`. A missing `--reports-dir` folder or an unreadable `--actors` file is untrusted reports (FN-4), never a pass.
- `gate.feedback decide` (section 10) reads a stored final verdict of `awaiting-review` as `NOT_A_FAILURE`: the gate's own checks did not fail, and the review's own comment still starts its fix round.

## 8a. `gate.diag_summary`

`python -P -m gate.diag_summary coverage --coverage-json FILE --repo DIR --base SHA --head SHA --out FILE`, and `python -P -m gate.diag_summary mutation --results FILE --out FILE`, write the summaries that `report` reads. Diagnostic only. A share of nothing is `"unknown"`, never 0.

## 8a-bis. `gate.publish`

The GitHub side of the judge: `context`, `jobs`, `extras`, `post-checks`, `post-final`, `final-facts`, `finalize`, `comment`, `pulls`, `limits`, `hide-paths`. It reads its token from `GATE_TOKEN` and prints only the kind of a failure, never a token. `final-facts`, `finalize` and the new behaviour of `post-final` and `post-checks` are in section 8.5.

- **P-1** `extras` counts `/time <minutes>` comments only from the repository's owner, and an approval only on the merged head.
- **P-3 (decision X)** `extras` requires `--actors`. When they are not `actors_ok`, it reads no stored run and sets `reports_untrusted`.
- **P-4 (F9)** `create-pull-request --branch NAME --prefix TEXT --base BRANCH` opens a PR for the branch the model ended on, the one in the working tree. A name without the prefix, or a branch not on the remote, exits 1.
- **P-5 (F10)** A refused read of a commit's statuses gives `independent_review` `"unknown"` in `extras`, and an empty list in `review-statuses`. It blocks nothing by itself.
- **P-6 (W.2)** `post-proposal --file FILE --branch NAME` posts the model's proposed security entry, neutralized, on its open PR. A missing or empty file does nothing.
- **P-6a** The model chooses what is at that path and the step holds a token. So a symbolic link, a file with a second name or anything but a plain file exits 2 and posts nothing, and it is never followed. A text holding the value of `GATE_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN` or `EXECUTOR_APP_PRIVATE_KEY`, or anything shaped like a GitHub token, an Anthropic key or a private key, exits 1 and posts nothing.
- **P-2** `hide-paths` takes `spec_tests.deny_read` out of the working folder with a sparse checkout, so that they do not show as deleted. An empty list exits 2.

## 8b. `gate.reproduce`

`python -P -m gate.reproduce --repo URL --sha SHA --out DIR`

- **X-0 (decision X)** On a GitHub remote, in any URL form (`https`, `ssh`, `git@`, in any letter case), or with `--api-repo`, it makes the check of W-12 and W-14 before it reads the stored evidence. Any foreign commit, a failed read, or an API that does not show the branch git has read exits 1 with `REPORTS_UNTRUSTED`. "Does not show" means the API has no such branch, or the commit git read is not among the commits the API lists. A newer commit on the API's side is no failure, because a report may be stored meanwhile and its authors are checked too. On another remote the authors cannot be checked, and it says so.
- **X-0b** `gate.reproduce` takes no secrets, because a rerun runs PR code under the same user, which can read this process. A non-empty variable whose name holds a word of E-2 exits 2 before anything runs, and the message names the variables and holds no value. `make reproduce` passes no token into the container. A private repository cannot be rerun with this command.
- **X-0a (C-3)** A credential in `--repo` exits 2 before anything runs, and the message holds no value: a password or a query in any URL, or a user name in any URL but `ssh`. `git@host:path` and `ssh://git@host/path` hold no credential.
- **X-1** It takes the stored context and extras of the newest attempt for the SHA, the configuration and acceptance tests at that run's `trusted_sha`, and only the runs stored before that attempt.
- **X-2** It reruns the mandatory checks of the `run` job, seals, regenerates the report and compares it with the stored one by K-1. Exit 0 when equal, 1 when not, 2 when no evidence is stored for the SHA.

## 9. `gate.archive`

`python -P -m gate.archive store (--remote URL | --api-repo OWNER/NAME) --branch reports --pr N --run-id R --attempt A --artifact DIR --publish DIR --context FILE --out FILE [--max-bytes N] [--config FILE]`

Stores `reports/<pr>/<run_id>-<attempt>/` on the branch: `context.json`, the files of `--publish`, the artifact under `artifact/`, and `SHA256SUMS` over all of them as `<sha256>  <relative path>`, readable by `sha256sum -c`. For later runs `guard.json` and `acceptance.json` are also stored at the top of the attempt's folder, from the artifact, when present.

`--out` writes `{"stored", "sha256sums_match", "path", "commit", "reason", "artifact_present", "skipped_unsafe", "actors_ok"}`, and `foreign_commits` when some exist. The exit code is 0 when stored, matching and `actors_ok`, otherwise 1.

`--remote` is a plain git remote, such as a local bare repository. `--api-repo` writes to GitHub through the API at `GITHUB_API_URL`, with the token in `GATE_TOKEN`:

| Purpose | Route |
|---|---|
| The branch's head | `GET /repos/{repo}/git/ref/heads/{branch}`: `object.sha`. A 404 means the branch does not exist |
| The files | `GET /repos/{repo}/git/trees/{commit}?recursive=1`: `sha` of the tree, `tree[].path`, `type`, `sha`, and `truncated`, which is an error when true |
| Write a file | `POST /repos/{repo}/git/blobs`: `content` in base64, `encoding`: `sha` |
| Write a tree | `POST /repos/{repo}/git/trees`: `tree[]` of `path`, `mode`, `type`, `sha`, and, when the branch exists, `base_tree`, the SHA of its head's tree: `sha` |
| Write a commit | `POST /repos/{repo}/git/commits`: exactly `message`, `tree`, `parents`: `sha` |
| Move the branch | `PATCH /repos/{repo}/git/refs/heads/{branch}`: `sha`, `force` false. For a new branch, `POST /repos/{repo}/git/refs`: `ref`, `sha`. A 409 or 422 means it moved |
| Read a file | `GET /repos/{repo}/git/blobs/{sha}`: `content` in base64 |
| The commits | `GET /repos/{repo}/commits?sha={branch}&per_page=100&page={n}`: `sha`, `author.login`, `commit.verification.verified` |
| One commit | `GET /repos/{repo}/commits/{sha}?per_page=100&page={n}`: `parents`, `files[].filename`, `files[].status` |

- **W-1** The branch is created, with no parent, when missing.
- **W-2** A missing artifact folder still stores the rest, with `artifact_present` false. This is the cancelled run.
- **W-3 Append only.** When the attempt's folder already exists, nothing changes and the result has `stored` false, reason `ALREADY_EXISTS`.
- **W-4** It never force-pushes. On a refused push it fetches and retries, up to 5 times. Two runs at once both end stored.
- **W-5 Read-back.** After the push it reads the branch again from the remote and recomputes every SHA-256. `sha256sums_match` is true only when all agree.
- **W-6 Untrusted artifact.** Symbolic links and anything under a `.git` folder are not stored and are listed in `skipped_unsafe`. Everything else is stored byte for byte, a `.gitignore` or a `.gitattributes` included, and neither changes how another file is stored.
- **W-7** An artifact larger than `--max-bytes` (default 200,000,000) is not stored: `stored` false, reason `TOO_LARGE`.
- **W-8** Earlier attempts are never changed.
- **W-11** A `--remote` on `github.com` exits 2. A `git push` would leave the commits unsigned, so GitHub is written only with `--api-repo`.
- **W-12 Another actor (HQ's addition to decision R).** The executor's app has Contents write, and the ruleset blocks only force pushes and deletion. With `--api-repo`, after each write every commit on the branch must have `author.login` `github-actions[bot]` and `commit.verification.verified` true. Otherwise `actors_ok` is false, `reason` is `reports written by another actor`, `foreign_commits` lists them, and the exit code is 1. The evidence stays stored. When the commits cannot be read, `actors_ok` is also false.
- **W-13** A commit body holds no author, committer or signature: GitHub signs a commit only without them.
- **W-14 Recovery (decision V).** A foreign commit whose full SHA is in `[[archive.accepted_foreign_commits]]` of the file given by `--config` is accepted only when it has one parent and every file in it has status `added` and a name under `reports/`. A commit that changes or deletes a record stays foreign even when listed. An entry without a full SHA, a reason and a date is ignored. No history is rewritten. Accepted commits go into `accepted_commits` in the result. The workflow gives the configuration from the default branch, and the list changes only through the CEO's maintenance PR.
- **W-15** `python -P -m gate.archive check-actors --api-repo OWNER/NAME --branch reports [--config FILE] --out FILE` makes only the check of W-12 and W-14, and writes `{"actors_ok", "foreign_commits", "accepted_commits", "reason"}`. Exit 0 when `actors_ok`, otherwise 1. A branch that does not exist yet is `actors_ok` true.

`python -P -m gate.archive append (--remote URL | --api-repo OWNER/NAME) --branch reports --path RELPATH --file FILE --out FILE` adds one file that does not yet exist to a stored folder, with a read-back, and writes the same result. `RELPATH` is the new file's own path from the branch's root, for example `reports/7/1001-1/final.json`. An existing file gives `stored` false, reason `ALREADY_EXISTS`.

## 10. `gate.feedback` (decisions N and R)

`python -P -m gate.feedback decide --event-name NAME --event FILE --pulls FILE --reports-dir DIR --actors FILE --config FILE --out FILE [--statuses FILE] [--integration-branch candidate/a]`

The events are `workflow_run` and `issue_comment`. Any other event exits 2, `status` included. A missing `--reports-dir` folder exits 2: a lost read must never look like "no earlier rounds".

`--pulls`, trusted, lists open PRs: `[{"number", "head_sha", "base_ref", "head_ref", "head_repository", "repository"}]`. `--actors`, trusted, is the result of `gate.archive check-actors`. `--statuses`, trusted, is the API's list of the commit's statuses, newest first: `[{"context", "state", "creator": {"login"}}]`.

Writes `{"act", "post", "pr", "head_sha", "round", "reason_code", "comment"}`. Exit 0 whether it acts or not. `act` is true only with `reason_code` null. `post` says whether the comment goes on the PR.

**`workflow_run` events.** In this order:

- `workflow_run.path` must equal `feedback.judge_workflow_path` and `workflow_run.event` must be `pull_request_target`, otherwise `UNEXPECTED_SENDER`.
- D-0 holds.
- `workflow_run.conclusion` of `cancelled` gives `NOT_ACTIONABLE`.
- The record is the one folder at `<reports-dir>/*/<workflow_run.id>-<workflow_run.run_attempt>/`: `context.json` gives `pr` and `head_sha`, `final.json` gives the verdict. No such folder, more than one, a `pr` that is not its folder's name, or a missing file gives `NO_RECORD`.
- `blocked` goes on. `ready-for-human` and `awaiting-review` (section 8.5) give `NOT_A_FAILURE`, `needs-human` gives `NEEDS_HUMAN`, and any other verdict gives `NOT_ACTIONABLE`: a cancelled or lost run starts no model.

**`issue_comment` events (decision R).** In this order:

- `action` must be `created` and `issue.pull_request` must be present, otherwise `NOT_A_REVIEW`.
- `sender.login` must be `<feedback.reviewer_app>[bot]`, otherwise `UNEXPECTED_SENDER`. The sender decides, never the comment's text.
- D-0 holds.
- The comment's body must hold the marker `<!-- gate-review sha=<40 hex> verdict=<pass|changes_requested> -->`, otherwise `NO_MARKER`. Its SHA is the head. A verdict of `pass` gives `NOT_A_FAILURE`.
- In `--statuses`, the newest status with `context` `independent-review` must have `state` `failure`, otherwise `STATUS_NOT_FAILURE`, and `creator.login` `<feedback.reviewer_app>[bot]`, otherwise `STATUS_WRONG_CREATOR`. A verdict in the comment alone starts nothing.
- For a comment event, D-1 also requires that the listed PR with this head is `issue.number`.

**D-0 (decision V).** `--actors` must say `actors_ok` true. Otherwise, or when it is missing or unreadable, the reason is `REPORTS_UNTRUSTED`: stored evidence is not read.

**Both events, in this order:**

- **D-1** `head_sha` must be the head of a listed PR, otherwise `SHA_NOT_CURRENT_HEAD`.
- **D-2** That PR's `base_ref` must be the integration branch, otherwise `PR_NOT_INTO_INTEGRATION`.
- **D-2a** Its `head_repository` must equal its `repository`, otherwise `FORK_PR`. Its `head_ref` must start with `ai/`, otherwise `NOT_AN_EXECUTOR_PR`: a fix round never touches a spec or a maintenance PR.
- **D-3** Done fix rounds are the distinct `head_sha` values in `<reports-dir>/<pr>/*/context.json`, minus one. At or past `limits.max_fix_rounds` gives `ROUND_CAP`.
- **D-4** A stored `guard.json` for this head with `repeated_fix` true gives `REPEATED_FIX`.
- **D-5** Otherwise `act` is true and `round` is the done rounds plus one.
- **D-6a (F4)** When it acts, `comment` holds what is wrong, because the model has no other way to read it. For `workflow_run`: the verdict's reasons, and from the record `guard.json`'s violations, `acceptance.json`'s `failing_not_listed` and `missing_tests`, `artifact/raw/gate-security/security.json`'s unreviewed findings, and `artifact/raw/gate-tests/missing_tests.json`. For `issue_comment`: the lines of the reviewer's comment. At most 60 lines of them.
- **D-6** `comment` always says what happened and why, in plain text, obeys C-4 and C-5, and writes the mention as `` `@claude` ``.
- **D-7** `post` is true, so that the PR is told why, except for `NOT_A_FAILURE`, `NOT_A_REVIEW` and `UNEXPECTED_SENDER`. Anyone can comment on a public repository, and the gate must not answer each one.

`python -P -m gate.feedback outputs --decision FILE --config FILE --output FILE --note FILE` hands a decision to the workflow: `act`, `post`, `pr`, `head-ref`, `allowed-bots`.

- **D-8** It refuses, with exit 2, a branch name or an app name that holds anything outside letters, digits and `._/-`, and a PR that is not a positive integer. These values reach expressions.

## 11. `gate.review_local`

`python -P -m gate.review_local --repo OWNER/NAME --pr N --sha SHA --issue N [--codex "COMMAND"] [--api-url URL] --out FILE`

Environment: `REVIEWER_APP_ID`, `REVIEWER_APP_INSTALLATION_ID`, `REVIEWER_APP_PRIVATE_KEY_PATH`. The operator sets them in their own window. The key file's content is read only to sign the app's token.

Routes it uses:

| Purpose | Route |
|---|---|
| App token | `POST /app/installations/{id}/access_tokens`, bearer a signed RS256 JWT with `iss` the app ID |
| PR | `GET /repos/{repo}/pulls/{n}`: `head.sha`, `state`, `base.ref` |
| Diff | `GET /repos/{repo}/pulls/{n}` with `Accept: application/vnd.github.v3.diff` |
| Spec | `GET /repos/{repo}/contents/SPEC.md?ref={sha}` with `Accept: application/vnd.github.raw+json` |
| Issue | `GET /repos/{repo}/issues/{n}`: `title`, `body` |
| Judge's report | `GET /repos/{repo}/git/trees/reports?recursive=1`, then the newest `reports/{pr}/{run_id}-{attempt}/report.json` with `verification.head_sha` equal to the SHA, through `GET /repos/{repo}/contents/{path}?ref=reports` with the raw `Accept` |
| Status | `POST /repos/{repo}/statuses/{sha}`: `state`, `context`, `description` |
| Comment | `POST /repos/{repo}/issues/{pr}/comments`: `body` |

- **L-1** The model gets only `SPEC.md`, the issue, the diff and the judge's report, on stdin, in an empty temporary folder. Its environment holds only these variables, when set: `PATH`, `PATHEXT`, `SYSTEMROOT`, `SYSTEMDRIVE`, `WINDIR`, `COMSPEC`, `TEMP`, `TMP`, `TMPDIR`, `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `CODEX_HOME`, `LANG`, `LC_ALL`.
- **L-1a (decision V)** Before it reads the judge's report, it makes the check of W-12 and W-14 on the `reports` branch, with the list from `GET /repos/{repo}/contents/quality.toml` with the raw `Accept` on the default branch (a 404 means no list). Any foreign commit, or a failed read, runs no model, posts nothing and exits 1, code `REPORTS_UNTRUSTED`.
- **L-2** The default command is `codex exec --sandbox read-only --skip-git-repo-check --ephemeral --ignore-user-config --ignore-rules --output-schema <file> -o <file> -`. `--codex "COMMAND"` replaces the program. The arguments `--output-schema <file>` and `-o <file>` are always passed. The result is the JSON written to the `-o` file: `{"verdict": "pass"|"changes_requested", "findings": [{"severity", "where", "what"}]}`.
- **L-3** `pass` posts `success`, and `changes_requested` posts `failure`, with `context` `independent-review` on exactly `--sha`. **The status is posted first, then the comment (decision R)**: the comment can start a fix round, which checks the status. The comment carries the findings, obeys C-4 and C-5, and holds the marker `<!-- gate-review sha=<the SHA> verdict=<the verdict> -->`.
- **L-4** When `--sha` is not the PR's head, before the model or again just before posting, nothing is posted and the exit code is 1, code `HEAD_MOVED`.
- **L-5** A model result that is missing, is not valid JSON, or has another verdict posts nothing and exits 1, code `MODEL_OUTPUT_INVALID`. The gate then stays blocked: it fails closed.
- **L-6** A missing part of the input, the judge's report included, runs no model, posts nothing and exits 1, code `MISSING_INPUT`.
- **L-7** A missing key path or an unreadable key exits 2 and prints the variable's name, never its content. The key never reaches a log, the `--out` file or the model.
- **L-8** `--out` writes `{"posted", "state", "code", "sha"}`.

## 12. Workflows (checked from their YAML)

- **Y-1** These four are `on: workflow_call`: `judge.yml`, `executor.yml`, `spec-tests.yml`, `feedback.yml`. Runners are exactly `ubuntu-24.04`, in every workflow.
- **Y-2** Every `uses:` of an action is `owner/name@<40 hex>`, and each is in `ACTIONS-LOCK.md`.
- **Y-3 Exact permissions in `judge.yml`.** `run`: `contents: read`. `publish`: `checks: write`, `pull-requests: write`, `actions: read`, `contents: read`. `archive`: `contents: write`, `checks: write`. These three permissions beyond the original table are amendment AA-01.
- **Y-4** No workflow or job grants `actions: write`, or `permissions: write-all`.
- **Y-5** `publish` has `needs: run` and `if: always()`. `archive` has `needs: [run, publish]` and `if: always()`.
- **Y-6** `judge.yml` uses no `secrets.*`, and it declares no `secrets:` input.
- **Y-7** In `run`, the checkout of the PR head has `persist-credentials: false`. Each check is its own step, named exactly after its check ID, with `if: ${{ !cancelled() }}` and without `continue-on-error`. `gate/env` and `gate/guard` come before any step that runs PR code. The `run` job does not run for a fork.
- **Y-8** No `run:` script holds `${{ github.event` or `${{ inputs.`: such values go through `env:`.
- **Y-9** The artifact upload has `retention-days: 30` and `if: ${{ always() }}`.
- **Y-10** In `executor.yml` the app token comes from `actions/create-github-app-token`, and `claude-code-action` takes it as `github_token`. `claude_args` holds `--max-turns`. The job has `timeout-minutes`.
- **Y-11** In `spec-tests.yml` the action's settings hold `permissions.deny` built from `spec_tests.deny_read`, for the read tools. The paths in `deny_read` are also removed from the working folder before the model starts.
- **Y-12** In `feedback.yml` secrets are referenced only in the job that runs the executor. The decision job comes first and the executor job runs only when it says `act`. Its permissions are `contents: read` and `pull-requests: write`, and nothing more.
- **Y-13 Self-test (decision T).** `self-test.yml` runs on `push` and `pull_request`, has `contents: read` and no secrets, and runs `make check` and actionlint, on Python given as an exact version, through `actions/setup-python` at a full SHA.
- **Y-14** In `judge.yml`, `gate.archive` is called with `--api-repo`, never `--remote`.
- **Y-16 (decision W)** In `judge.yml`'s `run` job, before any step that runs PR code and after `gate/guard`, the PR's `security-review.md` is replaced by the default branch's, or removed when that has none.
- **Y-17** In `executor.yml` and `spec-tests.yml`, the step that runs the action has `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "1"` in its `env`, and its allowed tools hold no `gh`. A later step, with the app's token, opens the PR: the model only pushes its branch.
- **Y-18** In `executor.yml` and `spec-tests.yml`, the prompt file comes from the default branch's copy, never from the PR's branch, and the gate's note and the issue's text are kept outside the working folder.
- **Y-19** In `judge.yml`, the guard gets the PR's author from the trusted context, and no label sets a requirement. As with every check, the `gate/guard` step runs `gate.run_checks`, so that its exit code is recorded, here with the gate's own `gate/builtin_checks.toml`. That file's guard command passes `--author {env:GATE_PR_AUTHOR}`, and the workflow's `env` sets `GATE_PR_AUTHOR` from `github.event.pull_request.user.login`.
- **Y-20** In `judge.yml`, the `archive` job installs nothing: it runs on the standard library alone.
- **Y-21** `feedback.yml`'s `fix` job has a `concurrency` group per PR, and `executor.yml` refuses to start the model when `expected-head` is given and the PR's head has moved.
- **Y-22 (decision X)** In `judge.yml`'s `run` and `publish` jobs, the stored runs are fetched only after `gate.archive check-actors` said they can be trusted. In `spec-tests.yml`, the default branch's copy is removed before the model starts.
- **Y-15** `executor.yml` passes its `allowed-bots` input to the action's `allowed_bots`. At this action's pin, a bot's event is refused without it. It holds named apps, never `*`.
- **Y-23 (FN-3, FN-6) `finalize.yml`.** It is `on: workflow_call` only, with a `config-path` input. Its one job runs on `ubuntu-24.04`, only for a `status` event with `context` `independent-review` (an `if:`, which the script checks again), with the permissions and the concurrency of FN-6. Its checkouts are the gate at `job.workflow_sha` and the default branch's configuration, each with `persist-credentials: false`, and none names the event's SHA or any PR ref. It runs `gate.archive check-actors` before it fetches the stored runs, then `gate.publish finalize`. No `run:` script holds `${{ github.event` or `${{ inputs.`, and every action is pinned and in `ACTIONS-LOCK.md`, as Y-2 and Y-8 say for every workflow.
- **Y-24 (FN-2, FN-8)** In `judge.yml`'s `archive` job, after `gate.archive store` and before the first `gate.report final`, `gate.publish final-facts` reads the facts for `GATE_HEAD_SHA`, and both calls of `gate.report final` take them with `--facts`.
