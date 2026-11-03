# Script contracts

The numbered rules every script must meet. Tests are written from this file and from the design, not from the code. A rule that a test cannot check from outside says so.

The pipeline names no application. Everything application-specific comes from `quality.toml` in the repository being judged.

## 0. Common rules

- **C-1 Entrance.** Each script is a module run as `python -P -m gate.<name>` with `PYTHONPATH` set to this repository's root. `-P` keeps the working directory off `sys.path`, so a judged repository cannot shadow the module.
- **C-2 Exit codes.** `0` success. `1` a rule failed. `2` a usage or configuration error. An expected failure prints a short message and no traceback.
- **C-3 Secrets.** No script prints, logs or writes the value of a secret, in any output file or message, including when the value is malformed.
- **C-4 Untrusted text.** Anything read from an artifact, a diff, a model or a comment is data. It never changes a verdict except through the checks named here. When it is posted, every `@word` from it appears inside backticks.
- **C-5 Mention.** Anything the gate posts writes `@claude` only in backticks.
- **C-6 Python.** Python 3.13. Standard library, plus `jsonschema` in `report` and `cryptography` in `review_local`.

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
- **E-3 Permissions.** For `run`, `publish`, `archive` and `feedback`, permissions are probed against the API at `GITHUB_API_URL`, for `GITHUB_REPOSITORY`, with the token in `GATE_PROBE_TOKEN`. A write probe sends the body `{}`, which is invalid on purpose and so changes nothing: status 422 means the write is allowed, 403 means it is denied. A read probe expects 200.

  | Permission | Probe |
  |---|---|
  | `checks` write | `POST /repos/{repo}/check-runs` |
  | `contents` write | `POST /repos/{repo}/git/refs` |
  | `pull-requests` write | `POST /repos/{repo}/pulls` |
  | `actions` read | `GET /repos/{repo}/actions/runs?per_page=1` |
  | `contents` read | `GET /repos/{repo}` |

  | Role | Must be allowed | Write must be denied |
  |---|---|---|
  | `run` | contents read | contents, checks, pull-requests |
  | `publish` | checks write, pull-requests write, actions read, contents read | contents |
  | `archive` | contents write, checks write | pull-requests |
  | `feedback` | pull-requests write, contents read | contents, checks |

  Items are named `permission:<name>:<allowed|denied>`. Any other status, or no token, or a network error, is broken: never a pass.
- **E-4 Environment.** When `[environment]` is set, items `environment:python` and `environment:image_os` compare the values. A mismatch names both the expected and the found value.
- **E-4a** The role `reproduce` is for a rerun in the pinned container: it runs E-2, and of E-4 only `environment:python`.
- **E-5 Names, never values.** Each broken item names the broken part. No value of any variable appears in stdout, stderr or `--out`, for any role.

## 3. `gate.run_checks`

`python -P -m gate.run_checks --config quality.toml --check ID --out DIR [--workdir DIR]`

Runs every command of one check, in order, in the working directory.

- **R-1** Each command's stdout and stderr go to `DIR/raw/<slug>/<index>.log`. The slug is the check ID with `/` replaced by `-`. The index starts at 0.
- **R-2** Each command appends one row to `DIR/exit-codes.tsv`, which starts with the header `check	index	exit_code	duration_seconds	raw_path	argv_json`. `exit_code` is the numeric exit code.
- **R-3** Every command runs even when an earlier one failed. The script's own exit code is the first non-zero exit code of the commands, or 0.
- **R-4** A command not found records 127. A command past `timeout_seconds` is killed and records 124. Neither is a pass.
- **R-5** A check with `junit` set reads that file from its raw folder, relative to it, and writes `counts.json` there with `tests`, `failures`, `errors`, `skipped`. A missing or unparsable file is a failure. With `forbid_skips`, `skipped > 0` is a failure. Such a failure appends a row with index `post` and exit code 1, and the script exits non-zero.
- **R-6** `required_outputs` are relative to the raw folder. A missing one appends a row with index `post` and exit code 1, and the script exits non-zero.
- **R-7** An unknown check ID, or a configuration refused by Q-2, exits 2.
- **R-8** Rows are appended, never rewritten: running two checks leaves both.
- **R-9** `argv_json` holds the command as configured, with its placeholders, so that a rerun on another machine records the same text.
- **R-10** With `--if-configured`, a check that is not configured exits 0 and records nothing.

## 4. `gate.acceptance` (decision O)

`python -P -m gate.acceptance --junit FILE --known-failing FILE [--mode subset|exact] [--require-empty] --out FILE`

The test ID is `<classname>::<name>` from the JUnit file. The list holds one entry per line: `<test id> <map id>`. Blank lines and lines starting with `#` are ignored. A map ID is `PUB-<2 digits>`, `SPEC-6.1`, `SPEC-6.2` or `DEF-<letters, digits, dashes>`. A missing list file is an empty list.

`--out` writes `{"ok", "mode", "list_size", "failing_not_listed", "listed_failing", "remove_from_list", "missing_listed", "passed", "reason_codes"}`, with sorted lists.

- **A-1** A listed test that fails does not fail the check. A failing or erroring test not on the list does, code `FAILING_NOT_LISTED`.
- **A-2** A skipped test not on the list counts as failing.
- **A-3** A listed test that passes goes into `remove_from_list` and does not fail the check in `subset` mode, the default.
- **A-4** A listed test absent from the JUnit file fails the check, code `MISSING_LISTED`. A JUnit file with no test cases fails, code `NO_TESTS`.
- **A-5** In `exact` mode, used on `spec/*` PRs, the failing set must equal the list. A listed test that passes fails the check, code `LIST_NOT_EXACT`.
- **A-6** With `--require-empty`, a non-empty list fails, code `LIST_NOT_EMPTY`.
- **A-7** An entry without a valid map ID, a duplicate entry or an unreadable JUnit file exits 2.
- **A-8** `list_size` and `remove_from_list` are always written.
- **A-9** A command after `--` runs first, and its exit code goes into `test_command_exit_code`. Exit codes 0, 1 and 5 are what pytest gives for passed, failed and no tests; any other fails the check, code `TEST_COMMAND_ERROR`. This keeps one exit code for the check: a listed failure makes pytest exit 1 and must not turn the check red.
- **A-10** `GATE_REQUIRE_EMPTY=1` in the environment acts as `--require-empty`. The workflow sets it from a trusted label on the final PR.

## 5. `gate.guard`

`python -P -m gate.guard --repo DIR --base SHA --head SHA --branch REF --config FILE --out FILE [--reports-dir DIR] [--pr N]`

Reads git objects only and runs no code from the repository. It compares the merge base of `--base` and `--head` with `--head`, with renames shown as a delete and an add.

`--out` writes `{"kind", "head_sha", "violations": [{"rule", "path", "detail"}], "needs_code_owner": [path], "dependency_changes": [{"name", "old", "new", "changelog"}], "fingerprint": {"round", "cumulative"}, "repeated_fix"}`.

Exit 1 when `violations` is non-empty, otherwise 0. `kind` is `ai` for a branch starting `ai/`, `spec` for `spec/`, and `other` for anything else.

**Rules for `ai` PRs:**

- **G-1 `PROTECTED_PATH`.** Touching any of these, added, changed or deleted, in any letter case: `.github/`, `acceptance/`, `quality.toml`, `CODEOWNERS`, `SPEC.md`, `TASK.md`, `BASELINE.md`, `OPEN-ISSUES.md`, `SOURCE-MANIFEST.json`, `evidence/`, and everything in `guard.extra_protected`. A renamed file is checked under both names.
- **G-2 `TEST_DELETED`.** A test file (`test_*.py`, `*_test.py`, or any `.py` under a `tests/` folder) deleted, or a `test_*` function present in the base and absent in the head.
- **G-3 `TEST_SKIPPED`.** A `test_*` function present in the base that gains `pytest.mark.skip`, `pytest.mark.skipif`, `pytest.mark.xfail`, `unittest.skip`, a `pytest.skip(` call or a `pytest.xfail(` call. A reason line does not excuse this.
- **G-4 `TEST_WEAKENED`.** A `test_*` function present in the base whose count of checks drops, or that gains an always-true assert (`assert True`, `assert 1`) or a `pytest.raises(Exception)`. A check is an `assert` statement, a `pytest.raises` call or a `self.assert*` call. Adding checks is allowed.
- **G-5 `SUPPRESSION_NO_REASON`.** An added line holding `# noqa`, `type: ignore` or `pytest.skip(`, in code that G-3 does not cover, without `# reason: <text>` on the same line or the line above.
- **G-6 `THRESHOLD_LOWERED`.** In a changed file, a numeric value lowered or removed for `fail_under`, `fail-under`, `cov-fail-under`, or a `guard.threshold_keys` entry, written as `key = value` or `key=value`.
- **G-7 `DEPENDENCY_NO_HASH`.** A changed `guard.dependency_files` file with a requirement line lacking `--hash=sha256:`, including across `\` line continuations. Also a changed `guard.dependency_sources` file with no change to a dependency file.
- **G-8 Dependency approval.** A changed dependency file whose requirement lines all have hashes is no violation. Its path goes into `needs_code_owner`, and each changed package goes into `dependency_changes` with old and new versions (`null` when absent) and `changelog` as `https://pypi.org/project/<name>/<new or old version>/`.
- **G-9 `REPEATED_FIX`.** See below. Also sets `repeated_fix` to true.
- **G-10 `UNPINNED_ACTION`.** An added line in any `.yml` or `.yaml` file with `uses: owner/name@ref` where `ref` is not 40 hex digits. Local paths starting `./` and `docker://` references with `@sha256:` are allowed.

**Fingerprints (G-9).**

- The normalized diff drops `index` lines, reduces hunk headers to `@@`, strips trailing whitespace and carriage returns, and orders files by path. The fingerprint is its SHA-256.
- `cumulative` covers the merge base to the head. `round` covers the previous stored head to the head, or the merge base when no earlier run is stored.
- Earlier values come from `<reports-dir>/<pr>/*/guard.json`, using `head_sha` and `fingerprint`. Files with the same `head_sha` as this run are ignored, so a rerun of one commit is not a repeat.
- A fix is repeated when `round` equals any earlier `round`, or `cumulative` equals any earlier `cumulative`.
- Without `--reports-dir` or `--pr` nothing is repeated.

**Rules for `spec` PRs:**

- **G-11 `SPEC_OUTSIDE_ACCEPTANCE`.** Touching anything outside `acceptance/`.

**The known-failing list, for every kind of PR (decision O).** Stored passes are the `passed` lists in `<reports-dir>/*/*/acceptance.json`.

- **G-12 `KNOWN_FAILING_ADD_PASSED`.** An entry added for a test that has a stored pass.
- **G-13 `KNOWN_FAILING_ADD_NOT_ALLOWED`.** An entry added on a PR that is not `spec`. When the base already has a list, also: an added entry whose map ID is not `DEF-*`, or whose test function already exists in the base. A `spec` PR that introduces the first list may map entries to any valid ID.
- **G-14 `KNOWN_FAILING_REMOVED_NOT_PASSED`.** An entry removed without a stored pass.

The rules G-1 to G-11 do not apply to `other` PRs, and G-1 to G-10 do not apply to `spec` PRs, except G-10.

## 6. `gate.security_check`

`python -P -m gate.security_check --bandit FILE --pip-audit FILE --gitleaks FILE --review FILE --repo DIR --base SHA --head SHA --out FILE`

`--out` writes `{"ok", "findings": [{"tool", "rule", "path", "line", "reviewed"}], "suppressions": [...], "reason_codes": [...]}`.

- **S-1** Bandit JSON: `results[].test_id`, `filename`, `line_number`. pip-audit JSON: `dependencies[].name` and `vulns[].id`, with the package name as the path. gitleaks JSON: a list of `RuleID`, `File`, `StartLine`.
- **S-2** The review file holds a Markdown table with the columns `tool`, `rule`, `path`, `reason`. A finding is reviewed when a row matches its tool, rule and path and the reason is not blank.
- **S-3** Any unreviewed finding exits 1, code `UNREVIEWED_FINDING`.
- **S-4** A missing or unparsable tool output exits 1, code `MISSING_TOOL_OUTPUT`: absence is never a pass.
- **S-5** An added line holding `# nosec` or `gitleaks:allow` with no row for that tool and path exits 1, code `SUPPRESSION_WITHOUT_ENTRY`.
- **S-6** A missing review file means no reviewed findings.
- **S-7** `--tool-command '<JSON list>'`, repeatable, runs a tool first and records its exit code in `tool_exit_codes`. A tool that finds something exits non-zero, so only its output decides.

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

**`report.json`** validates against `gate/schema/report.schema.json` and holds:

- `verification`: every field of the context;
- `environment`: from `environment.json` in the artifact, or `"unknown"`;
- `checks`: `[{"id", "class", "conclusion", "commands": [{"argv", "exit_code", "duration_seconds", "raw_path", "raw_sha256"}], "counts"}]`;
- `coverage`, `mutation`: from `raw/diag-coverage/summary.json` and `raw/diag-mutation/summary.json`, or `"unknown"`;
- `dependency_changes`, `findings`, `rounds`;
- `resources`: every named cost, with `"unknown"` for one not given, never 0;
- `human`: `{"interventions", "minutes"}`;
- `bypass_merges`;
- `known_failing`: `{"size", "remove_from_list"}`, from `acceptance.json`, or `"unknown"`;
- `verdicts`: `{"preliminary", "final", "reasons"}`, with `final` as `null` here;
- `semi_automatic_steps`;
- `generated_at`.

**Bypass.** **B-1** A merge in `extras.merges` goes into `bypass_merges` when `via_pr` is false, or `approvals` is 0, or `final_conclusion` is not `success`.

**Markdown.** **M-1** `report.md` is rendered from the JSON only and obeys C-4 and C-5.

### 8.2 `final`

`python -P -m gate.report final --verdict FILE --archive FILE --out FILE`

Writes `{"verdict", "reasons", "conclusions": {"gate/archive", "gate/final"}}`.

- **F-1** The verdict is `ready-for-human` only when the preliminary verdict is `ready-for-human` and the archive result says `stored` and `sha256sums_match` are both true.
- **F-2** With the evidence not stored or a missing or unreadable archive result, a preliminary `ready-for-human` becomes `incomplete` with code `EVIDENCE_NOT_STORED`. Any other preliminary verdict stays as it is and gains that reason.
- **F-2a** A missing or unreadable preliminary verdict gives `incomplete`, code `NO_PRELIMINARY`. `--expect-verdict-sha256 VALUE` compares the verdict file with the hash the publish job gave through its job output, which a job that ran PR code cannot change: a difference, or an empty value, gives `blocked`, code `PUBLISH_OUTPUT_MISMATCH`. `--env-result FILE` with `ok` not true adds `FAILED_CHECK`, and a ready verdict becomes `blocked`.
- **F-3** `gate/final` is `success` only for `ready-for-human`. Every other verdict is `failure`, never `neutral` or `skipped`, because GitHub counts those as success. `gate/archive` is `success` only when the evidence was stored and matches.

### 8.3 `compare`

`python -P -m gate.report compare A B`

- **K-1** Exit 0 when the two reports are equal except for `generated_at`, `duration_seconds`, `raw_sha256`, `verification.run_id`, `verification.run_attempt`, `verification.execution_environment` and `environment`. Otherwise exit 1, naming each differing path. The raw hashes are excluded because the tools print their own times into the logs. The environment fields are excluded because a rerun runs in the pinned container by design.

### 8.4 `seal`

`python -P -m gate.report seal --artifact DIR --head-sha SHA --run-id R --run-attempt A`

- **Z-1** Copies `raw/gate-guard/guard.json` and `raw/gate-acceptance/acceptance.json` to the artifact's top level when present, writes `environment.json` and `meta.json`, and writes `SHA256SUMS` over every other file.

## 8a. `gate.publish`

The GitHub side of the judge: `context`, `jobs`, `extras`, `post-checks`, `post-final`, `comment`, `pulls`, `limits`, `hide-paths`. It reads its token from `GATE_TOKEN` and prints only the kind of a failure, never a token.

- **P-1** `extras` counts `/time <minutes>` comments only from the repository's owner, and an approval only on the merged head.
- **P-2** `hide-paths` takes `spec_tests.deny_read` out of the working folder with a sparse checkout, so that they do not show as deleted. An empty list exits 2.

## 8b. `gate.reproduce`

`python -P -m gate.reproduce --repo URL --sha SHA --out DIR`

- **X-1** It takes the stored context and extras of the newest attempt for the SHA, the configuration and acceptance tests at that run's `trusted_sha`, and only the runs stored before that attempt.
- **X-2** It reruns the mandatory checks of the `run` job, seals, regenerates the report and compares it with the stored one by K-1. Exit 0 when equal, 1 when not, 2 when no evidence is stored for the SHA.

## 9. `gate.archive`

`python -P -m gate.archive store --remote URL --branch reports --pr N --run-id R --attempt A --artifact DIR --publish DIR --context FILE --out FILE [--max-bytes N]`

Stores `reports/<pr>/<run_id>-<attempt>/` on the branch: `context.json`, the files of `--publish`, the artifact under `artifact/`, and `SHA256SUMS` over all of them as `<sha256>  <relative path>`, readable by `sha256sum -c`. For later runs `guard.json` and `acceptance.json` are also stored at the top of the attempt's folder, from the artifact, when present.

`--out` writes `{"stored", "sha256sums_match", "path", "commit", "reason", "artifact_present", "skipped_unsafe"}`. The exit code is 0 when stored and matching, otherwise 1.

- **W-1** The branch is created, with no parent, when missing.
- **W-2** A missing artifact folder still stores the rest, with `artifact_present` false. This is the cancelled run.
- **W-3 Append only.** When the attempt's folder already exists, nothing changes and the result has `stored` false, reason `ALREADY_EXISTS`.
- **W-4** It never force-pushes. On a refused push it fetches and retries, up to 5 times. Two runs at once both end stored.
- **W-5 Read-back.** After the push it reads the branch again from the remote and recomputes every SHA-256. `sha256sums_match` is true only when all agree.
- **W-6 Untrusted artifact.** Symbolic links and anything under a `.git` folder are not stored and are listed in `skipped_unsafe`.
- **W-7** An artifact larger than `--max-bytes` (default 200,000,000) is not stored: `stored` false, reason `TOO_LARGE`.
- **W-8** Earlier attempts are never changed.

`python -P -m gate.archive append --remote URL --branch reports --path RELPATH --file FILE --out FILE` adds one file that does not yet exist to a stored folder, with a read-back, and writes the same result. An existing file gives `stored` false, reason `ALREADY_EXISTS`.

## 10. `gate.feedback` (decision N)

`python -P -m gate.feedback decide --event-name NAME --event FILE --pulls FILE --reports-dir DIR --config FILE --out FILE [--integration-branch candidate/a]`

`--pulls`, trusted, lists open PRs: `[{"number", "head_sha", "base_ref", "head_ref"}]`.

Writes `{"act", "pr", "head_sha", "round", "reason_code", "comment"}`. Exit 0 whether it acts or not. `act` is true only with `reason_code` null.

**`workflow_run` events.** `workflow_run.path` must equal `feedback.judge_workflow_path` and `workflow_run.event` must be `pull_request_target`, otherwise `UNEXPECTED_SENDER`. The record is found at `<reports-dir>/*/<workflow_run.id>-<workflow_run.run_attempt>/`: `context.json` gives `pr` and `head_sha`, `final.json` gives the verdict. No record gives `NO_RECORD`. A verdict of `ready-for-human` gives `NOT_A_FAILURE`, and `needs-human` gives `NEEDS_HUMAN`.

**`status` events.** `context` must be `independent-review`, otherwise `WRONG_CONTEXT`. `state` must be `failure`, otherwise `NOT_A_FAILURE`. `sender.login` must be `<feedback.reviewer_app>[bot]`, otherwise `UNEXPECTED_SENDER`. `sha` is the head.

**Both events, in this order:**

- **D-1** `head_sha` must be the head of a listed PR, otherwise `SHA_NOT_CURRENT_HEAD`.
- **D-2** That PR's `base_ref` must be the integration branch, otherwise `PR_NOT_INTO_INTEGRATION`.
- **D-3** Done fix rounds are the distinct `head_sha` values in `<reports-dir>/<pr>/*/guard.json`, minus one. At or past `limits.max_fix_rounds` gives `ROUND_CAP`.
- **D-4** A stored `guard.json` for this head with `repeated_fix` true gives `REPEATED_FIX`.
- **D-5** Otherwise `act` is true and `round` is the done rounds plus one.
- **D-6** `comment` always says what happened and why, in plain text, obeys C-4 and C-5, and writes the mention as `` `@claude` ``.

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

- **L-1** The model gets only `SPEC.md`, the issue, the diff and the judge's report, on stdin, in an empty temporary folder. Its environment holds none of the `REVIEWER_*` variables.
- **L-2** The default command is `codex exec --sandbox read-only --skip-git-repo-check --ephemeral --output-schema <file> -o <file> -`. `--codex "COMMAND"` replaces the program. The arguments `--output-schema <file>` and `-o <file>` are always passed. The result is the JSON written to the `-o` file: `{"verdict": "pass"|"changes_requested", "findings": [{"severity", "where", "what"}]}`.
- **L-3** `pass` posts `success`, and `changes_requested` posts `failure`, with `context` `independent-review` on exactly `--sha`. A comment carries the findings and obeys C-4 and C-5.
- **L-4** When `--sha` is not the PR's head, before the model or again just before posting, nothing is posted and the exit code is 1, code `HEAD_MOVED`.
- **L-5** A model result that is missing, is not valid JSON, or has another verdict posts nothing and exits 1, code `MODEL_OUTPUT_INVALID`. The gate then stays blocked: it fails closed.
- **L-6** A missing part of the input, the judge's report included, runs no model, posts nothing and exits 1, code `MISSING_INPUT`.
- **L-7** A missing key path or an unreadable key exits 2 and prints the variable's name, never its content. The key never reaches a log, the `--out` file or the model.
- **L-8** `--out` writes `{"posted", "state", "code", "sha"}`.

## 12. Workflows (checked from their YAML)

- **Y-1** All four are `on: workflow_call`: `judge.yml`, `executor.yml`, `spec-tests.yml`, `feedback.yml`. Runners are exactly `ubuntu-24.04`.
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
- **Y-12** In `feedback.yml` secrets are referenced only in the job that runs the executor. The decision job comes first and the executor job runs only when it says `act`.
