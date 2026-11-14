# The milestone controller: contract

`dispatcher/controller/xtl_controller.py` is a one-shot command. The operator runs it by hand, under the operator's own
Windows user, for one pull request. It is no service and has no schedule. It acts on GitHub only as the controller's
GitHub App. It decides whether one PR of the approved queue may merge into the integration branch by the customer's
policy (the customer's letter of 2026-11-13, section 4), posts the required check `stage-a/policy` on the PR's head
commit, and, when every rule holds, merges the PR through GitHub's normal protected path.

The rules below are numbered CR-1 onward. Each has at least one test in `dispatcher/controller/tests/`, written from
this text before the code, with a fake GitHub and no network.

Words used here: the *operator* is the person who owns the stand and runs the command; the *head* is the PR's head
commit SHA as read at the start of the run; the *base tip* is the integration branch's commit SHA as read at the start
of the run; *refuse* means the rule fails and the PR gets no automatic admission.

## 1. Input

- **CR-1 The command line.**
  `<python> -I xtl_controller.py --config <controller.toml> --repo <owner>/<name> --pr <N> --queue <queue.json> --queue-sha256 <64 hex>`.
  - Every option is required and given once. `--pr` is a positive decimal integer. `--queue-sha256` is 64 lowercase
    hexadecimal characters. `--repo` is `<owner>/<name>` of letters, digits, `.`, `_` and `-`.
  - Anything else is a usage error (CR-12, exit 2), found before any file is read or any request is made.
- **CR-1a The configuration file** is TOML with exactly these tables and keys; a missing key, an unknown key or a value
  of the wrong type is a usage error. Integers must be positive and are never booleans.

  | Key | Meaning |
  |---|---|
  | `[controller] app_id`, `installation_id` | the controller app's ID and its installation on the repository |
  | `[controller] key_file` | absolute path of the controller app's private key (PEM) |
  | `[controller] log_file` | absolute path of the run log (CR-10), in the operator's own space |
  | `[controller] base_branch` | the integration branch, `candidate/a` on the stand |
  | `[controller] reports_branch` | the gate's evidence branch, `reports` on the stand |
  | `[executor] app_slug`, `app_id`, `bot_id` | the executor app's slug and ID, and the user ID of its bot account |
  | `[reviewer] app_slug`, `app_id`, `bot_id` | the same for the reviewer app |
  | `[gate] actions_app_id` | the GitHub Actions app, 15368 on github.com |
  | `[gate] checks` | the gate's mandatory check names, distinct, each `gate/<lowercase letters>` |
  | `[gate] policy_check` | the controller's own check name, `stage-a/policy` |
  | `[policy] code_folders` | folders of ordinary application code, each `<name>/` (for the stand `["workflow/"]`) |
  | `[policy] test_folder` | the folder of ordinary tests, `<name>/` (for the stand `"tests/"`) |

  Nothing personal is written in the code: every name, ID and path above comes from this file. The example
  `controller.example.toml` holds placeholders only.
- **CR-1b The queue file** is read as bytes. Its SHA-256 must equal `--queue-sha256` (the value recorded when the
  queue was approved); otherwise `QUEUE_CHANGED` (usage error, exit 2). It is then parsed as strict JSON (UTF-8,
  no duplicate keys, no NaN or Infinity) and must hold:
  - `format` = `"xtl-stage-a-queue/1"`;
  - `repository` equal to `--repo`, and `integration_branch` equal to `[controller] base_branch`;
  - `base_sha` and `defects_sha`, each 40 lowercase hexadecimal characters;
  - `tasks`: a non-empty list. Each task has `id` matching `^[A-Z][A-Z0-9]*-T[1-9][0-9]*$`, unique; `title`, a text
    that starts with the ID and a space; `depends_on`, which must be the empty list (stage A's queue has no
    dependencies); and the texts `text` and `expected`.
  - The branch slugs of the tasks (CR-3) are distinct.

  A queue that breaks any of these is `QUEUE_INVALID` (usage error, exit 2).

## 2. The rules on the PR

The rules CR-2 to CR-6 are evaluated in this order, every one of them, on what GitHub answers. Each gives
`ok`, or a reason code with a detail. A request that fails or an answer of the wrong shape makes that rule fail with
the code `UNREADABLE` (fail closed). The first rule that fails, in this order, is the run's *first failing rule*.

- **CR-2 The PR.** `GET /repos/{repo}/pulls/{N}` must give a PR that is:
  - open (`state` = `open`) and not merged; not a draft;
  - based on `[controller] base_branch` of this repository (`base.ref`, `base.repo.full_name`);
  - from a branch of this same repository (`head.repo.full_name` = `--repo`; a fork, or a deleted head repository, is
    refused);
  - opened by the executor's bot: `user.login` = `<executor app_slug>[bot]`, `user.id` = `[executor] bot_id`,
    `user.type` = `Bot`.

  Codes: `PR_NOT_OPEN`, `PR_DRAFT`, `PR_WRONG_BASE`, `PR_FROM_FORK`, `PR_NOT_BY_EXECUTOR`.
  - The PR's first read gives the head. If it cannot be read at all, or gives no head SHA of 40 hexadecimal characters,
    nothing can be evaluated or posted: the run ends `GITHUB_ERROR` (exit 6).
- **CR-3 The task.** The queue's own rule: the executor's launcher names a task's branch
  `ai/<issue number>-<branch_slug(issue title)>` (launcher contract LR-22), and the issue's title is the task's
  `title`. So the PR's `head.ref` must match `^ai/[1-9][0-9]{0,9}-(.+)$` and the captured slug must equal
  `branch_slug(title)` of exactly one task of the queue. `branch_slug` is LR-22's function, re-implemented here and
  checked against the launcher's by a test.
  - The task must not be done already: no line of the run log (CR-10) records `MERGED` for this repository and task,
    and no closed PR of `GET /repos/{repo}/pulls?state=closed&base=<base_branch>` (every page, at most 10 pages of 100;
    more is `UNREADABLE`) has a `head.ref` of this task and a `merged_at`.
  - Codes: `NO_TASK` (no task, or more than one), `TASK_DONE`.
- **CR-4 The diff.** The base tip is read (`GET /repos/{repo}/branches/{base_branch}`), and the diff is
  `GET /repos/{repo}/compare/{base tip}...{head}`, which GitHub computes from the merge base. Only ordinary
  application code and added ordinary tests may change. Every file of the diff is classified; the first file that
  breaks a rule, in the API's order, gives the code:
  - `TOO_MANY_FILES`: 300 files or more (GitHub's compare lists at most 300); `EMPTY_DIFF`: no file.
  - `BAD_PATH`: a path that is not a plain relative POSIX path (empty, `.` or `..` segments, a backslash, a leading
    `/`, a control character).
  - `TEST_CHANGED`: a test file that is modified, renamed, removed, copied or changed in mode. A test file is any path
    under `test_folder` or `acceptance/`, or whose file name is `test_*.py` or `*_test.py`.
  - `RENAMED`, `REMOVED`, `MODE_CHANGED`: any other file renamed, removed, copied, or with a status other than
    `added` or `modified`.
  - `ACCEPTANCE`: any path under `acceptance/`.
  - `CONFTEST`: any file named `conftest.py`.
  - `WORKFLOW`: any path with a segment `.github` (workflows, `CODEOWNERS` there, templates).
  - `TEST_CONFIG`: test, coverage or security configuration, by file name in any folder: `pytest.ini`, `.pytest.ini`,
    `pytest.toml`, `.pytest.toml`, `tox.ini`, `setup.cfg`, `.coveragerc`, `.bandit`, `bandit.yaml`, `bandit.yml`,
    `.gitleaks.toml`, `.gitleaksignore`, `.gitattributes`, `ruff.toml`, `.ruff.toml`, `mypy.ini`, `.mypy.ini`,
    `.semgrep.yml`, `security-review.md`.
  - `CONTROL`: `quality.toml` or `CODEOWNERS` in any folder.
  - `DEPENDENCY`: a dependency file, by file name in any folder: `requirements*.txt`, `requirements*.in`,
    `requirements*.lock`, `constraints*.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `Pipfile.lock`, `poetry.lock`,
    `uv.lock`.
  - `SCHEMA`: a schema or migration file: a segment `migrations`, `migration` or `alembic`, or a name ending `.sql`;
    and any added or removed line of a code file's patch that matches (any case) the *schema words*
    `\b(CREATE|ALTER|DROP)\s+((TEMP|TEMPORARY|UNIQUE|VIRTUAL)\s+)*(TABLE|INDEX|VIEW|TRIGGER)\b` or
    `\bPRAGMA\s+user_version\b`. A code file whose patch GitHub does not give is `PATCH_UNREADABLE`.
    **Amendment R1 (review round 1, the CEO's word of 2026-11-14):** a schema held as SQL text inside ordinary code
    (the stand's `workflow/store.py`) changes without a schema word on a changed line. So for every *modified* code
    file, its contents at the merge base and at the head are read (`GET /repos/{repo}/contents/{path}?ref={sha}`), and
    the Python string literals that hold a schema word (found with the standard `tokenize` module; comments are not
    string literals) are compared, each with its runs of white space made one space and in lower case, as sorted lists.
    Any difference is `SCHEMA`. A file that cannot be read, is not base64, or does not tokenize is `UNREADABLE`.
  - **Amendment R6:** `CASE_CLASH`: an added path whose lower-case form equals the lower-case form of another path in
    the head's tree (on a checkout that ignores letter case, one file would replace the other).
  - `CODEOWNERS_PATH`: a path that a pattern of the base tip's CODEOWNERS names. The file is read from
    `.github/CODEOWNERS`, `CODEOWNERS` or `docs/CODEOWNERS` at the base tip, the first that exists, as GitHub does
    (`GET /repos/{repo}/contents/{path}?ref={base tip}`). No CODEOWNERS file is `CODEOWNERS_MISSING`. Each line's
    first word is its pattern; blank lines and lines starting with `#` are skipped. Supported patterns, with
    gitignore's meaning: `/dir/` and `/path` (anchored at the root), `dir/name` (a slash inside: anchored at the root
    too), `name` (a file or folder of that name at any depth) and `name/` (a folder of that name at any depth). A
    pattern names a path when it names the path itself or one of its folders. Matching ignores letter case (GitHub
    matches the exact case; this match refuses more, never less). A pattern with `*`, `?`, `[`, `]`, `!` or `\` is
    `CODEOWNERS_UNSUPPORTED` for every PR (fail closed).
  - `OUTSIDE_POLICY`: anything else that is not one of the two admitted kinds:
    - *ordinary application code*: status `added` or `modified`, under one of `code_folders`, ending `.py`;
    - *an ordinary test*: status `added`, under `test_folder`, file name `test_*.py`.

    **Amendment R6:** "under" a folder is matched in its exact letter case (`Tests/test_x.py` is not under `tests/`);
    the refusing rules above still ignore case.
  - `MODE`: an admitted file whose entry in the head's tree (`GET /repos/{repo}/git/trees/{head}?recursive=1`) is not a
    blob of mode `100644` (a symbolic link, a submodule, an executable). A truncated tree is `UNREADABLE`.

  The letter case of the fixed names above is ignored. The order of the checks for one file is the order of this list.
  - **Amendment R7 (the CEO's reading of the letter, 2026-11-14: «Требовать и код, и тест»):** when every file is
    admitted, the PR must hold at least one file of ordinary application code and at least one added ordinary test;
    otherwise `NO_CODE_CHANGE` or `NO_NEW_TEST`.
  - **Amendment R8:** the CODEOWNERS file's answer must have `encoding` `base64` and decode to a non-empty text
    (GitHub gives a file over 1 MB without content); otherwise `UNREADABLE`.
- **CR-5 The gate.**
  - **The checks.** `GET /repos/{repo}/commits/{head}/check-runs?filter=all` (every page; amendment R5: `filter=all`,
    as the gate reads them, never GitHub's default `latest`). For each name of `[gate] checks`, the
    run with the highest `id` among those of that name whose `app.id` is `[gate] actions_app_id` and whose `head_sha`
    is the head must be `completed` with conclusion `success`. Codes: `GATE_CHECK_MISSING` (no run of that name from
    that app), `GATE_CHECK_PENDING` (the newest is not completed), `GATE_CHECK_FAILED` (completed, not success).
  - **The stored report**, read as the gate itself reads it (FN-4):
    1. Every commit of `[controller] reports_branch` (`GET /repos/{repo}/commits?sha=<branch>`, every page, at most 10
       pages of 100) must have the author login `github-actions[bot]` and `commit.verification.verified` true;
       otherwise `REPORTS_UNTRUSTED`. A missing branch is `REPORT_MISSING`.
    2. The tree of the branch's newest commit (`GET /repos/{repo}/git/trees/{sha}?recursive=1`; truncated is
       `UNREADABLE`) is searched for `reports/<N>/<run_id>-<attempt>/context.json`; each such blob is read
       (`GET /repos/{repo}/git/blobs/{sha}`), and the records whose `head_sha` is the head and whose `pr` is N are kept.
       None is `REPORT_MISSING`. The newest by the numbers `run_id`, then `attempt`, is the record.
    3. The record's `final.json` must give `gate_verdict` = `ready-for-human` and `conclusions` `gate/archive` =
       `success`; its `verdict.json` must give `verdict` = `ready-for-human` with every value of `checks` = `success`;
       otherwise `GATE_NOT_READY`. A missing file is `REPORT_MISSING`.
    4. The record's `report.json` must give `verification.head_sha` = the head and `verification.pr` = N, and the lists
       `marked_tests`, `needs_code_owner`, `dependency_changes` and `security_review_changes` must be lists and empty.
       Codes: `REPORT_MISMATCH`, `MARKED_TESTS` (this is where a changed existing test is stopped, M1-B2's A.3),
       `NEEDS_CODE_OWNER`, `DEPENDENCY_CHANGES`, `SECURITY_CHANGES`.
- **CR-6 The review.** `GET /repos/{repo}/commits/{head}/statuses` (every page). Of the statuses with context
  `independent-review`, the one with the highest `id` (the newest) must have `state` = `success` and a `creator` with
  `login` = `<reviewer app_slug>[bot]`, `id` = `[reviewer] bot_id` and `type` = `Bot`, as the gate's FN-1 checks.
  Codes: `REVIEW_MISSING`, `REVIEW_PENDING`, `REVIEW_NOT_BY_REVIEWER`, `REVIEW_FAILED`.

**Waiting or refused.** The run is *waiting* when every failing rule fails only with `GATE_CHECK_MISSING`,
`GATE_CHECK_PENDING`, `REPORT_MISSING`, `REVIEW_MISSING` or `REVIEW_PENDING`: the gate or the reviewer has not finished.
Otherwise a failing run is *refused*.

## 3. The check, the merge and the record

- **CR-7 The policy check.** The controller posts `[gate] policy_check` on the head as its own app:
  - If check runs of that name from the controller's app (`app.id` = `[controller] app_id`) already exist on the head
    (read with `filter=all`, amendment R5),
    the newest of them is updated (`PATCH /repos/{repo}/check-runs/{id}`); otherwise one is created
    (`POST /repos/{repo}/check-runs`). So the head never carries two results of the controller's check.
  - It is always posted `completed`. Its conclusion is `success` only when CR-2 to CR-6 all hold; otherwise `failure`.
  - Its output's title says the conclusion; on failure the title names the first failing rule and its code. Its
    summary holds, on success, a short list of what was checked (the PR, the task's ID, the files, the eight gate
    checks and the record's path, the review's creator); on failure, the first failing rule, its code and its detail,
    then every other failing rule's code. It never holds a token or a key.
  - A merged PR gets no post (CR-9).
- **CR-8 The merge.** Only after a success was posted:
  1. Everything is read again: the PR, and CR-2 to CR-6 evaluated again with every request of section 2 made again
     (the base tip, the compare, the check runs, the `reports` branch, the statuses). The PR's head must still be the
     head, and every
     rule must still hold. If the head moved, the run ends `REFUSED` with `HEAD_MOVED` and nothing more is posted. If a
     rule now fails on the same head, the controller's check is updated to `failure` (CR-7) and the run ends `REFUSED`.
  2. The PR's `mergeable` must be `true`. When it is `null` (GitHub is still computing it, the documented transient
     answer), the PR is read once more after 5 seconds; a second `null`, or `false`, is `NOT_MERGEABLE`.
  3. `PUT /repos/{repo}/pulls/{N}/merge` with `{"sha": <head>, "merge_method": "merge"}`. A 200 answer with `merged`
     true ends the run `MERGED`, and its `sha` is the merge commit. Any other answer ends the run `MERGE_REFUSED` with
     GitHub's status code and message, without a retry. **Amendment R2:** when the merge request gets no answer at
     all, the PR is read once more: merged, with a `merge_commit_sha`, ends the run `MERGED` (the record's `message`
     says the answer was lost); not merged ends it `GITHUB_ERROR` ("the merge request got no answer; the PR is not
     merged"); unreadable ends it `GITHUB_ERROR` ("the merge's outcome is unknown"). The controller never approves, never changes a rule or a
     setting, and uses no other route than those named in this contract.
- **CR-9 Running twice.**
  - A PR that is already merged ends the run `ALREADY_MERGED`, after CR-2's first read, with nothing posted and no merge.
  - The check is updated in place (CR-7), so two runs on one head never leave two conflicting results.
  - The merge always carries the expected head (CR-8.3), so a second merge of one head is refused by GitHub.
  - Two runs at the same time are refused: the run creates `<log_file>.lock` exclusively before any request and removes
    it at its end. An existing lock ends the run `LOCKED` (exit 7) with nothing done. A lock left by a crash is removed
    by the operator after checking that no controller runs.
- **CR-10 The record.** Each run that got past CR-1, CR-1a, CR-1b, CR-11's key check and the lock appends one JSON line
  to `[controller] log_file` (its folder is created if missing) and flushes it to disk: `time` (UTC, ISO 8601),
  `repository`, `pr`, `head_sha`, `base_tip`, `task_id`, `queue_sha256`, `rules`, `outcome`, `policy_check_id`,
  `merge_sha`, and `message` (GitHub's status code and message, for a GitHub refusal or error). `rules` is an object
  keyed by `CR-2` to `CR-6`: `{"ok": true}`, or `{"ok": false, "code": <code>, "detail": <text>}`; a rule not
  evaluated is absent. A value not known is `null`. Never a token, a JWT or a key. A usage error and `LOCKED` write
  no record.
- **CR-11 The key.**
  - Before the key is read: `key_file` must be an absolute path to a regular file that is no symbolic link, and its
    access rules and its folder's must allow nobody but the operator's own user, SYSTEM (`S-1-5-18`) and the
    Administrators group (`S-1-5-32-544`). The check is the setup script's (`setup/setup_apps.py`: `Windows.acl_of`,
    `Windows.current_sid`, the rule of `check_key_folder`), applied to the file and to its folder. Otherwise
    `KEY_UNSAFE` (usage error, exit 2), with nothing read.
  - The PEM is read at run time and never printed. The app's JWT (RS256, `iat` 60 s back, `exp` 9 minutes ahead,
    `iss` the app ID) is signed with `cryptography` (pinned in `locks/review.lock`). The installation token is asked
    for with `POST /app/installations/{installation_id}/access_tokens`, narrowed to this one repository and to
    `contents: write`, `checks: write`, `pull_requests: read`, `statuses: read`.
  - The JWT and the token live in memory only: never on a command line, in an environment variable, in a file or in a
    log. Every message the controller prints or logs passes through a filter that replaces them.
  - Requests go only to `https://api.github.com`, each with a timeout of 30 seconds. **Amendment R4:** with no proxy
    (environment proxies are ignored) and no redirect followed: a 3xx answer is an answer, never followed.
  - **Amendment R2:** the installation token must be a text of letters, digits, `_`, `-` and `.` only; otherwise the
    run ends `GITHUB_ERROR`. The filter also replaces anything shaped like a GitHub token (`gh[pousr]_…`,
    `github_pat_…`) or a JWT.
- **CR-12 Exit codes and stop lines.** The run prints exactly one stop line, `CONTROLLER <OUTCOME>: <detail>`, and
  exits with:

  | Exit | Outcome | Meaning | Posted |
  |---|---|---|---|
  | 0 | `MERGED` | every rule held, the check is `success`, the PR merged | success |
  | 1 | `REFUSED` | a rule failed; the detail names the first failing rule and its code | failure (none for `HEAD_MOVED`) |
  | 2 | `USAGE` | a usage, configuration, queue or key error (CR-1, CR-1a, CR-1b, CR-11) | nothing |
  | 3 | `WAITING` | the gate or the reviewer has not finished (section 2); run again later | failure |
  | 4 | `MERGE_REFUSED` | every rule held and the check is `success`, but GitHub refused the merge or it is not mergeable | success |
  | 5 | `ALREADY_MERGED` | the PR was merged before this run | nothing |
  | 6 | `GITHUB_ERROR` | the token could not be had, the check could not be posted, a request outside the rules got no answer, or an unexpected error (amendment R2: any of these ends here, with the stop line and the record, never as an uncaught exception); the detail says what was posted | as stated |
  | 7 | `LOCKED` | another run holds the lock (CR-9) | nothing |

  The details: `MERGED` gives `PR <N> at <head> merged as <merge sha>`; `REFUSED` and `WAITING` start with the first
  failing rule and its code (`CR-4 TEST_CHANGED: …`), or `HEAD_MOVED`; `MERGE_REFUSED` gives GitHub's status code and
  message, or `NOT_MERGEABLE`; `USAGE` names the error's code where this contract gives one (`QUEUE_CHANGED`,
  `QUEUE_INVALID`, `KEY_UNSAFE`).

## 3a. Seams for the tests

The module offers `main(argv, *, http=None, windows=None, sleep=None, clock=None) -> int`. Left out, `http` is
`default_http(method, url, headers, body) -> (status, body bytes)`, which sends one request with `urllib` and a 30 s
timeout, gives an HTTP error's status and body as an answer, and raises `ControllerError` for any URL that does not
start with `https://api.github.com/`, before any request; `windows` is `default_windows()`, the setup script's
`Windows` object loaded from `setup/setup_apps.py` of this repository; `sleep` is `time.sleep`; `clock` is
`time.time`. `branch_slug(title)` is LR-22's function. The tests replace `http` with a fake GitHub, `windows` with a fake
of `current_sid` and `acl_of`, `sleep` with a recorder and `clock` with a fixed time.

## 4. Limits of this contract

- The controller trusts GitHub's answers for the PR, the checks, the statuses and the `reports` branch, as the gate does.
- CODEOWNERS is matched for the four simple pattern forms only; any other form refuses every PR until the matcher is
  extended.
- A schema change is seen when it changes a string literal that holds a schema word, or a changed line holds one
  (CR-4, amendment R1). A schema built at run time from pieces without a schema word (for example column names joined
  in code) is not seen; the gate's checks and the review are the other guards.
- The merge path is GitHub's: the ruleset on the integration branch, with no bypass, is the final guard. The controller
  never asks for, uses or simulates the operator's approval.
