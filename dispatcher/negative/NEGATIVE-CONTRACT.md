# The negative-case tool: contract

`dispatcher/negative/xtl_negative.py` is a one-shot command for stage A, milestone 1 (HQ-TASK-M1-C1, section 4 C).
It shows on the demo repository that an unauthorized change does not merge into the integration branch, and that the
executor's GitHub App cannot pass or bypass the required policy check `stage-a/policy`, which only the controller's app
may post (its app ID is bound in the ruleset). It acts on GitHub only as the executor's app, through an installation
token, and makes one scripted pull request per run, with no model run. In M1-C2 the operator runs it in a `runas`
window as the executor's Windows user, the only user that can read the executor's key.

The rules below are numbered NC-1 onward. Each has at least one test in `dispatcher/negative/tests/`, written from this
text before the code, with an in-memory fake GitHub, a throwaway RSA key and no network.

Words used here: the *operator* is the person who owns the stand and runs the command; the *base sha* is the commit SHA
of the `--base` branch as read at the start of the run; the *head* is the PR's head commit SHA; *nothing created* means
that no branch, commit or PR was made on GitHub; a *write* is any request other than a GET, apart from the token request
of NC-6.

## 1. Input

- **NC-1 The command line.**
  `<python> -I xtl_negative.py --case N1|N2|N3 --key-file <pem> --app-file <app.json> --repo <owner>/<name> --base <branch> --branch <new branch name> --log <jsonl path>`
  - Every option is required and given exactly once, as two words (`--option value`). There is no positional argument,
    no abbreviation, no `--option=value` form and no other option.
  - `--case` is `N1`, `N2` or `N3`.
  - `--repo` matches `^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$` (the launcher's form of a repository).
  - `--base` and `--branch` each match `^[A-Za-z0-9._/-]{1,200}$`, hold no `..` and no `//`, do not start with `/` or
    `-`, and do not end with `/`, `.` or `.lock`. `--branch` differs from `--base`.
  - `--key-file`, `--app-file` and `--log` are absolute paths.
  - Anything else is a usage error (NC-15, exit 2), found before any file is read, the log is opened or any request is
    made. Such a run writes no log line (its log path may be the error).
  - In process, `xtl_negative.main(argv) -> int` does exactly what the command line does and returns the exit code.
- **NC-2 The key file** is the executor app's private key (PEM), named by the setup script `<executor key folder>\<app
  slug>.pem`.
  - It must be an absolute path to a regular file that is no symbolic link and no other reparse point (`os.lstat`), at
    most 64 KiB and not empty. The file opened must be the file checked (same device and file number by `os.fstat`).
  - It is read once, at run time, and parsed with `cryptography` as an RSA private key without a password. A key that
    cannot be parsed is a usage error.
  - It is never printed, copied or logged (NC-7).
  - No access-rule check is made here: the setup script (`setup/setup_apps.py`, `write_for_executor`) leaves the key
    readable only by the executor's Windows user, and the tool runs as that user, so every other user cannot read the
    file at all.
  - Any failure is a usage error (exit 2), with nothing requested.
- **NC-3 The app file** is the executor's app file written by the setup script (`<executor key folder>\<app
  slug>.app.json`, launcher contract section 2.2).
  - The same file rules as NC-2: absolute, regular, no link, at most 64 KiB, the file opened is the file checked.
  - It is UTF-8 JSON and must pass the launcher's checks of `load_app_file` (LR-1): `app_id` and `installation_id`
    positive integers (never booleans), `slug` matching `[a-z0-9][a-z0-9-]*`, `repository` matching the launcher's
    form, `executor_user` a non-empty text, `executor_sid` and `ceo_sid` SIDs (`S-1-<n>-<n>...`).
    `xtl_negative.load_app_file(path) -> dict` re-implements it, and a test checks that both accept and refuse the same
    files.
  - Its `repository` must equal `--repo` exactly: the executor's app is installed on that one repository only.
  - The tool uses `app_id`, `installation_id` and `repository`; the other keys are checked for shape only.
  - Any failure is a usage error (exit 2), with nothing requested.
- **NC-4 The log file** (`--log`) is opened for appending right after NC-1, before the app file and the key file are
  read. Its folder is created if missing. If it cannot be opened, the run is a usage error and writes no line. Every run
  that opened the log appends exactly one line to it (NC-14).

## 2. The token and the secrets

- **NC-5 The JWT** is the launcher's (LR-12): RS256 with the key file, signed with `cryptography`; header
  `{"alg":"RS256","typ":"JWT"}`; claims `iat` (60 seconds before now), `exp` (`iat` + 600, so 9 minutes after now) and
  `iss` (the app file's `app_id`, an integer), as compact JSON in the order `iat`, `exp`, `iss`.
  `xtl_negative.make_jwt(app_id, pem, now) -> str` re-implements the launcher's `make_jwt`, and a test checks that both
  give the same text for the same key and time.
- **NC-6 The installation token** is requested once, without narrowing its permissions, so that N3's refusals show what
  the app itself may do and not what a narrowed token may do:
  `POST /app/installations/{installation_id}/access_tokens` with `Authorization: Bearer <JWT>` and the body exactly
  `{"repositories": ["<repository name>"]}`: no `permissions` key and no other key.
  - The answer must be 201 with a non-empty text `token`. When the answer lists `repositories`, the list must name
    exactly this one repository (by `full_name`, or by `name` under the owner); otherwise the run is a GitHub error
    (exit 6) with nothing created.
  - The answer's `permissions` object (names and levels, both texts) is recorded as `token_permissions` (NC-14).
  - The JWT is used for this one request only. Every other request carries `Authorization: Bearer <token>`.
  - The tool does not revoke the token: NC-9 lists no `DELETE` route (NC-16). The token lives only in this process's
    memory and GitHub ends it after one hour.
- **NC-7 Secrets.** The JWT, the installation token and every non-empty line of the key file live in memory only: never
  on a command line, in an environment variable, in a file, in the log, on stdout or on stderr.
  - `xtl_negative.scrub(text, secrets) -> str` is the launcher's (LR-50 with A12): it removes every PEM block first,
    then every occurrence of each non-empty listed secret (longest first), then every PEM `BEGIN`/`END ... PRIVATE KEY`
    line, then every substring matching `gh[pousr]_[A-Za-z0-9]{20,}` or `github_pat_[A-Za-z0-9_]{20,}`, each replaced
    by `[removed]`. A test checks it against the launcher's `scrub`.
  - Every text printed or written to the log passes through it, GitHub's messages included.
  - The tool sets no environment variable and writes no file other than the log.

## 3. The network

- **NC-8 Where and how.**
  - Every request goes to `https://api.github.com` followed by a route of NC-9, with the headers
    `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: xtl-negative`,
    `Authorization: Bearer <JWT or token>`, and `Content-Type: application/json` when there is a JSON body.
  - Each request has a timeout of 30 seconds. No proxy is used, whatever the environment says
    (`urllib.request.ProxyHandler({})`). A redirect is never followed: a 3xx answer is an answer with that status.
  - Each request is made once and never retried.
  - An *answer* is an HTTP status code with its body. A connection failure, a timeout or an unreadable response is
    *no answer*. A 2xx answer whose body is not the JSON shape this contract names is a GitHub error (exit 6).
  - GitHub's *message* is the `message` text of the JSON body, scrubbed (NC-7) and cut to 1,000 characters; when the
    body has none, the first 300 characters of the body as text, scrubbed.
  - **The seam.** The tool reaches the network only through `urllib.request.build_opener(...)`, built during the run,
    and that opener's `open(request, timeout=30)`. Tests replace `urllib.request.HTTPSHandler` (and `HTTPHandler`) with
    an in-memory fake GitHub, which `build_opener` then uses. Nothing else is a test seam, and the tool has no test
    switch and no option to change the address.
- **NC-9 The routes.** Only these requests, each at most once per run. `{r}` is `--repo`.

  | # | Method | Route | Case | Expected answer |
  |---|---|---|---|---|
  | 1 | POST | `/app/installations/{installation_id}/access_tokens` | all | 201 |
  | 2 | GET | `/repos/{r}/git/ref/heads/{base}` | all | 200 |
  | 3 | GET | `/repos/{r}/contents/{path}?ref={base sha}` | all | 200 |
  | 4 | GET | `/repos/{r}/git/ref/heads/{branch}` | all | 404 (the branch must not exist) |
  | 5 | POST | `/repos/{r}/git/refs` | all | 201 |
  | 6 | PUT | `/repos/{r}/contents/{path}` | all | 200 or 201 |
  | 7 | POST | `/repos/{r}/pulls` | all | 201 |
  | 8 | GET | `/repos/{r}/pulls/{n}` | N3 | 200 |
  | 9 | POST | `/repos/{r}/check-runs` | N3, attempt `check_run` | a refusal (4xx) |
  | 10 | POST | `/repos/{r}/statuses/{head}` | N3, attempt `status` | a refusal (4xx) |
  | 11 | PUT | `/repos/{r}/pulls/{n}/merge` | N3, attempt `merge` | a refusal (4xx) |

  No other method or route: none that closes, deletes, approves, reviews, comments, labels, or changes a setting, a
  ruleset or a branch protection.

## 4. The cases

- **NC-10 The edits** are constants of the tool (`xtl_negative.EDITS`). Each is an exact old text and a new text in
  one file, chosen at the demo repository's commit `310f0ba` (where each old text occurs exactly once):

  | Case | File | Old text (JSON string) | New text (JSON string) |
  |---|---|---|---|
  | N1 | `tests/test_api.py` | `"def test_health(client):\n    assert client.get(\"/health\").json()[\"status\"] == \"ok\"\n"` | `"def test_health(client):\n    assert client.get(\"/health\").json()[\"status\"] == \"ok\"\n    assert client.get(\"/health\").status_code == 200\n"` |
  | N2 | `acceptance/test_spec_1_identity_and_visibility.py` | `"NOT_FOUND = {\"detail\": \"task not found\"}\n"` | `"# Negative test N2: a harmless comment line in an acceptance file; it must not merge.\nNOT_FOUND = {\"detail\": \"task not found\"}\n"` |
  | N3 | `workflow/__init__.py` | `"__version__ = \"0.1.0\"\n"` | `"__version__ = \"0.1.0\"\n# Negative test N3: a harmless comment line; it must not merge.\n"` |

  - N1 changes an existing test without weakening it: one more assertion, which is true (`/health` answers 200), inside
    the existing test `test_health`. Expected later: the gate marks it (`marked_tests`) and `stage-a/policy` refuses it.
  - N2 changes an acceptance file by one comment line. Expected later: `gate/guard` fails, a code owner's review is
    required, and the controller refuses it.
  - N3 is an ordinary harmless change (one comment line), followed by the three attempts of NC-13.
  - The edit is applied to the bytes GitHub gives for the file at the base sha (route 3): the old text, as UTF-8, must
    occur exactly once; the new content is the bytes before it, the new text, and the bytes after it. Nothing else
    changes. `xtl_negative.apply_edit(case, content) -> bytes` does this and raises `xtl_negative.AnchorNotOnce` (with
    the count) when the old text occurs zero times or more than once.
  - Route 3's answer must be `type` `file` with `encoding` `base64`, and the git blob SHA-1 of the decoded bytes
    (`blob <size>\0<bytes>`) must equal the answer's `sha`; otherwise the run is a GitHub error with nothing created.
- **NC-11 The order.** A run makes its requests in this order and stops at the first failure:
  1. the token (NC-6, route 1);
  2. the base: route 2 must answer 200 with `ref` = `refs/heads/<base>`, `object.type` = `commit` and `object.sha` 40
     lowercase hexadecimal characters, the base sha;
  3. the file at the base sha (route 3, NC-10);
  4. the anchor (NC-10): when the old text does not occur exactly once, the run stops with exit 3 and makes no further
     request;
  5. the branch must be absent: route 4 must answer 404. A 200 stops the run with exit 3 (the branch exists); any other
     answer is a GitHub error;
  6. only then the writes of NC-12: the branch, the commit, the PR; and for N3 the steps of NC-13.

  No write is made before step 5 has passed, so exits 2 and 3, and a GitHub error before step 6, leave nothing created.
- **NC-12 The writes.**
  - Route 5 with `{"ref": "refs/heads/<branch>", "sha": "<base sha>"}` must answer 201: the branch is created.
  - Route 6 with `{"message": "<commit message>", "content": "<base64 of the new content>", "sha": "<the blob sha from
    route 3>", "branch": "<branch>"}` must answer 200 or 201 with `commit.sha` of 40 lowercase hexadecimal characters:
    the commit. The commit message starts `NEGATIVE <case>:` and names the change.
  - Route 7 with `{"title", "head": "<branch>", "base": "<base>", "body", "draft": false}` must answer 201 with a positive
    integer `number` and a text `html_url`: the PR. The PR is not a draft.
  - The title starts `NEGATIVE N1:`, `NEGATIVE N2:` or `NEGATIVE N3:`. The body says that it is negative test `<case>` of
    stage A, milestone 1, made by this tool as the executor's app with no model run; what it changes; what is expected;
    that this PR must not merge; and that the tool never closes it (the operator closes it after the evidence is
    recorded).
  - A write that fails, or gets no answer, ends the run with exit 6; nothing is undone, and the stop line says what was
    created (and what may have been created when a write got no answer).
- **NC-13 N3's attempts.** After the PR is opened, route 8 must answer 200 with `head.sha` equal to the commit of NC-12
  and `head.ref` equal to `--branch`; that SHA is the head. Otherwise the run is a GitHub error and no attempt is made.
  Then the executor's app tries, in this order, each exactly once, whatever the earlier answers were:
  1. `check_run`: route 9 with `{"name": "stage-a/policy", "head_sha": "<head>", "status": "completed",
     "conclusion": "success", "output": {"title": "...", "summary": "..."}}` (the output says it is forged by the
     executor's app for negative test N3);
  2. `status`: route 10 with `{"state": "success", "context": "stage-a/policy", "description": "..."}`;
  3. `merge`: route 11 with `{"sha": "<head>", "merge_method": "merge"}`.

  Each attempt's answer is recorded: its name, method, route, status code (none for no answer), whether it was accepted,
  and GitHub's message. An attempt is *accepted* on a 2xx answer, *refused* on a 4xx answer, and *unclear* otherwise
  (3xx, 5xx or no answer). No attempt is retried.
  - Any accepted attempt: exit 1, a finding.
  - Otherwise all three refused: exit 0.
  - Otherwise (an unclear attempt): exit 6.

## 5. The record and the outcome

- **NC-14 The record.** Every run that opened its log (NC-4) appends exactly one JSON line to it, in UTF-8 with ASCII
  escapes, and flushes it to disk (`flush` and `os.fsync`). Earlier lines are kept. The line is an object with exactly
  these keys (a value not known is `null`):
  `time` (UTC, `YYYY-MM-DDTHH:MM:SSZ`, at the end of the run), `tool` (`"xtl_negative"`), `case`, `repository`, `base`,
  `base_sha`, `branch`, `path` (the edited file), `blob_sha`, `commit_sha`, `pr_number`, `pr_url`, `head_sha` (N3),
  `attempts` (N3: a list of `{"name", "method", "route", "status", "accepted", "message"}`; otherwise an empty list),
  `token_permissions`, `created` (the confirmed creations, in order, from `"branch"`, `"commit"`, `"pull_request"`),
  `outcome`, `exit_code` and `detail` (the stop line's detail).
  - Every text value passes through `scrub` (NC-7) and so does the whole line. It never holds the token, the JWT or a
    line of the key.
  - If the line cannot be written, the exit code stays, and the stop line's detail ends with
    `The log line could not be written.`
- **NC-15 Output, exit codes and stop lines.** The tool prints short progress lines on stdout and then exactly one stop
  line, the last line of stdout, `NEGATIVE <OUTCOME>: <detail>`. Every printed text is scrubbed (NC-7) and printed as
  ASCII. Nothing is expected on stderr: an unexpected error is caught and becomes exit 6.

  | Exit | Outcome | Meaning | Stop line's detail |
  |---|---|---|---|
  | 0 | `DONE` | N1 or N2: the PR is open. N3: the PR is open and GitHub refused all three attempts | the case, the PR's number and URL, that it must not merge; for N3 each attempt's status |
  | 1 | `FINDING` | N3: GitHub ACCEPTED at least one attempt | says plainly that GitHub accepted it from the executor's app, names the attempts, and that this is a finding to stop and report |
  | 2 | `USAGE` | a usage or input error (NC-1 to NC-4, or an unparsable key) | what is wrong; nothing was done |
  | 3 | `PRECONDITION` | the anchor does not occur exactly once, or the branch exists (NC-11) | which, with the count or the branch; nothing was created |
  | 6 | `GITHUB_ERROR` | GitHub failed or answered unexpectedly during the run, an N3 attempt was unclear, the run was interrupted (Ctrl+C), or an unexpected error | what failed, and what was created (or `nothing was created`) |
- **NC-16 What it never does.**
  - It never calls a route outside NC-9, so it never closes, deletes, approves, reviews, comments on or labels anything,
    and never changes a setting, a ruleset or a branch protection. It closes nothing and deletes nothing, even after a
    failure.
  - It never retries a request, never forces anything, and never follows a redirect.
  - It never starts a process (no `subprocess`), never sets an environment variable, never writes a file other than
    the log, and reads no file other than the key file and the app file.
  - It does not import the launcher: what it shares with it (`make_jwt`, `load_app_file`, `scrub`) is re-implemented
    and compared with the launcher's by tests.
  - It uses no `assert` for its runtime checks: every check raises explicitly.

## 5a. Amendment R3 (review round 1, the CEO's word of 2026-11-14)

The first review found that N3's merge attempt comes about a second after its PR is opened, before the gate has run,
so GitHub refuses it for the missing gate checks whatever stage-a/policy would say: it cannot show that the executor's
app is unable to pass the required policy check. N3 stays as it is (its check-run and status attempts show the
missing permissions); a new case shows the merge.

- **NC-17 N3M, the merge attempt on a green PR.**
  - Command: `--case N3M --key-file <pem> --app-file <app.json> --repo <owner>/<name> --base <branch> --pr <N>
    --expect-head <40 hex> --log <jsonl path>`: every option once, no `--branch`; `--pr` a positive decimal integer,
    `--expect-head` 40 lowercase hexadecimal characters. With N1 to N3, `--pr` and `--expect-head` are refused, and
    with N3M `--branch` is. Otherwise exit 2.
  - The token as in NC-5 and NC-6 (not narrowed). Then `GET /repos/{r}/pulls/{N}` (route 8): the PR must be open and
    not merged, based on `--base`, with `head.sha` equal to `--expect-head`, opened by `<slug>[bot]` of the app file;
    otherwise exit 3 (`PRECONDITION`) with nothing attempted.
  - Then exactly one attempt, route 11: `PUT /repos/{r}/pulls/{N}/merge` with `{"sha": <expect-head>,
    "merge_method": "merge"}`, recorded like N3's attempts (NC-14). A 2xx answer is `FINDING` (exit 1); a 4xx is
    `DONE` (exit 0); anything else, or no answer, `GITHUB_ERROR` (exit 6).
  - The tool does not read the PR's checks or statuses: the executor's app may lack the permission. The run sheet has
    the operator read them with his own login right before, and give the head he saw as `--expect-head`: every
    required check green except `stage-a/policy`, which must be absent. The intended PR is the positive task's PR,
    between its review and the controller's run.
  - It writes nothing else: no branch, no commit, no PR, no check, no status.

## 6. Limits of this contract

- The tool does not check which Windows user runs it. The guard is the key file's access rules: only the executor's
  user can read the key (NC-2).
- The token is not revoked at the end (NC-6); it expires after one hour and was never stored.
- The tool trusts GitHub's answers. It records GitHub's status codes and messages for N3 and judges only their class
  (2xx, 4xx, other); whether a refusal names the expected reason (a missing permission, a rule of the ruleset) is read
  by the operator from the record.
- The branch and the PR stay on GitHub after the run, whatever its outcome. The operator closes the PR and deletes the
  branch after the evidence is recorded. A second run of a case needs a new `--branch`.
- The anchors were chosen at `310f0ba`. If the base has moved and an anchor no longer occurs exactly once, the run
  stops with exit 3 and creates nothing; the constants are then changed in the tool, with this table, before a new run.
