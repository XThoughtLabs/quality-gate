# The negative-case tool

`xtl_negative.py` makes the scripted negative pull requests of stage A, milestone 1 (HQ-TASK-M1-C1, section 4 C) on
the demo repository. It shows that an unauthorized change does not merge into the integration branch, and that the
executor's GitHub App cannot pass or bypass the required policy check `stage-a/policy`, which only the controller's
app may post. It acts only as the executor's app, through an installation token that is not narrowed, and runs no
model. The rules it meets are in [NEGATIVE-CONTRACT.md](NEGATIVE-CONTRACT.md), numbered NC-1 to NC-16.

| Case | What the PR changes | Expected |
|---|---|---|
| N1 | one more true assertion inside the existing test `test_health` of `tests/test_api.py` | the gate marks the changed test (`marked_tests`); `stage-a/policy` refuses |
| N2 | one comment line in `acceptance/test_spec_1_identity_and_visibility.py` | `gate/guard` fails, a code owner's review is required; the controller refuses |
| N3 | one comment line in `workflow/__init__.py`, then three attempts by the executor's app: create the check run `stage-a/policy` with success, post the status `stage-a/policy` with success, merge the PR | GitHub refuses all three |

## Who runs it, and how

In M1-C2 the operator runs it in a `runas` window as the executor's Windows user: only that user can read the
executor's key and app file, which the setup script (`setup/setup_apps.py`) wrote to `<executor key folder>`.

```
runas /user:<executor Windows user> cmd
<python> -I xtl_negative.py --case N1 --key-file "<executor key folder>\<app slug>.pem" --app-file "<executor key folder>\<app slug>.app.json" --repo <owner>/<demo repository> --base candidate/a --branch ai/<N>-<slug> --log "<executor's own folder>\negative.jsonl"
```

- Every option is required once. `--branch` must not exist yet; a new run needs a new branch name.
- `<python>` needs only the standard library and `cryptography`.
- The tool requests only `https://api.github.com`, with a 30-second timeout, no proxy, no redirect and no retry. It
  never closes, deletes, approves, reviews, comments on or labels anything, and never changes a setting. The PR and
  the branch stay for the operator to close and delete after the evidence is recorded.
- The JWT and the token stay in memory only. Every printed or logged text is scrubbed of them and of the key.

## Exit codes

Each run prints one stop line last, `NEGATIVE <OUTCOME>: <detail>`, and appends one JSON line to the log (except for
a command-line error, which writes nothing).

| Exit | Outcome | Meaning |
|---|---|---|
| 0 | `DONE` | N1 or N2: the PR is open. N3: the PR is open and GitHub refused all three attempts |
| 1 | `FINDING` | N3: GitHub accepted an attempt of the executor's app. Stop and report it |
| 2 | `USAGE` | a usage or input error; nothing was done |
| 3 | `PRECONDITION` | the edit's anchor is not in the file exactly once, or the branch exists; nothing was created |
| 6 | `GITHUB_ERROR` | GitHub failed or answered unexpectedly, an N3 attempt got no clear refusal, or the run was interrupted; the stop line says what was created |

## Tests

```
<python> -m pytest dispatcher\negative\tests -q -p no:cacheprovider
```

The tests run offline: an in-memory fake GitHub replaces `urllib.request`'s HTTPS handler, sockets are blocked, and
the key is a throwaway RSA key made for the test session.
