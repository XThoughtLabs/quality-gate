# The executor's launcher

`xtl_launcher.py` starts the gate's AI executor, and the blind spec-test author, on the operator's own
Windows machine instead of on GitHub. It runs as a separate standard Windows user that holds the
executor app's key, never as the operator. For each run it mints a one-hour installation token for one
repository, lets the model work in a fresh clone with no credential, checks the model's commits, pushes
the branch as the app and opens the pull request. It never merges, approves, labels or changes a setting.

Since stage A it also counts the model's messages itself: it reads Claude Code's `stream-json` output,
counts each message once by its `message.id` (subagents' messages included), keeps an append-only
ledger of attempts, refuses a task whose messages or runs are used up, and stops the model at the
attempt's limit. On Windows the model runs inside a job object, so the stop ends its whole process
tree, children whose parent has already exited included.

It comes from the WorkFlow API pilot (DEV-06). The gate's own `make check` does not run these tests:
`pytest.ini` at the repository root collects only `tests/`.

## Files

| File | What it is |
|---|---|
| `xtl_launcher.py` | the launcher: Python standard library, plus `cryptography` for the app's JWT |
| `LAUNCHER-CONTRACT.md` | the rules it meets, LR-1 to LR-66 (stage A's amendment: section 12) |
| `INSTRUCTION-CEO.md` | the operator's setup steps on Windows |
| `launcher.example.toml` | an example configuration: copy it as `launcher.toml` beside `xtl_launcher.py` and replace the `<...>` placeholders |
| `tests/` | its own offline test suite, with its own `pytest.ini`, a fake GitHub API and a fake Claude |

The GitHub Apps and the key files are made by the setup script in `../setup/`.

## Commands

As the executor's Windows user, with the launcher's own Python:

```
python -I xtl_launcher.py [--config launcher.toml] check                                   # preflight only
python -I xtl_launcher.py [--config launcher.toml] task --issue <n> [--max-messages <m>]    # the executor, on an issue
python -I xtl_launcher.py [--config launcher.toml] spec --slug <s> [--max-messages <m>]     # the blind spec-test author
python -I xtl_launcher.py [--config launcher.toml] fix --pr <n> [--max-messages <m>]        # a fix round on the executor's PR
```

`check` prints `PREFLIGHT OK` or `STOPPED <CODE>`. `--max-messages` can only lower the attempt's limit,
which is the smallest of `max_messages_attempt`, `quality.toml`'s `max_turns` and the task's remaining
messages. The stops of stage A are `BUDGET_EXHAUSTED`, `MESSAGE_LIMIT`, `STREAM_UNREADABLE`,
`JOB_SETUP_FAILED`, `PROCESS_SURVIVED` and `LEDGER_FAILED` (contract, LR-65); none of them pushes anything.

## Tests

On Windows, from this folder, with Python 3.13 and the pytest and cryptography versions that
`../locks/test.lock` pins:

```
python -m pytest tests -q -p no:cacheprovider
```

The tests clone the gate from this repository's own folder (the folder above `launcher/`) and check out
an older commit of it, so they need a full clone, not a shallow one. Each skip names its reason. The run
takes about ten minutes on the pilot's laptop: several tests wait for the one-minute timeout of their
fake `quality.toml` or for the stop's 10-second grace.

## Known limits

- The preflight (`check`) does not start the model command, so a wrong `claude_command` shows only on the
  first real run. On Windows give the full path to `claude.exe`; the plain `["claude"]` does not start.
- The model runs as the same Windows user that can read the app's key and the ledger (DEV-06). Claude's
  deny rules stop its file tools, not a Python script it runs, and native Windows gives it no sandbox.
  The pilot accepted and disclosed this risk. The attempt's own message count lives in the launcher's
  memory and cannot be changed that way.
- On Linux and macOS the stop ends the model's process group; a descendant that leaves the group
  (`setsid`) can survive there (LR-58). Stage A's live runs are on Windows.
