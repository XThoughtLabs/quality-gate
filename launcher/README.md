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
- Since stage A2 (LR-67 to LR-70): the launcher also searches, once a second and after the end, for processes
  of its own Windows user that appeared outside the model's job (for example started through WMI or the Task
  Scheduler), ends them and pushes nothing; a second Claude Code stops the attempt; the push sends the commit the
  checks verified, by its SHA, to the explicit repository URL; no git hook, no global git configuration and no
  change the model makes to the clone's `.git/config` acts on the launcher's git commands. What remains: a process
  that escapes and ends between two searches; anything run under another Windows user; code that a broker runs
  inside a Windows host the search allows (for example a COM server in `dllhost.exe`); a second model under another
  image name, inside the job. **Run the launcher in a session of the executor's user with nothing else of that user
  running** (no browser, no vendor agent): any other new process of that user stops the attempt. Real isolation,
  a separate Windows user per run or a sandbox, is stage B's.
- Since stage A3 (LR-79 to LR-88): after the model, every git step runs in a new bare repository the launcher makes
  with a random name, which fetches the branch head's SHA from the clone as data; the checks and the push run there,
  so no replace ref, graft, `commondir`, hook or setting of the clone acts on them. Every git command uses the hooks
  folder `git-hooks` beside the launcher, which must be read-only for the executor's user and hold only its
  `README.md` (copy it with the launcher), and an allow-list environment; the Windows folders come from the system.
  Processes are listed without opening them; one whose owner cannot be learned is judged by its parent. The search
  runs once more just before the push, and the preflight refuses to start while another process of the executor's
  user runs (`PROCESS_AT_START`): **start the launcher with `runas /user:<executor user>` from your own session**, not
  in a signed-in session of the executor's user, whose shell processes would stop every start. When `claude_image` is
  not set, it is the file name `claude_command[0]` resolves to; on Windows it must end in `.exe`, otherwise the
  preflight stops with `CLAUDE_IMAGE`: set `claude_image` then. What remains, besides the limits above: a second
  Ctrl+C while the stream is read to its end can leave a short count marked complete; a process that takes away its
  owner's rights is caught only through its parent, so a COM server the model registers that hides itself at once
  is not; processes inside WSL or a virtual machine are not seen; the launcher and the model share one Windows user,
  so the new repository and the searches defend by time, not by permissions (real isolation is stage B's); the merge
  policy on GitHub, not the launcher, is the final guard.
- Since stage A4 (LR-89 to LR-95): a foreign process the launcher cannot end is recorded in the ledger, the log and
  the stop message say so, and the next start refuses while it lives (`PROCESS_UNENDED`: restart Windows first);
  an allowed Windows image passes only under a live parent of another user (a service), never under the launcher, its
  terminal or a dead parent; the clone gets `core.autocrlf=false`; every commit of a spec run is checked, and a merge
  commit is refused; the virtual environment and pip run isolated, with nothing of the launcher's environment.
- **The DEV-06 class.** The launcher and the model share one Windows user. A process running under that user, outside
  the model's job or escaped from it, can in principle open the launcher and its terminal: it can evade the launcher's
  searches, survive a run, or act on the launcher, its terminal, its records or its own repository. The searches
  narrow this class but do not close it. A separate Windows user per run, or a sandbox, is stage B's; the merge
  policy on GitHub is the final guard. Findings in this class are disclosed in the contract's LR-66, not repaired in
  stage A.
- The 80 / 240 / 3 limits live in `launcher.toml`; the launcher does not hold the customer's ceilings in its
  code (the dispatcher will, from the approved queue). `timeout_minutes` above 59 is refused (LR-76).
