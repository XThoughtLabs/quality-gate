# The executor's launcher

`xtl_launcher.py` starts the gate's AI executor, and the blind spec-test author, on the operator's own
Windows machine instead of on GitHub. It runs as a separate standard Windows user that holds the
executor app's key (`mp-claude` in the pilot), never as the operator. For each run it mints a one-hour
installation token for one repository, lets the model work in a fresh clone with no credential, checks
the model's commits, pushes the branch as the app and opens the pull request. It never merges,
approves, labels or changes a setting.

It comes from the WorkFlow API pilot (DEV-06). The gate's own `make check` does not run these tests:
`pytest.ini` at the repository root collects only `tests/`.

## Files

| File | What it is |
|---|---|
| `xtl_launcher.py` | the launcher: Python standard library, plus `cryptography` for the app's JWT |
| `LAUNCHER-CONTRACT.md` | the rules it meets, LR-1 to LR-50 |
| `INSTRUCTION-CEO.md` | the operator's setup steps on Windows, as written for the pilot |
| `launcher.example.toml` | an example configuration: copy it as `launcher.toml` beside `xtl_launcher.py` and replace the `<...>` placeholders |
| `tests/` | its own offline test suite, with its own `pytest.ini`, a fake GitHub API and a fake Claude |

## Commands

As the executor's Windows user, with the launcher's own Python:

```
python -I xtl_launcher.py [--config launcher.toml] check            # preflight only: PREFLIGHT OK or STOPPED <CODE>
python -I xtl_launcher.py [--config launcher.toml] task --issue <n>  # the executor, on an issue
python -I xtl_launcher.py [--config launcher.toml] spec --slug <s>   # the blind spec-test author
python -I xtl_launcher.py [--config launcher.toml] fix --pr <n>      # a fix round on the executor's PR
```

## Tests

On Windows, from this folder, with Python 3.13 and the pytest and cryptography versions that
`../locks/test.lock` pins:

```
python -m pytest tests -q -p no:cacheprovider
```

The tests clone the gate from this repository's own folder (the folder above `launcher/`) and check out
an older commit of it, so they need a full clone, not a shallow one. Expected: 431 passed, 8 skipped;
each skip names its reason.

## Known limits

- The preflight (`check`) does not start the model command, so a wrong `claude_command` shows only on the
  first real run. On Windows give the full path to `claude.exe`; the plain `["claude"]` does not start.
- The model runs as the same Windows user that can read the app's key (DEV-06). Claude's deny rules stop
  its file tools, not a Python script it runs, and native Windows gives it no sandbox. The pilot accepted
  and disclosed this risk.
- `INSTRUCTION-CEO.md` is the pilot's text: its copy step names the pilot's local folder.
