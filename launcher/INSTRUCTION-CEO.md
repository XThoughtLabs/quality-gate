# Running the executor on your laptop

The AI executor and the spec-test author run on your laptop under a separate standard Windows user, not on GitHub. They reach GitHub only as the executor's GitHub App, with a token that lasts one hour. No key is stored in GitHub.

In the steps below, replace:

| Placeholder | What it is |
|---|---|
| `<executor user>` | the separate standard Windows user that runs the executor |
| `<key folder>` | the folder outside every user profile that holds the executor's key, for example `C:\<name of your choice>` |
| `<executor app name>` | the executor app's name, as the setup script's configuration gives it |
| `<python 3.13>` | the full path of the executor user's Python 3.13 |

Do these steps in order.

## 1. The Windows user

`<executor user>` must exist and be a standard user, not an administrator. The launcher refuses to run as an administrator.

## 2. Check the tools, signed in as `<executor user>`

Sign in to Windows as `<executor user>` (Start → your account picture → Switch user), or open its terminal from yours with `runas /user:<executor user> powershell`. Then run:

```
git --version
gh --version
claude --version
py -3.13 --version
```

- **git** and **gh** should answer.
- **Claude Code:** if `claude` is not found, install it for this user with Anthropic's Windows installer.
- **Python 3.13:** if `py -3.13` is not found, install Python 3.13 from python.org for this user only. Leave "for all users" unticked. The launcher and the application's tests need it. Note its path: it is `<python 3.13>` below.

## 3. Claude, signed in

Run `claude`, type `/status`, and check the account. Then type `/exit`.

## 4. No GitHub login for `<executor user>`

Still as `<executor user>`:

```
gh auth status
cmdkey /list | findstr /i github
```

- The first must say that you are not logged in. The second must print nothing.
- **Never run `gh auth login` as `<executor user>`, and never let git store a GitHub password there.** The launcher refuses to run if it finds one.

## 5. The key and the launcher's folder, as yourself

1. **Run the setup script**, `setup/setup_apps.py`, with its configuration (see `setup/README.md`). For the executor's role it writes two files into `<key folder>`, which only `<executor user>` can read, not even you:
   - `<key folder>\<executor app name>.pem`: the executor's key;
   - `<key folder>\<executor app name>.app.json`: the app's numbers, not secret.

   **Right after the script, do steps 2 and 4 below without a break.** Until step 4 runs, `<key folder>` may let any signed-in user add or change files in it. The key file itself is already closed, and the launcher refuses to run until step 4 is done.
2. **Copy the launcher**, in your own PowerShell window, from your clone of quality-gate:

   ```
   New-Item -ItemType Directory <key folder>\launcher
   $from = "<your clone of quality-gate>\launcher"
   Copy-Item "$from\xtl_launcher.py", "$from\LAUNCHER-CONTRACT.md" <key folder>\launcher\
   Copy-Item "$from\git-hooks" <key folder>\launcher\ -Recurse
   Copy-Item "$from\launcher.example.toml" <key folder>\launcher\launcher.toml
   Copy-Item "<your clone of quality-gate>\locks\review.lock" <key folder>\launcher\
   ```
3. **Fill in `launcher.toml`.** Open it in Notepad and replace every `<...>`: the key and app files, `runs_dir`, `claude_command`, `app_python` (`<python 3.13>`), `deny_read_paths`, `must_not_open`, and the ledger's path `ledger_file`. Keep stage A's limits (80, 240, 3) or set stricter ones.
4. **Make the launcher's files read-only for `<executor user>`.** The model runs as `<executor user>`, so it must not be able to change the launcher for the next run:

   ```
   $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   $ex = (Get-LocalUser <executor user>).SID.Value
   icacls <key folder>\launcher /inheritance:r /grant:r "*${me}:(OI)(CI)F" "*${ex}:(OI)(CI)RX" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T
   icacls <key folder> /inheritance:r /grant:r "*${me}:(OI)(CI)F" "*${ex}:(OI)(CI)RX" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
   ```

   The second line leaves the key's own rules as they are.
5. **Block the folders the executor must not open**, those you listed in `must_not_open`: deny `<executor user>` access to each. The launcher checks them before every run and stops if `<executor user>` can open one.

## 6. The launcher's Python, as `<executor user>`

```
py -3.13 -m venv $HOME\xtl-launcher-venv
& $HOME\xtl-launcher-venv\Scripts\python.exe -m pip install --require-hashes -r <key folder>\launcher\review.lock
& $HOME\xtl-launcher-venv\Scripts\python.exe -I <key folder>\launcher\xtl_launcher.py check
```

The last line must print `PREFLIGHT OK`. If it prints `STOPPED <CODE>`, the message says what to fix.

## 7. Using it, as `<executor user>`

Open the executor's terminal from your own session with `runas /user:<executor user> powershell`, and close every other program of `<executor user>` first. The launcher refuses to start while another process of that user runs (`PROCESS_AT_START`), so do not run it in a signed-in session of `<executor user>`, whose own shell processes would stop every start.

| What | Command |
|---|---|
| A task from an issue | `& $HOME\xtl-launcher-venv\Scripts\python.exe -I <key folder>\launcher\xtl_launcher.py task --issue <n>` |
| The spec tests | `... xtl_launcher.py spec --slug <slug>` |
| A fix round, after the judge and the reviewer have answered | `... xtl_launcher.py fix --pr <n>` |

- **What a run does:** the launcher clones the repository fresh, runs Claude with the limits from `quality.toml` and `launcher.toml`, counts Claude's messages, checks Claude's commits, pushes the branch as the app, and opens the PR. It never merges or approves.
- **Limits:** each attempt stops by itself at its message limit (`MESSAGE_LIMIT`), and a task whose messages or runs are used up does not start (`BUDGET_EXHAUSTED`). Add `--max-messages <m>` to lower one attempt's limit; nothing can raise it above `launcher.toml`. Every attempt is recorded in the ledger (`ledger_file`).
- **Fix rounds:** at most the gate's `max_fix_rounds`, and a repeated fix stops the work. These are the gate's own rules. A fix round counts against its issue's budget.
- **Logs:** each run writes `<runs_dir>\logs\<run>.log`, with no secret in it.
