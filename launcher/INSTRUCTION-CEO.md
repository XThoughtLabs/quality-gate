# Running the executor on your laptop (DEV-06)

The AI executor and the spec-test author now run on your laptop under the Windows user `mp-claude`, not on GitHub. They reach GitHub only as the app `xtl-gate-executor`, with a token that lasts one hour. No key is stored in GitHub.

Do these steps in order. Steps 1 to 3 are already done or only need a check.

## 1. The Windows user (done)

`mp-claude` exists and is a standard user, not an administrator (checked 2026-11-06). Keep it that way: the launcher refuses to run as an administrator.

## 2. Check the tools, signed in as `mp-claude`

Sign in to Windows as `mp-claude` (Start → your account picture → Switch user), or open its terminal from yours with `runas /user:mp-claude powershell`. Then run:

```
git --version
gh --version
claude --version
py -3.13 --version
```

- **git** (2.55.0) and **gh** (2.101.0) are installed for all users and should answer.
- **Claude Code:** if `claude` is not found, install it for this user with Anthropic's Windows installer.
- **Python 3.13:** if `py -3.13` is not found, install Python 3.13 from python.org for this user only. Leave "for all users" unticked. The launcher and the application's tests need it. Note its path: it is usually `C:\Users\mp-claude\AppData\Local\Programs\Python\Python313\python.exe`.

## 3. Claude, signed in to your subscription

You said this is done. To check, run `claude`, type `/status`, and see your subscription. Then type `/exit`.

## 4. No GitHub login for `mp-claude`

Still as `mp-claude`:

```
gh auth status
cmdkey /list | findstr /i github
```

- The first must say that you are not logged in. The second must print nothing.
- **Never run `gh auth login` as `mp-claude`, and never let git store a GitHub password there.** The launcher refuses to run if it finds one.

## 5. The key and the launcher's folder, as yourself

1. **Run `setup_apps.py` v2** (only after HQ's review; see the command list). When it asks:
   - for the user, press Enter for `mp-claude`;
   - for the folder, press Enter for `C:\xtl-gate-executor`.

   It writes two files there, which only `mp-claude` can read, not even you:
   - `C:\xtl-gate-executor\xtl-gate-executor.pem`: the executor's key;
   - `C:\xtl-gate-executor\xtl-gate-executor.app.json`: the app's numbers, not secret.

   **Right after the script, do steps 2 and 4 below without a break** (HQ, 2026-11-07). Until step 4 runs, the folder `C:\xtl-gate-executor` lets any signed-in user add or change files in it. The key file itself is already closed, and the launcher refuses to run until step 4 is done.
2. **Copy the launcher**, in your own PowerShell window:

   ```
   New-Item -ItemType Directory C:\xtl-gate-executor\launcher
   $from = "$env:USERPROFILE\GitHub\gate-practice-app\evidence-local\part-2\executor-launcher"
   Copy-Item "$from\xtl_launcher.py", "$from\LAUNCHER-CONTRACT.md" C:\xtl-gate-executor\launcher\
   Copy-Item "$from\launcher.example.toml" C:\xtl-gate-executor\launcher\launcher.toml
   Copy-Item "$env:USERPROFILE\GitHub\quality-gate\locks\review.lock" C:\xtl-gate-executor\launcher\
   ```
3. **Check `launcher.toml`.** Open it in Notepad. Set `app_python` to the Python path from step 2, if it differs.
4. **Make the launcher's files read-only for `mp-claude`.** The model runs as `mp-claude`, so it must not be able to change the launcher for the next run:

   ```
   $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   $mp = (Get-LocalUser mp-claude).SID.Value
   icacls C:\xtl-gate-executor\launcher /inheritance:r /grant:r "*${me}:(OI)(CI)F" "*${mp}:(OI)(CI)RX" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /T
   icacls C:\xtl-gate-executor /inheritance:r /grant:r "*${me}:(OI)(CI)F" "*${mp}:(OI)(CI)RX" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
   ```

   The second line leaves the key's own rules as they are.
5. **Block `codex-candidate`.** Done on 2026-11-06: you applied HQ's deny for `mp-claude` on `C:\Users\Public\Documents\codex-candidate`, and as `mp-claude` access is denied. The launcher checks it before every run and stops if `mp-claude` can open that folder.

## 6. The launcher's Python, as `mp-claude`

```
py -3.13 -m venv $HOME\xtl-launcher-venv
& $HOME\xtl-launcher-venv\Scripts\python.exe -m pip install --require-hashes -r C:\xtl-gate-executor\launcher\review.lock
& $HOME\xtl-launcher-venv\Scripts\python.exe -I C:\xtl-gate-executor\launcher\xtl_launcher.py check
```

The last line must print `PREFLIGHT OK`. If it prints `STOPPED <CODE>`, the message says what to fix.

## 7. Using it, as `mp-claude`

| What | Command |
|---|---|
| A task from an issue | `& $HOME\xtl-launcher-venv\Scripts\python.exe -I C:\xtl-gate-executor\launcher\xtl_launcher.py task --issue 5` |
| The spec tests | `... xtl_launcher.py spec --slug acceptance-v1` |
| A fix round, after the judge and the reviewer have answered | `... xtl_launcher.py fix --pr 7` |

- **What a run does:** the launcher clones the repository fresh, runs Claude with the limits from `quality.toml`, checks Claude's commits, pushes the branch as the app, and opens the PR. It never merges or approves.
- **Fix rounds:** at most 3, and a repeated fix stops the work. These are the gate's own rules.
- **Logs:** each run writes `C:\Users\mp-claude\xtl-runs\logs\<run>.log`, with no secret in it.
