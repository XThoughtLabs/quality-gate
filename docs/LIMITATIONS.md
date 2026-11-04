# Limitations

What the gate does not do or does not prove, written down rather than dropped. Each entry says why it stays. The design's own known limits are in section 11 of the design.

## Accepted by decision

- **L1, Codex on the laptop (decision U).** Codex runs with `--ignore-user-config` and `--ignore-rules`, from an empty folder, with an allow-listed environment. Its `read-only` sandbox limits writes, and it may still read files under the same Windows account, the reviewer's key file included. No separate Windows account is used for it now.
- **L2, A remote that is not GitHub.** `gate.reproduce` on another remote cannot check who wrote the branch, and says so. Every other read of `reports` goes through the check of decision V.4.

## Lows from review round 1, carried

- **L3** A dependency change with the same version and a different hash is missing from `dependency_changes`. `-e`, `--index-url` and `./x.whl` lines are skipped, a hash inside a comment counts as a hash, and files not in `guard.dependency_files` are unseen.
- **L4** `gate.publish hide-paths` hides what `spec_tests.deny_read` names, and the default branch's copy is removed before the model starts. A spec-test author can still reach the code through git history or the token left in the remote's URL; the tool list narrows this and does not close it.
- **L5** On Linux, a timeout in `gate.acceptance` or `gate.security_check` can leave their children running: they start in their own session.
- **L6** `gate.report seal` lists dotfiles that the artifact upload leaves out by default. A tool that writes a dotfile to a raw folder gives `incomplete`. It fails closed.
- **L7** `gate.feedback` is silent in the PR on an API failure and on `NO_RECORD`, because no PR is known yet.
- **L8** A green `gate/final` outlives new acceptance tests on the default branch: the design's rulesets have no up-to-date rule.
- **L9** `gate.publish extras` calls a commit a direct push when no merged PR brought it. A rebase merge rewrites commits, so all but the last of them would be flagged too. This over-reports and never hides.
- **L10** `resources.executor_runs` and `executor_turns` stay `"unknown"`: the action's numbers are not carried to the report. `actions_minutes` covers this attempt's jobs as the API gives them when `publish` runs.
- **L11** `verdicts.final` in `report.json` is always `null`. The stored report is sealed before the final verdict exists. The final verdict is in `final.json` beside it and in the check `gate/final`.
- **L12** `app-id` of `actions/create-github-app-token` is deprecated at this pin. It works; replace it when the pin moves.

## Carried from review round 2 (decision X)

- **L13, the rest of F6.** A changed module-level constant (`EXPECTED = 5` to `6`), a shrunken module-level list of cases, a class attribute, a changed data file under a test folder and a gutted helper outside a `tests/` folder are neither refused nor marked. A class-level `pytestmark` skip passes the guard, and `forbid_skips` catches it at run time. An inline list of cases moved to a constant is refused, falsely.
- **L14, the environment scrub.** The action installs bubblewrap only when `allowed_non_write_users` is set. Without it a tool may read `/proc` of its parent, and the app's token stays reachable through git. Part 3 should try this.
- **L15** `merged_by` is absent from the list-PRs endpoint, so a bypass line can say "by None".
- **L16** G-6 can fire falsely on a mention in a document, on `check(fail_under, 5)`, and it takes ` ;` as the start of a comment in every file type.
- **L17** A test ID with a space, such as `test_a[a b]`, cannot be put on the known-failing list: `gate.acceptance` exits 2.
- **L18** A whole-workflow `concurrency` on the thin `feedback` workflow lets a later comment cancel a queued reviewer's event, by GitHub's rule for pending runs.
- **L19** The issue's text sits in the main prompt with no closing marker, read when the job runs, so its author can change it after labeling. It opens no new shell or output path.

## Carried from review round 3

- **L20** R-11 and A-11 still fail falsely on what pytest passes over for reasons parsing does not see: default `norecursedirs` (`.*`, `build`, `dist`, `venv`, `node_modules`, `*.egg`), `__new__`, an inherited `__init__`, `@dataclass`, an inherited or annotated `__test__`, a `fixture as fx` alias, `collect_ignore`. It fails closed, and `expected_tests_ignore` is the way out.
- **L21** A prose-only change to `security-review.md` lists nothing, and removing the text above a dormant table row can turn on an exception without a listed row. A rename away is not seen by the merge flag.
- **L22** A path with a newline puts its second line at the start of a line in `decide`'s log, where the runner might read a `::` command.
- **L23** A fix round's note says only `gate/tests failed`, and the JUnit file's names are not carried. The model can run the tests itself.
- **L24** On an API failure, the reason `REPORTS_UNTRUSTED` says the branch holds a commit the gate did not write, when the truth is that it could not be read.
- **L25** A model that pushes and then checks out another branch ends with no PR, and exit 1. The prompt does not tell it to stay.
- **L26** The steps after the model hold the app's token and run the gate from `$RUNNER_TEMP/gate`, which the model's `Bash(python:*)` could change. L14's reach to the token applies there too. `actions/upload-artifact` also follows links in the run job's output folder. The text check of P-6a reads the text as it stands, so an encoded secret passes it.

## Carried from review round 4 (the CEO's answer of 2026-11-04)

- **L27, the mention rule traps ordinary work (R4-M1).** A version bump in a `setup.cfg` with `test = pytest`, a deleted vendored `setup.cfg`, or a `tox.ini` with `[docs] note = run pytest first` is refused, and removing the mention is refused too. Reverting is the only way out, and the model can spend its fix rounds up to `ROUND_CAP`. A person's PR can make the change.
- **L28, marks do not stop a PR.** A mark in `needs_code_owner` reaches the comment and has no effect on the verdict, so `ready` and a green `gate/final` stand beside it. By decision W, a `tests/conftest.py` holding `pytest_pyfunc_call` is marked and not refused, and it can turn every test green. Whether a person must act depends on the application's `CODEOWNERS` and ruleset. Very many marks can push one past the comment's 60,000-character cut, and the comment says it was cut.
- **L29, code that changes pytest from inside.** A test file or a helper can rebind a test dynamically (`globals()`, `setattr`, `sys.modules`, `exec`, a class decorator, a metaclass, or an attribute set through another name) or monkeypatch pytest when imported, and the application's own modules can do the same when a test imports them. Static reading does not see this; design section 11 does not claim to stop a deliberate adversary. R-11 and A-11 still see a test that goes missing.
- **L30, plugin declarations left.** `setup.py` with `entry_points` passes, as before. A `[tool.setuptools.dynamic]` change with `project.dynamic` already naming `entry-points` passes, marked in the root. Both matter only where `setup` installs the project; plain metadata files are refused by G-1f.
- **L31, `post-proposal` at the edges.** It does not `fstat` what it opened, so a process the model left running can swap the file after the check, or hang the step on a pipe until the job's time limit. `O_NOFOLLOW` guards the last part of the path only, and `executor.yml` passes a bare name. Only `GATE_TOKEN` is in that step's environment, so the value test cannot fire for the other four names. A cut after `neutralize` can leave a trailing mention without its closing backtick. An entry naming a private key's header line of a test key is refused, and the proposal is lost.
- **L32, `gate.reproduce` and URLs.** `ssh.github.com`, `github.com.` and ssh aliases count as other remotes, so the authors' check is skipped with a note. A private repository cannot be rerun with this command, and an ssh agent or a git credential helper reachable from the machine is not looked for.
- **L33, the first known-failing list.** A spec PR adding the first list may name an old test, because the rule compares with a list in the base. G-12 stops it when a stored pass exists.
- **L34, rootdir moved by a plain file.** A subfolder's `pyproject.toml` with only `[project]` moves pytest's rootdir, and the root `conftest.py` is not loaded. R-11 should notice through the IDs; this exact case was not run through `gate/tests`.
- **L35, a base already broken.** A broken root `pyproject.toml`, or a root `setup.cfg` that cannot be parsed, refuses every change, the repair included. A person's PR can make it.
- **L36, the prompt for spec tests** does not say that `conftest.py` is refused. The refusal's text says where fixtures go.

## Carried from review round 5 (the CEO's answer of 2026-11-04)

- **L37** Swapping the order of two `pytest11` tables with the same content is refused.
- **L38** A base with an unparsable `tests/pyproject.toml`, which a PR rewrites with a pytest table under an escaped name, passes, because the base's text cannot be compared. That base is already red whenever the folder is an ancestor of an argument.
- **L39** Under `acceptance/`, test data named like a control file (`acceptance/data/tox.ini` that mentions pytest, `acceptance/data/proj/conftest.py`) is refused, as G-11b says. Renaming it is the way out.
- **L40** G-1g and G-1h go by names in the pinned Python's list and in the gate's tools. A tool's dependency not named there, and a module of the application's dependencies, can still be stood in for.
- **L41** G-1h judges only a new file. A shadow the base already has stays, and a change to it is not refused.

## Open until a real run

These can only be seen on GitHub, in Part 3:

- whether GitHub signs the archive's commits through the API (public commits say it does; `gate/archive` fails closed if not);
- whether `decide` and `publish` can read a commit's statuses without `statuses: read` on this public repository, since no permission is added (decision R). A refusal fails closed in `decide`, and in `publish` it says `unknown`;
- whether the action's environment scrub leaves the model able to push through git;
- `if: always()` after a real cancellation, artifact behaviour on a rerun, and nested workflow resolution.
