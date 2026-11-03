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

## Open until a real run

These can only be seen on GitHub, in Part 3:

- whether GitHub signs the archive's commits through the API (public commits say it does; `gate/archive` fails closed if not);
- whether `decide` and `publish` can read a commit's statuses without `statuses: read` on this public repository, since no permission is added (decision R). A refusal fails closed in `decide`, and in `publish` it says `unknown`;
- whether the action's environment scrub leaves the model able to push through git;
- `if: always()` after a real cancellation, artifact behaviour on a rerun, and nested workflow resolution.
