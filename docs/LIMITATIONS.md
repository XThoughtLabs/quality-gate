# Limitations

What the gate does not do or does not prove, written down rather than dropped. Each entry says why it stays. The design's own known limits are in section 11 of the design.

## Accepted by decision

- **L1, Codex on the laptop (decision U).** Codex runs with `--ignore-user-config` and `--ignore-rules`, from an empty folder, with an allow-listed environment. Its `read-only` sandbox limits writes, and it may still read files under the same Windows account, the reviewer's key file included. No separate Windows account is used for it now.
- **L2, Actor check at the archive, feedback and review only (decision V).** The guard and `gate.reproduce` read `reports` unchecked. A forged record there cannot reach a green `gate/final`, because the same run's archive refuses the branch.

## Lows from review round 1, carried

- **L3** A dependency change with the same version and a different hash is missing from `dependency_changes`. `-e`, `--index-url` and `./x.whl` lines are skipped, a hash inside a comment counts as a hash, and files not in `guard.dependency_files` are unseen.
- **L4** `gate.publish hide-paths` hides what `spec_tests.deny_read` names. A spec-test author with a token can still reach the code through git history or the API; the tool list and the workflow's sparse checkout narrow this and do not close it.
- **L5** On Linux, a timeout in `gate.acceptance` or `gate.security_check` can leave their children running: they start in their own session.
- **L6** `gate.report seal` lists dotfiles that the artifact upload leaves out by default. A tool that writes a dotfile to a raw folder gives `incomplete`. It fails closed.
- **L7** `gate.feedback` is silent in the PR on an API failure and on `NO_RECORD`, because no PR is known yet.
- **L8** A green `gate/final` outlives new acceptance tests on the default branch: the design's rulesets have no up-to-date rule.
- **L9** `gate.publish extras` calls a commit a direct push when no merged PR brought it. A rebase merge rewrites commits, so all but the last of them would be flagged too. This over-reports and never hides.
- **L10** `resources.executor_runs` and `executor_turns` stay `"unknown"`: the action's numbers are not carried to the report. `actions_minutes` covers this attempt's jobs as the API gives them when `publish` runs.
- **L11** `verdicts.final` in `report.json` is always `null`. The stored report is sealed before the final verdict exists. The final verdict is in `final.json` beside it and in the check `gate/final`.
- **L12** `app-id` of `actions/create-github-app-token` is deprecated at this pin. It works; replace it when the pin moves.

## Open until a real run

These can only be seen on GitHub, in Part 3:

- whether GitHub signs the archive's commits through the API (public commits say it does; `gate/archive` fails closed if not);
- whether `decide` can read a commit's statuses with `contents: read` on this public repository, since no permission is added (decision R);
- whether the action's environment scrub leaves the model able to push through git;
- `if: always()` after a real cancellation, artifact behaviour on a rerun, and nested workflow resolution.
