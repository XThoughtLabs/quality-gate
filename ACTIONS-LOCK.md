# Pins

Every action is used at a full commit SHA. Checked against GitHub on 2026-11-03: each SHA is the commit of the named release tag.

## Actions

| Action | Version | Commit SHA | Date checked |
|---|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-11-03 |
| `actions/setup-python` | v7.1.0 | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | 2026-11-03 |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | 2026-11-03 |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | 2026-11-03 |
| `actions/create-github-app-token` | v3.3.0 | `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` | 2026-11-03 |
| `anthropics/claude-code-action` | v1.0.267 | `4845bacbb38b3c4b15d948f035349786f678e068` | 2026-11-03 |

`claude-code-action` pins its own dependencies inside its `action.yml`, for example `oven-sh/setup-bun`. Those pins come with its commit.

## Tools

| Tool | Version | Pin | Date checked |
|---|---|---|---|
| gitleaks | 8.30.1 | SHA-256 of `gitleaks_8.30.1_linux_x64.tar.gz`: `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`, checked by `scripts/install_gitleaks.sh` | 2026-11-03 |
| Bandit, pip-audit, ruff, mypy, mutmut, Schemathesis | see `locks/tools.in` | `locks/tools.lock`, with hashes | 2026-11-03 |
| Semgrep | 1.183.0 | `locks/semgrep.lock`, with hashes, in its own environment. Open-source CLI with the rules in `semgrep/rules.yml`, metrics off, no cloud | 2026-11-03 |
| The gate's own libraries | see `locks/gate.in`, `locks/review.in`, `locks/test.in` | the matching `.lock` files, with hashes | 2026-11-03 |
| actionlint | 1.7.12, released 2026-03-30 | From `https://github.com/rhysd/actionlint/releases/tag/v1.7.12`. SHA-256 checked against the release's checksums file. `actionlint_1.7.12_linux_amd64.tar.gz`: `8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8`, checked by `scripts/install_actionlint.sh`. `actionlint_1.7.12_windows_amd64.zip`: `6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9`, kept outside the repository | 2026-11-03 |

This actionlint is older than GitHub's `job.workflow_repository` and `job.workflow_sha`, added in September 2026, and calls them unknown. It runs with one `-ignore` for exactly those two properties and nothing else.

The lock files were made with `uv pip compile --generate-hashes --python-version 3.13 --python-platform x86_64-unknown-linux-gnu`.

## Environment

| Thing | Pin | Date checked |
|---|---|---|
| Runner | `ubuntu-24.04`, standard GitHub-hosted | 2026-11-03 |
| Python | 3.13.15, exact, from `actions/setup-python`, in every workflow; the customer's baseline ran on the same version | 2026-11-03 |
| Container for `make reproduce` | `python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26` | 2026-11-03 |
| Artifact retention | 30 days | 2026-11-03 |

## Facts about GitHub this design relies on, checked 2026-11-03

| Fact | Source |
|---|---|
| `pull_request_target` runs in the context of the default branch of the base repository, with `GITHUB_SHA` the last commit there | GitHub Docs, Events that trigger workflows |
| `job.workflow_repository` and `job.workflow_sha` name the reusable workflow's own source | GitHub Docs, Contexts reference; GitHub Changelog, 2026-09-03 |
| A required check passes on `success`, `skipped` or `neutral`, so anything but ready is posted as `failure` | GitHub Docs, Troubleshooting required status checks |
| Events from the built-in token start no workflow, except `workflow_dispatch` and `repository_dispatch` | GitHub Docs, Events that trigger workflows |
| `workflow_run` runs only from a workflow on the default branch; `issue_comment` too | GitHub Docs, Events that trigger workflows |
| A `git push` as `github-actions[bot]` is `unsigned`. A commit by that bot with committer `web-flow` is `valid`: 3 and 5 public commits read 2026-11-03. GitHub verifies a bot's commit only when the request holds no custom author, committer or signature | GitHub API, `commit.verification`; GitHub Docs, About commit signature verification |
| `claude-code-action` at this pin accepts `issues`, `issue_comment`, `pull_request`, `pull_request_target`, `pull_request_review`, `pull_request_review_comment`, `workflow_dispatch`, `repository_dispatch`, `schedule` and `workflow_run`. Any other event, `status` included, throws `Unsupported event type` | Its source at this pin, `src/github/context.ts` |
| At this pin the action treats an actor whose name ends in `[bot]` as having write access, but refuses a bot not named in `allowed_bots` | Its source at this pin, `src/github/validation/permissions.ts`, `actor.ts` |
| At this pin `issue_comment` with a `prompt` runs in agent mode, whatever the comment says | Its source at this pin, `src/modes/detector.ts`, `src/entrypoints/run.ts` |

These come from reading documentation and source. Real runs test them in Part 3.
