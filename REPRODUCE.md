# Reproducing the gate

This repository holds the pipeline only and names no application. An application connects to it with thin workflows, a `quality.toml` and the manual steps below.

## 1. Accounts and manual setup

Nothing here needs a secret to be typed into a file or shown to a model. The operator enters every secret, in the repository's settings or in their own window.

1. A GitHub account that owns the application's repository. The pilot used a personal account; nothing relied on is organization-only.
2. Create the app `<name>-executor` under Settings → Developer settings → GitHub Apps:
   - webhook off;
   - repository permissions: Contents, Issues and Pull requests read and write, nothing else;
   - installable only on this account, and installed only on the application's repository;
   - generate a private key.
3. In the application's repository, add the secret `EXECUTOR_APP_PRIVATE_KEY` (the key's content) and the variable `EXECUTOR_APP_ID`.
4. Run `claude setup-token` in your own terminal, and store the result as the secret `CLAUDE_CODE_OAUTH_TOKEN`.
5. Create the app `<name>-reviewer` the same way, with repository permissions Commit statuses and Pull requests read and write and Contents read, nothing else. Keep its private key in a folder outside every repository.
6. Sign in to Codex CLI with `codex login`.

## 2. Connecting an application

Add to the application's repository, on its default branch:

- thin workflows that call this repository's reusable workflows at a full commit SHA;
- a `quality.toml`; see `docs/quality.example.toml` and section 1 of `docs/CONTRACTS.md`;
- `CODEOWNERS`, the prompt files and the issue template.

`pull_request_target`, `workflow_run` and `issue_comment` all run workflows from the default branch, so these files must be there. The thin `feedback` workflow should also set `concurrency` for the whole workflow, so that two events on one PR are decided in turn.

## 3. Commands

| Command | What it does |
|---|---|
| `make check` | runs this repository's own tests |
| `make reproduce REPO=<url> SHA=<sha>` | reruns every deterministic check in the pinned container, regenerates the report, and compares it with the stored one |

`make reproduce` needs `make` and Docker, and on a GitHub remote it first reads the `reports` branch's commits through GitHub's API, with no token. It takes no secrets: a rerun runs PR code, which could read them, so a secret-named variable in its environment or a credential in `REPO` exits 2 before anything runs. So a private repository cannot be rerun with this command. The comparison ignores the times: `generated_at`, `duration_seconds`, the hashes of raw logs (the tools print their own times into them), and the run's ID and attempt. It also ignores `environment` and `verification.execution_environment`, because a rerun runs in another environment by design.

AI steps are reproducible as a procedure (prompts, versions, limits), not as identical output.

To run an independent review of a PR, on the laptop, first install its one library, with hashes: `python -m pip install --require-hashes -r locks/review.lock`. Then:

```
export REVIEWER_APP_ID=...
export REVIEWER_APP_INSTALLATION_ID=...
export REVIEWER_APP_PRIVATE_KEY_PATH=/a/folder/outside/every/repository/key.pem
PYTHONPATH=<this repository> python -P -m gate.review_local --repo OWNER/NAME --pr N --sha <head sha> --issue N --out review.json
```

## 4. Which environment runs what

| Where | Operating system | Used for |
|---|---|---|
| GitHub-hosted runner | Ubuntu 24.04 (`ubuntu-24.04`, the pin) | every workflow, and `make reproduce` in the proofs |
| Container on that runner | Debian bookworm, `python:3.13.15-slim-bookworm` at its digest | the deterministic rerun of `make reproduce` |
| GitHub-hosted runner, `self-test.yml` | Ubuntu 24.04, Python 3.13.15 | this repository's own tests and actionlint |
| The laptop's Linux | Ubuntu 26.04, Python 3.14 | **not used**. It has neither `pip`, `venv`, `make` nor Docker, nothing is installed there (decision T), and neither its system nor its Python is the pinned one |
| The laptop's Windows 11 | Windows 11, Python 3.13.15 | writing this repository, a first run of its tests, and `review_local` |

The runner pin stays `ubuntu-24.04`. Each report's `verification.execution_environment` records the image it ran on.
