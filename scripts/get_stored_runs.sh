#!/usr/bin/env bash
# Put the stored runs in a folder. Fails when the branch cannot be read: rounds and
# repeated fixes are judged from these records, so a lost read must never look like
# "no earlier rounds". The folder stays absent then, and the scripts that need it stop.
set -uo pipefail
repo="$1"
target="$2"

git -C "$repo" ls-remote --exit-code --heads origin reports >/dev/null
code=$?
case "$code" in
  0)
    set -e
    git -C "$repo" fetch --no-tags --quiet origin '+refs/heads/reports:refs/remotes/origin/reports'
    git -C "$repo" worktree add --quiet --detach "$target" origin/reports
    mkdir -p "$target/reports"
    ;;
  2)
    # The branch does not exist yet: there is no evidence so far.
    mkdir -p "$target/reports"
    ;;
  *)
    echo "cannot read the reports branch" >&2
    exit 1
    ;;
esac
