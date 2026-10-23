#!/usr/bin/env bash
# WHICH TREE THE GOAL GUARD JUDGES, resolved once for both hooks.
#
# The guard itself is right: `goal_guard.py::repo_root()` resolves through `__file__`, so a
# worktree's own copy resolves to the worktree and reads the worktree's `.goal/`.
#
# TWO OPPOSITE TRAPS, and a fix for either one alone re-opens the other.
#
# `$CLAUDE_PROJECT_DIR` only — the shape this replaces. A session that started in the main checkout
# and then entered a worktree still carries it pointing at MAIN, so the hook ran main's copy and
# judged main's working tree.
#
# `$PWD` only — worse, and it has already happened.
#
# the discriminator is the COMMON GIT DIR. A worktree of this repository
# shares one with the main checkout; a nested repository does not. So `$PWD` wins
# when it is the same repository, and `$CLAUDE_PROJECT_DIR` wins otherwise — the
# worktree case is served without giving a stray `cd` any authority at all.
#
# Usage: goal_guard_hook.sh [args passed through to goal_guard.py]
set -uo pipefail

# The nearest ancestor of $1 that carries the guard, or nothing.
guard_root() {
    local d="${1:-}"
    [ -n "$d" ] || return 1
    while [ ! -f "$d/scripts/goal_guard.py" ] && [ "$d" != / ] && [ -n "$d" ]; do
        d="$(dirname "$d")"
    done
    [ -f "$d/scripts/goal_guard.py" ] && printf '%s\n' "$d"
}

# The repository a directory belongs to, as an absolute path both a worktree and
# its main checkout agree on. Empty when it is not a repository at all.
common_git_dir() {
    git -C "${1:-.}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null
}

here="$(guard_root "$PWD" || true)"
declared="$(guard_root "${CLAUDE_PROJECT_DIR:-$PWD}" || true)"

root="$declared"
if [ -n "$here" ] && [ -n "$declared" ] && [ "$here" != "$declared" ]; then
    mine="$(common_git_dir "$here")"
    theirs="$(common_git_dir "$declared")"
    # Same repository, different checkout  a worktree, and its own tree is the
    # one this session is working in.
    if [ -n "$mine" ] && [ "$mine" = "$theirs" ]; then
        root="$here"
    fi
fi
# No declared root at all (a bare host, a test) leaves the walk as the answer.
[ -n "$root" ] || root="$here"

if [ -n "$root" ] && [ -f "$root/scripts/goal_guard.py" ]; then
    exec python3 "$root/scripts/goal_guard.py" "$@"
fi
printf '%s\n' '{"decision":"block","reason":"The goal guard could not be located from this working directory, so it did NOT run and NOTHING has been verified. This is not the goal being met. cd to the repository root, and fix the hook command in .claude/settings.json."}'
