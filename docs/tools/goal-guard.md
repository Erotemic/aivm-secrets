# goal_guard

`scripts/goal_guard.py` is a deterministic Stop-hook guard for long agent runs.
An armed goal blocks a session's Stop and tells the agent to keep working. It runs
no commands. Only a release condition ends a run: an absolute deadline
(`deadline_utc`), a maximum run duration (`max_run_hours`, counted from the first
block), a stalled-commit limit (`max_stalled_blocks`), a crash fuse, or a human.

`.claude/settings.json` wires it as the Stop and SessionStart hook (through
`scripts/goal_guard_hook.sh` when present). `AGENTS.md` has the operating rules.
Never hand-edit `.goal/active.json`.

## Commands

```bash
python3 scripts/goal_guard.py --status            # what is armed, who holds it, when it releases, last verdict
python3 scripts/goal_guard.py --arm goal.json     # arm a goal (writes a receipt for any goal it replaces)
python3 scripts/goal_guard.py --extend 48h        # also 2d, 90m, or ISO-8601; bare = print the clocks
python3 scripts/goal_guard.py --pause "reason"    # let THIS turn end; blocks again next turn
python3 scripts/goal_guard.py --hold "reason"     # every turn may end until --unhold; deadlines still run
python3 scripts/goal_guard.py --unhold
python3 scripts/goal_guard.py --share             # every session that stops here joins the roster
python3 scripts/goal_guard.py --unshare           # no new session joins; the roster stays held
python3 scripts/goal_guard.py --own <session-id>  # add one session to the roster
python3 scripts/goal_guard.py --disown            # release every session
python3 scripts/goal_guard.py --resume            # take over an orphaned goal and print it
python3 scripts/goal_guard.py --clear <session-id># one session leaves; bare --clear refuses on a shared roster
python3 scripts/goal_guard.py --clear-all         # disarm for every session
```

Use `--pause` and `--hold` only when the human asks.

## Standing rules, and why

- **The arbiter is a command, not a model.** A judge that reads prose can be
  persuaded by a completion-shaped status report. Writing a status report does
  not close an item. Guard: `test_a_transcript_claiming_success_does_not_release_it`.
- **A goal contains no checks.** `--arm` refuses a `checks` list. Per-Stop
  verification commands cost hours of builds and decided nothing, because the
  backlog always has open rows. Do not reintroduce them.
- **Outstanding background work is not a stand-down condition.** Abandoned
  shells are the normal state of a long session, so such a condition leaves the
  run unguarded by default. Before you make X a condition, ask how often X is
  true when nothing is wrong. `--pause` and `--hold` are the explicit stand-downs.
- **The hook must find the guard from any directory and fail closed.** The hook
  command walks up from `$CLAUDE_PROJECT_DIR`, and `repo_root()` derives from
  `__file__`, not from git (a nested repository such as
  a vendored subproject answers `--show-toplevel` wrongly). If the
  guard cannot be found, the hook emits its own block.
- **Not knowing is a stall.** If `git rev-parse` fails, the stall counter
  advances. A new commit resets it; the same commit or an unknown commit counts.
- **`--extend` moves both clocks.** `deadline_utc` and `max_run_hours` are
  independent releases and the earlier one wins. It does not reset
  `max_stalled_blocks`; it prints the stall count instead.
- **Arming never destroys a goal.** `.goal/` is gitignored, so a replaced goal
  exists nowhere else. Every exit from a goal, replacement included, writes a
  `done-<stamp>.json` receipt.
- **Ownership is a roster in `.goal/owner`, one session id per line.** The
  roster is appended to, never read-modify-written, because a concurrent claim
  would be lost. `--own` adds. The share marker dies with `--clear`. The test
  suite (`scripts/tests/test_goal_guard.py`) drives sessions one at a time, so it
  does not prove the append property; do not "tidy" `join_owner` into a
  read-modify-write.
- **`--share` is a flag, not the default.** An unshared goal does not hold a
  window somebody opened to ask one question. Two worktrees can hold two
  different goals, because each copy of the script resolves its own `.goal/`.
- **Block and stall counters are shared across the roster.** A stall is a fact
  about the repository; HEAD moving in either lane resets it for both.
- **Every path out of `mode_stop` records a one-line verdict.** A bare `return`
  makes "the guard stood down" and "the hook never ran" look the same.
  `--status` prints the verdict and its age, or `NEVER`.

## A rotated session id

A compact or resume opens a new transcript under a new session id. The runtime
injects the previous transcript's path into the first records of the new one.
The guard treats that as proof of continuation and lets the new session inherit
the run, but only from an id already on the roster. Mentioning somebody else's
transcript inherits nothing; use `--share` to join a run on purpose.
SessionStart names the holder and points at `--resume`.

## What it cannot do

It cannot make an agent work. It removes "I have decided I am finished" as a way
for a turn to end, and nothing more.
