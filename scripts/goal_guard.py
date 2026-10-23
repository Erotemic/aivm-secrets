#!/usr/bin/env python3
"""Deterministic Stop-hook guard for long agent runs.

An armed goal blocks Stop and tells the agent to keep working. It does NOT run
commands: the backlog outlives any run, so there is nothing to verify and
nothing to wait for. Only a release condition ends a run — an absolute deadline,
a maximum run duration, a stalled-commit limit, or a crash fuse.

`--pause` skips one Stop; `--hold` skips Stops until `--unhold`, while deadlines
continue to run. `--extend` moves both clock-based releases. Those are the only
ways to stand the guard down: it does NOT infer one from outstanding background
work, because abandoned shells are the normal state of a long session.

Goals are repository-local but session-scoped. The first stopping session claims
an unowned goal; `--share` permits additional sessions to join the same goal.
`--resume` releases stale ownership after a session reset. Hook wiring must find
this script from any working directory and must fail closed on Stop if it cannot.

Typical commands::

    python3 scripts/goal_guard.py --arm .goal/my-run.json
    python3 scripts/goal_guard.py --status
    python3 scripts/goal_guard.py --pause "reason"
    python3 scripts/goal_guard.py --hold "reason"
    python3 scripts/goal_guard.py --unhold
    python3 scripts/goal_guard.py --extend 48h
    python3 scripts/goal_guard.py --clear

Goal files contain `goal` and release limits — nothing executable. The
historical incidents behind these rules belong in `docs/tools/goal-guard.md`."""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_MAX_STALLED_BLOCKS = 3
# The stall fuse also needs this much wall-clock time with no new commit. A
# block is only a turn ending, and a turn ends every time the agent waits on a
# long build or test lane — so a count of blocks alone released healthy runs
# mid-validation. Zero means blocks alone decide.
DEFAULT_MAX_STALLED_HOURS = 4.0
# The wall-clock ceiling on how long an armed goal may block, counted from its
# FIRST block. A backstop under `deadline_utc`, not a replacement for it: a goal
# with no deadline (or one armed before `--arm` validated deadlines) would
# otherwise block forever.
DEFAULT_MAX_RUN_HOURS = 36.0
# How many consecutive crashes of this script are treated as "the guard is
# broken" rather than "the work is not done". A crashed guard keeps blocking —
# deliberately, because a broken instrument must not read as success — but it
# cannot do so forever, or a typo in this file wedges every session in the repo.
MAX_CONSECUTIVE_CRASHES = 3
# How long a `--pause` token stays valid. A pause is armed DURING a turn and
# spent when that turn ends, so this only has to cover one turn's work — and it
# has to expire, because a token that lives forever is a release the agent can
# arm at hour 2 and cash in at hour 40, long after the human who asked for it
# has gone to bed.
PAUSE_TTL_MINUTES = 30.0


# How often the FULL goal text is reprinted in a block reason. The preamble runs
# to several thousand tokens and it is identical every turn, so repeating it at
# every block spends context to say nothing new. Repeats get the short form; the
# full text comes back on the first block, on this interval, and — the case that
# actually matters — whenever the transcript shows a COMPACT since the last full
# print, because that is precisely when the agent has lost it.
FULL_REASON_INTERVAL_MINUTES = 120.0

# How much of the transcript tail to read when looking for those signals. The
# transcripts in this project reach tens of megabytes, and this runs at the end
# of every turn. A launch older than this window is not a live wait, and a
# compact older than it is covered by FULL_REASON_INTERVAL_MINUTES anyway.
TRANSCRIPT_TAIL_BYTES = 2_000_000

# Below this, a goal is reprinted in full every time. The short form carries a
# sentence explaining where the full text went, so abbreviating a small goal
# makes the block BIGGER — the saving only exists for the multi-thousand-token
# preambles this repo actually arms.
SHORT_FORM_MIN_GOAL_CHARS = 1200


def as_int(value, fallback: int) -> int:
    """Parse an integer setting without letting malformed goal JSON crash the guard."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def as_float(value, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def repo_root() -> Path:
    """Return the repository containing this script, independent of cwd.

    The guard is committed at `<repo>/scripts/goal_guard.py`; resolving from
    `__file__` also gives each worktree its own repository-local goal state.
    """
    return Path(__file__).resolve().parent.parent


def goal_dir(root: Path) -> Path:
    return root / ".goal"


def active_path(root: Path) -> Path:
    return goal_dir(root) / "active.json"


def state_path(root: Path) -> Path:
    return goal_dir(root) / "state.json"


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def session_id_of(hook_input: dict) -> str:
    """The calling session's id, from either field the runtime provides.

    `session_id` is the documented one. `transcript_path` is read as a fallback
    because its stem IS the session id, and a guard that decides who owns a run
    should not hinge on one key surviving a schema change.
    """
    session = hook_input.get("session_id")
    if isinstance(session, str) and session.strip():
        return session.strip()
    transcript = hook_input.get("transcript_path")
    if isinstance(transcript, str) and transcript.strip():
        return Path(transcript.strip()).stem
    return ""


def owner_path(root: Path) -> Path:
    """Ownership gets its OWN file, deliberately, not a key in `state.json`.

    `mode_stop` loads `state.json` and writes the whole dict back. A second
    session claiming ownership during that window would have its key silently
    dropped by the owning session's write — and the symptom is the goal quietly
    reverting to unclaimed, which is the failure that releases runs. A separate
    file has no writer to lose a race with.
    """
    return goal_dir(root) / "owner"


def owner_sessions(root: Path) -> list[str]:
    """Return owner session ids in claim order, one per line."""
    try:
        text = owner_path(root).read_text()
    except OSError:
        return ""  # type: ignore[return-value]
    return [line.strip() for line in text.splitlines() if line.strip()]


def owner_session(root: Path) -> str:
    """The FIRST owner, for the one-line `owner session:` display."""
    roster = owner_sessions(root) or []
    return roster[0] if roster else ""


def join_owner(root: Path, session: str) -> None:
    """Add one session to the roster, by APPEND.

    ⛔ **append, never read-modify-write.** `owner_path`'s own docstring records
    why ownership is not a key in `state.json`: `mode_stop` reads that dict and
    writes the whole thing back, so a concurrent claim is silently dropped. A
    roster read-modify-written has the same defect against itself — two sessions
    joining in the same window and one of them vanishing. `O_APPEND` of a single
    short line does not.
    """
    if not session:
        return
    goal_dir(root).mkdir(parents=True, exist_ok=True)
    try:
        if session in (owner_sessions(root) or []):
            return
        with owner_path(root).open("a", encoding="utf8") as handle:
            handle.write(session + "\n")
    except OSError:
        # Not fatal: an unrecorded owner reads as unclaimed, which blocks. The
        # failure direction is "holds the run", never "releases it".
        pass


def leave_owner(root: Path, session: str) -> None:
    """Remove ONE session from the roster, leaving the others held."""
    try:
        roster = [s for s in (owner_sessions(root) or []) if s != session]
        if roster:
            owner_path(root).write_text("\n".join(roster) + "\n")
        else:
            owner_path(root).unlink(missing_ok=True)
    except OSError:
        pass


def set_owner(root: Path, session: str) -> None:
    """Replace the whole roster with one session (or clear it)."""
    goal_dir(root).mkdir(parents=True, exist_ok=True)
    try:
        if session:
            owner_path(root).write_text(session + "\n")
        else:
            owner_path(root).unlink(missing_ok=True)
    except OSError:
        pass


def shared_path(root: Path) -> Path:
    return goal_dir(root) / "shared"


def goal_is_shared(root: Path) -> bool:
    """**Is this run open to MORE THAN ONE session?**

    ⭐ **off by default, and that default is load-bearing.** An unshared goal
    holds exactly the session that claimed it, so a second window — a quick
    question, another agent, a fresh terminal — is untouched by a run it is not
    doing. That is the property the single-owner design bought and this must not
    spend it by accident.

    ⚠ **a SHARED goal holds every session that finishes a turn in this
    repository**, including the window somebody opened to ask one thing. That is
    the cost, it is why sharing is an explicit act (`--share`), and it is why
    `--disown` removes only the session that runs it and leaves the rest held.
    """
    return shared_path(root).exists()


_TRANSCRIPT_STEM = re.compile(
    r"([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\.jsonl"
)
CONTINUATION_HEAD_LINES = 64


def continued_sessions(hook_input: dict) -> set[str]:
    """The session ids this transcript says it CONTINUES.

    ⛔⛔ A SESSION ID ROTATES ON A COMPACT OR RESUME AND THE ROSTER DOES NOT
    FOLLOW IT, so a run stays bound to an id that will never stop again. The
    runtime injects the PREVIOUS transcript's path into the first records of the
    new one; that is proof of continuation, not a guess at one. Only ids already
    on the roster are honoured — mentioning somebody's transcript inherits
    nothing. See docs/tools/goal-guard.md, "A rotated session id".
    """
    path = hook_input.get("transcript_path")
    if not isinstance(path, str) or not path.strip():
        return set()
    mine = session_id_of(hook_input)
    try:
        with open(path.strip(), encoding="utf8", errors="replace") as handle:
            head = "".join(
                line for _, line in zip(range(CONTINUATION_HEAD_LINES), handle)
            )
    except OSError:
        return set()
    return {s for s in _TRANSCRIPT_STEM.findall(head) if s and s != mine}


def session_owns_goal(root: Path, hook_input: dict, *, claim: bool) -> bool:
    """Does the armed goal belong to the session calling this hook?

    `claim` is True only for the Stop hook: an unclaimed goal binds to the first
    session that finishes a turn under it, which is the arming run. SessionStart
    must NOT claim — it fires for every new session, so the first window opened
    after arming would steal a run it is not doing.
    """
    session = session_id_of(hook_input)
    if not session:
        return True  # Cannot tell. Fail toward blocking, never toward release.
    roster = owner_sessions(root) or []
    if session in roster:
        return True
    if not roster:
        if claim:
            join_owner(root, session)
        return True
    # ⭐ **A SHARED run lets a second session JOIN rather than stand down.** The
    # unshared path below is unchanged and is still the default: a goal one
    # session claimed does not reach out and hold every other window.
    if claim and goal_is_shared(root):
        join_owner(root, session)
        return True
    # ⭐ **THE SAME CONVERSATION UNDER A NEW ID INHERITS THE RUN.** Not a second
    # window taking a goal it is not doing — the transcript itself names the
    # session it continues, and that session must be on the roster already.
    inherited = continued_sessions(hook_input) & set(roster)
    if inherited:
        if claim:
            join_owner(root, session)
            for dead in inherited:
                # The rotated id will never stop again; leaving it on the roster
                # only makes `--clear` ambiguous later.
                leave_owner(root, dead)
        return True
    return False


def head_sha(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def now_utc() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def parse_deadline(raw) -> _dt.datetime | None:
    if not raw:
        return None
    try:
        text = str(raw).replace("Z", "+00:00")
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


_DURATION_UNIT_HOURS = {
    "": 1.0,
    "h": 1.0,
    "hr": 1.0,
    "hrs": 1.0,
    "hour": 1.0,
    "hours": 1.0,
    "m": 1.0 / 60.0,
    "min": 1.0 / 60.0,
    "mins": 1.0 / 60.0,
    "minute": 1.0 / 60.0,
    "minutes": 1.0 / 60.0,
    "d": 24.0,
    "day": 24.0,
    "days": 24.0,
    "w": 168.0,
    "week": 168.0,
    "weeks": 168.0,
}


def parse_duration_hours(raw) -> float | None:
    """`48h`, `48`, `2d`, `90m`, `1.5h`, `2 days` → hours. Anything else, None.

    A BARE NUMBER MEANS HOURS, which is the one thing a caller might get wrong
    silently, so the unit is echoed back by every command that uses this.
    """
    text = str(raw).strip().lower().replace(" ", "")
    if not text:
        return None
    digits = 0
    while digits < len(text) and (text[digits].isdigit() or text[digits] == "."):
        digits += 1
    unit = _DURATION_UNIT_HOURS.get(text[digits:])
    if unit is None:
        return None
    try:
        value = float(text[:digits])
    except ValueError:
        return None
    return value * unit if value > 0 else None


def format_hours(hours: float) -> str:
    """`122.0` → `5d 2h`. For humans reading a release time, not for parsing."""
    if hours <= 0:
        return "0h"
    days, rest = divmod(round(hours * 60), 24 * 60)
    part_h, minutes = divmod(rest, 60)
    parts = [f"{days}d" if days else "", f"{part_h}h" if part_h else "", f"{minutes}m" if minutes else ""]
    return " ".join(p for p in parts if p) or "0h"


def stamp_utc(when: _dt.datetime) -> str:
    """The `deadline_utc` spelling this file already uses, so `--extend` writes
    what a hand edit would have written."""
    return when.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clear_goal(
    root: Path,
    reason: str,
    remove: bool = True,
    session: str = "",
) -> None:
    """Archive a goal, optionally releasing only one owner session.

    `remove=False` archives the outgoing goal without disarming it, which is
    used when `--arm` replaces one goal with another. With `session`, only that
    owner leaves and the goal remains armed while other owners exist. Without a
    session, the goal ends for every owner.
    """
    active = active_path(root)
    if not active.exists():
        return
    if session and remove:
        leave_owner(root, session)
        if owner_sessions(root):
            # Somebody else is still holding this goal. Leave it armed for them
            # and say so; a silent return here reads as "cleared" to the caller.
            print(
                f"left the goal to {len(owner_sessions(root))} other session(s); "
                "it stays armed for them"
            )
            return
    stamp = now_utc().strftime("%Y%m%dT%H%M%SZ")
    archive = goal_dir(root) / f"done-{stamp}.json"
    payload = load_json(active) or {}
    payload["_cleared_at"] = now_utc().isoformat()
    payload["_cleared_because"] = reason
    try:
        archive.write_text(json.dumps(payload, indent=2) + "\n")
        if not remove:
            return
        active.unlink()
        state_path(root).unlink(missing_ok=True)
        owner_path(root).unlink(missing_ok=True)
        # ⛔ the SHARE marker dies with the run it shared. A stale one would make
        # the NEXT goal armed here hold every window in the repository without
        # anybody asking for it.
        shared_path(root).unlink(missing_ok=True)
    except OSError:
        pass


# ── Reading the transcript for what the hook input does not say ───────────────

_COMPACT_BOUNDARY = "compact_boundary"


def transcript_tail(hook_input: dict) -> list[str]:
    """The last TRANSCRIPT_TAIL_BYTES of the session transcript, as lines.

    Returns [] for anything unreadable. Every caller treats an empty result as
    "no signal", and every signal here can only make the guard QUIETER, so
    failing to read must fail toward the existing behaviour: block as before.
    """
    path = hook_input.get("transcript_path")
    if not isinstance(path, str) or not path.strip():
        return []
    try:
        with open(path.strip(), "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - TRANSCRIPT_TAIL_BYTES))
            raw = handle.read()
    except OSError:
        return []
    text = raw.decode("utf8", errors="replace")
    lines = text.split("\n")
    # A window that starts mid-record leaves a fragment that will not parse.
    return lines[1:] if size > TRANSCRIPT_TAIL_BYTES and len(lines) > 1 else lines


def transcript_signals(hook_input: dict) -> dict:
    """What the transcript knows that the Stop payload does not.

    `last_compact_at`: when this session was last compacted, if it was — the one
    thing that makes a block reprint the whole goal instead of the short form.

    ⛔ IT NO LONGER TRACKS IN-FLIGHT WORK. It used to return the set of async
    tool calls that had never reported back, and `mode_stop` stood down while it
    was non-empty. See the note there: abandoned background shells are the
    normal state of a long session, so that set is almost never empty and the
    guard almost never enforced.
    """
    last_compact = None
    for line in transcript_tail(hook_input):
        if not line.strip():
            continue
        if _COMPACT_BOUNDARY in line:
            try:
                record = json.loads(line)
                confirmed = record.get("subtype") == _COMPACT_BOUNDARY
            except (ValueError, TypeError, AttributeError):
                confirmed, record = False, {}
            stamp = parse_deadline(record.get("timestamp")) if confirmed else None
            if stamp and (last_compact is None or stamp > last_compact):
                last_compact = stamp
    return {"last_compact_at": last_compact}


# ── Hook output shapes ────────────────────────────────────────────────────────


def emit(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def open_items_text(goal: dict) -> str:
    return f"GOAL STILL OPEN: {goal.get('goal', '(unnamed goal)')}"


def short_open_items_text() -> str:
    """The block WITHOUT the goal preamble, for a repeat.

    The preamble is several thousand tokens and is byte-identical every turn, so
    reprinting it at every block buys nothing and costs the context the agent
    needs to actually do the work. The full text comes back on the schedule in
    `wants_full_reason` — above all, after a compact.
    """
    return (
        "GOAL STILL OPEN (short form — the full goal text is unchanged in "
        ".goal/active.json, and is reprinted here after a compact)."
    )


def wants_full_reason(state: dict, signals: dict, goal: dict | None = None) -> bool:
    """Whether this block should carry the whole goal text.

    Four ways to earn it. The first is that there is nothing to save: a SHORT
    goal costs less to reprint than the sentence explaining why it was not
    reprinted, and abbreviating it makes the block longer. Then: nothing has been
    printed yet; the transcript shows a COMPACT newer than the last full print,
    which is the case that matters because a compact is precisely when the agent
    lost the goal; or enough time has passed that a re-read is worth the tokens.
    """
    text = (goal or {}).get("goal") or ""
    if len(text) < SHORT_FORM_MIN_GOAL_CHARS:
        return True
    last_full = parse_deadline(state.get("last_full_reason_at"))
    if last_full is None:
        return True
    compact_at = signals.get("last_compact_at")
    if compact_at and compact_at > last_full:
        return True
    return now_utc() - last_full >= _dt.timedelta(
        minutes=FULL_REASON_INTERVAL_MINUTES
    )


def block_reason(goal: dict, deadline, full: bool = True) -> str:
    parts = [open_items_text(goal) if full else short_open_items_text()]
    if deadline:
        hours = max(0.0, (deadline - now_utc()).total_seconds() / 3600.0)
        # Only worth saying when it is close enough to shape what to do next; a
        # far deadline printed to one decimal place is just noise in a message
        # the agent reads at the end of every single turn.
        if hours <= 168.0:
            parts.append(f"\n{hours:.1f}h remain before this goal releases on its own.")
    parts.append(
        "\nThere is open work in docs/planning and this run is not over. Writing "
        "a status report will not end this turn. Pick up the next item now — no "
        "recap, no hand-off, mid-thought."
    )
    return "\n".join(parts)


def record_verdict(root: Path, verdict: str) -> None:
    """Write down what this Stop DECIDED, in one line.

    ⛔⛔ EVERY PATH OUT OF `mode_stop` RECORDS, ESPECIALLY THE QUIET ONES. A
    bare `return 0` makes "the guard stood down" and "the hook never ran" the
    same observation from outside. `--status` reads this back.
    """
    state = load_json(state_path(root)) or {}
    state["last_verdict"] = verdict
    state["last_verdict_at"] = now_utc().isoformat()
    write_state(root, state)


def write_state(root: Path, state: dict) -> None:
    goal_dir(root).mkdir(parents=True, exist_ok=True)
    try:
        state_path(root).write_text(json.dumps(state, indent=2) + "\n")
    except OSError:
        pass


def current_hold(root: Path) -> dict | None:
    """Return the sustained hold, if any.

    A hold remains until `--unhold`; unlike a one-shot pause, reading it does not
    consume it. Goal deadlines and run fuses still apply while held.
    """
    state = load_json(state_path(root)) or {}
    hold = state.get("hold")
    return hold if isinstance(hold, dict) else None


def hold_age_text(hold: dict) -> str:
    """How long this hold has been in force, for the message that says so."""
    started = hold.get("held_at")
    try:
        began = _dt.datetime.fromisoformat(started) if started else None
    except (TypeError, ValueError):
        began = None
    if began is None:
        return ""
    mins = (now_utc() - began).total_seconds() / 60.0
    if mins < 90:
        return f" (held {mins:.0f}m)"
    return f" (held {mins / 60.0:.1f}h)"


def take_pause(root: Path) -> dict | None:
    """Consume and return a live one-shot pause record.

    The token is removed before returning so it can skip exactly one Stop. An
    expired token is discarded.
    """
    state = load_json(state_path(root)) or {}
    pending = state.get("pause_once")
    if not isinstance(pending, dict):
        return None

    state.pop("pause_once", None)
    expires = parse_deadline(pending.get("expires_at"))
    if expires and now_utc() >= expires:
        # Say nothing to the agent: an expired token is not a decision anybody
        # made, and announcing it invites treating the next one as a release.
        state["last_pause_expired_at"] = now_utc().isoformat()
        write_state(root, state)
        return None

    state["last_pause_at"] = now_utc().isoformat()
    state["pauses"] = as_int(state.get("pauses"), 0) + 1
    write_state(root, state)
    return pending


# ── Modes ─────────────────────────────────────────────────────────────────────


def mode_stop(root: Path, hook_input: dict) -> int:
    goal = load_json(active_path(root))
    if not goal:
        return 0  # Not armed: ordinary sessions are untouched.

    # Whose run is this? Checked FIRST, so a session that does not own the goal
    # has no effect on it at all — it does not run the checks (which can take
    # minutes), count a block, or advance the stall counter toward a release
    # somebody else's work would be judged by.
    if not session_owns_goal(root, hook_input, claim=True):
        record_verdict(
            root,
            "stood down: not this session's run (held by "
            + (", ".join(owner_sessions(root) or []) or "nobody")
            + ")",
        )
        return 0

    # A SUSTAINED pause the human asked for. Checked before everything else for
    # the same reason the one-shot is: the point is to hand the turn back now.
    # ⚠ it is deliberately LOUD — every single Stop says the goal is held, names
    # the reason and says how to lift it, so a hold cannot be quietly forgotten
    # the way a silent one would be.
    hold = current_hold(root)
    if hold is not None:
        note = hold.get("reason") or ""
        emit(
            {
                "systemMessage": (
                    "Goal guard: ON HOLD at the human's request"
                    + hold_age_text(hold)
                    + (f" — {note}" if note else "")
                    + ". The goal is STILL ARMED and was not checked; it stays "
                    "held until somebody runs `python3 scripts/goal_guard.py "
                    "--unhold`. Its deadline still releases it on time. Goal: "
                    + goal.get("goal", "")
                )
            }
        )
        record_verdict(root, "stood down: ON HOLD" + hold_age_text(hold))
        return 0

    # A pause the human asked for, spent BEFORE the checks run: the point is to
    # hand the turn back now, and the checks can take minutes. It is not a
    # release — the goal stays armed, this consumes the token, and the next Stop
    # blocks as if nothing happened.
    paused = take_pause(root)
    if paused is not None:
        note = paused.get("reason") or ""
        emit(
            {
                "systemMessage": (
                    "Goal guard: PAUSED for this turn at the agent's request"
                    + (f" — {note}" if note else "")
                    + ". The goal is STILL ARMED and was not checked; it blocks "
                    "again at the end of the next turn. Goal: "
                    + goal.get("goal", "")
                )
            }
        )
        record_verdict(root, "stood down: one-shot pause spent")
        return 0

    deadline = parse_deadline(goal.get("deadline_utc"))
    if deadline and now_utc() >= deadline:
        clear_goal(root, "deadline passed")
        emit(
            {
                "systemMessage": (
                    f"Goal guard: deadline passed, releasing the run. "
                    f"Goal was: {goal.get('goal', '')}"
                )
            }
        )
        return 0

    # ⛔⛔ OUTSTANDING BACKGROUND WORK IS NOT A REASON TO STAND DOWN, and this
    # used to consult one. Jon, 2026-08-23: *"I often see rando shells that you
    # often just forget about and they just exist and are never killed. That
    # pattern happens ALL THE TIME. So the goal guard should never be using that
    # as a condition."* An abandoned poll loop or a superseded gate run never
    # reports a completion, so "something is in flight" was true almost always
    # and the run was unguarded by default — the inverse of a check that cannot
    # fail. A deliberate stand-down is `--pause` (one turn) or `--hold`.
    signals = transcript_signals(hook_input)

    # ⛔ THE GOAL IS NEVER "MET" HERE. Jon, 2026-08-25: the backlog outlives any
    # run, so there is no completion condition to test — only Jon, a deadline, or
    # a fuse ends a run. This used to execute the goal's own shell commands and
    # release when they all passed; `.goal/check_cost.jsonl` recorded 972 such
    # turns, many hours of builds, and not one release.
    #
    # Decide whether blocking is still useful, or whether this run is simply
    # stuck and a human should hear about it.
    state = load_json(state_path(root)) or {}
    sha = head_sha(root)
    # An unreadable head is not progress. A new commit resets the stall
    # counter; the same or unknown head increments it.
    progress_at = state.get("last_progress_at") or now_utc().isoformat()
    if not sha:
        stalled = as_int(state.get("stalled"), 0) + 1
    elif sha == state.get("last_head"):
        stalled = as_int(state.get("stalled"), 0) + 1
    else:
        stalled = 0
        progress_at = now_utc().isoformat()
    max_stalled = as_int(
        goal.get("max_stalled_blocks"), DEFAULT_MAX_STALLED_BLOCKS
    )
    max_stalled_hours = as_float(
        goal.get("max_stalled_hours"), DEFAULT_MAX_STALLED_HOURS
    )
    since_progress = parse_deadline(progress_at)
    stalled_hours = (
        (now_utc() - since_progress).total_seconds() / 3600.0 if since_progress else 0.0
    )
    blocks = as_int(state.get("blocks"), 0) + 1
    first_block_at = state.get("first_block_at") or now_utc().isoformat()

    state.update(
        {
            "last_head": sha,
            "stalled": stalled,
            "last_progress_at": progress_at,
            "blocks": blocks,
            "first_block_at": first_block_at,
            "last_block_at": now_utc().isoformat(),
            # A clean run: the crash fuse in `main` counts consecutive crashes,
            # so reaching here at all means the guard is working.
            "crashes": 0,
            "last_verdict": "blocked: the run is not over",
            "last_verdict_at": now_utc().isoformat(),
        }
    )
    write_state(root, state)

    if (
        max_stalled > 0
        and stalled >= max_stalled
        and stalled_hours >= max_stalled_hours
    ):
        record_verdict(
            root,
            f"RELEASED: {stalled} blocks and {stalled_hours:.1f}h with no new commit",
        )
        emit(
            {
                "systemMessage": (
                    f"Goal guard: released after {stalled} blocks and "
                    f"{stalled_hours:.1f}h with no new commit — the run is "
                    f"stuck, not finished."
                )
            }
        )
        return 0

    # The WALL-CLOCK fuse, which depends on nothing but the clock.
    #
    # `deadline_utc` is the intended release and every armed goal should carry
    # one — but it is optional, and an unparseable one used to become silently
    # no deadline at all. A goal with no deadline is an unbounded block, so the
    # guard keeps its own ceiling: `--arm` now rejects a malformed deadline
    # outright, and this catches goals armed before that existed, or edited by
    # hand afterwards.
    fuse_h = as_float(goal.get("max_run_hours"), DEFAULT_MAX_RUN_HOURS)
    started = parse_deadline(first_block_at)
    if fuse_h > 0 and started and now_utc() - started >= _dt.timedelta(hours=fuse_h):
        record_verdict(root, f"RELEASED: wall-clock fuse at {fuse_h}h")
        clear_goal(root, f"wall-clock fuse: blocked for over {fuse_h}h")
        emit(
            {
                "systemMessage": (
                    f"Goal guard: RELEASED by the {fuse_h}h wall-clock fuse — this "
                    f"goal has been blocking since {first_block_at} and is being "
                    f"cleared so the session is usable. It was NOT met."
                )
            }
        )
        return 0

    full = wants_full_reason(state, signals, goal)
    if full:
        state["last_full_reason_at"] = now_utc().isoformat()
        write_state(root, state)
    emit(
        {
            "decision": "block",
            "reason": block_reason(goal, deadline, full=full),
        }
    )
    return 0


def mode_inject(root: Path, hook_input: dict) -> int:
    """Inject cached goal context without running checks.

    Session-start injection must remain cheap and non-blocking. It may restate
    stale open items, but only the Stop hook decides that checks are satisfied.
    """
    goal = load_json(active_path(root))
    if not goal:
        return 0

    # Someone else's run: do not CLAIM it — SessionStart fires for every new
    # session, and the first window opened after arming would take a run it is
    # not doing. But do not be SILENT either: silence is how an orphan stays an
    # orphan, because "another session holds this" and "enforcing on nobody"
    # look identical from here.
    if not session_owns_goal(root, hook_input, claim=False):
        roster = owner_sessions(root) or []
        emit(
            {
                "systemMessage": (
                    "Goal guard: a goal is ARMED in this repository and is NOT "
                    "held by this session — it is held by "
                    + (", ".join(roster) if roster else "(unclaimed)")
                    + ", so nothing here will be blocked. If that session is "
                    "gone, take the run over with `python3 "
                    "scripts/goal_guard.py --resume`. Goal: "
                    + goal.get("goal", "")[:200]
                )
            }
        )
        return 0

    deadline = parse_deadline(goal.get("deadline_utc"))
    if deadline and now_utc() >= deadline:
        clear_goal(root, "deadline passed before this session started")
        emit({"systemMessage": f"Goal guard: deadline passed, releasing the run. Goal was: {goal.get('goal', '')}"})
        return 0

    state = load_json(state_path(root)) or {}
    # ⚠ a HELD goal must say so at session start, or a fresh session reads the
    # open items as pressure and starts working on something the human paused.
    held = state.get("hold")
    if isinstance(held, dict):
        note = held.get("reason") or ""
        emit(
            {
                "systemMessage": (
                    "GOAL ON HOLD"
                    + hold_age_text(held)
                    + (f" — {note}" if note else "")
                    + ". It is still armed and its deadline still runs, but no "
                    "turn will be blocked until somebody runs `python3 "
                    "scripts/goal_guard.py --unhold`. ⛔ do NOT resume the goal's "
                    "work on your own; the human paused it deliberately. Goal: "
                    + goal.get("goal", "")
                )
            }
        )
        return 0

    headline = "GOAL STILL OPEN" if state.get("blocks") else "GOAL ARMED"
    lines = [f"{headline}: {goal.get('goal', '(unnamed goal)')}"]

    if deadline:
        hours = max(0.0, (deadline - now_utc()).total_seconds() / 3600.0)
        # The one place the answer to "extend it" belongs: an agent asked for
        # more time reads this, and without the pointer it goes reading the goal
        # file, finds ONE clock, and edits the wrong half. Injected once per
        # session, not per block, so it costs nothing per turn.
        lines += [
            "",
            f"{hours:.1f}h remain before this goal releases on its own. "
            "⛔ To give it more time, run `python3 scripts/goal_guard.py --extend 48h` "
            "— never hand-edit deadline_utc, there are two clocks and it moves both.",
        ]
    lines += [
        "",
        "A Stop hook (scripts/goal_guard.py) blocks this session's turn from "
        "ending while the goal is armed. Continue working it.",
    ]

    event = hook_input.get("hook_event_name") or "SessionStart"
    emit(
        {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": "\n".join(lines),
            }
        }
    )
    return 0


def mode_resume(root: Path) -> int:
    """Hand an orphaned goal to the session running this command.

    `/clear` gives a session a new id, so a goal stays bound to an id that will
    never stop again: the run is silently unguarded, and SessionStart says
    nothing because the new session is not the owner. That silence is the reason
    this prints the goal rather than only re-pointing it — an agent told to
    "resume the goal" otherwise has no idea what the goal IS.

    Ownership is RELEASED rather than reassigned, because a command line has no
    session id to assign. The next Stop hook claims it, which in practice is this
    session at the end of this turn. The gap is real but small: another session
    stopping in between would take it instead, and `--status` shows who did.
    """
    goal = load_json(active_path(root))
    if not goal:
        print("no goal armed — nothing to resume")
        return 0

    previous = owner_session(root)
    set_owner(root, "")

    print(f"GOAL: {goal.get('goal', '(unnamed goal)')}")
    deadline = parse_deadline(goal.get("deadline_utc"))
    if deadline:
        hours = max(0.0, (deadline - now_utc()).total_seconds() / 3600.0)
        print(f"deadline: {deadline.isoformat()} ({hours:.1f}h remain)")

    print(
        f"\nreleased from session {previous or '(unclaimed)'}; THIS session claims "
        f"it when the turn ends — keep working it."
    )
    return 0


def mode_pause(root: Path, reason: str) -> int:
    """Arm a visible one-shot pause for the current turn.

    The next Stop consumes the pause, it expires after `PAUSE_TTL_MINUTES`, and
    its reason is recorded in state/transcript output. Clearing the goal is not
    required.
    """
    if not load_json(active_path(root)):
        print("no goal armed — nothing to pause")
        return 0
    state = load_json(state_path(root)) or {}
    expires = now_utc() + _dt.timedelta(minutes=PAUSE_TTL_MINUTES)
    state["pause_once"] = {
        "armed_at": now_utc().isoformat(),
        "expires_at": expires.isoformat(),
        "reason": reason.strip(),
    }
    write_state(root, state)
    print(
        f"one-shot pause armed — THIS turn may end; the goal blocks again at the "
        f"end of the next turn. Expires {expires.isoformat()} if unused."
    )
    return 0


def mode_hold(root: Path, reason: str) -> int:
    """Hold the goal until `--unhold`.

    Unlike `--pause`, a hold is sustained. Goal deadlines and run fuses continue
    to run, and Stop output reports the hold duration and reason.
    """
    if not load_json(active_path(root)):
        print("no goal armed — nothing to hold")
        return 0
    state = load_json(state_path(root)) or {}
    if state.get("hold"):
        print("already on hold — `--unhold` lifts it")
        return 0
    state["hold"] = {
        "held_at": now_utc().isoformat(),
        "reason": reason.strip(),
    }
    state["holds"] = as_int(state.get("holds"), 0) + 1
    write_state(root, state)
    print(
        "goal HELD — every turn may now end until `--unhold`. The goal stays "
        "armed and its deadline still releases it on time."
        + (f" Reason: {reason.strip()}" if reason.strip() else "")
    )
    return 0


def mode_unhold(root: Path) -> int:
    """Lift a `--hold`; the next Stop checks the goal normally again."""
    state = load_json(state_path(root)) or {}
    hold = state.get("hold")
    if not hold:
        print("not on hold — nothing to lift")
        return 0
    state.pop("hold", None)
    state["last_unhold_at"] = now_utc().isoformat()
    write_state(root, state)
    print(
        "hold lifted"
        + (hold_age_text(hold) if isinstance(hold, dict) else "")
        + " — the goal blocks again at the end of this turn."
    )
    return 0


def timer_lines(root: Path, goal: dict) -> list[str]:
    """Return the deadline, run fuse, and stall fuse without running checks.

    The stall fuse counts blocks AND time since the last commit, and is not
    changed by `--extend`, so it is reported separately from the two clocks.
    """
    now = now_utc()
    state = load_json(state_path(root)) or {}
    lines: list[str] = []

    deadline = parse_deadline(goal.get("deadline_utc"))
    if deadline:
        left = (deadline - now).total_seconds() / 3600.0
        when = "PASSED" if left <= 0 else f"in {format_hours(left)}"
        lines.append(f"  deadline    {stamp_utc(deadline)}  ({when})")
    else:
        lines.append("  deadline    (none) — ⚠ this run has no intended end")

    fuse_h = as_float(goal.get("max_run_hours"), DEFAULT_MAX_RUN_HOURS)
    first_block = parse_deadline(state.get("first_block_at"))
    if fuse_h <= 0:
        lines.append("  run fuse    disabled (max_run_hours = 0)")
    elif first_block:
        fires = first_block + _dt.timedelta(hours=fuse_h)
        left = (fires - now).total_seconds() / 3600.0
        when = "PASSED" if left <= 0 else f"in {format_hours(left)}"
        lines.append(
            f"  run fuse    {stamp_utc(fires)}  ({when})"
            f" — {fuse_h:g}h from the first block {stamp_utc(first_block)}"
        )
    else:
        lines.append(f"  run fuse    {fuse_h:g}h from the first block (not blocked yet)")

    max_stalled = as_int(goal.get("max_stalled_blocks"), DEFAULT_MAX_STALLED_BLOCKS)
    max_hours = as_float(goal.get("max_stalled_hours"), DEFAULT_MAX_STALLED_HOURS)
    stalled = as_int(state.get("stalled"), 0)
    since = parse_deadline(state.get("last_progress_at"))
    idle_h = (now - since).total_seconds() / 3600.0 if since else 0.0
    close = (
        "  ⚠ CLOSE"
        if max_stalled > 0 and stalled >= max_stalled - 2 and idle_h >= max_hours * 0.75
        else ""
    )
    lines.append(
        f"  stall fuse  {stalled} of {max_stalled} blocks and {format_hours(idle_h)} "
        f"of {max_hours:g}h with no new commit (both must trip)"
        f"{close} — ⛔ NOT movable by --extend; commit something instead"
    )
    return lines


def mode_extend(root: Path, raw: str) -> int:
    """Extend the deadline and max-run clock while preserving their gap.

    The stall fuse is intentionally unchanged because elapsed time is not
    evidence of progress. With no duration, print the clocks without running
    checks.
    """
    goal = load_json(active_path(root))
    if not goal:
        print("no goal armed — nothing to extend")
        return 1

    if not str(raw).strip():
        print(f"goal: {str(goal.get('goal', ''))[:90]}…")
        for line in timer_lines(root, goal):
            print(line)
        print("\nextend with:  python3 scripts/goal_guard.py --extend 48h")
        return 0

    now = now_utc()
    old = parse_deadline(goal.get("deadline_utc"))
    live_base = old if (old and old > now) else now
    hours = parse_duration_hours(raw)
    if hours is not None:
        new_deadline = live_base + _dt.timedelta(hours=hours)
    else:
        # An absolute timestamp is the other thing a human means by "extend to".
        new_deadline = parse_deadline(raw)
        if new_deadline is None:
            print(
                f"cannot read {raw!r} — give a duration (48h, 2d, 90m; a bare "
                f"number is HOURS) or an ISO-8601 timestamp (2026-08-20T20:15Z)"
            )
            return 2
        if new_deadline <= now:
            print(f"{stamp_utc(new_deadline)} is in the past — that would end the run, not extend it")
            return 2
        hours = (new_deadline - live_base).total_seconds() / 3600.0

    fuse_h = as_float(goal.get("max_run_hours"), DEFAULT_MAX_RUN_HOURS)
    if fuse_h > 0:
        # Written even when it was ABSENT: the default applies either way, and a
        # default that fires early is the failure this command exists to prevent.
        goal["max_run_hours"] = round(fuse_h + hours, 3)
    goal["deadline_utc"] = stamp_utc(new_deadline)

    problems = validate_goal(goal)
    if problems:
        print("refusing to write — the extended goal would not arm:")
        for problem in problems:
            print(f"  ⛔ {problem}")
        return 2

    log = goal.get("extended")
    if not isinstance(log, list):
        log = []
    log.append(
        {
            "at": stamp_utc(now),
            "by": f"+{format_hours(hours)}",
            "deadline_utc": goal["deadline_utc"],
            "max_run_hours": goal.get("max_run_hours"),
        }
    )
    goal["extended"] = log[-12:]

    # Written through a temp file: a Stop hook in another session may be reading
    # this exact path, and a half-written goal is an unarmed one.
    target = active_path(root)
    temp = target.with_suffix(".json.tmp")
    try:
        temp.write_text(json.dumps(goal, indent=2, ensure_ascii=False) + "\n")
        temp.replace(target)
    except OSError as exc:
        print(f"could not write {target}: {exc}")
        return 2

    print(f"extended by {format_hours(hours)}" + (f" (from {stamp_utc(old)})" if old else ""))
    for line in timer_lines(root, goal):
        print(line)
    return 0


def mode_status(root: Path) -> int:
    goal = load_json(active_path(root))
    if not goal:
        print("no goal armed")
        return 0
    print(f"goal: {goal.get('goal', '')}")
    held = current_hold(root)
    if held is not None:
        note = held.get("reason") or ""
        print(
            "⏸ ON HOLD"
            + hold_age_text(held)
            + (f" — {note}" if note else "")
            + "   (`--unhold` lifts it; the deadline still releases the goal)"
        )
    roster = owner_sessions(root) or []
    shared = goal_is_shared(root)
    if roster:
        label = "owner session" if len(roster) == 1 else f"owner sessions ({len(roster)})"
        print(f"{label}: " + ", ".join(roster))
    else:
        print("owner session: (unclaimed — the next session to stop claims it)")
    if shared:
        print(
            "  ⭐ SHARED — every session that stops here joins this run "
            "(`--unshare` narrows it back to the roster above)"
        )
    for line in timer_lines(root, goal):
        print(line)

    # ⛔ EVERYTHING ABOUT THE INSTRUMENT PRINTS BEFORE THE CHECKS RUN. The checks
    # are the goal's own shell commands — minutes of builds per Stop —
    # and the one line that says the guard is not running at all used to sit
    # behind them. A diagnostic nobody waits for is a diagnostic nobody reads.
    state = load_json(state_path(root)) or {}
    pending = state.get("pause_once")
    if isinstance(pending, dict):
        live = "expired" if (parse_deadline(pending.get("expires_at")) or now_utc()) <= now_utc() else "pending"
        print(
            f"one-shot pause: {live} (armed {pending.get('armed_at', '?')}"
            + (f", {pending['reason']}" if pending.get("reason") else "")
            + ")"
        )
    if state.get("pauses"):
        print(f"pauses spent: {state['pauses']}, last {state.get('last_pause_at', '?')}")
    print(f"blocks so far: {state.get('blocks', 0)}, stalled: {state.get('stalled', 0)}")
    verdict = state.get("last_verdict")
    stamped = parse_deadline(state.get("last_verdict_at"))
    if verdict:
        ago = f"{(now_utc() - stamped).total_seconds() / 3600.0:.1f}h ago" if stamped else "?"
        print(f"last Stop decided: {verdict}  ({ago})")
    last = stamped or parse_deadline(state.get("last_block_at"))
    if last:
        idle_h = (now_utc() - last).total_seconds() / 3600.0
        note = "  ⚠ THE GUARD MAY NOT BE RUNNING" if idle_h >= 1.0 else ""
        print(f"last Stop check: {idle_h:.1f}h ago{note}")
    else:
        # ⚠ printed rather than skipped: "no state yet" and "the hook has never
        # fired" look the same from here, and the second is the failure.
        print(
            "last Stop check: NEVER — no turn has been checked under this goal. "
            "⚠ if the run is not new, the hook is not reaching the guard."
        )

    return 0


def validate_goal(goal: dict) -> list[str]:
    """Validate goal fields that could disable a release or crash the Stop hook."""
    problems: list[str] = []

    if not str(goal.get("goal") or "").strip():
        problems.append("no `goal` — the text is the whole message the block carries")

    # ⛔ A goal carries no commands. `checks` was removed 2026-08-25; refusing it
    # here is what stops the next agent quietly reintroducing a per-turn build.
    if "checks" in goal:
        problems.append(
            "`checks` is not supported — the guard runs nothing. It says there is "
            "work left in docs/planning; if you want a suite green, run the suite"
        )

    raw_deadline = goal.get("deadline_utc")
    if raw_deadline and parse_deadline(raw_deadline) is None:
        # An invalid deadline must fail arming rather than disable the deadline.
        problems.append(
            f"`deadline_utc` {raw_deadline!r} is not an ISO-8601 timestamp — a "
            "deadline that does not parse is silently NO deadline"
        )

    for field, kind in (
        ("max_stalled_blocks", int),
        ("max_stalled_hours", float),
        ("max_run_hours", float),
    ):
        if field in goal:
            try:
                kind(goal[field])
            except (TypeError, ValueError):
                problems.append(f"`{field}` is not a number")

    return problems


def mode_arm(root: Path, source: str) -> int:
    src = Path(source)
    if not src.is_absolute():
        src = root / source
    goal = load_json(src)
    if goal is None:
        print(f"cannot read a goal from {src}", file=sys.stderr)
        return 2
    problems = validate_goal(goal)
    if problems:
        print(f"refusing to arm {src}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2
    goal_dir(root).mkdir(parents=True, exist_ok=True)
    # Preserve the outgoing goal before replacement. `remove=False` archives it
    # without disarming before the incoming goal overwrites `active.json`.
    if src.resolve() != active_path(root).resolve():
        clear_goal(root, "replaced by --arm", remove=False)
        shutil.copyfile(src, active_path(root))
    state_path(root).unlink(missing_ok=True)
    set_owner(root, "")  # A fresh run is unclaimed; its first Stop takes it.
    print(f"armed: {goal.get('goal', '')}")
    return mode_status(root)


def main() -> int:
    # ⛔ NOT `description=__doc__`. `--help` is read mid-task and owes the
    # operational answer; the module docstring orients whoever opens the FILE,
    # and the incidents behind the rules live in docs/tools/goal-guard.md.
    parser = argparse.ArgumentParser(
        description=(
            "Goal guard: blocks a session's Stop while a goal is armed, so a long "
            "run keeps going. It runs no commands -- only a clock releases it."
        ),
        epilog=(
            "typical use\n"
            "  --status                 what is armed, who holds it, when it releases\n"
            "  --arm goal.json          arm a goal (replaces any current one)\n"
            "  --clear <session-id>     stand down; others keep the goal\n"
            "  --extend 4h              push the deadline out\n"
            "\n"
            "if it will not let you stop\n"
            "  --pause <reason>         stop enforcing for a while\n"
            "  --hold <reason>          stop enforcing until --unhold\n"
            "  --clear-all              disarm it for every session\n"
            "\n"
            "ownership is a ROSTER: several sessions can hold one goal. A bare\n"
            "--clear refuses when more than one does; name your session instead.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--inject", action="store_true", help="SessionStart mode")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--arm", metavar="GOAL_JSON")
    parser.add_argument(
        "--clear",
        nargs="?",
        const="",
        metavar="SESSION_ID",
        help="stand down. With a session id, only that session leaves the roster "
        "and the goal stays armed for the rest. Bare, it disarms the goal for "
        "everyone -- and REFUSES if more than one session holds it.",
    )
    parser.add_argument(
        "--clear-all",
        action="store_true",
        help="disarm for every session, even a shared roster",
    )
    parser.add_argument(
        "--own",
        metavar="SESSION_ID",
        help="bind the armed goal to one session id (transcript basename)",
    )
    parser.add_argument(
        "--disown",
        action="store_true",
        help="unbind the goal; the next session to stop claims it",
    )
    parser.add_argument(
        "--share",
        action="store_true",
        help="let EVERY session that stops in this repository join this run",
    )
    parser.add_argument(
        "--unshare",
        action="store_true",
        help="stop new sessions joining; the current roster stays held",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="take over an orphaned goal (after /clear) and print what it is",
    )
    parser.add_argument(
        "--extend",
        nargs="?",
        const="",
        metavar="DURATION",
        help=(
            "give the armed goal more time: --extend 48h (also 2d, 90m, or an "
            "ISO-8601 timestamp; a bare number is HOURS). Moves deadline_utc AND "
            "max_run_hours together — they are two independent releases and the "
            "earlier one wins. With no argument, just prints the clocks."
        ),
    )
    parser.add_argument(
        "--pause",
        nargs="?",
        const="",
        metavar="REASON",
        help=(
            "let THIS turn end and wait for the human; the goal stays armed and "
            "blocks again at the end of the next turn. Only when asked."
        ),
    )
    parser.add_argument(
        "--hold",
        nargs="?",
        const="",
        metavar="REASON",
        help=(
            "hold the goal until --unhold: every turn may end, the goal stays "
            "armed, and its deadline still releases it. For working on something "
            "together, where a one-shot --pause would need re-arming every turn. "
            "Only when the human asks."
        ),
    )
    parser.add_argument(
        "--unhold",
        action="store_true",
        help="lift a --hold; the goal blocks normally again",
    )
    args = parser.parse_args()

    root = repo_root()

    if args.extend is not None:
        return mode_extend(root, args.extend)
    if args.hold is not None:
        return mode_hold(root, args.hold)
    if args.unhold:
        return mode_unhold(root)
    if args.pause is not None:
        return mode_pause(root, args.pause)
    if args.own:
        # ⭐ ADDS to the roster rather than replacing it, so binding a second
        # session by id does not silently release the first.
        join_owner(root, args.own.strip())
        roster = owner_sessions(root) or []
        print(
            f"goal bound to session {args.own.strip()} — roster is now "
            + ", ".join(roster)
        )
        return 0
    if args.disown:
        set_owner(root, "")
        print("goal unbound — the next session to stop will claim it")
        return 0
    if args.share:
        if load_json(active_path(root)) is None:
            print("no goal armed — nothing to share", file=sys.stderr)
            return 2
        shared_path(root).parent.mkdir(parents=True, exist_ok=True)
        shared_path(root).write_text(
            "every session that finishes a turn in this repository joins this "
            "run's roster and is held to it\n"
        )
        roster = owner_sessions(root) or []
        print(
            "goal SHARED — every session that stops here now joins the roster "
            f"and is held to it (currently {len(roster)}: "
            + (", ".join(roster) if roster else "unclaimed")
            + ")\n⚠ that includes a window somebody opened to ask one thing. "
            "`--unshare` narrows it back to the sessions already on the roster; "
            "`--disown` removes only the session that runs it."
        )
        return 0
    if args.unshare:
        shared_path(root).unlink(missing_ok=True)
        roster = owner_sessions(root) or []
        print(
            "goal NARROWED — no new session joins. Still held: "
            + (", ".join(roster) if roster else "(unclaimed)")
        )
        return 0
    if args.resume:
        return mode_resume(root)
    if args.arm:
        return mode_arm(root, args.arm)
    if args.clear_all:
        clear_goal(root, "cleared by hand for every session")
        print("goal cleared for every session")
        return 0
    if args.clear is not None:
        roster = owner_sessions(root) or []
        if args.clear:
            # ⛔ per-session: drops THIS window and disarms only if it held the
            # goal alone. See `clear_goal`'s `session` argument.
            clear_goal(root, "cleared by hand", session=args.clear.strip())
            return 0
        # A bare clear is ambiguous for a shared roster; require the caller to
        # choose one session or all sessions explicitly.
        if len(roster) > 1:
            print(
                "REFUSING: this goal is held by "
                + str(len(roster))
                + " sessions ("
                + ", ".join(roster)
                + ").\n"
                "A bare --clear would disarm all of them. Either:\n"
                "  --clear <your-session-id>   leave, and let the others keep it\n"
                "  --clear-all                 disarm it for everybody"
            )
            return 1
        clear_goal(root, "cleared by hand")
        print("goal cleared")
        return 0
    if args.status:
        return mode_status(root)

    hook_input = {}
    if not sys.stdin.isatty():
        try:
            raw = sys.stdin.read()
            if raw.strip():
                hook_input = json.loads(raw)
        except (OSError, ValueError):
            hook_input = {}

    if args.inject:
        return mode_inject(root, hook_input)
    return mode_stop(root, hook_input)


def note_crash(root: Path) -> int:
    """Count consecutive crashes, so a broken guard is bounded.

    Returns the new count; any clean `mode_stop` resets it to zero.
    """
    state = load_json(state_path(root)) or {}
    crashes = as_int(state.get("crashes"), 0) + 1
    state["crashes"] = crashes
    state["last_crash_at"] = now_utc().isoformat()
    try:
        goal_dir(root).mkdir(parents=True, exist_ok=True)
        state_path(root).write_text(json.dumps(state, indent=2) + "\n")
    except OSError:
        # Cannot even record it. Treat that as the fuse blowing: a guard that can
        # neither run nor remember that it failed has nothing left to be trusted
        # with, and the alternative is an unbreakable block.
        return MAX_CONSECUTIVE_CRASHES
    return crashes


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        # A crashed guard must never silently release a run: say so loudly and
        # keep blocking, because "the guard broke" is not "the work is done".
        #
        # Bound crash blocking so a broken guard cannot make the repository
        # unusable. The release message explicitly says the goal was not met.
        root = repo_root()
        if active_path(root).exists():
            crashes = note_crash(root)
            if crashes >= MAX_CONSECUTIVE_CRASHES:
                emit(
                    {
                        "systemMessage": (
                            f"Goal guard: RELEASED after crashing {crashes} times "
                            f"in a row ({exc!r}). The goal is NOT met — the guard "
                            f"itself is broken and is standing down so the session "
                            f"is usable. Fix scripts/goal_guard.py, then re-arm."
                        )
                    }
                )
                sys.exit(0)
            emit(
                {
                    "decision": "block",
                    "reason": (
                        f"goal_guard.py crashed ({exc!r}) while a goal was armed "
                        f"({crashes} of {MAX_CONSECUTIVE_CRASHES} consecutive "
                        f"crashes before it stands down). Treating this as NOT "
                        f"MET. FIX THE GUARD FIRST — it is the instrument this "
                        f"run is judged by — then continue the goal."
                    ),
                }
            )
        else:
            print(f"goal_guard: {exc!r}", file=sys.stderr)
        sys.exit(0)
