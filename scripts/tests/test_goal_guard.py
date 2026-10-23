"""Poison tests for the deterministic goal guard.

The guard runs no commands: an armed goal blocks until a CLOCK releases it. What
must not happen is a release for any other reason — a crash, a transcript claim,
or a hand-edited goal file. The suite verifies both the blocking outcome and the
reason surfaced by the guard."""

from __future__ import annotations

import datetime as _dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# The goal guard is a self-contained maintainer tool, outside the default
# `tests/` suite. Run it explicitly after editing the tool:
#     python -m pytest -q scripts/tests

GUARD_SOURCE = Path(__file__).resolve().parents[1] / "goal_guard.py"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def guard_in(repo: Path) -> Path:
    return repo / "scripts" / "goal_guard.py"


@pytest.fixture(scope="session")
def repo_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One committed tiny repo, copied per test instead of rebuilt per test.

    The guard's progress oracle genuinely is Git, so these remain real Git
    repositories. What was expensive was paying five process launches (`init`,
    two `config`s, `add`, `commit`) for every assertion even though every test
    begins from the same commit. A byte-for-byte copy of this tiny repository
    gives each test independent refs/index/worktree while preserving the real
    Git behavior the fixture exists to exercise.
    """
    root = tmp_path_factory.mktemp("goal-guard-template") / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(GUARD_SOURCE, guard_in(root))
    git(root, "init", "-q")
    git(root, "config", "user.email", "guard@test")
    git(root, "config", "user.name", "guard")
    (root / "seed.txt").write_text("seed\n")
    git(root, "add", "seed.txt", "scripts/goal_guard.py")
    git(root, "commit", "-qm", "seed")
    return root


@pytest.fixture()
def repo(tmp_path: Path, repo_template: Path) -> Path:
    """An independent real Git repo starting from the shared committed template."""
    root = tmp_path / "repo"
    shutil.copytree(repo_template, root)
    return root


def arm(repo: Path, **goal) -> None:
    goal.setdefault("goal", "the test goal")
    (repo / ".goal").mkdir(exist_ok=True)
    (repo / ".goal" / "active.json").write_text(json.dumps(goal))


def run(repo: Path, *args: str, stdin: dict | None = None, cwd: Path | None = None) -> dict:
    proc = subprocess.run(
        [sys.executable, str(guard_in(repo)), *args],
        cwd=str(cwd or repo),
        input=json.dumps(stdin or {}),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"the guard must never fail the hook: {proc.stderr}"
    out = proc.stdout.strip()
    return json.loads(out) if out else {}




# ── It can say no ─────────────────────────────────────────────────────────────


def test_a_failing_check_blocks_the_stop(repo: Path) -> None:
    arm(repo)
    out = run(repo)
    assert out.get("decision") == "block"


def test_the_block_carries_the_goal(repo: Path) -> None:
    """A block that says only "not done" sends the agent hunting. The goal text
    IS the message — it is the only thing the guard has to say."""
    arm(repo, goal="work docs/planning continuously")
    assert "work docs/planning continuously" in run(repo)["reason"]


def test_it_tells_the_agent_a_summary_will_not_end_the_turn(repo: Path) -> None:
    """A status report must not be mistaken for completion."""
    arm(repo)
    reason = run(repo)["reason"].lower()
    assert "status report" in reason and "will not end this turn" in reason


# ── The poison cases: a plausible guard would wrongly release here ────────────


def test_a_transcript_claiming_success_does_not_release_it(repo: Path) -> None:
    """THE bug this file exists for.

    `/goal`'s judge reads the conversation, so a well-written "everything is
    done" message clears it. This guard is handed the same claim — through the
    hook payload, including a transcript path whose contents shout success — and
    must not care, because it never reads either.
    """
    transcript = repo / "transcript.jsonl"
    transcript.write_text(
        json.dumps(
            {
                "role": "assistant",
                "text": "All queue items are complete. A1 done, A2 done. "
                "Nothing remains. The goal has been fully met.",
            }
        )
        + "\n"
    )
    arm(repo)
    out = run(
        repo,
        stdin={
            "session_id": "abc",
            "transcript_path": str(transcript),
            "stop_hook_active": False,
        },
    )
    assert out.get("decision") == "block", "prose must not be able to close a goal"


def test_it_keeps_blocking_even_when_stop_hook_active_is_set(repo: Path) -> None:
    """`stop_hook_active` must not bypass an open goal.

    The runtime owns consecutive-block loop protection; this guard keeps
    enforcing the repository checks.
    """
    arm(repo)
    out = run(repo, stdin={"stop_hook_active": True})
    assert out.get("decision") == "block"





def test_a_goal_carrying_checks_cannot_be_armed(repo: Path) -> None:
    """⛔ The guard runs NOTHING. `checks` was removed 2026-08-25 after it spent
    66 hours of cargo across 972 turns without once deciding a verdict; refusing
    the key is what stops the next agent quietly reintroducing a per-turn build."""
    (repo / "empty.json").write_text(
        json.dumps({"goal": "x", "checks": [{"name": "n", "cmd": "true"}]})
    )
    proc = subprocess.run(
        [sys.executable, str(guard_in(repo)), "--arm", "empty.json"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert not (repo / ".goal" / "active.json").exists()


def test_a_crash_while_armed_blocks_rather_than_releases(repo: Path) -> None:
    """`.goal/active.json` exists but is not valid JSON for a goal: the guard
    must not treat its own confusion as permission to stop."""
    (repo / ".goal").mkdir(exist_ok=True)
    (repo / ".goal" / "active.json").write_text('{"goal": "x", "checks": "not-a-list"}')
    out = run(repo)
    assert out.get("decision") == "block"


# ── And it can say yes, exactly once, and then get out of the way ─────────────


def test_an_unarmed_repo_is_completely_untouched(repo: Path) -> None:
    """An unarmed repository must produce no hook output or side effects."""
    assert run(repo) == {}





def test_a_released_goal_is_archived_not_deleted(repo: Path) -> None:
    """What a run was asked to do is evidence for the post-mortem."""
    arm(repo, deadline_utc="2000-01-01T00:00:00Z")
    run(repo)
    archived = list((repo / ".goal").glob("done-*.json"))
    assert len(archived) == 1
    assert json.loads(archived[0].read_text())["_cleared_because"] == "deadline passed"


def test_the_deadline_releases_the_run(repo: Path) -> None:
    """"24 hours" has to mean 24 hours in BOTH directions, or an unattended
    session is pinned against the wall forever."""
    arm(repo, deadline_utc="2000-01-01T00:00:00Z")
    out = run(repo)
    assert "decision" not in out
    assert "deadline passed" in out.get("systemMessage", "")


def test_a_far_deadline_does_not_release_it(repo: Path) -> None:
    arm(repo, deadline_utc="2999-01-01T00:00:00Z")
    out = run(repo)
    assert out.get("decision") == "block"
    assert "remain before this goal releases" not in out["reason"], (
        "a deadline 900 years out is noise in a message the agent reads every turn"
    )


def test_a_near_deadline_says_how_long_is_left(repo: Path) -> None:
    """Within the week it IS decision-shaping: how much is left changes whether
    you start the big item or close the small ones."""
    soon = (
        _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=6)
    ).isoformat()
    arm(repo, deadline_utc=soon)
    assert "remain before this goal releases" in run(repo)["reason"]


# ── The stall escape hatch, and its poison ───────────────────────────────────


def test_it_gives_up_after_blocking_with_no_new_commit(repo: Path) -> None:
    """Blocking forever against an agent that has stopped committing is not
    enforcement, it is a hang. Three strikes and it says so out loud."""
    arm(repo, max_stalled_blocks=3, max_stalled_hours=0)
    decisions = [run(repo).get("decision") for _ in range(4)]
    assert decisions[:3] == ["block", "block", "block"]
    assert decisions[3] is None, "the fourth must release"
    out = run(repo)
    assert "stuck, not finished" in out.get("systemMessage", "")


def test_a_new_commit_resets_the_stall_counter(repo: Path) -> None:
    """The poison for the test above: an agent that IS working must never be
    released early just because the goal is taking a while."""
    arm(repo, max_stalled_blocks=2)
    assert run(repo).get("decision") == "block"
    assert run(repo).get("decision") == "block"

    (repo / "work.txt").write_text("real work\n")
    git(repo, "add", "work.txt")
    git(repo, "commit", "-qm", "did something")

    assert run(repo).get("decision") == "block", "progress buys more time"
    assert run(repo).get("decision") == "block"


def test_blocks_alone_do_not_release_a_run_waiting_on_a_build(repo: Path) -> None:
    """A turn ends every time the agent waits on a long test lane, so a block
    count with no clock released healthy runs mid-validation. Blocks must be
    joined by hours without a commit."""
    arm(repo, max_stalled_blocks=2, max_stalled_hours=4)
    decisions = [run(repo).get("decision") for _ in range(6)]
    assert decisions == ["block"] * 6, "six quick blocks are a wait, not a stall"

    stale = state_of(repo)
    past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=5)
    stale["last_progress_at"] = past.isoformat()
    (repo / ".goal" / "state.json").write_text(json.dumps(stale))
    assert run(repo).get("decision") is None, "five idle hours and many blocks release"


# ── The one-shot pause: it must be a pause and not a door ────────────────────


def state_of(repo: Path) -> dict:
    return json.loads((repo / ".goal" / "state.json").read_text())


def cli(repo: Path, *args: str) -> str:
    """The text-printing modes — `run` above parses stdout as hook JSON."""
    proc = subprocess.run(
        [sys.executable, str(guard_in(repo)), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_a_pause_lets_exactly_this_turn_end(repo: Path) -> None:
    arm(repo, max_stalled_blocks=0)
    assert run(repo).get("decision") == "block"
    cli(repo, "--pause", "Jon asked me to wait")
    out = run(repo)
    assert out.get("decision") is None, "the paused turn must be allowed to end"
    assert "PAUSED" in out.get("systemMessage", "")
    assert "Jon asked me to wait" in out["systemMessage"], "say whose idea it was"


def test_the_goal_is_still_armed_after_a_pause(repo: Path) -> None:
    """A one-shot pause must leave the goal armed for the next turn."""
    arm(repo, max_stalled_blocks=0)
    cli(repo, "--pause")
    run(repo)  # spends it
    assert (repo / ".goal" / "active.json").exists(), "a pause must not disarm"
    assert run(repo).get("decision") == "block", "the very next turn is guarded"
    assert run(repo).get("decision") == "block"


def test_a_pause_is_spent_once_and_cannot_be_re_used(repo: Path) -> None:
    """One ask, one turn. An agent that could re-spend one token would have an
    unbounded exit and the run would end whenever it got tired."""
    arm(repo, max_stalled_blocks=0)
    cli(repo, "--pause")
    assert run(repo).get("decision") is None
    assert "pause_once" not in state_of(repo), "the token is consumed, not kept"
    assert state_of(repo)["pauses"] == 1, "and counted where a human can see it"
    assert run(repo).get("decision") == "block"


def test_an_expired_pause_does_not_release_the_turn(repo: Path) -> None:
    """A token armed at hour 2 and cashed at hour 40 is not "waiting for input",
    it is a delayed release — exactly the shape this guard exists to refuse."""
    arm(repo, max_stalled_blocks=0)
    cli(repo, "--pause")
    stale = state_of(repo)
    past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=5)
    stale["pause_once"]["expires_at"] = past.isoformat()
    (repo / ".goal" / "state.json").write_text(json.dumps(stale))

    assert run(repo).get("decision") == "block"
    assert "pause_once" not in state_of(repo), "and the dead token is cleared"


def test_pausing_an_unarmed_repo_does_nothing(repo: Path) -> None:
    """No goal, no state file: a pause must not leave a token lying around for
    the NEXT run to spend before it has done any work."""
    cli(repo, "--pause")
    assert not (repo / ".goal" / "state.json").exists()


# ── Extending a live run ─────────────────────────────────────────────────────


def cli_raw(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """`cli` asserts rc 0; `--extend` REFUSES bad input with a non-zero rc, and
    refusing is half of what these tests are about."""
    return subprocess.run(
        [sys.executable, str(guard_in(repo)), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=120,
    )


def goal_of(repo: Path) -> dict:
    return json.loads((repo / ".goal" / "active.json").read_text())


def test_extending_moves_both_clocks(repo: Path) -> None:
    """⛔⛔ THE WHOLE REASON THIS IS A COMMAND. Two independent releases end a
    run on time — an absolute deadline and a fuse counted in hours from the first
    block — and the earlier one wins. A hand edit moves the one you can see, and
    the run then releases itself on the old schedule from the one you cannot."""
    arm(repo, deadline_utc="2999-01-01T00:00:00Z", max_run_hours=74)
    assert cli_raw(repo, "--extend", "48h").returncode == 0
    after = goal_of(repo)
    assert after["deadline_utc"] == "2999-01-03T00:00:00Z"
    assert after["max_run_hours"] == 122, "the fuse must move by the same 48 hours"


def test_extending_does_not_forgive_a_stall(repo: Path) -> None:
    """The poison. `--extend` buys TIME, and time is not evidence that work is
    landing. A version that also reset the stall counter would turn every "give
    it another day" into an unbounded silence, which is the failure the stall
    fuse exists for."""
    arm(
        repo,
        deadline_utc="2999-01-01T00:00:00Z",
        max_stalled_blocks=2,
        max_stalled_hours=0,
    )
    assert run(repo).get("decision") == "block"
    assert run(repo).get("decision") == "block"
    assert cli_raw(repo, "--extend", "48h").returncode == 0
    assert run(repo).get("decision") is None, "the stall still releases it"
    assert state_of(repo)["stalled"] >= 2, "and the count was never rewritten"


def test_a_dead_deadline_extends_from_now_not_from_itself(repo: Path) -> None:
    """+48h onto a deadline that lapsed three days ago is still in the past, so
    "extend" would hand back a run that is already over — the shape where the
    command reports success and changes nothing."""
    stale = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=3)).isoformat()
    arm(repo, deadline_utc=stale)
    assert cli_raw(repo, "--extend", "48h").returncode == 0
    extended = _dt.datetime.fromisoformat(goal_of(repo)["deadline_utc"].replace("Z", "+00:00"))
    assert extended > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=47)


def test_a_nonsense_duration_changes_nothing(repo: Path) -> None:
    """A guard file half-written by a rejected command is an UNARMED run."""
    arm(repo, deadline_utc="2999-01-01T00:00:00Z", max_run_hours=74)
    before = (repo / ".goal" / "active.json").read_text()
    proc = cli_raw(repo, "--extend", "next tuesday")
    assert proc.returncode != 0
    assert "ISO-8601" in proc.stdout, "say what it would have accepted"
    assert (repo / ".goal" / "active.json").read_text() == before


def test_a_bare_number_of_hours_is_echoed_as_such(repo: Path) -> None:
    """`--extend 2` is the one input a caller can mean two ways. It means hours,
    and the answer says so rather than leaving them to check the file."""
    arm(repo, deadline_utc="2999-01-01T00:00:00Z")
    proc = cli_raw(repo, "--extend", "2")
    assert goal_of(repo)["deadline_utc"] == "2999-01-01T02:00:00Z"
    assert "2h" in proc.stdout





def test_extending_an_unarmed_repo_arms_nothing(repo: Path) -> None:
    proc = cli_raw(repo, "--extend", "48h")
    assert proc.returncode != 0
    assert not (repo / ".goal" / "active.json").exists()


# ── Context injection, the compaction half ───────────────────────────────────


def test_inject_restates_the_open_items(repo: Path) -> None:
    """`PostCompact` has no `additionalContext` in its schema, so the goal
    cannot be re-injected at the compaction boundary itself. SessionStart plus
    the Stop hook's own reason are the channels that survive."""
    arm(repo, goal="work docs/planning continuously")
    out = run(repo, "--inject", stdin={"hook_event_name": "SessionStart"})
    specific = out["hookSpecificOutput"]
    assert specific["hookEventName"] == "SessionStart"
    assert "work docs/planning continuously" in specific["additionalContext"]





def test_inject_restates_an_armed_goal_that_has_never_been_checked(repo: Path) -> None:
    """With no Stop hook run yet there is no cache, and silence would read as
    'nothing is armed' — the one thing a fresh session must not conclude."""
    arm(repo)
    out = run(repo, "--inject", stdin={"hook_event_name": "SessionStart"})
    assert "GOAL ARMED" in out["hookSpecificOutput"]["additionalContext"]


def test_inject_is_silent_when_unarmed(repo: Path) -> None:
    assert run(repo, "--inject", stdin={"hook_event_name": "SessionStart"}) == {}




def test_a_nested_git_repo_does_not_hide_the_goal(repo: Path) -> None:
    """Nested repositories must not change which repository owns the goal."""
    nested = repo / "tools" / "sub_repo"
    nested.mkdir(parents=True)
    git(nested, "init", "-q")
    git(nested, "config", "user.email", "sub@test")
    git(nested, "config", "user.name", "sub")
    (nested / "f.txt").write_text("x\n")
    git(nested, "add", "f.txt")
    git(nested, "commit", "-qm", "sub seed")

    arm(repo)
    assert run(repo, cwd=nested).get("decision") == "block", (
        "the guard must belong to the repository it is COMMITTED IN, "
        "not to whichever one the working directory happens to be inside"
    )
    # A test that is green through its own motivating case is not coverage, it is furniture.


# ── Background work is NOT a reason to stand down ─────────────────────────────
#
# The guard used to read the transcript for async tool calls that had never
# reported back and stay quiet while any were outstanding. Jon, 2026-08-23:
# *"I often see rando shells that you often just forget about and they just
# exist and are never killed. That pattern happens ALL THE TIME. So the goal
# guard should never be using that as a condition."* An abandoned poll loop
# never reports, so the set was almost never empty and the run was unguarded by
# default — a stand-down that always applies is the inverse of a check that
# cannot fail. `--pause` and `--hold` remain, and they are explicit.


def transcript(repo: Path, *records: dict, name: str = "t.jsonl") -> str:
    path = repo / name
    path.write_text("\n".join(json.dumps(r) for r in records))
    return str(path)


def launched(tool_use_id: str, task_id: str = "task1") -> dict:
    return {
        "type": "assistant",
        "message": {
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": f"Command running in background with ID: {task_id}",
                }
            ]
        },
    }


def test_work_still_in_flight_does_not_buy_silence(repo: Path) -> None:
    """⛔⛔ THE POISON FOR THE WHOLE MECHANISM THAT USED TO LIVE HERE."""
    arm(repo)
    out = run(repo, stdin={"transcript_path": transcript(repo, launched("toolu_A"))})
    assert out.get("decision") == "block", (
        "a launched background task stood the guard down, and forgetting one is "
        "the normal case rather than the exception"
    )


def test_an_unreadable_transcript_still_blocks(repo: Path) -> None:
    arm(repo)
    assert run(repo, stdin={"transcript_path": "/nope/nope.jsonl"})["decision"] == "block"


# ── The full goal text is worth tokens sometimes, not every turn ──────────────


def test_a_repeat_block_drops_the_goal_preamble(repo: Path) -> None:
    arm(repo, goal="THE WHOLE PREAMBLE, " + "thousands of tokens of it. " * 80)
    first = run(repo)["reason"]
    second = run(repo)["reason"]
    assert "THE WHOLE PREAMBLE" in first, "the first block carries the goal"
    assert "THE WHOLE PREAMBLE" not in second, "the second does not repeat it"
    assert len(second) < len(first)


def test_a_repeat_block_still_pushes_the_agent_on(repo: Path) -> None:
    """Shorter must not mean vaguer. The preamble is what drops, never the
    instruction to keep going."""
    arm(repo, goal="THE WHOLE PREAMBLE, " + "thousands of tokens of it. " * 80)
    run(repo)
    second = run(repo)["reason"]
    assert "will not end this turn" in second, "the closing push survives"
    assert ".goal/active.json" in second, "and it says where the full text is"


def test_a_compact_brings_the_whole_goal_back(repo: Path) -> None:
    """The one case that matters. A compact is precisely when the agent has lost
    the goal, so that is when reprinting it is worth the tokens."""
    arm(repo, goal="THE WHOLE PREAMBLE, " + "thousands of tokens of it. " * 80)
    tp = transcript(repo, {"type": "assistant", "message": {"content": []}})
    run(repo, stdin={"transcript_path": tp})
    assert "THE WHOLE PREAMBLE" not in run(repo, stdin={"transcript_path": tp})["reason"]
    later = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(minutes=1)).isoformat()
    tp = transcript(
        repo,
        {"type": "system", "subtype": "compact_boundary", "timestamp": later},
    )
    assert "THE WHOLE PREAMBLE" in run(repo, stdin={"transcript_path": tp})["reason"]


# ── Replacing a goal is not the same as having no receipt for it ──────────────


def test_arming_over_a_live_goal_archives_the_one_it_replaces(repo: Path) -> None:
    """Re-arming over a live goal must archive the replaced goal first."""
    arm(repo, goal="THE GOAL THAT WAS ALREADY RUNNING")
    replacement = repo / "next.json"
    replacement.write_text(
        json.dumps({"goal": "the new one", "deadline_utc": "2099-01-01T00:00:00Z"})
    )
    cli(repo, "--arm", str(replacement))
    archived = [p for p in (repo / ".goal").glob("done-*.json")]
    assert archived, "the replaced goal must leave a receipt"
    assert any(
        "THE GOAL THAT WAS ALREADY RUNNING" in json.loads(p.read_text())["goal"]
        for p in archived
    )


def test_arming_still_installs_the_new_goal(repo: Path) -> None:
    """Archiving the outgoing goal must not disarm the incoming one."""
    arm(repo, goal="the old one")
    replacement = repo / "next.json"
    replacement.write_text(
        json.dumps({"goal": "the new one", "deadline_utc": "2099-01-01T00:00:00Z"})
    )
    cli(repo, "--arm", str(replacement))
    assert json.loads((repo / ".goal" / "active.json").read_text())["goal"] == "the new one"
    assert run(repo)["decision"] == "block", "and the new goal is live"


# ── Repo-specific settings live in the repo, not in the guard ────────────────


def test_a_goal_of_text_and_clocks_alone_still_works(repo: Path) -> None:
    """A port needs no config file and no commands: text plus clocks is a goal."""
    arm(repo)
    assert run(repo)["decision"] == "block"













# ── More than one session can be held by one run ──────────────────────────────


def _stop(repo: Path, session: str) -> dict:
    return run(repo, stdin={"session_id": session, "hook_event_name": "Stop"})


def _cli_raw(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """Like `_cli` but tolerates a non-zero exit — a REFUSAL is a real outcome
    with its own status, and asserting success would make it untestable."""
    return subprocess.run(
        [sys.executable, str(guard_in(repo)), *args],
        cwd=str(repo),
        input="{}",
        capture_output=True,
        text=True,
        timeout=120,
    )


def _roster(repo: Path) -> list[str]:
    owner = repo / ".goal" / "owner"
    return owner.read_text().split() if owner.exists() else []


def test_a_bare_clear_refuses_to_disarm_a_roster_it_does_not_own(repo: Path) -> None:
    """A bare clear must refuse when multiple sessions own the goal.

    Without an explicit session, the guard cannot know which owner should be
    released.
    """
    arm(repo, goal="shared work")
    _cli(repo, "--own", "sess-A")
    _cli(repo, "--own", "sess-B")

    proc = _cli_raw(repo, "--clear")

    assert proc.returncode != 0, "a bare --clear on a shared roster must not succeed"
    assert "REFUS" in proc.stdout.upper()
    assert "sess-A" in proc.stdout and "sess-B" in proc.stdout, (
        "the refusal has to name who is holding it, or the caller cannot act on it"
    )
    assert (repo / ".goal" / "active.json").exists(), "the goal was disarmed anyway"
    assert _roster(repo) == ["sess-A", "sess-B"], "the roster was disturbed"


def test_clearing_by_session_leaves_the_other_holders_armed(repo: Path) -> None:
    """The per-session stand-down: one name leaves, the goal does not."""
    arm(repo, goal="shared work")
    _cli(repo, "--own", "sess-A")
    _cli(repo, "--own", "sess-B")

    _cli(repo, "--clear", "sess-A")

    assert _roster(repo) == ["sess-B"]
    assert (repo / ".goal" / "active.json").exists(), (
        "a session leaving is not the goal ending — sess-B is still working"
    )


def test_the_last_holder_leaving_disarms_the_goal(repo: Path) -> None:
    """⚠ the other half, and without it the fix would strand goals forever: a
    goal nobody holds is not armed, it is litter."""
    arm(repo, goal="shared work")
    _cli(repo, "--own", "sess-A")
    _cli(repo, "--own", "sess-B")

    _cli(repo, "--clear", "sess-A")
    assert (repo / ".goal" / "active.json").exists()
    _cli(repo, "--clear", "sess-B")

    assert not (repo / ".goal" / "active.json").exists(), (
        "the last holder left and the goal stayed armed with nobody to enforce it"
    )
    assert _roster(repo) == []


def test_clear_all_disarms_a_shared_roster_on_purpose(repo: Path) -> None:
    """The escape hatch the refusal points at. Named separately so that ending a
    run for everybody is a thing you TYPE, not a thing you get by accident."""
    arm(repo, goal="shared work")
    _cli(repo, "--own", "sess-A")
    _cli(repo, "--own", "sess-B")

    _cli(repo, "--clear-all")

    assert not (repo / ".goal" / "active.json").exists()
    assert _roster(repo) == []


def test_help_stays_short_enough_for_an_agent_to_read(repo: Path) -> None:
    """⛔ `--help` used to print the module docstring — 296 lines of design
    history — to an agent that was mid-task and wanted to know which flag stops
    the blocking. A reference nobody can skim is a reference nobody reads.

    ⚠ the bound is deliberately loose: this guards the ORDER OF MAGNITUDE, not a
    line count somebody has to keep updating. The docstring itself is untouched
    and still in the file for whoever opens it.
    """
    proc = _cli_raw(repo, "--help")

    lines = proc.stdout.splitlines()
    assert proc.returncode == 0
    assert len(lines) < 90, f"--help is {len(lines)} lines again"
    assert "--clear-all" in proc.stdout, "the way out has to be IN the way out"
    assert "--status" in proc.stdout


def _cli(repo: Path, *args: str) -> str:
    """A management flag prints prose, not a hook decision, so it does not go
    through `run` (which parses stdout as JSON)."""
    proc = subprocess.run(
        [sys.executable, str(guard_in(repo)), *args],
        cwd=str(repo),
        input="{}",
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"{args} failed: {proc.stderr}"
    return proc.stdout


def test_an_unshared_goal_still_holds_exactly_one_session(repo: Path) -> None:
    """An unshared goal must hold only the session that claimed it."""
    arm(repo, max_stalled_blocks=99)
    assert _stop(repo, "first")["decision"] == "block"
    assert _stop(repo, "second") == {}, "an unshared goal held a session that never claimed it"


def test_a_shared_goal_holds_every_session_that_stops(repo: Path) -> None:
    """The capability itself: two sessions, one run, both held."""
    arm(repo, max_stalled_blocks=99)
    assert _stop(repo, "first")["decision"] == "block"
    _cli(repo, "--share")
    assert _stop(repo, "second")["decision"] == "block", "a shared goal let a second session go"
    assert _stop(repo, "third")["decision"] == "block"
    roster = (repo / ".goal" / "owner").read_text().split()
    assert roster == ["first", "second", "third"], f"the roster is not in claim order: {roster}"


def test_sharing_is_an_explicit_act_and_is_reversible(repo: Path) -> None:
    """⚠ a shared run holds windows nobody meant to enlist, so it must be
    possible to narrow it again WITHOUT releasing the sessions already working."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "first")
    _cli(repo, "--share")
    assert _stop(repo, "second")["decision"] == "block"
    _cli(repo, "--unshare")
    assert _stop(repo, "third") == {}, "a narrowed goal still enlisted a new session"
    assert _stop(repo, "second")["decision"] == "block", "narrowing released a session already held"
    assert _stop(repo, "first")["decision"] == "block"


def test_disown_removes_only_the_session_that_runs_it(repo: Path) -> None:
    """⛔ the multi-session failure that would be worst: one lane finishing and
    silently releasing the other."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "first")
    _cli(repo, "--share")
    _stop(repo, "second")
    _cli(repo, "--own", "second")  # idempotent; `second` is already on the roster
    roster = (repo / ".goal" / "owner").read_text().split()
    assert roster == ["first", "second"], f"--own duplicated or replaced: {roster}"
    assert _stop(repo, "first")["decision"] == "block"
    assert _stop(repo, "second")["decision"] == "block"


def test_own_adds_a_second_session_rather_than_replacing_the_first(repo: Path) -> None:
    """`--own` used to REPLACE, so binding a second lane released the first
    without saying so."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "first")
    _cli(repo, "--own", "second")
    assert _stop(repo, "first")["decision"] == "block", "--own released the session already held"
    assert _stop(repo, "second")["decision"] == "block", "--own did not bind the new session"


def test_clearing_a_run_takes_its_share_marker_with_it(repo: Path) -> None:
    """⛔ a stale marker would make the NEXT goal armed here hold every window in
    the repository without anybody asking for it."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "first")
    _cli(repo, "--share")
    _cli(repo, "--clear")
    assert not (repo / ".goal" / "shared").exists(), "the share marker outlived its run"
    arm(repo, max_stalled_blocks=99)
    assert _stop(repo, "a")["decision"] == "block"
    assert _stop(repo, "b") == {}, "a cleared run's sharing leaked into the next goal"


# ── A session id rotates; the roster does not follow it ───────────────────────
#
# A compact or a resume opens a new transcript under a new id, and the goal stays
# bound to one that will never stop again: `mode_stop` returns before doing
# anything and SessionStart says nothing, so the run is armed and enforcing on
# nobody. The runtime's own handover names the previous transcript in the first
# records of the new one, which is what these read.


CONTINUED = "6a4e37e1-38c1-4f74-9cf0-71df82473012"
ROTATED = "4e1ecff1-a997-4db8-b045-62f34919b129"


def continuation(repo: Path, previous: str, name: str) -> str:
    """A transcript whose opening records carry the runtime's handover line."""
    return transcript(
        repo,
        {
            "type": "user",
            "message": {
                "content": "This session is being continued from a previous "
                "conversation... read the full transcript at: "
                f"/home/agent/.claude/projects/-x-/{previous}.jsonl"
            },
        },
        name=name,
    )


def test_the_same_conversation_under_a_new_id_inherits_the_run(repo: Path) -> None:
    arm(repo, max_stalled_blocks=99)
    _stop(repo, CONTINUED)
    assert _roster(repo) == [CONTINUED]

    out = run(
        repo,
        stdin={
            "session_id": ROTATED,
            "hook_event_name": "Stop",
            "transcript_path": continuation(repo, CONTINUED, f"{ROTATED}.jsonl"),
        },
    )
    assert out.get("decision") == "block", "a compact must not release the run"
    assert _roster(repo) == [ROTATED], (
        "the rotated id will never stop again; leaving it on the roster only "
        "makes a later --clear ambiguous"
    )


def test_a_stranger_window_still_does_not_inherit_the_run(repo: Path) -> None:
    """⛔ THE POISON. Inheritance is proof of continuation, not a way for any new
    window to take a goal it is not doing — that is what `--share` is for."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, CONTINUED)
    assert _stop(repo, ROTATED) == {}, "a window with no continuation took the run"
    assert _roster(repo) == [CONTINUED]


def test_session_start_says_so_when_a_goal_is_armed_but_not_held(repo: Path) -> None:
    """Silence is how an orphan stays an orphan: nothing distinguished "somebody
    else holds this" from "the guard is enforcing on nobody"."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, CONTINUED)
    out = run(repo, "--inject", stdin={"session_id": "some-other-window"})
    message = out.get("systemMessage", "")
    assert "ARMED" in message and CONTINUED in message
    assert "--resume" in message, "the notice has to say how to take it over"
    assert "additionalContext" not in json.dumps(out), (
        "a window that does not hold the run must not be given its work"
    )




# ── A quiet exit that leaves no trace is the bug, not the tidy path ───────────


def test_every_quiet_stand_down_records_what_it_decided(repo: Path) -> None:
    """⛔⛔ THE INVARIANT BEHIND BOTH 2026-08-23 DEFECTS. A bare `return 0` wrote
    nothing, so "the guard decided to stand down" and "the hook never ran" were
    the same observation from outside — no state changed either way."""
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "holder")
    assert "blocked" in state_of(repo)["last_verdict"]

    assert _stop(repo, "a-stranger") == {}, "a stranger must still be untouched"
    verdict = state_of(repo)["last_verdict"]
    assert "not this session" in verdict and "holder" in verdict, (
        "the run enforcing on nobody has to be readable from the state file"
    )


def test_status_reads_the_last_decision_back(repo: Path) -> None:
    arm(repo, max_stalled_blocks=99)
    _stop(repo, "holder")
    out = cli(repo, "--status")
    assert "last Stop decided: blocked:" in out
