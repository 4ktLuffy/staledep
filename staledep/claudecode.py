"""Adapter for real Claude Code session transcripts.

AgentDojo is a benchmark: synthetic environments, scripted tasks, a fixed tool
catalog. This reads trajectories from an agent doing actual work -- editing real
files, running real commands -- which is the only way to find out whether the
detector says anything about live systems or only about fixtures.

The read-then-act hazard is genuinely present here, and Claude Code itself
treats it as real: the Edit tool refuses to run unless the file was Read first
in the same session. That guard exists because editing a file you read earlier,
which changed in between, is a live correctness problem. So this is not a
contrived mapping -- it is the same hazard the tool was built to prevent.

CONFIDENTIALITY. Transcripts contain whatever the user was working on. Provenance
matching reads argument values and tool output, so only projects whose content is
safe to inspect should ever be passed here. Selection is the caller's
responsibility and is deliberately not defaulted.
"""

from __future__ import annotations

import json
import pathlib

from .effects import Effect, Risk
from .trajectory import Step

_r = frozenset


#: Claude Code's tool catalog, typed the same way as an AgentDojo suite.
#:
#: "workspace.files" is the working tree. "shell" is arbitrary command effect --
#: Bash can do anything, which is why it is HIGH and why its binding is unknown.
#: "web" is attacker-influenceable: a fetched page is third-party content.
CLAUDE_CODE: dict[str, Effect] = {
    # reads
    "Read":       Effect(Risk.READ,  reads=_r({"workspace.files"})),
    "Glob":       Effect(Risk.READ,  reads=_r({"workspace.files"})),
    "Grep":       Effect(Risk.READ,  reads=_r({"workspace.files"})),
    "NotebookRead": Effect(Risk.READ, reads=_r({"workspace.files"})),
    "WebFetch":   Effect(Risk.READ,  reads=_r({"web"})),
    "WebSearch":  Effect(Risk.READ,  reads=_r({"web"})),
    "TodoRead":   Effect(Risk.READ,  reads=_r({"todo"})),

    # writes
    "Edit":       Effect(Risk.HIGH,  reads=_r({"workspace.files"}),
                                     writes=_r({"workspace.files"})),
    "MultiEdit":  Effect(Risk.HIGH,  reads=_r({"workspace.files"}),
                                     writes=_r({"workspace.files"})),
    "NotebookEdit": Effect(Risk.HIGH, reads=_r({"workspace.files"}),
                                      writes=_r({"workspace.files"})),
    # Write does NOT require a prior Read and overwrites unconditionally
    "Write":      Effect(Risk.HIGH,  reads=_r({"workspace.files"}),
                                     writes=_r({"workspace.files"})),
    "Bash":       Effect(Risk.HIGH,  reads=_r({"workspace.files", "shell"}),
                                     writes=_r({"workspace.files", "shell"})),
    "TodoWrite":  Effect(Risk.WRITE, reads=_r({"todo"}), writes=_r({"todo"})),
}

#: Who can move each resource between a check and a use.
CLAUDE_CODE_WRITERS = {
    # another process, a build, a watcher, a second agent session, or the user
    # in their editor -- all write the tree while an agent is working in it
    "workspace.files": "agent",
    "shell":           "agent",
    "web":             "untrusted",   # third-party pages
    "todo":            "user",
}


def load_session(path: str | pathlib.Path) -> tuple[list[Step], set[int]]:
    """Parse one .jsonl transcript into staledep's Step sequence.

    Turn identity comes from the assistant message uuid: several tool_use blocks
    in one assistant message were composed together, so a later one cannot have
    consumed an earlier one's result. That is the same rule applied to AgentDojo
    and it matters more here, because Claude Code batches calls routinely.
    """
    results: dict[str, tuple[str, bool]] = {}      # tool_use_id -> (text, errored)
    calls: list[tuple[str, str, dict, str]] = []   # (id, name, args, turn_key)

    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        try:
            rec = json.loads(line)
        except Exception:
            continue
        msg = rec.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, list):
            continue

        if msg.get("role") == "assistant":
            turn = rec.get("uuid") or ""
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    calls.append((block.get("id", ""), block.get("name", ""),
                                  block.get("input") or {}, turn))
        elif msg.get("role") == "user":
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    body = block.get("content")
                    if isinstance(body, list):
                        body = " ".join(b.get("text", "") if isinstance(b, dict) else str(b)
                                        for b in body)
                    results[block.get("tool_use_id", "")] = (
                        str(body or ""), bool(block.get("is_error")))

    steps: list[Step] = []
    errored: set[int] = set()
    turn_ids: dict[str, int] = {}
    for cid, name, args, turn_key in calls:
        if turn_key not in turn_ids:
            turn_ids[turn_key] = len(turn_ids)
        out, failed = results.get(cid, ("", False))
        idx = len(steps)
        if failed:
            errored.add(idx)
        steps.append(Step(idx=idx, turn=turn_ids[turn_key], tool=name,
                          args=args, output=out, errored=failed))
    return steps, errored


def register() -> None:
    """Make the Claude Code catalog available to the detector as a suite."""
    from . import effects
    effects.SUITES["claude_code"] = CLAUDE_CODE
    effects.RESOURCE_WRITERS["claude_code"] = {
        k: effects.Writer(v) for k, v in CLAUDE_CODE_WRITERS.items()
    }
