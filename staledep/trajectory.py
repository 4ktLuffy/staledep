"""Extract executed tool sequences from AgentDojo message logs.

Ground-truth labelling says which tasks *could* expose a window. This module
works on what an agent actually did, which is what any enforcement claim would
have to move. Figures from arXiv:2508.17155 are not directly comparable:
different criterion, task subset, and counting unit.

TURN IDENTITY IS LOAD-BEARING. An assistant message may emit several tool calls
at once. Those calls are issued together, so a later one in the same message
CANNOT have consumed an earlier one's output -- the model had not seen it. A
flat call list loses that fact and manufactures dependencies: verified, a single
message containing read_file and send_money produced a provenance link claiming
the payment came from the file. Every step therefore carries its turn index, and
lineage refuses to link within a turn.

SINK EXECUTION STATUS is likewise carried. An action that raised did not commit,
and an uncommitted action is not an exploited use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Step:
    """One executed tool call, with the provenance-relevant context."""
    idx: int          # position in the flat sequence
    turn: int         # which assistant message emitted it
    tool: str
    args: dict
    output: Any
    errored: bool     # the call raised; it did not commit

    def as_tuple(self) -> tuple[str, dict, Any]:
        return (self.tool, self.args, self.output)


def steps_from_messages(messages: list[dict]) -> tuple[list[Step], set[int]]:
    """Return the executed steps in order, plus the indices that errored.

    Results are matched to calls by tool_call_id where available, falling back
    to the first unconsumed result for that tool. Errored calls are kept: the
    agent still issued them, and whether they committed is recorded rather than
    inferred.
    """
    # id -> QUEUE of results, not a single value. A model may reuse a
    # tool_call_id across different calls (gpt-4-0125-preview does), and a plain
    # dict lets the second result overwrite the first, so BOTH calls resolve to
    # the later output. That silently attributes a write's confirmation to an
    # earlier read and corrupts every provenance link from that step.
    outputs_by_id: dict[str, list[tuple[Any, bool]]] = {}
    ordered_results: list[tuple[str, dict, Any, bool]] = []

    for msg in messages:
        if msg.get("role") != "tool":
            continue
        call = msg.get("tool_call") or {}
        cid = msg.get("tool_call_id") or call.get("id")
        content = msg.get("content")
        if isinstance(content, list):  # some providers use content blocks
            content = " ".join(
                b.get("content", "") if isinstance(b, dict) else str(b) for b in content
            )
        failed = bool(msg.get("error"))
        if cid:
            outputs_by_id.setdefault(cid, []).append((content, failed))
        ordered_results.append((call.get("function", ""), call.get("args") or {},
                                content, failed))

    steps: list[Step] = []
    errored: set[int] = set()
    turn = -1
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        calls = msg.get("tool_calls") or []
        if not calls:
            continue
        turn += 1                       # one turn per assistant message that acts
        for call in calls:
            name = call.get("function")
            if not name:
                continue
            args = call.get("args") or {}
            cid = call.get("id")
            output, failed = None, False
            queue = outputs_by_id.get(cid) if cid else None
            if queue:
                output, failed = queue.pop(0)     # consume in emission order
            if output is None:
                for i, (rn, _, rout, rfail) in enumerate(ordered_results):
                    if rn == name:
                        output, failed = rout, rfail
                        ordered_results.pop(i)
                        break
            idx = len(steps)
            if failed:
                errored.add(idx)
            steps.append(Step(idx=idx, turn=turn, tool=name, args=args,
                              output=output, errored=failed))

    return steps, errored


def tool_names(steps: list[Step]) -> list[str]:
    return [s.tool for s in steps]


def committed(steps: list[Step]) -> list[bool]:
    """Per-step: did this call actually commit? An action that raised did not."""
    return [not s.errored for s in steps]
