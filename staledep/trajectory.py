"""Extract executed tool sequences from AgentDojo message logs.

Ground-truth labelling says which tasks *could* expose a window. This module
works on what an agent *actually did*, which is what any enforcement claim would
have to move. Note that figures from arXiv:2508.17155 are not directly
comparable: different criterion, task subset, and counting unit.

A recorded run interleaves assistant messages carrying tool_calls with tool
messages carrying the corresponding output, matched by tool_call_id.
"""

from __future__ import annotations

from typing import Any


def steps_from_messages(messages: list[dict]) -> list[tuple[str, dict, Any]]:
    """Return the executed (tool_name, args, output) sequence, in order.

    Results are matched to calls by tool_call_id where available, falling back
    to the tool message's embedded tool_call. Calls that errored are kept: the
    agent still saw a response and may have acted on it.
    """
    outputs_by_id: dict[str, Any] = {}
    errored_ids: set[str] = set()
    ordered_results: list[tuple[str, dict, Any]] = []

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
        if cid:
            outputs_by_id[cid] = content
            if msg.get("error"):
                errored_ids.add(cid)
        ordered_results.append((call.get("function", ""), call.get("args") or {}, content))

    steps: list[tuple[str, dict, Any]] = []
    errored: set[int] = set()
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        for call in msg.get("tool_calls") or []:
            name = call.get("function")
            if not name:
                continue
            args = call.get("args") or {}
            cid = call.get("id")
            output = outputs_by_id.get(cid) if cid else None
            if output is None:
                # No id match: fall back to the first unconsumed result for this tool.
                for i, (rn, _, rout) in enumerate(ordered_results):
                    if rn == name:
                        output = rout
                        ordered_results.pop(i)
                        break
            if cid and cid in errored_ids:
                errored.add(len(steps))
            steps.append((name, args, output))

    return steps, errored


def tool_names(steps: list[tuple[str, dict, Any]]) -> list[str]:
    return [name for name, _, _ in steps]
