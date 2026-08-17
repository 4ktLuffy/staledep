"""Argument provenance: which earlier tool output determined this call's arguments.

Effect typing alone misses a whole class of TOCTOU window. In AgentDojo's
banking/user_task_0 the agent calls read_file, then send_money with an amount and
recipient taken *from that file*. No shared resource links them under state
typing, yet swapping the file between the two calls redirects the payment. The
dependency is data-flow, not state.

This module executes a call sequence, captures each output, and links a later
call's argument values back to the earlier output they came from. Those links
turn into TOCTOU windows exactly as state dependencies do.

Matching is deliberately conservative: only values specific enough that a
coincidental match is implausible are linked, because a false provenance edge
invents a vulnerability that is not there.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# A value must be at least this distinctive to count as evidence of data-flow.
# Audit finding: 6 chars of prose matched coincidentally, and bare small integers
# matched almost anything ("3rd most active user" linked via the digit 3).
_MIN_STR_LEN = 8
_MIN_SHORT_STR_LEN = 5          # allowed only if identifier-like (see below)
_MIN_NUMERIC_DIGITS = 4         # or a fractional part
_NUMERIC = re.compile(r"-?\d+(?:\.\d+)?")
_IDENTIFIERISH = re.compile(r"[@._\-/\d]")


def _numeric_is_distinctive(raw: str) -> bool:
    """Reject numbers too common to be evidence of data-flow.

    A bare 1, 2 or 3 appears in nearly every output. Require either enough
    digits to be an identifier (IBAN, id, year) or a fractional part (a money
    amount, which is what actually flows between financial calls).
    """
    if "." in raw:
        return True
    return len(raw.lstrip("-").lstrip("0")) >= _MIN_NUMERIC_DIGITS


@dataclass(frozen=True)
class ProvenanceLink:
    """A later call's argument traced back to an earlier call's output."""
    source_idx: int
    source_tool: str
    sink_idx: int
    sink_tool: str
    arg_name: str
    value: str

    def __str__(self) -> str:
        return (
            f"{self.source_tool}@{self.source_idx} -> "
            f"{self.sink_tool}@{self.sink_idx} via {self.arg_name}={self.value!r}"
        )


def _normalise_numbers(text: str) -> set[str]:
    """Numbers compared by value, so 98.70 in a file matches 98.7 in an argument.

    Only numbers distinctive enough to be evidence are kept -- see
    `_numeric_is_distinctive`.
    """
    out: set[str] = set()
    for m in _NUMERIC.findall(text):
        if not _numeric_is_distinctive(m):
            continue
        try:
            f = float(m)
        except ValueError:
            continue
        out.add(repr(round(f, 6)))
    return out


def _distinctive_values(value: Any) -> set[str]:
    """Extract argument values distinctive enough to serve as provenance evidence."""
    out: set[str] = set()
    if isinstance(value, bool) or value is None:
        return out
    if isinstance(value, (int, float)):
        # Bare small integers (counts, indexes) match far too easily.
        if isinstance(value, int) and abs(value) < 1000:
            return out
        out.add(repr(round(float(value), 6)))
        return out
    if isinstance(value, str):
        s = value.strip()
        # Long strings stand on their own; short ones only if they look like an
        # identifier (email, IBAN, filename, id) rather than prose.
        if len(s) >= _MIN_STR_LEN or (
            len(s) >= _MIN_SHORT_STR_LEN and _IDENTIFIERISH.search(s)
        ):
            out.add(s.lower())
        out |= _normalise_numbers(s)
        return out
    if isinstance(value, (list, tuple, set)):
        for v in value:
            out |= _distinctive_values(v)
        return out
    if isinstance(value, dict):
        for v in value.values():
            out |= _distinctive_values(v)
    return out


_TOKEN = re.compile(r"[A-Za-z0-9]{5,}")
_MIN_TOKEN_MATCHES = 2      # one shared word is coincidence; two is data-flow
_DISTINCTIVE_TOKEN_LEN = 7  # at least one match must be a substantial word


def _tokens(value: Any) -> set[str]:
    """Component words of a string argument.

    Recall audit finding: agents frequently *synthesise* arguments rather than
    copying them. "Alice's hobby: Painting" never appears verbatim in the inbox
    that supplied it, so whole-string matching missed the data-flow entirely.
    Matching component tokens catches it, guarded by a two-token minimum so a
    single shared common word cannot manufacture a link.
    """
    if not isinstance(value, str):
        return set()
    return {t.lower() for t in _TOKEN.findall(value)}


def _token_match(tokens: set[str], haystack: str) -> bool:
    hits = {t for t in tokens if t in haystack}
    if len(hits) < _MIN_TOKEN_MATCHES:
        return False
    return any(len(t) >= _DISTINCTIVE_TOKEN_LEN for t in hits)


def _output_haystack(output: Any) -> tuple[str, set[str]]:
    """Render an output as searchable text plus its numeric values."""
    text = str(output).lower()
    return text, _normalise_numbers(text)


def trace_from_log(
    steps: list[tuple[str, dict, Any]],
    errored: set[int] | None = None,
) -> list[ProvenanceLink]:
    """Compute provenance from an already-executed trajectory.

    `steps` is an ordered list of (tool_name, args, output). Unlike `trace`,
    nothing is executed -- these are the real outputs the agent actually saw,
    which is what we want when analysing recorded runs.

    `errored` holds indices whose call failed. Their output is an error string,
    not state, so they are excluded as provenance sources: a value "matching" an
    error message is coincidence, not data-flow.
    """
    errored = errored or set()
    links: list[ProvenanceLink] = []
    outputs: list[tuple[int, str, str, set[str]]] = []

    for idx, (name, kwargs, output) in enumerate(steps):
        for arg_name, arg_value in (kwargs or {}).items():
            wanted = _distinctive_values(arg_value)
            toks = _tokens(arg_value)
            if not wanted and not toks:
                continue
            # Nearest-source attribution: scan backwards so the freshest check
            # is credited. Scanning forwards credited the earliest read, which
            # inflated window spans.
            for src_idx, src_tool, src_text, src_nums in reversed(outputs):
                direct = next((w for w in wanted if (w in src_text) or (w in src_nums)), None)
                if direct is not None or _token_match(toks, src_text):
                    links.append(ProvenanceLink(
                        source_idx=src_idx, source_tool=src_tool,
                        sink_idx=idx, sink_tool=name,
                        arg_name=arg_name, value=str(arg_value),
                    ))
                    break

        if idx not in errored:
            text, nums = _output_haystack(output)
            outputs.append((idx, name, text, nums))

    return links


def trace(
    calls: list[tuple[str, dict]],
    runtime,
    env,
) -> tuple[list[ProvenanceLink], list[str]]:
    """Execute `calls` in order, linking each call's arguments to earlier outputs.

    Returns (links, errors). Execution mutates `env`, so pass a copy if the
    caller needs the original.
    """
    links: list[ProvenanceLink] = []
    errors: list[str] = []
    outputs: list[tuple[int, str, str, set[str]]] = []  # idx, tool, text, numbers

    for idx, (name, kwargs) in enumerate(calls):
        # Link this call's arguments to any earlier output containing them.
        for arg_name, arg_value in (kwargs or {}).items():
            wanted = _distinctive_values(arg_value)
            if not wanted:
                continue
            for src_idx, src_tool, src_text, src_nums in outputs:
                hit = next(
                    (w for w in wanted if (w in src_text) or (w in src_nums)),
                    None,
                )
                if hit is not None:
                    links.append(ProvenanceLink(
                        source_idx=src_idx, source_tool=src_tool,
                        sink_idx=idx, sink_tool=name,
                        arg_name=arg_name, value=str(arg_value),
                    ))
                    break  # nearest-source attribution: one edge per argument

        result, err = runtime.run_function(env, name, kwargs or {}, raise_on_error=False)
        if err:
            errors.append(f"{idx}:{name}: {err}")
        text, nums = _output_haystack(result)
        outputs.append((idx, name, text, nums))

    return links, errors
