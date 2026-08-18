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

#: A calendar year is four digits, so the digit-count test above admitted it as
#: an identifier. It is the opposite: a constant of the corpus. Measured, 96.4%
#: of all numeric-rule matches were a bare year and 706 of 808 were literally
#: 2024 -- every date argument in the workspace suite "matched" every earlier
#: output that mentioned any 2024 date. That is co-occurrence, not data-flow.
_YEARLIKE = re.compile(r"^(?:19|20)\d\d$")
#: What the year matches were standing in for. A full date IS specific enough to
#: be evidence, and is usually present in both output and argument -- but a
#: timestamp argument ("2024-05-19 16:00") is not a substring of a date-only
#: output, so whole-string matching missed it and the year caught it by accident.
#: Extracting the date component finds the same links for the right reason.
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _numeric_is_distinctive(raw: str) -> bool:
    """Reject numbers too common to be evidence of data-flow.

    A bare 1, 2 or 3 appears in nearly every output. Require either enough
    digits to be an identifier (IBAN, id) or a fractional part (a money amount,
    which is what actually flows between financial calls). Years are excluded
    explicitly: they pass the digit test and carry no information.
    """
    if "." in raw:
        return True
    body = raw.lstrip("-").lstrip("0")
    if _YEARLIKE.match(body):
        return False
    return len(body) >= _MIN_NUMERIC_DIGITS


@dataclass(frozen=True)
class ProvenanceLink:
    """A later call's argument traced back to an earlier call's output."""
    source_idx: int
    source_tool: str
    sink_idx: int
    sink_tool: str
    arg_name: str
    value: str
    rule: str = "direct"     # "direct" | "date" | "numeric" | "token"

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
        out |= {d for d in _DATE.findall(s)}
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
    steps,
    errored: set[int] | None = None,
) -> list[ProvenanceLink]:
    """Compute provenance from an already-executed trajectory.

    `steps` may be a list of `staledep.trajectory.Step` (preferred) or of raw
    (tool, args, output) tuples. Nothing is executed -- these are the real
    outputs the agent saw.

    Two exclusions, both necessary for a link to mean anything:

    SAME-TURN. An assistant message can emit several calls at once. A later call
    in the SAME message cannot have consumed an earlier one's output, because
    the model had not seen it when it composed them. Verified: one message
    containing read_file and send_money produced a link claiming the payment
    came from the file. Without turn identity this fabricates dependencies
    wherever a trajectory batches calls. Tuple input has no turn information, so
    the exclusion cannot be applied -- pass Step objects.

    ERRORED SOURCES. A failed call's output is an error string, not state; a
    value "matching" it is coincidence.
    """
    errored = errored or set()
    links: list[ProvenanceLink] = []
    outputs: list[tuple[int, str, str, set[str], int]] = []   # + turn

    from .signals import normalise
    norm = [(s.idx, s.turn, s.tool, s.args, s.output) for s in normalise(steps, errored)]

    for idx, turn, name, kwargs, output in norm:
        for arg_name, arg_value in (kwargs or {}).items():
            # Longest first, so the most specific matching value is the one
            # credited. `wanted` is a set, and Python randomises string hashing
            # per process, so an arbitrary scan order made which value matched --
            # and therefore which rule was recorded -- differ between runs on
            # identical input. An audit cannot rest on that.
            wanted = sorted(_distinctive_values(arg_value), key=len, reverse=True)
            toks = _tokens(arg_value)
            if not wanted and not toks:
                continue
            # Nearest-source attribution: scan backwards so the freshest check
            # is credited. Scanning forwards credited the earliest read, which
            # inflated window spans.
            for src_idx, src_tool, src_text, src_nums, src_turn in reversed(outputs):
                # Same-turn calls were composed together; the sink could not have
                # seen this output. Skip unless turn information is unavailable.
                if turn >= 0 and src_turn >= 0 and src_turn == turn:
                    continue
                literal = next((w for w in wanted if w in src_text), None)
                numeric = next((w for w in wanted if w in src_nums), None)
                if literal is not None:
                    # Tagged apart from `direct` so the per-rule precision audit
                    # can see it. It is a literal substring match like any other,
                    # but of a component rather than the whole argument.
                    rule = "date" if _DATE.fullmatch(literal) else "direct"
                elif numeric is not None:
                    rule = "numeric"
                elif _token_match(toks, src_text):
                    rule = "token"
                else:
                    continue
                links.append(ProvenanceLink(
                    source_idx=src_idx, source_tool=src_tool,
                    sink_idx=idx, sink_tool=name,
                    arg_name=arg_name, value=str(arg_value), rule=rule,
                ))
                break

        if idx not in errored:
            text, nums = _output_haystack(output)
            outputs.append((idx, name, text, nums, turn))

    return links


def trace(calls: list[tuple[str, dict]], runtime, env):
    """Execute `calls`, then delegate to `trace_from_log`.

    This used to be a second, divergent implementation. It scanned sources
    forward (crediting the EARLIEST rather than the nearest) and recorded
    errored outputs as lineage sources -- both bugs that were fixed in
    `trace_from_log` and left here, while `label_suites.py` went on calling this
    one. A public API that disagrees with the evaluated path is worse than no
    public API, so it now executes and delegates rather than duplicating.

    Ground-truth call lists have no turn structure, so same-turn exclusion
    cannot apply here; each call is treated as its own turn, which is the
    correct reading of a sequential ground truth.

    Returns (links, errors). Execution mutates `env`; pass a copy if needed.
    """
    from .trajectory import Step

    steps: list[Step] = []
    errors: list[str] = []
    for idx, (name, kwargs) in enumerate(calls):
        result, err = runtime.run_function(env, name, kwargs or {}, raise_on_error=False)
        if err:
            errors.append(f"{idx}:{name}: {err}")
        steps.append(Step(idx=idx, turn=idx, tool=name, args=kwargs or {},
                          output=result, errored=bool(err)))

    errored = {s.idx for s in steps if s.errored}
    return trace_from_log(steps, errored), errors
