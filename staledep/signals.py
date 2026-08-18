"""The rules every lineage signal must take a position on, and one input adapter.

THREE BUGS, ONE CAUSE. Each of these shipped, produced confident numbers, and was
found only by auditing the code a turn later:

  trace() vs trace_from_log()   trace() credited the EARLIEST source rather than
                                the nearest, and accepted errored outputs as
                                lineage. Both were fixed in one and left in the
                                other, while label_suites.py called the broken one.

  trace_numeric() tuple steps   It read st.tool directly, so every caller passing
                                raw tuples raised AttributeError. The seeded
                                recall harness passes tuples, so numeric lineage
                                had NEVER been exercised against the classes it
                                was written to cover -- and `aggregate` was
                                published as zero-coverage on that basis.

  absence.py invalidation       Shipped without a supersession rule, though
                                find_windows had carried the equivalent rule for
                                positive checks all along. All nine danger-set
                                entries it produced were the same false positive:
                                the agent retried, found the file, and acted on
                                what it found.

The common cause is not carelessness about any one rule. It is that each signal
was written as a NEW code path that happened to re-implement most of a sibling,
so whatever the sibling had learned was inherited only by whoever remembered it.
Nothing in the codebase made an omission visible.

This module is the fix. `normalise` is the single input adapter -- previously
hand-rolled three times. `RULES` names every invariant a signal can hold, and
`DECLARED` records each signal's position on each one WITH a justification.
tests/test_signal_contract.py fails if a signal does not declare, so a new signal
cannot be merged silently missing what its siblings know.

Declaring N/A is a legitimate answer. Forcing every signal to behave identically
would be worse than the disease: these signals genuinely differ, and the goal is
that every difference is a decision on the record rather than an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormStep:
    """One executed call, however the caller supplied it."""
    idx: int
    turn: int
    tool: str
    args: dict
    output: Any
    errored: bool


def normalise(steps, errored: set[int] | None = None) -> list[NormStep]:
    """Accept `Step` objects or raw (tool, args, output) tuples. One adapter.

    Tuple input carries no turn structure, so each call is treated as its own
    turn -- the correct reading of a sequential ground truth, and the reading
    that lets same-turn exclusion be a no-op there rather than silently wrong.
    """
    errored = errored or set()
    out: list[NormStep] = []
    for pos, st in enumerate(steps):
        if hasattr(st, "tool"):
            out.append(NormStep(st.idx, st.turn, st.tool, st.args or {},
                                st.output, st.idx in errored or bool(getattr(st, "errored", False))))
        else:
            tool, args, output = st[0], st[1] or {}, st[2]
            out.append(NormStep(pos, pos, tool, args, output, pos in errored))
    return out


#: Every invariant a signal can hold. Adding one here forces every signal to
#: declare against it, which is the entire point.
RULES = {
    "tuple-input":
        "Accepts raw (tool, args, output) tuples as well as Step objects, so a "
        "caller cannot silently exercise nothing.",
    "same-turn":
        "Refuses to link calls emitted by one assistant message: the sink had "
        "not seen the source's output when it was composed.",
    "errored-source":
        "Refuses a failed call's output as evidence. An error string is not "
        "state, and matching against it is coincidence.",
    "nearest-source":
        "Credits the freshest qualifying source rather than the earliest, so "
        "window spans are not inflated.",
    "supersession":
        "A later observation of the same resource cancels an earlier one: a "
        "check is only load-bearing while it is the most recent information.",
}

#: Each signal's position on each rule. "yes" means it holds; anything else is a
#: justification for why it does not, and is reviewed rather than assumed.
DECLARED: dict[str, dict[str, str]] = {
    "provenance.trace_from_log": {
        "tuple-input": "yes",
        "same-turn": "yes",
        "errored-source": "yes",
        "nearest-source": "yes",
        "supersession": (
            "OPEN -- not implemented, and not yet decided. Measured: 195 of 5389 "
            "links (3.6%) have their source resource overwritten inside the "
            "window, 98 of which back a temporal window. Unlike a state check, a "
            "lineage link stays factually true after an overwrite -- the argument "
            "really did come from that output -- and acting on the stale value is "
            "arguably the race itself rather than a reason to drop it. Recorded "
            "as undecided rather than quietly absent."
        ),
    },
    "numeric.trace_numeric": {
        "tuple-input": "yes",
        "same-turn": "yes",
        "errored-source": "yes",
        "nearest-source": "yes",
        "supersession": "OPEN -- same question as lexical lineage, same measurement.",
    },
    "absence.trace_absence": {
        "tuple-input": "yes",
        "same-turn": "yes",
        "errored-source": "yes",
        "nearest-source": (
            "N/A -- an absence has no source value to attribute, so there is no "
            "competition between candidate sources to resolve."
        ),
        "supersession": "yes",
    },
}
