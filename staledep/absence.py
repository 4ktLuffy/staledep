"""Negative evidence: the check that found nothing.

The highest-value recall gap, and structurally different from everything else
here. Lexical and numeric lineage both follow a VALUE from an output into a later
argument. When the check returns nothing there is no value to follow, so both are
blind by construction -- yet "I searched for a cancellation, found none, and
proceeded" is a textbook race: the thing that was absent can arrive during the
window, and the action commits anyway.

    search_emails(query="cancellation") -> []        # check: nothing found
        ... window ...                               # <- the email arrives here
    create_calendar_event(...)                       # use: proceeds regardless

WHY THE BINDING IS CONTROL, AND WHY THAT IS NOT THE MISTAKE MADE BEFORE.

An earlier version of this project declared `send_money` CONTROL on
`account.balance` -- "funds must suffice at execution" -- and that was fiction:
the implementation never reads the balance. The inference here runs the other
way and does not depend on any implementation. The check returned NO VALUE, so
nothing could have been copied into the action; if the read influenced the action
at all, the only channel left is control flow. That is a deduction from the
observed trajectory rather than an assumption about code.

It is still the weakest claim in the codebase, because whether the agent
conditioned on the empty result is not observable. So absence windows carry their
own evidence tier and are never counted as `strong`.

DELIBERATELY NARROW. Every empty read paired with every later write would
reproduce the read-then-act tautology this project exists to refute. Only the
NEAREST subsequent state-changing call is paired, and only genuinely empty
results count -- an error string is not an absence, it is a failure.

SUPERSESSION. An absence is only load-bearing if it is still the agent's most
recent information about that resource when it acts. The first version of this
module had no such rule and every one of the nine danger-set entries it produced
was the same false positive:

    search_files_by_filename("team meeting minutes") -> []      # missed
    search_files("team meeting minutes")             -> found   # RETRIED, found
    get_file_by_id("25")                             -> content
    send_email(...)                                             # acts on content

The agent did not proceed on an absence. It recovered from a failed lookup, which
is the opposite. A later non-empty read of the same resource therefore cancels the
absence -- the mirror of the existing rule in find_windows that a write
invalidates an earlier check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .effects import Risk, effects_for

#: Textual renderings of "nothing here". Deliberately short: each is a phrase a
#: tool returns INSTEAD of results, not prose that merely mentions absence.
_EMPTY_TEXT = re.compile(
    r"^\s*(\[\]|\{\}|none|null|no results?|not found|404 not found|"
    r"no matching \w+|no \w+ found|empty)\s*\.?\s*$",
    re.IGNORECASE,
)


def is_absent(output) -> bool:
    """Did this read genuinely come back with nothing?

    An error is NOT an absence. "ValueError: channel not found" means the check
    did not happen; treating that as evidence of absence would credit a failed
    call as a successful negative observation.
    """
    if output is None:
        return True
    if isinstance(output, (list, tuple, set, dict)):
        return len(output) == 0
    if isinstance(output, str):
        return bool(_EMPTY_TEXT.match(output))
    return False


@dataclass(frozen=True)
class AbsenceLink:
    """A read that found nothing, and the state change that followed it.

    Duck-types as a provenance link so it flows through the existing window
    machinery: same fields, different resource prefix.
    """
    source_idx: int
    source_tool: str
    sink_idx: int
    sink_tool: str
    arg_name: str = "<absence>"
    value: str = ""
    rule: str = "absence"

    def __str__(self) -> str:
        return (f"{self.source_tool}@{self.source_idx} found nothing -> "
                f"{self.sink_tool}@{self.sink_idx} proceeded anyway")


def trace_absence(steps, errored: set[int] | None = None) -> list[AbsenceLink]:
    """Pair each empty read with the next state-changing call that follows it."""
    errored = errored or set()
    out: list[AbsenceLink] = []
    if not steps:
        return out

    from .signals import normalise
    norm = [(s.idx, s.turn, s.tool, s.output, s.errored) for s in normalise(steps, errored)]

    suite_guess = None
    for _, _, tool, _, _ in norm:
        for suite in ("banking", "slack", "travel", "workspace", "claude_code"):
            if tool in effects_for(suite):
                suite_guess = suite
                break
        if suite_guess:
            break
    if suite_guess is None:
        return out
    table = effects_for(suite_guess)

    for i, (idx, turn, tool, output, failed) in enumerate(norm):
        eff = table.get(tool)
        if eff is None or eff.risk is not Risk.READ or failed:
            continue
        if not is_absent(output):
            continue
        covered = eff.reads
        # Nearest subsequent state change only. Pairing every later write would
        # rebuild the read-then-act tautology.
        for j in range(i + 1, len(norm)):
            s_idx, s_turn, s_tool, s_out, s_failed = norm[j]
            s_eff = table.get(s_tool)
            if s_eff is None:
                continue
            if s_eff.risk is Risk.READ:
                # A later successful read of the same resource supersedes the
                # absence: the agent looked again and found something, so it is
                # no longer acting on "nothing is there".
                if (s_eff.reads & covered) and not s_failed and not is_absent(s_out):
                    break
                continue
            if turn >= 0 and s_turn >= 0 and s_turn == turn:
                break      # composed together; the agent had not seen the result
            out.append(AbsenceLink(source_idx=idx, source_tool=tool,
                                   sink_idx=s_idx, sink_tool=s_tool))
            break
    return out
