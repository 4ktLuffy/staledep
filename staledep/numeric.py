"""Numeric-relation lineage: an argument computed from earlier output.

Lexical matching finds values that were copied. It is blind to values that were
*derived*, which in financial work is most of them: a payment total is the sum of
line items, a VAT line is a percentage of a subtotal. Neither appears verbatim in
any source, so `aggregate` and `derived-value` were the two seeded classes with
zero coverage -- and both reviewers named them as the gap that disqualifies the
instrument for invoice work specifically.

Two relations are detected, chosen because they are verifiable rather than
plausible:

    SUBSET SUM   the argument equals the exact sum of two or more numbers in an
                 earlier output. 120.0 + 65.5 + 14.5 = 200.0.

    FIXED RATE   the argument equals an earlier number times a rate from a small
                 declared set (VAT and common markups). 1000 * 1.15 = 1150.

Arbitrary conversion is NOT attempted. `100 EUR -> 6350 ETB` requires an unknown
exchange rate, and admitting unknown multipliers would match any pair of numbers.
That class stays uncovered, and stays declared as uncovered.

False-positive control matters more here than anywhere else in the codebase: a
subset sum over n numbers has 2^n candidates, so a loose threshold invents
lineage. Guards are documented at each constant.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass

_NUM = re.compile(r"-?\d[\d,]*\.?\d*")

#: Below this, coincidental matches are common: small integers appear everywhere.
_MIN_MAGNITUDE = 10.0
#: Combinatorial guard. 12 numbers is 4095 subsets; beyond that the odds of an
#: accidental exact match stop being negligible and the cost stops being free.
_MAX_TERMS = 12
#: A sum of one term is a literal copy, already caught by lexical matching.
_MIN_SUBSET = 2
_TOL = 0.005

#: Declared multipliers. Deliberately short: every entry is a rate a financial
#: system actually applies, not a fitted constant.
RATES: dict[str, float] = {
    "vat_15": 0.15, "vat_15_incl": 1.15,     # Ethiopian standard rate
    "vat_20": 0.20, "vat_20_incl": 1.20,
    "vat_5": 0.05, "vat_5_incl": 1.05,
}
# `double`, `half` and `ten_pct` were here and are removed. They are not rates a
# system applies, they are arithmetic coincidences: any figure and its double
# co-occur constantly, and on the real corpus those three produced 8 of 10 new
# links while the VAT rates produced 2. The stated guard -- "every entry is a
# rate a financial system actually applies" -- excluded them all along; keeping
# them contradicted it.


@dataclass(frozen=True)
class NumericLink:
    """An argument value explained by arithmetic over an earlier output."""
    source_idx: int
    source_tool: str
    sink_idx: int
    sink_tool: str
    arg_name: str
    value: float
    relation: str          # "subset-sum" | "rate:<name>"
    terms: tuple[float, ...]

    def __str__(self) -> str:
        return (f"{self.source_tool}@{self.source_idx} -> {self.sink_tool}@{self.sink_idx} "
                f"via {self.arg_name}={self.value} [{self.relation} of {list(self.terms)}]")


def numbers_in(text: str) -> list[float]:
    """Distinctive numbers in a tool output, de-duplicated, order preserved."""
    out: list[float] = []
    for raw in _NUM.findall(str(text)):
        try:
            v = float(raw.replace(",", ""))
        except ValueError:
            continue
        if abs(v) >= _MIN_MAGNITUDE and v not in out:
            out.append(v)
    return out


def explain(target: float, pool: list[float]) -> tuple[str, tuple[float, ...]] | None:
    """How `target` could have been computed from `pool`, or None.

    Rates are tried before sums: a single multiplication is a simpler and more
    specific explanation than a subset, so preferring it avoids attributing
    `1000 * 1.15` to whichever combination happens to reach 1150.
    """
    if abs(target) < _MIN_MAGNITUDE:
        return None

    for term in pool:
        for name, rate in RATES.items():
            if abs(term * rate - target) <= _TOL:
                return f"rate:{name}", (term,)

    usable = pool[:_MAX_TERMS]
    for size in range(_MIN_SUBSET, min(len(usable), _MAX_TERMS) + 1):
        for combo in itertools.combinations(usable, size):
            if abs(sum(combo) - target) <= _TOL:
                return "subset-sum", combo
    return None


def trace_numeric(steps, errored: set[int] | None = None) -> list[NumericLink]:
    """Find arguments computed from an earlier output.

    Same exclusions as lexical lineage: a call cannot consume output from its own
    turn, and a failed call's output is an error string rather than state.
    """
    errored = errored or set()
    links: list[NumericLink] = []
    sources: list[tuple[int, str, list[float], int]] = []   # idx, tool, numbers, turn

    for st in steps:
        idx, turn = getattr(st, "idx", 0), getattr(st, "turn", -1)
        tool, args, output = st.tool, st.args or {}, st.output

        for arg_name, arg_value in args.items():
            if not isinstance(arg_value, (int, float)) or isinstance(arg_value, bool):
                continue
            target = float(arg_value)
            for src_idx, src_tool, pool, src_turn in reversed(sources):
                if turn >= 0 and src_turn >= 0 and src_turn == turn:
                    continue
                found = explain(target, pool)
                if found:
                    relation, terms = found
                    links.append(NumericLink(
                        source_idx=src_idx, source_tool=src_tool,
                        sink_idx=idx, sink_tool=tool, arg_name=arg_name,
                        value=target, relation=relation, terms=terms))
                    break

        if idx not in errored:
            sources.append((idx, tool, numbers_in(output), turn))

    return links
