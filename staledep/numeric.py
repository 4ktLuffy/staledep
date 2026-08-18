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

#: The floor applies to the TARGET being explained, not to the pool. Small money
#: amounts collide constantly -- a 50.0 subscription read as 5% of a prior 1000.0
#: purchase -- so a small target is not worth explaining. But a sum of small line
#: items is exactly how a large total arises, and an earlier version applied this
#: floor to the pool too, silently dropping 65.5 and 14.5 so 200.0 could never be
#: reached. Two floors, because they answer different questions.
_MIN_TARGET = 100.0
#: Pool members only need to be large enough not to be an index or a count.
_MIN_TERM = 1.0
#: Combinatorial guard. 12 numbers is 4095 subsets; beyond that the odds of an
#: accidental exact match stop being negligible and the cost stops being free.
_MAX_TERMS = 12
#: A sum of one term is a literal copy; a sum of TWO is usually coincidence --
#: 100 + 1000 = 1100 matched a rent constant that was never computed from either.
#: Three or more terms is a claim the arithmetic actually supports.
_MIN_SUBSET = 3
_TOL = 0.005

#: Declared multipliers. Deliberately short: every entry is a rate a financial
#: system actually applies, not a fitted constant.
#: One rate only. vat_5 (0.05) and vat_20 (0.20) each produced pure coincidences
#: on the real corpus: any figure is 5% or 20% of some other figure in a
#: transaction log. 0.15 is the rate this domain actually applies, and a
#: multi-rate table is a fishing licence rather than a hypothesis.
RATES: dict[str, float] = {
    "vat_15": 0.15,
    "vat_15_incl": 1.15,
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
        if abs(v) >= _MIN_TERM and v not in out:
            out.append(v)
    return out


#: A product needs both factors to be large enough that their product is not a
#: coincidence. 2 x 3 = 6 explains nothing; 12 x 45.50 = 546.0 is a line item.
_MIN_FACTOR = 2.0
#: Only ONE pair may explain the target. If several do, the relation is fitted.
def _product(target: float, pool: list[float]) -> tuple[float, float] | None:
    """target = a * b, with BOTH factors observed in earlier output.

    This is the verifiable half of the derived-value gap. An unknown multiplier
    (`100 EUR -> 6350 ETB` with the rate nowhere in the trajectory) stays
    uncovered and stays declared as uncovered, because admitting unknown
    multipliers matches any pair of numbers at all. But quantity x unit price is
    the commonest derivation in invoice work and both factors are normally right
    there in the source -- refusing that was throwing away a checkable relation
    along with the uncheckable one.
    """
    hits = []
    for i, a in enumerate(pool):
        if abs(a) < _MIN_FACTOR:
            continue
        for b in pool[i + 1:]:
            if abs(b) < _MIN_FACTOR:
                continue
            # At least one factor must have a fractional part. Two integers
            # multiplying to the target is cheap -- any composite number factors
            # several ways -- and measured on the corpus, an integer-only rule
            # produced 9 links and every one was a coincidence:
            # get_most_recent_transactions(n=100) "explained" as 2.0 x 50.0 from
            # unrelated transaction amounts. A real price x quantity almost
            # always carries a non-integer price.
            if a.is_integer() and b.is_integer():
                continue
            if abs(a * b - target) <= _TOL:
                hits.append((a, b))
                if len(hits) > 1:
                    return None          # fitted, not found
    return hits[0] if hits else None


def explain(target: float, pool: list[float]) -> tuple[str, tuple[float, ...]] | None:
    """How `target` could have been computed from `pool`, or None.

    Rates are tried before sums: a single multiplication is a simpler and more
    specific explanation than a subset, so preferring it avoids attributing
    `1000 * 1.15` to whichever combination happens to reach 1150.
    """
    if abs(target) < _MIN_TARGET:
        return None

    # A rate match is only evidence if it is UNIQUE. If several pool figures
    # explain the target under some rate, the relation is fitted, not found.
    rate_hits = [(name, term) for term in pool for name, rate in RATES.items()
                 if abs(term * rate - target) <= _TOL]
    if len(rate_hits) == 1:
        name, term = rate_hits[0]
        return f"rate:{name}", (term,)

    # A subset that CONTAINS the target is a literal copy wearing a sum's
    # clothes, and lexical `direct` matching already owns copies. The last
    # surviving numeric link on the corpus was exactly this:
    # amount=200.0 "derived" from [-1.0, 1.0, 200.0], where the cancelling pair
    # padded a copy up to the three-term minimum.
    usable = [x for x in pool[:_MAX_TERMS] if abs(x - target) > _TOL]
    # Tried before subset-sum: a product of two observed factors is a more
    # specific explanation than some combination that happens to reach the total.
    prod = _product(target, usable)
    if prod is not None:
        return "product", prod

    for size in range(_MIN_SUBSET, min(len(usable), _MAX_TERMS) + 1):
        for combo in itertools.combinations(usable, size):
            if abs(sum(combo) - target) <= _TOL:
                return "subset-sum", combo
    return None


def trace_numeric(steps, errored: set[int] | None = None,
                  suite: str | None = None) -> list[NumericLink]:
    """Find arguments computed from an earlier output.

    Same exclusions as lexical lineage: a call cannot consume output from its own
    turn, and a failed call's output is an error string rather than state.

    THIRD EXCLUSION, when `suite` is given: a READ sink is skipped. It can never
    form a window -- "a read acting on stale data changes nothing" is already the
    rule in windows_from_provenance -- so a numeric link into one is pure noise
    in a link-level audit. Measured, every numeric link on the corpus was one:
    `get_most_recent_transactions(n=100)` explained as 2.0 x 50.0, or as a subset
    sum, from unrelated transaction amounts. `n` is a pagination count. Nine
    links, nine coincidences, zero windows.
    """
    errored = errored or set()
    read_sinks: set[str] = set()
    if suite is not None:
        from .effects import Risk, effects_for
        read_sinks = {t for t, e in effects_for(suite).items() if e.risk is Risk.READ}
    links: list[NumericLink] = []
    sources: list[tuple[int, str, list[float], int]] = []   # idx, tool, numbers, turn

    # Accept both Step objects and raw (tool, args, output) tuples, exactly as
    # trace_from_log does. It did not, so every tuple caller -- including the
    # seeded recall harness -- raised AttributeError and numeric lineage was
    # never once exercised against the seeded cases it was written to cover.
    # A second entry point that disagrees with the first is the same defect that
    # made trace() and trace_from_log() diverge.
    from .signals import normalise
    for _ns in normalise(steps, errored):
        idx, turn, tool, args, output = _ns.idx, _ns.turn, _ns.tool, _ns.args, _ns.output

        for arg_name, arg_value in args.items():
            if tool in read_sinks:
                continue
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
