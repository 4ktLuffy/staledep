"""Print the seeded-recall table.

Recall cannot be audited by inspecting flags -- that only tells you about
positives. This runs the detector over synthetic trajectories containing a known
dependency of each class and reports what it catches.

Catches are split into two columns deliberately. A case can be flagged by a rule
that happens to fire rather than by the mechanism the class is meant to exercise,
and an incidental catch is fragile: reconstruct the case slightly differently and
it disappears. Reporting only the combined number would overstate coverage.
"""

from staledep.provenance import trace_from_log
from staledep.seeded import CASES
from staledep.toctou import classify_task

# Classes where a catch does not demonstrate the mechanism handles the class.
INCIDENTAL = {
    "control-dependence": "state rule fired because the sink happens to declare "
                          "the same resource; a control dependence over an "
                          "undeclared resource is still missed",
    "aliasing":           "both calls touch the same coarse resource, so the "
                          "alias never had to be resolved",
    "phantom":            "lexical match on a literal amount; the new row "
                          "appearing was not what was detected",
}


def main() -> None:
    rows = []
    for case in CASES:
        links = trace_from_log(case.steps)
        r = classify_task([n for n, _, _ in case.steps], case.suite, links=links)
        rows.append((case, r))

    print("SEEDED RECALL BY DEPENDENCY CLASS")
    print()
    print("%-24s %-11s %-9s %s" % ("CLASS", "FLAGGED", "MECHANISM", "SIGNAL"))
    print("-" * 78)
    flagged = mechanism = 0
    for case, r in rows:
        is_flagged = bool(r["vulnerable"])
        is_real = is_flagged and case.cls not in INCIDENTAL
        flagged += is_flagged
        mechanism += is_real
        signal = ("state" if r["n_state_windows"] else
                  "dataflow" if r["n_dataflow_windows"] else "-")
        print("%-24s %-11s %-9s %s" % (
            case.cls,
            "yes" if is_flagged else "NO",
            "yes" if is_real else ("incidental" if is_flagged else "no"),
            signal,
        ))

    n = len(rows)
    print("-" * 78)
    print("flagged by any rule       : %d/%d (%.0f%%)" % (flagged, n, 100 * flagged / n))
    print("handled by the mechanism  : %d/%d (%.0f%%)" % (mechanism, n, 100 * mechanism / n))
    print()
    print("Incidental catches, and why they do not count:")
    for cls, why in INCIDENTAL.items():
        print("  %-22s %s" % (cls, why))
    print()
    print("Classes with no coverage at all:")
    for case, r in rows:
        if not r["vulnerable"]:
            print("  %-22s %s" % (case.cls, case.why))


if __name__ == "__main__":
    main()
