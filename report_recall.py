"""Print the seeded-recall table.

Recall cannot be audited by inspecting flags -- that only tells you about
positives. This runs the detector over synthetic trajectories containing a known
dependency of each class and reports what it catches.

Catches are split into two columns deliberately. A case can be flagged by a rule
that happens to fire rather than by the mechanism the class is meant to exercise,
and an incidental catch is fragile: reconstruct the case slightly differently and
it disappears. Reporting only the combined number would overstate coverage.
"""

from staledep.binding import Bind, bind_of
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
    print("%-24s %-9s %-10s %s" % ("CLASS", "FLAGGED", "TEMPORAL", "BINDING"))
    print("-" * 78)
    flagged = mechanism = n_temporal = 0
    for case, r in rows:
        is_flagged = bool(r["candidate"])
        is_real = is_flagged and case.cls not in INCIDENTAL
        binds = {bind_of(case.suite, w.use_tool, w.resource) for w in r["windows"]}
        temporal = bool(binds & {Bind.DEREFERENCE, Bind.CONTROL})
        signal = ",".join(sorted(b.value for b in binds)) or "-"
        flagged += is_flagged
        n_temporal += temporal
        mechanism += bool(is_real and temporal)
        print("%-24s %-9s %-10s %s" % (
            case.cls,
            "yes" if is_flagged else "NO",
            ("yes" if temporal else "SNAPSHOT" if is_flagged else "-"),
            signal,
        ))

    n = len(rows)
    print("-" * 78)
    print("flagged by any rule            : %d/%d (%.0f%%)" % (flagged, n, 100 * flagged / n))
    print("produce a TEMPORAL window      : %d/%d (%.0f%%)" % (n_temporal, n, 100 * n_temporal / n))
    print("temporal AND intended mechanism: %d/%d (%.0f%%)  <- the defensible figure" % (
        mechanism, n, 100 * mechanism / n))
    print()
    print("Snapshot flows are flagged but are NOT temporal dependencies: the")
    print("checked value was copied into the argument, so mutating the source")
    print("afterwards changes nothing. Counting them as catches credited the")
    print("detector for finding flows it also calls safe.")
    print()
    print("Incidental catches, and why they do not count:")
    for cls, why in INCIDENTAL.items():
        print("  %-22s %s" % (cls, why))
    print()
    print("Classes with no coverage at all:")
    for case, r in rows:
        if not r["candidate"]:
            print("  %-22s %s" % (case.cls, case.why))


if __name__ == "__main__":
    main()
