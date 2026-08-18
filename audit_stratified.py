"""Precision audited PER SIGNAL, not pooled.

Both reviewers flagged the same hole: precision was measured by sampling flagged
windows at random, but the detector has three independent signals and lexical
lineage alone is the sole basis for roughly half of all flags. A pooled ~93% is
consistent with effect typing at 100% and lexical at 75%, and those are very
different instruments. Nothing in the earlier audits could tell them apart.

Sampling is stratified: an equal quota from each signal, drawn with a fixed seed,
so a signal that produces few flags is still audited at the same depth as one
that produces many.

    STATE     effect typing only -- a declared read followed by a declared write
    LEXICAL   argument value matched an earlier output (string or token overlap)
    NUMERIC   argument value computed from an earlier output (sum or rate)

Each sampled window is printed with the evidence that produced it, so the
judgement is checkable rather than asserted.
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import random

from staledep.absence import trace_absence
from staledep.binding import bind_of
from staledep.numeric import trace_numeric
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task, find_windows, windows_from_provenance
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]
SEED = 20260818


def collect():
    """Every flagged window, tagged by the signal that produced it."""
    pool = collections.defaultdict(list)
    for model in sorted(os.listdir(RUNS)):
        for suite in SUITES:
            for path in glob.glob(os.path.join(RUNS, model, suite, "user_task_*", "*", "*.json")):
                try:
                    d = json.load(open(path))
                except Exception:
                    continue
                if d.get("injection_task_id"):
                    continue
                steps, errored = steps_from_messages(d.get("messages") or [])
                if not steps:
                    continue
                names = tool_names(steps)
                lex = trace_from_log(steps, errored)
                num = trace_numeric(steps, errored, suite)

                state_w = {(w.check_idx, w.use_idx, w.resource)
                           for w in find_windows(names, suite)}
                lex_w = {(w.check_idx, w.use_idx, w.resource)
                         for w in windows_from_provenance(names, lex, suite)}
                num_w = {(w.check_idx, w.use_idx, w.resource)
                         for w in windows_from_provenance(names, num, suite)}

                r = classify_task(names, suite, links=lex, committed=committed(steps),
                                  absence_links=trace_absence(steps, errored),
                                  numeric_links=num)
                for w in r["windows"]:
                    key = (w.check_idx, w.use_idx, w.resource)
                    if key in state_w:
                        signal = "STATE"
                    elif key in num_w and key not in lex_w:
                        signal = "NUMERIC"
                    elif key in lex_w:
                        signal = "LEXICAL"
                    else:
                        continue
                    ev = None
                    if signal == "LEXICAL":
                        ev = next((str(x) for x in lex
                                   if x.source_idx == w.check_idx and x.sink_idx == w.use_idx), None)
                    elif signal == "NUMERIC":
                        ev = next((str(x) for x in num
                                   if x.source_idx == w.check_idx and x.sink_idx == w.use_idx), None)
                    pool[signal].append({
                        "model": model, "suite": suite, "task": d.get("user_task_id"),
                        "window": str(w), "binding": bind_of(suite, w.use_tool, w.resource).value,
                        "evidence": ev,
                        "src_out": str(steps[w.check_idx].output)[:150].replace("\n", " "),
                        "sink_args": str(steps[w.use_idx].args)[:110],
                    })
    return pool


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-signal", type=int, default=12)
    args = ap.parse_args()

    pool = collect()
    print("FLAG POPULATION BY SIGNAL")
    total = sum(len(v) for v in pool.values())
    for sig, rows in sorted(pool.items(), key=lambda kv: -len(kv[1])):
        print("   %-8s %6d  (%.1f%% of flags)" % (sig, len(rows), 100 * len(rows) / max(total, 1)))
    print("   %-8s %6d" % ("TOTAL", total))
    print("\nA pooled precision figure cannot distinguish these. Sampling %d per signal,"
          " seed=%d.\n" % (args.per_signal, SEED))

    rng = random.Random(SEED)
    for sig in ("STATE", "LEXICAL", "NUMERIC"):
        rows = pool.get(sig, [])
        if not rows:
            print("=== %s: no flags ===\n" % sig)
            continue
        print("=" * 78)
        print("%s  (%d flags, auditing %d)" % (sig, len(rows), min(args.per_signal, len(rows))))
        print("=" * 78)
        for i, r in enumerate(rng.sample(rows, min(args.per_signal, len(rows))), 1):
            print("[%2d] %s/%s  [%s]" % (i, r["suite"], r["task"], r["binding"]))
            print("     %s" % r["window"])
            if r["evidence"]:
                print("     evidence : %s" % r["evidence"][:120])
            print("     src out  : %s" % r["src_out"][:120])
            print("     sink args: %s" % r["sink_args"])
            print("     VERDICT: ______")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
