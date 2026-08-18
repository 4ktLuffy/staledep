"""Measurement waterfall: where a broad dependency proxy loses its population.

The headline was never a danger figure. This reports each filter separately so a
reader can see which semantic condition removes which share, rather than being
handed one number whose derivation is invisible.

Stages, in order of how much they assume:

  eligible              trajectories with >=1 recorded tool call
  broad candidate       read-then-act, the original proxy
  after same-turn       links within one assistant message removed -- those
                        calls were composed together, so a later one cannot
                        have consumed an earlier one's output
  after committed-sink  sinks that raised removed; an action that did not
                        commit is not an exploited use
  snapshot-only         the checked value was copied into the argument;
                        mutation-immune however wide the window
  temporal              dereference or control binding: mutation can move it
  attacker-writable     AND an adversary is in a position to move that resource
  high-risk committed   AND the sink is irreversible/financial and committed
"""

from __future__ import annotations

import collections
import glob
import json
import os

from staledep.absence import trace_absence
from staledep.binding import bind_of
from staledep.effects import Risk
from staledep.numeric import trace_numeric
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task, find_windows, windows_from_provenance
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
#: Best-evidence-first. `absence` ranks last: it is the weakest claim here,
#: since whether the agent conditioned on an empty result is unobservable.
_TIER_ORDER = {"state": 0, "strong": 1, "token-only": 2, "absence": 3}
SUITES = ["banking", "slack", "travel", "workspace"]


def main() -> None:
    stage = collections.Counter()
    per_suite = collections.defaultdict(collections.Counter)
    bind_counts = collections.Counter()
    tier_danger = collections.Counter()
    tier_temporal = collections.Counter()
    danger_rows = []

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
                stage["eligible"] += 1
                per_suite[suite]["eligible"] += 1

                names = tool_names(steps)
                # broad: no same-turn exclusion, no committed filter
                raw_links = trace_from_log([s.as_tuple() for s in steps], errored)
                broad = find_windows(names, suite) + windows_from_provenance(names, raw_links, suite)
                if broad:
                    stage["broad"] += 1
                    per_suite[suite]["broad"] += 1

                # same-turn excluded (Step objects carry turn identity)
                links = trace_from_log(steps, errored)
                numeric = trace_numeric(steps, errored, suite)
                w_turn = find_windows(names, suite) + windows_from_provenance(names, links, suite)
                if w_turn:
                    stage["after_same_turn"] += 1
                    per_suite[suite]["after_same_turn"] += 1

                # The funnel is lineage + effect typing ONLY. Absence is a new
                # SIGNAL, not a filter, so folding it in here made a later stage
                # larger than an earlier one -- a funnel that grows is not a
                # funnel. Its contribution is reported separately below.
                r = classify_task(names, suite, links=links, committed=committed(steps),
                                  numeric_links=numeric)
                absence = trace_absence(steps, errored)
                r_abs = classify_task(names, suite, links=links, committed=committed(steps),
                                      numeric_links=numeric, absence_links=absence)
                if absence:
                    stage["absence_traj"] += 1
                    if r_abs["temporal"] and not r["temporal"]:
                        stage["absence_new_temporal"] += 1
                    if r_abs["n_danger_high_risk"] and not r["n_danger_high_risk"]:
                        stage["absence_new_danger"] += 1
                tier_temporal.update(r_abs["tier_temporal"])
                if r["candidate"]:
                    stage["after_committed"] += 1
                    per_suite[suite]["after_committed"] += 1
                if r["n_snapshot_only_windows"] and not r["n_temporal_windows"]:
                    stage["snapshot_only"] += 1
                    per_suite[suite]["snapshot_only"] += 1
                if r["temporal"]:
                    stage["temporal"] += 1
                    per_suite[suite]["temporal"] += 1
                if r["danger"]:
                    stage["danger"] += 1
                    per_suite[suite]["danger"] += 1
                if r["n_danger_high_risk"]:
                    # A trajectory is credited to its STRONGEST evidence: the
                    # question is whether the claim stands, not whether some
                    # weaker corroboration also exists.
                    tier_danger[min(r["tier_danger_high"],
                                    key=lambda t: _TIER_ORDER[t])] += 1
                    stage["danger_high"] += 1
                    per_suite[suite]["danger_high"] += 1
                    danger_rows.append((model, suite, d.get("user_task_id"),
                                        [str(w) for w in r["windows"]
                                         if w.use_risk is Risk.HIGH]))

                for w in r["windows"]:
                    bind_counts[(suite, w.use_tool, bind_of(suite, w.use_tool, w.resource).value)] += 1

    n = stage["eligible"]
    print("MEASUREMENT WATERFALL   (attack-free trajectories, pinned corpus)\n")
    print("%-34s %8s %9s" % ("STAGE", "COUNT", "RATE"))
    print("-" * 54)
    for key, label in [
        ("eligible", "eligible trajectories"),
        ("broad", "broad candidates (original proxy)"),
        ("after_same_turn", "after same-turn exclusion"),
        ("after_committed", "after failed-sink exclusion"),
        ("snapshot_only", "snapshot-only flows"),
        ("temporal", "temporal (dereference/control)"),
        ("danger", "+ attacker-writable"),
        ("danger_high", "+ high-risk committed sink"),
    ]:
        print("%-34s %8d %8.1f%%" % (label, stage[key], 100 * stage[key] / max(n, 1)))

    print("\nBY SUITE (rate of eligible)")
    print("%-11s %9s %9s %9s %9s %9s" % ("suite", "broad", "same-turn", "committed", "temporal", "danger-hi"))
    for suite in SUITES:
        c = per_suite[suite]
        e = max(c["eligible"], 1)
        print("%-11s %8.1f%% %8.1f%% %8.1f%% %8.1f%% %8.1f%%" % (
            suite, 100*c["broad"]/e, 100*c["after_same_turn"]/e,
            100*c["after_committed"]/e, 100*c["temporal"]/e, 100*c["danger_high"]/e))

    print("\nNEGATIVE EVIDENCE — a new signal, reported outside the funnel")
    print("  (a read that found NOTHING, then a state change. Both lineage signals")
    print("   follow a value, so both are blind to it by construction.)")
    print("  trajectories with an absence window : %d  (%.1f%%)"
          % (stage["absence_traj"], 100 * stage["absence_traj"] / max(n, 1)))
    print("  newly temporal because of it        : %d" % stage["absence_new_temporal"])
    print("  newly in the danger set             : %d" % stage["absence_new_danger"])

    print("\nEVIDENCE TIER — what each flag actually rests on")
    print("  (state = effect typing alone; strong = exact value, full date or"
          " arithmetic;\n   token-only = nothing but two shared words)")
    tt = sum(tier_temporal.values())
    print("  temporal windows      : " + "  ".join(
        "%s %d (%.1f%%)" % (k, tier_temporal[k], 100 * tier_temporal[k] / max(tt, 1))
        for k in ("state", "strong", "token-only", "absence")))
    td = sum(tier_danger.values())
    print("  danger-set trajectories: " + "  ".join(
        "%s %d (%.1f%%)" % (k, tier_danger[k], 100 * tier_danger[k] / max(td, 1))
        for k in ("state", "strong", "token-only", "absence")))
    print("  -> the loosest matcher contributes %.1f%% of the headline set."
          % (100 * tier_danger["token-only"] / max(td, 1)))

    print("\nWINDOWS BY EDGE BINDING (top 14)")
    for (suite, tool, b), c in bind_counts.most_common(14):
        print("   %-10s %-32s %-12s %5d" % (suite, tool, b, c))

    print("\nHIGH-RISK COMMITTED DANGER SET: %d trajectories" % len(danger_rows))
    if danger_rows and len(danger_rows) <= 200:
        print("(small enough to audit exhaustively rather than sample)")
    with open("danger_set.json", "w") as fh:
        json.dump([{"model": m, "suite": s, "task": t, "windows": w}
                   for m, s, t, w in danger_rows], fh, indent=2)
    print("written: danger_set.json")


if __name__ == "__main__":
    main()
