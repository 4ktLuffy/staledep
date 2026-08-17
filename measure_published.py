"""Measure stale-dependency candidate rate across AgentDojo's published runs.

SUPERSEDED by report_waterfall.py. This reports the broad read-then-act proxy,
which is close to tautological on its own and is NOT a danger figure: most of
that population is snapshot flows that state mutation cannot move.

Reports the binary per-trajectory rate, which is close to tautological on its
own -- read-then-act is what agency is. Use report_conditioned.py for the rate
conditioned on who can actually move the resource, which is the threat statement."""
import collections
import glob
import json
import os

from staledep.provenance import trace_from_log
from staledep.toctou import classify_task
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]

per_model = collections.defaultdict(lambda: {"n":0, "vuln":0, "high":0, "calls":0})
per_suite = collections.defaultdict(lambda: {"n":0, "vuln":0, "high":0})
grand = {"n":0, "vuln":0, "high":0}

for model in sorted(os.listdir(RUNS)):
    for suite in SUITES:
        for f in glob.glob(os.path.join(RUNS, model, suite, "user_task_*", "*", "*.json")):
            try:
                d = json.load(open(f))
            except Exception:
                continue
            if d.get("injection_task_id"):
                continue                      # attack runs measured separately
            steps, errored = steps_from_messages(d.get("messages") or [])
            if not steps:
                continue
            links = trace_from_log(steps, errored)
            r = classify_task(tool_names(steps), suite, links=links, committed=committed(steps))
            for bucket in (per_model[model], per_suite[suite], grand):
                bucket["n"] += 1
                bucket["vuln"] += r["candidate"]
                bucket["high"] += bool(r["n_high_risk_windows"])
            per_model[model]["calls"] += len(steps)

print("=== candidate-trajectory rate by model (no attack) ===")
print("%-46s %6s %10s %8s %6s" % ("MODEL", "TRAJ", "CANDIDATE", "HIGH", "CALLS"))
for m, s in sorted(per_model.items(), key=lambda kv: -(kv[1]["vuln"]/max(kv[1]["n"],1))):
    if not s["n"]:
        continue
    print("%-46s %6d %7.1f%% %7.1f%% %6.1f" % (
        m, s["n"], 100*s["vuln"]/s["n"], 100*s["high"]/s["n"], s["calls"]/s["n"]))

print("\n=== by suite ===")
for k, s in per_suite.items():
    if s["n"]:
        print("  %-10s %4d traj  %5.1f%% candidate  %5.1f%% high-risk" % (
            k, s["n"], 100*s["vuln"]/s["n"], 100*s["high"]/s["n"]))

print("\nOVERALL: %d trajectories, %.1f%% contain a candidate window, %.1f%% high-risk" % (
    grand["n"], 100*grand["vuln"]/grand["n"], 100*grand["high"]/grand["n"]))
print("NOTE: SUPERSEDED -- this is the broad proxy, not a danger figure. Most of\n"
      "      this population is snapshot flows that mutation cannot move. Run\n"
      "      report_waterfall.py for the staged measurement. Not comparable to\n"
      "      published figures using different criteria. See README.")
