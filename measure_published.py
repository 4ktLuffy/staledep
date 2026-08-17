"""Measure TOCTOU-vulnerable trajectory rate across AgentDojo's published runs.
Comparable to arXiv:2508.17155's headline: 12% of trajectories contain a vulnerability."""
import glob, json, os, collections
from agenttx.trajectory import steps_from_messages, tool_names
from agenttx.provenance import trace_from_log
from agenttx.toctou import classify_task

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
            r = classify_task(tool_names(steps), suite, links=links)
            for bucket in (per_model[model], per_suite[suite], grand):
                bucket["n"] += 1
                bucket["vuln"] += r["vulnerable"]
                bucket["high"] += bool(r["n_high_risk_windows"])
            per_model[model]["calls"] += len(steps)

print("=== vulnerable-trajectory rate by model (no attack) ===")
print("%-46s %6s %8s %8s %6s" % ("MODEL", "TRAJ", "VULN", "HIGH", "CALLS"))
for m, s in sorted(per_model.items(), key=lambda kv: -(kv[1]["vuln"]/max(kv[1]["n"],1))):
    if not s["n"]: continue
    print("%-46s %6d %7.1f%% %7.1f%% %6.1f" % (
        m, s["n"], 100*s["vuln"]/s["n"], 100*s["high"]/s["n"], s["calls"]/s["n"]))

print("\n=== by suite ===")
for k, s in per_suite.items():
    if s["n"]:
        print("  %-10s %4d traj  %5.1f%% vulnerable  %5.1f%% high-risk" % (
            k, s["n"], 100*s["vuln"]/s["n"], 100*s["high"]/s["n"]))

print("\nOVERALL: %d trajectories, %.1f%% contain a TOCTOU window, %.1f%% high-risk" % (
    grand["n"], 100*grand["vuln"]/grand["n"], 100*grand["high"]/grand["n"]))
print("Paper (arXiv:2508.17155) reports 12% of trajectories vulnerable, pre-mitigation.")
