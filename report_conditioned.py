"""Candidate rate conditioned on who can actually move the resource.

The binary rate from measure_published.py is close to tautological: read-then-act
is what agency is. This reports the subset an adversary is in a position to
exploit, under three threat models, which is the threat statement.
"""

import collections
import glob
import json
import os

from staledep.provenance import trace_from_log
from staledep.toctou import classify_task
from staledep.trajectory import steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]
MODELS = ["strict", "moderate", "multi_agent"]


def main() -> None:
    per = collections.defaultdict(lambda: collections.defaultdict(int))
    total = collections.defaultdict(int)

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
                links = trace_from_log(steps, errored)
                names = tool_names(steps)
                per[suite]["n"] += 1
                total["n"] += 1
                base = classify_task(names, suite, links=links)
                per[suite]["cand"] += base["candidate"]
                total["cand"] += base["candidate"]
                for tm in MODELS:
                    r = classify_task(names, suite, links=links, threat_model=tm)
                    per[suite][tm] += r["exposed"]
                    total[tm] += r["exposed"]
                    per[suite][tm + "_h"] += bool(r["n_exposed_high_risk"])
                    total[tm + "_h"] += bool(r["n_exposed_high_risk"])

    print("%-10s %6s %10s %9s %10s %12s" % (
        "SUITE", "TRAJ", "CANDIDATE", "STRICT", "MODERATE", "MULTI-AGENT"))
    print("-" * 62)
    for suite, b in per.items():
        print("%-10s %6d %9.1f%% %8.1f%% %9.1f%% %11.1f%%" % (
            suite, b["n"], 100 * b["cand"] / b["n"], 100 * b["strict"] / b["n"],
            100 * b["moderate"] / b["n"], 100 * b["multi_agent"] / b["n"]))
    n = total["n"]
    print("%-10s %6d %9.1f%% %8.1f%% %9.1f%% %11.1f%%" % (
        "OVERALL", n, 100 * total["cand"] / n, 100 * total["strict"] / n,
        100 * total["moderate"] / n, 100 * total["multi_agent"] / n))
    print()
    print("high-risk sink only: strict {:.1f}%  moderate {:.1f}%  multi-agent {:.1f}%".format(
        100 * total["strict_h"] / n, 100 * total["moderate_h"] / n,
        100 * total["multi_agent_h"] / n))


if __name__ == "__main__":
    main()
