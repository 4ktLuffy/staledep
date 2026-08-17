"""False-positive audit: dump concrete evidence for a random sample of flagged
windows so a human can judge each one.

45.6% is an unaudited number until someone checks whether the provenance matcher
is linking real data-flow or coincidence. This prints, for each sampled window,
the exact argument value and the surrounding context in the source output that
caused the link -- enough to rule it genuine or spurious by eye.
"""

import glob
import json
import os
import random

from staledep.provenance import trace_from_log, _distinctive_values
from staledep.toctou import classify_task
from staledep.trajectory import steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]
SAMPLE = int(os.environ.get("SAMPLE", "20"))
SEED = int(os.environ.get("SEED", "4211"))

random.seed(SEED)

# Collect every flagged trajectory, then sample -- sampling files first would
# oversample models with more runs.
flagged = []
for model in sorted(os.listdir(RUNS)):
    for suite in SUITES:
        for f in glob.glob(os.path.join(RUNS, model, suite, "user_task_*", "*", "*.json")):
            try:
                d = json.load(open(f))
            except Exception:
                continue
            if d.get("injection_task_id"):
                continue
            steps, errored = steps_from_messages(d.get("messages") or [])
            if not steps:
                continue
            links = trace_from_log(steps, errored)
            r = classify_task(tool_names(steps), suite, links=links)
            if r["vulnerable"]:
                flagged.append((model, suite, d.get("user_task_id"), steps, links, r))

print("flagged trajectories: %d; sampling %d (seed=%d)\n" % (len(flagged), SAMPLE, SEED))
sample = random.sample(flagged, min(SAMPLE, len(flagged)))


def context(haystack: str, needle: str, pad: int = 34) -> str:
    i = haystack.lower().find(needle.lower())
    if i < 0:
        return "(numeric match, not literal substring)"
    lo, hi = max(0, i - pad), min(len(haystack), i + len(needle) + pad)
    return "..." + haystack[lo:hi].replace("\n", "\\n") + "..."


for n, (model, suite, tid, steps, links, r) in enumerate(sample, 1):
    w = max(r["windows"], key=lambda x: (x.use_risk.value == "high", x.span))
    print("[%2d] %s | %s/%s" % (n, model, suite, tid))
    print("     calls: %s" % " -> ".join(tool_names(steps)))
    print("     window: %s" % w)
    if w.resource.startswith("dataflow:"):
        for lk in links:
            if lk.source_idx == w.check_idx and lk.sink_idx == w.use_idx:
                src_out = str(steps[lk.source_idx][2])
                for val in sorted(_distinctive_values(steps[lk.sink_idx][1].get(lk.arg_name)),
                                  key=len, reverse=True)[:1]:
                    print("     arg %s=%r" % (lk.arg_name, lk.value[:60]))
                    print("     source output: %s" % context(src_out, val)[:150])
                break
    else:
        print("     shared resource: %s (state dependency)" % w.resource)
    print("     VERDICT: ______")
    print()
