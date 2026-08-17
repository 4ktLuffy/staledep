"""Recall audit: sample trajectories the classifier called CLEAN and look for
windows it missed.

Precision tells you whether flags are real. It says nothing about what slipped
through. Adding provenance already revealed one entire blind class
(read_file -> send_money), so assuming there are no others is unjustified.

This prints unflagged trajectories in full -- every call, its arguments, and a
truncated output -- so a human can look for a check-then-act pattern the
classifier did not catch.
"""

import glob
import json
import os
import random

from agenttx.effects import Risk, effects_for
from agenttx.provenance import trace_from_log
from agenttx.toctou import classify_task
from agenttx.trajectory import steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]
SAMPLE = int(os.environ.get("SAMPLE", "14"))
SEED = int(os.environ.get("SEED", "90210"))
random.seed(SEED)

clean = []
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
            # A single-call trajectory cannot contain a window; including them
            # would pad the sample with trivially-clean cases.
            if len(steps) < 2:
                continue
            links = trace_from_log(steps, errored)
            r = classify_task(tool_names(steps), suite, links=links)
            if not r["vulnerable"]:
                clean.append((model, suite, d.get("user_task_id"), steps, errored, links))

print("unflagged trajectories with >=2 calls: %d; sampling %d (seed=%d)\n"
      % (len(clean), SAMPLE, SEED))

for n, (model, suite, tid, steps, errored, links) in enumerate(
        random.sample(clean, min(SAMPLE, len(clean))), 1):
    table = effects_for(suite)
    print("[%2d] %s | %s/%s" % (n, model, suite, tid))
    for i, (name, args, out) in enumerate(steps):
        eff = table.get(name)
        risk = eff.risk.value if eff else "UNDECLARED"
        flag = " <-- state-changing" if eff and eff.risk is not Risk.READ else ""
        err = " [ERRORED]" if i in errored else ""
        print("   %d. %-34s [%s]%s%s" % (i, name, risk, flag, err))
        if args:
            print("        args: %s" % json.dumps(args, default=str)[:150])
        print("        out : %s" % str(out).replace("\n", " ")[:130])
    if links:
        print("   provenance links found but no window: %s" % [str(l) for l in links][:2])
    print("   MISSED WINDOW? ______")
    print()
