"""Which matching rule produces the links that actually BECOME windows?

Link precision is not window precision. Most lexical links have a read sink and
never form a window at all, so a rule's share of all links says nothing about its
share of any reported rate. Pooled figures therefore hide the thing that matters:
a rule can be a small fraction of links while backing a large fraction of the
windows, and only the second number affects a result.

That gap is how the year defect stayed invisible. `numeric` was 14.1% of links --
unremarkable -- but 39.4% of the links backing temporal windows, and 96.4% of its
matches were a bare calendar year. This report is the measurement that exposes
it, kept so the enrichment can be rechecked after any change to the matcher.

Read the three tables as a funnel. A rule whose share GROWS from one table to the
next is concentrated in exactly the flags that get reported.

Usage:
    python report_rule_mix.py
"""

from __future__ import annotations

import collections
import glob
import json
import os

from staledep.absence import trace_absence
from staledep.binding import Bind, bind_of
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]


def collect():
    all_links = collections.Counter()
    win_links = collections.Counter()
    temporal_links = collections.Counter()
    examples = collections.defaultdict(list)

    for model in sorted(os.listdir(RUNS)):
        for suite in SUITES:
            pattern = os.path.join(RUNS, model, suite, "user_task_*", "*", "*.json")
            for path in glob.glob(pattern):
                try:
                    d = json.load(open(path))
                except Exception:
                    continue
                if d.get("injection_task_id"):
                    continue
                steps, errored = steps_from_messages(d.get("messages") or [])
                if not steps:
                    continue
                lex = trace_from_log(steps, errored)
                for link in lex:
                    all_links[link.rule] += 1

                r = classify_task(tool_names(steps), suite, links=lex,
                                  committed=committed(steps),
                                  absence_links=trace_absence(steps, errored))
                for w in r["windows"]:
                    b = bind_of(suite, w.use_tool, w.resource)
                    # The rule of the FIRST link backing this window, which is
                    # the evidence the window actually rests on.
                    for link in lex:
                        if (link.source_idx, link.sink_idx) != (w.check_idx, w.use_idx):
                            continue
                        win_links[link.rule] += 1
                        if b in (Bind.DEREFERENCE, Bind.CONTROL):
                            temporal_links[link.rule] += 1
                            if len(examples[link.rule]) < 4:
                                examples[link.rule].append(
                                    (suite, d.get("user_task_id"), str(link)[:110]))
                        break
    return all_links, win_links, temporal_links, examples


def show(name, counter):
    total = sum(counter.values())
    print("%-24s total=%d" % (name, total))
    for rule, n in counter.most_common():
        print("     %-10s %6d  (%.1f%%)" % (rule, n, 100 * n / max(total, 1)))


def main() -> int:
    all_links, win_links, temporal_links, examples = collect()
    show("ALL LEXICAL LINKS", all_links)
    show("LINKS FORMING WINDOWS", win_links)
    show("LINKS -> TEMPORAL WINDOW", temporal_links)
    print("\nA rule whose share grows down this funnel is concentrated in the"
          " flags that get reported.\n")
    for rule, rows in sorted(examples.items()):
        print("=== temporal examples: %s ===" % rule)
        for suite, task, ev in rows:
            print("   %-9s %-22s %s" % (suite, task, ev))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
