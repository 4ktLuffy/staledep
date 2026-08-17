"""Which matching rule produces the links that actually BECOME windows?

Link precision != window precision. Most lexical links have read sinks and never
form a window at all, so a rule's share of links says nothing about its share of
the reported rate. This measures the rule distribution restricted to links that
survive into a window, and again restricted to the danger tier.
"""
import collections, glob, json, os
from staledep.binding import bind_of, Bind
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task, windows_from_provenance
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]

all_links = collections.Counter()
win_links = collections.Counter()
temporal_links = collections.Counter()
danger_links = collections.Counter()
examples = collections.defaultdict(list)

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
            for l in lex:
                all_links[l.rule] += 1
            # which links form windows
            r = classify_task(names, suite, links=lex, committed=committed(steps))
            wkeys = {(w.check_idx, w.use_idx) for w in r["windows"]}
            for w in r["windows"]:
                b = bind_of(suite, w.use_tool, w.resource)
                for l in lex:
                    if (l.source_idx, l.sink_idx) != (w.check_idx, w.use_idx):
                        continue
                    win_links[l.rule] += 1
                    if b in (Bind.DEREFERENCE, Bind.CONTROL):
                        temporal_links[l.rule] += 1
                        if len(examples[l.rule]) < 6:
                            examples[l.rule].append((suite, d.get("user_task_id"), str(l)[:130]))
                    break

def show(name, c):
    t = sum(c.values())
    print("%-22s total=%d" % (name, t))
    for rule, n in c.most_common():
        print("     %-10s %6d  (%.1f%%)" % (rule, n, 100*n/max(t,1)))

show("ALL LEXICAL LINKS", all_links)
show("LINKS FORMING WINDOWS", win_links)
show("LINKS -> TEMPORAL WIN", temporal_links)
print()
for rule, ex in examples.items():
    print("=== temporal examples: %s ===" % rule)
    for s,t,e in ex:
        print("   %-9s %-22s %s" % (s, t, e))
