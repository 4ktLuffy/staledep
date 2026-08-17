"""Apply the TOCTOU criterion to all 97 AgentDojo ground-truth trajectories,
using state typing + argument provenance."""
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from staledep.effects import coverage
from staledep.provenance import trace
from staledep.toctou import classify_task

grand_t = grand_v = grand_h = 0
state_only_total = 0
for suite_name in ["banking", "slack", "travel", "workspace"]:
    suite = get_suite("v1", suite_name)
    _, undeclared = coverage(suite_name, [t.name for t in suite.tools])
    if undeclared:
        print(f"!! {suite_name} UNDECLARED: {undeclared}")

    n = v = h = so = 0
    for _tid, task in sorted(suite.user_tasks.items()):
        env = suite.load_and_inject_default_environment({})
        try:
            gt = task.ground_truth(env)
        except Exception:
            continue
        calls = [(c.function, c.args) for c in gt]
        names = [c.function for c in gt]
        runtime = FunctionsRuntime(suite.tools)
        try:
            links, _ = trace(calls, runtime, env.model_copy(deep=True))
        except Exception:
            links = []
        r = classify_task(names, suite_name, links=links)
        n += 1
        v += r["candidate"]
        h += bool(r["n_high_risk_windows"])
        so += bool(r["n_state_windows"])
    grand_t += n
    grand_v += v
    grand_h += h
    state_only_total += so
    print("%-10s %2d/%2d vulnerable  (%2d state-only)  %2d with HIGH-risk window" % (
        suite_name, v, n, so, h))

print()
print("TOTAL vulnerable      : %d/%d (%.0f%%)" % (grand_v, grand_t, 100*grand_v/grand_t))
print("  state typing alone  : %d/%d (%.0f%%)" % (state_only_total, grand_t, 100*state_only_total/grand_t))
print("  with HIGH-risk sink : %d/%d (%.0f%%)" % (grand_h, grand_t, 100*grand_h/grand_t))
print()
print("Paper hand-labelled 56/66 of a filtered subset drawn from these same 97 tasks.")
