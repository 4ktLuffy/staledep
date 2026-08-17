"""Find tasks where the agent actually emits a state-changing call.

The gap sweep needs a task the agent ACTS on. It does not need one the agent
passes: the action oracle judges emitted calls, so a task the agent fails is
still usable as long as it reaches a sink. Selecting by utility instead of by
action is what voided the first sweep -- and on this suite four of sixteen
utility checks pass without the agent doing anything at all.
"""

import os
import sys

os.environ.setdefault("OPENAI_COMPATIBLE_BASE_URL", "http://localhost:11434/v1")
os.environ.setdefault("OPENAI_COMPATIBLE_API_KEY", "ollama")

import openai  # noqa: E402
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline  # noqa: E402
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage  # noqa: E402
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM  # noqa: E402
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor  # noqa: E402
from agentdojo.functions_runtime import FunctionsRuntime  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from staledep.oracle import ActionLog, make_recording_runtime  # noqa: E402
from staledep.provenance import trace_from_log  # noqa: E402
from staledep.toctou import classify_task  # noqa: E402

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen3.5:4b-mlx"
SUITE = "banking"


def main() -> None:
    suite = get_suite("v1", SUITE)
    client = openai.OpenAI(base_url=os.environ["OPENAI_COMPATIBLE_BASE_URL"], api_key="ollama")
    llm = LocalLLM(client, MODEL, temperature=0.0)
    pipeline = AgentPipeline([
        SystemMessage("You are an AI assistant that can use tools to help the user."),
        InitQuery(), llm, ToolsExecutor(), llm,
    ])
    pipeline.name = MODEL

    print(f"model={MODEL} suite={SUITE}\n")
    print("%-14s %-6s %-6s %-9s %s" % ("TASK", "UTIL", "ACTS", "WINDOW", "calls"))
    print("-" * 92)
    usable = []
    for tid, task in sorted(suite.user_tasks.items()):
        log = ActionLog()
        try:
            utility, _ = suite.run_task_with_pipeline(
                pipeline, task, injection_task=None, injections={},
                runtime_class=make_recording_runtime(FunctionsRuntime, log))
        except Exception as exc:
            print("%-14s ERROR %s" % (tid, str(exc)[:60]))
            continue

        high = log.high_risk(SUITE)
        changing = log.state_changing(SUITE)
        steps = [(c.tool, c.args, None) for c in log.calls]
        r = classify_task(log.tools(), SUITE, links=trace_from_log(steps))

        acts = "HIGH" if high else ("write" if changing else "-")
        print("%-14s %-6s %-6s %-9s %s" % (
            tid, utility, acts,
            "yes" if r["candidate"] else "-",
            " -> ".join(log.tools())[:46]))
        # Usable for a sweep: the agent reaches a state-changing call.
        if changing:
            usable.append((tid, bool(high), r["candidate"]))

    print()
    print("USABLE FOR A SWEEP (agent emits a state-changing call):")
    for tid, high, cand in usable:
        print("   %-14s high_risk=%-6s candidate_window=%s" % (tid, high, cand))
    if not usable:
        print("   none -- this model never reaches a sink on this suite")


if __name__ == "__main__":
    main()
