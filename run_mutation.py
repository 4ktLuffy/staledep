"""Run the gap sweep against a live agent on AgentDojo's banking suite.

Wraps FunctionsRuntime so a declared mutation fires after a chosen tool call,
then compares the outcome against the unmutated baseline and the two controls.

Usage:
    python run_mutation.py [model] [task_id]
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

from staledep.mutate import MUTATIONS, is_toctou, sweep_gaps  # noqa: E402

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen3.5:4b-mlx"
TASK = sys.argv[2] if len(sys.argv) > 2 else "user_task_0"
SUITE = "banking"


def make_runtime_class(mutation, gap):
    """A runtime that applies `mutation` after tool call number `gap`.

    gap == -1 fires before any call; gap >= n fires after the last one.
    """
    class MutatingRuntime(FunctionsRuntime):
        _calls = 0
        _fired = False

        def run_function(self, env, function, kwargs, raise_on_error=False):
            if gap == -1 and not MutatingRuntime._fired and env is not None:
                mutation.apply(env)
                MutatingRuntime._fired = True
            result = super().run_function(env, function, kwargs, raise_on_error)
            MutatingRuntime._calls += 1
            if (gap is not None and gap >= 0 and MutatingRuntime._calls == gap + 1
                    and not MutatingRuntime._fired and env is not None):
                mutation.apply(env)
                MutatingRuntime._fired = True
            return result

    MutatingRuntime._calls = 0
    MutatingRuntime._fired = False
    return MutatingRuntime


def build_pipeline():
    client = openai.OpenAI(base_url=os.environ["OPENAI_COMPATIBLE_BASE_URL"], api_key="ollama")
    llm = LocalLLM(client, MODEL, temperature=0.0)
    p = AgentPipeline([
        SystemMessage("You are an AI assistant that can use tools to help the user."),
        InitQuery(), llm, ToolsExecutor(), llm,
    ])
    p.name = MODEL
    return p


def main() -> None:
    suite = get_suite("v1", SUITE)
    task = suite.get_user_task_by_id(TASK)
    pipeline = build_pipeline()

    print(f"model={MODEL}  suite={SUITE}  task={TASK}")
    print(f"prompt: {task.PROMPT}\n")

    baseline = suite.run_task_with_pipeline(pipeline, task, injection_task=None, injections={})
    print(f"BASELINE (no mutation): utility={baseline[0]} security={baseline[1]}")

    env = suite.load_and_inject_default_environment({})
    n_gaps = len(task.ground_truth(env))
    print(f"ground-truth calls: {n_gaps}  -> sweeping gaps -1..{n_gaps}\n")

    for mutation in MUTATIONS[SUITE]:
        print(f"--- {mutation}")
        print(f"    {mutation.describe}")

        def run(gap, _m=mutation):
            return suite.run_task_with_pipeline(
                pipeline, task, injection_task=None, injections={},
                runtime_class=make_runtime_class(_m, gap),
            )

        outcomes = sweep_gaps(run, n_gaps, mutation)
        for o in outcomes:
            where = ("before all" if o.gap == -1
                     else "after last" if o.gap >= n_gaps
                     else f"after call {o.gap}")
            mark = "" if o.error else (
                "  <-- CHANGED" if (o.utility, o.security) != baseline else "")
            print(f"    gap {o.gap:>2} ({where:<12}) utility={o.utility} "
                  f"security={o.security}{mark}{'  ERROR: ' + o.error if o.error else ''}")

        verdict = is_toctou(outcomes, baseline, n_gaps)
        print(f"    VERDICT: {verdict['verdict']}")
        if verdict["interior_gaps_that_changed"]:
            print(f"    interior gaps that changed: {verdict['interior_gaps_that_changed']}")
        print()


if __name__ == "__main__":
    main()
