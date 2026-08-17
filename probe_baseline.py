"""Baseline utility probe: can a local model complete AgentDojo banking tasks?
If it can't, TOCTOU enforcement is unmeasurable. This number gates the project."""
import os
import sys
import time

os.environ["OPENAI_COMPATIBLE_BASE_URL"] = "http://localhost:11434/v1"
os.environ["OPENAI_COMPATIBLE_API_KEY"] = "ollama"

import openai
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.llms.local_llm import LocalLLM
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.task_suite.load_suites import get_suite

MODEL = sys.argv[1] if len(sys.argv) > 1 else "qwen3.5:4b-mlx"
N     = int(sys.argv[2]) if len(sys.argv) > 2 else 3

client = openai.OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
llm    = LocalLLM(client, MODEL, temperature=0.0)
suite  = get_suite("v1", "banking")

pipeline = AgentPipeline([
    SystemMessage("You are an AI assistant that can use tools to help the user."),
    InitQuery(),
    llm,
    ToolsExecutor(),
    llm,
])
pipeline.name = MODEL

print("model: %s | banking | first %d tasks\n" % (MODEL, N))
passed = 0
for tid, task in sorted(suite.user_tasks.items())[:N]:
    t0 = time.time()
    try:
        utility, security = suite.run_task_with_pipeline(
            pipeline, task, injection_task=None, injections={})
        passed += bool(utility)
        print("  %-13s utility=%-5s security=%-5s  %6.1fs" % (
            tid, utility, security, time.time() - t0))
    except Exception as e:
        print("  %-13s ERROR %s (%.0fs)" % (tid, str(e)[:90], time.time() - t0))

print("\nBASELINE UTILITY: %d/%d" % (passed, N))
