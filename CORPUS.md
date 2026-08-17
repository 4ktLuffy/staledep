# Corpus provenance

Every measurement in the README is computed over trajectories shipped inside
AgentDojo, pinned here so figures are reproducible rather than merely stated.

    repository  https://github.com/ethz-spylab/agentdojo
    commit      089ed468cf3ed0322acc66b0211f26d9d90dbf60
    path        runs/<model>/<suite>/user_task_*/<attack>/*.json

Reproduce:

    git clone https://github.com/ethz-spylab/agentdojo reference/agentdojo
    git -C reference/agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
    pip install -e ".[dev]" && pip install -e reference/agentdojo
    python report_waterfall.py

Selection rules, stated because they set every denominator:

  - attack-free only: files carrying `injection_task_id` are excluded
  - a trajectory needs >=1 recorded tool call to be eligible
  - 2,756 attack-free files exist; 216 have zero tool calls and are excluded,
    giving n=2540
  - 57 model-task cells are absent from the upstream data
  - the 29 rows are model/CONFIGURATION pairs, not 29 independent models:
    several are defense variants of the same base
