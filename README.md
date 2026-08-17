# staledep

Finds **stale-dependency candidates** in LLM agent trajectories: places where an
agent reads state at one step and acts on it later, without anything guaranteeing
the state is unchanged in between.

```
get_iban()          -> DE89370400440532013000        # check
   ... other steps ...                                # <- candidate window
send_money(recipient="DE89370400440532013000")        # use
```

**This is a measurement instrument, not a vulnerability scanner.** A candidate is
an opportunity, not a demonstrated exploit — see [Scope](#scope-what-this-does-not-claim).

## Why the careful naming

An earlier version of this README called these "TOCTOU vulnerabilities" and
reported a prevalence figure. Two independent reviews established that was wrong,
and the corrections are worth stating plainly because they shaped the design:

- **Read-then-act is the definition of agency.** Any agent doing nontrivial work
  reads state and later acts on it. Binary per-trajectory candidate rate is
  therefore close to tautological, and rises with tool-call count.
- **Copying a checked value into the action often *prevents* retargeting.**
  `read_file` → `send_money(literal_amount)` is a snapshot, not a race: mutating
  the file afterwards changes nothing. A genuine time-of-check/time-of-use bug
  requires the action to *dereference* current state at use time.

A defensible vulnerability claim needs four conditions. This tool establishes
part of the first:

1. the action causally depends on the earlier observation
2. a stated attacker can mutate the relevant state during the interval
3. that mutation invalidates an authorization predicate or rebinds the action
4. the unsafe action still commits

## Method

Two independent signals, because either alone misses cases.

**Effect typing** (`effects.py`) — tools declare the resources they read and
write, plus a risk tier. A `READ` of `R` followed by a state-changing call
depending on `R` is a candidate.

**Lexical lineage** (`provenance.py`) — links a later call's argument values back
to earlier tool output. Catches candidates effect typing cannot see, such as
`read_file` → `send_money` where no resource is shared.

> Naming note: this is **lexical evidence, not provenance**. String and token
> overlap do not prove causality — a value may equally have come from the user
> prompt, model knowledge, or coincidence. Establishing real provenance needs
> tagged handles or counterfactual perturbation.

Matching is conservative: bare small integers, short prose fragments, and
error-message text are rejected as evidence.

## Measurements

Over 2,540 attack-free trajectories from 29 **model/configuration pairs** (not 29
independent models — several are defense variants of the same base) shipped with
[AgentDojo](https://github.com/ethz-spylab/agentdojo):

| metric | value |
|---|---|
| Trajectories containing a candidate | 45.4% |
| With a high-risk sink | 15.9% |
| Candidates per tool call | 0.078 – 0.398 across configurations |

**Report the normalized figures, not the binary rate.** The binary rate largely
tracks how many calls a model made before stopping. Under normalization the
model ranking scrambles completely — a configuration near the bottom of the
binary table (`claude-3-sonnet-repeat_user_prompt`, 38.7%) has the *highest*
candidate density per call (0.398).

Denominator note: 2,756 attack-free run files exist; 216 contained zero tool
calls and are excluded; 57 model-task cells are absent from the upstream data.

### Retracted

Earlier drafts reported two findings and a comparison. All are withdrawn:

- ~~"Capability correlates with exposure"~~ — an artifact. Does not survive
  normalization by tool-call count.
- ~~"Prompt-injection defenses don't help"~~ — definitionally expected. They
  operate on message content and cannot change the read/act structure of a
  benign trajectory. Only `tool_filter` moves the number, and removing
  unnecessary authority is least privilege, not a fake defense.
- ~~"3.5× higher than the published 12%"~~ — numerology. It multiplied
  incompatible experimental units. The figures are not comparable: different
  criterion, different task subset, different counting unit.

## Scope: what this does not claim

- **Not prevalence.** Precision-adjusting a flagged rate does not yield
  prevalence while false negatives are unquantified.
- **Precision ≈93%**, from three hand-audited samples of 14–18. The interval on
  that is roughly 70–99%. Too small to stratify.
- **Recall unquantified.** Known structural blind spots: control dependence
  (a read gates *whether* a call happens), negative evidence ("no invoice
  exists"), aggregates and arithmetic, semantic transformation, aliasing,
  mutable references, laundering through intermediate tools, and implicit reads
  inside write tools.
- **Effect declarations are self-reported.** A third-party tool that
  under-declares silently removes edges.
- **Attack-free runs only.**

## Related work

- [arXiv:2508.17155](https://arxiv.org/abs/2508.17155) — established the problem;
  hand-labelled a filtered AgentDojo subset, not released. Heuristic mitigations
  moved executed-trajectory vulnerability 12% → 8%.
- [ACID-Agent](https://github.com/TsinghuaDatabaseGroup/ACID-Agent)
  (arXiv:2608.13900) — transactional framing for agents. Its released
  implementation targets **task reliability**, evaluated on KramaBench for task
  success, rather than adversarial security.
- Classical prior art this does **not** claim to invent: optimistic concurrency
  control, HTTP `If-Match`/ETag conditional requests, capability-based security,
  the Saga pattern, idempotency keys.

## Usage

```python
from staledep.trajectory import steps_from_messages, tool_names
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task

steps, errored = steps_from_messages(messages)
links = trace_from_log(steps, errored)
result = classify_task(tool_names(steps), "banking", links=links)
```

## Tests

Every test corresponds to a bug found by hand-auditing real output.

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
