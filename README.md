# agenttx

Detects **time-of-check-to-time-of-use (TOCTOU) windows** in LLM agent trajectories.

An agent reads state at one step and acts on it several steps later. Between those
two points, nothing guarantees the state is unchanged. That interval is a *window*:

```
get_iban()            -> DE89 3704 0044 0532 0130 00     # check
   ... other steps ...                                    # <- window
send_money(recipient="DE89 3704 0044 0532 0130 00")       # use
```

This library finds those windows automatically, in ground-truth task definitions
or in recorded trajectories.

## Why

[*Mind the Gap: Time-of-Check to Time-of-Use Vulnerabilities in LLM-Enabled
Agents*](https://arxiv.org/abs/2508.17155) (arXiv:2508.17155) established the
problem, hand-labelling a filtered subset of [AgentDojo](https://github.com/ethz-spylab/agentdojo)
tasks. That labelled set was not released, and hand-labelling does not scale to
live trajectories.

`agenttx` implements the same criterion in auditable code:

> an earlier tool call reads the state of a resource, and a later call assumes
> that state remains unchanged

## How it works

Detection runs on two independent signals, because either alone misses cases.

**1. Effect typing** (`agenttx/effects.py`) — every tool declares the resources it
reads and writes, plus a risk tier. A `READ` of `R` followed by a state-changing
call that depends on `R` is a window.

**2. Argument provenance** (`agenttx/provenance.py`) — links a later call's
argument values back to the earlier output they came from. This catches windows
effect typing cannot see. In AgentDojo's `banking/user_task_0` the agent calls
`read_file` then `send_money` with an amount taken *from that file*; no resource
is shared, yet swapping the file redirects the payment.

Provenance matching is deliberately conservative. Bare small integers, short
prose fragments and error-message text are rejected as evidence, because a false
link invents a vulnerability that is not there.

## Usage

```python
from agenttx.trajectory import steps_from_messages, tool_names
from agenttx.provenance import trace_from_log
from agenttx.toctou import classify_task

steps, errored = steps_from_messages(messages)      # AgentDojo-format message log
links = trace_from_log(steps, errored)
result = classify_task(tool_names(steps), "banking", links=links)

result["vulnerable"]            # bool
result["n_windows"]             # distinct check->use edges
result["n_high_risk_windows"]   # edges whose use is irreversible/financial
result["max_span"]              # widest window, in steps
```

## Results

Measured over **2,540 attack-free trajectories** from 29 models whose runs ship
with AgentDojo:

| | rate |
|---|---|
| Trajectories containing a TOCTOU window | **45.4%** |
| Containing a window with a high-risk sink | **15.9%** |
| Estimated true prevalence (precision-adjusted) | **~42%** |

By suite: slack 73.4%, banking 47.8% (32.5% high-risk), workspace 39.8%,
travel 26.2%.

Two observations that were not expected:

**Capability correlates with exposure.** The most capable models are the most
exposed, because they complete more multi-step work. Weaker models are "safer"
only because they give up sooner.

**Prompt-injection defenses do not help.** `Meta-SecAlign-70B` — explicitly
hardened against injection — sits at the top of the table. `spotlighting_with_delimiting`
and `repeat_user_prompt` variants are indistinguishable from their base models.
Only `tool_filter` moves the number, and it does so by removing tools rather than
protecting them.

Reproduce with `python measure_published.py` (requires the AgentDojo clone).

## Honest limitations

Read these before citing any number above.

- **The 45.4% is not directly comparable to the paper's 12%.** They labelled a
  filtered 66-task subset; this measures all 97 tasks across 29 models. Same base,
  different denominator. The gap is plausibly explained by their automated
  detector's reported 25% true-positive rate, but that is a hypothesis, not a
  finding.
- **Precision is ~93%, measured by hand-auditing 3 samples of 14–18 flagged
  trajectories.** That sample is too small for a published precision figure; 50+
  is the right size.
- **Recall is not quantified.** One blind class was found and fixed by auditing
  unflagged trajectories (synthesised arguments). Others may remain.
- **A window is an opportunity, not an exploit.** Nothing here demonstrates that
  these windows are reachable by an attacker. That requires a state-mutation
  primitive fired inside the window, which AgentDojo does not provide.
- **Attack-free runs only.** Trajectories with an active injection are excluded.
- **Weakest evidence class:** numeric matches inside prose bodies. Usually
  genuine, but the thinnest link type the matcher produces.

## Tests

Every test corresponds to a bug found by hand-auditing real trajectories.

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT
