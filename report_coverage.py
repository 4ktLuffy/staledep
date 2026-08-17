"""The metric staledep should be judged on, and its baseline.

Accuracy is the wrong headline for this instrument. It does not predict a label;
it decides whether each (observed resource -> sink) edge can be moved by mutating
state. The failure that matters is therefore not a wrong answer but *no answer*:
an `unknown` binding means the detector cannot say whether a window is dangerous,
and a window it cannot classify is a window it cannot help with.

CLASSIFICATION COVERAGE = windows with a binding other than unknown / all windows

This is the right primary metric because:

  - it is computable on any corpus without ground-truth labels
  - it degrades honestly: adding tools the detector cannot model lowers it
  - it is the binding constraint. On live Claude Code sessions, Bash -> Bash
    alone is 1,406 of 2,751 windows, all unknown -- more than half the
    population is unanswerable, which no precision figure would reveal.

Reported alongside, because coverage alone can be gamed by guessing:

  DECIDED-DANGEROUS RATE   of classified windows, how many are deref/control
  UNKNOWN CONCENTRATION    which (check -> use) pairs produce the unknowns

Usage:
    python report_coverage.py                 # AgentDojo corpus
    python report_coverage.py --live <dir>    # real Claude Code sessions
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os

from staledep.binding import Bind, bind_of
from staledep.provenance import trace_from_log
from staledep.shell import effect_for_step
from staledep.toctou import classify_task
from staledep.trajectory import committed, steps_from_messages, tool_names

RUNS = "reference/agentdojo/runs"
SUITES = ["banking", "slack", "travel", "workspace"]


def _tally(windows, suite, binds, pairs, unknown_pairs, step_binds=None):
    for w in windows:
        if step_binds is not None and w.use_idx < len(step_binds) and step_binds[w.use_idx]:
            b = step_binds[w.use_idx]
        else:
            b = bind_of(suite, w.use_tool, w.resource)
        binds[b] += 1
        pairs[(w.check_tool, w.use_tool)] += 1
        if b is Bind.UNKNOWN:
            unknown_pairs[(suite, w.check_tool, w.use_tool)] += 1


def agentdojo():
    binds = collections.Counter()
    pairs = collections.Counter()
    unknown_pairs = collections.Counter()
    n_traj = 0
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
                n_traj += 1
                r = classify_task(tool_names(steps), suite,
                                  links=trace_from_log(steps, errored),
                                  committed=committed(steps))
                _tally(r["windows"], suite, binds, pairs, unknown_pairs)
    return n_traj, binds, unknown_pairs


def live(directory: str):
    from staledep.claudecode import load_session, register
    register()
    binds = collections.Counter()
    pairs = collections.Counter()
    unknown_pairs = collections.Counter()
    n_traj = n_files = n_no_calls = 0
    for path in sorted(glob.glob(os.path.join(os.path.expanduser(directory), "*.jsonl"))):
        n_files += 1
        steps, errored = load_session(path)
        if not steps:
            n_no_calls += 1          # reported, never silently dropped
            continue
        n_traj += 1
        pairs_eff = [effect_for_step(st.tool, st.args) for st in steps]
        step_effects = [pe[0] if pe else None for pe in pairs_eff]
        step_binds = [pe[1] if pe else None for pe in pairs_eff]
        r = classify_task(tool_names(steps), "claude_code",
                          links=trace_from_log(steps, errored),
                          committed=committed(steps),
                          step_effects=step_effects, step_binds=step_binds)
        _tally(r["windows"], "claude_code", binds, pairs, unknown_pairs, step_binds)
    print("transcripts on disk: %d | with tool calls: %d | conversation-only: %d"
          % (n_files, n_traj, n_no_calls))
    return n_traj, binds, unknown_pairs


def report(label, n_traj, binds, unknown_pairs):
    total = sum(binds.values())
    known = total - binds[Bind.UNKNOWN]
    dangerous = binds[Bind.DEREFERENCE] + binds[Bind.CONTROL]
    print("\n=== %s ===" % label)
    print("  trajectories                : %d" % n_traj)
    print("  windows                     : %d" % total)
    print("  CLASSIFICATION COVERAGE     : %d/%d  (%.1f%%)   <- primary metric"
          % (known, total, 100 * known / max(total, 1)))
    print("  of classified, deref/control: %d/%d  (%.1f%%)"
          % (dangerous, known, 100 * dangerous / max(known, 1)))
    for b in (Bind.SNAPSHOT, Bind.DEREFERENCE, Bind.CONTROL, Bind.UNKNOWN):
        print("     %-12s %6d  (%.1f%%)" % (b.value, binds[b], 100 * binds[b] / max(total, 1)))
    if unknown_pairs:
        print("  unknown concentrated in:")
        for (s, c, u), n in unknown_pairs.most_common(6):
            print("     %-11s %-16s -> %-16s %5d  (%.1f%% of all unknown)"
                  % (s, c, u, n, 100 * n / max(binds[Bind.UNKNOWN], 1)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", help="directory of Claude Code .jsonl transcripts")
    args = ap.parse_args()
    if args.live:
        report("LIVE (Claude Code sessions)", *live(args.live))
    else:
        report("AgentDojo corpus", *agentdojo())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
