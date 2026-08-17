"""Run the detector over real Claude Code sessions, not a benchmark.

AgentDojo is synthetic: scripted tasks, a fixed catalog, an environment built to
be evaluated. This reads trajectories from an agent doing actual work, which is
the only way to learn whether the detector says anything about live systems.

CONFIDENTIALITY. Transcripts contain whatever was being worked on, and provenance
matching reads argument values and tool output. The project directory is a
required argument with no default: choosing what is safe to inspect is the
caller's decision, not this script's.

Usage:
    python report_live.py ~/.claude/projects/<project>
"""

from __future__ import annotations

import collections
import glob
import os
import sys

from staledep.binding import bind_of
from staledep.claudecode import CLAUDE_CODE, load_session, register
from staledep.provenance import trace_from_log
from staledep.toctou import classify_task
from staledep.trajectory import committed, tool_names

SUITE = "claude_code"


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    register()
    files = sorted(glob.glob(os.path.join(os.path.expanduser(sys.argv[1]), "*.jsonl")))
    if not files:
        print("no .jsonl transcripts found")
        return 1

    stage = collections.Counter()
    undeclared = collections.Counter()
    shapes = collections.Counter()
    batched = 0
    total_calls = 0
    per_session = []

    for path in files:
        steps, errored = load_session(path)
        if not steps:
            continue
        total_calls += len(steps)
        for s in steps:
            if s.tool not in CLAUDE_CODE:
                undeclared[s.tool] += 1
        turns = collections.Counter(s.turn for s in steps)
        batched += sum(1 for t, c in turns.items() if c > 1)

        names = tool_names(steps)
        links = trace_from_log(steps, errored)
        r = classify_task(names, SUITE, links=links, committed=committed(steps))

        stage["sessions"] += 1
        stage["candidate"] += r["candidate"]
        stage["temporal"] += r["temporal"]
        stage["danger"] += r["danger"]
        stage["danger_high"] += bool(r["n_danger_high_risk"])
        for w in r["windows"]:
            b = bind_of(SUITE, w.use_tool, w.resource)
            shapes[(w.check_tool, w.use_tool, b.value, w.use_risk.value)] += 1
        per_session.append((os.path.basename(path)[:8], len(steps),
                            r["n_windows"], r["n_temporal_windows"],
                            r["n_snapshot_only_windows"], r["n_danger_high_risk"]))

    n = stage["sessions"]
    print("LIVE SESSIONS — real agent trajectories, not a benchmark\n")
    print("sessions analysed        : %d  (%d tool calls total)" % (n, total_calls))
    print("assistant turns emitting >1 call: %d  (same-turn exclusion applies to these)"
          % batched)
    if undeclared:
        print("UNDECLARED tools (skipped, not guessed): %s"
              % dict(undeclared.most_common(6)))
    print()
    print("%-28s %8s %9s" % ("STAGE", "COUNT", "RATE"))
    print("-" * 48)
    for k, label in [("sessions", "sessions"), ("candidate", "contain a candidate"),
                     ("temporal", "temporal (deref/control)"),
                     ("danger", "+ attacker-writable"),
                     ("danger_high", "+ high-risk committed sink")]:
        print("%-28s %8d %8.1f%%" % (label, stage[k], 100 * stage[k] / max(n, 1)))

    print("\nWINDOW SHAPES (check -> use, binding, risk)")
    for (c, u, b, risk), cnt in shapes.most_common(12):
        print("   %-16s -> %-14s %-12s %-6s %4d" % (c, u, b, risk, cnt))

    print("\nPER SESSION")
    print("%-10s %7s %8s %9s %10s %9s" % (
        "session", "calls", "windows", "temporal", "snapshot", "danger-hi"))
    for s, calls, w, t, snap, dh in per_session:
        print("%-10s %7d %8d %9d %10d %9d" % (s, calls, w, t, snap, dh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
