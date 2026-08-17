"""Stale-dependency candidate detection over agent trajectories.

A candidate is an OPPORTUNITY, not a demonstrated vulnerability. Read-then-act is
the definition of agency, and copying a checked value into an action often
prevents retargeting rather than enabling it. Naming these "vulnerabilities"
was retracted; see the README.

The criterion is adapted from "Mind the Gap" (arXiv:2508.17155), which the
authors applied *by hand* to 97 AgentDojo tasks and did not release:

    "whether an earlier tool call reads the state of a resource and whether a
     later call assumes that state remains unchanged"

Formalised here as: a call at step i reads resource R, and a later call at step
j > i depends on R (reads it implicitly) while acting on it. The interval
(i, j) is the *window* -- the span during which a mutation of R would go unnoticed.

Doing this in code rather than by hand makes the labels auditable and lets the
same criterion run over live trajectories, not just ground truth.
"""

from __future__ import annotations

from dataclasses import dataclass

from .binding import Bind, bind_of
from .effects import Effect, Risk, effects_for, is_attacker_writable


@dataclass(frozen=True)
class Window:
    """A candidate window: state read at `check`, acted upon at `use`."""
    resource: str
    check_idx: int
    check_tool: str
    use_idx: int
    use_tool: str
    use_risk: Risk

    @property
    def span(self) -> int:
        """Steps between check and use. A wider span is a wider attack window."""
        return self.use_idx - self.check_idx

    def __str__(self) -> str:
        return (
            f"{self.resource}: {self.check_tool}@{self.check_idx} -> "
            f"{self.use_tool}@{self.use_idx} (span {self.span}, {self.use_risk.value})"
        )


def find_windows(
    calls: list[str],
    suite: str,
    *,
    high_risk_only: bool = False,
    step_effects: list | None = None,
) -> list[Window]:
    """Find candidate windows in an ordered sequence of tool names.

    A window exists when an explicit READ of R is followed by a later call that
    both depends on R and changes state. The later call re-reads R implicitly and
    assumes it is unchanged -- that assumption is what makes it a candidate.

    Only the most recent check before each use is reported, since that is the
    narrowest defensible window; reporting every earlier read would inflate counts.
    """
    table = effects_for(suite)
    windows: list[Window] = []
    last_read: dict[str, tuple[int, str]] = {}

    for idx, name in enumerate(calls):
        # Per-call effect wins over name-based typing. Bash is the reason: its
        # effect lives in the command string, so `Bash(ls)` is a READ and must
        # not act as a sink, while `Bash(rm)` writes. Typing it by name made
        # 78% of live windows unclassifiable.
        eff: Effect | None = None
        if step_effects is not None and idx < len(step_effects) and step_effects[idx]:
            eff = step_effects[idx]
        else:
            eff = table.get(name)
        if eff is None:
            continue  # undeclared tool: cannot reason about it, so do not guess

        if eff.risk is not Risk.READ and (not high_risk_only or eff.risk is Risk.HIGH):
            # A state-changing call: any resource it depends on that was read
            # earlier constitutes a window.
            for resource in eff.reads:
                prior = last_read.get(resource)
                if prior is not None:
                    windows.append(Window(
                        resource=resource,
                        check_idx=prior[0], check_tool=prior[1],
                        use_idx=idx, use_tool=name, use_risk=eff.risk,
                    ))

        # Record reads *after* checking, so a call that reads and writes the same
        # resource does not form a window with itself.
        #
        # Only an explicit READ counts as a check. Audit finding: letting a
        # write's implicit read register as a check produced windows between two
        # consecutive send_direct_message calls, where neither was a verification.
        if eff.risk is Risk.READ:
            for resource in eff.reads:
                last_read[resource] = (idx, name)

        # A write invalidates any earlier check of what it wrote: subsequent uses
        # must re-verify against the new state, not the stale one.
        for resource in eff.writes:
            last_read.pop(resource, None)

    return windows


def windows_from_provenance(calls: list[str], links, suite: str,
                            step_effects: list | None = None) -> list[Window]:
    """Convert data-flow links into candidate windows.

    A link says a later call's argument came from an earlier call's output. If
    that later call changes state, then it acted on a value it checked earlier
    and assumed unchanged -- the same shape as a state dependency, just carried
    through arguments instead of shared resources.
    """
    table = effects_for(suite)
    windows: list[Window] = []
    # One window per (check, use) pair, not per argument. Audit finding: the bill
    # case produced three windows because three arguments flowed across a single
    # read->send edge, inflating window counts threefold.
    seen: set[tuple[int, int]] = set()
    for link in links:
        eff = None
        if step_effects is not None and link.sink_idx < len(step_effects) and step_effects[link.sink_idx]:
            eff = step_effects[link.sink_idx]
        else:
            eff = table.get(link.sink_tool)
        if eff is None or eff.risk is Risk.READ:
            continue  # a read acting on stale data changes nothing
        key = (link.source_idx, link.sink_idx)
        if key in seen:
            continue
        seen.add(key)
        windows.append(Window(
            resource=f"dataflow:{link.source_tool}",
            check_idx=link.source_idx, check_tool=link.source_tool,
            use_idx=link.sink_idx, use_tool=link.sink_tool,
            use_risk=eff.risk,
        ))
    return windows


def classify_task(calls: list[str], suite: str, links=None, threat_model: str = "moderate",
                  committed: list[bool] | None = None,
                  step_effects: list | None = None,
                  step_binds: list | None = None,
                  numeric_links=None) -> dict:
    """Label a single task as carrying a stale-dependency candidate or not.

    `links` are optional provenance edges from staledep.provenance.trace; without
    them only state-typed windows are found, which under-counts.
    """
    windows = find_windows(calls, suite, step_effects=step_effects)
    n_state = len(windows)
    # Numeric lineage: an argument DERIVED from earlier output rather than copied.
    # Lexical matching is blind to it, which is why aggregates and rate
    # derivations -- most financial arithmetic -- had zero coverage.
    all_links = list(links or [])
    if numeric_links:
        all_links = all_links + list(numeric_links)
    links = all_links or None
    if links:
        seen = {(w.check_idx, w.use_idx, w.resource) for w in windows}
        for w in windows_from_provenance(calls, links, suite, step_effects):
            if (w.check_idx, w.use_idx, w.resource) not in seen:
                windows.append(w)
                seen.add((w.check_idx, w.use_idx, w.resource))

    # A sink that raised did not commit. An uncommitted action is not an
    # exploited use, so it is counted separately rather than silently included.
    if committed is not None:
        uncommitted = [w for w in windows
                       if w.use_idx < len(committed) and not committed[w.use_idx]]
        windows = [w for w in windows
                   if w.use_idx >= len(committed) or committed[w.use_idx]]
    else:
        uncommitted = []

    # Edge-level binding. A SNAPSHOT edge copies the checked value into the
    # argument and cannot be moved by mutating state, however wide the window.
    def _bind(w):
        if step_binds is not None and w.use_idx < len(step_binds) and step_binds[w.use_idx]:
            return step_binds[w.use_idx]
        return bind_of(suite, w.use_tool, w.resource)

    temporal = [w for w in windows if _bind(w) in (Bind.DEREFERENCE, Bind.CONTROL)]
    snapshot_only = [w for w in windows if _bind(w) is Bind.SNAPSHOT]
    unknown_bind = [w for w in windows if _bind(w) is Bind.UNKNOWN]

    high = [w for w in windows if w.use_risk is Risk.HIGH]
    # Conditioning on mutability is what makes this a threat statement rather
    # than a restatement of what agency is. A candidate over state only the user
    # can write has no adversary in a position to move it.
    exposed = [w for w in windows if is_attacker_writable(suite, w.resource, threat_model)]
    exposed_high = [w for w in exposed if w.use_risk is Risk.HIGH]
    # The narrow set: temporal binding AND an attacker who can move it AND a
    # high-risk sink that committed.
    danger = [w for w in temporal
              if is_attacker_writable(suite, w.resource, threat_model)]
    danger_high = [w for w in danger if w.use_risk is Risk.HIGH]
    return {
        "n_calls": len(calls),
        "candidate": bool(windows),
        "n_windows": len(windows),
        "n_state_windows": n_state,
        "n_dataflow_windows": len(windows) - n_state,
        "n_high_risk_windows": len(high),
        # attacker-writable subset
        "exposed": bool(exposed),
        "n_exposed_windows": len(exposed),
        "n_exposed_high_risk": len(exposed_high),
        # lexical/effect flow vs temporal dependency -- these are NOT the same
        "temporal": bool(temporal),
        "n_temporal_windows": len(temporal),
        "n_snapshot_only_windows": len(snapshot_only),
        "n_unknown_bind_windows": len(unknown_bind),
        "n_uncommitted_sink_windows": len(uncommitted),
        "danger": bool(danger),
        "n_danger_windows": len(danger),
        "n_danger_high_risk": len(danger_high),
        "max_span": max((w.span for w in windows), default=0),
        "resources": sorted({w.resource for w in windows}),
        "windows": windows,
    }
