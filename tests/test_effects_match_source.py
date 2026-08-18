"""Declared read/write effects, checked against the tool bodies.

Bindings only classify windows that already exist; `effects.py` decides whether a
window FORMS. A wrong entry here is worse than a wrong binding, because it can
hide a window as well as invent one: a tool declared read-only never invalidates
an earlier check, so a stale check keeps getting credited.

This is the write-direction check. It is deliberately narrow, because writing it
taught the same lesson three times: a sloppy analyser invents findings faster
than it finds them. Three of its own bugs, each of which produced confident
false results before being caught:

  1. `slack.user_channels[user].append(c)` -- stopping the name walk at the
     Subscript yielded "" and reported add_user_to_channel as writing nothing.
  2. `users = []; users.append(x)` -- counting locals reported read-only tools as
     writers. Only chains rooted at a `Depends(...)` parameter are state.
  3. `calendar.create_event(...)` -- stopping at the call site saw a READ and
     reported TEN tools as "declared writer but writes nothing". One level of
     delegation into the client method is resolved.

TWO CLASSES ARE EXEMPT, listed rather than silently passed:

  ALIAS_MUTATORS  fetch an object out of state and mutate the object:
      `file = cloud_drive.get_file_by_id(id); file.shared_with[email] = perm`
      The write is real but invisible to root-based tracking. Each was read by
      hand and confirmed to write.

  LOG_ONLY_WRITES  write something that is not the modelled resource.
      get_webpage does `web.web_requests.append(url)` -- a request log, not page
      content. Declaring it a writer of `web` would invalidate every earlier
      content check and delete genuine windows. The resource models content; the
      log write is deliberately unmodelled.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from staledep.effects import effects_for

TOOLS = pathlib.Path(__file__).resolve().parents[1] / (
    "reference/agentdojo/src/agentdojo/default_suites/v1/tools")
MUTATORS = {"append", "pop", "remove", "clear", "update", "extend",
            "insert", "add", "discard", "setdefault", "sort"}

#: Verified by hand: the write happens through an object fetched from state.
ALIAS_MUTATORS = {
    "update_scheduled_transaction",   # t = next(...); t.amount = ...
    "append_to_file",                 # file = get_file_by_id(); file.content += ...
    "share_file",                     # file = get_file_by_id(); file.shared_with[e] = p
    "add_calendar_event_participants",
    "reschedule_calendar_event",
}
#: Writes something other than the resource the declaration models.
LOG_ONLY_WRITES = {"get_webpage"}


class _Effects(ast.NodeVisitor):
    def __init__(self, roots):
        self.roots, self.reads, self.writes, self.calls = roots, set(), set(), []

    def _chain(self, node):
        parts = []
        while True:
            if isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            elif isinstance(node, ast.Subscript):
                node = node.value          # bug 1: walk THROUGH the index
            else:
                break
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _is_state(self, chain):           # bug 2: locals are not state
        return "." in chain and chain.split(".")[0] in self.roots

    def visit_Attribute(self, node):
        c = self._chain(node)
        if self._is_state(c):
            (self.writes if isinstance(node.ctx, ast.Store) else self.reads).add(c)
        self.generic_visit(node)

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Attribute):
            target = self._chain(f.value)
            if f.attr in MUTATORS and self._is_state(target):
                self.writes.add(target)
                self.reads.discard(target)
            elif target.split(".")[0] in self.roots:
                self.calls.append(f.attr)   # bug 3: delegation, resolve later
        self.generic_visit(node)

    def visit_Subscript(self, node):
        if isinstance(node.ctx, ast.Store):
            c = self._chain(node.value)
            if self._is_state(c):
                self.writes.add(c)
        self.generic_visit(node)


def _analyse():
    methods, funcs = {}, {}
    for path in TOOLS.glob("*.py"):
        tree = ast.parse(path.read_text())
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            for m in [n for n in cls.body
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
                v = _Effects({"self"})
                for st in m.body:
                    v.visit(st)
                prev = methods.get(m.name, set())
                methods[m.name] = prev | v.writes
        for n in tree.body:
            if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            roots = {a.arg for a in list(n.args.args) + list(n.args.kwonlyargs)
                     if a.annotation is not None and "Depends" in ast.dump(a.annotation)}
            if not roots:
                continue
            v = _Effects(roots)
            for st in n.body:
                v.visit(st)
            funcs[n.name] = (v.writes, v.calls)
    resolved = {}
    for tool, (writes, calls) in funcs.items():
        w = set(writes)
        for c in calls:
            w |= {x.replace("self.", "", 1) for x in methods.get(c, set())}
        resolved[tool] = w
    return resolved


WRITES = _analyse() if TOOLS.is_dir() else {}
CASES = sorted(
    (suite, tool)
    for suite in ("banking", "slack", "travel", "workspace")
    for tool in effects_for(suite)
    if tool in WRITES
)


@pytest.mark.skipif(not TOOLS.is_dir(), reason="AgentDojo source not vendored")
@pytest.mark.parametrize("suite,tool", CASES, ids=[f"{s}.{t}" for s, t in CASES])
def test_declared_writer_status_matches_the_source(suite, tool):
    declared = bool(effects_for(suite)[tool].writes)
    observed = bool(WRITES[tool])
    if tool in ALIAS_MUTATORS:
        assert declared, f"{tool} is a listed alias-mutator but declares no write"
        return
    if tool in LOG_ONLY_WRITES:
        assert not declared, f"{tool} is listed as log-only but declares a write"
        return
    assert declared == observed, (
        f"{suite}.{tool} declares writes={declared} but its source writes="
        f"{sorted(WRITES[tool]) or 'nothing'}. If the write goes through an object "
        f"fetched from state, add it to ALIAS_MUTATORS with the line that proves it."
    )
