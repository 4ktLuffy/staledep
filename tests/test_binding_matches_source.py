"""Every non-snapshot binding must be justified by the tool's actual source.

52.2% of the headline danger set rests on effect typing alone -- no lineage, just
the hand-written tables in binding.py asserting that a tool resolves a resource
live. Those tables were written from what the tools are NAMED and what the
domain implies, and not one entry had been checked against AgentDojo's code.

Two were wrong, both in the same direction, both inventing a dependency:

    banking send_money   "account.balance": CONTROL
        Claimed the balance gates the transfer. It does not. send_money builds a
        Transaction, appends it to account.transactions and returns. There is no
        balance read, no overdraft check, nothing. A real bank gates on funds;
        this mock does not, and the binding has to describe the system under
        analysis rather than the system it resembles.

    travel  reserve_hotel / reserve_restaurant   "hotels"/"restaurants": DEREFERENCE
        Claimed price and availability are resolved at booking. They are not.
        Both take the venue NAME as a string and assign reservation.title = name.
        The collection is never consulted, so mutating it cannot move the
        booking: that is the definition of SNAPSHOT.

DEREFERENCE and CONTROL are the claims that produce danger flags, so an
unjustified one manufactures a vulnerability. This test makes the claim checkable
instead of asserted: if a tool's implementation never touches the resource, it
cannot be resolving it live.

It reads the vendored AgentDojo source pinned in CORPUS.md. It is deliberately a
NECESSARY condition, not a sufficient one -- a mention proves the resource is
reachable, not that it is dereferenced. It cannot confirm a binding is right; it
can only catch one that is impossible.

DEMONSTRATED FALSE NEGATIVE. It passed
("workspace","create_calendar_event"): {"calendar": CONTROL} for four
iterations. The body contains `calendar.create_event(...)`, which satisfies the
mention test -- but create_event allocates a fresh id and assigns
self.events[id_] = event, consulting nothing. A delegation MENTION is not
evidence of gating, and 83 windows rested on that fiction.

WHAT COUNTS AS EVIDENCE NOW. A CONTROL binding claims the sink reads the
resource to DECIDE, so the bar is a conditional that depends on it: a branch,
comparison, or raise reached from the resource. A DEREFERENCE binding claims the
sink resolves an argument against the resource, so the bar is a lookup keyed by
an argument. Neither is inferable from a bare call, so where static evidence is
absent the binding needs runtime evidence
(tests/test_intervention_harness.py) or an explicit attestation recorded at the
entry. ATTESTED below names the entries carrying a human-checked justification
rather than a mechanical one.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from staledep.binding import EDGE_BINDING, Bind

TOOLS = pathlib.Path(__file__).resolve().parents[1] / (
    "reference/agentdojo/src/agentdojo/default_suites/v1/tools")

#: Bindings whose justification is a hand-read of the implementation rather than
#: anything this checker can establish. Naming them is the point: an attestation
#: that is not written down is indistinguishable from an oversight.
ATTESTED = {
    ("banking", "send_money", "account.iban"),      # sender=get_iban(account)
    ("workspace", "delete_file", "files"),          # files.pop(file_id)
    ("workspace", "share_file", "files"),           # get_file_by_id then mutate acl
}

#: The symbol in AgentDojo's source that a staledep resource name refers to.
#: A resource with no entry is not checkable here and is skipped explicitly
#: rather than silently passing.
RESOURCE_SYMBOL: dict[tuple[str, str], tuple[str, ...]] = {
    ("banking", "account.balance"): ("balance",),
    ("banking", "account.iban"): ("iban", "get_iban"),
    ("banking", "scheduled"): ("scheduled_transactions",),
    ("banking", "transactions"): ("transactions",),
    ("banking", "user"): ("account.", "user_account", "first_name", "street"),
    ("slack", "channels"): ("channels",),
    ("slack", "workspace.users"): ("users",),
    ("slack", "channel.users"): ("user_channels", "channels"),
    ("slack", "web"): ("web", "url"),
    ("travel", "hotels"): ("hotels",),
    ("travel", "restaurants"): ("restaurants",),
    ("travel", "cars"): ("car_rental",),
    ("travel", "calendar"): ("calendar", "events"),
    ("travel", "user"): ("user", "get_user_information"),
    ("workspace", "files"): ("cloud_drive", "files"),
    ("workspace", "calendar"): ("calendar", "events"),
    ("workspace", "inbox"): ("inbox", "emails"),
}


def _source_index() -> dict[str, str]:
    """Every tool function's BODY, by name -- signature and docstring excluded.

    The signature is excluded deliberately. AgentDojo declares its state as
    `Annotated[CarRental, Depends("car_rental")]` parameters, so every tool
    mentions its own resource in its signature whether or not it ever reads it.
    Checking the whole function made this test pass trivially for exactly the
    entries it exists to catch. The docstring goes too: prose about hotels is not
    a hotel lookup.
    """
    out: dict[str, str] = {}
    for path in TOOLS.glob("*.py"):
        text = path.read_text()
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            stmts = node.body
            if (stmts and isinstance(stmts[0], ast.Expr)
                    and isinstance(stmts[0].value, ast.Constant)
                    and isinstance(stmts[0].value.value, str)):
                stmts = stmts[1:]          # drop the docstring
            body = "\n".join(ast.get_source_segment(text, s) or "" for s in stmts)
            out[node.name] = out.get(node.name, "") + body
    return out


SOURCE = _source_index()

CASES = [
    (suite, tool, resource, bind)
    for (suite, tool), table in sorted(EDGE_BINDING.items())
    for resource, bind in sorted(table.items())
    if bind in (Bind.DEREFERENCE, Bind.CONTROL)
    and suite in {"banking", "slack", "travel", "workspace"}
]


@pytest.mark.skipif(not TOOLS.is_dir(), reason="AgentDojo source not vendored")
@pytest.mark.parametrize("suite,tool,resource,bind", CASES,
                         ids=[f"{s}.{t}.{r}" for s, t, r, _ in CASES])
def test_live_resolution_claim_is_reachable_in_the_tool_source(suite, tool, resource, bind):
    """A tool that never mentions a resource cannot be resolving it at call time."""
    body = SOURCE.get(tool)
    if body is None:
        pytest.skip(f"{tool} not found in vendored source")
    symbols = RESOURCE_SYMBOL.get((suite, resource))
    if symbols is None:
        pytest.skip(f"no source symbol mapped for {suite}/{resource}")
    assert any(sym in body for sym in symbols), (
        f"{suite}.{tool} is declared {bind.value} on '{resource}', which claims it "
        f"resolves that resource live -- but its implementation never mentions "
        f"{list(symbols)}. Either the binding is wrong or the mapping is."
    )


def test_a_delegation_mention_is_not_evidence_of_gating():
    """REGRESSION for the checker's own false negative.

    ("workspace","create_calendar_event"): {"calendar": CONTROL} passed this
    module for four iterations because the body contains
    `calendar.create_event(...)`. create_event allocates a fresh id and assigns;
    it consults nothing. 83 windows rested on it.

    The binding is now SNAPSHOT, so the fiction cannot return silently. The
    checker still cannot tell a gating read from a delegation, which is why the
    bar for CONTROL is a conditional on the resource and why ATTESTED exists."""
    from staledep.binding import Bind, bind_of

    body = SOURCE.get("create_calendar_event", "")
    assert "calendar" in body, "the mention that fooled the checker is still there"
    assert bind_of("workspace", "create_calendar_event", "calendar") is Bind.SNAPSHOT
    assert bind_of("travel", "create_calendar_event", "calendar") is Bind.SNAPSHOT


def test_control_bindings_are_either_conditional_backed_or_attested():
    """A CONTROL binding claims the sink reads the resource to DECIDE. That needs
    a conditional reached from the resource, or a recorded attestation."""
    import re as _re
    unjustified = []
    for suite, tool, resource, bind in CASES:
        if bind is not Bind.CONTROL:
            continue
        if (suite, tool, resource) in ATTESTED:
            continue
        body = SOURCE.get(tool, "")
        if not _re.search(r"\b(if|raise|assert|while|else)\b", body):
            unjustified.append((suite, tool, resource))
    assert not unjustified, (
        f"CONTROL with no conditional in the body and no attestation: "
        f"{unjustified}. That is the create_calendar_event failure shape."
    )


# ------------------------------------------------- adversarial checker fixtures
#: Hand-written bodies that probe exactly what the checker can and cannot prove.
#: Written because the checker's one demonstrated false negative was found by
#: accident, four iterations after it shipped.
_FIXTURES = {
    "irrelevant_conditional_plus_delegation": '''
        if not title:
            raise ValueError("title required")
        return calendar.create_event(title, start)
    ''',
    "lookup_keyed_by_the_wrong_argument": '''
        return cloud_drive.files[owner_email].content
    ''',
    "lookup_only_after_the_sink": '''
        result = cloud_drive.create_file(filename, content)
        existing = cloud_drive.files.get(file_id)
        return result, existing
    ''',
    "real_resource_derived_conditional": '''
        if user in slack.users:
            raise ValueError("already a member")
        slack.users.append(user)
    ''',
    "real_argument_keyed_dereference": '''
        file = cloud_drive.files.pop(file_id)
        return file
    ''',
}


def _mentions(body, symbol):
    """What the current checker actually tests: does the body name the resource."""
    return symbol in body


def _has_resource_conditional(body, symbol):
    """The bar for CONTROL: a conditional reached from the resource."""
    import re as _re
    for line in body.splitlines():
        if _re.search(r"\b(if|while|assert)\b", line) and symbol in line:
            return True
    return False


def _has_argument_keyed_lookup(body, symbol, argument):
    """The bar for DEREFERENCE: a lookup into the resource keyed by an argument."""
    import re as _re
    return bool(_re.search(rf"{_re.escape(symbol)}[\.\[][^\n]*{_re.escape(argument)}", body)
                or _re.search(rf"{_re.escape(symbol)}\[[^\]]*{_re.escape(argument)}", body))


def test_mention_alone_cannot_distinguish_any_of_the_five():
    """WHAT THE CHECKER PROVES, stated as a failure. Every fixture mentions its
    resource, including the three that establish nothing -- so the mention test
    is necessary and nowhere near sufficient. This is the create_calendar_event
    failure in miniature."""
    assert _mentions(_FIXTURES["irrelevant_conditional_plus_delegation"], "calendar")
    assert _mentions(_FIXTURES["lookup_only_after_the_sink"], "cloud_drive")
    assert _mentions(_FIXTURES["real_argument_keyed_dereference"], "cloud_drive")


def test_the_control_bar_accepts_only_a_resource_derived_conditional():
    real = _FIXTURES["real_resource_derived_conditional"]
    fake = _FIXTURES["irrelevant_conditional_plus_delegation"]
    assert _has_resource_conditional(real, "slack.users")
    assert not _has_resource_conditional(fake, "calendar"), (
        "`if not title` is a conditional, but not one reached from the resource"
    )


def test_the_dereference_bar_needs_the_right_argument_as_the_key():
    real = _FIXTURES["real_argument_keyed_dereference"]
    wrong = _FIXTURES["lookup_keyed_by_the_wrong_argument"]
    assert _has_argument_keyed_lookup(real, "cloud_drive", "file_id")
    assert not _has_argument_keyed_lookup(wrong, "cloud_drive", "file_id"), (
        "files[owner_email] is a lookup, but not keyed by the argument in question"
    )


def test_a_lookup_after_the_sink_is_not_a_dependency_and_needs_ordering():
    """The limit this fixture proves: the bar is textual and order-blind. Here
    the lookup follows create_file, so the sink cannot depend on it -- and the
    regex cannot tell. This case requires runtime evidence or an attestation,
    which is precisely why ATTESTED exists."""
    body = _FIXTURES["lookup_only_after_the_sink"]
    assert _has_argument_keyed_lookup(body, "cloud_drive", "file_id"), (
        "the textual bar passes here, and it should not -- ordering is invisible"
    )
    sink_at = body.index("create_file")
    lookup_at = body.index("files.get")
    assert sink_at < lookup_at, "the lookup happens after the sink has committed"
