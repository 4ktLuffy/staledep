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
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from staledep.binding import EDGE_BINDING, Bind

TOOLS = pathlib.Path(__file__).resolve().parents[1] / (
    "reference/agentdojo/src/agentdojo/default_suites/v1/tools")

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
