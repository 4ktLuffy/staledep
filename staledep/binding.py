"""Can mutating state change what a sink actually does?

This bounds exploitability, and it is a STATIC property of the tool catalog --
independent of trajectory, model, or replay harness.

CLASSIFIED PER EDGE, NOT PER TOOL. An earlier version labelled whole tools, which
is wrong in a way that erases real dependencies. `send_money` simultaneously:

    - carries a SNAPSHOT literal recipient (mutation-immune)
    - reads the CURRENT balance as a predicate (funds must suffice)
    - acts from the CURRENT source account identity

Calling the tool "SNAPSHOT" discards the last two. The unit of classification is
therefore (observed resource -> sink), and one tool can appear under several
kinds.

    SNAPSHOT      the checked value is copied into the argument. Mutating the
                  source afterwards changes nothing.
                  read_file -> send_money(recipient="DE89...")

    DEREFERENCE   the sink names an entity resolved against live state at
                  execution. If the record moved, the effect lands elsewhere.
                  get_scheduled -> update_scheduled_transaction(id=7)

    CONTROL       the checked value gates WHETHER or HOW the sink runs, without
                  being copied into it. A balance check does not appear in
                  send_money's arguments but determines whether it succeeds.

    UNKNOWN       not classifiable from the signature. Counted separately; never
                  folded into the exploitable set.

Only DEREFERENCE and CONTROL edges can be exploited by state mutation. SNAPSHOT
edges cannot, however wide the window -- which is why a broad candidate rate was
never a danger figure.
"""

from __future__ import annotations

from enum import Enum


class Bind(Enum):
    SNAPSHOT = "snapshot"
    DEREFERENCE = "dereference"
    CONTROL = "control"
    UNKNOWN = "unknown"


#: (suite, sink_tool) -> {observed_resource: Bind}
#: "*" is the fallback for resources not named explicitly.
#: Judgement calls are commented; they are the contestable part.
EDGE_BINDING: dict[tuple[str, str], dict[str, Bind]] = {
    # --- banking -------------------------------------------------------------
    ("banking", "send_money"): {
        # recipient/amount are copied in as literals
        "file": Bind.SNAPSHOT,
        "transactions": Bind.SNAPSHOT,
        # No balance entry. It used to say CONTROL, "funds must suffice AT
        # EXECUTION". send_money never reads the balance -- verified against the
        # pinned source, which builds a Transaction and appends it. The gate is
        # real banking, not this system.
        # the sending account is resolved live (`sender=get_iban(account)`)
        "account.iban": Bind.DEREFERENCE,
        "*": Bind.UNKNOWN,
    },
    ("banking", "schedule_transaction"): {
        "file": Bind.SNAPSHOT, "transactions": Bind.SNAPSHOT,
        "account.iban": Bind.DEREFERENCE,      # same live sender resolution
        "*": Bind.UNKNOWN,
    },
    ("banking", "update_scheduled_transaction"): {
        # id=7 resolves to whichever record now holds it -- lost update
        "scheduled": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },
    ("banking", "update_user_info"): {
        # fields literal, but the target is the implicit current user record
        "user": Bind.DEREFERENCE, "file": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("banking", "update_password"): {
        "user": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },

    # --- slack ---------------------------------------------------------------
    ("slack", "send_direct_message"): {
        "workspace.users": Bind.DEREFERENCE,   # handle resolved live
        "inbox": Bind.SNAPSHOT, "web": Bind.SNAPSHOT, "messages": Bind.SNAPSHOT,
        "*": Bind.UNKNOWN,
    },
    ("slack", "send_channel_message"): {
        "channels": Bind.DEREFERENCE,
        "web": Bind.SNAPSHOT, "messages": Bind.SNAPSHOT, "inbox": Bind.SNAPSHOT,
        "*": Bind.UNKNOWN,
    },
    ("slack", "add_user_to_channel"): {
        "channel.users": Bind.DEREFERENCE, "channels": Bind.DEREFERENCE,
        "*": Bind.UNKNOWN,
    },
    ("slack", "remove_user_from_slack"): {
        "workspace.users": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },
    ("slack", "invite_user_to_slack"): {
        "web": Bind.SNAPSHOT, "inbox": Bind.SNAPSHOT,     # email is a literal
        "workspace.users": Bind.CONTROL,                   # already-member gate
        "*": Bind.UNKNOWN,
    },
    ("slack", "post_webpage"): {
        "web": Bind.DEREFERENCE,                           # url names a target
        "inbox": Bind.SNAPSHOT, "messages": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },

    # --- travel --------------------------------------------------------------
    # All three reservation tools take the venue NAME as a string and assign
    # `reservation.title = name`. The collection is never consulted, so mutating
    # it cannot move the booking -- that is SNAPSHOT. These said DEREFERENCE,
    # "price/availability resolved at booking", which is what a real booking
    # system does and not what this one does.
    ("travel", "reserve_hotel"): {
        "hotels": Bind.SNAPSHOT,
        "user": Bind.DEREFERENCE,        # get_user_information(user), resolved live
        "*": Bind.UNKNOWN,
    },
    ("travel", "reserve_restaurant"): {
        "restaurants": Bind.SNAPSHOT, "user": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },
    ("travel", "reserve_car_rental"): {
        "cars": Bind.SNAPSHOT, "user": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },
    ("travel", "cancel_calendar_event"): {
        "calendar": Bind.DEREFERENCE, "*": Bind.UNKNOWN,
    },
    ("travel", "create_calendar_event"): {
        # Was CONTROL, "slot-free check gates the booking". VERIFIED FICTION:
        # CalendarClient.create_event allocates a fresh id and assigns
        # self.events[id_] = event. There is no overlap check, no availability
        # test, nothing that consults existing events to decide. Mutating the
        # calendar cannot change what gets booked, which is SNAPSHOT.
        # tests/test_binding_matches_source.py passed this because the body
        # contains `calendar.create_event(...)` -- a delegation MENTION is not
        # evidence of gating. That is a false negative in the checker itself,
        # now recorded in its docstring.
        "calendar": Bind.SNAPSHOT,
        "hotels": Bind.SNAPSHOT, "restaurants": Bind.SNAPSHOT,
        "cars": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("travel", "send_email"): {
        "user": Bind.SNAPSHOT, "hotels": Bind.SNAPSHOT,
        "restaurants": Bind.SNAPSHOT, "cars": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },

    # --- workspace -----------------------------------------------------------
    ("workspace", "append_to_file"): {"files": Bind.DEREFERENCE, "*": Bind.UNKNOWN},
    ("workspace", "delete_file"): {"files": Bind.DEREFERENCE, "*": Bind.UNKNOWN},
    ("workspace", "delete_email"): {"email.received": Bind.DEREFERENCE, "*": Bind.UNKNOWN},
    ("workspace", "share_file"): {
        "files": Bind.DEREFERENCE, "contacts": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("workspace", "cancel_calendar_event"): {"calendar": Bind.DEREFERENCE, "*": Bind.UNKNOWN},
    ("workspace", "reschedule_calendar_event"): {"calendar": Bind.DEREFERENCE, "*": Bind.UNKNOWN},
    ("workspace", "add_calendar_event_participants"): {
        "calendar": Bind.DEREFERENCE, "contacts": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("workspace", "create_calendar_event"): {
        # Was CONTROL, "free-slot check". Same verified fiction as the travel
        # entry above and the same underlying client method:
        # CalendarClient.create_event allocates a fresh id and assigns
        # self.events[id_] = event, with no overlap or availability check.
        # Mutating the calendar cannot change what gets booked.
        "calendar": Bind.SNAPSHOT,
        "email.received": Bind.SNAPSHOT, "files": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("workspace", "create_file"): {
        # Was CONTROL, "name-collision check". VERIFIED FICTION, the third of
        # this shape: create_file allocates _get_next_id() = max(existing)+1 and
        # assigns self.files[id] = new_file. There is no collision check and
        # duplicate filenames are permitted. It reads `files` only to pick an id,
        # which an attacker cannot steer, so mutating the drive cannot change
        # what is created.
        "files": Bind.SNAPSHOT,
        "email.received": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("workspace", "send_email"): {
        "contacts": Bind.SNAPSHOT, "email.received": Bind.SNAPSHOT,
        "files": Bind.SNAPSHOT, "calendar": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
}

# --- claude code (real sessions, not a benchmark) --------------------------
# Edit carries old_string, which must match EXACTLY or the call fails. That is a
# staleness guard: if the file moved, the edit does not land wrong, it refuses.
# Write has no such guard -- it overwrites whatever is at the path now. Same
# resource, same window, opposite safety, which is precisely why binding has to
# be per edge rather than per tool.
EDGE_BINDING.update({
    ("claude_code", "Edit"): {
        "workspace.files": Bind.SNAPSHOT,   # exact-match old_string fails safe
        "web": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("claude_code", "MultiEdit"): {
        "workspace.files": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    ("claude_code", "Write"): {
        # Was DEREFERENCE, "overwrites whatever is there now, including changes
        # made since the Read". REFUTED BY EXPERIMENT (see module docstring):
        # Write is guarded by the same staleness check as Edit and aborts with
        # "File has been modified since read". A concurrent mutation cannot
        # redirect the write, it cancels it, so the edge is not movable.
        "workspace.files": Bind.SNAPSHOT,
        "web": Bind.SNAPSHOT, "*": Bind.UNKNOWN,
    },
    # NotebookEdit and TodoWrite appear ZERO times in the live corpus, so their
    # bindings were asserted from the tool name and never exercised. Declaring
    # them UNKNOWN is the honest state: untested is not the same as snapshot.
    ("claude_code", "NotebookEdit"): {
        "workspace.files": Bind.UNKNOWN, "*": Bind.UNKNOWN,
    },
    ("claude_code", "Bash"): {
        # arbitrary effect; cannot be classified from a signature
        "workspace.files": Bind.UNKNOWN, "shell": Bind.UNKNOWN,
        "web": Bind.UNKNOWN, "*": Bind.UNKNOWN,
    },
    ("claude_code", "TodoWrite"): {"todo": Bind.UNKNOWN, "*": Bind.UNKNOWN},
})


#: Only these can be moved by mutating state.
EXPLOITABLE = frozenset({Bind.DEREFERENCE, Bind.CONTROL})


def bind_of(suite: str, sink_tool: str, resource: str) -> Bind:
    """Classify one (observed resource -> sink) edge."""
    table = EDGE_BINDING.get((suite, sink_tool))
    if table is None:
        return Bind.UNKNOWN
    # An absence check copied no value into the action, so the only channel by
    # which it could have influenced the action is control flow. Unlike the
    # send_money balance gate this does not assume anything about the sink's
    # implementation -- it is a deduction from an observed empty result.
    if resource.startswith("absence:"):
        return Bind.CONTROL
    # a dataflow pseudo-resource resolves through its source tool's reads
    if resource.startswith("dataflow:"):
        from .effects import effects_for
        src = resource.split(":", 1)[1]
        eff = effects_for(suite).get(src)
        if eff is None:
            return table.get("*", Bind.UNKNOWN)
        kinds = {table.get(r, table.get("*", Bind.UNKNOWN)) for r in eff.reads}
        for k in (Bind.DEREFERENCE, Bind.CONTROL, Bind.UNKNOWN, Bind.SNAPSHOT):
            if k in kinds:
                return k
        return Bind.UNKNOWN
    return table.get(resource, table.get("*", Bind.UNKNOWN))


def is_exploitable_edge(suite: str, sink_tool: str, resource: str) -> bool:
    return bind_of(suite, sink_tool, resource) in EXPLOITABLE
