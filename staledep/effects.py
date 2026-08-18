"""Effect typing for agent tools.

Every tool is declared with the resources it READS and the resources it WRITES,
plus a risk tier. This is the foundation the transaction layer needs: to know
whether a call requires a version-pinned capability token, you must first know
what state it depends on.

Resources are coarse-grained names, not object identities. That is deliberate --
TOCTOU windows open at the granularity an attacker can mutate, and an attacker
who can change one scheduled transaction can usually change the set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Risk(Enum):
    READ = "read"        # observes state, changes nothing
    WRITE = "write"      # mutates state, ordinarily reversible
    HIGH = "high"        # irreversible, financial, or privilege-affecting


class Writer(Enum):
    """Who can mutate a resource during a trajectory.

    A stale-dependency candidate over a resource only the user can write is dead
    code: nobody hostile is in a position to move it. Conditioning on this is
    what separates "the agent read something and later acted" -- true of all
    agency -- from "the agent acted on state an adversary controls".

    Ordered loosely by hostility.
    """
    UNTRUSTED = "untrusted"        # arbitrary third parties write this
    COUNTERPARTY = "counterparty"  # a specific external party legitimately writes it
    AGENT = "agent"                # another agent or concurrent process
    USER = "user"                  # only the principal or their systems
    STATIC = "static"              # effectively immutable within a session


#: Which resources an adversary can move, per suite. These are judgements about
#: AgentDojo's environments, not facts derivable from the code, so they are
#: stated explicitly and can be argued with.
RESOURCE_WRITERS: dict[str, dict[str, Writer]] = {
    "banking": {
        # AgentDojo's bill files are the banking injection vector: attacker text
        # lands here and the agent pays from it.
        "file":            Writer.UNTRUSTED,
        # Anyone who can send you money writes your transaction history, and the
        # recipient IBANs in it get reused by agents issuing refunds.
        "transactions":    Writer.COUNTERPARTY,
        "account.balance": Writer.COUNTERPARTY,   # inbound transfers move it
        "account.iban":    Writer.USER,
        "scheduled":       Writer.AGENT,
        "user":            Writer.AGENT,          # update_user_info is agent-reachable
        "user.password":   Writer.AGENT,
    },
    "slack": {
        "web":             Writer.UNTRUSTED,      # arbitrary websites
        "inbox":           Writer.UNTRUSTED,      # anyone can send
        "messages":        Writer.UNTRUSTED,      # any channel member
        "channels":        Writer.AGENT,
        "channel.users":   Writer.AGENT,
        "workspace.users": Writer.AGENT,
    },
    "travel": {
        # Providers legitimately change their own prices, hours and availability
        # between the agent checking and booking.
        "hotels":       Writer.COUNTERPARTY,
        "restaurants":  Writer.COUNTERPARTY,
        "cars":         Writer.COUNTERPARTY,
        "flights":      Writer.COUNTERPARTY,
        "calendar":     Writer.AGENT,
        "reservations": Writer.AGENT,
        "user":         Writer.USER,
        "email.sent":   Writer.USER,
    },
    "workspace": {
        "email.received": Writer.UNTRUSTED,       # anyone can email you
        "files":          Writer.UNTRUSTED,       # shared drive, external collaborators
        "files.acl":      Writer.AGENT,
        "calendar":       Writer.UNTRUSTED,       # external invitees write your calendar
        "contacts":       Writer.USER,
        "email.drafts":   Writer.USER,
        "email.sent":     Writer.USER,
        "clock":          Writer.STATIC,
    },
}

#: Threat models, from strict to permissive. Which one applies is a deployment
#: question, so the rate is reported at each tier rather than collapsed into one
#: number.
#:
#: A first pass folded AGENT into the attacker set and the filter turned out
#: vacuous -- it removed 0.1% of candidates -- because nearly every resource is
#: agent-writable. In a single-agent deployment there is no other agent, so that
#: tier only means something under concurrency.
THREAT_MODELS: dict[str, frozenset[Writer]] = {
    # Arbitrary third parties: inbound email, web pages, channel messages,
    # uploaded documents. The attacker needs no relationship with the victim.
    "strict":   frozenset({Writer.UNTRUSTED}),
    # Plus parties with legitimate write access to their own records: a supplier
    # changing bank details, a hotel changing prices.
    "moderate": frozenset({Writer.UNTRUSTED, Writer.COUNTERPARTY}),
    # Plus concurrent agents or processes. Only meaningful in multi-agent
    # deployments; otherwise this tier is close to unconditioned.
    "multi_agent": frozenset({Writer.UNTRUSTED, Writer.COUNTERPARTY, Writer.AGENT}),
}

ATTACKER_WRITABLE = THREAT_MODELS["moderate"]


def writer_of(suite: str, resource: str) -> Writer | None:
    """Who writes `resource`. Dataflow pseudo-resources resolve via their source tool."""
    table = RESOURCE_WRITERS.get(suite, {})
    if resource in table:
        return table[resource]
    if resource.startswith("dataflow:"):
        tool = resource.split(":", 1)[1]
        eff = SUITES.get(suite, {}).get(tool)
        if eff is not None:
            # The window is only as hostile as the most hostile thing the source read.
            writers = [table[r] for r in eff.reads if r in table]
            for w in (Writer.UNTRUSTED, Writer.COUNTERPARTY, Writer.AGENT, Writer.USER):
                if w in writers:
                    return w
    return None


def is_attacker_writable(suite: str, resource: str, threat_model: str = "moderate") -> bool:
    """Can an adversary under `threat_model` move this resource mid-trajectory?

    An unknown resource returns False, which EXCLUDES it from conditioned counts.
    That is a silent undercount, so `writer_coverage` exists to catch it and a
    test asserts every read resource has a declared writer.
    """
    if threat_model not in THREAT_MODELS:
        raise ValueError(
            f"unknown threat model {threat_model!r}; expected one of {sorted(THREAT_MODELS)}"
        )
    w = writer_of(suite, resource)
    return w is not None and w in THREAT_MODELS[threat_model]


def writer_coverage(suite: str) -> tuple[set[str], set[str]]:
    """Return (declared, undeclared) resources for a suite's effect table.

    Undeclared resources are silently treated as not-attacker-writable, which
    understates every conditioned rate. Windows form only on resources a sink
    READS, so those are the ones that actually corrupt counts -- but all are
    reported here, since an effect table can gain a reader at any time.
    """
    table = SUITES.get(suite, {})
    used = {r for e in table.values() for r in (e.reads | e.writes)}
    declared = set(RESOURCE_WRITERS.get(suite, {}))
    return used & declared, used - declared


@dataclass(frozen=True)
class Effect:
    risk: Risk
    reads: frozenset[str] = field(default_factory=frozenset)
    writes: frozenset[str] = field(default_factory=frozenset)


def _r(*names: str) -> frozenset[str]:
    return frozenset(names)


# --- banking -----------------------------------------------------------------
# send_money resolves the ORIGINATING IBAN at call time (`sender=get_iban(account)`),
# and that implicit read is what a TOCTOU attack targets. It does NOT read the
# balance: the implementation builds a Transaction, appends it to
# account.transactions and returns, with no funds check anywhere. A real bank
# gates on available funds and this mock does not, so declaring the read was
# describing the system it resembles instead of the system under analysis.
# Verified against the pinned source by tests/test_binding_matches_source.py.
BANKING: dict[str, Effect] = {
    "get_balance":                  Effect(Risk.READ,  reads=_r("account.balance")),
    "get_iban":                     Effect(Risk.READ,  reads=_r("account.iban")),
    "get_most_recent_transactions": Effect(Risk.READ,  reads=_r("transactions")),
    "get_scheduled_transactions":   Effect(Risk.READ,  reads=_r("scheduled")),
    "get_user_info":                Effect(Risk.READ,  reads=_r("user")),
    "read_file":                    Effect(Risk.READ,  reads=_r("file")),
    "schedule_transaction":         Effect(Risk.WRITE, reads=_r("account.iban"),     writes=_r("scheduled")),
    "update_scheduled_transaction": Effect(Risk.WRITE, reads=_r("scheduled"),       writes=_r("scheduled")),
    "send_money":                   Effect(Risk.HIGH,  reads=_r("account.iban"),
                                                       writes=_r("transactions")),
    "update_user_info":             Effect(Risk.HIGH,  reads=_r("user"),            writes=_r("user")),
    "update_password":              Effect(Risk.HIGH,  reads=_r("user"),            writes=_r("user.password")),
}

# --- slack -------------------------------------------------------------------
# get_webpage and read_inbox return attacker-influenceable content: they are the
# entry points for indirect injection, not merely reads.
SLACK: dict[str, Effect] = {
    "get_channels":           Effect(Risk.READ,  reads=_r("channels")),
    "get_users_in_channel":   Effect(Risk.READ,  reads=_r("channel.users")),
    # Declared READ although the body does `web.web_requests.append(url)`. That
    # write is a request LOG, not page content, and `web` models content. Calling
    # it a writer would invalidate every earlier content check and delete genuine
    # windows. A deliberate modelling choice, not an oversight -- it is listed in
    # LOG_ONLY_WRITES in tests/test_effects_match_source.py so it stays visible.
    "get_webpage":            Effect(Risk.READ,  reads=_r("web")),
    "read_channel_messages":  Effect(Risk.READ,  reads=_r("messages")),
    "read_inbox":             Effect(Risk.READ,  reads=_r("inbox")),
    "add_user_to_channel":    Effect(Risk.WRITE, reads=_r("channel.users"), writes=_r("channel.users")),
    "post_webpage":           Effect(Risk.WRITE, writes=_r("web")),
    "send_channel_message":   Effect(Risk.WRITE, reads=_r("channels"),      writes=_r("messages")),
    "send_direct_message":    Effect(Risk.WRITE, reads=_r("workspace.users"), writes=_r("messages")),
    "invite_user_to_slack":   Effect(Risk.HIGH,  reads=_r("workspace.users"), writes=_r("workspace.users")),
    "remove_user_from_slack": Effect(Risk.HIGH,  reads=_r("workspace.users"), writes=_r("workspace.users")),
}

# --- travel ------------------------------------------------------------------
_TRAVEL_READS = {
    "check_restaurant_opening_hours": "restaurants", "get_all_car_rental_companies_in_city": "cars",
    "get_all_hotels_in_city": "hotels", "get_all_restaurants_in_city": "restaurants",
    "get_car_fuel_options": "cars", "get_car_price_per_day": "cars", "get_car_rental_address": "cars",
    "get_car_types_available": "cars", "get_contact_information_for_restaurants": "restaurants",
    "get_cuisine_type_for_restaurants": "restaurants", "get_day_calendar_events": "calendar",
    "get_dietary_restrictions_for_all_restaurants": "restaurants", "get_flight_information": "flights",
    "get_hotels_address": "hotels", "get_hotels_prices": "hotels", "get_price_for_restaurants": "restaurants",
    "get_rating_reviews_for_car_rental": "cars", "get_rating_reviews_for_hotels": "hotels",
    "get_rating_reviews_for_restaurants": "restaurants", "get_restaurants_address": "restaurants",
    "get_user_information": "user", "search_calendar_events": "calendar",
}
TRAVEL: dict[str, Effect] = {n: Effect(Risk.READ, reads=_r(res)) for n, res in _TRAVEL_READS.items()}
TRAVEL.update({
    "create_calendar_event": Effect(Risk.WRITE, reads=_r("calendar"), writes=_r("calendar")),
    "cancel_calendar_event": Effect(Risk.WRITE, reads=_r("calendar"), writes=_r("calendar")),
    "reserve_car_rental":    Effect(Risk.HIGH,  reads=_r("user"),        writes=_r("reservations")),
    "reserve_hotel":         Effect(Risk.HIGH,  reads=_r("user"),      writes=_r("reservations")),
    "reserve_restaurant":    Effect(Risk.HIGH,  reads=_r("user"), writes=_r("reservations")),
    "send_email":            Effect(Risk.HIGH,  reads=_r("user"),                writes=_r("email.sent")),
})

# --- workspace ---------------------------------------------------------------
_WS_READS = {
    "get_current_day": "clock", "get_day_calendar_events": "calendar", "get_draft_emails": "email.drafts",
    "get_file_by_id": "files", "get_received_emails": "email.received", "get_sent_emails": "email.sent",
    "get_unread_emails": "email.received", "list_files": "files", "search_calendar_events": "calendar",
    "search_contacts_by_email": "contacts", "search_contacts_by_name": "contacts",
    "search_emails": "email.received", "search_files": "files", "search_files_by_filename": "files",
}
WORKSPACE: dict[str, Effect] = {n: Effect(Risk.READ, reads=_r(res)) for n, res in _WS_READS.items()}
WORKSPACE.update({
    "create_file":                     Effect(Risk.WRITE, writes=_r("files")),
    "append_to_file":                  Effect(Risk.WRITE, reads=_r("files"),    writes=_r("files")),
    "create_calendar_event":           Effect(Risk.WRITE, reads=_r("calendar"), writes=_r("calendar")),
    "cancel_calendar_event":           Effect(Risk.WRITE, reads=_r("calendar"), writes=_r("calendar")),
    "reschedule_calendar_event":       Effect(Risk.WRITE, reads=_r("calendar"), writes=_r("calendar")),
    "add_calendar_event_participants": Effect(Risk.WRITE, reads=_r("calendar", "contacts"), writes=_r("calendar")),
    "delete_file":                     Effect(Risk.HIGH,  reads=_r("files"),    writes=_r("files")),
    "delete_email":                    Effect(Risk.HIGH,  reads=_r("email.received"), writes=_r("email.received")),
    "share_file":                      Effect(Risk.HIGH,  reads=_r("files", "contacts"), writes=_r("files.acl")),
    "send_email":                      Effect(Risk.HIGH,  reads=_r("contacts"), writes=_r("email.sent")),
})

SUITES: dict[str, dict[str, Effect]] = {
    "banking": BANKING, "slack": SLACK, "travel": TRAVEL, "workspace": WORKSPACE,
}


def effects_for(suite: str) -> dict[str, Effect]:
    return SUITES[suite]


def coverage(suite: str, tool_names: list[str]) -> tuple[list[str], list[str]]:
    """Return (declared, undeclared) so a missing tool is never silently ignored."""
    table = SUITES[suite]
    declared = [n for n in tool_names if n in table]
    undeclared = [n for n in tool_names if n not in table]
    return declared, undeclared
