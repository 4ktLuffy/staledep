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


@dataclass(frozen=True)
class Effect:
    risk: Risk
    reads: frozenset[str] = field(default_factory=frozenset)
    writes: frozenset[str] = field(default_factory=frozenset)


def _r(*names: str) -> frozenset[str]:
    return frozenset(names)


# --- banking -----------------------------------------------------------------
# send_money reads the account (funds + originating IBAN) as well as writing it;
# that implicit read is precisely what a TOCTOU attack targets.
BANKING: dict[str, Effect] = {
    "get_balance":                  Effect(Risk.READ,  reads=_r("account.balance")),
    "get_iban":                     Effect(Risk.READ,  reads=_r("account.iban")),
    "get_most_recent_transactions": Effect(Risk.READ,  reads=_r("transactions")),
    "get_scheduled_transactions":   Effect(Risk.READ,  reads=_r("scheduled")),
    "get_user_info":                Effect(Risk.READ,  reads=_r("user")),
    "read_file":                    Effect(Risk.READ,  reads=_r("file")),
    "schedule_transaction":         Effect(Risk.WRITE, reads=_r("account.balance"), writes=_r("scheduled")),
    "update_scheduled_transaction": Effect(Risk.WRITE, reads=_r("scheduled"),       writes=_r("scheduled")),
    "send_money":                   Effect(Risk.HIGH,  reads=_r("account.balance", "account.iban"),
                                                       writes=_r("account.balance", "transactions")),
    "update_user_info":             Effect(Risk.HIGH,  reads=_r("user"),            writes=_r("user")),
    "update_password":              Effect(Risk.HIGH,  reads=_r("user"),            writes=_r("user.password")),
}

# --- slack -------------------------------------------------------------------
# get_webpage and read_inbox return attacker-influenceable content: they are the
# entry points for indirect injection, not merely reads.
SLACK: dict[str, Effect] = {
    "get_channels":           Effect(Risk.READ,  reads=_r("channels")),
    "get_users_in_channel":   Effect(Risk.READ,  reads=_r("channel.users")),
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
    "reserve_car_rental":    Effect(Risk.HIGH,  reads=_r("cars", "user"),        writes=_r("reservations")),
    "reserve_hotel":         Effect(Risk.HIGH,  reads=_r("hotels", "user"),      writes=_r("reservations")),
    "reserve_restaurant":    Effect(Risk.HIGH,  reads=_r("restaurants", "user"), writes=_r("reservations")),
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
