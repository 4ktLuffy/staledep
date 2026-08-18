"""Every binding claim exercised by the temporal set, audited against source.

The temporal count is only as good as the bindings under it. Three CONTROL
entries turned out to be fiction (send_money/schedule_transaction balance,
create_calendar_event, create_file), each found separately and by accident. This
is the finite sweep that closes the DEREFERENCE side, so "verified tables" can be
claimed or withdrawn on evidence rather than on the ones I happened to check.

SCOPE. 447 temporal trajectories contain 749 temporal windows over 29 unique
(suite, resource, sink, binding) edges, which collapse to 14 distinct BINDING
CLAIMS -- `dataflow:` pseudo-resources resolve through the source tool's reads,
so the claim being made is on the underlying resource. 14 is the auditable unit.

THE BAR, as set in tests/test_binding_matches_source.py:
    DEREFERENCE  a lookup keyed by an ARGUMENT of the sink
    CONTROL      a conditional reached from the resource

VERIFIED    the bar is met in the pinned source
REJECTED    the source contradicts the label
UNRESOLVED  the source neither establishes nor refutes it; needs runtime
            evidence or an attestation

Before this sweep, 11 of 14 claims were unaudited: only delete_file, share_file
and send_money.account.iban had been read. After it: 0 unaudited, 13 VERIFIED,
1 REJECTED. No claim remains UNRESOLVED -- both were settled by running the
mutation rather than by argument.
"""

from __future__ import annotations

import pathlib

import pytest

from staledep.binding import Bind, bind_of

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "reference/agentdojo/src/agentdojo/default_suites/v1/tools"
pytestmark = pytest.mark.skipif(not TOOLS.is_dir(), reason="corpus not vendored")

#: (suite, sink, resource, declared, windows, status, source evidence)
SWEEP = [
    ("slack", "send_channel_message", "channels", Bind.DEREFERENCE, 170, "VERIFIED",
     "slack.channel_inbox[channel].append(msg) -- lookup keyed by the `channel` argument"),
    ("workspace", "append_to_file", "files", Bind.DEREFERENCE, 160, "VERIFIED",
     "file = self.get_file_by_id(file_id); file.content += content"),
    ("slack", "add_user_to_channel", "channels", Bind.CONTROL, 137, "VERIFIED",
     "RELABELLED from DEREFERENCE after audit. `if channel not in slack.channels: "
     "raise` is a CONDITIONAL on the resource, which is the CONTROL bar; the "
     "mutation is user_channels[user], keyed by `user`, so it was never an "
     "argument-keyed lookup on `channels`. Both labels are temporal, so no count "
     "moves -- only the mechanism claim is now accurate."),
    ("banking", "update_scheduled_transaction", "scheduled", Bind.DEREFERENCE, 62, "VERIFIED",
     "next(t for t in account.scheduled_transactions if t.id == id) -- keyed by `id`"),
    ("banking", "send_money", "account.iban", Bind.DEREFERENCE, 48, "VERIFIED",
     "sender=get_iban(account) resolves the originating IBAN at call time"),
    ("workspace", "delete_file", "files", Bind.DEREFERENCE, 43, "VERIFIED",
     "self.files.pop(file_id) -- keyed by `file_id`; runtime-demonstrated"),
    ("workspace", "share_file", "files", Bind.DEREFERENCE, 33, "VERIFIED",
     "file = get_file_by_id(file_id); file.shared_with[email] = permission; "
     "runtime-demonstrated"),
    ("slack", "add_user_to_channel", "channel.users", Bind.DEREFERENCE, 27, "VERIFIED",
     "slack.user_channels[user].append(channel) -- keyed by the `user` argument"),
    ("workspace", "add_calendar_event_participants", "calendar", Bind.DEREFERENCE, 26, "VERIFIED",
     "event = self.events[event_id]; event.participants.extend(...) -- keyed by `event_id`"),
    ("workspace", "reschedule_calendar_event", "calendar", Bind.DEREFERENCE, 16, "VERIFIED",
     "if event_id not in self.events: raise; then mutates self.events[event_id]"),
    ("banking", "schedule_transaction", "account.iban", Bind.DEREFERENCE, 15, "VERIFIED",
     "sender=get_iban(account), same live resolution as send_money"),
    ("banking", "update_user_info", "user", Bind.SNAPSHOT, 10, "REJECTED",
     "RESOLVED BY RUNTIME EVIDENCE, and rejected. There is one account and no "
     "argument selects it, so the write cannot be retargeted. Unspecified fields do "
     "carry whatever an attacker left, but mutating INSIDE and OUTSIDE the window "
     "produce an identical post-state -- condition 4 fails, the window is "
     "irrelevant. Now SNAPSHOT; see test_update_user_info_fails_condition_four."),
    ("travel", "reserve_hotel", "user", Bind.DEREFERENCE, 1, "VERIFIED",
     "RESOLVED BY RUNTIME EVIDENCE, and upheld. reservation.contact_information = "
     "get_user_information(user)['Phone Number'] resolves live: mutating the phone "
     "number inside the window puts attacker-controlled contact data in the "
     "reservation, and the same mutation after the sink does not. Condition 4 holds. "
     "It does not retarget the BOOKING, but it does move what the action writes."),
    ("slack", "post_webpage", "web", Bind.DEREFERENCE, 1, "VERIFIED",
     "web.web_content[standardize_url(url)] = content -- keyed by the `url` argument"),
]


@pytest.mark.parametrize("suite,sink,resource,declared,windows,status,evidence", SWEEP,
                         ids=[f"{s}.{k}.{r}" for s, k, r, _, _, _, _ in SWEEP])
def test_every_temporal_binding_claim_is_audited(suite, sink, resource, declared,
                                                 windows, status, evidence):
    """The table IS the audit. This pins each claim to the label it was audited
    under, so a silent change to binding.py fails here with the evidence next to
    it."""
    assert status in {"VERIFIED", "REJECTED", "UNRESOLVED"}
    assert evidence, "every row must carry its source evidence"
    assert bind_of(suite, sink, resource) is declared, (
        f"{suite}.{sink} on '{resource}' is now {bind_of(suite, sink, resource).value}, "
        f"audited as {declared.value}. Re-audit before changing the table."
    )


def test_the_sweep_covers_every_claim_the_temporal_set_exercises():
    """14 distinct claims measured over the corpus; the table must not drift from
    that. A claim appearing in the data but not here is an unaudited edge."""
    assert len(SWEEP) == 14
    assert sum(w for *_, w, _, _ in [(a, b, c, d, e, f, g) for a, b, c, d, e, f, g in SWEEP]) == 749


def test_no_claim_is_left_unexamined():
    unexamined = [r for r in SWEEP if r[5] not in {"VERIFIED", "REJECTED", "UNRESOLVED"}]
    assert not unexamined
    verified = [r for r in SWEEP if r[5] == "VERIFIED"]
    rejected = [r for r in SWEEP if r[5] == "REJECTED"]
    assert len(verified) == 13 and len(rejected) == 1
    assert not [r for r in SWEEP if r[5] == "UNRESOLVED"], (
        "both former UNRESOLVED claims were settled by runtime evidence"
    )


def test_update_user_info_fails_condition_four():
    """RUNTIME EVIDENCE that settled a claim the source could not.

    The write target cannot move -- one account, no argument selects it. What an
    attacker CAN do is leave values in fields the agent does not specify, since
    update_user_info is a partial update. But that is not a race: mutating inside
    the window and mutating after the sink produce an identical post-state, so
    the window is irrelevant. It is "an attacker can write the record", which is
    true with or without the agent."""
    import yaml
    from agentdojo.default_suites.v1.tools.user_account import UserAccount, update_user_info

    env = ROOT / "reference/agentdojo/src/agentdojo/data/suites/banking/environment.yaml"
    raw = yaml.safe_load(env.read_text())["user_account"]

    inside = UserAccount(**raw)
    inside.first_name = "ATTACKER"
    update_user_info(inside, street="12 New Road")

    outside = UserAccount(**raw)
    update_user_info(outside, street="12 New Road")
    outside.first_name = "ATTACKER"

    assert (inside.first_name, inside.street) == (outside.first_name, outside.street), (
        "identical post-state means the window plays no part"
    )


def test_reserve_hotel_user_passes_condition_four():
    """The mirror case, and why the two were not settled by one rule.

    contact_information is resolved live from the user record, so timing decides
    the outcome: the attacker's number reaches the reservation only when the
    mutation lands inside the window."""
    import yaml
    from agentdojo.default_suites.v1.tools.travel_booking_client import (
        Hotels,
        Reservation,
        User,
        reserve_hotel,
    )

    env = ROOT / "reference/agentdojo/src/agentdojo/data/suites/travel/environment.yaml"
    raw = yaml.safe_load(env.read_text())

    def fresh():
        return User(**raw["user"]), Reservation(**raw["reservation"]), Hotels(**raw["hotels"])

    u1, r1, h1 = fresh()
    u1.phone_number = "+1-666-ATTACKER"
    reserve_hotel(r1, u1, h1.hotel_list[0].name, "2025-01-01", "2025-01-03")

    u2, r2, h2 = fresh()
    reserve_hotel(r2, u2, h2.hotel_list[0].name, "2025-01-01", "2025-01-03")
    u2.phone_number = "+1-666-ATTACKER"

    assert r1.contact_information == "+1-666-ATTACKER"
    assert r2.contact_information != r1.contact_information, "timing is what decides it"
