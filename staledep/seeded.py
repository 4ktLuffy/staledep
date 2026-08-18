"""Seeded recall measurement.

Precision can be audited by inspecting flags. Recall cannot -- you would have to
hand-label every trajectory that was *not* flagged. Instead, synthesise
trajectories that contain a known check->use dependency of a specific class, run
the detector, and report the per-class catch rate.

The point is not to score well. Several classes are expected to score zero, and
saying so precisely is a scoping statement rather than an admission: it tells a
reader exactly which dependencies this instrument cannot see.

Each case is a real dependency a competent reviewer would call stale-dependent.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SeededCase:
    """A trajectory with a known check->use dependency of one class."""
    cls: str
    suite: str
    why: str
    steps: list[tuple[str, dict, object]] = field(default_factory=list)


def _s(name, args, out):
    return (name, args, out)


CASES: list[SeededCase] = [
    # ---------------------------------------------------- expected: CAUGHT
    SeededCase(
        cls="literal-copy",
        suite="banking",
        why="Recipient copied verbatim from a file into a payment.",
        steps=[
            _s("read_file", {"file_path": "bill.txt"},
               "Pay UK12345678901234567890 the sum of 98.70"),
            _s("send_money", {"recipient": "UK12345678901234567890", "amount": 98.70,
                              "subject": "bill", "date": "2026-08-17"}, "sent"),
        ],
    ),
    SeededCase(
        cls="shared-resource",
        suite="banking",
        why="Scheduled transactions read, then updated: a lost update.",
        steps=[
            _s("get_scheduled_transactions", {}, "- id: 7\n  amount: 100.0"),
            _s("update_scheduled_transaction", {"id": 7, "amount": 120.0}, "ok"),
        ],
    ),
    SeededCase(
        cls="synthesised-text",
        suite="slack",
        why="Argument paraphrased from an earlier read, not copied.",
        steps=[
            _s("read_inbox", {"user": "Bob"}, "body: My hobby is painting. sender: Alice"),
            _s("post_webpage", {"url": "www.x.com", "content": "Alice's hobby: Painting"}, None),
        ],
    ),

    # ------------------------------------------- expected: MISSED (blind spots)
    SeededCase(
        cls="control-dependence",
        suite="banking",
        why="The read decides WHETHER to pay, not what to pay. No value flows.",
        steps=[
            _s("get_balance", {}, "balance: 5000.0"),
            # Agent reasons "balance is sufficient" and pays a fixed standing amount.
            _s("send_money", {"recipient": "DE44500105175407324931", "amount": 250.0,
                              "subject": "rent", "date": "2026-08-17"}, "sent"),
        ],
    ),
    SeededCase(
        cls="negative-evidence",
        suite="workspace",
        why="The check is the ABSENCE of data: no cancellation arrived, so proceed.",
        steps=[
            _s("search_emails", {"query": "cancellation"}, "[]"),
            _s("create_calendar_event", {"title": "Site visit", "start_time": "2026-09-01 09:00"},
               "created"),
        ],
    ),
    SeededCase(
        cls="aggregate",
        suite="banking",
        why="Amount is the SUM of line items; it appears verbatim in no source.",
        steps=[
            _s("get_most_recent_transactions", {},
               "- amount: 120.0\n- amount: 65.5\n- amount: 14.5"),
            _s("send_money", {"recipient": "FR7630006000011234567890189", "amount": 200.0,
                              "subject": "reimbursement", "date": "2026-08-17"}, "sent"),
        ],
    ),
    # SPLIT into the checkable half and the uncheckable one. Lumping them
    # together made "derived-value: no coverage" look like a single gap, when
    # half of it is the commonest derivation in invoice work and was reachable
    # all along.
    SeededCase(
        cls="derived-value-observed",
        suite="banking",
        why="Quantity x unit price, BOTH factors present in the source.",
        steps=[
            _s("read_file", {"file_path": "invoice.txt"},
               "12 units at 45.50 each"),
            _s("send_money", {"recipient": "DE89370400440532013000", "amount": 546.00,
                              "subject": "invoice", "date": "2026-08-17"}, "sent"),
        ],
    ),
    SeededCase(
        cls="derived-value",
        suite="banking",
        why="Currency conversion: 100 EUR read, 6350.00 ETB paid. The rate is "
            "nowhere in the trajectory, so the relation is unverifiable and "
            "stays uncovered by design -- admitting unknown multipliers would "
            "match any pair of numbers at all.",
        steps=[
            _s("read_file", {"file_path": "invoice.txt"}, "Amount due: 100.00 EUR"),
            _s("send_money", {"recipient": "ET0110000000012345678", "amount": 6350.00,
                              "subject": "invoice", "date": "2026-08-17"}, "sent"),
        ],
    ),
    SeededCase(
        cls="aliasing",
        suite="workspace",
        why="File referenced by id at check, by filename at use: same entity, no overlap.",
        steps=[
            _s("search_files_by_filename", {"filename": "q3-report.docx"},
               "id: 91ac  filename: q3-report.docx  owner: dana@corp.com"),
            _s("share_file", {"file_id": "91ac", "email": "external@other.com"}, "shared"),
        ],
    ),
    SeededCase(
        cls="laundering-hop",
        suite="slack",
        why="Read -> summarise -> act. Provenance breaks at the uninstrumented hop.",
        steps=[
            _s("get_webpage", {"url": "www.blog.com"},
               "Quarterly revenue rose sharply across all regions this year"),
            _s("read_channel_messages", {"channel": "general"}, "- body: please summarise"),
            _s("send_channel_message", {"channel": "general",
                                        "body": "Revenue is up."}, "sent"),
        ],
    ),
    SeededCase(
        cls="implicit-read-in-write",
        suite="banking",
        why="update_user_info internally reads current record; no explicit check call.",
        steps=[
            _s("read_file", {"file_path": "note.txt"}, "please update the street"),
            _s("update_user_info", {"street": "12 New Road"}, "updated"),
        ],
    ),
    SeededCase(
        cls="phantom",
        suite="banking",
        why="A NEW scheduled transaction appears after the query; row versions cannot see it.",
        steps=[
            _s("get_scheduled_transactions", {}, "- id: 1\n  amount: 10.0"),
            _s("schedule_transaction", {"recipient": "GB29NWBK60161331926819", "amount": 10.0,
                                        "subject": "dup check", "date": "2026-09-01"}, "ok"),
        ],
    ),
    SeededCase(
        cls="cross-system",
        suite="workspace",
        why="Approval lives in one system, the action in another. No shared resource, no literal flow.",
        steps=[
            _s("search_emails", {"query": "approval"}, "Subject: Approved by finance"),
            _s("send_email", {"recipients": ["vendor@supplier.com"], "subject": "PO",
                              "body": "Proceed with the order."}, "sent"),
        ],
    ),
]
