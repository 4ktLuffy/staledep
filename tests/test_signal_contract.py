"""Differential and contract tests: identical inputs through every signal.

Three bugs shipped because each signal was a NEW code path re-implementing most
of a sibling, inheriting the sibling's lessons only if someone remembered them.
Nothing made an omission visible. These tests make it visible.

Two layers:

  CONTRACT     every signal must DECLARE a position on every rule in
               staledep.signals.RULES. Declaring N/A is fine; declaring nothing
               is not. A new signal cannot be merged silently missing what its
               siblings know.

  DIFFERENTIAL the same input is pushed through every signal and each declared
               "yes" is actually exercised. A declaration nobody tests is a
               comment.

WHICH PAST BUG EACH LAYER WOULD HAVE CAUGHT
  trace/trace_from_log divergence  -> `nearest-source` + `errored-source`
                                      differential, run against both entry points
  trace_numeric tuple rejection    -> `tuple-input` differential (it raised
                                      AttributeError; the test calls every signal
                                      with tuples)
  absence missing supersession     -> CONTRACT: absence would have had to declare
                                      a position on `supersession`, and there was
                                      no defensible N/A to write
"""

from __future__ import annotations

import pytest

from staledep.absence import trace_absence
from staledep.numeric import trace_numeric
from staledep.provenance import trace_from_log
from staledep.signals import DECLARED, RULES, normalise

SIGNALS = {
    "provenance.trace_from_log": lambda steps, errored=None: trace_from_log(steps, errored),
    "numeric.trace_numeric": lambda steps, errored=None: trace_numeric(steps, errored),
    "absence.trace_absence": lambda steps, errored=None: trace_absence(steps, errored),
}


# ------------------------------------------------------------------- contract
@pytest.mark.parametrize("name", sorted(SIGNALS))
def test_every_signal_declares_a_position_on_every_rule(name):
    """The guard that would have caught the absence bug at merge time."""
    declared = DECLARED.get(name)
    assert declared is not None, (
        f"{name} is a lineage signal with no entry in staledep.signals.DECLARED. "
        f"Add one taking a position on each of {sorted(RULES)}."
    )
    missing = set(RULES) - set(declared)
    assert not missing, (
        f"{name} does not declare a position on {sorted(missing)}. "
        f"'yes' if it holds, otherwise a justification -- N/A is a legitimate "
        f"answer, silence is not."
    )


@pytest.mark.parametrize("name", sorted(DECLARED))
def test_declarations_reference_only_known_rules(name):
    unknown = set(DECLARED[name]) - set(RULES)
    assert not unknown, f"{name} declares unknown rule(s) {sorted(unknown)}"


def test_every_declared_signal_is_actually_wired_here():
    """A signal declared but not exercised below is a comment, not a contract."""
    assert set(DECLARED) == set(SIGNALS)


# --------------------------------------------------------------- differential
@pytest.mark.parametrize("name", sorted(SIGNALS))
def test_tuple_input_is_accepted_by_every_signal(name):
    """WOULD HAVE CAUGHT trace_numeric. It read st.tool directly, so tuple
    callers raised AttributeError -- and the seeded recall harness passes tuples,
    so numeric lineage was never exercised against the classes it was written
    for. `aggregate` was published as zero-coverage on that basis."""
    if DECLARED[name]["tuple-input"] != "yes":
        pytest.skip("declared N/A")
    steps = [
        ("read_file", {"file_path": "bill.txt"}, "Total 98.70 to UK12345678901234567890"),
        ("send_money", {"recipient": "UK12345678901234567890", "amount": 98.70}, "sent"),
    ]
    SIGNALS[name](steps)          # must not raise


@pytest.mark.parametrize("name", sorted(SIGNALS))
def test_errored_sources_are_refused_by_every_signal(name):
    """WOULD HAVE CAUGHT trace(). It recorded errored outputs as lineage sources
    while trace_from_log did not, and label_suites.py called the broken one."""
    if DECLARED[name]["errored-source"] != "yes":
        pytest.skip("declared N/A")
    steps = [
        ("get_iban", {}, "Error: ValueError: UK12345678901234567890 is invalid"),
        ("send_money", {"recipient": "UK12345678901234567890", "amount": 500.0}, "sent"),
    ]
    assert SIGNALS[name](steps, {0}) == [], (
        f"{name} declares errored-source but drew evidence from a failed call"
    )


@pytest.mark.parametrize("name", sorted(SIGNALS))
def test_same_turn_calls_never_link(name):
    """A sink composed in the same assistant message cannot have consumed the
    source's output -- the model had not seen it."""
    if DECLARED[name]["same-turn"] != "yes":
        pytest.skip("declared N/A")
    from staledep.trajectory import Step
    steps = [
        Step(0, 0, "read_file", {"file_path": "bill.txt"},
             "Total 98.70 to UK12345678901234567890", False),
        Step(1, 0, "send_money",
             {"recipient": "UK12345678901234567890", "amount": 98.70}, "sent", False),
    ]
    assert SIGNALS[name](steps) == [], f"{name} linked two calls from one turn"


def test_nearest_source_is_credited_not_earliest():
    """WOULD HAVE CAUGHT trace(). It scanned forward and credited the earliest
    read, inflating every window span."""
    steps = [
        ("get_iban", {}, "IBAN DE89370400440532013000"),
        ("get_balance", {}, "balance 500.0"),
        ("get_iban", {}, "IBAN DE89370400440532013000"),
        ("send_money", {"recipient": "DE89370400440532013000", "amount": 10.0}, "sent"),
    ]
    links = trace_from_log(steps)
    assert links and links[0].source_idx == 2


# ------------------------------------------------------------------- adapter
def test_the_adapter_gives_tuples_and_steps_the_same_shape():
    """One adapter, previously hand-rolled in three modules with three subtly
    different conventions for the turn of a tuple step."""
    from staledep.trajectory import Step
    tup = normalise([("a", {}, "x"), ("b", {"k": 1}, "y")])
    obj = normalise([Step(0, 0, "a", {}, "x", False), Step(1, 1, "b", {"k": 1}, "y", False)])
    assert [(s.idx, s.tool, s.args, s.output) for s in tup] == \
           [(s.idx, s.tool, s.args, s.output) for s in obj]


def test_tuple_steps_get_distinct_turns_so_same_turn_is_a_no_op():
    """Tuple input carries no turn structure. Giving each call its own turn is
    the correct reading of a sequential ground truth, and makes same-turn
    exclusion a no-op there rather than silently wrong."""
    turns = [s.turn for s in normalise([("a", {}, 1), ("b", {}, 2), ("c", {}, 3)])]
    assert len(set(turns)) == 3


def test_errored_indices_reach_every_signal_the_same_way():
    steps = [("read_file", {}, "boom"), ("send_money", {"amount": 500.0}, "sent")]
    assert normalise(steps, {0})[0].errored is True
    assert normalise(steps, {0})[1].errored is False
