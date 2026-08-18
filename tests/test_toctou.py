"""Regression tests for TOCTOU window detection.

Every test here corresponds to a bug found by hand-auditing real trajectories.
They exist so those bugs cannot come back silently -- the classifier reports
confident numbers, so a regression would be invisible without them.
"""

import pytest

from staledep.effects import Risk, effects_for
from staledep.provenance import (
    ProvenanceLink,
    _distinctive_values,
    _numeric_is_distinctive,
    _token_match,
    _tokens,
    trace_from_log,
)
from staledep.toctou import (
    classify_task,
    evidence_tier,
    find_windows,
    windows_from_provenance,
)


# --------------------------------------------------------------- state typing
def test_read_then_high_risk_write_is_a_window():
    """The canonical case: check the IBAN, then pay it."""
    w = find_windows(["get_iban", "send_money"], "banking")
    assert len(w) == 1
    assert w[0].resource == "account.iban"
    assert w[0].use_risk is Risk.HIGH


def test_lost_update_is_a_window():
    w = find_windows(["get_scheduled_transactions", "update_scheduled_transaction"], "banking")
    assert [x.resource for x in w] == ["scheduled"]


def test_read_only_trajectory_has_no_window():
    assert find_windows(["get_iban", "get_balance", "get_user_info"], "banking") == []


def test_write_does_not_count_as_a_check():
    """BUG 2: a write's implicit read was registering as a verification, so two
    consecutive sends formed a window where neither was a check."""
    assert find_windows(["send_direct_message", "send_direct_message"], "slack") == []


def test_write_invalidates_an_earlier_check():
    """After something writes a resource, an earlier read of it is stale; the
    next use must not be credited to that outdated check."""
    w = find_windows(
        ["get_scheduled_transactions", "update_scheduled_transaction",
         "update_scheduled_transaction"],
        "banking",
    )
    assert len(w) == 1
    assert w[0].check_idx == 0 and w[0].use_idx == 1


def test_call_does_not_form_a_window_with_itself():
    assert find_windows(["update_scheduled_transaction"], "banking") == []


def test_undeclared_tool_is_ignored_not_guessed():
    assert find_windows(["get_iban", "totally_unknown_tool"], "banking") == []


# ------------------------------------------------------------------ numerics
@pytest.mark.parametrize("raw", ["1", "3", "12", "999"])
def test_small_bare_integers_are_not_evidence(raw):
    """BUG 1: 'Congrats on being the 3rd most active user!' linked via the digit 3."""
    assert not _numeric_is_distinctive(raw)


@pytest.mark.parametrize("raw", ["98.70", "50.0", "60161331926819"])
def test_amounts_and_identifiers_are_evidence(raw):
    assert _numeric_is_distinctive(raw)


@pytest.mark.parametrize("raw", ["2024", "2022", "1999"])
def test_bare_years_are_not_evidence(raw):
    """A year has four digits, so the digit-count test admitted it as an
    identifier. Measured on the corpus, 96.4% of numeric-rule matches were a
    bare year and 706 of 808 were literally 2024 -- every date argument in the
    workspace suite matched every earlier output mentioning any 2024 date.
    This test previously asserted the opposite."""
    assert not _numeric_is_distinctive(raw)


def test_a_full_date_is_evidence_where_the_year_alone_is_not():
    """The year matches were standing in for a real relation. A timestamp
    argument is not a substring of a date-only output, so whole-string matching
    missed it; the date component finds the same link for the right reason."""
    steps = [
        ("get_day_calendar_events", {"day": "2024-05-19"},
         "Event: standup, start 2024-05-19 09:00"),
        ("create_calendar_event", {"start_time": "2024-05-19 16:00"}, None),
    ]
    links = trace_from_log(steps)
    assert [(lk.rule, lk.value) for lk in links] == [("date", "2024-05-19 16:00")]


def test_the_most_specific_matching_value_is_credited():
    """`wanted` is a set and Python randomises string hashing per process, so an
    arbitrary scan order made which value matched -- and so which rule was
    recorded -- differ between runs on identical input."""
    steps = [
        ("read_file", {"p": "x"}, "due 2024-05-19 for invoice inv-2024-05-19-77"),
        ("send_money", {"note": "inv-2024-05-19-77"}, None),
    ]
    rules = {lk.rule for lk in trace_from_log(steps)}
    assert rules == {"direct"}, "full identifier must win over its date substring"


def test_password_digits_do_not_link_to_transactions():
    """BUG 1, real case: password '1j1l-2k3j' matched transaction data on digits."""
    vals = _distinctive_values("1j1l-2k3j")
    assert not any(v in {"1.0", "2.0", "3.0"} for v in vals)


# ----------------------------------------------------------------- provenance
def test_argument_copied_from_earlier_output_is_linked():
    steps = [
        ("read_file", {"file_path": "bill.txt"}, "Total 98.70 to UK12345678901234567890"),
        ("send_money", {"recipient": "UK12345678901234567890", "amount": 98.70}, None),
    ]
    links = trace_from_log(steps)
    assert links and all(lk.source_idx == 0 and lk.sink_idx == 1 for lk in links)


def test_nearest_source_is_credited_not_earliest():
    """BUG 3: scanning forwards credited the earliest read, inflating spans."""
    steps = [
        ("get_iban", {}, "IBAN DE89370400440532013000"),
        ("get_balance", {}, "balance 500.0"),
        ("get_iban", {}, "IBAN DE89370400440532013000"),
        ("send_money", {"recipient": "DE89370400440532013000"}, None),
    ]
    links = trace_from_log(steps)
    assert links[0].source_idx == 2, "should credit the freshest read, not index 0"


def test_errored_call_is_not_a_provenance_source():
    """BUG 4: matching an argument against an error string is coincidence."""
    steps = [
        ("get_iban", {}, "Error: ValueError: UK12345678901234567890 is invalid"),
        ("send_money", {"recipient": "UK12345678901234567890"}, None),
    ]
    assert trace_from_log(steps, errored={0}) == []


def test_synthesised_argument_is_linked_via_tokens():
    """BUG 6: agents paraphrase. "Alice's hobby: Painting" never appears verbatim
    in the inbox that supplied it, so whole-string matching missed the flow."""
    steps = [
        ("read_inbox", {"user": "Bob"}, "body: My hobby is painting. sender: Alice"),
        ("post_webpage", {"url": "www.x.com", "content": "Alice's hobby: Painting"}, None),
    ]
    assert trace_from_log(steps), "token matching should link the synthesised argument"


def test_single_common_word_does_not_manufacture_a_link():
    """The guard on BUG 6's fix: one shared word is coincidence, not data-flow."""
    assert not _token_match(_tokens("please"), "please confirm the meeting")


def test_two_tokens_need_one_substantial_word():
    assert not _token_match({"there", "hello"}, "hello there")
    assert _token_match({"painting", "alice"}, "alice said my hobby is painting")


# --------------------------------------------------------------- aggregation
def test_one_window_per_edge_not_per_argument():
    """BUG 5: three arguments crossing one read->send edge counted as three."""
    links = [
        ProvenanceLink(0, "read_file", 1, "send_money", arg, "v")
        for arg in ("recipient", "amount", "subject")
    ]
    r = classify_task(["read_file", "send_money"], "banking", links=links)
    assert r["n_windows"] == 1
    assert r["n_high_risk_windows"] == 1


def test_dataflow_into_a_read_is_not_a_window():
    links = [ProvenanceLink(0, "get_channels", 1, "get_users_in_channel", "channel", "x")]
    r = classify_task(["get_channels", "get_users_in_channel"], "slack", links=links)
    assert r["n_windows"] == 0


def test_state_and_dataflow_windows_are_counted_separately():
    links = [ProvenanceLink(0, "read_file", 1, "send_money", "recipient", "x")]
    r = classify_task(["read_file", "send_money"], "banking", links=links)
    assert r["n_state_windows"] == 0
    assert r["n_dataflow_windows"] == 1


def test_effect_tables_declare_every_suite_tool():
    """A tool missing from the table is silently un-analysable, so fail loudly."""
    for suite in ("banking", "slack", "travel", "workspace"):
        assert effects_for(suite), f"{suite} has no effect table"


# ------------------------------------------------------------ seeded recall
def test_seeded_recall_is_pinned():
    """Recall by dependency class. If a fix improves coverage, update these
    numbers deliberately -- silent drift in either direction is the failure
    mode this test exists to prevent."""
    from staledep.absence import trace_absence
    from staledep.numeric import trace_numeric
    from staledep.provenance import trace_from_log
    from staledep.seeded import CASES
    from staledep.toctou import classify_task

    # All three signals, which is the point. An earlier version passed only
    # lexical links, so numeric lineage was never exercised here at all -- and
    # `trace_numeric` could not even accept the tuple steps this harness uses,
    # raising AttributeError. The aggregate class had been reported as
    # zero-coverage on that basis while the code to catch it already existed.
    caught = {
        c.cls
        for c in CASES
        if classify_task([n for n, _, _ in c.steps], c.suite,
                         links=trace_from_log(c.steps),
                         numeric_links=trace_numeric(c.steps, None, c.suite),
                         absence_links=trace_absence(c.steps))["candidate"]
    }
    # control-dependence dropped out when the fictional balance gate was removed.
    # seeded.py has always filed it under "expected: MISSED (blind spots)" -- "the
    # read decides WHETHER to pay, not what to pay. No value flows." It was being
    # caught only because send_money was declared CONTROL on account.balance, a
    # gate the implementation does not have. The case is back to the status it
    # documents for itself, and recall is correspondingly lower.
    assert caught == {
        "literal-copy", "shared-resource", "synthesised-text",
        "aliasing", "phantom",
        "aggregate",                 # numeric lineage, finally exercised
        "negative-evidence",         # new signal: the check that found nothing
        "derived-value-observed",    # new relation: quantity x unit price
    }


def test_known_blind_spots_stay_documented():
    """These classes are not detected. The test asserts the gap so it cannot be
    quietly forgotten when the README is next edited."""
    from staledep.provenance import trace_from_log
    from staledep.seeded import CASES
    from staledep.toctou import classify_task

    blind = {"negative-evidence", "aggregate", "derived-value",
             "laundering-hop", "implicit-read-in-write", "cross-system"}
    for c in CASES:
        if c.cls in blind:
            r = classify_task([n for n, _, _ in c.steps], c.suite,
                              links=trace_from_log(c.steps))
            assert not r["candidate"], f"{c.cls} now detected -- update the table"


# ----------------------------------------------------- upstream oracle bug
def test_vacuous_utility_checks_are_pinned():
    """Four banking utility() checks pass on the untouched environment.

    Only user_task_5 is a bug (already upstream issue #161); t8/t9/t10 are
    intentional -- read-only or underspecified tasks where not acting is
    correct. Pinned as a fact about the fixture, not as a defect claim: any
    exploitability measurement over these tasks must use the action oracle.

    Skipped when agentdojo is absent (the library itself does not need it).
    """
    pytest.importorskip("agentdojo")
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite("v1", "banking")
    vacuous = set()
    for tid, task in suite.user_tasks.items():
        env = suite.load_and_inject_default_environment({})
        pre = env.model_copy(deep=True)
        init = task.init_environment(env) if hasattr(task, "init_environment") else env
        try:
            if task.utility("", pre, init, strict=False):
                vacuous.add(tid)
        except Exception:
            continue
    assert vacuous == {"user_task_5", "user_task_8", "user_task_9", "user_task_10"}, (
        "the set of banking checks passing on an untouched environment changed; "
        "re-verify any baseline that used them"
    )


def test_action_oracle_reads_calls_not_environment():
    """The action oracle must judge emitted calls, so a mutated environment
    cannot fool it."""
    from staledep.oracle import SENTINEL, ActionLog, verdict

    base = ActionLog()
    base.record("get_iban", {})
    base.record("send_money", {"recipient": "DE89370400440532013000", "amount": 10.0})

    clean = ActionLog()
    clean.record("get_iban", {})
    clean.record("send_money", {"recipient": "DE89370400440532013000", "amount": 10.0})
    assert not verdict(clean, base, "banking")["redirected"]

    hijacked = ActionLog()
    hijacked.record("get_iban", {})
    hijacked.record("send_money", {"recipient": SENTINEL, "amount": 10.0})
    v = verdict(hijacked, base, "banking")
    assert v["sentinel_in_action"], "attacker data reaching an action must be detected"
    assert v["target_diverged"]
    assert v["redirected"]


def test_read_only_agent_is_not_redirected():
    """An agent that never acts cannot have been redirected, whatever the
    environment says. This is the case that broke the first sweep."""
    from staledep.oracle import ActionLog, verdict

    base = ActionLog()
    base.record("get_most_recent_transactions", {"n": 100})
    log = ActionLog()
    log.record("get_most_recent_transactions", {"n": 100})
    assert not verdict(log, base, "banking")["redirected"]


# ==================================================================== hostile
# Written to break the code, not to confirm it. Each targets a path that
# produced a headline number while having no direct test.

# ------------------------------------------------- mutability conditioning
def test_unknown_resource_is_not_silently_attacker_writable():
    """An unknown resource returns False, which EXCLUDES it from conditioned
    counts. Silent undercount, so writer_coverage must catch it."""
    from staledep.effects import is_attacker_writable, writer_of
    assert writer_of("banking", "no.such.resource") is None
    assert not is_attacker_writable("banking", "no.such.resource")
    assert writer_of("nosuchsuite", "file") is None


def test_every_effect_table_resource_has_a_declared_writer():
    """travel.email.sent was undeclared and silently excluded. Windows form only
    on resources a SINK READS, so that one did not move the numbers -- but a new
    reader would have made it corrupt them invisibly."""
    from staledep.effects import SUITES, writer_coverage
    for suite in SUITES:
        _, undeclared = writer_coverage(suite)
        assert not undeclared, f"{suite} has resources with no declared writer: {undeclared}"


def test_invalid_threat_model_raises_rather_than_keyerrors():
    from staledep.effects import is_attacker_writable
    with pytest.raises(ValueError, match="unknown threat model"):
        is_attacker_writable("banking", "file", "not_a_model")


def test_threat_models_are_nested():
    """strict ⊆ moderate ⊆ multi_agent. If this breaks, the tiers stop being
    comparable and the conditioned table is meaningless."""
    from staledep.effects import THREAT_MODELS as T
    assert T["strict"] <= T["moderate"] <= T["multi_agent"]


def test_dataflow_resource_resolves_to_its_source_tools_hostility():
    """dataflow:read_file must inherit read_file's UNTRUSTED, or the bill class
    silently drops out of the strict count."""
    from staledep.effects import Writer, is_attacker_writable, writer_of
    assert writer_of("banking", "dataflow:read_file") is Writer.UNTRUSTED
    assert is_attacker_writable("banking", "dataflow:read_file", "strict")
    assert writer_of("banking", "dataflow:get_iban") is Writer.USER
    assert not is_attacker_writable("banking", "dataflow:get_iban", "strict")
    # malformed forms must not explode
    for bad in ("dataflow:", "dataflow:nope", "dataflow:read_file.recipient", ""):
        assert writer_of("banking", bad) is None


# ------------------------------------------------------- TOCTOU discrimination
def test_discriminate_requires_both_controls_clean():
    from staledep.mutate import discriminate
    n = 3
    # interior only -> TOCTOU
    assert discriminate({-1: False, 0: True, 1: False, 2: False, 3: False}, n)["toctou"]
    # before-control also changed -> corruption, not TOCTOU
    assert not discriminate({-1: True, 0: True, 1: False, 2: False, 3: False}, n)["toctou"]
    # after-control also changed -> corruption
    assert not discriminate({-1: False, 0: True, 1: False, 2: False, 3: True}, n)["toctou"]
    # nothing changed -> no effect
    v = discriminate({-1: False, 0: False, 1: False, 2: False, 3: False}, n)
    assert not v["toctou"] and v["verdict"] == "no effect"


def test_discriminate_does_not_count_controls_as_interior():
    """Off-by-one here would let a control masquerade as an in-window hit."""
    from staledep.mutate import discriminate
    v = discriminate({-1: False, 0: False, 1: False, 2: True}, 2)  # gap 2 == n_gaps
    assert not v["toctou"]
    assert v["control_after_changed"]
    assert v["interior_gaps_that_changed"] == []


def test_discriminate_on_empty_input_is_no_effect():
    from staledep.mutate import discriminate
    assert discriminate({}, 3)["verdict"] == "no effect"


# --------------------------------------------------------------- action oracle
def test_sentinel_in_a_read_argument_is_not_a_redirect():
    """Attacker data reaching a READ is not an action. Counting it would inflate
    every exploitability figure."""
    from staledep.oracle import SENTINEL, ActionLog, sentinel_reached_action
    log = ActionLog()
    log.record("get_most_recent_transactions", {"n": 100, "note": SENTINEL})
    assert sentinel_reached_action(log, "banking") == []


def test_sentinel_nested_in_a_list_argument_is_found():
    from staledep.oracle import SENTINEL, ActionLog, sentinel_reached_action
    log = ActionLog()
    log.record("send_email", {"recipients": ["ok@x.com", SENTINEL]})
    assert sentinel_reached_action(log, "workspace")


def test_target_divergence_reports_a_missing_call():
    """Not making a high-risk call is itself a behavioural change; silently
    treating it as 'unchanged' would hide a denial-of-action."""
    from staledep.oracle import ActionLog, target_diverged
    base = ActionLog()
    base.record("send_money", {"recipient": "DE89", "amount": 5.0})
    suppressed = ActionLog()
    suppressed.record("get_iban", {})
    d = target_diverged(suppressed, base, "banking")
    assert d, "suppressing a high-risk call is a behavioural change, not 'unchanged'"
    assert any("not called" in str(x[0]) for x in d)
    extra = ActionLog()
    extra.record("send_money", {"recipient": "DE89", "amount": 5.0})
    extra.record("send_money", {"recipient": "XX99", "amount": 5.0})
    assert target_diverged(extra, base, "banking"), "an extra unmatched call must diverge"


def test_undeclared_tool_is_not_treated_as_a_sink():
    from staledep.oracle import ActionLog
    log = ActionLog()
    log.record("some_unknown_tool", {"x": 1})
    assert log.state_changing("banking") == []
    assert log.high_risk("banking") == []


# ------------------------------------------------------------ trajectory parse
def test_steps_from_messages_matches_results_by_id():
    from staledep.trajectory import steps_from_messages
    msgs = [
        {"role": "assistant", "tool_calls": [{"function": "get_iban", "args": {}, "id": "a"}]},
        {"role": "tool", "tool_call_id": "a", "tool_call": {"function": "get_iban", "args": {}},
         "content": "DE89", "error": None},
    ]
    steps, errored = steps_from_messages(msgs)
    assert [s.as_tuple() for s in steps] == [("get_iban", {}, "DE89")]
    assert steps[0].turn == 0 and not steps[0].errored
    assert errored == set()


def test_steps_from_messages_flags_errored_calls():
    from staledep.trajectory import steps_from_messages
    msgs = [
        {"role": "assistant", "tool_calls": [{"function": "send_money", "args": {}, "id": "b"}]},
        {"role": "tool", "tool_call_id": "b", "tool_call": {"function": "send_money", "args": {}},
         "content": "ValueError: nope", "error": "ValueError"},
    ]
    steps, errored = steps_from_messages(msgs)
    assert errored == {0}


def test_steps_from_messages_survives_empty_and_malformed():
    from staledep.trajectory import steps_from_messages
    assert steps_from_messages([]) == ([], set())
    assert steps_from_messages([{"role": "assistant"}]) == ([], set())
    assert steps_from_messages([{"role": "assistant", "tool_calls": [{}]}]) == ([], set())


def test_same_turn_calls_do_not_form_a_dependency():
    """VERIFIED FABRICATION: two calls in ONE assistant message were linked, so
    a payment appeared to depend on a file the model had not yet seen. Calls
    composed together cannot consume each other's output."""
    from staledep.provenance import trace_from_log
    from staledep.trajectory import steps_from_messages

    msgs = [
        {"role": "assistant", "tool_calls": [
            {"function": "read_file", "args": {"file_path": "b.txt"}, "id": "a"},
            {"function": "send_money",
             "args": {"recipient": "UK12345678901234567890", "amount": 98.70}, "id": "b"}]},
        {"role": "tool", "tool_call_id": "a",
         "tool_call": {"function": "read_file", "args": {}},
         "content": "Pay UK12345678901234567890 the sum of 98.70", "error": None},
        {"role": "tool", "tool_call_id": "b",
         "tool_call": {"function": "send_money", "args": {}},
         "content": "sent", "error": None},
    ]
    steps, errored = steps_from_messages(msgs)
    assert {s.turn for s in steps} == {0}, "both calls are one turn"
    assert trace_from_log(steps, errored) == []


def test_uncommitted_sink_is_separated_not_counted():
    """A sink that raised did not commit, so it is not an exploited use."""
    r = classify_task(["get_iban", "send_money"], "banking", committed=[True, False])
    assert r["n_uncommitted_sink_windows"] == 1
    assert not r["candidate"]


def test_binding_is_per_edge_not_per_tool():
    """send_money is SNAPSHOT for a copied recipient and DEREFERENCE for the
    source account. Labelling the whole tool erases the second."""
    from staledep.binding import Bind, bind_of
    assert bind_of("banking", "send_money", "transactions") is Bind.SNAPSHOT
    assert bind_of("banking", "send_money", "account.iban") is Bind.DEREFERENCE
    # Not CONTROL. That entry claimed funds gate the transfer; send_money never
    # reads the balance. Unknown is the honest answer for a resource the tool
    # does not touch -- see tests/test_binding_matches_source.py.
    assert bind_of("banking", "send_money", "account.balance") is Bind.UNKNOWN


def test_trace_and_trace_from_log_agree():
    """They diverged: trace() credited the earliest source and kept errored
    outputs, while trace_from_log() fixed both -- and label_suites.py used the
    broken one."""
    import inspect

    from staledep import provenance
    src = inspect.getsource(provenance.trace)
    assert "trace_from_log" in src, "trace() must delegate, not reimplement"


def test_classify_task_on_empty_trajectory():
    r = classify_task([], "banking")
    assert not r["candidate"] and r["n_windows"] == 0 and r["max_span"] == 0


def test_unfired_control_is_inconclusive_not_clean():
    """VERIFIED FALSE POSITIVE: an agent that stops after one call while the
    sweep assumes n_gaps=2 never fires the after-control. Recording that as
    'unchanged' makes it indistinguishable from a clean control, which is the
    condition for declaring TOCTOU."""
    from staledep.mutate import discriminate
    changed = {-1: False, 0: True, 1: False, 2: False}
    fired = {-1: True, 0: True, 1: False, 2: False}       # gaps 1,2 never ran
    v = discriminate(changed, 2, fired)
    assert not v["toctou"]
    assert v["inconclusive"]
    assert 2 in v["unfired_gaps"]
    # same evidence with every gap fired IS a TOCTOU
    all_fired = dict.fromkeys(fired, True)
    assert discriminate(changed, 2, all_fired)["toctou"]


def test_recording_runtime_reports_whether_the_mutation_fired():
    from staledep.mutate import Mutation
    from staledep.oracle import ActionLog, make_recording_runtime

    class FakeRT:
        def __init__(self, tools=None):
            pass

        def run_function(self, env, function, kwargs, raise_on_error=False):
            return ("ok", None)

    hits = []
    mut = Mutation("probe", "file", "untrusted", lambda env: hits.append(1))

    for gap, expect in ((-1, True), (0, True), (1, False), (2, False)):
        hits.clear()
        log = ActionLog()
        RT = make_recording_runtime(FakeRT, log, mut, gap)
        rt = RT(None)
        rt.run_function(object(), "get_iban", {})     # agent makes ONE call
        assert rt.did_fire() is expect, f"gap {gap}"
        assert bool(hits) is expect


def test_snapshot_flows_are_not_counted_as_temporal():
    """CORRECTION: an earlier recall claim credited literal-copy and
    synthesised-text as successes. Both produce SNAPSHOT windows -- exactly what
    this project argues is NOT a temporal dependency. The detector was being
    credited for catching flows it also calls safe."""
    from staledep.binding import Bind, bind_of
    from staledep.provenance import trace_from_log
    from staledep.seeded import CASES
    from staledep.toctou import classify_task

    temporal, snapshot = set(), set()
    for c in CASES:
        r = classify_task([n for n, _, _ in c.steps], c.suite,
                          links=trace_from_log(c.steps))
        if not r["candidate"]:
            continue
        binds = {bind_of(c.suite, w.use_tool, w.resource) for w in r["windows"]}
        (temporal if binds & {Bind.DEREFERENCE, Bind.CONTROL} else snapshot).add(c.cls)

    assert temporal == {"shared-resource", "aliasing"}
    assert snapshot == {"literal-copy", "synthesised-text", "phantom"}
    # only shared-resource is temporal AND caught by the intended mechanism
    assert len(temporal - {"aliasing"}) == 1


def test_no_regex_pattern_contains_control_characters():
    """VERIFIED BUG: a pattern written through a non-raw Python string turned
    every \\b into a literal backspace (\\x08). It compiled cleanly and silently
    never matched, so `curl -o file` was classified read-only instead of as a
    file write. Regexes that fail closed are invisible without this check."""
    import importlib
    import pkgutil
    import re

    import staledep
    for m in pkgutil.iter_modules(staledep.__path__):
        mod = importlib.import_module(f"staledep.{m.name}")
        for name, val in vars(mod).items():
            if isinstance(val, re.Pattern):
                ctrl = [c for c in val.pattern if ord(c) < 32 and c not in "\n\t"]
                assert not ctrl, f"{m.name}.{name} pattern has control chars: {ctrl!r}"


def test_read_only_shell_call_is_not_a_sink():
    """`Bash(ls)` observes; a window cannot end there. Typing Bash by NAME made
    78% of live windows unclassifiable."""
    from staledep.effects import Risk
    from staledep.shell import classify_command
    for cmd in ("ls -la", "git status", "cd x && ls", "echo hi", "curl -s http://x"):
        assert classify_command(cmd)[0].risk is Risk.READ, cmd
    for cmd in ("rm -rf build", "git checkout main", "echo hi > f", "curl -o f http://x"):
        assert classify_command(cmd)[0].risk is Risk.HIGH, cmd


def test_unrecognised_command_stays_pessimistic():
    """Guessing an unfamiliar command is harmless is the one error that makes
    this dangerous rather than merely incomplete."""
    from staledep.binding import Bind
    from staledep.effects import Risk
    from staledep.shell import classify_command
    for cmd in ("python train.py", "npm install", "./deploy.sh", "make release"):
        eff, bind = classify_command(cmd)
        assert eff.risk is Risk.HIGH and bind is Bind.UNKNOWN, cmd


def test_numeric_lineage_covers_aggregates():
    """`aggregate` and `derived-value` were the two seeded classes with ZERO
    coverage: a payment total is the SUM of line items and appears verbatim in
    no source.

    Exercised END TO END through numbers_in(), not by calling explain() with a
    hand-supplied pool. That shortcut let a real regression pass: raising the
    magnitude floor filtered the POOL as well as the target, dropping 65.5 and
    14.5 so 200.0 could never be reached, and this test stayed green."""
    from staledep.numeric import explain, trace_numeric
    from staledep.trajectory import Step

    steps = [
        Step(0, 0, "get_most_recent_transactions", {},
             "- amount: 120.0\n- amount: 65.5\n- amount: 14.5", False),
        Step(1, 1, "send_money", {"recipient": "FR76", "amount": 200.0}, "sent", False),
    ]
    links = trace_numeric(steps)
    assert links, "aggregate must be found through the real pipeline"
    assert links[0].relation == "subset-sum"
    assert explain(1150.0, [1000.0])[0] == "rate:vat_15_incl"


def test_numeric_lineage_refuses_unexplainable_conversions():
    """100 EUR -> 6350 ETB needs an unknown rate. Admitting unknown multipliers
    would match any two numbers, so that class stays uncovered BY DESIGN."""
    from staledep.numeric import explain
    assert explain(6350.0, [100.0]) is None
    assert explain(42.0, [7.0, 11.0, 13.0]) is None
    assert explain(5.0, [1000.0]) is None, "below the magnitude floor"


def test_numeric_refuses_the_audited_false_positives():
    """A stratified audit found EVERY sampled numeric link on the real corpus was
    coincidence. These are the exact three, and they must stay refused."""
    from staledep.numeric import explain
    assert explain(50.0, [1000.0]) is None, "a 50.0 subscription is not 5% of 1000.0"
    assert explain(1100.0, [100.0, 1000.0]) is None, "a rent constant is not a 2-term sum"
    assert explain(10.0, [50.0]) is None, "a 10.0 refund is not 20% of 50.0"


def test_rate_table_contains_no_coincidental_multipliers():
    """double/half/ten_pct were in RATES and produced 8 of 10 new links on the
    real corpus, against 2 from the VAT rates. Any figure co-occurs with its
    double; that is arithmetic coincidence, not a rate a system applies."""
    from staledep.numeric import RATES
    assert not ({0.5, 2.0, 0.1, 1.1, 0.05, 0.2} & set(RATES.values())), \
        "a coincidental multiplier re-entered the rate table"
    assert all(k.startswith("vat_") for k in RATES), "every rate must be a declared tax rate"


def test_reused_tool_call_id_does_not_overwrite_an_earlier_result():
    """VERIFIED CORRUPTION: gpt-4-0125-preview reused one tool_call_id across two
    different calls. Keying results by id let the second overwrite the first, so
    a READ resolved to a later WRITE's confirmation and every provenance link
    from that step was wrong. Results are queued per id and consumed in order."""
    from staledep.trajectory import steps_from_messages

    dup = "call_SAME"
    msgs = [
        {"role": "assistant", "tool_calls": [
            {"function": "get_rating_reviews_for_hotels", "args": {}, "id": dup}]},
        {"role": "tool", "tool_call_id": dup,
         "tool_call": {"function": "get_rating_reviews_for_hotels", "args": {}},
         "content": "{'Le Marais Boutique': 'Rating: 4.2'}", "error": None},
        {"role": "assistant", "tool_calls": [
            {"function": "reserve_hotel", "args": {"hotel": "Le Marais Boutique"}, "id": dup}]},
        {"role": "tool", "tool_call_id": dup,
         "tool_call": {"function": "reserve_hotel", "args": {}},
         "content": "Reservation for Le Marais Boutique has been made successfully.",
         "error": None},
    ]
    steps, _ = steps_from_messages(msgs)
    assert "Rating" in str(steps[0].output), "the read must keep its own result"
    assert "Reservation" in str(steps[1].output)


def test_lexical_links_record_which_rule_matched():
    """Precision differs by rule, so a pooled lexical figure hides it. Links
    carry direct / numeric / token so each can be audited separately."""
    from staledep.provenance import trace_from_log
    from staledep.trajectory import Step

    steps = [
        Step(0, 0, "read_file", {}, "Pay UK12345678901234567890 the sum of 98.70", False),
        Step(1, 1, "send_money", {"recipient": "UK12345678901234567890"}, "sent", False),
    ]
    links = trace_from_log(steps)
    assert links and links[0].rule == "direct"


# ------------------------------------------------------------- evidence tier
def test_effect_typed_window_needs_no_lineage_to_be_reported():
    w = find_windows(["get_iban", "send_money"], "banking")[0]
    assert evidence_tier(w, []) == "state"


def test_a_window_resting_only_on_shared_words_is_marked_weak():
    """The objection any reviewer raises about fuzzy matching. Without a tier it
    cannot be answered with a number; measured, token-only is 0% of the
    high-risk committed set."""
    w = find_windows(["get_iban", "send_money"], "banking")[0]
    link = ProvenanceLink(w.check_idx, "get_iban", w.use_idx, "send_money",
                          "subject", "v", rule="token")
    assert evidence_tier(w, [link]) == "token-only"


def test_one_strong_link_outranks_any_number_of_weak_ones():
    w = find_windows(["get_iban", "send_money"], "banking")[0]
    weak = [ProvenanceLink(w.check_idx, "get_iban", w.use_idx, "send_money",
                           f"a{i}", "v", rule="token") for i in range(5)]
    strong = ProvenanceLink(w.check_idx, "get_iban", w.use_idx, "send_money",
                            "recipient", "DE89370400440532013000", rule="direct")
    assert evidence_tier(w, weak + [strong]) == "strong"


def test_numeric_lineage_is_strong_and_not_silently_called_direct():
    """A NumericLink has no `rule` field. A getattr default would quietly label
    arithmetic as `direct`; the tier is read off the type instead."""
    from staledep.numeric import NumericLink
    w = find_windows(["get_iban", "send_money"], "banking")[0]
    link = NumericLink(w.check_idx, "get_iban", w.use_idx, "send_money",
                       "amount", 200.0, "subset-sum", (120.0, 65.5, 14.5))
    assert evidence_tier(w, [link]) == "strong"


def test_links_on_a_different_edge_do_not_strengthen_this_window():
    w = find_windows(["get_iban", "send_money"], "banking")[0]
    elsewhere = ProvenanceLink(90, "read_file", 91, "send_money",
                               "recipient", "DE89370400440532013000", rule="direct")
    assert evidence_tier(w, [elsewhere]) == "state"


# ------------------------------------------------- claude_code, verified live
def test_write_fails_safe_and_is_not_a_dereference():
    """VERIFIED BY EXPERIMENT. Read a file, mutate it externally, then Write:
    the harness aborts with "File has been modified since read". The binding said
    DEREFERENCE, "overwrites whatever is there now, including changes made since
    the Read" -- both halves wrong. A concurrent mutation cancels the write, it
    does not redirect it."""
    from staledep.binding import Bind, bind_of
    from staledep.claudecode import register
    register()
    assert bind_of("claude_code", "Write", "workspace.files") is Bind.SNAPSHOT
    assert bind_of("claude_code", "Edit", "workspace.files") is Bind.SNAPSHOT


def test_untested_tools_are_unknown_rather_than_assumed():
    """NotebookEdit and TodoWrite appear zero times in the live corpus, so their
    bindings were never exercised. Untested is not the same as safe, and the
    metric degrades honestly by admitting it."""
    from staledep.binding import Bind, bind_of
    from staledep.claudecode import register
    register()
    assert bind_of("claude_code", "NotebookEdit", "workspace.files") is Bind.UNKNOWN
    assert bind_of("claude_code", "TodoWrite", "todo") is Bind.UNKNOWN


def test_unknown_outranks_snapshot_when_resolving_a_dataflow_edge():
    """The subtle consequence of the Write correction, pinned because it cost
    4.8 points of the primary metric and was not obvious.

    A `dataflow:X` pseudo-resource resolves through X's reads and takes the most
    dangerous verdict. Bash reads {shell, workspace.files}. While workspace.files
    claimed DEREFERENCE that outranked the `shell` UNKNOWN and the edge counted as
    classified; with SNAPSHOT, UNKNOWN wins and it is honestly unclassifiable.
    Coverage was inflated by the fiction, not by anything real."""
    from staledep.binding import Bind, bind_of
    from staledep.claudecode import register
    register()
    assert bind_of("claude_code", "Write", "dataflow:Bash") is Bind.UNKNOWN
    # and a source whose reads are all modelled still classifies
    assert bind_of("claude_code", "Write", "dataflow:Read") is not Bind.DEREFERENCE


# ------------------------------------------------- negative evidence (absence)
def test_a_read_that_found_nothing_is_a_check():
    """The highest-value recall gap. Both lineage signals follow a VALUE from an
    output into a later argument; when the check returns nothing there is no
    value to follow, so both are blind by construction. "I searched for a
    cancellation, found none, and proceeded" is a textbook race."""
    from staledep.absence import trace_absence
    steps = [
        ("search_emails", {"query": "cancellation"}, []),
        ("create_calendar_event", {"title": "Site visit"}, "created"),
    ]
    links = trace_absence(steps)
    assert [(x.source_idx, x.sink_idx) for x in links] == [(0, 1)]


def test_an_error_is_not_an_absence():
    """"channel not found" means the check did not happen. Treating that as a
    successful negative observation credits a failed call as evidence."""
    from staledep.absence import is_absent, trace_absence
    assert not is_absent("ValueError: channel not found")
    steps = [
        ("search_emails", {"query": "x"}, []),
        ("send_email", {"recipients": ["a@b.c"]}, "sent"),
    ]
    assert trace_absence(steps, errored={0}) == []


def test_absence_pairs_only_with_the_nearest_state_change():
    """Pairing every empty read with every later write would rebuild the
    read-then-act tautology this project exists to refute."""
    from staledep.absence import trace_absence
    steps = [
        ("search_emails", {"query": "x"}, []),
        ("send_email", {"recipients": ["a@b.c"]}, "sent"),
        ("send_email", {"recipients": ["d@e.f"]}, "sent"),
    ]
    assert [x.sink_idx for x in trace_absence(steps)] == [1]


def test_absence_binds_as_control_and_is_never_strong():
    """The check copied NO value into the action, so the only channel left is
    control flow -- a deduction from the observed trajectory, not an assumption
    about the sink's code, which is what made the send_money balance gate wrong.
    It remains the weakest claim here, so it gets its own tier."""
    from staledep.absence import AbsenceLink
    from staledep.binding import Bind, bind_of
    from staledep.toctou import Window, evidence_tier
    assert bind_of("workspace", "create_calendar_event",
                   "absence:search_emails") is Bind.CONTROL
    w = Window("absence:search_emails", 0, "search_emails", 1,
               "create_calendar_event", Risk.WRITE)
    link = AbsenceLink(0, "search_emails", 1, "create_calendar_event")
    assert evidence_tier(w, [link]) == "absence"


# ------------------------------------------------------ derived value: product
def test_quantity_times_unit_price_is_lineage():
    """The checkable half of the derived-value gap: both factors are in the
    source. Refusing it threw away a verifiable relation along with the
    unverifiable one."""
    from staledep.numeric import explain
    assert explain(546.0, [12.0, 45.5, 3.0]) == ("product", (12.0, 45.5))


def test_an_unobserved_exchange_rate_stays_uncovered():
    """100 EUR -> 6350 ETB needs a rate that is nowhere in the trajectory.
    Admitting unknown multipliers would match any pair of numbers at all, so
    this class stays uncovered and stays declared as uncovered."""
    from staledep.numeric import explain
    assert explain(6350.0, [100.0]) is None


def test_two_integers_multiplying_to_the_target_are_not_evidence():
    """Any composite number factors several ways. Measured, an integer-only rule
    produced 9 links on the corpus and every one was a coincidence --
    get_most_recent_transactions(n=100) "explained" as 2.0 x 50.0."""
    from staledep.numeric import explain
    assert explain(100.0, [2.0, 50.0]) is None


def test_a_sum_containing_the_target_is_a_copy_not_a_derivation():
    """amount=200.0 "derived" from [-1.0, 1.0, 200.0]: a cancelling pair padding
    a literal copy up to the three-term minimum. Lexical matching owns copies."""
    from staledep.numeric import explain
    assert explain(200.0, [-1.0, 1.0, 200.0]) is None
    assert explain(200.0, [120.0, 65.5, 14.5]) == ("subset-sum", (120.0, 65.5, 14.5))


def test_numeric_lineage_skips_read_sinks_when_the_suite_is_known():
    """A read acting on stale data changes nothing, so a numeric link into one
    can never form a window -- it is pure noise in a link-level audit."""
    from staledep.numeric import trace_numeric
    steps = [
        ("get_most_recent_transactions", {"n": 100}, "amount: 2.0 amount: 50.5"),
        ("get_most_recent_transactions", {"n": 101.0}, "x"),
    ]
    assert trace_numeric(steps, None, "banking") == []


def test_a_later_successful_read_cancels_the_absence():
    """VERIFIED FALSE POSITIVE, and the reason this guard exists. Every one of
    the nine danger-set entries the first version of the absence signal produced
    was this shape:

        search_files_by_filename("team meeting minutes") -> []
        search_files("team meeting minutes")             -> found it
        get_file_by_id("25")                             -> content
        send_email(...)

    The agent did not proceed on an absence, it recovered from a failed lookup --
    the opposite. An absence only counts while it is still the agent's most
    recent information about that resource, mirroring the rule that a write
    invalidates an earlier check. The guard took the signal's contribution to the
    danger set from 9 to 0."""
    from staledep.absence import trace_absence
    retried = [
        ("search_files_by_filename", {"filename": "minutes"}, []),
        ("search_files", {"query": "minutes"}, "content: Team Meeting Minutes"),
        ("send_email", {"recipients": ["a@b.c"]}, "sent"),
    ]
    assert trace_absence(retried) == [], "the retry found it; nothing was absent"

    never_found = [
        ("search_files_by_filename", {"filename": "grocery list"}, []),
        ("create_file", {"filename": "grocery_list.txt"}, "created"),
    ]
    assert len(trace_absence(never_found)) == 1, "check-then-create is still a race"


def test_no_blanket_supersession_rule_for_lineage_the_categories_differ():
    """A blanket resource-granular rule was implemented, shipped, and REVERTED.

    All 98 affected windows were classified by hand and they are not one thing:

      83  get_day_calendar_events -> create_calendar_event -> create_calendar_event
          create_event allocates a fresh id and assigns; it never consults
          existing events. The sink has NO dependence on calendar state, so this
          is a BINDING error -- now SNAPSHOT -- not a freshness one.

      15  search_files -> create_file -> share_file(file_id="26")
          create_file allocates max(existing)+1, so it CANNOT change what id 26
          resolves to. These windows are genuine, and the blanket rule deleted
          them for a reason that does not apply.

    Entity-granular supersession would be right, but the effect tables model
    RESOURCES, not entities, so it is not expressible. Recorded as N/A with the
    reason rather than implemented wrongly."""
    links = [ProvenanceLink(0, "search_files", 2, "share_file", "file_id", "26")]
    calls = ["search_files", "create_file", "share_file"]
    w = windows_from_provenance(calls, links, "workspace")
    assert [(x.check_idx, x.use_idx) for x in w] == [(0, 2)], (
        "create_file allocates a fresh id and cannot supersede a check of id 26"
    )


def test_create_calendar_event_does_not_gate_on_the_calendar():
    """VERIFIED FICTION, and the real cause of 83 of the 98. The binding said
    CONTROL, "slot-free check gates the booking". CalendarClient.create_event
    allocates a fresh id and assigns self.events[id_] = event -- no overlap
    check, no availability test. Mutating the calendar cannot change what gets
    booked.

    tests/test_binding_matches_source.py passed this: the body contains
    `calendar.create_event(...)`, and a delegation MENTION is not evidence of
    gating. A false negative in the checker, not a gap in the corpus."""
    from staledep.binding import Bind, bind_of
    assert bind_of("workspace", "create_calendar_event", "calendar") is Bind.SNAPSHOT
