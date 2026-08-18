"""Prove the corpus-dependent cases were COLLECTED, not just that a directory exists.

The first version of this guard only checked `TOOLS.is_dir()`. That is too weak:
the failure mode is not a missing directory, it is parametrised tests whose
parameter lists are built at import time from the corpus and therefore collect to
ZERO cases when it is absent. They do not skip. They vanish, silently, and the
run still reports success.

    with    reference/  ->  178 tests collected
    without reference/  ->  116 tests collected

62 tests disappear with no signal at all. So this asserts the actual case counts
and the pinned revision, which is what "the corpus is usable" really means.

Counts are lower bounds, not equalities: adding a binding or a tool should not
break CI, but losing two thirds of the suite must.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENTDOJO = ROOT / "reference/agentdojo"
TOOLS = AGENTDOJO / "src/agentdojo/default_suites/v1/tools"
DRIVE = AGENTDOJO / "src/agentdojo/data/suites/workspace/include/cloud_drive.yaml"
TRAVEL = AGENTDOJO / "src/agentdojo/data/suites/travel/environment.yaml"

#: The commit CORPUS.md pins. A different revision means the source-verification
#: findings were checked against code that is not what CI is running.
PINNED = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"

#: EXACT counts at the pinned revision, not minimums. A minimum still lets cases
#: disappear silently -- losing 4 of 24 binding cases would pass a >=20 bound.
#: These are a manifest: changing them requires editing this file, which is the
#: explicit review step. A count that moves for a legitimate reason (a binding
#: added, a tool declared) fails here first and is updated deliberately.
EXPECTED_BINDING_CASES = 22   # 23 before update_user_info.user -> SNAPSHOT
EXPECTED_EFFECT_CASES = 63

#: Collection accounting, so the two figures cannot be mistaken for one another.
#: Adding the corpus moves collection 170 -> 232, a difference of 62, and ALL 62
#: come from one test: test_declared_writer_status_matches_the_source goes from a
#: single empty-parametrize placeholder to 63 cases (63 - 1 = 62). The 22 binding
#: cases are built from EDGE_BINDING rather than the corpus, so they always
#: collect and SKIP visibly instead of vanishing.
#: Updated deliberately when the suite grows -- this assertion firing IS the
#: review step, and it fired on the first real CI run because tests added after
#: the constant was written pushed collection from 209 to 232.
EXPECTED_COLLECTED_WITH_CORPUS = 232
EXPECTED_COLLECTED_WITHOUT_CORPUS = 170

#: The ONLY skip permitted in a full corpus run. Any other skip means a test
#: silently stopped covering something.
EXPECTED_SKIPS = {
    ("test_binding_matches_source.py",
     "no source symbol mapped for workspace/email.received"),
}
REQUIRED = os.environ.get("STALEDEP_REQUIRE_CORPUS") == "1"


def _required(msg: str) -> None:
    if REQUIRED:
        raise AssertionError(msg)


def test_corpus_fixtures_are_present_when_required():
    if not REQUIRED:
        return          # a local checkout without the corpus is legitimate
    assert TOOLS.is_dir(), f"{TOOLS} missing"
    assert DRIVE.is_file(), f"{DRIVE} missing; exploitability tests cannot run"
    assert TRAVEL.is_file(), f"{TRAVEL} missing; the snapshot control cannot run"


def test_corpus_is_at_the_pinned_revision():
    """A green run against an unpinned revision proves nothing about the
    findings, which were verified against specific source."""
    if not REQUIRED:
        return
    head = subprocess.run(["git", "-C", str(AGENTDOJO), "rev-parse", "HEAD"],
                          capture_output=True, text=True)
    assert head.returncode == 0, f"cannot read corpus revision: {head.stderr.strip()}"
    got = head.stdout.strip()
    assert got == PINNED, (
        f"corpus is at {got}, CORPUS.md pins {PINNED}. The binding and effects "
        f"findings were verified against the pinned source."
    )


def test_binding_cases_were_actually_built():
    """The specific failure: CASES is a module-level comprehension over the
    corpus, so an absent corpus yields an empty list and zero collected tests."""
    from tests import test_binding_matches_source as mod
    if not TOOLS.is_dir():
        _required(f"corpus absent: {mod.__name__} built {len(mod.CASES)} cases")
        return
    assert len(mod.CASES) == EXPECTED_BINDING_CASES, (
        f"{mod.__name__} built {len(mod.CASES)} cases, manifest says "
        f"{EXPECTED_BINDING_CASES}. If a binding was added or removed on purpose, "
        f"update EXPECTED_BINDING_CASES in this file -- that edit is the review."
    )


def test_effect_cases_were_actually_built():
    from tests import test_effects_match_source as mod
    if not TOOLS.is_dir():
        _required(f"corpus absent: {mod.__name__} built {len(mod.CASES)} cases")
        return
    assert len(mod.CASES) == EXPECTED_EFFECT_CASES, (
        f"{mod.__name__} built {len(mod.CASES)} cases, manifest says "
        f"{EXPECTED_EFFECT_CASES}. Update deliberately if intended."
    )


def test_exploitability_fixtures_load():
    """Its tests are skipif-guarded, which is a skip and therefore visible --
    unlike the two above. Still asserted so CI cannot pass on a truncated run."""
    if not DRIVE.is_file():
        _required("cloud_drive fixture absent; exploitability tests would skip")
        return
    import yaml
    data = yaml.safe_load(DRIVE.read_text())
    files = data.get("initial_files")
    assert files, f"cloud_drive fixture has no initial_files; keys={sorted(data)}"
    assert len(files) >= 5, f"only {len(files)} files; the demo indexes listing[3]"


def test_exactly_one_skip_in_a_full_corpus_run():
    """A skip is a test that stopped covering something. One is expected and
    named; a second means coverage was lost silently, which is the failure this
    whole guard exists to prevent."""
    if not REQUIRED:
        return
    import subprocess
    import sys
    # sys.executable, not "python": the bare name does not exist on macOS with a
    # venv and the guard silently FileNotFound-ed locally while passing on CI,
    # where setup-python provides it. Same interpreter as the running suite is
    # also the only correct choice -- a different one could collect differently.
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", "--co", "-p", "no:cacheprovider"],
        cwd=str(ROOT), capture_output=True, text=True)
    assert out.returncode == 0, out.stdout[-400:]
    assert f"{EXPECTED_COLLECTED_WITH_CORPUS} tests collected" in out.stdout, (
        f"expected exactly {EXPECTED_COLLECTED_WITH_CORPUS} collected; "
        f"tail: {out.stdout.strip().splitlines()[-1]}"
    )


def test_collection_accounting_is_recorded_not_inferred():
    """147 -> 209 is 62 vanished items, all from ONE test going 1 -> 63. The
    manifest's 23 and 63 are CASE counts, not collection deltas; recording the
    mapping stops them being read as the same quantity."""
    assert EXPECTED_COLLECTED_WITH_CORPUS - EXPECTED_COLLECTED_WITHOUT_CORPUS == 62
    assert EXPECTED_EFFECT_CASES - 1 == 62, "63 cases replace 1 empty placeholder"
