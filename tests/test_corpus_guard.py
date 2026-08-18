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
EXPECTED_BINDING_CASES = 23   # 24 before create_file CONTROL -> SNAPSHOT
EXPECTED_EFFECT_CASES = 63
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
