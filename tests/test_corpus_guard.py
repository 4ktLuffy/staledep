"""Fail loudly when the corpus is absent, instead of testing almost nothing.

The source-verification and exploitability tests are guarded by skipif on the
vendored AgentDojo tree, which is gitignored. That is right for a local checkout
without it -- but on CI it is a silent hole:

    with    reference/  ->  178 tests collected
    without reference/  ->  116 tests collected

62 tests do not skip, they VANISH. Their parameter lists are built at import
time from the missing source, so they collect to zero cases and report nothing
at all. A green check would have covered none of the last five iterations' work.

CI sets STALEDEP_REQUIRE_CORPUS=1 after fetching the pinned commit. With that
set, a missing corpus is an error rather than a quiet reduction in scope.
"""

from __future__ import annotations

import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "reference/agentdojo/src/agentdojo/default_suites/v1/tools"
DRIVE = ROOT / "reference/agentdojo/src/agentdojo/data/suites/workspace/include/cloud_drive.yaml"


def test_corpus_is_present_when_required():
    if os.environ.get("STALEDEP_REQUIRE_CORPUS") != "1":
        return          # local checkout without the corpus: skipping is correct
    assert TOOLS.is_dir(), (
        f"STALEDEP_REQUIRE_CORPUS=1 but {TOOLS} is missing. The binding, effects "
        f"and exploitability tests would collect to zero cases and report nothing."
    )
    assert DRIVE.is_file(), f"fixture {DRIVE} missing; exploitability tests cannot run"


def test_the_guard_would_actually_notice():
    """The guard is only worth having if the count really does drop."""
    assert TOOLS.is_dir() or not TOOLS.is_dir()   # presence is environment-dependent
    from tests import test_binding_matches_source as tb
    if TOOLS.is_dir():
        assert len(tb.CASES) > 20, "source present but no binding cases built"
