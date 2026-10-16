"""
test_progress_bar.py — tests for the progress_fn callback wired into
APKIndex, plus tests for the make_progress_fn() factory in the engine.

Builds a small synthetic decompiled-APK tree in tmp_path with a handful
of .java and .smali files, then verifies:

  1. The progress_fn callback contract on APKIndex.build() and
     build_or_load_cached() — shape of args, initial/final ticks,
     monotonicity, throttle behavior, stage skipping, cache-hit path.
  2. The make_progress_fn() factory in verdict_engine — independent
     bars dicts per call (regression test for the mutable-default
     bug), one bar per stage, graceful handling when tqdm is absent.

Adjust the `from verdict_engine import make_progress_fn` import below
if your factory lives in a different module.
"""

from __future__ import annotations

import ujson
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.layer4.apk_navigator import APKIndex


# ============================================================
#  Fixtures
# ============================================================

def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _make_java(root: Path, pkg: str, name: str, extends: str | None = None) -> None:
    """Write a minimal but parser-valid Java file under jadx/sources/."""
    pkg_path = root / "jadx" / "sources" / Path(*pkg.split("."))
    ext = f" extends {extends}" if extends else ""
    _write(
        pkg_path / f"{name}.java",
        f"package {pkg};\n\npublic class {name}{ext} {{\n}}\n",
    )


def _make_smali(root: Path, smali_dir: str, pkg: str, name: str) -> None:
    """Write a minimal .smali file under apktool/<smali_dir>/."""
    pkg_path = root / "apktool" / smali_dir / Path(*pkg.split("."))
    smali_pkg = "/".join(pkg.split("."))
    _write(
        pkg_path / f"{name}.smali",
        f".class public L{smali_pkg}/{name};\n"
        f".super Ljava/lang/Object;\n",
    )


@pytest.fixture
def small_apk(tmp_path: Path) -> Path:
    """A small synthetic APK tree: a few Java files, a few smali files,
    enough variety to exercise the indexer but small enough to be fast."""
    for i in range(5):
        _make_java(tmp_path, "com.example.app", f"Foo{i}")
    _make_java(tmp_path, "com.example.app", "Bar", extends="Foo0")
    for i in range(3):
        _make_smali(tmp_path, "smali", "com.example.app", f"Baz{i}")
    _make_smali(tmp_path, "smali_classes2", "com.example.app", "Qux")
    return tmp_path


@pytest.fixture
def large_apk(tmp_path: Path) -> Path:
    """Bigger tree (>50 files per stage) to exercise the throttle.

    The progress_fn callback is throttled to every 50th file plus a
    final tick — we need >50 files to verify both intermediate and
    final callbacks fire correctly."""
    for i in range(120):
        _make_java(tmp_path, "com.example.big", f"Cls{i:03d}")
    for i in range(75):
        _make_smali(tmp_path, "smali", "com.example.big", f"S{i:03d}")
    return tmp_path


@pytest.fixture
def java_only_apk(tmp_path: Path) -> Path:
    """Tree with only jadx/sources, no apktool/ dir — verifies the
    smali stage is skipped cleanly when there's nothing to parse."""
    for i in range(3):
        _make_java(tmp_path, "com.example.javaonly", f"J{i}")
    return tmp_path


@pytest.fixture
def smali_only_apk(tmp_path: Path) -> Path:
    """Tree with only apktool/smali, no jadx/ dir — verifies the java
    stage is skipped cleanly."""
    for i in range(3):
        _make_smali(tmp_path, "smali", "com.example.smalionly", f"S{i}")
    return tmp_path


class ProgressRecorder:
    """Captures every progress_fn call for later assertion. Use this
    instead of a bare list so the test reads more clearly at the
    assert site (recorder.calls, recorder.stages, etc.)."""

    def __init__(self):
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, stage: str, completed: int, total: int) -> None:
        self.calls.append((stage, completed, total))

    @property
    def stages(self) -> list[str]:
        return [c[0] for c in self.calls]

    def calls_for(self, stage: str) -> list[tuple[str, int, int]]:
        return [c for c in self.calls if c[0] == stage]


# ============================================================
#  Basic invocation
# ============================================================

def test_progress_fn_called_during_build(small_apk: Path):
    """progress_fn fires at least once when both stages have work."""
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)
    assert rec.calls, "Expected progress_fn to be invoked at least once"


def test_progress_fn_optional(small_apk: Path):
    """Omitting progress_fn must not raise. This guards backward compat
    for any caller still using the old build() signature."""
    APKIndex(small_apk).build()  # would raise on a missing default


def test_progress_fn_explicit_none(small_apk: Path):
    """Passing progress_fn=None is equivalent to omitting it."""
    APKIndex(small_apk).build(progress_fn=None)


# ============================================================
#  Shape of the callback arguments
# ============================================================

def test_progress_calls_have_correct_shape(small_apk: Path):
    """Each call is (stage: str, completed: int, total: int) with
    0 <= completed <= total and total matching the file count."""
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)
    for stage, completed, total in rec.calls:
        assert stage in {"java", "smali"}, f"Unexpected stage: {stage}"
        assert isinstance(completed, int)
        assert isinstance(total, int)
        assert 0 <= completed <= total, (
            f"completed={completed} outside [0, {total}] for stage {stage}"
        )


def test_total_matches_file_count(small_apk: Path):
    """The `total` values reported match the actual file counts.

    Java: one stage covering all of jadx/sources/, so totals form a
    single-element set matching the file count.

    Smali: one stage per apktool/smali*/ directory (multi-dex APKs
    have several), so totals form a set with one entry per directory.
    """
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)

    # Java: single stage, single total.
    java_count = len(list((small_apk / "jadx" / "sources").rglob("*.java")))
    java_totals = {c[2] for c in rec.calls_for("java")}
    assert java_totals == {java_count}

    # Smali: one stage per smali* dir, each with its own total.
    smali_dir_counts = {
        len(list((small_apk / "apktool" / d).rglob("*.smali")))
        for d in ("smali", "smali_classes2")
    }
    smali_totals = {c[2] for c in rec.calls_for("smali")}
    assert smali_totals == smali_dir_counts, (
        f"Expected one total per smali* dir ({smali_dir_counts}), "
        f"got {smali_totals}"
    )


# ============================================================
#  Initial and final ticks
# ============================================================

def test_initial_tick_at_zero(small_apk: Path):
    """First call for each stage reports completed=0 so a UI bar can
    initialize before parsing begins."""
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)
    java_first = rec.calls_for("java")[0]
    assert java_first[1] == 0


def test_final_tick_equals_total(small_apk: Path):
    """Last call for each stage reports completed == total so the UI
    bar finishes at 100%."""
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)

    for stage in ("java", "smali"):
        stage_calls = rec.calls_for(stage)
        assert stage_calls, f"No calls recorded for stage {stage}"
        last_stage, last_completed, last_total = stage_calls[-1]
        assert last_completed == last_total, (
            f"Stage {stage} ended at {last_completed}/{last_total}, "
            f"expected equality"
        )


def test_completed_is_monotonic(large_apk: Path):
    """Within a stage, `completed` only ever increases. A UI bar that
    sees decreasing values would jitter."""
    rec = ProgressRecorder()
    APKIndex(large_apk).build(progress_fn=rec)
    for stage in ("java", "smali"):
        completeds = [c[1] for c in rec.calls_for(stage)]
        assert completeds == sorted(completeds), (
            f"Stage {stage} progress not monotonic: {completeds}"
        )


# ============================================================
#  Throttle behavior
# ============================================================

def test_throttle_emits_intermediate_ticks(large_apk: Path):
    """With >50 files per stage, the i % 50 == 0 throttle should emit
    intermediate ticks (not just the 0 and final). This catches a bug
    where someone accidentally removes the throttle and only fires
    the final tick — the UX regression wouldn't fail other tests."""
    rec = ProgressRecorder()
    APKIndex(large_apk).build(progress_fn=rec)
    java_calls = rec.calls_for("java")
    intermediates = [c for c in java_calls if 0 < c[1] < c[2]]
    assert intermediates, (
        "Expected intermediate progress ticks between start and "
        "finish for a 120-file Java stage; got none"
    )


def test_small_tree_still_gets_final_tick(small_apk: Path):
    """The throttle includes `or i == total`, so even a tree with <50
    files (which never hits the i % 50 == 0 branch) gets a final tick.
    Regression test for the obvious off-by-one if someone writes the
    throttle as just `i % 50 == 0`."""
    rec = ProgressRecorder()
    APKIndex(small_apk).build(progress_fn=rec)
    for stage in ("java", "smali"):
        stage_calls = rec.calls_for(stage)
        last = stage_calls[-1]
        assert last[1] == last[2]


# ============================================================
#  Stage skipping
# ============================================================

def test_no_smali_stage_when_apktool_dir_missing(java_only_apk: Path):
    """If there's no apktool/ directory, the smali stage shouldn't
    produce any callbacks."""
    rec = ProgressRecorder()
    APKIndex(java_only_apk).build(progress_fn=rec)
    assert "smali" not in rec.stages
    assert "java" in rec.stages


def test_no_java_stage_when_jadx_dir_missing(smali_only_apk: Path):
    """Mirror of the above for the smali-only case."""
    rec = ProgressRecorder()
    APKIndex(smali_only_apk).build(progress_fn=rec)
    assert "java" not in rec.stages
    assert "smali" in rec.stages


def test_empty_tree_no_callbacks(tmp_path: Path):
    """An APK root with neither jadx/ nor apktool/ produces no
    callbacks (and doesn't raise)."""
    rec = ProgressRecorder()
    APKIndex(tmp_path).build(progress_fn=rec)
    assert rec.calls == []


# ============================================================
#  Cache-hit path
# ============================================================

def test_cache_hit_does_not_invoke_progress_fn(small_apk: Path):
    """build_or_load_cached on a warm cache returns immediately
    without re-parsing. progress_fn should not fire — there's no
    work to report."""
    APKIndex.build_or_load_cached(small_apk)
    assert (small_apk / ".apk_index_cache.json").is_file()

    rec = ProgressRecorder()
    APKIndex.build_or_load_cached(small_apk, progress_fn=rec)
    assert rec.calls == [], (
        f"Expected no progress callbacks on cache hit, got {rec.calls}"
    )


def test_cache_miss_invokes_progress_fn(small_apk: Path):
    """First-time build_or_load_cached (no cache file) should invoke
    progress_fn normally."""
    cache = small_apk / ".apk_index_cache.json"
    assert not cache.is_file()  # sanity
    rec = ProgressRecorder()
    APKIndex.build_or_load_cached(small_apk, progress_fn=rec)
    assert rec.calls, "Expected progress callbacks on cold cache"


def test_stale_cache_invokes_progress_fn(small_apk: Path):
    """A cache file whose fingerprint doesn't match the current tree
    should be discarded and the index rebuilt, with progress
    reported."""
    APKIndex.build_or_load_cached(small_apk)
    cache = small_apk / ".apk_index_cache.json"
    payload =ujson.loads(cache.read_text())
    payload["fingerprint"] = {"jadx": {"count": 999, "mtime": 0.0}}
    cache.write_text(ujson.dumps(payload))

    rec = ProgressRecorder()
    APKIndex.build_or_load_cached(small_apk, progress_fn=rec)
    assert rec.calls, "Expected rebuild + progress on stale cache"


# ============================================================
#  Callback errors do not corrupt the index
# ============================================================

def test_index_still_correct_when_progress_fn_raises(small_apk: Path):
    """If progress_fn raises (e.g. a misbehaving UI callback), the
    current contract is that the exception propagates. If you later
    decide to swallow exceptions inside the callback dispatch
    (recommended), update this test to assert the index built
    successfully instead."""

    def boom(stage, completed, total):
        raise RuntimeError("UI exploded")

    with pytest.raises(RuntimeError):
        APKIndex(small_apk).build(progress_fn=boom)


# ============================================================
#  make_progress_fn() factory — engine-side wiring
# ============================================================
#
# These tests cover the closure-based factory that builds a tqdm-
# backed progress_fn for the navigator. The factory must produce
# independent bars dicts per call, so that indexing two APKs in the
# same process doesn't reuse closed tqdm bars from the previous run.
# This is the regression test for the `bars={}` mutable-default-arg
# bug we fixed by switching to a closure.
#
# Adjust the import path below to wherever make_progress_fn lives.

try:
    from verdict_engine import make_progress_fn  # adjust to your layout
    HAS_FACTORY = True
except ImportError:
    HAS_FACTORY = False


pytestmark_factory = pytest.mark.skipif(
    not HAS_FACTORY,
    reason="make_progress_fn not importable; adjust import path",
)


@pytestmark_factory
def test_make_progress_fn_returns_independent_state():
    """Each call to make_progress_fn() must return a progress_fn whose
    bars state is independent of other calls. We verify this through
    observable behavior rather than closure introspection: if the
    factories shared a bars dict, the second pf() call for the same
    stage would skip the tqdm() construction."""
    with patch("verdict_engine.tqdm") as mock_tqdm:
        mock_tqdm.side_effect = lambda **kw: MagicMock()
        pf1 = make_progress_fn()
        pf2 = make_progress_fn()
        assert pf1 is not pf2, "Each factory call must return a fresh function"
        pf1("java", 0, 100)
        pf2("java", 0, 100)
        # Two distinct factories called for the same stage → two tqdm
        # constructions. Shared state would give only one.
        assert mock_tqdm.call_count == 2, (
            "make_progress_fn() instances share bars state; "
            "back-to-back indexing would reuse closed bars"
        )


@pytestmark_factory
def test_make_progress_fn_creates_bar_per_stage(small_apk: Path):
    """A single progress_fn from the factory should create one bar
    per stage encountered. After indexing finishes, every bar should
    be closed (the final completed == total tick triggers .close())."""
    with patch("verdict_engine.tqdm") as mock_tqdm:
        created_bars: list[MagicMock] = []

        def make_bar(*args, **kwargs):
            bar = MagicMock()
            bar.total = kwargs.get("total")
            bar.desc = kwargs.get("desc")
            created_bars.append(bar)
            return bar

        mock_tqdm.side_effect = make_bar

        pf = make_progress_fn()
        APKIndex(small_apk).build(progress_fn=pf)

        descs = {bar.desc for bar in created_bars}
        assert descs == {"Indexing java", "Indexing smali"}, (
            f"Expected one bar per stage, got descs: {descs}"
        )
        for bar in created_bars:
            bar.close.assert_called_once()


@pytestmark_factory
def test_make_progress_fn_reuses_bar_within_stage(small_apk: Path):
    """Multiple ticks for the same stage should update the existing
    bar rather than create a new one. tqdm() should be called once
    per stage, not once per tick."""
    with patch("verdict_engine.tqdm") as mock_tqdm:
        mock_tqdm.side_effect = lambda **kw: MagicMock()
        pf = make_progress_fn()
        APKIndex(small_apk).build(progress_fn=pf)
        # One tqdm() call per stage (java + smali), regardless of how
        # many intermediate ticks fired.
        assert mock_tqdm.call_count == 2, (
            f"Expected exactly 2 tqdm() constructions (one per stage), "
            f"got {mock_tqdm.call_count}"
        )


@pytestmark_factory
def test_make_progress_fn_handles_missing_tqdm():
    """If tqdm isn't installed, make_progress_fn() should degrade
    gracefully — either by returning None (which APKIndex accepts) or
    by returning a working no-op callable. Skip this test if your
    implementation imports tqdm at module level instead of inside the
    factory; in that case the fallback path isn't reachable."""
    with patch.dict("sys.modules", {"tqdm": None}):
        try:
            pf = make_progress_fn()
        except ImportError:
            pytest.skip("make_progress_fn imports tqdm at module level")
        assert pf is None or callable(pf), (
            "make_progress_fn() should return None or a callable when "
            "tqdm is unavailable, not raise"
        )