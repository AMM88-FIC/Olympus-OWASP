#!/usr/bin/env python3
"""
build_evidence.py — rebuild selected Layer 3 evidence files.

The point of this tool: **most evidence files can be rebuilt without re-running
any extraction tool.** Apktool and JADX already wrote their output to
`storage/artifacts/<job>/`, so a builder that reads those directories can run
again in seconds. Only the Androguard- and LibScout-backed files need a tool
re-run, because those runners produce data in-process rather than on disk.

So after changing a builder, this rebuilds just the files it affects:

    python build_evidence.py --job xiaomi-explorer --only crypto_usage

    python build_evidence.py --list            # what can be built, and from what
    python build_evidence.py --job X --all     # everything the artifacts allow
    python build_evidence.py --job X --only crypto_usage --dry-run

Dependencies are resolved automatically. `--only deep_links` builds `components`
first because `deep_links` consumes it, but by default writes only what you
asked for; pass `--write-deps` to persist the intermediates too.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# ============================================================
#  What each evidence file needs
# ============================================================
#
# `needs`: artifact sources. 'jadx' and 'apktool' are read from disk, so they
#          cost nothing. 'androguard' and 'libscout' require the APK and a tool
#          re-run. '' means it is derived purely from other evidence files.
# `deps`:  other evidence files, built first.

SPEC: dict[str, dict] = {
    # --- JADX only: rebuildable from existing artifacts, fast ---------------
    "api_usages":          {"needs": ("jadx",),   "deps": ()},
    "crypto_usage":        {"needs": ("jadx",),   "deps": ()},
    "network_usage":       {"needs": ("jadx",),   "deps": ()},
    "outgoing_intents":    {"needs": ("jadx",),   "deps": ()},
    "storage_usage":       {"needs": ("jadx",),   "deps": ()},
    "webview_usage":       {"needs": ("jadx",),   "deps": ()},

    # --- Apktool only ------------------------------------------------------
    "manifest_findings":   {"needs": ("apktool",), "deps": ()},
    "permissions":         {"needs": ("apktool",), "deps": ()},
    "native_binaries":     {"needs": ("apktool",), "deps": ()},
    "components":          {"needs": ("apktool",), "deps": ()},
    "network_security":    {"needs": ("apktool",), "deps": ("manifest_findings",)},
    "assets_inventory":    {"needs": ("apktool",), "deps": ("network_security",)},

    # --- both --------------------------------------------------------------
    "native_methods":      {"needs": ("jadx", "apktool"), "deps": ()},

    # --- derived from other evidence files only -----------------------------
    "deep_links":          {"needs": (), "deps": ("components",)},
    "validation_errors":   {"needs": (), "deps": ()},
    "sensitivity_signals": {"needs": (), "deps": (
        "storage_usage", "api_usages", "network_usage", "crypto_usage")},
    "app_capabilities":    {"needs": (), "deps": (
        "components", "permissions", "deep_links", "webview_usage")},

    # --- need a tool re-run (Androguard runs in-process; needs the APK) -----
    "strings":             {"needs": ("androguard",), "deps": ()},
    "third_party_sdks":    {"needs": ("androguard",), "deps": ()},
    "call_graph":          {"needs": ("androguard",), "deps": ()},
    "obfuscation":         {"needs": ("androguard", "apktool"), "deps": ()},
    "app_metadata":        {"needs": ("androguard", "apksigner", "apk"), "deps": ()},
    "detected_libraries":  {"needs": ("libscout",), "deps": ()},
}

# coverage consumes nearly everything, so it is opt-in rather than part of --all.
COVERAGE_DEPS = (
    "obfuscation", "components", "permissions", "deep_links", "api_usages",
    "crypto_usage", "webview_usage", "network_usage", "storage_usage",
    "outgoing_intents", "strings", "third_party_sdks", "assets_inventory",
    "native_methods", "manifest_findings",
)

FILENAME = {name: f"{name}.json" for name in SPEC}
FILENAME["validation_errors"] = "_validation_errors.json"


# ============================================================
#  Artifact sources, built lazily
# ============================================================

class Sources:
    """Reconstructs Layer 2 results from what is already on disk, and only
    re-runs a tool when a builder genuinely needs in-process data."""

    def __init__(self, job: str, artifacts: Path, apk: Path | None, log):
        self.job = job
        self.root = artifacts / job
        self.apk = apk
        self.log = log
        self._cache: dict[str, object] = {}

    # -- on-disk: free -----------------------------------------------------

    def jadx(self):
        if "jadx" not in self._cache:
            from app.layer2.jadx_runner import JadxResult
            out = self.root / "jadx"
            src = out / "sources"
            if not src.is_dir():
                raise Missing(
                    f"JADX sources not found at {src}. This job was not "
                    f"decompiled, or the artifact tree is elsewhere."
                )
            java = list(src.rglob("*.java"))
            self.log(f"  jadx      {len(java):,} .java files  ({src})")
            self._cache["jadx"] = JadxResult(
                success=True, job_id=self.job, output_dir=out,
                source_dir=src,
                resources_dir=(out / "resources") if (out / "resources").is_dir() else None,
                java_files=java,
            )
        return self._cache["jadx"]

    def apktool(self):
        if "apktool" not in self._cache:
            from app.layer2.apktool_runner import ApktoolResult
            out = self.root / "apktool"
            if not out.is_dir():
                raise Missing(f"Apktool output not found at {out}.")
            manifest = out / "AndroidManifest.xml"
            nsc = out / "res" / "xml" / "network_security_config.xml"
            smali = sorted(p for p in out.glob("smali*") if p.is_dir())
            self.log(f"  apktool   manifest={'yes' if manifest.is_file() else 'NO'}  "
                     f"{len(smali)} smali dir(s)  ({out})")
            self._cache["apktool"] = ApktoolResult(
                success=True, job_id=self.job, output_dir=out,
                manifest_path=manifest if manifest.is_file() else None,
                nsc_path=nsc if nsc.is_file() else None,
                smali_dirs=smali,
                assets_dir=(out / "assets") if (out / "assets").is_dir() else None,
                res_dir=(out / "res") if (out / "res").is_dir() else None,
            )
        return self._cache["apktool"]

    # -- needs a tool re-run ----------------------------------------------

    def androguard(self):
        if "androguard" not in self._cache:
            if not self.apk:
                raise Missing(
                    "Androguard-backed files need the APK: pass --apk PATH. "
                    "(Androguard returns data in-process, so unlike JADX and "
                    "Apktool there is nothing on disk to reuse.)"
                )
            from app.layer2.androguard_runner import run_androguard
            self.log(f"  androguard  running over {self.apk.name} (slow)...")
            t = time.time()
            res = run_androguard(self.job, self.apk)
            self.log(f"              done in {time.time() - t:.1f}s "
                     f"(success={res.success})")
            self._cache["androguard"] = res
        return self._cache["androguard"]

    def libscout(self):
        if "libscout" not in self._cache:
            if not self.apk:
                raise Missing("detected_libraries needs the APK: pass --apk PATH.")
            from app.layer2.libscout_runner import run_libscout
            self.log(f"  libscout    running over {self.apk.name} (slow)...")
            self._cache["libscout"] = run_libscout(
                self.job, self.apk, self.root.parent)
        return self._cache["libscout"]

    def apksigner(self):
        """The signing certificate, or None when apksigner cannot run.

        app_metadata's `certificates` and `signing_schemes` come from here and
        nowhere else. Without it `_build_certificates(None)` returns an empty
        list with status "unavailable" — honest, but it drops the one field
        that names who published and signed the APK, which is what separates
        the publisher's own code from a bundled third-party library.

        Returns None rather than raising: a missing apksigner should degrade
        this one section, not fail the rebuild. `certificates_status` reports
        the degradation, so nothing here asserts a falsehood.
        """
        if "apksigner" not in self._cache:
            if not self.apk:
                raise Missing("app_metadata's certificates need the APK: pass --apk PATH.")
            try:
                from app.layer2.apksigner_runner import run_apksigner
                self.log(f"  apksigner   reading the signature of {self.apk.name}...")
                self._cache["apksigner"] = run_apksigner(
                    self.job, self.apk, self.root.parent)
            except Exception as exc:                         # noqa: BLE001
                self.log(f"  apksigner   UNAVAILABLE ({exc}) — certificates and "
                         f"signing schemes will be empty. Put apksigner on PATH, "
                         f"or set APKSIGNER_BIN in app/utils/config.py.")
                self._cache["apksigner"] = None
        return self._cache["apksigner"]

    def apk_path(self):
        if not self.apk:
            raise Missing("app_metadata needs the APK: pass --apk PATH.")
        return self.apk


class Missing(Exception):
    """A required input is absent. Reported without a traceback."""


# ============================================================
#  Build one file
# ============================================================

def build_one(name: str, b, job: str, src: Sources, built: dict):
    """Call the builder for `name`, wiring whatever inputs it declares."""
    mod = getattr(b, name)

    if name in ("api_usages", "crypto_usage", "network_usage",
                "outgoing_intents", "storage_usage", "webview_usage"):
        return mod.build(job, src.jadx())
    if name in ("manifest_findings", "permissions", "native_binaries"):
        return mod.build(job, src.apktool())
    if name == "components":
        meta = built.get("app_metadata")
        target_sdk = meta.app.target_sdk if meta else None
        return mod.build(job, src.apktool(), target_sdk)
    if name == "network_security":
        return mod.build(job, src.apktool(), built.get("manifest_findings"))
    if name == "assets_inventory":
        return mod.build(job, src.apktool(), built.get("network_security"))
    if name == "native_methods":
        return mod.build(job, src.jadx(), src.apktool())
    if name == "deep_links":
        return mod.build(job, built["components"])
    if name == "validation_errors":
        return mod.build(job)
    if name == "sensitivity_signals":
        return mod.build(
            job,
            storage_usage_file=built.get("storage_usage"),
            api_usages_file=built.get("api_usages"),
            network_usage_file=built.get("network_usage"),
            crypto_usage_file=built.get("crypto_usage"),
        )
    if name == "app_capabilities":
        return mod.build(
            job,
            components_file=built.get("components"),
            permissions_file=built.get("permissions"),
            deep_links_file=built.get("deep_links"),
            webview_usage_file=built.get("webview_usage"),
        )
    if name in ("strings", "third_party_sdks", "call_graph"):
        return mod.build(job, src.androguard())
    if name == "obfuscation":
        return mod.build(job, src.androguard(), src.apktool())
    if name == "app_metadata":
        return mod.build(job, src.androguard(), src.apk_path(),
                         apksigner_result=src.apksigner())
    if name == "detected_libraries":
        return mod.build(job, src.libscout())
    if name == "coverage":
        return mod.build(
            job, src.apktool(), src.jadx(), src.androguard(),
            *(built.get(d) for d in COVERAGE_DEPS),
        )
    raise Missing(f"No wiring defined for {name!r}")


def resolve_order(requested: list[str]) -> list[str]:
    """Depth-first dependency expansion, preserving a deterministic order."""
    order: list[str] = []

    def visit(n: str, chain: tuple[str, ...] = ()):
        if n in order:
            return
        if n in chain:
            raise Missing(f"Dependency cycle: {' -> '.join(chain + (n,))}")
        deps = COVERAGE_DEPS if n == "coverage" else SPEC[n]["deps"]
        for d in deps:
            visit(d, chain + (n,))
        order.append(n)

    for n in requested:
        visit(n)
    return order


# ============================================================
#  CLI
# ============================================================

def cmd_list() -> int:
    groups = [
        ("from existing JADX output — fast, no tool re-run",
         [n for n, s in SPEC.items() if s["needs"] == ("jadx",)]),
        ("from existing Apktool output — fast, no tool re-run",
         [n for n, s in SPEC.items() if s["needs"] == ("apktool",)]),
        ("from both",
         [n for n, s in SPEC.items() if set(s["needs"]) == {"jadx", "apktool"}]),
        ("derived from other evidence files only",
         [n for n, s in SPEC.items() if not s["needs"]]),
        ("NEEDS --apk and a tool re-run (slow)",
         [n for n, s in SPEC.items()
          if {"androguard", "libscout", "apk"} & set(s["needs"])]),
    ]
    print()
    for title, names in groups:
        if not names:
            continue
        print(f"  {title}:")
        for n in sorted(names):
            deps = SPEC[n]["deps"]
            suffix = f"   (after: {', '.join(deps)})" if deps else ""
            print(f"     {n}{suffix}")
        print()
    print("  coverage   (after: everything above — opt in with --only coverage)")
    print()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Rebuild selected Layer 3 evidence files from existing "
                    "Layer 2 artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--job", help="Job id, i.e. the dir under --artifacts.")
    ap.add_argument("--artifacts", type=Path, default=REPO / "storage" / "artifacts")
    ap.add_argument("--only", default="",
                    help="Comma-separated evidence names to build.")
    ap.add_argument("--all", action="store_true",
                    help="Everything the available artifacts allow.")
    ap.add_argument("--apk", type=Path, default=None,
                    help="APK path — required only for Androguard/LibScout files.")
    ap.add_argument("--out", type=Path, default=None,
                    help="Output dir (default: <artifacts>/<job>/evidence).")
    ap.add_argument("--write-deps", action="store_true",
                    help="Also write files built only as dependencies.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Resolve and report, write nothing.")
    ap.add_argument("--list", action="store_true", dest="do_list")
    args = ap.parse_args()

    if args.do_list:
        return cmd_list()
    if not args.job:
        ap.error("--job is required (or use --list)")
    if not args.only and not args.all:
        ap.error("pass --only NAME[,NAME...] or --all")

    def log(m=""):
        print(m)

    job_root = args.artifacts / args.job
    if not job_root.is_dir():
        print(f"ERROR: no job at {job_root}", file=sys.stderr)
        return 2

    if args.all:
        requested = [n for n, s in SPEC.items()
                     if not ({"androguard", "libscout", "apk"} & set(s["needs"]))]
        if args.apk:
            requested = list(SPEC)
    else:
        requested = [n.strip() for n in args.only.split(",") if n.strip()]

    unknown = [n for n in requested if n not in SPEC and n != "coverage"]
    if unknown:
        print(f"ERROR: unknown evidence name(s): {', '.join(unknown)}\n"
              f"       run --list to see the available names", file=sys.stderr)
        return 2

    try:
        order = resolve_order(requested)
    except Missing as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out_dir = args.out or (job_root / "evidence")
    deps_only = [n for n in order if n not in requested]

    print(f"\njob         {args.job}")
    print(f"artifacts   {job_root}")
    print(f"output      {out_dir}")
    print(f"requested   {', '.join(requested)}")
    if deps_only:
        print(f"+ deps      {', '.join(deps_only)}"
              f"{'  (written too)' if args.write_deps else '  (built, not written)'}")
    print()

    if args.dry_run:
        print("dry run — nothing written. Build order:")
        for i, n in enumerate(order, 1):
            print(f"  {i:2}. {n}")
        return 0

    print("inputs:")
    src = Sources(args.job, args.artifacts, args.apk, log)

    # Importing the builders pulls in pydantic and ujson. Report a missing
    # one plainly — a 12-frame ModuleNotFoundError traceback tells the reader
    # nothing they can act on.
    try:
        from app.layer3 import builders as b
        from app.layer3.helpers.ids import reset
        from app.layer3.writer import write
    except ModuleNotFoundError as exc:
        print(
            f"\nERROR: Layer 3 needs {exc.name!r}, which is not installed."
            f"\n       pip install {exc.name}"
            f"\n       (Layer 3 imports pydantic and ujson at module scope, so"
            f"\n        every builder needs both present — even --only one.)",
            file=sys.stderr,
        )
        return 2

    # Record IDs are per-job counters. Reset once so a rebuilt file numbers its
    # records from 001, matching what a full run would produce.
    reset(args.job)

    print("\nbuilding:")
    built: dict[str, object] = {}
    written = failed = 0
    for name in order:
        t = time.time()
        try:
            built[name] = build_one(name, b, args.job, src, built)
        except Missing as exc:
            print(f"  SKIP  {name}: {exc}")
            failed += 1
            continue
        except Exception as exc:
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
            failed += 1
            continue

        n_rec = len(getattr(built[name], "records", []) or [])
        dur = time.time() - t
        should_write = name in requested or args.write_deps
        if should_write:
            path = write(built[name], out_dir, FILENAME.get(name, f"{name}.json"))
            if path:
                written += 1
                print(f"  WROTE {name:22} {n_rec:6,} records  {dur:5.1f}s  -> {path.name}")
            else:
                failed += 1
                print(f"  FAIL  {name}: writer returned None (see log)")
        else:
            print(f"  built {name:22} {n_rec:6,} records  {dur:5.1f}s  (dep only)")

    print(f"\n{written} written, {failed} failed/skipped, "
          f"{len(order)} built into {out_dir}\n")
    return 0 if not failed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Missing as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
