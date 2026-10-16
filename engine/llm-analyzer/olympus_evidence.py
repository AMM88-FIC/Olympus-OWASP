#!/usr/bin/env python3
"""
olympus_evidence.py — build this engine's evidence tree from an Olympus target.

Olympus already decodes every target with apktool into `targets/<name>/rsc_base/`,
which is the layout `app/layer2/apktool_runner.ApktoolResult` expects: an
`AndroidManifest.xml` at the root and one or more `smali*/` directories beside
it. So the apktool half costs nothing — it is linked, not rebuilt. That alone
satisfies ten of `build_evidence.py`'s builders: six apktool-backed
(`manifest_findings`, `permissions`, `native_binaries`, `components`,
`network_security`, `assets_inventory`) and four derived from them.

The other two groups are not free:

  jadx        Seven builders have no other input — `api_usages`, `crypto_usage`,
              `network_usage`, `outgoing_intents`, `storage_usage`,
              `webview_usage`, `native_methods`. Olympus never runs jadx; its
              readiness panel lists it as optional, "Java sources for the
              conformance differential, not for an assessment". So this is the
              step that actually costs time, not androguard.

  androguard  Five builders run androguard in-process (`strings`,
              `third_party_sdks`, `call_graph`, `obfuscation`, `app_metadata`),
              plus `detected_libraries` via LibScout. Olympus runs its own
              androguard, but an `AnalyzeAPK` object does not serialise, and
              Olympus pins androguard==4.1.3 *because* it sits in its evidence
              path. Sharing a process would put our resolver in a position to
              change Olympus's verdicts. So these stay in our process, on our
              pins, and are made cheap by caching instead of sharing.

Everything is keyed on the sha256 of `rsc_base/base.apk` — the same identity
Olympus prints as `context matches base.apk (<hash>)` — so a second run over an
unchanged target does nothing.

Usage
-----
    python3 olympus_evidence.py \
        --olympus-target ~/.local/share/olympus-owasp/usr/share/olympus-owasp/targets/file_manager

    # explicit job name and a forced rebuild
    python3 olympus_evidence.py --olympus-target <dir> --job xiaomi-explorer --force

    # see what it would do
    python3 olympus_evidence.py --olympus-target <dir> --dry-run

Prints the job root on stdout when it finishes, so it can feed straight into
`olympus_bridge.py --apk-root "$(olympus_evidence.py ... )"`. Logs go to stderr.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


# `build_evidence.py --job <name>` resolves the job under this root. If a
# deployment moves it, pass --artifacts-root rather than editing here.
DEFAULT_ARTIFACTS_ROOT = REPO / "storage" / "artifacts"

STAMP = ".olympus_evidence.json"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def die(msg: str) -> "NoReturn":                            # noqa: F821
    raise SystemExit("error: " + msg)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_base_apk(target: Path) -> Path:
    """Olympus keeps the raw artefact beside its decode, as rsc_base/base.apk."""
    candidate = target / "rsc_base" / "base.apk"
    if candidate.is_file():
        return candidate
    loose = sorted((target / "rsc_base").glob("*.apk")) or sorted(target.glob("*.apk"))
    if loose:
        log("note: no rsc_base/base.apk; using %s" % loose[0].name)
        return loose[0]
    die("no APK under %s — was the target prepared? (prepare writes rsc_base/base.apk)"
        % target)


def check_decode(rsc_base: Path) -> None:
    """Refuse a decode that has no sources.

    A target decoded by an apktool too old for the APK's DEX writes resources
    and no `smali*/` at all, silently. Every smali- and jadx-backed builder
    would then produce an empty file, and an empty evidence file reads as
    'nothing found' rather than 'could not look'. Fail here instead.
    """
    if not (rsc_base / "AndroidManifest.xml").is_file():
        die("%s has no AndroidManifest.xml — the Olympus decode is incomplete"
            % rsc_base)
    if not any(p.is_dir() for p in rsc_base.glob("smali*")):
        die("%s has no smali*/ directories — the decode produced resources but no "
            "sources. Re-prepare the target with a current apktool before building "
            "evidence, or every code-backed evidence file will be silently empty."
            % rsc_base)


def link_or_copy(src: Path, dst: Path, *, copy: bool) -> str:
    if dst.exists() or dst.is_symlink():
        if dst.is_symlink() and Path(os.readlink(dst)) == src:
            return "already linked"
        return "already present"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not copy:
        try:
            dst.symlink_to(src, target_is_directory=True)
            return "linked"
        except (OSError, NotImplementedError) as exc:
            log("note: symlink failed (%s); copying instead" % exc)
    shutil.copytree(src, dst)
    return "copied"


def run_jadx(apk: Path, out: Path, extra: list[str], dry: bool) -> None:
    if (out / "sources").is_dir() and any((out / "sources").rglob("*.java")):
        log("  jadx      already decompiled at %s" % out)
        return
    jadx = shutil.which("jadx")
    if not jadx:
        die("jadx is not on PATH. Olympus's readiness panel reports it as optional, "
            "but seven evidence builders have no other input.")
    cmd = [jadx, "-d", str(out), "--no-debug-info"] + extra + [str(apk)]
    log("  jadx      %s" % " ".join(cmd))
    if dry:
        return
    started = time.monotonic()
    # jadx exits non-zero on partial decompilation, which is common and still
    # useful — judge the result by whether sources landed, not by the code.
    proc = subprocess.run(cmd, capture_output=True, text=True)
    produced = len(list((out / "sources").rglob("*.java"))) if (out / "sources").is_dir() else 0
    log("  jadx      %d .java files in %.0fs (exit %d)"
        % (produced, time.monotonic() - started, proc.returncode))
    if not produced:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        die("jadx produced no sources:\n  " + "\n  ".join(tail))


def run_build_evidence(job: str, artifacts_root: Path, apk: Path | None,
                       only: list[str], dry: bool) -> None:
    # build_evidence.py resolves the job as <--artifacts>/<--job>, defaulting
    # --artifacts to REPO/storage/artifacts. Pass it explicitly so the job may
    # live off the repo — on a VirtualBox share, jadx output and evidence
    # belong on a local filesystem even when the code does not. `--only` is a
    # single comma-separated string there, not a list.
    cmd = [sys.executable, str(REPO / "build_evidence.py"),
           "--job", job, "--artifacts", str(artifacts_root)]
    if apk is not None:
        cmd += ["--apk", str(apk)]
    cmd += (["--only", ",".join(only)] if only else ["--all"])
    log("  evidence  %s" % " ".join(cmd))
    if dry:
        return
    env = dict(os.environ, PYTHONPATH=str(REPO))
    proc = subprocess.run(cmd, cwd=str(REPO), env=env)
    if proc.returncode != 0:
        die("build_evidence.py exited %d — see its output above" % proc.returncode)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="olympus_evidence.py",
        description="Build this engine's evidence tree from an Olympus target.",
    )
    p.add_argument("--olympus-target", required=True,
                   help="an Olympus targets/<name> directory")
    p.add_argument("--job", default="",
                   help="evidence job name (default: the target's directory name)")
    p.add_argument("--artifacts-root", default=str(DEFAULT_ARTIFACTS_ROOT))
    p.add_argument("--only", nargs="*", default=[],
                   help="build only these evidence files (default: --all)")
    p.add_argument("--copy-apktool", action="store_true",
                   help="copy Olympus's rsc_base instead of symlinking it")
    p.add_argument("--jadx-arg", action="append", default=[],
                   help="extra jadx flag, repeatable (e.g. --jadx-arg --no-res)")
    p.add_argument("--force", action="store_true",
                   help="rebuild even if the stamp says this APK is done")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    target = Path(args.olympus_target).expanduser().resolve()
    if not target.is_dir():
        die("no such Olympus target: %s" % target)

    rsc_base = target / "rsc_base"
    if not rsc_base.is_dir():
        die("%s has no rsc_base/ — Olympus has not prepared this target" % target)
    check_decode(rsc_base)

    apk = find_base_apk(target)
    job = args.job or target.name
    job_root = Path(args.artifacts_root).expanduser().resolve() / job
    stamp = job_root / STAMP

    log("target      %s" % target)
    log("job         %s -> %s" % (job, job_root))

    digest = sha256(apk)
    log("base.apk    %s (%s…)" % (apk.name, digest[:16]))

    if stamp.is_file() and not args.force:
        try:
            prior = json.loads(stamp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prior = {}
        if prior.get("apk_sha256") == digest:
            log("up to date  evidence already built for this APK (--force to rebuild)")
            print(job_root)
            return 0

    if args.dry_run:
        log("  apktool   would link %s -> %s/apktool" % (rsc_base, job_root))
    else:
        job_root.mkdir(parents=True, exist_ok=True)
        log("  apktool   %s" % link_or_copy(rsc_base, job_root / "apktool",
                                            copy=args.copy_apktool))
    run_jadx(apk, job_root / "jadx", args.jadx_arg, args.dry_run)

    # Some builders want the APK itself (app_metadata needs 'apk'); keep a copy
    # beside the artifacts rather than reaching back into Olympus's tree, which
    # the AppImage re-extracts.
    local_apk = job_root / "base.apk"
    if not local_apk.exists() and not args.dry_run:
        shutil.copy2(apk, local_apk)
        log("  apk       copied base.apk into the job")
    if local_apk.exists() and not args.dry_run:
        # Verify, because the failure is silent downstream: an APK the
        # extractors cannot read produces app_metadata with package_name
        # "unknown", apk_size_bytes 0 and the sha256 of the empty string —
        # written as facts, not as an error. Ownership classification reads
        # that package name, so first-party code starts looking third-party.
        copied = sha256(local_apk)
        if copied != digest:
            die("the APK in the job does not match the source:\n"
                "  source %s  %s\n  job    %s  %s\n"
                "Delete the job copy and re-run; check free space with `df -h`."
                % (apk, digest[:16], local_apk, copied[:16]))
        log("  apk       verified %s (%d bytes)" % (digest[:16], local_apk.stat().st_size))

    run_build_evidence(job, Path(args.artifacts_root).expanduser().resolve(),
                       local_apk if local_apk.exists() else apk,
                       args.only, args.dry_run)

    if not args.dry_run:
        evidence_dir = job_root / "evidence"
        built = sorted(p.name for p in evidence_dir.glob("*.json")) if evidence_dir.is_dir() else []
        log("  evidence  %d file(s) in %s" % (len(built), evidence_dir))
        if not built:
            die("no evidence files were produced — refusing to stamp this job as done")
        stamp.write_text(json.dumps({
            "apk_sha256": digest,
            "olympus_target": str(target),
            "built": built,
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }, indent=2), encoding="utf-8")

    print(job_root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
