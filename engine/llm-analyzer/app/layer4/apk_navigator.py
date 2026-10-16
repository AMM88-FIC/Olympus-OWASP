"""
apk_navigator.py — Tool surface over an extracted decompiled APK.

Builds a lightweight structural index of jadx Java sources and apktool smali,
then exposes typed methods that map 1:1 onto LLM tool calls:

    list_dir(prefix)
    read_file(path, line_start?, line_end?)
    find_class(name)                  # FQN or simple name
    find_subclasses(fqn, transitive?)
    list_imports(path)
    grep(pattern, path_prefix?, file_glob?)

The index is built once per APK, persisted to disk, and reused across all
MASTG verdicts for that APK. Java is parsed by regex (good enough for class
declarations, imports, and inheritance — not for statement-level analysis;
use grep for that).

Layout assumed:
    <root>/
      jadx/sources/<pkg_path>/<Class>.java
      jadx/resources/...
      apktool/smali/<pkg_path>/<Class>.smali
      apktool/smali_classes2/...     (multi-dex)
      apktool/AndroidManifest.xml
      apktool/res/...
"""

from __future__ import annotations

import fnmatch

import ujson as json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
import shutil
import subprocess


# ============================================================
#  Result types  (all serialize cleanly to JSON for tool replies)
# ============================================================

@dataclass
class ClassRef:
    fqn: str
    path: str
    is_smali: bool = False


@dataclass
class GrepMatch:
    path: str
    line: int
    snippet: str


@dataclass
class ReadResult:
    path: str
    line_start: int
    line_end: int
    total_lines: int
    truncated: bool
    content: str


def _to_jsonable(obj):
    """Recursively convert dataclasses / lists to plain JSON-able structures."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


def _find_records_list(data: dict) -> list | None:
    """Best-effort: return the first list-of-dicts-with-'id' in a JSON dict.

    Used to locate the records array in evidence files when the wrapping key
    is unknown. Returns None if no such list is found at the top level.
    """
    if not isinstance(data, dict):
        return None
    for value in data.values():
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], dict)
            and "id" in value[0]
        ):
            return value
    return None


# ============================================================
#  Parsing primitives
# ============================================================

JAVA_PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.MULTILINE)
JAVA_IMPORT_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.*$]+)\s*;", re.MULTILINE)

# Best-effort match of class/interface/enum/record declarations.
# Captures: simple name, optional extends target, optional implements list.
JAVA_DECL_RE = re.compile(
    r"\b(?:public|private|protected)?\s*"
    r"(?:static|final|abstract|sealed|non-sealed)*\s*"
    r"(?:class|interface|enum|record)\s+"
    r"(\w+)"                                        # 1: simple name
    r"(?:\s*<[^{]*?>)?"                             # generics (skipped)
    r"(?:\s+extends\s+([\w.$]+(?:\s*<[^{]*?>)?))?"  # 2: superclass
    r"(?:\s+implements\s+([^{]+?))?"                # 3: implements list
    r"\s*\{",
    re.DOTALL,
)

SMALI_CLASS_RE = re.compile(r"^\.class\s+[\w\s]*?(L[^;]+;)", re.MULTILINE)
SMALI_SUPER_RE = re.compile(r"^\.super\s+(L[^;]+;)", re.MULTILINE)
SMALI_IMPL_RE = re.compile(r"^\.implements\s+(L[^;]+;)", re.MULTILINE)


def _smali_to_fqn(smali_type: str) -> str:
    """Convert 'Lcom/foo/Bar;' to 'com.foo.Bar', or 'Lcom/foo/Bar$Inner;' similarly."""
    return smali_type.lstrip("L").rstrip(";").replace("/", ".")


def _strip_java_comments_and_strings(src: str) -> str:
    """Remove block/line comments and string literals to reduce regex false matches."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r'"(?:\\.|[^"\\])*"', '""', src)
    return src


# ============================================================
#  Index
# ============================================================

class APKIndex:
    """Structural index of an extracted APK directory."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.classes: dict[str, ClassRef] = {}
        self.simple_to_fqns: dict[str, list[str]] = {}
        self.parents: dict[str, list[str]] = {}   # fqn -> [supertype fqns]
        self.children: dict[str, list[str]] = {}  # supertype fqn -> [subtype fqns]
        self.imports: dict[str, list[str]] = {}   # rel java path -> [imported fqns]

    # ---------- build ----------

    def build(self) -> "APKIndex":
        jadx_sources = self.root / "jadx" / "sources"
        if jadx_sources.is_dir():
            self._index_java(jadx_sources)

        apktool = self.root / "apktool"
        if apktool.is_dir():
            for child in sorted(apktool.iterdir()):
                if child.is_dir() and child.name.startswith("smali"):
                    self._index_smali(child)

        # Invert parents into children
        for fqn, parents in self.parents.items():
            for p in parents:
                self.children.setdefault(p, []).append(fqn)
        return self

    def _record(self, fqn: str, rel_path: str, is_smali: bool, parents: list[str]):
        existing = self.classes.get(fqn)
        # Prefer Java entry over smali if both exist (jadx is L2, smali is L3)
        if existing and not existing.is_smali and is_smali:
            return
        self.classes[fqn] = ClassRef(fqn=fqn, path=rel_path, is_smali=is_smali)
        simple = fqn.rsplit(".", 1)[-1]
        self.simple_to_fqns.setdefault(simple, [])
        if fqn not in self.simple_to_fqns[simple]:
            self.simple_to_fqns[simple].append(fqn)
        if parents:
            self.parents.setdefault(fqn, []).extend(p for p in parents if p)

    def _index_java(self, sources_root: Path):
        # Parsing is I/O-bound (read each .java file from disk, run regexes
        # over its text). Threads work well here despite the GIL because
        # most time is in os.read syscalls. Single-threaded fallback if the
        # tree is small.
        java_files = list(sources_root.rglob("*.java"))
        if not java_files:
            return

        # Per-file parser returns a small dict of facts; we merge serially
        # into the index (thread-safe because mutation only happens here).
        def _parse_one(java_file: Path) -> dict | None:
            try:
                src = java_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return None
            cleaned = _strip_java_comments_and_strings(src)
            pkg_m = JAVA_PACKAGE_RE.search(cleaned)
            pkg = pkg_m.group(1) if pkg_m else ""
            rel_path = str(java_file.relative_to(self.root))
            imports = JAVA_IMPORT_RE.findall(cleaned)
            decls = []
            for m in JAVA_DECL_RE.finditer(cleaned):
                name, ext, impl = m.group(1), m.group(2), m.group(3)
                fqn = f"{pkg}.{name}" if pkg else name
                parents: list[str] = []
                if ext:
                    parents.append(self._resolve(ext, pkg, imports))
                if impl:
                    for piece in impl.split(","):
                        piece = piece.strip().split("<")[0].strip()
                        if piece:
                            parents.append(self._resolve(piece, pkg, imports))
                decls.append((fqn, parents))
            return {
                "rel_path": rel_path,
                "imports": imports,
                "decls": decls,
            }

        # Use threads for I/O-bound parsing. 8 workers is a reasonable
        # default that helps on most boxes without pegging anyone's machine.
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(_parse_one, java_files):
                if result is None:
                    continue
                if result["imports"]:
                    self.imports[result["rel_path"]] = result["imports"]
                for fqn, parents in result["decls"]:
                    self._record(fqn, result["rel_path"],
                                 is_smali=False, parents=parents)

    def _resolve(self, type_name: str, pkg: str, imports: list[str]) -> str:
        type_name = type_name.split("<")[0].strip()
        if "." in type_name:
            return type_name
        for imp in imports:
            if imp.endswith("." + type_name):
                return imp
        return f"{pkg}.{type_name}" if pkg else type_name

    def _index_smali(self, smali_root: Path):
        smali_files = list(smali_root.rglob("*.smali"))
        if not smali_files:
            return

        def _parse_one(smali_file: Path) -> tuple[str, str, list[str]] | None:
            try:
                src = smali_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                return None
            cls_m = SMALI_CLASS_RE.search(src)
            if not cls_m:
                return None
            fqn = _smali_to_fqn(cls_m.group(1))
            parents = []
            super_m = SMALI_SUPER_RE.search(src)
            if super_m:
                parents.append(_smali_to_fqn(super_m.group(1)))
            for impl in SMALI_IMPL_RE.findall(src):
                parents.append(_smali_to_fqn(impl))
            rel_path = str(smali_file.relative_to(self.root))
            return fqn, rel_path, parents

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(_parse_one, smali_files):
                if result is None:
                    continue
                fqn, rel_path, parents = result
                self._record(fqn, rel_path, is_smali=True, parents=parents)

    # ---------- persistence ----------

    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps({
            "root": str(self.root),
            "fingerprint": self._fingerprint(),
            "classes": {k: asdict(v) for k, v in self.classes.items()},
            "simple_to_fqns": self.simple_to_fqns,
            "parents": self.parents,
            "children": self.children,
            "imports": self.imports,
        }))

    @classmethod
    def load(cls, path: Path) -> "APKIndex":
        d =json.loads(Path(path).read_text())
        idx = cls(Path(d["root"]))
        idx.classes = {k: ClassRef(**v) for k, v in d["classes"].items()}
        idx.simple_to_fqns = d["simple_to_fqns"]
        idx.parents = d["parents"]
        idx.children = d["children"]
        idx.imports = d["imports"]
        return idx

    def _fingerprint(self) -> dict:
        """Cheap signature of the source tree. Used to invalidate cached
        indexes when files change. Counts files and captures max mtime per
        relevant directory — O(n) directory walk, no parsing."""
        fp: dict = {}
        jadx = self.root / "jadx" / "sources"
        if jadx.is_dir():
            count = 0
            mtime = 0.0
            for f in jadx.rglob("*.java"):
                try:
                    mtime = max(mtime, f.stat().st_mtime)
                    count += 1
                except OSError:
                    pass
            fp["jadx"] = {"count": count, "mtime": mtime}
        apktool = self.root / "apktool"
        if apktool.is_dir():
            count = 0
            mtime = 0.0
            for child in apktool.iterdir():
                if child.is_dir() and child.name.startswith("smali"):
                    for f in child.rglob("*.smali"):
                        try:
                            mtime = max(mtime, f.stat().st_mtime)
                            count += 1
                        except OSError:
                            pass
            fp["smali"] = {"count": count, "mtime": mtime}
        return fp

    @classmethod
    def build_or_load_cached(
        cls, root: Path, *, log_fn=None,
    ) -> "APKIndex":
        """Construct an APKIndex, loading from a persisted cache when the
        source-tree fingerprint matches. Cache lives at <root>/.apk_index_cache.json."""
        log = log_fn or (lambda *a, **k: None)
        root = Path(root).resolve()
        cache_path = root / ".apk_index_cache.json"

        if cache_path.is_file():
            try:
                cached = cls.load(cache_path)
                # Compute current fingerprint (cheap) and compare to the
                # stored one. We re-set root because the cached value may
                # carry an absolute path from a different machine.
                cached.root = root
                current_fp = cached._fingerprint()
                stored_fp =json.loads(cache_path.read_text()).get("fingerprint")
                if stored_fp == current_fp:
                    log(
                        f"  Index: loaded from cache "
                        f"({len(cached.classes):,} classes, "
                        f"{cache_path.name})",
                        color="green",
                    )
                    return cached
                else:
                    log(
                        "  Index cache stale (file count or mtime changed); "
                        "rebuilding...",
                        color="dim",
                    )
            except Exception as e:
                log(
                    f"  Index cache unreadable ({type(e).__name__}: {e}); "
                    f"rebuilding...",
                    color="dim",
                )

        # Cache miss or stale — build from scratch and persist
        idx = cls(root).build()
        try:
            idx.save(cache_path)
            log(
                f"  Index: cached to {cache_path.name} for next run",
                color="dim",
            )
        except Exception as e:
            log(
                f"  Index built but cache write failed ({type(e).__name__}: {e})",
                color="yellow",
            )
        return idx

    def stats(self) -> dict:
        return {
            "classes": len(self.classes),
            "java_classes": sum(1 for c in self.classes.values() if not c.is_smali),
            "smali_classes": sum(1 for c in self.classes.values() if c.is_smali),
            "indexed_files_with_imports": len(self.imports),
        }


# ============================================================
#  Evidence index (lazy per-file loading)
# ============================================================

def _get_nested(obj, dotted_path: str):
    """Walk a dotted-path ('source.path', 'storage_target.mode') against
    a record. Returns the value at the path, or _MISSING if any segment
    is absent or the intermediate value is not a dict.

    The returned _MISSING sentinel lets callers distinguish 'present but
    None' from 'not present' — important for filter semantics where
    {"key": None} should match null fields but not missing fields."""
    cur = obj
    for segment in dotted_path.split("."):
        if not isinstance(cur, dict) or segment not in cur:
            return _MISSING
        cur = cur[segment]
    return cur


_MISSING = object()


class EvidenceIndex:
    """Lazy in-memory index of L1 evidence files. Each file is loaded on
    first access (parsed once, retained for subsequent queries). Records
    are keyed by (filename, id).

    Records are NOT delivered to the model as bulk content — instead, the
    navigator's evidence tools provide targeted access:
      get_evidence_record(file, id) → full record
      match_evidence_records(file, filters) → records whose fields match regex patterns
      count_evidence_records(file, group_by) → counts

    The schema document the model receives at bootstrap describes what
    fields each evidence file has; the model uses that knowledge plus
    these tools to retrieve only what it needs."""

    def __init__(self, evidence_dir: Path | None):
        self.evidence_dir = (
            Path(evidence_dir).resolve() if evidence_dir else None
        )
        # filename -> {id -> record}
        self._records: dict[str, dict[str, dict]] = {}
        # filename -> True if loaded (even if empty)
        self._loaded: set[str] = set()
        # filename -> the records list (preserves insertion order)
        self._record_lists: dict[str, list[dict]] = {}

    def _load(self, filename: str) -> bool:
        """Read + parse + index one evidence file. Returns True on success,
        False if the file doesn't exist or is unparseable. Idempotent:
        once a file is loaded, repeat calls return immediately."""
        if filename in self._loaded:
            return filename in self._records
        self._loaded.add(filename)
        if self.evidence_dir is None:
            return False
        path = self.evidence_dir / filename
        if not path.is_file():
            return False
        try:
            data =json.loads(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except json.JSONDecodeError:
            return False
        records = (
            data.get("records")
            or data.get("strings")
            or data.get("string_records")
            or _find_records_list(data)
            or []
        )
        if not isinstance(records, list):
            return False
        by_id: dict[str, dict] = {}
        for rec in records:
            if not isinstance(rec, dict):
                continue
            rid = rec.get("id")
            if not rid:
                continue
            by_id[rid] = rec
        self._records[filename] = by_id
        self._record_lists[filename] = [
            r for r in records if isinstance(r, dict) and r.get("id")
        ]
        return True

    def list_files(self) -> list[str]:
        """Return all evidence filenames present in the directory (whether
        or not they've been loaded yet). Cheap directory scan."""
        if self.evidence_dir is None or not self.evidence_dir.is_dir():
            return []
        return sorted(
            f.name for f in self.evidence_dir.iterdir()
            if f.is_file() and f.suffix == ".json"
            and not f.name.startswith("_")
        )

    def get_record(self, filename: str, record_id: str) -> dict:
        """Return one record by ID. Raises KeyError on miss with a clear
        message about whether the file or the id was the problem."""
        if not self._load(filename):
            raise KeyError(
                f"Evidence file {filename!r} could not be loaded "
                f"(missing or malformed)."
            )
        rec = self._records[filename].get(record_id)
        if rec is None:
            raise KeyError(
                f"No record with id={record_id!r} in {filename}. "
                f"Check the schema for which IDs that file contains."
            )
        return rec

    def match_records(
        self,
        filename: str,
        filters: dict | None = None,
        limit: int = 50,
        case_insensitive: bool = False,
    ) -> dict:
        """Return records in `filename` whose every field in `filters`
        matches its regex pattern. Filter values are Python regex patterns
        applied via re.search — they match if the pattern is found anywhere
        in the field's value.

        Filter keys may use dotted-path syntax to address nested fields
        (e.g. 'source.path', 'storage_target.mode'). Filter values must be
        strings; non-string field values in the records are coerced to
        their JSON representation before matching (so a bool field with
        value True matches the pattern 'true').

        For exact-match semantics, use anchored patterns: '^foo$'.
        For substring matching, use bare strings: 'foo'.

        Returns:
            {
              "matched": [record, ...],   # capped at limit
              "match_count": int,         # total matches before capping
              "truncated": bool,          # True if match_count > len(matched)
              "limit": int,
            }

        Returns {"error": str} on invalid regex (the model can self-correct
        without the engine crashing). Empty filters returns every record
        (still capped). Filter keys that no record has yield zero matches —
        not an error, because some optional fields may be absent in this APK."""
        import json as _json
        import re as _re

        if not self._load(filename):
            raise KeyError(
                f"Evidence file {filename!r} could not be loaded "
                f"(missing or malformed)."
            )
        records = self._record_lists[filename]
        filters = filters or {}

        # Compile every pattern up-front; if any is malformed, return an
        # error instead of partially executing. Compiling once is also far
        # faster than re-compiling per record.
        compiled: dict[str, "_re.Pattern"] = {}
        flags = _re.IGNORECASE if case_insensitive else 0
        for key, pattern in filters.items():
            if not isinstance(pattern, str):
                return {
                    "error": (
                        f"filter value for {key!r} must be a string regex "
                        f"pattern, got {type(pattern).__name__}: "
                        f"{pattern!r}"
                    ),
                }
            try:
                compiled[key] = _re.compile(pattern, flags)
            except _re.error as e:
                return {
                    "error": (
                        f"invalid regex for filter {key!r}: {e}. "
                        f"Pattern was {pattern!r}."
                    ),
                }

        def _coerce_for_match(value) -> str:
            """Render a field value as a string for regex matching. Strings
            pass through; bool/int/float/None get their JSON repr."""
            if isinstance(value, str):
                return value
            if value is None:
                return "null"
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, (int, float)):
                return str(value)
            # Lists/dicts: render as compact JSON. Useful for fields like
            # noise_signals (a list) where the model might want to ask
            # "does this field contain 'in_third_party_sdk'?"
            try:
                return _json.dumps(value, ensure_ascii=False)
            except Exception:
                return str(value)

        matched: list[dict] = []
        for rec in records:
            ok = True
            for key, pattern in compiled.items():
                actual = _get_nested(rec, key)
                if actual is _MISSING:
                    ok = False
                    break
                actual_str = _coerce_for_match(actual)
                if pattern.search(actual_str) is None:
                    ok = False
                    break
            if ok:
                matched.append(rec)
        capped = matched[: max(0, int(limit))]
        return {
            "matched": capped,
            "match_count": len(matched),
            "truncated": len(matched) > len(capped),
            "limit": int(limit),
        }

    def field_vocabularies(
        self,
        filename: str,
        max_fields: int = 6,
        max_values_per_field: int = 10,
        max_cardinality: int = 30,
    ) -> dict:
        """Compute a small set of useful field histograms for a file. Used
        by the engine at evidence-delivery time to give the model a peek
        at what values actually appear in each file, so it can target its
        match_records filters without guessing the vocabulary.

        Returns a dict mapping field_path → {value → count, "_more": int}.
        Only fields whose distinct-value count is between 2 and
        max_cardinality are included (skips unique-id fields like 'id' and
        constant fields). Within each field, only the top
        max_values_per_field values by frequency are listed; the rest are
        summarised in "_more"."""
        if not self._load(filename):
            return {}
        records = self._record_lists[filename]
        if not records:
            return {}

        # Discover candidate paths: walk every record, gather every leaf
        # field's path. Limit walking depth to keep noise low — we want
        # categorical fields like 'category', 'domain', 'source.path' etc.
        # not arbitrarily deep arrays.
        def _walk_paths(obj, prefix: str = ""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    p = f"{prefix}.{k}" if prefix else k
                    if isinstance(v, dict):
                        # Recurse into objects one level (matches the
                        # depth that filter keys typically address).
                        for kk, vv in v.items():
                            yield f"{p}.{kk}"
                    else:
                        yield p

        path_counts: dict[str, dict] = {}
        for rec in records:
            for path in _walk_paths(rec):
                value = _get_nested(rec, path)
                if value is _MISSING:
                    continue
                # Skip list/dict-valued fields — they aren't categorical
                if isinstance(value, (list, dict)):
                    continue
                # Coerce to a hashable key
                if isinstance(value, bool):
                    key = "true" if value else "false"
                elif value is None:
                    key = "null"
                elif isinstance(value, (int, float)):
                    key = str(value)
                elif isinstance(value, str):
                    # Skip very long strings (snippets etc.) — not useful
                    # as vocabulary entries
                    if len(value) > 80:
                        continue
                    key = value
                else:
                    continue
                bucket = path_counts.setdefault(path, {})
                bucket[key] = bucket.get(key, 0) + 1

        # Filter to fields with useful cardinality
        useful: list[tuple[str, dict]] = []
        for path, counts in path_counts.items():
            n = len(counts)
            if n < 2 or n > max_cardinality:
                continue
            # Skip fields where one value dominates (>95%) — usually
            # constants like a schema_version on every record
            top = max(counts.values())
            if top >= len(records) * 0.95:
                continue
            useful.append((path, counts))

        # Rank fields by how informative the distribution is. A field with
        # a flatter histogram is more useful than one where 90% of records
        # have the same value. We approximate this with the count of
        # distinct values, then by total records covered.
        useful.sort(key=lambda x: (-len(x[1]), -sum(x[1].values())))
        useful = useful[:max_fields]

        # Format each field's top values
        out: dict[str, dict] = {}
        for path, counts in useful:
            sorted_vals = sorted(counts.items(), key=lambda x: -x[1])
            top = sorted_vals[:max_values_per_field]
            more = sum(c for _, c in sorted_vals[max_values_per_field:])
            field_summary: dict = {k: v for k, v in top}
            if more > 0:
                field_summary["_more"] = more
            out[path] = field_summary

        return out

    def count_records(
        self,
        filename: str,
        group_by: str | None = None,
    ) -> dict:
        """Return record counts for `filename`. Without group_by, returns
        {"total": N}. With group_by (a field name or dotted path), returns
        {"total": N, "groups": {value: count, ...}, "missing": M}.

        Records where the group_by path is absent are counted in 'missing'
        rather than under a synthetic 'null' bucket — this is honest about
        schema drift (the field genuinely isn't there) versus the field
        being explicitly null in the source."""
        if not self._load(filename):
            raise KeyError(
                f"Evidence file {filename!r} could not be loaded "
                f"(missing or malformed)."
            )
        records = self._record_lists[filename]
        out: dict = {"total": len(records)}
        if not group_by:
            return out
        groups: dict[str, int] = {}
        missing = 0
        for rec in records:
            v = _get_nested(rec, group_by)
            if v is _MISSING:
                missing += 1
                continue
            # Hash-friendly key. Lists aren't grouped (rare for evidence
            # fields anyway); we coerce to string in that edge case.
            try:
                key = v if isinstance(v, (str, int, float, bool)) or v is None else str(v)
            except Exception:
                key = str(v)
            # JSON-friendly group keys: None becomes the literal string "null"
            # so the model can read counts without ambiguity over which
            # records had null vs. truthy false.
            if key is None:
                key = "null"
            elif isinstance(key, bool):
                key = "true" if key else "false"
            groups[str(key)] = groups.get(str(key), 0) + 1
        out["groups"] = groups
        out["missing"] = missing
        return out

    def stats(self) -> dict:
        """Cheap summary for startup logging: filenames + record counts.
        Forces a load of every evidence file — only call this when
        eagerness is wanted (e.g. Phase 0 logging)."""
        result: dict[str, int] = {}
        for fname in self.list_files():
            if self._load(fname):
                result[fname] = len(self._records[fname])
        return result


# ============================================================
#  Navigator (the public tool surface)
# ============================================================

class APKNavigator:
    """The methods on this class ARE the tools exposed to the LLM."""

    MAX_FILE_BYTES = 200_000      # cap on a single read_file payload
    MAX_GREP_RESULTS = 200

    # Suffixes grep never searches. Two reasons, and the second one is a bug
    # this list fixes rather than a preference:
    #
    #  1. The .tar snapshots (evidence.tar, jadx.tar, apktool.tar) sit BESIDE
    #     the extracted trees and duplicate their contents. Matching inside
    #     them returns the same finding twice, at an offset no auditor can
    #     follow — `evidence.tar:215677` is not a citable location.
    #  2. The Python fallback opens files with errors="replace", so binaries
    #     match as text and can exhaust MAX_GREP_RESULTS before the walk ever
    #     reaches a source file. ripgrep's own binary detection already skips
    #     them, so WITHOUT this list the two implementations return different
    #     results for the same query depending on whether rg is installed —
    #     and the fallback is the one that silently loses the real matches.
    #
    # `.xml` is deliberately absent: AndroidManifest.xml and res/xml/*.xml are
    # legitimate level-2 evidence.
    GREP_EXCLUDE_SUFFIXES = frozenset({
        ".tar", ".tgz", ".gz", ".zip", ".jar", ".apk", ".aar",
        ".dex", ".so", ".a", ".bin", ".arsc",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
        ".ttf", ".otf", ".woff", ".woff2",
        ".mp3", ".mp4", ".ogg", ".wav", ".webm", ".pdf",
    })
    MAX_MATCH_RECORDS = 100        # cap for match_evidence_records
    MAX_SEARCH_CODE_RESULTS = 20   # cap for search_code top_k

    # ripgrep configuration. None = autodetect (uses shutil.which on
    # first call and caches the result). Set to an absolute path to
    # force a specific binary, or to "" to disable ripgrep entirely
    # and use the Python fallback.
    _RG_PATH: str | None = None
 
    # Per-query timeout in seconds. ripgrep on an indexed codebase is
    # sub-second; 60 is generous and bounds the worst case if a query
    # hits pathological regex.
    _RG_TIMEOUT_SEC = 60

    TOOL_NAMES = (
        "list_dir", "read_file", "find_class",
        "find_subclasses", "list_imports", "grep",
        "list_evidence_files",
        "get_evidence_record",
        "match_evidence_records",
        "count_evidence_records",
        "search_code",
        "find_callers",
        "find_callees",
    )

    def __init__(
        self,
        root: Path,
        index: APKIndex | None = None,
        evidence_dir: Path | None = None,
        rag=None,  # APKCodeRAG | None — kept untyped to avoid hard import
        log_fn=None,
    ):
        self.root = Path(root).resolve()
        # Cache-aware build: skip the expensive walk when source-tree
        # fingerprint matches a previous run's stored index.
        self.index = index or APKIndex.build_or_load_cached(
            self.root, log_fn=log_fn,
        )
        self.rag = rag  # may be None; search_code returns [] when missing
        self.evidence_dir = (
            Path(evidence_dir).resolve() if evidence_dir else None
        )
        # Lazy evidence index — files load on first tool access.
        self.evidence_index = EvidenceIndex(self.evidence_dir)

        # Lazy-loaded call graph data. Loaded on first find_callers call;
        # cached for subsequent calls in the same session. Schema:
        #   {"package_name": "com.duolingo",
        #    "callers": {callee_fqn: [caller_fqn, ...], ...}}
        self._call_graph_data: dict | None = None
        self._call_graph_load_attempted = False

    # ---------- internal ----------

    # Common prefixes to try when a relative path doesn't exist directly under
    # the APK root. Models often emit short-form paths like
    # 'sources/com/foo/Bar.java' (rooted under jadx/) or 'smali/com/foo/Bar.smali'
    # (rooted under apktool/). These prefixes let us silently resolve those.
    _PATH_FALLBACK_PREFIXES: tuple[str, ...] = (
        "jadx",
        "apktool",
        "jadx/sources",
        "jadx/resources",
        "apktool/smali",
    )

    def _mount_roots(self) -> "list[Path]":
        """The root, plus the real target of every symlink directly under it.

        A job tree is not always one filesystem subtree. When this engine runs
        beside Olympus, `<job>/apktool` is a LINK to Olympus's own decode
        (`targets/<name>/rsc_base`) rather than a copy of it — the decode is
        gigabytes and already exists. Those deliberate mounts are the only
        places outside the root a path is allowed to land; a link found deeper
        in the tree is not honoured, because apktool writes whatever the APK
        told it to and a crafted APK is exactly the input this tool handles.
        """
        cached = getattr(self, "_mounts", None)
        if cached is not None:
            return cached
        mounts = [self.root]
        try:
            for child in self.root.iterdir():
                if child.is_symlink() and child.is_dir():
                    mounts.append(child.resolve())
        except OSError:
            pass
        self._mounts = mounts
        return mounts

    def _safe_join(self, rel: str) -> Path | None:
        """Join rel onto root without escaping it. Returns None on escape attempt.

        The containment test is LEXICAL (`normpath`), not `resolve()`. What this
        guard is for is refusing `../../etc/passwd` from a model, and normpath
        collapses `..` without touching the filesystem. `resolve()` also follows
        symlinks, which made every path under a linked `apktool/` read as an
        escape: `grep`, `list_dir` and `read_file` all raised "Path escapes
        root" on smali paths, while the index — built by walking, not by
        joining — held those very files. A verdict then recorded that the smali
        could not be inspected, which is a wrong answer dressed as a limitation.

        The resolved form is still checked, against `_mount_roots`, so a link
        planted inside the decode cannot reach the rest of the disk.
        """
        candidate = Path(os.path.normpath(os.path.join(str(self.root), rel)))
        try:
            candidate.relative_to(self.root)            # lexical: blocks `..`
        except ValueError:
            return None
        try:
            real = candidate.resolve()
        except OSError:                                 # broken link, missing parent
            return candidate
        for mount in self._mount_roots():
            try:
                real.relative_to(mount)
                return candidate
            except ValueError:
                continue
        return None

    def _resolve(self, rel: str, *, must_be: str | None = None) -> Path:
        """Resolve a relative path under root, with prefix fallbacks.

        Args:
            rel: relative path as supplied by the caller.
            must_be: optional 'file' or 'dir' — if set, only candidates of that
                kind count as a successful match. This makes the fallback
                deterministic when both a directory and an unrelated file might
                share the same suffix path under different prefixes.

        Resolution order:
            1. Literal path under root
            2. Each fallback prefix in _PATH_FALLBACK_PREFIXES, prepended

        The first candidate matching the kind constraint wins. If none match,
        returns the literal candidate (which the caller will then fail on with
        a clean is_file()/is_dir() check).
        """
        if not rel:
            return self.root

        rel = rel.lstrip("/")  # tolerate leading slashes

        def _matches_kind(p: Path) -> bool:
            if must_be == "file":
                return p.is_file()
            if must_be == "dir":
                return p.is_dir()
            return p.exists()

        # Try literal first
        literal = self._safe_join(rel)
        if literal is None:
            raise ValueError(f"Path escapes root: {rel}")
        if must_be is None or _matches_kind(literal):
            if literal.exists():
                return literal

        # Try each fallback prefix
        for prefix in self._PATH_FALLBACK_PREFIXES:
            candidate = self._safe_join(f"{prefix}/{rel}")
            if candidate is None:
                continue
            if _matches_kind(candidate):
                return candidate

        # Nothing matched. Return the literal so the caller's existence check
        # produces the natural FileNotFoundError / empty list_dir result.
        return literal

    # ---------- tools ----------

    def list_dir(self, prefix: str = "") -> list[str]:
        """List immediate children of <root>/<prefix>. Directories end with '/'."""
        target = self._resolve(prefix, must_be="dir")
        if not target.is_dir():
            return []
        out = []
        for child in sorted(target.iterdir()):
            tag = "/" if child.is_dir() else ""
            out.append(str(child.relative_to(self.root)) + tag)
        return out

    def read_file(self, path: str, line_start: int | None = None,
                  line_end: int | None = None) -> ReadResult:
        """Read a file or a line range. Always prefer ranges from L1 source pointers."""
        target = self._resolve(path, must_be="file")
        if not target.is_file():
            raise FileNotFoundError(path)
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        s = max(1, line_start) if line_start else 1
        e = min(total, line_end) if line_end else total
        chunk = "\n".join(lines[s - 1:e])
        truncated = False
        if len(chunk) > self.MAX_FILE_BYTES:
            chunk = chunk[: self.MAX_FILE_BYTES]
            truncated = True
        # Always report the actual on-disk path (relative to root) so the model
        # learns the canonical form and the verdict's `reference` field is
        # correct for an auditor.
        canonical = str(target.relative_to(self.root))
        return ReadResult(path=canonical, line_start=s, line_end=e,
                          total_lines=total, truncated=truncated, content=chunk)

    def find_class(self, name: str) -> list[ClassRef]:
        """Resolve an FQN or simple class name to one or more ClassRefs."""
        if name in self.index.classes:
            return [self.index.classes[name]]
        return [self.index.classes[f]
                for f in self.index.simple_to_fqns.get(name, [])
                if f in self.index.classes]

    def find_subclasses(self, fqn: str, transitive: bool = False) -> list[ClassRef]:
        """All known direct (or transitive) subclasses/implementers of an FQN."""
        seen, result, stack = set(), [], list(self.index.children.get(fqn, []))
        while stack:
            child = stack.pop()
            if child in seen:
                continue
            seen.add(child)
            ref = self.index.classes.get(child)
            if ref:
                result.append(ref)
            if transitive:
                stack.extend(self.index.children.get(child, []))
        return result

    def list_imports(self, path: str) -> list[str]:
        """Imports declared at the top of a Java source file."""
        return list(self.index.imports.get(path, []))

    def grep(self, pattern: str, path_prefix: str = "",
             file_glob: str = "*") -> list[GrepMatch]:
        """Regex search across the tree. Result snippets capped at 300
        chars. Uses ripgrep when available (much faster on large APKs),
        falls back to the Python implementation otherwise.
 
        The pattern is treated as a regex compatible with both Python's
        `re` and Rust's `regex` crate. Most common patterns (literal
        strings, character classes, alternation, anchors) work
        identically; some edge-case syntax (backreferences, lookahead)
        is unsupported by ripgrep and will fall back to Python.
        """
        # Validate the pattern up front — fail fast on malformed input
        # the same way the original implementation did.
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}")
 
        
        base = self._resolve(path_prefix, must_be="dir")
        if not base.is_dir():
            return []
 
        # Try ripgrep first; on any failure (binary missing, timeout,
        # unsupported regex feature), fall through to the Python
        # implementation. This is intentional: ripgrep being broken
        # should never cause grep to fail outright.
        rg_result = self._grep_via_ripgrep(pattern, base, file_glob)
        if rg_result is not None:
            return rg_result
 
        return self._grep_via_python(pattern, base, file_glob)
 
    def _grep_via_ripgrep(
        self, pattern: str, base: "Path", file_glob: str,
    ) -> "list[GrepMatch] | None":
        """Try to run the query through ripgrep. Returns None if
        ripgrep is unavailable or fails for any reason; the caller
        falls back to the Python implementation in that case.
        """
        # Resolve the binary path once per session.
        if self._RG_PATH is None:
            type(self)._RG_PATH = shutil.which("rg") or ""
        if not self._RG_PATH:
            return None
 
        cmd = [
            self._RG_PATH,
            "--no-heading",        # one match per line, no file-header lines
            "--line-number",        # prefix each match with its line number
            "--with-filename",      # always include the filename
            "--max-count", str(self.MAX_GREP_RESULTS),  # cap per file
            "--max-filesize", "5M",  # skip pathologically large files
            "--no-config",          # ignore user's ~/.ripgreprc
            "--color", "never",     # plain output
            "--no-messages",        # suppress permission-denied noise
            # Search hidden and gitignored files too. APK extractions
            # often contain dotfiles that matter (e.g. .dex artifacts)
            # and have no .gitignore, but if one slips in we still
            # want full coverage.
            "-uu",
            # Descend into symlinked directories. Without this a search from
            # the job root silently skips a linked tree — `<job>/apktool` is a
            # link to Olympus's decode — and returns Java hits with no smali
            # ones, which reads as "the smali is clean" rather than "the smali
            # was never searched". ripgrep follows a link named directly on the
            # command line either way; this is about the traversal.
            "--follow",
        ]
 
        # Exclude the same archives/binaries the Python fallback skips, so
        # both implementations answer the same query identically. `-uu` above
        # disables ignore files, which would otherwise have let ripgrep search
        # the .tar snapshots too.
        for suffix in sorted(self.GREP_EXCLUDE_SUFFIXES):
            cmd.extend(["--glob", f"!*{suffix}"])

        # Apply the glob filter if the caller specified one.
        # ripgrep's --glob takes shell-style patterns, same as fnmatch,
        # so simple globs like "*.java" or "*.smali" pass through.
        if file_glob and file_glob != "*":
            cmd.extend(["--glob", file_glob])
 
        # Positional args: pattern, then directory.
        cmd.extend([pattern, str(base)])
 
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._RG_TIMEOUT_SEC,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            # Timeout or process failure — fall back to Python so the
            # caller still gets a result.
            return None
 
        # ripgrep exit codes:
        #   0 = matches found
        #   1 = no matches (still success)
        #   2 = error (regex syntax not supported, I/O failure, etc.)
        # On code 2, return None so the Python fallback handles the
        # query (handles unsupported regex constructs gracefully).
        if proc.returncode not in (0, 1):
            return None
 
        matches: list[GrepMatch] = []
        for line in proc.stdout.splitlines():
            # Format: <path>:<line_number>:<snippet>
            # Snippets may contain colons (especially in Java/smali
            # source), so split on the first two colons only.
            parts = line.split(":", 2)
            if len(parts) != 3:
                continue
            path_str, lineno_str, snippet = parts
            try:
                lineno = int(lineno_str)
            except ValueError:
                continue
            # Convert to a path relative to self.root so the response
            # matches what the Python fallback produces.
            try:
                rel_path = str(Path(path_str).relative_to(self.root))
            except ValueError:
                # ripgrep returned a path outside self.root, which
                # shouldn't happen given we pass base. Use absolute.
                rel_path = path_str
 
            matches.append(GrepMatch(
                path=rel_path,
                line=lineno,
                snippet=snippet.rstrip("\n")[:300],
            ))
            if len(matches) >= self.MAX_GREP_RESULTS:
                break
 
        return matches
 
    def _grep_via_python(
        self, pattern: str, base: "Path", file_glob: str,
    ) -> list[GrepMatch]:
        """The original grep implementation, kept as the fallback. Used when
        ripgrep is unavailable or fails.

        The traversal is `os.walk(followlinks=True)` rather than `rglob("*")`,
        for the reason `--follow` is passed to ripgrep: `**` does not descend
        into symlinked directories, so a search from the job root skipped the
        linked `apktool/` tree entirely and said "no matches" about files it
        never opened. `seen` keeps a link cycle from turning that into a hang.
        """
        regex = re.compile(pattern)
        matches: list[GrepMatch] = []
        seen: set[str] = set()

        def _walk():
            for dirpath, dirnames, filenames in os.walk(base, followlinks=True):
                real = os.path.realpath(dirpath)
                if real in seen:
                    dirnames[:] = []                    # a cycle: do not re-enter
                    continue
                seen.add(real)
                for name in filenames:
                    yield Path(dirpath) / name

        for f in _walk():
            if not f.is_file() or not fnmatch.fnmatch(f.name, file_glob):
                continue
            if f.suffix.lower() in self.GREP_EXCLUDE_SUFFIXES:
                continue
            try:
                with f.open(encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if regex.search(line):
                            matches.append(GrepMatch(
                                path=str(f.relative_to(self.root)),
                                line=i,
                                snippet=line.rstrip("\n")[:300],
                            ))
                            if len(matches) >= self.MAX_GREP_RESULTS:
                                return matches
            except Exception:
                continue
        return matches

    # ---------- evidence tools ----------

    def list_evidence_files(self) -> list[dict]:
        """Return the evidence files available for this APK with record
        counts. The schema document received at bootstrap describes what
        fields each file's records contain — use this tool to learn which
        files are present and how big they are, then drill in via
        get_evidence_record / match_evidence_records / count_evidence_records.

        Returns a list of {'name': str, 'records': int} sorted by filename.
        Loads each file once on first access (lazy)."""
        out: list[dict] = []
        for name in self.evidence_index.list_files():
            if self.evidence_index._load(name):
                out.append({
                    "name": name,
                    "records": len(self.evidence_index._record_lists[name]),
                })
            else:
                out.append({"name": name, "records": 0})
        return out

    def get_evidence_record(self, file: str, ids) -> dict:
        """Return one or more records from evidence file `file` by id.

        `file` is the bare filename (e.g. 'api_usages.json'). `ids` is
        either a single id string or a list of id strings.

        Returns:
            {'records': {id: record, ...}, 'missing': [id, ...],
             'error': '...'}   # error only present if file load failed
        """
        if isinstance(ids, str):
            id_list = [ids]
        elif isinstance(ids, list):
            id_list = [str(x) for x in ids]
        else:
            return {
                "records": {}, "missing": [],
                "error": (
                    f"ids parameter must be a string or list of strings, "
                    f"got {type(ids).__name__}"
                ),
            }

        # Probe the file once via the first id so a load failure is
        # distinguishable from id-not-found.
        try:
            self.evidence_index.get_record(file, id_list[0]) if id_list else None
        except KeyError as e:
            if "could not be loaded" in str(e):
                return {"records": {}, "missing": id_list, "error": str(e)}

        records: dict[str, dict] = {}
        missing: list[str] = []
        for rid in id_list:
            try:
                records[rid] = self.evidence_index.get_record(file, rid)
            except KeyError:
                missing.append(rid)
        return {"records": records, "missing": missing}

    def match_evidence_records(
        self,
        file: str,
        filters: dict | None = None,
        limit: int = 50,
        case_insensitive: bool = False,
    ) -> dict:
        """Return records in `file` whose every field matches the regex
        pattern in `filters`. Filter keys may use dotted paths to address
        nested fields (e.g. 'source.path', 'storage_target.mode'). Filter
        values are Python regex patterns applied via re.search — they
        match if the pattern is found anywhere in the field's value.

        For exact-match semantics, use anchored patterns: '^foo$'.
        For substring matching, use bare strings: 'foo'.

        Non-string field values are coerced to their JSON repr before
        matching, so a bool field with value True matches 'true', an int
        with value 42 matches '42', and a list like ['in_third_party_sdk']
        matches '\"in_third_party_sdk\"' (or just 'third_party').

        Examples:
            match_evidence_records('api_usages.json',
                                    {'api_call': 'AuthorizationRequest'},
                                    limit=20)
            match_evidence_records('api_usages.json',
                                    {'domain': '^crypto$'})
            match_evidence_records('components.json',
                                    {'type': 'activity',
                                     'exported.effective': 'true'})
            match_evidence_records('storage_usage.json',
                                    {'category': 'file_external'})
            match_evidence_records('strings.json',
                                    {'value': 'response_type'})

        Returns:
            {
              'matched':     [record, ...],   # capped at limit
              'match_count': int,             # total matches before cap
              'truncated':   bool,            # True if cap was applied
              'limit':       int,
            }
        Or:
            {'error': '...'} when a filter's regex is malformed.

        Empty filters returns every record (still capped)."""
        # Cap limit at the navigator's MAX_MATCH_RECORDS regardless of
        # what the model asks for, to keep tool responses tractable.
        capped_limit = min(int(limit), self.MAX_MATCH_RECORDS)
        return self.evidence_index.match_records(
            file, filters, capped_limit, case_insensitive=case_insensitive,
        )

    def count_evidence_records(
        self, file: str, group_by: str | None = None,
    ) -> dict:
        """Return record counts for `file`. Without group_by, returns the
        total count. With group_by (a field name or dotted path), returns
        a histogram.

        Examples:
            count_evidence_records('api_usages.json')
                → {'total': 2344}
            count_evidence_records('api_usages.json', group_by='domain')
                → {'total': 2344,
                   'groups': {'logging': 996, 'reflection': 736, ...},
                   'missing': 0}
            count_evidence_records('components.json', group_by='type')
                → {'total': 170,
                   'groups': {'activity': 130, 'service': 25, ...},
                   'missing': 0}

        'missing' counts records that didn't have the group_by path at
        all — distinct from records where the field is explicitly null
        (those are bucketed under the literal string 'null')."""
        return self.evidence_index.count_records(file, group_by)

# ---------- call graph ----------

    _CALL_GRAPH_NODE_CAP = 200
    _CALL_GRAPH_MAX_EXAMPLES = 5
    
    _OBFUSCATED_FIRST_SEGMENT_MAX_LEN = 3

    _CALLEES_NODE_CAP = 400
    _JADX_C_PREFIX_RE = re.compile(r'\bC(\d{4,})([A-Za-z_])')

    def _load_call_graph(self) -> dict | None:
        """Load call_graph.json lazily. Returns the parsed dict or None
        if the file is missing or malformed. Cached after first call."""
        if self._call_graph_load_attempted:
            return self._call_graph_data
        self._call_graph_load_attempted = True

        if self.evidence_dir is None:
            return None
        path = self.evidence_dir / "call_graph.json"
        if not path.is_file():
            return None
        try:
            self._call_graph_data = json.loads(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except json.JSONDecodeError:
            return None
        return self._call_graph_data

    def _classify_fqn(self, fqn: str, package_name: str | None) -> str:
        """Classify a method FQN as 'proprietary', 'obfuscated', or
        'named_third_party'.

        Obfuscation heuristic: all namespace segments (excluding the method
        name) are short. So 'aj.b.c.method' is obfuscated but
        'com.sendbird.android.ChatMessage.persist' is not."""
        if package_name and fqn.startswith(package_name + "."):
            return "proprietary"
        parts = fqn.split(".")
        if len(parts) < 2:
            return "named_third_party"
        if all(
            len(seg) <= self._OBFUSCATED_FIRST_SEGMENT_MAX_LEN
            for seg in parts[:-1]
        ):
            return "obfuscated"
        return "named_third_party"

    def _walk_callers(
        self,
        method: str,
        callers_index: dict[str, list[str]],
        package_name: str | None,
        max_depth: int,
        node_budget: int,
    ) -> dict:
        """BFS over the inverted caller graph from `method`."""
        EXPAND_PAST = {"proprietary": False, "named_third_party": True,
                       "obfuscated": True}

        reached = {"proprietary": False, "named_third_party": False}
        examples = {"proprietary": [], "named_third_party": [],
                    "obfuscated_leaf": []}
        stopped_at_depth = False
        nodes_visited = 0

        queue: list[tuple[str, int, list[str]]] = [(method, 0, [method])]
        visited = {method}

        while queue and nodes_visited < node_budget:
            current, depth, path = queue.pop(0)
            if depth >= max_depth:
                stopped_at_depth = True
                continue

            callers = callers_index.get(current, [])
            if not callers and depth > 0:
                if (self._classify_fqn(current, package_name) == "obfuscated"
                        and len(examples["obfuscated_leaf"]) < 2):
                    examples["obfuscated_leaf"].append(path)
                continue

            for caller in callers:
                if caller in visited or nodes_visited >= node_budget:
                    continue
                visited.add(caller)
                nodes_visited += 1
                cls = self._classify_fqn(caller, package_name)
                new_path = path + [caller]

                if cls in reached:
                    reached[cls] = True
                    if len(examples[cls]) < 2:
                        examples[cls].append(new_path)

                if EXPAND_PAST[cls]:
                    queue.append((caller, depth + 1, new_path))

        flat = []
        for dest, paths in examples.items():
            for p in paths:
                flat.append({"destination": dest, "chain": p})
                if len(flat) >= self._CALL_GRAPH_MAX_EXAMPLES:
                    break
            if len(flat) >= self._CALL_GRAPH_MAX_EXAMPLES:
                break

        return {
            "method": method,
            "reachable_from_proprietary": reached["proprietary"],
            "reachable_from_named_third_party": reached["named_third_party"],
            "all_chains_unresolved": not any(reached.values()),
            "stopped_at_depth_limit": stopped_at_depth,
            "example_paths": flat,
            "nodes_visited": nodes_visited,
        }

    def find_callers(self, methods, max_depth: int = 5) -> dict:
        """For each input method, walk the call graph backwards to determine
        whether it is reachable from proprietary code or only from third-party
        code.

        Precedence: reachable_from_proprietary=True → in scope. Else
        reachable_from_named_third_party=True → out of scope. Else
        all_chains_unresolved=True → fall back to v1.3.9 default.
        """
        if isinstance(methods, str):
            method_list = [methods]
        elif isinstance(methods, list):
            method_list = [str(m) for m in methods]
        else:
            return {"results": [], "truncated": False,
                    "total_nodes_visited": 0,
                    "error": f"methods must be str or list, got "
                             f"{type(methods).__name__}"}

        max_depth = max(1, min(10, int(max_depth)))

        cg_data = self._load_call_graph()
        if cg_data is None:
            return {"results": [], "truncated": False,
                    "total_nodes_visited": 0,
                    "error": "call_graph.json missing or unparseable"}

        callers_index = cg_data.get("callers", {})
        package_name = cg_data.get("package_name")

        results = []
        total_visited = 0
        truncated = False

        for method in method_list:
            if total_visited >= self._CALL_GRAPH_NODE_CAP:
                truncated = True
                results.append({
                    "method": method,
                    "reachable_from_proprietary": False,
                    "reachable_from_named_third_party": False,
                    "all_chains_unresolved": False,
                    "stopped_at_depth_limit": False,
                    "example_paths": [],
                    "not_in_graph": False,
                    "skipped_due_to_node_cap": True,
                })
                continue

            if method not in callers_index:
                results.append({
                    "method": method,
                    "reachable_from_proprietary": False,
                    "reachable_from_named_third_party": False,
                    "all_chains_unresolved": True,
                    "stopped_at_depth_limit": False,
                    "example_paths": [],
                    "not_in_graph": True,
                })
                continue

            remaining_budget = (
                self._CALL_GRAPH_NODE_CAP - total_visited
            )
            walk = self._walk_callers(
                method, callers_index, package_name,
                max_depth, remaining_budget,
            )
            total_visited += walk.pop("nodes_visited")
            walk["not_in_graph"] = False
            results.append(walk)

        return {
            "package_name": package_name,
            "results": results,
            "truncated": truncated,
            "total_nodes_visited": total_visited,
        }
    
    def _normalize_for_call_graph(self, fqn: str) -> str:
        """JADX renames bytecode classes whose names collide on case-
        insensitive filesystems by prepending 'C<NNNN>' (e.g. bytecode
        class 'g' becomes JADX class 'C0334g'). The call graph uses
        bytecode names. Strip the JADX prefix from all segments before
        lookup.
 
        Examples:
          'com.android.fileexplorer.h.C0334g.a' -> 'com.android.fileexplorer.h.g.a'
          'com.android.fileexplorer.h.g.a'      -> 'com.android.fileexplorer.h.g.a'
          'com.foo.C0123Bar.method'              -> 'com.foo.Bar.method'
        """
        return self._JADX_C_PREFIX_RE.sub(r'\2', fqn)
 
    def _build_callees_index(self, callers_index: dict) -> dict:
        """Invert callers_index into a callees_index. Called once per
        session, on first find_callees invocation, then cached.
 
        callers_index: {callee_fqn: [caller_fqn, ...]}
        Returns:       {caller_fqn: [callee_fqn, ...]}
 
        On a 69k-entry callers map this completes in well under a second.
        """
        callees: dict[str, list[str]] = {}
        for callee, caller_list in callers_index.items():
            for caller in caller_list:
                callees.setdefault(caller, []).append(callee)
        return callees
 
    def _classify_fqn_with_platform(
        self, fqn: str, package_name: str | None,
    ) -> str:
        """Classification used by find_callees. Identical to
        _classify_fqn for proprietary/obfuscated/named_third_party, but
        adds 'platform' for android.*, java.*, javax.*, dalvik.* — the
        leaf nodes of the call graph where source is not available.
 
        A separate function from _classify_fqn so find_callers' existing
        binary scoping (proprietary vs named_third_party) is not
        altered.
        """
        PLATFORM_PREFIXES = (
            "android.", "java.", "javax.", "dalvik.", "org.json.",
        )
        for p in PLATFORM_PREFIXES:
            if fqn.startswith(p):
                return "platform"
        if package_name and fqn.startswith(package_name + "."):
            return "proprietary"
        parts = fqn.split(".")
        if len(parts) < 2:
            return "named_third_party"
        if all(
            len(seg) <= self._OBFUSCATED_FIRST_SEGMENT_MAX_LEN
            for seg in parts[:-1]
        ):
            return "obfuscated_leaf"
        return "named_third_party"
 
    def _walk_callees(
        self,
        method: str,
        callees_index: dict[str, list[str]],
        package_name: str | None,
        max_depth: int,
        node_budget: int,
    ) -> dict:
        """BFS over the callees graph from `method`. Mirrors
        _walk_callers structure but in the forward direction.
 
        Expansion policy: expand past any non-platform node that has
        further callees in the graph. Platform leaves naturally
        terminate because the call graph extractor does not decompile
        android.*/java.* code.
        """
        reached = {
            "proprietary": False,
            "platform": False,
            "named_third_party": False,
            "obfuscated_leaf": False,
        }
        examples = {k: [] for k in reached}
        by_class = {k: [] for k in reached}
        stopped_at_depth = False
        nodes_visited = 0
 
        direct_callees = list(callees_index.get(method, []))
 
        queue: list[tuple[str, int, list[str]]] = [(method, 0, [method])]
        visited = {method}
 
        while queue and nodes_visited < node_budget:
            current, depth, path = queue.pop(0)
            if depth >= max_depth:
                stopped_at_depth = True
                continue
 
            next_calls = callees_index.get(current, [])
            for callee in next_calls:
                if callee in visited or nodes_visited >= node_budget:
                    continue
                visited.add(callee)
                nodes_visited += 1
                cls = self._classify_fqn_with_platform(callee, package_name)
                new_path = path + [callee]
 
                if cls in by_class and callee not in by_class[cls]:
                    by_class[cls].append(callee)
 
                reached[cls] = True
                if len(examples[cls]) < 2:
                    examples[cls].append(new_path)
 
                # Platform nodes are leaves; no decompiled source means
                # no further callees to discover.
                if cls != "platform":
                    queue.append((callee, depth + 1, new_path))
 
        flat = []
        for dest, paths in examples.items():
            for p in paths:
                flat.append({"destination": dest, "chain": p})
                if len(flat) >= self._CALL_GRAPH_MAX_EXAMPLES:
                    break
            if len(flat) >= self._CALL_GRAPH_MAX_EXAMPLES:
                break
 
        # Cap each class list so the response payload stays reasonable.
        MAX_PER_CLASS = 50
        transitive_by_class = {
            cls: lst[:MAX_PER_CLASS] for cls, lst in by_class.items()
        }
        transitive_truncated = any(
            len(lst) > MAX_PER_CLASS for lst in by_class.values()
        )
 
        return {
            "method": method,
            "direct_callees": direct_callees,
            "reaches_proprietary": reached["proprietary"],
            "reaches_platform": reached["platform"],
            "reaches_named_third_party": reached["named_third_party"],
            "reaches_obfuscated_leaf": reached["obfuscated_leaf"],
            "stopped_at_depth_limit": stopped_at_depth,
            "transitive_callees_by_class": transitive_by_class,
            "transitive_callees_truncated": transitive_truncated,
            "example_paths": flat,
            "nodes_visited": nodes_visited,
        }
 
    def find_callees(self, methods, max_depth: int = 5) -> dict:
        """Walk the call graph FORWARD from a method to find what it
        invokes, directly or transitively. Symmetric to find_callers.
 
        For each input method, returns:
          - direct_callees: immediate (depth-1) callees, always shown
          - reaches_proprietary / reaches_platform /
            reaches_named_third_party / reaches_obfuscated_leaf:
            boolean flags about what the call tree reaches
          - transitive_callees_by_class: deduplicated lists of methods
            reached, classified. Cap of 50 per class;
            transitive_callees_truncated signals when the cap was hit.
          - example_paths: up to 5 chains showing how notable
            destinations are reached
          - stopped_at_depth_limit / not_in_graph: standard flags
 
        JADX-form class names with C<NNNN> collision prefixes are
        normalized to bytecode form before lookup, so the same name the
        LLM sees in source code or api_usages.json works as input.
 
        Use this for IPC workflow tracing: pass the FQN of an exported
        component's entry method (onCreate, onReceive, query, etc.)
        and examine transitive_callees_by_class.platform for sink
        patterns (new File, openFileDescriptor, FileOutputStream, etc.).
        """
        if isinstance(methods, str):
            method_list = [methods]
        elif isinstance(methods, list):
            method_list = [str(m) for m in methods]
        else:
            return {
                "results": [], "truncated": False,
                "total_nodes_visited": 0,
                "error": (f"methods must be str or list, got "
                          f"{type(methods).__name__}"),
            }
 
        max_depth = max(1, min(10, int(max_depth)))
 
        cg_data = self._load_call_graph()
        if cg_data is None:
            return {
                "results": [], "truncated": False,
                "total_nodes_visited": 0,
                "error": "call_graph.json missing or unparseable",
            }
 
        # Lazily build the inverted (callees) index on first use; cache
        # on the instance for the rest of the session.
        if not hasattr(self, "_callees_index_cache"):
            self._callees_index_cache = self._build_callees_index(
                cg_data.get("callers", {})
            )
        callees_index = self._callees_index_cache
        package_name = cg_data.get("package_name")
 
        results = []
        total_visited = 0
        truncated = False
 
        for raw_method in method_list:
            method = self._normalize_for_call_graph(raw_method)
            was_normalized = (method != raw_method)
 
            if total_visited >= self._CALLEES_NODE_CAP:
                truncated = True
                results.append({
                    "method": raw_method,
                    "method_normalized": method if was_normalized else None,
                    "direct_callees": [],
                    "reaches_proprietary": False,
                    "reaches_platform": False,
                    "reaches_named_third_party": False,
                    "reaches_obfuscated_leaf": False,
                    "stopped_at_depth_limit": False,
                    "transitive_callees_by_class": {},
                    "transitive_callees_truncated": False,
                    "example_paths": [],
                    "not_in_graph": False,
                    "skipped_due_to_node_cap": True,
                })
                continue
 
            if method not in callees_index:
                results.append({
                    "method": raw_method,
                    "method_normalized": method if was_normalized else None,
                    "direct_callees": [],
                    "reaches_proprietary": False,
                    "reaches_platform": False,
                    "reaches_named_third_party": False,
                    "reaches_obfuscated_leaf": False,
                    "stopped_at_depth_limit": False,
                    "transitive_callees_by_class": {},
                    "transitive_callees_truncated": False,
                    "example_paths": [],
                    "not_in_graph": True,
                })
                continue
 
            remaining_budget = self._CALLEES_NODE_CAP - total_visited
            walk = self._walk_callees(
                method, callees_index, package_name,
                max_depth, remaining_budget,
            )
            total_visited += walk.pop("nodes_visited")
            walk["not_in_graph"] = False
            if was_normalized:
                walk["method"] = raw_method
                walk["method_normalized"] = method
            results.append(walk)
 
        return {
            "package_name": package_name,
            "results": results,
            "truncated": truncated,
            "total_nodes_visited": total_visited,
        }

    def search_code(
        self,
        query: str,
        top_k: int = 5,
        path_prefix: str | None = None,
        is_smali: bool | None = None,
    ) -> list[dict]:
        """Semantic search over the indexed APK source code.

        Returns chunks ranked by similarity to a natural-language query like
        'plaintext credential storage' or 'SQL execution from user input'.
        Each result contains path, line_start, line_end, class_fqn, method,
        a similarity score, and a snippet — use the path/line metadata to
        issue a precise read_file when you need the full content.

        Args:
            query: natural language description of what to find.
            top_k: number of results to return (1-20, default 5).
            path_prefix: limit results to paths starting with this string,
                e.g. 'jadx/sources/com/example/' to scope to one package.
            is_smali: if True, only smali results; if False, only Java;
                if None (default), both, ranked together.
        """
        if self.rag is None:
            return []
        top_k = max(1, min(self.MAX_SEARCH_CODE_RESULTS, int(top_k)))
        # Lazy import so this module loads without RAG dependencies installed.
        from apk_rag import hit_to_dict
        hits = self.rag.search(
            query,
            top_k=top_k,
            path_prefix=path_prefix,
            is_smali=is_smali,
        )
        return [hit_to_dict(h) for h in hits]

    # ---------- dispatcher (used by the runners) ----------

    def call(self, name: str, args: dict) -> object:
        """Invoke a tool by name with kwargs; returns a JSON-serializable result."""
        if name not in self.TOOL_NAMES:
            raise ValueError(f"Unknown tool: {name}")
        result = getattr(self, name)(**(args or {}))
        return _to_jsonable(result)