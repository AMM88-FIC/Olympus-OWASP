"""
Unit tests for constant-resolved cipher transformations.

Background: `_patterns.CRYPTO_PATTERNS` originally required a string LITERAL
immediately after `getInstance(`. A transformation passed as a named constant
therefore matched nothing and produced NO RECORD — the call site was invisible,
indistinguishable from "this file does no crypto". A real
`DES/ECB/PKCS5Padding` cipher in `com/xiaomi/utils/Commons.java` went
unreported, and MASTG-TEST-0221/0232 both returned the wrong verdict as a
result.

Two properties are asserted here, and the second matters as much as the first:

  1. a same-file `final String` constant IS resolved, so the finding appears
  2. a non-constant argument (a method parameter) is still NOT recorded, so
     library wrappers like Bouncy Castle's `Cipher.getInstance(str)` stay out

Runs without pydantic or the Kali toolchain: `_patterns.py` imports only `re`,
and `_parse_transform`'s resolution logic is exercised through it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "_crypto_patterns", REPO / "app" / "layer3" / "builders" / "_patterns.py")
patterns = importlib.util.module_from_spec(_spec)
sys.modules["_crypto_patterns"] = patterns
_spec.loader.exec_module(patterns)

CIPHER = dict(patterns.CRYPTO_PATTERNS)["cipher_get_instance"]
DIGEST = dict(patterns.CRYPTO_PATTERNS)["message_digest"]

# Mirrors crypto_usage._TRANSFORM_RE.
_TRANSFORM_RE = re.compile(
    r'^(?P<algo>[A-Z0-9]+)(?:/(?P<mode>[A-Z0-9]+)(?:/(?P<padding>[A-Z0-9]+))?)?$'
)
_EXPR_GROUPS = ("transform_expr", "algo_expr", "proto_expr")


def extract(pattern, source: str):
    """Return the records the builder would emit for `source`.

    Mirrors `_scan_file` + `_parse_transform`, including the rule that an
    unresolvable non-literal argument yields NO record.
    """
    constants = patterns.harvest_string_constants(source)
    out = []
    for line in source.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        g = m.groupdict()
        transform = g.get("transform") or g.get("algo") or g.get("proto")
        if not transform:
            expr = next((g[k] for k in _EXPR_GROUPS if g.get(k)), None)
            if expr:
                transform = patterns.resolve_const_arg(expr, constants)
        if not transform:
            # Unresolvable non-literal -> skipped, as the builder does.
            if any(g.get(k) for k in _EXPR_GROUPS):
                continue
            out.append((None, None, None))
            continue
        tm = _TRANSFORM_RE.match(transform.upper())
        out.append((tm.group("algo"), tm.group("mode"), tm.group("padding"))
                   if tm else (transform.upper(), None, None))
    return out


# ---------------------------------------------------------------- resolution

def test_same_file_constant_is_resolved():
    """The bug this fixes: a constant transformation must become a record."""
    src = '''
    public final class Commons {
        public static final String CIPHER_ALGORITHM = "DES/ECB/PKCS5Padding";
        public static byte[] encrypt(byte[] a, byte[] b) throws Exception {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(1, k);
            return cipher.doFinal(b);
        }
    }
    '''
    assert extract(CIPHER, src) == [("DES", "ECB", "PKCS5PADDING")]


def test_qualified_constant_is_resolved():
    src = '''
    class X {
        static final String ALG = "AES/GCM/NoPadding";
        void f() { Cipher.getInstance(X.ALG); }
    }
    '''
    assert extract(CIPHER, src) == [("AES", "GCM", "NOPADDING")]


def test_literal_still_works():
    """Regression: the original behaviour must be untouched."""
    src = 'void f(){ Cipher.getInstance("AES/CBC/PKCS5Padding"); }'
    assert extract(CIPHER, src) == [("AES", "CBC", "PKCS5PADDING")]


def test_message_digest_constant_is_resolved():
    """The same defect affected MessageDigest, KeyGenerator and SSLContext."""
    src = '''
    class H {
        private static final String HASH = "MD5";
        void f() { MessageDigest.getInstance(HASH); }
    }
    '''
    assert extract(DIGEST, src) == [("MD5", None, None)]


# ------------------------------------------------------------- noise control

def test_method_parameter_is_not_recorded():
    """Bouncy Castle's wrappers must stay out.

    `createCipher(String str) { return Cipher.getInstance(str); }` takes the
    transformation from its caller. It is unresolvable here, and recording it
    would add dozens of algorithm-less rows no test case can act on.
    """
    src = '''
    public class DefaultJcaJceHelper {
        public Cipher createCipher(String str) throws Exception {
            return Cipher.getInstance(str);
        }
    }
    '''
    assert extract(CIPHER, src) == []


def test_method_call_argument_is_not_recorded():
    src = 'void f(){ Cipher.getInstance(getAlgorithmName()); }'
    assert extract(CIPHER, src) == []


def test_unknown_identifier_is_not_recorded():
    """An identifier with no matching constant in this file resolves to
    nothing, so no record — a miss, never a guess."""
    src = 'void f(){ Cipher.getInstance(SOME_OTHER_CLASS_CONSTANT); }'
    assert extract(CIPHER, src) == []


def test_constant_declared_after_use_still_resolves():
    """Constants are harvested from the whole file before scanning, so
    declaration order does not matter."""
    src = '''
    class X {
        void f() { Cipher.getInstance(ALG); }
        static final String ALG = "DESede/CBC/PKCS5Padding";
    }
    '''
    assert extract(CIPHER, src) == [("DESEDE", "CBC", "PKCS5PADDING")]


# --------------------------------------------------------------- real sample

def test_real_commons_java_if_present():
    """Against the actual file whose omission caused the wrong verdict."""
    f = (REPO / "storage" / "artifacts" / "xiaomi-explorer" / "jadx"
         / "sources" / "com" / "xiaomi" / "utils" / "Commons.java")
    if not f.is_file():
        return  # artifact tree not present in this checkout
    got = extract(CIPHER, f.read_text(encoding="utf-8", errors="replace"))
    assert ("DES", "ECB", "PKCS5PADDING") in got, got


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {name}: {exc}")
    print(f"\n  {'all passed' if not failed else f'{failed} failed'}")
    sys.exit(1 if failed else 0)
