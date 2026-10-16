"""
Diagnostic for why native_binaries builder produces 0 records when
native_methods produces many.

Run this from the project root, pointing at the same apktool output
directory used by your test_extraction script. It prints what the
filesystem walk finds at each step so we can see exactly where the
mismatch is.
"""

import sys
from pathlib import Path

# Adjust this path to match your project
APKTOOL_DIR = Path("storage/artifacts/test-layer3-chrome/apktool")

if len(sys.argv) > 1:
    APKTOOL_DIR = Path(sys.argv[1])

print(f"Inspecting: {APKTOOL_DIR}")
print(f"Exists:     {APKTOOL_DIR.exists()}")
print()

if not APKTOOL_DIR.exists():
    print("ERROR: directory not found. Pass the apktool output dir as argv[1].")
    sys.exit(1)

# Step 1: what's at the top level
print("=== Top-level entries ===")
for entry in sorted(APKTOOL_DIR.iterdir()):
    marker = "/" if entry.is_dir() else ""
    print(f"  {entry.name}{marker}")
print()

# Step 2: lib/ specifically
lib_dir = APKTOOL_DIR / "lib"
print(f"=== lib/ directory ===")
print(f"  Exists:      {lib_dir.exists()}")
if lib_dir.exists():
    print(f"  Is dir:      {lib_dir.is_dir()}")
    print(f"  Contents:")
    for entry in sorted(lib_dir.iterdir()):
        marker = "/" if entry.is_dir() else ""
        print(f"    {entry.name}{marker}")
print()

# Step 3: walk the whole tree looking for .so files using multiple patterns
print("=== Searching for .so files (any depth) ===")
patterns_to_try = [
    "**/*.so",
    "**/*.so.*",
    "lib/**/*.so",
]

found_anywhere: list[Path] = []
for pattern in patterns_to_try:
    matches = list(APKTOOL_DIR.rglob(pattern))
    print(f"  rglob('{pattern}'): {len(matches)} matches")
    found_anywhere.extend(matches)

print()
print("=== Sample of .so files found ===")
seen = set()
for f in found_anywhere:
    if f in seen:
        continue
    seen.add(f)
    rel = f.relative_to(APKTOOL_DIR)
    size_kb = f.stat().st_size / 1024
    print(f"  {rel} ({size_kb:.1f} KB)")
    if len(seen) >= 15:
        print(f"  ... and {len(set(found_anywhere)) - 15} more")
        break

print()
print("=== Possible alternative locations ===")
# Some apktool output put native libs under different names
for candidate in ("lib", "libs", "jniLibs", "native"):
    p = APKTOOL_DIR / candidate
    if p.exists():
        print(f"  {p.name}/ exists ({sum(1 for _ in p.rglob('*'))} entries)")

# Check what apktool puts in unknown/
unknown_dir = APKTOOL_DIR / "unknown"
if unknown_dir.exists():
    print(f"  unknown/ exists — apktool sometimes places unrecognized files here")
    for so in unknown_dir.rglob("*.so"):
        print(f"    {so.relative_to(APKTOOL_DIR)}")