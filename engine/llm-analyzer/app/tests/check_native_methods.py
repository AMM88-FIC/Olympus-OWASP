"""
Inspect native_methods.json to see what classes the 218 records belong to.
Run from project root with:
  python3 /tmp/check_native_methods.py storage/artifacts/test-layer3-brain-app/evidence/native_methods.json
"""
import ujson
import sys
from collections import Counter

if len(sys.argv) < 2:
    print("Usage: check_native_methods.py <path to native_methods.json>")
    sys.exit(1)

data =ujson.load(open(sys.argv[1]))
records = data.get("records", [])
print(f"Total records: {len(records)}")
print()

# Count by Java class
classes = Counter(r["java_class"] for r in records)
print(f"Distinct classes: {len(classes)}")
print()
print("Top 20 classes by count:")
for cls, n in classes.most_common(20):
    print(f"  {n:4d}  {cls}")

print()

# Count by package prefix (top three components)
def pkg(name):
    parts = name.split(".")
    return ".".join(parts[:3]) if len(parts) >= 3 else name

packages = Counter(pkg(r["java_class"]) for r in records)
print("Top 10 package prefixes:")
for p, n in packages.most_common(10):
    print(f"  {n:4d}  {p}")

print()

# Check found_in_library and symbol_present
with_lib = sum(1 for r in records if r.get("found_in_library"))
sym_present = sum(1 for r in records if r.get("symbol_present"))
print(f"Records with found_in_library set: {with_lib}")
print(f"Records with symbol_present == True: {sym_present}")

# How many have actually meaningful native_methods data
print()
print("Distinct expected_jni_symbols (sample of 10):")
syms = [r.get("expected_jni_symbol") for r in records if r.get("expected_jni_symbol")]
for s in syms[:10]:
    print(f"  {s}")