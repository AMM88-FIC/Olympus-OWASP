import sys
from pathlib import Path
sys.path.insert(0, "/media/sf_KaliShared/Shared-Tools/llm-android-analyzer")

from app.layer2.coordinator import run_extraction_sync
from app.layer3.helpers.ids import reset
from app.layer3 import builders as b
from app.layer3.writer import write, evidence_dir

APK = Path("DivaApplication.apk")
ARTIFACTS = Path("storage/artifacts")
JOB = "test-layer3"

# Layer 2
reset(JOB)
ex = run_extraction_sync(JOB, APK, ARTIFACTS)
out = evidence_dir(ARTIFACTS, JOB)

# Layer 3 — manifest builders
app_meta    = b.app_metadata.build(JOB, ex.androguard, APK)
mf          = b.manifest_findings.build(JOB, ex.apktool)
comps       = b.components.build(JOB, ex.apktool, app_meta.app.target_sdk)
perms       = b.permissions.build(JOB, ex.apktool)
nsc         = b.network_security.build(JOB, ex.apktool, mf)
dl          = b.deep_links.build(JOB, comps)

# Layer 3 — Androguard builders
obf         = b.obfuscation.build(JOB, ex.androguard, ex.apktool)
strs        = b.strings.build(JOB, ex.androguard)
sdks        = b.third_party_sdks.build(JOB, ex.androguard)

# Layer 3 — JADX builders
crypto      = b.crypto_usage.build(JOB, ex.jadx)
net         = b.network_usage.build(JOB, ex.jadx)
stor        = b.storage_usage.build(JOB, ex.jadx)
wv          = b.webview_usage.build(JOB, ex.jadx)
api         = b.api_usages.build(JOB, ex.jadx)
oint        = b.outgoing_intents.build(JOB, ex.jadx)
assets      = b.assets_inventory.build(JOB, ex.apktool, nsc)
jni         = b.native_methods.build(JOB, ex.jadx, ex.apktool)

# Coverage last — needs all others
cov = b.coverage.build(
    JOB, ex.apktool, ex.jadx, ex.androguard,
    obf, comps, perms, dl, api, crypto, wv, net, stor, oint, strs, sdks, assets, jni, mf
)

# Write everything
for filename, evidence in [
    ("app_metadata.json", app_meta),
    ("manifest_findings.json", mf),
    ("components.json", comps),
    ("permissions.json", perms),
    ("network_security.json", nsc),
    ("deep_links.json", dl),
    ("obfuscation.json", obf),
    ("strings.json", strs),
    ("third_party_sdks.json", sdks),
    ("crypto_usage.json", crypto),
    ("network_usage.json", net),
    ("storage_usage.json", stor),
    ("webview_usage.json", wv),
    ("api_usages.json", api),
    ("outgoing_intents.json", oint),
    ("assets_inventory.json", assets),
    ("native_methods.json", jni),
    ("coverage.json", cov),
]:
    write(evidence, out, filename)
    print(f"{filename}: OK")