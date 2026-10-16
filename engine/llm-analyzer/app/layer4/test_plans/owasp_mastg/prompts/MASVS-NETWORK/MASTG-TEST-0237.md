MASTG-TEST-0237

maswe_id       MASWE-0050
masvs_v2_id    MASVS-NETWORK-1
platform       android
title          Cross-Platform Framework Configurations Allowing Cleartext Traffic - framework HTTP bypassing the platform NSC (static)

NOTE - UPSTREAM PLACEHOLDER, BEST-EFFORT STATIC: OWASP ships MASTG-TEST-0237 as a `status: placeholder` (no procedure body). This prompt implements the best-effort static detection the control describes: cross-platform frameworks (Flutter, React Native, Cordova/Capacitor, Xamarin/.NET MAUI, Unity, Qt) bundle their OWN HTTP stacks that may NOT honour the Android manifest/Network Security Configuration, so cleartext can flow even when the native config (MASTG-TEST-0235) looks safe. This test detects framework presence and any framework-level cleartext-permitting configuration or `http://` use.

What this test looks for
If the app embeds a cross-platform framework, its framework-level networking must also forbid cleartext. This is a static evaluation: identify the framework, then check its config/code for cleartext permission or `http://` endpoints that bypass the native NSC. Verdict: `pass` (no cross-platform HTTP stack, or the framework forbids cleartext / uses only https), `fail` (>=1 framework-level config permits cleartext, or a framework `http://` endpoint is used), `n/a` (no cross-platform framework is present - pure native app), or `inconclusive`.

SHORT-CIRCUIT (decide first): detect framework presence (below). If NONE -> `n/a` (pure-native; cleartext is covered by MASTG-TEST-0235; state the search).

Framework indicators & cleartext surfaces
- **Flutter**: `libflutter.so`, `io.flutter.*`; Dart HTTP (`dart:io HttpClient`, `package:http`, `dio`) does NOT consult the Android NSC. Look for `http://` base URLs in Dart-derived strings / assets, or an `HttpClient` with `badCertificateCallback`.
- **React Native**: `libreactnativejni.so`/`index.android.bundle`; RN `fetch`/`XMLHttpRequest` route through OkHttp and DO honour the NSC on modern RN, BUT a custom `OkHttpClientProvider` or `usesCleartextTraffic` matters; scan the JS bundle for `http://` endpoints.
- **Cordova/Capacitor/Ionic**: `config.xml` / `capacitor.config` - `<access origin="...">`, `cleartext` allowances, WebView loading `http://`.
- **Xamarin/.NET MAUI**: `assemblies/*.dll`, `HttpClient` with `ServerCertificateCustomValidationCallback` returning true, or `http://` base addresses.
- **Unity**: `libunity.so`/`il2cpp`; `UnityWebRequest` to `http://`.
- **Qt**: `libQt*`; `QNetworkAccessManager` to `http://`.

EVIDENCE DISCIPLINE (applies to every row and the verdict)
1. **Every verdict-affecting disposition quotes the evidence it rests on.** Quote the framework indicator AND the cleartext config / `http://` endpoint. No quoted evidence -> `unverified`.
2. **Read from the artifact, not the index.** Cite the file path (`assets/...`, `lib/<abi>/...`, a config file, a decompiled source) and line/offset where resolvable, not an index record or line 1.
3. **No finding by inference/hedge.** A finding requires quoting (a) the framework and (b) a cleartext-permitting config or used `http://` endpoint. "Flutter apps sometimes allow cleartext" with no quoted config is NOT evidence -> `unverified`.
4. **Unresolved determinacy is `unverified`, not a hedge.** Framework bundles are often opaque to static analysis (compiled Dart/IL2CPP, minified JS) - if the cleartext behaviour can't be resolved, the row is `unverified` (name the bundle). `false_positive_risks` is out-of-APK only.

Procedure
1. Detect framework: `grep -rEn "io\.flutter|libflutter|reactnativejni|index\.android\.bundle|cordova|capacitor|Xamarin|Mono\.Android|il2cpp|libunity|QNetworkAccessManager" jadx/sources/ jadx/resources/` and inspect `lib/<abi>/` and `assets/` names. If none -> short-circuit `n/a` (state the search).
2. For the detected framework, locate its networking config/endpoints (the framework-specific surfaces above). Read config files; scan readable bundles/assets for `http://` and cleartext-permission flags.
3. Flag a finding when a framework-level config permits cleartext, or a framework `http://` endpoint is used for app traffic that bypasses the native NSC. Quote the config/endpoint. Opaque/compiled bundle that can't be resolved -> `unverified` (recommend dynamic capture).
4. Owner: framework-bundled code is third-party, but the cleartext policy it carries is the APP's responsibility - report it (attribute the stack).
5. Conclude per surface: Finding (framework cleartext config / http endpoint quoted); Compliant (https-only / cleartext forbidden, quoted); Unverified (opaque bundle).
6. Budget ~2-4 reads (framework detection, the config/bundle, any endpoint string). Unresolved within budget -> `unverified` naming the bundle.

Out-of-scope / static limits
Compiled framework bytecode (AOT Dart, IL2CPP, release JS) is frequently unreadable statically -> `unverified` with a dynamic-capture recommendation. The NATIVE manifest/NSC cleartext config is MASTG-TEST-0235; this test covers the framework layer that may bypass it.

Output
List **all** framework networking surfaces examined - one L1 row per surface with its disposition - plus one L1 row naming the detected framework. <=20 -> one L1 row each. >20 (collapse) -> group compliant https endpoints, but always break out every Finding and unverified surface individually. Never sample findings.
- Framework: L1 row quoting the detection indicator.
- Finding: L1 row plus L2 quoting the cleartext config / used `http://` endpoint, plus stack owner.
- Compliant: L1 row plus L2 showing https-only / cleartext forbidden.

```
{
  "id": "xf-001",
  "description": "Finding (Flutter HTTP bypassing NSC): The bundled Flutter app uses an http:// API base URL via Dart's HttpClient, which does not consult the Android Network Security Configuration.",
  "reference": "assets/flutter_assets/",
  "level": 1
},
{
  "id": "L2-xf-fw",
  "description": "Framework (quoted): libflutter.so present under lib/arm64-v8a/ and io.flutter.embedding.* in jadx/sources - Flutter app.",
  "reference": "jadx/sources/io/flutter/embedding/",
  "level": 2
},
{
  "id": "L2-xf-endpoint",
  "description": "Cleartext endpoint (quoted): the readable Dart string \"http://api.example.com\" appears in assets/flutter_assets/.../strings (or kernel_blob) used as the API base - Dart HttpClient ignores the NSC. Owner: app via Flutter stack. Dynamic capture recommended to confirm.",
  "reference": "assets/flutter_assets/kernel_blob.bin",
  "level": 2
}
```

Full output:
```
{
  "test_id": "MASTG-TEST-0237",
  "verdict": "fail" | "pass" | "n/a" | "inconclusive",
  "certainty_percent": <int>,
  "evidence_table": [ ... ],
  "rationale": "Framework: <Flutter/RN/Cordova/Xamarin/Unity/none>. S framework networking surfaces examined, N findings (framework cleartext config / http endpoint), C compliant (https-only), U unverified (opaque bundle). Cross-platform stack present? <no -> n/a / yes>. <one or two sentences>",
  "needs_dynamic_testing": <bool>,
  "false_positive_risks": [ ... factors outside the APK only ... ]
}
```

Rules
- The verdict is fully static and final. `needs_dynamic_testing` MAY be true where the framework bundle is opaque (a traffic capture is the reliable check); it does not change `pass`/`fail`.
- `fail`: >=1 quoted framework-level cleartext config or used `http://` endpoint that bypasses/ignores the native NSC. A finding stated with "likely"/"may" instead of quoted evidence is INVALID -> `unverified`.
- **Framework layer only.** The native manifest/NSC is MASTG-TEST-0235. Here the point is the framework HTTP stack that may NOT honour it.
- **No sampling / ownership default / false_positive hygiene** as in the suite: every Finding broken out individually; framework code attributed but the policy is the app's; `false_positive_risks` out-of-APK only - resolvable in-APK facts read, unresolved/opaque -> `unverified` (not a guess).
- `pass`: no cross-platform HTTP stack, or the framework forbids cleartext / uses only https, with evidence.
- `n/a`: no cross-platform framework present (short-circuit; state the search).
- `unverified` rows name the opaque bundle/entry point. Neither pass nor fail.
- `inconclusive` if rationale counts don't reconcile with L1 rows, if any false_positive_risk references in-APK evidence, if a finding was dropped without evidence, or if any `fail` lacks its quoted framework + cleartext-surface L2 rows.

Self-check before emitting (per finding)
For every Finding confirm: (1) the framework is identified by a quoted indicator; (2) the cleartext config / used `http://` endpoint is quoted; (3) it bypasses or ignores the native NSC; (4) owner/stack named.
Hedge scan: "likely", "may", "appears", "probably", "might" in a finding's evidence -> downgrade to `unverified`.
Before any `pass`/`fail`/`n/a`: confirm the framework-detection search was performed (n/a / pass state it), every readable framework surface was examined (opaque -> `unverified`), and no `false_positive_risks` entry describes an unresolved in-APK fact. Confirm counts reconcile (no sampling). Only then emit.

If you reach 39 tool iterations, provide an answer with the information you have. A full iteration = your tool calls + their returned results.
