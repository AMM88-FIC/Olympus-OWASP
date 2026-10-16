# OLYMPUS OWASP + LLM Android Analyzer

OLYMPUS OWASP with the LLM Android Analyzer integrated as a tool family
(`llm_status`, `llm_run_test`, `llm_review`).

## Requirements

- **Linux x86_64 with glibc 2.38 or newer**: Ubuntu 24.04+, Debian 13+,
  Fedora 39+, or Kali 2024.2+. Ubuntu 22.04 and older are **not supported**:
  the AppImage's bundled libraries need a newer glibc than those systems have.
  To check your system, run `ldd --version`: the first line ends with the glibc
  version. `setup.sh` also checks this before installing anything.
- A desktop session (Olympus is a GUI application).
- Internet access during setup (to download uv, Python and packages).
- `libfuse2` to run AppImages (Ubuntu 24.04: `sudo apt install libfuse2t64`).
- A Gemini API key, entered in Olympus's AI panel.

## Install

```bash
git clone https://github.com/AMM88-FIC/Olympus-OWASP.git
cd https://github.com/AMM88-FIC/Olympus-OWASP.git
./setup.sh
```

(If `./setup.sh` reports "Permission denied", run `bash setup.sh` instead.)

### The OLYMPUS OWASP AppImage

The AppImage is not stored in the repository; it is published as an asset of
this repo's [GitHub Releases](../../releases). You do not need to fetch it
yourself: `setup.sh` downloads it from the latest release.

If you prefer to download it manually (or the automatic download fails),
download `OLYMPUS-OWASP-0.1.2-slim-x86_64.AppImage` from the Releases page and
place it in this folder, next to `setup.sh`, before running the script. Keep
the file name exactly as published: when the file is already there, the script
uses it and skips the download.

### What `setup.sh` does

1. Downloads the OLYMPUS OWASP AppImage from the latest GitHub release
   (skipped if the file is already in this folder).
2. Creates the analyzer's environment in `engine/llm-analyzer/.venv` with
   [uv](https://docs.astral.sh/uv/) (installed automatically if missing).
3. Installs the plugin settings into `~/.config/olympus-owasp/llm_plugin.json`,
   pointing them at this folder. Existing files are backed up first.
4. Unpacks Olympus into `~/.local/share/olympus-owasp` and adds it to the
   applications menu.
5. Installs the LLM plugin and patches Olympus to load it.
6. Starts Olympus.

After setup, launch Olympus from the applications menu or by running the
AppImage.

## Evaluating an APK

1. Go to **Targets** > **Acquire**.
2. Select an APK and click **Acquire APK**.
3. Open the target and click **Build context**.
4. To run the tests, click **Controls** inside the target, then **Assessment**.
5. Go to **Static** and click **Run static**.

## Using the LLM engine

The LLM engine is used through the tools available in the **LLM orchestrator**.
First connect a Gemini backend with your API key in Olympus's AI panel.

The orchestrator can fully control the application through natural language,
so every step in [Evaluating an APK](#evaluating-an-apk) can also be done by
asking it, for example: *"Acquire the APK at ~/apks/app.apk, build its context
and run the static assessment."*

To use the LLM engine itself, ask the orchestrator explicitly, naming the test:

- **Run a test with the LLM engine**: the engine answers the test itself from
  the APK's evidence (`llm_run_test`). For example: *"Run test
  MASTG-TEST-0001 on this target using the LLM engine."*
- **Review a test with the LLM engine**: the engine checks the result Olympus
  already produced and looks for checks that were missed (`llm_review`). The
  test must have been run by Olympus first. For example: *"Use the LLM engine
  to review Olympus's result for MASTG-TEST-0001."*

Neither tool changes Olympus's own verdict: the LLM engine's result is shown
next to it. If the orchestrator says the LLM tools are unavailable, ask it to
run `llm_status`, which names the missing setting.

## After updating the AppImage

A new AppImage version unpacks itself again and removes the plugin. Re-run:

```bash
./setup.sh
```

## Uninstall

```bash
./uninstall.sh
```

Removes the Olympus runtime, its menu entry, its settings, the analyzer's
virtual environment and the downloaded AppImage, and optionally uv. Analysis
results in `~/olympus-evidence` are kept.

## Troubleshooting

- **`GLIBC_2.38' not found`**: the system is too old; see Requirements.
- **Errors mentioning `/usr/lib/python3/dist-packages`**: a global
  `PYTHONPATH` is set. Remove it from `~/.bashrc`, `~/.profile` or
  `/etc/environment`, then re-run `./setup.sh`.
- **The AppImage download fails**: download it manually from the Releases page,
  put it in this folder, and run `./setup.sh` again.
- **The AppImage does not start at all**: install `libfuse2` (see Requirements).
- **The LLM tools say they are unavailable**: run `llm_status` from Olympus; it
  names the missing setting.
- **Logs**: `olympus.log` in this folder, from the last start by `setup.sh`.
