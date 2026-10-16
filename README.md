# OLYMPUS OWASP + LLM Android Analyzer

OLYMPUS OWASP with the LLM Android Analyzer integrated as a tool family
(`llm_status`, `llm_run_test`, `llm_review`).

## Requirements

- **Linux x86_64 with glibc 2.38 or newer**: Ubuntu 24.04+, Debian 13+,
  Fedora 39+, or a current Kali. Ubuntu 22.04 and older are **not supported**:
  the AppImage's bundled libraries need a newer glibc than those systems have.
- A desktop session (Olympus is a GUI application).
- Internet access during setup (to download uv, Python and packages).
- `libfuse2` to run AppImages (Ubuntu 24.04: `sudo apt install libfuse2t64`).
- A Gemini API key, entered in Olympus's AI panel.

## Install

```bash
git clone https://github.com/AMM88-FIC/Olympus-OWASP.git
cd Olympus-OWASP
./setup.sh
```

`setup.sh`:

1. Creates the analyzer's environment in `engine/llm-analyzer/.venv` with
   [uv](https://docs.astral.sh/uv/) (installed automatically if missing).
2. Installs the plugin settings into `~/.config/olympus-owasp/llm_plugin.json`,
   pointing them at this folder. Existing files are backed up first.
3. Unpacks Olympus into `~/.local/share/olympus-owasp` and adds it to the
   applications menu.
4. Installs the LLM plugin and patches Olympus to load it.
5. Starts Olympus.

After setup, launch Olympus from the applications menu or by running the
AppImage.

## After updating the AppImage

A new AppImage version unpacks itself again and removes the plugin. Re-run:

```bash
./setup.sh
```

## Troubleshooting

- **`GLIBC_2.38' not found`**: the system is too old; see Requirements.
- **Errors mentioning `/usr/lib/python3/dist-packages`**: a global
  `PYTHONPATH` is set. Remove it from `~/.bashrc`, `~/.profile` or
  `/etc/environment`, then re-run `./setup.sh`.
- **The AppImage does not start at all**: install `libfuse2` (see Requirements).
- **The LLM tools say they are unavailable**: run `llm_status` from Olympus; it
  names the missing setting.
- **Logs**: `olympus.log` in this folder, from the last start by `setup.sh`.
