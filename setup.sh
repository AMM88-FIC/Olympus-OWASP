#!/usr/bin/env bash
# Setup script for OLYMPUS OWASP + LLM Android Analyzer
#
#   0. Download the AppImage from the GitHub release (if not already here)
#   1. uv sync for the LLM analyzer (component A)
#   2. Install the config into ~/.config/olympus-owasp
#   3. Let the AppImage unpack its runtime (--install, no window)
#   4. Drop the LLM plugin and patch scripts into the extracted app and patch it
#   5. Launch Olympus for real
set -euo pipefail

# --- GitHub release that holds the AppImage ---
# GITHUB_REPO: "owner/repo". Left empty, it is read from this clone's git remote.
# RELEASE_TAG: e.g. "v0.1.2". Left empty, the latest release is used.
GITHUB_REPO="AMM88-FIC/Olympus-OWASP"
RELEASE_TAG=""
APPIMAGE_NAME="OLYMPUS-OWASP-0.1.2-slim-x86_64.AppImage"

# --- Paths (everything is relative to where setup.sh lives, not where it's run from) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPIMAGE="$SCRIPT_DIR/$APPIMAGE_NAME"
LLM_HOME="$SCRIPT_DIR/engine/llm-analyzer"
LLM_PYTHON="$LLM_HOME/.venv/bin/python"
CONFIG_SRC="$SCRIPT_DIR/config"
CONFIG_DST="$HOME/.config/olympus-owasp"
PATCH_SRC="$SCRIPT_DIR/patches"          # llm_plugin.py + the three patch scripts

# Where the AppImage unpacks its runtime
EXTRACT_ROOT="${OLYMPUS_OWASP_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/olympus-owasp}"   # same rule as AppRun
APP_DIR="$EXTRACT_ROOT/usr/share/olympus-owasp"

info()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
fail()  { echo -e "\033[1;31m[x]\033[0m $*" >&2; exit 1; }

# --- 0. Check everything is in place before touching anything ---
# The AppImage's bundled libraries were built against glibc 2.38; older systems
# (e.g. Ubuntu 22.04 with 2.35) cannot load them, and nothing here can change that.
MIN_GLIBC="2.38"
glibc="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
if [[ -z "$glibc" ]]; then
    fail "Could not detect glibc. OLYMPUS OWASP needs a glibc-based Linux (not Alpine/musl)."
elif [[ "$(printf '%s\n%s\n' "$MIN_GLIBC" "$glibc" | sort -V | head -1)" != "$MIN_GLIBC" ]]; then
    fail "This system has glibc $glibc; OLYMPUS OWASP needs $MIN_GLIBC or newer
    (Ubuntu 24.04+, Debian 13+, Fedora 39+, current Kali)."
fi
[[ "$(uname -m)" == "x86_64" ]] || fail "OLYMPUS OWASP is x86_64 only (this machine: $(uname -m))"

if [[ -n "${PYTHONPATH:-}" ]]; then
    warn "PYTHONPATH is set ($PYTHONPATH). It breaks Python tools that bring their own"
    warn "Python; consider removing it from ~/.bashrc, ~/.profile or /etc/environment."
    warn "This setup ignores it, and Olympus is patched to ignore it too."
fi
[[ -d "$LLM_HOME" ]]   || fail "Component A folder not found: $LLM_HOME"
[[ -d "$CONFIG_SRC" ]] || fail "Config folder not found: $CONFIG_SRC"
for f in llm_plugin.py reapply_llm_plugin.sh patch_toolsurface_llm.py patch_llm_key.py; do
    [[ -f "$PATCH_SRC/$f" ]] || fail "Missing $PATCH_SRC/$f"
done

# --- 0b. Download the AppImage from the GitHub release ---
if [[ -f "$APPIMAGE" ]]; then
    info "AppImage already present, skipping download"
else
    if [[ -z "$GITHUB_REPO" ]]; then
        remote="$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)"
        GITHUB_REPO="$(sed -nE 's#.*github\.com[:/]([^/]+/[^/]+)$#\1#p' <<<"$remote")"
        GITHUB_REPO="${GITHUB_REPO%.git}"
        [[ -n "$GITHUB_REPO" ]] || fail "Cannot tell which GitHub repo to download from.
    Set GITHUB_REPO at the top of setup.sh, or download $APPIMAGE_NAME
    from the repo's Releases page into $SCRIPT_DIR and run setup.sh again."
    fi
    if [[ -n "$RELEASE_TAG" ]]; then
        url="https://github.com/$GITHUB_REPO/releases/download/$RELEASE_TAG/$APPIMAGE_NAME"
    else
        url="https://github.com/$GITHUB_REPO/releases/latest/download/$APPIMAGE_NAME"
    fi

    info "Downloading $APPIMAGE_NAME from $GITHUB_REPO..."
    tmp="$APPIMAGE.part"
    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --progress-bar -o "$tmp" "$url" || dl_ok=no
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress -O "$tmp" "$url" || dl_ok=no
    else
        fail "Neither curl nor wget is installed"
    fi
    if [[ "${dl_ok:-yes}" == "no" ]]; then
        rm -f "$tmp"
        fail "Download failed: $url
    Check that the release exists and contains $APPIMAGE_NAME. If the repo is private,
    download it from the Releases page into $SCRIPT_DIR and run setup.sh again."
    fi
    mv "$tmp" "$APPIMAGE"
    ok "Downloaded $APPIMAGE"
fi

# --- 1. Set up component A (LLM analyzer) with uv ---
if ! command -v uv >/dev/null 2>&1; then
    info "uv not found, installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    command -v uv >/dev/null 2>&1 || fail "uv installation failed"
fi

# Use a uv-managed Python, never the distro's. Ubuntu/Debian's system Python
# leaks /usr/lib/python3/dist-packages into source builds, and its patched
# setuptools there breaks packages that must be compiled (e.g. mutf8, needed
# by androguard).
export UV_PYTHON_PREFERENCE=only-managed
unset PYTHONPATH PYTHONHOME

# A .venv left over from an earlier attempt with the system Python is rebuilt
if [[ -f "$LLM_HOME/.venv/pyvenv.cfg" ]] && \
   ! grep -q "uv/python" "$LLM_HOME/.venv/pyvenv.cfg"; then
    info "Removing a .venv built with the system Python..."
    rm -rf "$LLM_HOME/.venv"
fi

# Packages without a prebuilt wheel need a C compiler
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
    warn "No C compiler found. If uv sync fails while building a package, run:"
    warn "    sudo apt install build-essential"
fi

info "Creating LLM analyzer environment with uv sync..."
(cd "$LLM_HOME" && uv sync)
[[ -x "$LLM_PYTHON" ]] || fail "Expected Python not found at $LLM_PYTHON"
ok "LLM analyzer environment ready: $LLM_PYTHON"

# --- 2. Install the config into ~/.config/olympus-owasp ---
mkdir -p "$CONFIG_DST"

# Back up any existing files that would be overwritten
for src in "$CONFIG_SRC"/*; do
    dst="$CONFIG_DST/$(basename "$src")"
    if [[ -e "$dst" ]]; then
        backup="$dst.bak.$(date +%Y%m%d%H%M%S)"
        cp -r "$dst" "$backup"
        info "Backed up existing $(basename "$dst") to $backup"
    fi
done

cp -r "$CONFIG_SRC"/. "$CONFIG_DST"/

# Update llm_home and llm_python in every JSON file of the copied config
# (the repo's ./config stays untouched)
shopt -s nullglob
json_files=("$CONFIG_DST"/*.json)
[[ ${#json_files[@]} -gt 0 ]] || fail "No .json file found in $CONFIG_SRC"

for f in "${json_files[@]}"; do
    "$LLM_PYTHON" - "$f" "$LLM_HOME" "$LLM_PYTHON" <<'EOF'
import json, sys
path, home, python = sys.argv[1:4]
with open(path) as fh:
    cfg = json.load(fh)
if any(k.startswith("llm_") for k in cfg):
    cfg["llm_home"] = home
    cfg["llm_python"] = python
    with open(path, "w") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    print("updated")
EOF
    ok "Config installed: $f"
done
[[ -f "$CONFIG_DST/llm_plugin.json" ]] || \
    warn "No llm_plugin.json in $CONFIG_DST - the plugin reads its settings from that file"

# --- 3. Prepare the Olympus runtime (unpack only, no window) ---
# AppRun's --install unpacks the bundle into $EXTRACT_ROOT on first run or when the
# AppImage version changes, adds the menu entry, and exits without starting the app.
# When the runtime is already current it does nothing, so it is safe to run every time.
chmod +x "$APPIMAGE"
info "Preparing the Olympus runtime (first run takes a minute)..."
"$APPIMAGE" --install || fail "The AppImage failed to prepare its runtime"
[[ -f "$APP_DIR/tooling/toolsurface.py" && -f "$APP_DIR/olympus_owasp_app.py" \
   && -d "$APP_DIR/gui_shared" ]] || fail "Olympus runtime not found in $APP_DIR after --install"
ok "Olympus runtime ready in $APP_DIR"

# --- 4. Install the LLM plugin and patch the extracted app ---
cp "$PATCH_SRC/llm_plugin.py" "$APP_DIR/gui_shared/llm_plugin.py"
cp "$PATCH_SRC/reapply_llm_plugin.sh" \
   "$PATCH_SRC/patch_toolsurface_llm.py" \
   "$PATCH_SRC/patch_llm_key.py" "$APP_DIR/"
chmod +x "$APP_DIR/reapply_llm_plugin.sh"
ok "Plugin copied to $APP_DIR/gui_shared/llm_plugin.py"

# Make the bundled Python ignore the system's Python folders. A global PYTHONPATH
# (e.g. /usr/lib/python3/dist-packages) would otherwise load the system's cairo/gi,
# built for a different Python, instead of the bundled ones. A .pth file runs at
# interpreter start-up, before any of Olympus's imports, however Olympus is launched.
BUNDLE_SITE="$EXTRACT_ROOT/usr/lib/python3.12/site-packages"
if [[ -d "$BUNDLE_SITE" ]]; then
    cat > "$BUNDLE_SITE/zz_olympus_pathfix.pth" <<'EOF'
import sys; sys.path[:] = [p for p in sys.path if not (p.startswith(("/usr/lib/python3", "/usr/local/lib/python3")) and not p.startswith(sys.prefix))]
EOF
    ok "Olympus isolated from the system's Python packages"
else
    warn "Bundled site-packages not found at $BUNDLE_SITE; skipping PYTHONPATH isolation"
fi

info "Patching Olympus (reapply_llm_plugin.sh)..."
if sh "$APP_DIR/reapply_llm_plugin.sh"; then
    ok "LLM plugin registered"
else
    warn "reapply_llm_plugin.sh reported a problem (see output above). Olympus will still"
    warn "start, but the llm_* tools may be missing. Re-run it with:"
    warn "    sh \"$APP_DIR/reapply_llm_plugin.sh\""
fi

# --- 5. Launch Olympus for real ---
echo
ok "Setup complete."
echo "    llm_home   = $LLM_HOME"
echo "    llm_python = $LLM_PYTHON"
echo "    app dir    = $APP_DIR"
echo

info "Launching OLYMPUS OWASP (log: $SCRIPT_DIR/olympus.log)..."
nohup setsid "$APPIMAGE" --no-install >"$SCRIPT_DIR/olympus.log" 2>&1 &
app_pid=$!

# Catch a crash at startup instead of reporting success blindly
sleep 5
if kill -0 "$app_pid" 2>/dev/null; then
    ok "OLYMPUS started (PID $app_pid)"
else
    warn "OLYMPUS exited right after starting. Last lines of $SCRIPT_DIR/olympus.log:"
    tail -n 15 "$SCRIPT_DIR/olympus.log" >&2
    exit 1
fi
