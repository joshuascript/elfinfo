#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

usage() {
    echo "Usage: $0 [--uninstall]"
    echo "  (no flags)   Create venv and install elfinfo"
    echo "  --uninstall  Remove venv, egg-info, and symlink"
    exit 1
}

install() {
    if [ ! -d "$VENV" ]; then
        echo "Creating virtual environment at $VENV ..."
        python3 -m venv "$VENV"
    fi

    echo "Installing elfinfo into $VENV ..."
    "$VENV/bin/pip" install -e "$SCRIPT_DIR" --quiet

    # Symlink into ~/.local/bin so 'elfinfo' works from anywhere
    LOCAL_BIN="$HOME/.local/bin"
    mkdir -p "$LOCAL_BIN"
    ln -sf "$VENV/bin/elfinfo" "$LOCAL_BIN/elfinfo"
    echo "Symlinked elfinfo → $LOCAL_BIN/elfinfo"

    echo ""
    echo "Done. elfinfo is now available system-wide:"
    echo "  elfinfo <path/to/lib.so>"
}

uninstall() {
    if [ -d "$VENV" ]; then
        echo "Removing $VENV ..."
        rm -rf "$VENV"
    else
        echo "No venv found at $VENV — nothing to remove."
    fi

    if [ -d "$SCRIPT_DIR/elfinfo.egg-info" ]; then
        echo "Removing elfinfo.egg-info ..."
        rm -rf "$SCRIPT_DIR/elfinfo.egg-info"
    fi

    LINK="$HOME/.local/bin/elfinfo"
    if [ -L "$LINK" ]; then
        echo "Removing symlink $LINK ..."
        rm "$LINK"
    fi

    echo "Done. elfinfo uninstalled."
}

case "${1:-}" in
    "")           install ;;
    --uninstall)  uninstall ;;
    *)            usage ;;
esac
