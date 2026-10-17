#!/usr/bin/env bash
# Install cursor-revoke for the current user (no sudo needed).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bin="$HOME/.local/bin"
apps="$HOME/.local/share/applications"
icons="$HOME/.local/share/icons/hicolor/scalable/apps"

command -v python3 >/dev/null || { echo "python3 is required (sudo apt install python3)"; exit 1; }
python3 -c "import curses" 2>/dev/null || { echo "Python curses module missing"; exit 1; }

mkdir -p "$bin" "$apps" "$icons"
install -m 755 "$here/cursor_revoke.py" "$bin/cursor-revoke"
install -m 644 "$here/assets/logo.svg" "$icons/cursor-revoke.svg"

# Pick a terminal for the launcher entry: COSMIC Terminal first (Pop!_OS).
if command -v cosmic-term >/dev/null; then term="cosmic-term -e"
elif command -v gnome-terminal >/dev/null; then term="gnome-terminal --"
elif command -v kitty >/dev/null; then term="kitty"
elif command -v alacritty >/dev/null; then term="alacritty -e"
else term="x-terminal-emulator -e"
fi

sed -e "s|@TERM@|$term|" -e "s|@BIN@|$bin/cursor-revoke|" \
    "$here/packaging/cursor-revoke.desktop.in" > "$apps/cursor-revoke.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$apps" 2>/dev/null || true

# systemd user units for the optional scheduled audit (off until you enable it)
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$units"
sed -e "s|@BIN@|$bin/cursor-revoke|" "$here/packaging/cursor-revoke-audit.service.in" > "$units/cursor-revoke-audit.service"
install -m 644 "$here/packaging/cursor-revoke-audit.timer" "$units/cursor-revoke-audit.timer"
command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null || true

echo "Installed: $bin/cursor-revoke"
echo "Launcher:  'Cursor Revoke' (opens in: ${term%% *})"
case ":$PATH:" in
  *":$bin:"*) ;;
  *) echo "Note: $bin is not on your PATH yet - log out and back in, or open a new terminal." ;;
esac
echo
echo "Start with a safe look:  cursor-revoke --report"
echo "Weekly check, optional:  cursor-revoke --schedule weekly"
