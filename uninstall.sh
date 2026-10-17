#!/usr/bin/env bash
# Remove cursor-revoke. Your quarantine folder (~/.cursor-revoke-quarantine) is kept.
set -euo pipefail
# scheduled audit: stop the timer and remove its units and schedule override
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
command -v systemctl >/dev/null && systemctl --user disable --now cursor-revoke-audit.timer 2>/dev/null || true
rm -rf "$units/cursor-revoke-audit.timer.d"
rm -f "$units/cursor-revoke-audit.service" "$units/cursor-revoke-audit.timer" \
      "$units/timers.target.wants/cursor-revoke-audit.timer"   # in case disable could not run
command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null || true
rm -f "$HOME/.local/bin/cursor-revoke" \
      "$HOME/.local/share/applications/cursor-revoke.desktop" \
      "$HOME/.local/share/icons/hicolor/scalable/apps/cursor-revoke.svg"
echo "cursor-revoke removed."
if [ -d "$HOME/.cursor-revoke-quarantine" ]; then
  echo "Quarantine kept at ~/.cursor-revoke-quarantine - delete it yourself once you're sure."
fi
