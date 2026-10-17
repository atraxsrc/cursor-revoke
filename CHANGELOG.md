# Changelog

## 0.1.0 - 2026-10-17

First release.

- Installer-style TUI with four categories: agent permissions, sandbox settings, MCP servers and hooks, project data folders.
- Grouped checkboxes (STALE / RISKY / OK) with group-level ticking, search and view filters. Deny rules, block rules and the approval mode are shown but locked.
- Removes single allow rules, auto-run rules, risky sandbox fields (reset field by field, files never deleted), MCP servers and hooks; moves `~/.cursor/projects/<name>` folders to quarantine.
- One-tick hardening: deny rules for keys and `.env` files in `~/.cursor/cli-config.json` (Cursor CLI agent only).
- Quarantine at `~/.cursor-revoke-quarantine/<timestamp>/`, JSON backups, `--restore`.
- Files in an unknown format are shown and never rewritten.
- `--report`, `--only`, `--dry-run`, `--roots`, `--pause`, `--accent`, `NO_COLOR`.
- `--schedule weekly|daily|off` and `--notify`: a systemd user timer with a desktop notification.
- `.deb`, `.rpm` and Arch packages, `install.sh` / `uninstall.sh`, launcher entry, CI.
- Not in v1: chat history, secret scan, anything inside Cursor's SQLite or LevelDB stores.
