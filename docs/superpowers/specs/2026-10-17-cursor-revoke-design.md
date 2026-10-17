# cursor-revoke design

Date: 2026-10-17. Status: draft, awaiting approval. Passages marked
"my call" were decided by the assistant, not the author; overrule freely.

## Intent

claude-revoke (sibling repo, `../claude-revoke`) shows everything Claude
Code has been given on a Linux machine, lets the user tick what to remove,
and quarantines instead of deleting. cursor-revoke is the same thing for
Cursor, the AI editor built on VS Code (editor window plus a separate
"Agents Window" in the same app).

Cursor's agent can run shell commands, read files, reach the network and
call MCP servers, and like Claude Code it remembers what the user allowed.
Over time that builds up across global and per-project files with no single
place to see it. cursor-revoke is that place.

It is a public open-source project on GitHub (`atraxsrc/cursor-revoke`),
aimed at people like the author: Cursor users on Linux who want a safety
net and may be new to AI tools. It should feel like claude-revoke's
sibling: same look, same keys, same safety model.

## Goals

- Show every permission-like grant Cursor has on the machine, grouped into
  STALE, RISKY and OK, in the same checkbox TUI as claude-revoke.
- Let the user tick items and apply, with nothing deleted: removed files go
  to a quarantine folder, edited JSON files are backed up first, and
  `--restore <quarantine dir>` undoes a run.
- Ship the same way claude-revoke does: single file, no dependencies,
  `.deb`/`.rpm`/Arch packages, `install.sh`, launcher entry.

## Non-goals (v1)

- Chat history and agent transcripts. No secret scan in v1.
- Anything inside Cursor's SQLite / LevelDB stores (`state.vscdb`,
  `*.sqlite`, `*.db`, `IndexedDB`, `Local Storage`). v1 does not open them,
  not even read-only, so a Cursor update cannot break the tool. (Its
  `workspace.json` and `storage.json` files are plain JSON and are fine to
  read.)
- Cursor's cloud side: background/cloud agents, Automations, Bugbot,
  GitHub connection, cloud MCP servers, team settings.
- Rules, skills, subagents and `.cursorignore` content (instructions, not
  grants).
- macOS and Windows. Paths are Linux-only; keep them in one place so a port
  is possible later.
- Sharing code with claude-revoke. Each repo stays one self-contained file.

## Anti-goals

- Breaking a working Cursor install, or leaving a config file Cursor can't
  parse. Every write is atomic and backed up, and the tool never writes to a
  file it failed to parse.
- Silently widening access. "Remove" must only ever take a grant away.
  Sandbox files can be stricter than Cursor's defaults, so they are edited
  field by field, never deleted (see below).
- Guessing. When a file's format isn't recognised, show the item as
  "unknown format, not touched" instead of acting on it.

## Constraints

- Python 3.8+, standard library only, single file `cursor_revoke.py`,
  installed as the `cursor-revoke` command.
- Same safety features as claude-revoke: `--dry-run`, review screen, typed
  `YES` to apply, JSON backups, quarantine with `manifest.json`,
  `--restore` that puts back only what that run removed.
- Warn (don't block) if Cursor is running, since it may rewrite these files.
  Detect the `cursor` / `Cursor` process the way claude-revoke's
  `running_claude()` does.
- Same author identity and noreply address as claude-revoke; MIT license.
- No emails, tokens or personal data in code, docs or fixtures. Tests use a
  fake temporary home, like claude-revoke's.

## What it reads (decided)

Scope confirmed against a real install (Cursor, October 2026) and Cursor's
docs: [permissions.json](https://cursor.com/docs/reference/permissions),
[CLI permissions](https://cursor.com/docs/cli/reference/permissions),
[sandbox](https://cursor.com/docs/reference/sandbox),
[run modes](https://cursor.com/docs/agent/run-modes).

| Location | What it is |
| --- | --- |
| `~/.cursor/cli-config.json` → `permissions.allow` / `.deny`, `approvalMode`, `sandbox` | Agent/CLI allow and deny rules (`Shell(ls)`, `Read(...)`, `Write(...)`, `Mcp(server:tool)`), approval mode, CLI sandbox mode |
| `<project>/.cursor/cli.json` → `permissions` | Per-project allow/deny rules |
| `~/.cursor/permissions.json`, `<project>/.cursor/permissions.json` → `autoRun.allow_instructions` / `block_instructions` and any other allowlist keys | Auto-run allow/block rules (arrays concatenate with the in-app list) |
| `~/.cursor/sandbox.json`, `<project>/.cursor/sandbox.json` | What sandboxed agent commands may read, write and reach on the network |
| `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json` → `mcpServers` | MCP servers the user added |
| `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json` | Hooks: commands Cursor runs automatically |
| `~/.cursor/projects/*` | Per-project agent data folders (MCP descriptors, terminals, canvases, transcripts) |

Project folders are found by walking `--roots` (default: home), same
pruning as claude-revoke's `scan_settings`, looking for `.cursor/` dirs.
`~/.cursor/.cursor/` exists on a real install (it holds a `sandbox.json`);
my call: the walk treats it as the project-level folder of the project
`~/.cursor` and labels it that way, it is not a second global file.

### Real file shapes (redacted, Cursor October 2026)

`~/.cursor/cli-config.json` (relevant keys only):

```json
{
  "version": 1,
  "permissions": { "allow": ["Shell(ls)"], "deny": [] },
  "approvalMode": "allowlist",
  "sandbox": { "mode": "disabled", "networkAccess": "user_config_with_defaults" }
}
```

`~/.cursor/permissions.json`:

```json
{ "autoRun": { "allow_instructions": [], "block_instructions": ["<free text>", "<free text>"] } }
```

`~/.cursor/sandbox.json` (also `~/.cursor/.cursor/sandbox.json`):

```json
{
  "type": "workspace_readwrite",
  "readBoundary": "workspace",
  "additionalReadPaths": [],
  "disableTmpWrite": false,
  "networkPolicy": { "default": "deny", "allow": [], "deny": [] }
}
```

`mcp.json` and `hooks.json` were not present on the reference install;
use the shapes in Cursor's docs and treat anything else as unknown format.
Only `"allowlist"` has been seen for `approvalMode`, and Cursor's docs don't
list the values.

### Sandbox defaults and merging (from Cursor's sandbox reference)

With no file, Cursor uses: `type` `workspace_readwrite`, `readBoundary`
`system` (agent can read the whole system), `networkPolicy.default` `deny`,
all lists empty, `disableTmpWrite` `false`. `type` can also be
`workspace_readonly` (stricter) or `insecure_none` (no sandbox).

User and project files merge: path lists and `networkPolicy.allow`/`deny`
are unioned, project `readBoundary` and `additionalReadPaths` replace the
user's, `networkPolicy.default` `deny` wins, `true` wins for restrictive
booleans. So a user file can be stricter than the defaults (the reference
install's `readBoundary: "workspace"` is), and deleting it would widen
access.

## Grouping

STALE:
- `~/.cursor/projects/<name>` whose project folder no longer exists, plus
  `tmp-<uuid>` folders and numeric empty-window folders. Folder names are
  the project path with `/` turned into `-` and the leading `-` dropped
  (for example `/home/user/code/my-app` becomes `home-user-code-my-app`). That
  encoding is lossy, so resolve a name by comparing it against the encoded
  form of known folders (from `~/.config/Cursor/User/workspaceStorage/*/workspace.json`
  `folder` URIs and `globalStorage/storage.json` `backupWorkspaces`) and,
  failing that, against encoded candidates found on disk. A folder counts
  as STALE (and is pre-ticked) only when the path is known and gone, or
  the name is a `tmp-<uuid>` or numeric empty-window folder. My call: a
  name that can't be matched to any path is shown as "unknown, folder not
  found" and is NOT pre-ticked, because the lossy encoding (paths with `-`
  or `.`, projects outside `--roots`, unmounted drives) can hide a live
  project.
- Per-project `.cursor/*.json` grants are never stale (the folder exists
  by definition).

RISKY:
- Allow rules that are broad: `Shell(*)`, `Shell(sudo...)`, `Shell(curl...)`
  piped forms, `Write(**)`, `Write(~/...)`, `Read(~/.ssh...)` and similar.
  Reuse the spirit of claude-revoke's `is_broad()`.
- `approvalMode` other than `allowlist`. My call: shown as RISKY with the
  value and "change this in Cursor's settings"; the tool does not rewrite
  it, since the full list of modes is unknown and a reset could widen.
- Any auto-run `allow_instructions`.
- Sandbox fields that are wider than Cursor's defaults: `type`
  `insecure_none`, `networkPolicy.default` `allow`, a `networkPolicy.allow`
  entry of `*` (or similarly broad), and `additionalReadwritePaths` /
  `additionalReadonlyPaths` / `additionalReadPaths` entries outside the
  project (home, `/`, `~/.ssh` and so on). Fields at or stricter than the
  defaults are OK and never offered for removal.
- Any user-added MCP server. Any hook.

OK: everything else (for example `Shell(ls)`, block rules, default sandbox
files). Deny and block rules are shown for completeness but are never
pre-ticked and are listed as protective.

## What "remove" does

| Item | Action |
| --- | --- |
| One allow rule in `cli-config.json` / `cli.json` | Remove that entry from the array, file backed up |
| `approvalMode` flagged risky | Nothing; shown with advice only |
| One auto-run allow instruction | Remove that entry, file backed up |
| One risky sandbox field | Reset just that field to Cursor's default (remove the list entry, or set `type` to `workspace_readwrite`, `networkPolicy.default` to `deny`), file backed up. Sandbox files are never quarantined or deleted whole. |
| An MCP server | Remove the entry from `mcpServers`, file backed up |
| A hooks file or one hook | Remove the entry (or quarantine the file), file backed up |
| A `~/.cursor/projects/<name>` folder | Move to quarantine |

Block and deny rules are never removed by the tool.

## Same as claude-revoke (decided by default, overrule if wanted)

- TUI, keys, views, search, `--accent` / `NO_COLOR` theming, `--report`,
  `--report --only stale|risky`, `--dry-run`, `--roots`, `--pause`,
  `--version`.
- Hardening tick: adds `Read(...)` deny rules for `~/.ssh`, `~/.aws`,
  `~/.gnupg`, `.env`, `*.pem`, `*.key` to `~/.cursor/cli-config.json`
  `permissions.deny` (JSON edit, so the existing backup/restore covers it).
  My call: Cursor's docs only confirm the CLI agent reads that file, so the
  item and README say "Cursor CLI agent" and do not promise it protects the
  editor or Agents Window. The tool does not write `.cursorignore` in v1
  (unverified global location, and a text file restore would need new
  machinery). If the builder can confirm on a real install that the editor
  agent honours these rules, widen the wording.
- `--schedule weekly|daily|off` and `--notify` with a systemd user timer
  named `cursor-revoke-audit`.
- Quarantine at `~/.cursor-revoke-quarantine/<timestamp>/`.
- Packaging, CI, `install.sh` / `uninstall.sh`, desktop entry and banner
  mirror claude-revoke's 2026-10-10 packaging design with names swapped.

## Left to the builder

- How much of `claude_revoke.py` to copy as-is versus rewrite; the TUI and
  apply/restore machinery should carry over nearly unchanged.
- The exact broad-rule patterns and test fixtures, as long as they cover the
  examples above.
- README wording and screenshots, following claude-revoke's README layout,
  with a clear note that Cursor's file formats are young and shift between
  versions (several open forum reports of files and app disagreeing), so
  users should run `--report` first.
- Commit granularity and order of work.

## Later (not v1)

- Secret scan of agent transcripts under `~/.cursor/projects/*/agent-transcripts`
  (plain files, so possible without SQLite) and, maybe, chat history.
- A Cursor section inside claude-revoke, or a shared core, if both tools
  grow together.
