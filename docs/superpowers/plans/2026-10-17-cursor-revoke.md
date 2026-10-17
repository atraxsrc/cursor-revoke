# cursor-revoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build cursor-revoke 0.1.0, a single-file Linux TUI that lists what Cursor's AI agent has been granted, groups it into STALE / RISKY / OK, and removes ticked items with quarantine, backups and `--restore`.

**Architecture:** One file, `cursor_revoke.py`, ported from `../claude-revoke/claude_revoke.py` (read it first; the TUI, quarantine, restore, report, schedule and packaging carry over nearly unchanged). The new part is the data model: every item names the file it lives in and the JSON path inside that file, so one generic apply/restore engine handles global and per-project files alike. Tests run against a fake home folder, same as claude-revoke.

**Tech Stack:** Python 3.8+ standard library only (`curses`, `json`, `unittest`), nfpm for packages, systemd user timer, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-17-cursor-revoke-design.md` (read it; this plan argues from it).

## Global Constraints

- Python 3.8+, standard library only, one file `cursor_revoke.py`, command name `cursor-revoke`, `__version__ = "0.1.0"`.
- Linux only. All paths come from constants at the top of the file (`HOME`, `CURSOR_DIR`, `CURSOR_USER_DIR`, `QUARANTINE_ROOT`), overridable with env `CURSOR_REVOKE_HOME` like claude-revoke's `CLAUDE_REVOKE_HOME`.
- Never open Cursor's SQLite / LevelDB stores (`*.vscdb`, `*.sqlite`, `*.db`, `IndexedDB`, `Local Storage`), not even read-only.
- Never write a file that failed to parse as a JSON object. Every write goes through `write_json_atomic` after a backup into the run's quarantine folder.
- "Remove" only ever narrows access. Block/deny rules are never removed. Sandbox files are never quarantined or deleted whole.
- Same author identity as claude-revoke (`atraxsrc` with the GitHub noreply address already in its history). No `Co-Authored-By` trailers. No em or en dashes anywhere. No real usernames, emails or tokens in code, fixtures or docs; test paths use `/home/user/...` shapes under the temp home.
- Git in a Claude Code sandbox: prefix with `GIT_CONFIG_GLOBAL=/dev/null` and run `gitleaks git --pre-commit --staged --redact --no-banner .` by hand before each commit. Stage files by name, never `git add .`.

## Review Focus

1. **Hand-edited JSON with comments or trailing commas** (VS Code users write JSONC): the file shows as one locked "unknown format, not touched" item and is never rewritten. Test in Task 4.
2. **Cursor rewrites a file between scan and apply:** apply reloads each file and only removes entries that are still there, logging `SKIP` for the rest. Test in Task 5.
3. **Restore after Cursor changed the file again:** removed entries go back into the current file; a sandbox field reset is only undone if the field still holds the value the tool wrote. Test in Task 5.
4. **Project folders whose names contain `-`** (`my-app`): `~/.cursor/projects/home-user-code-my-app` resolves to the existing folder by probing the disk and is not marked stale. Test in Task 3.
5. **Symlinks and unreadable folders during the project walk:** no crash, no following symlinked dirs, `~/.cursor` itself is never treated as a normal project except for the documented `~/.cursor/.cursor/` case. Test in Task 4.

---

### Task 1: Repo skeleton, data model and shared helpers

**Files:**
- Create: `cursor_revoke.py`, `tests/test_cursor_revoke.py`, `LICENSE` (MIT, copy claude-revoke's with the same holder), `.gitignore` (copy claude-revoke's)

**Interfaces:**
- Produces:
  - Constants `HOME`, `CURSOR_DIR = HOME/".cursor"`, `CURSOR_USER_DIR = HOME/".config"/"Cursor"/"User"`, `PROJECTS_DIR = CURSOR_DIR/"projects"`, `GLOBAL_CLI = CURSOR_DIR/"cli-config.json"`, `QUARANTINE_ROOT = HOME/".cursor-revoke-quarantine"`.
  - Copied unchanged from claude-revoke: `load_json`, `as_dict`, `as_list`, `str_list`, `write_json_atomic` (tmp suffix `.cursor-revoke.tmp`), `short_home`, `split_name`, `human`, `fmt_date`, `parse_accent`, `Category`, `SKIP_DIRS`, `SKIP_ROOT_DIRS`.
  - `@dataclass Item`: claude-revoke's fields plus `file: str = ""` (JSON file edited, or folder moved), `jpath: list` (path inside the JSON to the container), `value: object = None` (list entry to remove, or dict key, or the new value for a reset), `op: str = ""` (one of `"drop_entry"`, `"pop_key"`, `"reset"`, `"move"`, `"harden"`, `""` for display-only), `locked: bool = False` (cannot be ticked).
  - Test base class `FakeHome(unittest.TestCase)` in the test file: patches the constants above to a temp dir, with helpers `write(rel, data)` (JSON) and `write_text(rel, text)`.

- [ ] **Step 1: Write failing tests** `TestFilePermissions.test_rewrite_keeps_private_file_private`, `test_new_file_is_private`, and `TestItem.test_locked_defaults_false` (`Item("allow", "Shell(ls)", "x").locked is False` and `.op == ""`).
- [ ] **Step 2: Run** `python3 -m unittest discover -s tests` - expect import error.
- [ ] **Step 3: Implement** the constants, helpers and `Item` above, plus a module docstring in claude-revoke's style describing cursor-revoke.
- [ ] **Step 4: Run** the tests - expect PASS.
- [ ] **Step 5: Commit** `git add cursor_revoke.py tests/test_cursor_revoke.py LICENSE .gitignore && git commit -m "Skeleton: data model and helpers"`

### Task 2: Risk rules (allow rules and sandbox fields)

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`

**Interfaces:**
- Produces:
  - `is_broad(rule: str) -> bool` for Cursor permission tokens.
  - `SANDBOX_DEFAULTS = {"type": "workspace_readwrite", "readBoundary": "system", "networkPolicy.default": "deny"}`
  - `sandbox_risks(data: dict) -> list[tuple[list, str, object, str]]`: one `(jpath, op, value, reason)` per risky field, where `op` is `"reset"` (value = default to write) or `"drop_entry"` (value = list entry to remove).

- [ ] **Step 1: Write failing tests**

```python
class TestIsBroad(unittest.TestCase):
    def test_broad(self):
        for r in ["Shell(*)", "Shell", "Shell(sudo)", "Shell(bash)", "Shell(curl)",
                  "Shell(python3)", "Read(**)", "Write(**)", "Write(~/**)",
                  "Read(~/.ssh/**)", "Read(/**)", "Mcp(*)", "Mcp(github:*)"]:
            self.assertTrue(cr.is_broad(r), r)
    def test_narrow(self):
        for r in ["Shell(ls)", "Shell(git)", "Read(src/**)", "Write(docs/*.md)", "Mcp(github:list_issues)"]:
            self.assertFalse(cr.is_broad(r), r)

class TestSandboxRisks(unittest.TestCase):
    def test_reference_install_file_is_fine(self):
        data = {"type": "workspace_readwrite", "readBoundary": "workspace", "additionalReadPaths": [],
                "disableTmpWrite": False, "networkPolicy": {"default": "deny", "allow": [], "deny": []}}
        self.assertEqual(cr.sandbox_risks(data), [])
    def test_wide_fields(self):
        data = {"type": "insecure_none", "networkPolicy": {"default": "allow", "allow": ["*", "pypi.org"]},
                "additionalReadwritePaths": ["~", "build"], "additionalReadPaths": ["~/.ssh"]}
        got = {(tuple(p), op, json.dumps(v)) for p, op, v, _ in cr.sandbox_risks(data)}
        self.assertEqual(got, {
            (("type",), "reset", '"workspace_readwrite"'),
            (("networkPolicy", "default"), "reset", '"deny"'),
            (("networkPolicy", "allow"), "drop_entry", '"*"'),
            (("additionalReadwritePaths",), "drop_entry", '"~"'),
            (("additionalReadPaths",), "drop_entry", '"~/.ssh"'),
        })
    def test_never_flags_stricter_or_default_values(self):
        self.assertEqual(cr.sandbox_risks({"type": "workspace_readonly", "readBoundary": "system",
                                           "disableTmpWrite": True}), [])
```

- [ ] **Step 2: Run** `python3 -m unittest tests.test_cursor_revoke.TestIsBroad tests.test_cursor_revoke.TestSandboxRisks` - expect FAIL.
- [ ] **Step 3: Implement.** `is_broad`: strip spaces; broad if the bare tool name, an arg of `*`/`**`, a path arg that is `/`, `~`, `/**`, `~/**`, or under `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config`, a `Shell(base)` whose base is in `{"sudo","su","bash","sh","zsh","fish","env","eval","xargs","python","python3","node","perl","ruby","curl","wget","rm","dd","chmod","chown"}`, or `Mcp(server:*)` / `Mcp(*)`. `sandbox_risks`: path-list entries are risky when they are `/`, `~`, the home folder or an ancestor of it, contain `**` at the root, or fall under the sensitive dirs above; network allow entries are risky when `*`, `*.*` or `0.0.0.0/0`. Ignore unknown keys.
- [ ] **Step 4: Run** the tests - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Risk rules for Cursor permissions and sandbox fields"`

### Task 3: Project data folders (`~/.cursor/projects`)

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`

**Interfaces:**
- Produces:
  - `encode_project(path: str) -> str`: every non-alphanumeric character to `-`, leading and trailing `-` stripped (`/home/user/code/my-app` -> `home-user-code-my-app`).
  - `known_folders() -> set[str]`: absolute paths from `CURSOR_USER_DIR/"workspaceStorage"/*/workspace.json` (`folder` file URIs) and `CURSOR_USER_DIR/"globalStorage"/"storage.json"` (`backupWorkspaces.folders[].folderUri`, `profileAssociations.workspaces` keys). JSON only; URL-decode `file://` URIs.
  - `resolve_project(name: str, known: set) -> str | None`: known match first, else disk probe (below).
  - `scan_projects() -> list[Item]`: kind `"projdir"`, op `"move"`, `file` = the folder.

- [ ] **Step 1: Write failing tests** in `TestProjects(FakeHome)`, each creating folders under `PROJECTS_DIR`:
  - `test_known_folder_that_exists_is_ok`: workspace.json points at an existing `<home>/code/app`; item has `stale=False, selected=False`.
  - `test_known_folder_that_is_gone_is_stale_and_ticked`: `stale=True, selected=True`, detail mentions the original path.
  - `test_dash_in_name_resolves_by_disk_probe`: `<home>/code/my-app` exists, no workspace.json; not stale (Review Focus 4).
  - `test_tmp_and_numeric_folders_are_stale`: `tmp-c317...` and `1792207849851` are `stale=True, selected=True`.
  - `test_unmatched_name_is_unknown_not_ticked`: `stale=False, selected=False`, badge `UNKNOWN`.
  - `test_empty_window_and_dot_folders`: `empty-window` is listed OK; names starting with `.` are not listed.
- [ ] **Step 2: Run** the tests - expect FAIL.
- [ ] **Step 3: Implement.** Disk probe for `resolve_project`, depth-first from `/`, splitting the name on `-`:

```python
def probe(base, parts, budget):
    # The encoding turned "/", "-", "." and "_" all into "-". Try taking the
    # next k parts as one path segment, rejoined with each separator, and
    # recurse on the rest. First full match wins.
    if not parts:
        return base
    for k in range(1, len(parts) + 1):
        seps = ("-",) if k == 1 else ("-", ".", "_")
        for sep in seps:
            budget[0] -= 1
            if budget[0] < 0:
                return None
            seg = base / sep.join(parts[:k])
            if seg.is_dir():
                found = probe(seg, parts[k:], budget)
                if found:
                    return found
    return None
```

  Call it as `probe(Path("/"), name.split("-"), [10000])`; past the budget it returns `None` (shown as UNKNOWN). Badges: `MISSING`, `TEMP`, `UNKNOWN`. Detail lists the subfolders present (`mcps`, `agent-transcripts`, `terminals`, `canvases`) and total size via the same walk claude-revoke uses for sessions.
- [ ] **Step 4: Run** - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Scan ~/.cursor/projects for stale agent data"`

### Task 4: File scanners and the project walk

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`

**Interfaces:**
- Consumes: `is_broad`, `sandbox_risks`, `scan_projects`, `Item`.
- Produces:
  - `find_cursor_dirs(roots: list) -> list[Path]`: every `<project>/.cursor` dir under the roots, same pruning as claude-revoke's `scan_settings`, `os.walk(followlinks=False)`. Skips `CURSOR_DIR` itself but includes `CURSOR_DIR/".cursor"` (labelled as the project `~/.cursor`).
  - `scan_cli(file: Path, scope: str) -> list[Item]` (`cli-config.json` global or `cli.json` project): kind `"allow"` (op `drop_entry`, jpath `["permissions","allow"]`), kind `"deny"` (locked, display only), kind `"approval"` (locked, risky when `approvalMode != "allowlist"`, detail "change this in Cursor's settings"), `"harden"` (global only, see Task 5).
  - `scan_autorun(file: Path, scope: str) -> list[Item]` (`permissions.json`): kind `"autorun"` for each `autoRun.allow_instructions` entry (risky, op `drop_entry`); one locked kind `"block"` item summarising block instructions. Any other top-level key holding a list of strings (Cursor's docs mention MCP and terminal allowlists; the exact key names are unverified) becomes an `"allow"`-style `drop_entry` item under its own jpath; anything else unrecognised is listed in the detail and left alone.
  - The global `harden` item (from `scan_cli` on `GLOBAL_CLI` only, when any `DENY_RULES` entry is missing) is titled `"HARDEN: stop the Cursor CLI agent reading keys and .env files"`, and its detail says it is confirmed for the CLI agent only.
  - `scan_sandbox(file: Path, scope: str) -> list[Item]`: one kind `"sandbox"` item per `sandbox_risks` entry (risky, op from the tuple); if none, one locked OK item "sandbox settings at or stricter than Cursor's defaults".
  - `scan_mcp(file: Path, scope: str) -> list[Item]`: kind `"mcp"`, op `pop_key`, jpath `["mcpServers"]`, value = server name, risky, detail shows command+args or url.
  - `scan_hooks(file: Path, scope: str) -> list[Item]`: kind `"hook"`, op `pop_key`, jpath `["hooks"]`, value = event name, risky, detail shows the commands.
  - `scan_all(roots: list) -> list[Category]` with four categories in this order: "Agent permissions" (allow, deny, approval, autorun, block, harden), "Sandbox settings", "MCP servers and hooks", "Project data folders". Global files come first, then each project dir sorted by path.
  - Every scanner: if `load_json` returns something that is not a dict, emit one locked item kind `"unknown"`, title `"<file>: unknown format, not touched"`, and nothing else for that file.

- [ ] **Step 1: Write failing tests** in `TestScan(FakeHome)` using the real shapes from the spec's "Real file shapes" section:
  - `test_reference_install`: the three reference files give exactly one `allow` item `Shell(ls)` (not risky), one locked `approval` item (not risky), one locked `block` item, one locked OK sandbox item, and no `unknown` items.
  - `test_project_files_are_found_and_labelled`: `<home>/code/app/.cursor/{cli.json,permissions.json,sandbox.json,mcp.json,hooks.json}` each produce items whose `file` is that path and whose `where` names `~/code/app`.
  - `test_jsonc_file_is_unknown_and_untouched` (Review Focus 1): `mcp.json` containing `{"mcpServers": {}, // note\n}` gives one locked `unknown` item; its bytes are unchanged after `scan_all`.
  - `test_walk_skips_symlinks_and_unreadable` (Review Focus 5): a symlink `<home>/link -> <home>/code` and a `0o000` folder; `find_cursor_dirs` returns each real `.cursor` once and does not raise.
  - `test_dot_cursor_inside_global_dir`: `<home>/.cursor/.cursor/sandbox.json` is scanned as project `~/.cursor`; `<home>/.cursor` itself is not listed as a project.
- [ ] **Step 2: Run** - expect FAIL.
- [ ] **Step 3: Implement** the functions above. Titles follow claude-revoke's tone, for example `"allow rule: Shell(curl)"`, `"MCP server: github"`, `"sandbox: network default allow"`; `where` is `"global"` or the short project path.
- [ ] **Step 4: Run** - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Scan Cursor permission, sandbox, MCP and hook files"`

### Task 5: Apply, harden and restore

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`

**Interfaces:**
- Consumes: items from Task 4 with `file`, `jpath`, `value`, `op`.
- Produces:
  - `DENY_RULES = ["Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.gnupg/**)", "Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)"]`, written to `GLOBAL_CLI` `permissions.deny`.
  - `describe(it: Item) -> str` for every op-bearing kind.
  - `apply_plan(plan: list[Item]) -> list[str]` (log lines, same format as claude-revoke).
  - `put_back(data: dict, e: dict) -> bool` and `restore(qdir)` as in claude-revoke, plus one new manifest edit form: `{"file", "path", "was", "now"}` for `reset`, undone only when the current value equals `now`.

- [ ] **Step 1: Write failing tests** in `TestApply(FakeHome)`:
  - `test_round_trip_restores_everything`: tick one item of every op across global and project files plus one projdir; after apply each is gone and a backup exists; after `restore` every file equals the original JSON and the folder is back.
  - `test_locked_items_are_ignored`: a plan containing `deny`, `approval`, `block`, `unknown` items changes no file.
  - `test_entry_removed_by_cursor_meanwhile_is_skipped` (Review Focus 2): scan, then delete the rule from the file, then apply; log contains `SKIP`, file still valid, no manifest edit recorded for it.
  - `test_file_turned_invalid_meanwhile_is_not_written`: scan, then write `{bad` into the file, then apply; file bytes unchanged, log has `SKIP ... unreadable`.
  - `test_restore_undoes_untouched_reset`: sandbox `type` `insecure_none` is reset to `workspace_readwrite`; restore with the file untouched puts `insecure_none` back.
  - `test_restore_keeps_newer_changes` (Review Focus 3): same reset, then the user sets `type` to `workspace_readonly` and adds `networkPolicy.allow: ["pypi.org"]`; after restore `type` is still `workspace_readonly` and `pypi.org` is still there.
  - `test_sandbox_file_is_never_moved`: after applying sandbox items the file still exists at its path.
  - `test_harden_adds_deny_rules_and_keeps_existing`: existing deny `Read(secret.txt)` stays; all `DENY_RULES` present once; restore removes only the added ones.
  - `test_quarantine_folders_are_private`: modes `0o700`.
- [ ] **Step 2: Run** - expect FAIL.
- [ ] **Step 3: Implement.** Group the plan by `file`; for each file back it up once, reload it, skip the whole group with a `SKIP <file>: unreadable` line if it is not a dict, then apply each item by op, recording a manifest edit only when something changed: `drop_entry` -> `{"append": value}`, `pop_key` -> `{"set": old}` with path `jpath + [value]`, `reset` -> `{"was": old, "now": value}`, `harden` -> `{"remove": added}`. Create missing containers for `harden` only. `move` items go through claude-revoke's move-into-quarantine code with subfolder `projects`.
- [ ] **Step 4: Run** - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Apply and restore with per-file JSON edits"`

### Task 6: Command line, report and running-Cursor warning

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`

**Interfaces:**
- Consumes: `scan_all`, `apply_plan`, `restore`.
- Produces: `print_report(cats, only)`, `summarize(cats)`, `running_cursor() -> list[int]`, `main()` and `run(args, ap)` with exactly claude-revoke's flags: `--report`, `--only {all,stale,risky}`, `--dry-run`, `--restore DIR`, `--roots`, `--accent`, `--pause`, `--version`, `--notify`, `--schedule {weekly,daily,off}`. Env `CURSOR_REVOKE_ACCENT`.

- [ ] **Step 1: Write failing tests** (subprocess with `CURSOR_REVOKE_HOME` set to the temp home): `test_report_lists_categories_and_legend`, `test_report_only_risky_hides_ok_items`, `test_version_prints_0_1_0`, `test_report_never_writes` (file mtimes unchanged, no quarantine dir), `test_report_does_not_touch_sqlite` (a `state.vscdb` made unreadable with `0o000` causes no error).
- [ ] **Step 2: Run** - expect FAIL.
- [ ] **Step 3: Implement.** Port claude-revoke's `print_report`, `summarize`, `main`, `run`. `running_cursor()` scans `/proc/*/comm` and `cmdline` for a process named `cursor` or an argv[0] ending in `/cursor`, `/Cursor` or `.AppImage` with `cursor` in the name; print a warning before the TUI and before apply, never block. Report legend: `! risky   ~ stale   # locked (shown only)`.
- [ ] **Step 4: Run** - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "CLI, report and running-Cursor warning"`

### Task 7: TUI

**Files:**
- Modify: `cursor_revoke.py`

**Interfaces:**
- Consumes: `scan_all`, `describe`, `apply_plan`, `show_in`, `Item.locked`.

- [ ] **Step 1: Port** claude-revoke's `App` class and curses setup, replacing names and help text. Changes: Space, `a`, `s`, `r` never tick a `locked` item; locked rows are drawn dim with a `#` marker; the review screen and apply only see unlocked selected items; the apply confirmation repeats the running-Cursor warning when `running_cursor()` is non-empty.
- [ ] **Step 2: Add test** `TestTui.test_bulk_tick_skips_locked`: extract the tick logic into module-level `tick(items: list, pred, on: bool) -> int` (sets `selected` on unlocked items matching `pred`, returns how many changed) and have `App` call it; assert ticking all leaves locked items unselected and returns the unlocked count.
- [ ] **Step 3: Run** all tests - expect PASS.
- [ ] **Step 4: Manual check** in a real terminal: `CURSOR_REVOKE_HOME=<temp home with fixtures> python3 cursor_revoke.py --dry-run`, walk every category, tick, review, type `YES`, confirm the dry-run log. Then `python3 cursor_revoke.py --report` against the real home and compare with the spec's reference install.
- [ ] **Step 5: Commit** `git commit -m "Checklist TUI"`

### Task 8: Scheduled audit

**Files:**
- Modify: `cursor_revoke.py`, `tests/test_cursor_revoke.py`
- Create: `packaging/cursor-revoke-audit.service.in`, `packaging/cursor-revoke-audit.timer`

- [ ] **Step 1: Port** claude-revoke's schedule/notify tests with names swapped (`TIMER = "cursor-revoke-audit.timer"`, state under `cursor-revoke`).
- [ ] **Step 2: Run** - expect FAIL.
- [ ] **Step 3: Port** `config_dir`, `state_dir`, `send_notification`, `schedule` and the two unit files. Notification text: "Cursor: 2 stale, 1 risky. Run cursor-revoke to review."
- [ ] **Step 4: Run** - expect PASS.
- [ ] **Step 5: Commit** `git commit -m "Scheduled audit with desktop notification"`

### Task 9: Install scripts, packages and CI

**Files:**
- Create: `install.sh`, `uninstall.sh`, `packaging/build.sh`, `packaging/nfpm.yaml`, `packaging/cursor-revoke.desktop.in`, `.github/workflows/ci.yml`, `tests/test_install_scripts.py`, `tests/test_packaging.py`, `assets/logo.svg`

- [ ] **Step 1: Port** claude-revoke's install-script and packaging tests with names swapped.
- [ ] **Step 2: Run** - expect FAIL.
- [ ] **Step 3: Port** every file above from claude-revoke following its 2026-10-10 packaging design, swapping `claude` for `cursor` in names, the description ("Audit and revoke Cursor agent access on Linux") and the homepage (`https://github.com/atraxsrc/cursor-revoke`). New logo in the same style, distinct accent.
- [ ] **Step 4: Run** all tests and `packaging/build.sh` if nfpm is available - expect PASS and three packages plus `SHA256SUMS` in `dist/`.
- [ ] **Step 5: Commit** `git commit -m "Install scripts, packages and CI"`

### Task 10: README and release notes

**Files:**
- Create: `README.md`, `CHANGELOG.md`, `assets/banner.svg`, screenshots (`assets/screenshot-*.svg`)

- [ ] **Step 1: Write** the README in claude-revoke's layout: features, install, usage, keys, scheduled audits, theme, a "What it reads and changes" table matching the spec, limitations. Must say: v1 does not read chat history; hardening covers the Cursor CLI agent only; Cursor's formats change between versions so run `--report` first; close Cursor before applying; link claude-revoke under "See also" (and add a matching link in claude-revoke's README in a separate commit there).
- [ ] **Step 2: Write** `CHANGELOG.md` with a `0.1.0` entry.
- [ ] **Step 3: Verify** `grep -nP '[\x{2013}\x{2014}]' -r . --exclude-dir=.git` prints nothing, and the full test suite passes.
- [ ] **Step 4: Commit** `git commit -m "Release 0.1.0"`. Do not push or tag; the author does that.
