#!/usr/bin/env python3
"""
cursor-revoke - audit and revoke Cursor access on Linux.

An installer-style terminal UI in reverse: it scans everything Cursor (the
editor and its CLI agent) has left behind (auto-approve rules, trusted
folders, project state, MCP servers, sandbox settings), lets you tick what to
remove, and QUARANTINES it instead of deleting, so every run can be undone.

Needs only the Python 3 standard library. Close Cursor before applying
changes (it rewrites its config files while running).
"""
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "0.1.0"

# CURSOR_REVOKE_HOME lets you point the tool at a test home folder.
HOME = Path(os.environ.get("CURSOR_REVOKE_HOME", str(Path.home()))).expanduser()
CURSOR_DIR = HOME / ".cursor"
CURSOR_USER_DIR = HOME / ".config" / "Cursor" / "User"
PROJECTS_DIR = CURSOR_DIR / "projects"
GLOBAL_CLI = CURSOR_DIR / "cli-config.json"
QUARANTINE_ROOT = HOME / ".cursor-revoke-quarantine"

# Bar/accent color = an index into YOUR terminal theme's palette (0-15), so the
# UI always matches the theme. Names: black red green yellow blue magenta cyan
# white, prefix "bright-" for 8-15. Set with --accent or CURSOR_REVOKE_ACCENT.
PALETTE = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"]


def parse_accent(v):
    v = str(v).strip().lower()
    if v.isdigit() and 0 <= int(v) <= 15:
        return int(v)
    bright = v.startswith("bright-")
    name = v[7:] if bright else v
    if name in PALETTE:
        return PALETTE.index(name) + (8 if bright else 0)
    raise ValueError(f"unknown color '{v}' (use 0-15 or e.g. blue, bright-cyan)")


ACCENT = 4

SKIP_DIRS = {
    "node_modules", ".git", ".cache", ".npm", ".cargo", ".rustup", ".venv", "venv",
    "__pycache__", ".cursor-revoke-quarantine", "Trash",
    ".local", ".mozilla", ".steam", "snap",
}
# Only skipped directly under / ("dev" or "run" deeper down can be real projects).
SKIP_ROOT_DIRS = {"proc", "sys", "dev", "run"}


# --------------------------------------------------------------------------- model
@dataclass
class Item:
    kind: str          # what sort of finding this is (set by the scanners)
    key: str           # what the action acts on (path, rule, server name)
    title: str
    badge: str = ""
    detail: list = field(default_factory=list)
    risky: bool = False
    stale: bool = False
    selected: bool = False
    size: int = 0
    name: str = ""     # short display name (folder name)
    where: str = ""    # parent location, shown dimmer
    file: str = ""     # JSON file edited, or folder moved
    jpath: list = field(default_factory=list)   # path inside the JSON to the container
    value: object = None   # list entry to remove, or dict key, or the new value for a reset
    op: str = ""       # drop_entry | pop_key | reset | move | harden | "" (display only)
    locked: bool = False   # cannot be ticked

    def __post_init__(self):
        if not self.name:
            self.name, self.where = split_name(self.title)


@dataclass
class Category:
    name: str
    help: str
    items: list


# --------------------------------------------------------------------------- helpers
def load_json(p):
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# Cursor's files are hand-editable, so any key can hold the wrong type.
def as_dict(v):
    return v if isinstance(v, dict) else {}


def as_list(v):
    return v if isinstance(v, list) else []


def str_list(v):
    return [x for x in as_list(v) if isinstance(x, str)]


SANDBOX_DEFAULTS = {"type": "workspace_readwrite", "readBoundary": "system",
                    "networkPolicy.default": "deny"}
SANDBOX_PATH_KEYS = ("additionalReadwritePaths", "additionalReadonlyPaths", "additionalReadPaths")
SENSITIVE_DIRS = ("~/.ssh", "~/.aws", "~/.gnupg", "~/.config")
RISKY_SHELL_BASES = {"sudo", "su", "bash", "sh", "zsh", "fish", "env", "eval", "xargs",
                     "python", "python3", "node", "perl", "ruby", "curl", "wget", "rm",
                     "dd", "chmod", "chown"}


def broad_path(p):
    """True for a path that reaches the whole disk, the home folder (or a parent
    of it) or a credentials folder. Relative project paths are fine."""
    p = p.strip()
    home = str(HOME).rstrip("/")
    if home and (p == home or p.startswith(home + "/")):
        p = "~" + p[len(home):]
    if p in ("", "/", "~", "~/", "**", "/**", "~/**", "*"):
        return True
    if p.startswith("/") and not p.startswith("~"):
        flat = p.rstrip("/*")
        if flat == "" or home == flat or home.startswith(flat + "/"):
            return True
    return any(p == d or p.startswith(d + "/") for d in SENSITIVE_DIRS)


def is_broad(rule):
    """True for a Cursor permission token that grants too much."""
    r = rule.replace(" ", "")
    m = re.fullmatch(r"(\w+)(?:\((.*)\))?", r, re.S)
    if not m:
        return False
    tool, arg = m.group(1), m.group(2)
    if tool in ("Shell", "Read", "Write", "Mcp"):
        if arg is None or arg in ("*", "**", ":*"):
            return True
    if tool == "Shell":
        base = re.split(r"[:\s]", rule.strip()[6:-1].strip(), 1)[0]
        return base in RISKY_SHELL_BASES
    if tool in ("Read", "Write"):
        return broad_path(arg)
    if tool == "Mcp":
        return arg.endswith(":*")
    return False


def sandbox_risks(data):
    """Risky sandbox fields as (jpath, op, value, reason). op is "reset"
    (value = default to write) or "drop_entry" (value = entry to remove)."""
    out = []
    data = as_dict(data)
    if data.get("type") == "insecure_none":
        out.append((["type"], "reset", SANDBOX_DEFAULTS["type"],
                    "sandbox is switched off"))
    net = as_dict(data.get("networkPolicy"))
    if net.get("default") == "allow":
        out.append((["networkPolicy", "default"], "reset", "deny",
                    "all network traffic is allowed by default"))
    for e in str_list(net.get("allow")):
        if e.strip() in ("*", "*.*", "0.0.0.0/0"):
            out.append((["networkPolicy", "allow"], "drop_entry", e,
                        "allows network access to every host"))
    for key in SANDBOX_PATH_KEYS:
        for e in str_list(data.get(key)):
            if broad_path(e):
                out.append(([key], "drop_entry", e,
                            "gives the sandbox access to the home folder or secrets"))
    return out


def write_json_atomic(p, data):
    # Keep the original file's permissions (config files are often 0600);
    # files that don't exist yet are created private.
    try:
        mode = os.stat(p).st_mode & 0o777
    except OSError:
        mode = 0o600
    tmp = Path(str(p) + ".cursor-revoke.tmp")
    try:
        os.unlink(tmp)   # a stale (or planted) temp path; never write through it
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
        os.fchmod(fh.fileno(), mode)
    os.replace(tmp, p)


def short_home(p):
    p = str(p)
    for home in {str(HOME), str(Path.home())}:
        if p == home:
            return "~"
        if p.startswith(home + "/"):
            return "~" + p[len(home):]
    return p


def split_name(title):
    """'/home/me/code/app  [settings.json]' -> ('app [settings.json]', '~/code')"""
    m = re.match(r"^(/[^\s]*)(.*)$", title)
    if not m:
        return title, ""
    path, rest = m.group(1).rstrip("/"), m.group(2).strip()
    name = (os.path.basename(path) or path) + (" " + rest if rest else "")
    return name, short_home(os.path.dirname(path))


def human(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def fmt_date(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts)) if ts else "?"


# --------------------------------------------------------------------------- projects
PROJECT_SUBDIRS = ("mcps", "agent-transcripts", "terminals", "canvases")
TEMP_NAME = re.compile(r"tmp-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                       re.I)


def safe_is_dir(p):
    try:
        return Path(p).is_dir()
    except OSError:
        return False


def path_state(p):
    """"exists", "missing" or "unknown" (cannot be checked, e.g. no permission)."""
    try:
        os.stat(p)
        return "exists"
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except (OSError, ValueError):
        return "unknown"


def encode_project(path):
    """Cursor names a project's data folder after its path: every character that
    is not a letter or digit becomes '-', and leading/trailing '-' are dropped."""
    return re.sub(r"[^A-Za-z0-9]", "-", str(path)).strip("-")


def file_uri_path(uri):
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    path = urllib.parse.unquote(urllib.parse.urlsplit(uri).path)
    return path.rstrip("/") or None if path.startswith("/") else None


def known_folders():
    """Project folders Cursor knows about, from its JSON state files only."""
    out = set()
    uris = []
    ws = CURSOR_USER_DIR / "workspaceStorage"
    try:
        files = sorted(ws.glob("*/workspace.json"))
    except OSError:
        files = []
    for f in files:
        uris.append(as_dict(load_json(f)).get("folder"))
    st = as_dict(load_json(CURSOR_USER_DIR / "globalStorage" / "storage.json"))
    for e in as_list(as_dict(st.get("backupWorkspaces")).get("folders")):
        uris.append(as_dict(e).get("folderUri"))
    uris += list(as_dict(as_dict(st.get("profileAssociations")).get("workspaces")))
    for u in uris:
        p = file_uri_path(u)
        if p:
            out.add(p)
    return out


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
            if safe_is_dir(seg):
                found = probe(seg, parts[k:], budget)
                if found:
                    return found
    return None


def resolve_project(name, known):
    for k in known:
        if encode_project(k) == name:
            return k
    found = probe(Path("/"), name.split("-"), [10000])
    return str(found) if found else None


def folder_stats(d):
    """(files, bytes) under d. Symlinks are counted as links, never followed."""
    files = size = 0
    for dirpath, _, names in os.walk(d, onerror=lambda e: None, followlinks=False):
        for n in names:
            try:
                size += os.lstat(os.path.join(dirpath, n)).st_size
                files += 1
            except OSError:
                continue
    return files, size


def scan_projects():
    items = []
    try:
        dirs = sorted(d for d in PROJECTS_DIR.iterdir()
                      if not d.name.startswith(".") and d.is_dir() and not d.is_symlink())
    except OSError:
        return items
    known = known_folders()
    for d in dirs:
        name = d.name
        orig, status, stale, unchecked = None, "", False, False
        if name == "empty-window":
            pass
        elif TEMP_NAME.fullmatch(name) or name.isdigit():
            status, stale = "TEMP", True
        else:
            orig = resolve_project(name, known)
            if orig is None:
                status = "UNKNOWN"
            else:
                state = path_state(orig)
                if state == "missing":
                    status, stale = "MISSING", True
                elif state == "unknown":
                    status, unchecked = "UNKNOWN", True
        files, size = folder_stats(d)
        present = [s for s in PROJECT_SUBDIRS if safe_is_dir(d / s)]
        detail = [f"Data folder: {d}"]
        if unchecked:
            detail.append(f"Project: {orig}   [could not be checked, no permission]")
        elif status == "UNKNOWN":
            detail.append("unknown, folder not found")
        elif status == "TEMP":
            detail.append("temporary or empty-window project, no folder behind it")
        elif orig:
            detail.append(f"Project: {orig}" + ("   [no longer exists]" if stale else ""))
        detail.append("Holds: " + (", ".join(present) if present else "nothing known")
                      + f"  ({files} files, {human(size)})")
        badge = f"{human(size):>7}" + (f"  {status}" if status else "")
        title = orig or name
        items.append(Item("projdir", str(d), title, badge, detail, stale=stale,
                          selected=stale, size=size, name=name,
                          where=short_home(Path(orig).parent) if orig else short_home(PROJECTS_DIR),
                          file=str(d), op="move"))
    return items


# --------------------------------------------------------------------------- config files
DENY_RULES = ["Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.gnupg/**)", "Read(**/.env)",
              "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)"]
PROJECT_FILES = ("cli.json", "permissions.json", "sandbox.json", "mcp.json", "hooks.json")


def find_cursor_dirs(roots):
    """Every real <project>/.cursor dir under the roots, sorted. ~/.cursor itself
    is the global folder, but ~/.cursor/.cursor is the project ~/.cursor's."""
    found = {}

    def add(cdir):
        try:
            if cdir.is_symlink() or not cdir.is_dir():
                return
            real = cdir.resolve()
        except (OSError, RuntimeError):
            return
        if real == global_dir:
            return
        found.setdefault(real, cdir)

    try:
        global_dir = CURSOR_DIR.resolve()
    except (OSError, RuntimeError):
        global_dir = CURSOR_DIR
    for root in roots:
        root = Path(root).expanduser()
        for dirpath, dirnames, _ in os.walk(root, onerror=lambda e: None, followlinks=False):
            skip = SKIP_DIRS | SKIP_ROOT_DIRS if dirpath == "/" else SKIP_DIRS
            dirnames[:] = [d for d in dirnames if d not in skip]
            if ".cursor" in dirnames:
                dirnames.remove(".cursor")
                add(Path(dirpath) / ".cursor")
    add(CURSOR_DIR / ".cursor")
    return sorted(found.values())


def load_config(file):
    """(data, items): items holds one locked "unknown" item when the file exists
    but is not a JSON object (JSONC, broken, unreadable). Missing file: (None, [])."""
    data = load_json(file)
    if isinstance(data, dict):
        return data, []
    if data is None and path_state(file) == "missing":
        return None, []
    return None, [unknown_item(file, None)]


def unknown_item(file, scope, what=""):
    title = f"{short_home(file)}: {what + ' ' if what else ''}unknown format, not touched"
    return Item("unknown", f"{file}::unknown", title,
                detail=[f"File: {file}",
                        "Not a plain JSON object (comments, trailing commas or a wrong type?).",
                        "cursor-revoke never rewrites a file it cannot parse."],
                name=title, where=scope or "", file=str(file), locked=True)


def mk(kind, file, scope, jpath, value, title, **kw):
    kw.setdefault("key", f"{file}::{'/'.join(jpath)}::{value}")
    return Item(kind, kw.pop("key"), title, name=title, where=scope, file=str(file),
                jpath=list(jpath), value=value, **kw)


def unique(entries):
    return list(dict.fromkeys(entries))


def scan_cli(file, scope):
    """cli-config.json (global) or <project>/.cursor/cli.json."""
    data, items = load_config(file)
    if items:
        items[0].where = scope
        return items
    is_global = Path(file) == Path(GLOBAL_CLI)
    if data is None and not is_global:
        return []
    data = data or {}
    where = f"In {file}" + (" (applies in every project)" if is_global else "")
    perms = as_dict(data.get("permissions"))
    for r in unique(str_list(perms.get("allow"))):
        broad = is_broad(r)
        items.append(mk("allow", file, scope, ["permissions", "allow"], r, f"allow rule: {r}",
                        badge="BROAD" if broad else "", risky=broad, op="drop_entry",
                        detail=[where, "The agent may do this without asking."
                                + ("  This rule grants a lot." if broad else "")]))
    deny = str_list(perms.get("deny"))
    for r in unique(deny):
        items.append(mk("deny", file, scope, ["permissions", "deny"], r, f"deny rule: {r}",
                        locked=True, detail=[where, "Protective rule, shown for completeness. Never removed."]))
    if "approvalMode" in data:
        mode = data.get("approvalMode")
        risky = mode != "allowlist"
        items.append(mk("approval", file, scope, ["approvalMode"], mode, f"approval mode: {mode}",
                        badge="RISKY" if risky else "", risky=risky, locked=True,
                        detail=[where, "Only \"allowlist\" is known to ask before running other commands."
                                if risky else "Agent asks before anything outside the allow list.",
                                "change this in Cursor's settings (cursor-revoke does not rewrite it)"]))
    if is_global:
        missing = [r for r in DENY_RULES if r not in deny]
        if missing:
            items.append(mk("harden", file, scope, ["permissions", "deny"], missing,
                            "HARDEN: stop the Cursor CLI agent reading keys and .env files",
                            badge=f"+{len(missing)} rules", op="harden",
                            detail=[f"Adds deny rules to {file} (does not remove anything).",
                                    "Confirmed for the Cursor CLI agent only; it may not protect "
                                    "the editor or the Agents Window."] + missing))
    return items


def scan_autorun(file, scope):
    """permissions.json: auto-run allow/block instructions and other allowlists."""
    data, items = load_config(file)
    if items:
        items[0].where = scope
        return items
    if data is None:
        return []
    where = f"In {file}"
    other = []
    for key, val in data.items():
        if key == "autoRun" and isinstance(val, dict):
            for sub in val:
                if sub not in ("allow_instructions", "block_instructions"):
                    other.append(f"autoRun.{sub}")
            for e in unique(str_list(val.get("allow_instructions"))):
                items.append(mk("autorun", file, scope, ["autoRun", "allow_instructions"], e,
                                f"auto-run rule: {e}", badge="AUTO-RUN", risky=True, op="drop_entry",
                                detail=[where, "The agent runs matching commands without asking."]))
            block = str_list(val.get("block_instructions"))
            if block:
                items.append(mk("block", file, scope, ["autoRun", "block_instructions"], len(block),
                                f"auto-run block rules: {len(block)}", locked=True,
                                detail=[where, "Protective rules, shown for completeness. Never removed."]
                                + [f"  {b}" for b in block[:5]]
                                + ([f"  ... and {len(block) - 5} more"] if len(block) > 5 else [])))
        elif (isinstance(val, list) and val and all(isinstance(e, str) for e in val)):
            # Key names are unverified. A block/deny list is protective: show, never remove.
            protective = any(w in key.lower() for w in ("block", "deny", "disallow"))
            for e in unique(val):
                if protective:
                    items.append(mk("block", file, scope, [key], e, f"{key}: {e}", locked=True,
                                    detail=[where, "Protective rule, shown for completeness. Never removed."]))
                else:
                    items.append(mk("allow", file, scope, [key], e, f"{key}: {e}", badge="AUTO-RUN",
                                    risky=True, op="drop_entry",
                                    detail=[where, "Allowlist entry: the agent may use this without asking."]))
        elif not (isinstance(val, list) and not val):
            other.append(key)
    if other:
        items.append(mk("other", file, scope, [], None, f"other keys left alone: {', '.join(other)}",
                        key=f"{file}::other", locked=True,
                        detail=[where, "Not recognised, so not touched: " + ", ".join(other)]))
    return items


def sandbox_title(data, jpath, value):
    if jpath == ["type"]:
        return f"sandbox: type {data.get('type')} (sandbox off)"
    if jpath == ["networkPolicy", "default"]:
        return "sandbox: network default allow"
    if jpath == ["networkPolicy", "allow"]:
        return f"sandbox: network allow {value}"
    return f"sandbox: {jpath[-1]} {value}"


def scan_sandbox(file, scope):
    data, items = load_config(file)
    if items:
        items[0].where = scope
        return items
    if data is None:
        return []
    where = f"In {file}"
    for jpath, op, value, reason in sandbox_risks(data):
        fix = (f"Removing resets it to Cursor's default: {value}" if op == "reset"
               else "Removing drops just this entry.")
        items.append(mk("sandbox", file, scope, jpath, value, sandbox_title(data, jpath, value),
                        badge="WIDE", risky=True, op=op, detail=[where, reason, fix]))
    if not items:
        items.append(mk("sandbox", file, scope, [], None,
                        "sandbox settings at or stricter than Cursor's defaults",
                        key=f"{file}::ok", locked=True,
                        detail=[where, "Nothing wider than Cursor's defaults. Never deleted: "
                                "removing a stricter file would widen access."]))
    return items


def scan_mcp(file, scope):
    data, items = load_config(file)
    if items:
        items[0].where = scope
        return items
    if data is None:
        return []
    servers = data.get("mcpServers", {})
    if not isinstance(servers, dict):
        return [unknown_item(file, scope, "mcpServers")]
    for name, cfg in servers.items():
        cfg = as_dict(cfg)
        if cfg.get("url"):
            runs = f"URL: {cfg.get('url')}"
        else:
            args = " ".join(str(a) for a in as_list(cfg.get("args")))
            runs = f"Runs: {cfg.get('command') or '?'} {args}".rstrip()
        items.append(mk("mcp", file, scope, ["mcpServers"], name, f"MCP server: {name}",
                        risky=True, op="pop_key",
                        detail=[f"In {file}", runs, "The agent can call this server's tools."]))
    return items


def scan_hooks(file, scope):
    data, items = load_config(file)
    if items:
        items[0].where = scope
        return items
    if data is None:
        return []
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        return [unknown_item(file, scope, "hooks")]
    for event, entries in hooks.items():
        cmds = []
        for e in as_list(entries):
            if isinstance(e, str):
                cmds.append(e)
            elif isinstance(as_dict(e).get("command"), str):
                cmds.append(e["command"])
        shown = [f"  {c}" for c in cmds] or ["  " + json.dumps(entries)[:300]]
        items.append(mk("hook", file, scope, ["hooks"], event, f"hook: {event}",
                        risky=True, op="pop_key",
                        detail=[f"In {file}", "Runs commands automatically on this Cursor event:"]
                        + shown))
    return items


def scan_all(roots):
    perm, sand, mcp = [], [], []
    files = [("global", GLOBAL_CLI, CURSOR_DIR / "permissions.json", CURSOR_DIR / "sandbox.json",
              CURSOR_DIR / "mcp.json", CURSOR_DIR / "hooks.json")]
    for d in find_cursor_dirs(roots):
        files.append((short_home(d.parent),) + tuple(d / n for n in PROJECT_FILES))
    for scope, cli, perms, sandbox, mcpf, hooks in files:
        perm += scan_cli(cli, scope) + scan_autorun(perms, scope)
        sand += scan_sandbox(sandbox, scope)
        mcp += scan_mcp(mcpf, scope) + scan_hooks(hooks, scope)
    return [
        Category("Agent permissions",
                 "Allow, deny and auto-run rules for Cursor's agent (cli-config.json, cli.json, permissions.json)",
                 perm),
        Category("Sandbox settings",
                 "What sandboxed agent commands may read, write and reach (sandbox.json)", sand),
        Category("MCP servers and hooks",
                 "Servers the agent can call and commands Cursor runs automatically", mcp),
        Category("Project data folders",
                 "Per-project agent data: MCP descriptors, terminals, transcripts (~/.cursor/projects)",
                 scan_projects()),
    ]
