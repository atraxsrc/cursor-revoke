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
