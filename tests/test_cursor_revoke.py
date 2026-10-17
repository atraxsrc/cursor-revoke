"""Tests for cursor_revoke, run against a throwaway home folder.

    python3 -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "cursor_revoke.py"

sys.path.insert(0, str(ROOT))
import cursor_revoke as cr  # noqa: E402


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


class FakeHome(unittest.TestCase):
    """Points every path constant in cursor_revoke at a temp home folder."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self._saved = {}
        paths = {
            "HOME": self.home,
            "CURSOR_DIR": self.home / ".cursor",
            "CURSOR_USER_DIR": self.home / ".config" / "Cursor" / "User",
            "PROJECTS_DIR": self.home / ".cursor" / "projects",
            "GLOBAL_CLI": self.home / ".cursor" / "cli-config.json",
            "QUARANTINE_ROOT": self.home / ".cursor-revoke-quarantine",
        }
        for name, value in paths.items():
            self._saved[name] = getattr(cr, name)
            setattr(cr, name, value)

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(cr, name, value)
        self._tmp.cleanup()

    def write(self, rel, data, perms=0o644):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))
        os.chmod(p, perms)
        return p

    def write_text(self, rel, text, perms=0o644):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(p, perms)
        return p

    def latest_quarantine(self):
        return next(cr.QUARANTINE_ROOT.iterdir())

    def restore_latest(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            cr.restore(self.latest_quarantine())
        return out.getvalue()

    def manifest(self):
        return cr.load_json(self.latest_quarantine() / "manifest.json")


class TestFilePermissions(FakeHome):
    def test_rewrite_keeps_private_file_private(self):
        p = self.write(".cursor/cli-config.json", {"permissions": {}}, perms=0o600)
        cr.write_json_atomic(p, {"permissions": {}})
        self.assertEqual(mode(p), 0o600)

    def test_new_file_is_private(self):
        p = self.home / "new.json"
        cr.write_json_atomic(p, {})
        self.assertEqual(mode(p), 0o600)

    def test_symlink_at_tmp_path_is_not_followed(self):
        p = self.write("a.json", {"old": 1}, perms=0o600)
        target = self.write_text("victim.txt", "keep me", perms=0o644)
        os.symlink(target, str(p) + ".cursor-revoke.tmp")
        cr.write_json_atomic(p, {"new": 2})
        self.assertEqual(target.read_text(), "keep me")
        self.assertEqual(mode(target), 0o644)
        self.assertEqual(json.loads(p.read_text()), {"new": 2})
        self.assertEqual(mode(p), 0o600)


class TestItem(unittest.TestCase):
    def test_locked_defaults_false(self):
        it = cr.Item("allow", "Shell(ls)", "x")
        self.assertIs(it.locked, False)
        self.assertEqual(it.op, "")
        self.assertEqual(it.jpath, [])


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


class TestProjects(FakeHome):
    def proj(self, name):
        d = cr.PROJECTS_DIR / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "mcps").mkdir(exist_ok=True)
        (d / "mcps" / "x.json").write_text("{}")
        return d

    def only(self, name):
        got = [i for i in cr.scan_projects() if i.name == name]
        self.assertEqual(len(got), 1, [i.name for i in cr.scan_projects()])
        return got[0]

    def workspace(self, folder_uri, n="a"):
        self.write(f".config/Cursor/User/workspaceStorage/{n}/workspace.json", {"folder": folder_uri})

    def test_known_folder_that_exists_is_ok(self):
        app = self.home / "code" / "app"
        app.mkdir(parents=True)
        self.workspace("file://" + str(app))
        self.proj(cr.encode_project(str(app)))
        it = self.only(cr.encode_project(str(app)))
        self.assertEqual((it.stale, it.selected), (False, False))
        self.assertEqual((it.kind, it.op), ("projdir", "move"))
        self.assertEqual(it.file, str(cr.PROJECTS_DIR / it.name))
        self.assertGreater(it.size, 0)

    def test_known_folder_that_is_gone_is_stale_and_ticked(self):
        gone = self.home / "code" / "old app"
        self.workspace("file://" + str(gone).replace(" ", "%20"))
        self.proj(cr.encode_project(str(gone)))
        it = self.only(cr.encode_project(str(gone)))
        self.assertEqual((it.stale, it.selected), (True, True))
        self.assertIn("MISSING", it.badge)
        self.assertTrue(any(str(gone) in d for d in it.detail), it.detail)

    def test_dash_in_name_resolves_by_disk_probe(self):
        app = self.home / "code" / "my-app"
        app.mkdir(parents=True)
        self.proj(cr.encode_project(str(app)))
        it = self.only(cr.encode_project(str(app)))
        self.assertEqual((it.stale, it.selected), (False, False))
        self.assertNotIn("UNKNOWN", it.badge)

    def test_tmp_and_numeric_folders_are_stale(self):
        self.proj("tmp-c317a0de-1b2c-4d3e-8f90-a1b2c3d4e5f6")
        self.proj("1792207849851")
        for n in ("tmp-c317a0de-1b2c-4d3e-8f90-a1b2c3d4e5f6", "1792207849851"):
            it = self.only(n)
            self.assertEqual((it.stale, it.selected), (True, True), n)
            self.assertIn("TEMP", it.badge)

    def test_unmatched_name_is_unknown_not_ticked(self):
        self.proj("zz-nowhere-qq-9")
        it = self.only("zz-nowhere-qq-9")
        self.assertEqual((it.stale, it.selected), (False, False))
        self.assertIn("UNKNOWN", it.badge)
        self.assertIn("unknown, folder not found", it.detail)

    def test_empty_window_and_dot_folders(self):
        self.proj("empty-window")
        self.proj(".hidden")
        names = [i.name for i in cr.scan_projects()]
        self.assertIn("empty-window", names)
        self.assertNotIn(".hidden", names)
        it = self.only("empty-window")
        self.assertEqual((it.stale, it.selected), (False, False))

    def test_missing_projects_dir_and_bad_json(self):
        self.assertEqual(cr.scan_projects(), [])
        self.write_text(".config/Cursor/User/workspaceStorage/a/workspace.json", "{nope")
        self.write(".config/Cursor/User/globalStorage/storage.json",
                   {"backupWorkspaces": {"folders": [{"folderUri": "vscode-remote://x/y"}]},
                    "profileAssociations": {"workspaces": {"file:///home/user/p": "d"}}})
        self.assertEqual(cr.known_folders(), {"/home/user/p"})

    def test_short_tmp_name_is_not_temp(self):
        self.proj("tmp-deadbeef")
        it = self.only("tmp-deadbeef")
        self.assertNotIn("TEMP", it.badge)
        self.assertEqual((it.stale, it.selected), (False, False))

    @unittest.skipIf(os.geteuid() == 0, "root ignores permissions")
    def test_unreadable_ancestor_does_not_crash(self):
        locked = self.home / "locked"
        (locked / "inner").mkdir(parents=True)
        os.chmod(locked, 0o000)
        try:
            self.proj(cr.encode_project(str(locked / "inner")))
            self.proj("zz-" + cr.encode_project(str(locked / "inner")))
            self.workspace("file://" + str(locked / "gone"))
            self.proj(cr.encode_project(str(locked / "gone")))
            names = [i.name for i in cr.scan_projects()]
            self.assertEqual(len(names), 3)
            it = self.only(cr.encode_project(str(locked / "gone")))
            self.assertIn("UNKNOWN", it.badge)
            self.assertNotIn("MISSING", it.badge)
            self.assertEqual((it.stale, it.selected), (False, False))
            self.assertTrue(any("could not be checked" in d for d in it.detail), it.detail)
        finally:
            os.chmod(locked, 0o755)

    def test_symlink_not_followed_in_size(self):
        d = self.proj("1792207849852")
        big = self.home / "big"
        big.mkdir()
        (big / "f").write_bytes(b"x" * 5000)
        os.symlink(big, d / "link")
        self.assertLess(self.only("1792207849852").size, 5000)


REF_CLI = {"version": 1, "permissions": {"allow": ["Shell(ls)"], "deny": []},
           "approvalMode": "allowlist",
           "sandbox": {"mode": "disabled", "networkAccess": "user_config_with_defaults"}}
REF_PERMS = {"autoRun": {"allow_instructions": [], "block_instructions": ["no rm", "no push"]}}
REF_SANDBOX = {"type": "workspace_readwrite", "readBoundary": "workspace", "additionalReadPaths": [],
               "disableTmpWrite": False, "networkPolicy": {"default": "deny", "allow": [], "deny": []}}


class TestScan(FakeHome):
    def items(self, roots=None):
        cats = cr.scan_all(roots or [self.home])
        return [i for c in cats for i in c.items]

    def kinds(self, items, kind):
        return [i for i in items if i.kind == kind]

    def test_reference_install(self):
        self.write(".cursor/cli-config.json", REF_CLI)
        self.write(".cursor/permissions.json", REF_PERMS)
        self.write(".cursor/sandbox.json", REF_SANDBOX)
        items = self.items()
        allow = self.kinds(items, "allow")
        self.assertEqual([(i.value, i.risky) for i in allow], [("Shell(ls)", False)])
        self.assertEqual((allow[0].op, allow[0].jpath), ("drop_entry", ["permissions", "allow"]))
        approval = self.kinds(items, "approval")
        self.assertEqual([(i.locked, i.risky) for i in approval], [(True, False)])
        block = self.kinds(items, "block")
        self.assertEqual(len(block), 1)
        self.assertTrue(block[0].locked)
        sandbox = self.kinds(items, "sandbox")
        self.assertEqual(len(sandbox), 1)
        self.assertTrue(sandbox[0].locked)
        self.assertIn("at or stricter than Cursor's defaults", sandbox[0].title)
        self.assertEqual(self.kinds(items, "unknown"), [])
        self.assertFalse(any(i.selected for i in items if i.locked))
        self.assertEqual(len({i.key for i in items}), len(items))

    def test_categories_in_order(self):
        names = [c.name for c in cr.scan_all([self.home])]
        self.assertEqual(names, ["Agent permissions", "Sandbox settings",
                                 "MCP servers and hooks", "Project data folders"])

    def test_project_files_are_found_and_labelled(self):
        base = "code/app/.cursor/"
        self.write(base + "cli.json", {"permissions": {"allow": ["Shell(curl)"], "deny": ["Read(x)"]}})
        self.write(base + "permissions.json", {"autoRun": {"allow_instructions": ["run tests"]}})
        self.write(base + "sandbox.json", {"networkPolicy": {"default": "allow"}})
        self.write(base + "mcp.json", {"mcpServers": {"github": {"command": "npx", "args": ["gh-mcp"]}}})
        self.write(base + "hooks.json", {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}})
        items = self.items()
        for name in ("cli.json", "permissions.json", "sandbox.json", "mcp.json", "hooks.json"):
            f = str(self.home / base / name)
            got = [i for i in items if i.file == f]
            self.assertTrue(got, name)
            for i in got:
                self.assertEqual(i.where, "~/code/app", (name, i.title))
        by = {i.kind: i for i in items if i.where == "~/code/app"}
        self.assertTrue(by["allow"].risky)
        self.assertTrue(by["deny"].locked)
        self.assertEqual((by["autorun"].value, by["autorun"].op, by["autorun"].risky),
                         ("run tests", "drop_entry", True))
        self.assertEqual((by["sandbox"].jpath, by["sandbox"].op, by["sandbox"].value),
                         (["networkPolicy", "default"], "reset", "deny"))
        self.assertEqual((by["mcp"].title, by["mcp"].op, by["mcp"].jpath, by["mcp"].value),
                         ("MCP server: github", "pop_key", ["mcpServers"], "github"))
        self.assertTrue(any("npx gh-mcp" in d for d in by["mcp"].detail), by["mcp"].detail)
        self.assertEqual((by["hook"].op, by["hook"].jpath, by["hook"].value),
                         ("pop_key", ["hooks"], "beforeShellExecution"))
        self.assertTrue(any("./audit.sh" in d for d in by["hook"].detail), by["hook"].detail)
        self.assertFalse(any(i.selected for i in items))

    def test_jsonc_file_is_unknown_and_untouched(self):
        text = '{"mcpServers": {}, // note\n}'
        p = self.write_text(".cursor/mcp.json", text)
        before = p.read_bytes()
        items = [i for i in self.items() if i.file == str(p)]
        self.assertEqual(len(items), 1)
        self.assertEqual((items[0].kind, items[0].locked, items[0].op), ("unknown", True, ""))
        self.assertIn("unknown format, not touched", items[0].title)
        self.assertEqual(p.read_bytes(), before)

    def test_missing_files_give_no_items(self):
        self.write(".cursor/cli-config.json", {"permissions": {"deny": list(cr.DENY_RULES)}})
        items = self.items()
        self.assertEqual({(i.kind, i.file) for i in items}, {("deny", str(cr.GLOBAL_CLI))})

    def test_harden_global_only(self):
        self.write(".cursor/cli-config.json", {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
        self.write("code/app/.cursor/cli.json", {"permissions": {"deny": []}})
        h = self.kinds(self.items(), "harden")
        self.assertEqual(len(h), 1)
        h = h[0]
        self.assertEqual(h.title, "HARDEN: stop the Cursor CLI agent reading keys and .env files")
        self.assertEqual((h.file, h.jpath, h.op, h.locked, h.selected),
                         (str(cr.GLOBAL_CLI), ["permissions", "deny"], "harden", False, False))
        self.assertEqual(h.value, [r for r in cr.DENY_RULES if r != "Read(~/.ssh/**)"])
        self.assertTrue(any("CLI agent only" in d for d in h.detail), h.detail)

    def test_harden_when_global_file_missing(self):
        h = self.kinds(self.items(), "harden")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0].value, cr.DENY_RULES)

    def test_risky_approval_mode(self):
        self.write(".cursor/cli-config.json", {"approvalMode": "yolo"})
        a = self.kinds(self.items(), "approval")
        self.assertEqual([(i.locked, i.risky) for i in a], [(True, True)])
        self.assertTrue(any("change this in Cursor's settings" in d for d in a[0].detail))

    def test_other_permission_lists(self):
        self.write(".cursor/permissions.json", {
            "autoRun": {"allow_instructions": [], "block_instructions": []},
            "mcpAllowlist": ["github:list_issues", 3],
            "terminalAllowlist": ["git status"],
            "terminalBlocklist": ["rm"],
            "weird": {"a": 1},
        })
        items = self.items()
        allow = {i.value: i for i in self.kinds(items, "allow")}
        self.assertEqual(set(allow), {"git status"})
        self.assertTrue(allow["git status"].risky)
        self.assertEqual((allow["git status"].jpath, allow["git status"].op),
                         (["terminalAllowlist"], "drop_entry"))
        removable = [i for i in items if i.op]
        self.assertFalse(any(i.value == "rm" for i in removable))
        notes = " ".join(d for i in items for d in i.detail)
        self.assertIn("weird", notes)
        self.assertIn("mcpAllowlist", notes)
        block = self.kinds(items, "block")
        self.assertEqual([(i.value, i.locked) for i in block], [("rm", True)])

    @unittest.skipIf(os.geteuid() == 0, "root ignores permissions")
    def test_walk_skips_symlinks_and_unreadable(self):
        (self.home / "code" / "app" / ".cursor").mkdir(parents=True)
        (self.home / "code" / "lib" / ".cursor").mkdir(parents=True)
        os.symlink(self.home / "code", self.home / "link")
        locked = self.home / "locked"
        (locked / ".cursor").mkdir(parents=True)
        os.chmod(locked, 0o000)
        try:
            got = cr.find_cursor_dirs([self.home])
        finally:
            os.chmod(locked, 0o755)
        self.assertEqual(got, [self.home / "code" / "app" / ".cursor",
                               self.home / "code" / "lib" / ".cursor"])

    def test_dot_cursor_inside_global_dir(self):
        self.write(".cursor/.cursor/sandbox.json", REF_SANDBOX)
        dirs = cr.find_cursor_dirs([self.home])
        self.assertIn(self.home / ".cursor" / ".cursor", dirs)
        self.assertNotIn(self.home / ".cursor", dirs)
        f = str(self.home / ".cursor" / ".cursor" / "sandbox.json")
        got = [i for i in self.items() if i.file == f]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].where, "~/.cursor")
        self.assertEqual(cr.find_cursor_dirs([self.home / "nowhere"]),
                         [self.home / ".cursor" / ".cursor"])


class TestApply(FakeHome):
    def items(self):
        return [i for c in cr.scan_all([self.home]) for i in c.items]

    def test_round_trip_restores_everything(self):
        files = {
            ".cursor/cli-config.json": {"version": 1, "permissions": {"allow": ["Shell(*)"], "deny": []}},
            ".cursor/mcp.json": {"mcpServers": {"srv": {"command": "x"}}},
            "code/app/.cursor/permissions.json": {"autoRun": {"allow_instructions": ["run all"],
                                                              "block_instructions": ["no rm"]}},
            "code/app/.cursor/sandbox.json": {"type": "insecure_none",
                                              "networkPolicy": {"default": "allow", "allow": ["*", "pypi.org"]},
                                              "additionalReadwritePaths": ["~", "build"]},
            "code/app/.cursor/hooks.json": {"version": 1, "hooks": {"stop": [{"command": "./x.sh"}]}},
            "code/lib/.cursor/cli.json": {"permissions": {"allow": ["Read(**)", "Shell(ls)"]}},
        }
        paths = {rel: self.write(rel, data, perms=0o600) for rel, data in files.items()}
        proj = cr.PROJECTS_DIR / "tmp-0123abcd-0123-4567-89ab-0123456789ab"
        (proj / "mcps").mkdir(parents=True)
        (proj / "mcps" / "a.json").write_text("{}")

        plan = [i for i in self.items() if i.op and not i.locked and i.value != "Shell(ls)"]
        self.assertEqual({i.op for i in plan}, {"drop_entry", "pop_key", "reset", "harden", "move"})
        log = cr.apply_plan(plan)
        self.assertFalse(any(line.startswith(("SKIP", "FAIL")) for line in log), log)

        got = {rel: cr.load_json(p) for rel, p in paths.items()}
        self.assertEqual(got[".cursor/cli-config.json"]["permissions"],
                         {"allow": [], "deny": cr.DENY_RULES})
        self.assertEqual(got[".cursor/mcp.json"], {"mcpServers": {}})
        self.assertEqual(got["code/app/.cursor/permissions.json"]["autoRun"],
                         {"allow_instructions": [], "block_instructions": ["no rm"]})
        self.assertEqual(got["code/app/.cursor/sandbox.json"],
                         {"type": "workspace_readwrite",
                          "networkPolicy": {"default": "deny", "allow": ["pypi.org"]},
                          "additionalReadwritePaths": ["build"]})
        self.assertEqual(got["code/app/.cursor/hooks.json"], {"version": 1, "hooks": {}})
        self.assertEqual(got["code/lib/.cursor/cli.json"], {"permissions": {"allow": ["Shell(ls)"]}})
        self.assertFalse(proj.exists())
        backups = [Path(b["copy"]) for b in self.manifest()["backups"]]
        self.assertEqual(sorted(b["original"] for b in self.manifest()["backups"]),
                         sorted(str(p) for p in paths.values()))
        self.assertEqual(len(set(backups)), len(backups))
        self.assertTrue(all(b.is_file() for b in backups))

        self.restore_latest()
        for rel, p in paths.items():
            self.assertEqual(cr.load_json(p), files[rel], rel)
            self.assertEqual(mode(p), 0o600, rel)
        self.assertTrue((proj / "mcps" / "a.json").is_file())

    def test_locked_items_are_ignored(self):
        self.write(".cursor/cli-config.json", {"permissions": {"deny": ["Read(x)"]}, "approvalMode": "yolo"})
        self.write(".cursor/permissions.json", {"autoRun": {"block_instructions": ["no rm"]},
                                                "terminalBlocklist": ["rm"]})
        self.write_text(".cursor/mcp.json", '{"mcpServers": {}, // note\n}')
        files = sorted(p for p in (self.home / ".cursor").iterdir())
        before = {p: p.read_bytes() for p in files}
        plan = [i for i in self.items() if i.kind in ("deny", "approval", "block", "unknown")]
        self.assertEqual({i.kind for i in plan}, {"deny", "approval", "block", "unknown"})
        for i in plan:
            i.op = i.op or "drop_entry"   # even if something set an op, locked wins
        cr.apply_plan(plan)
        self.assertEqual({p: p.read_bytes() for p in files}, before)
        self.assertEqual(self.manifest()["edits"], [])

    def test_entry_removed_by_cursor_meanwhile_is_skipped(self):
        p = self.write(".cursor/cli-config.json", {"permissions": {"allow": ["Shell(*)", "Shell(ls)"]}})
        plan = [i for i in self.items() if i.value == "Shell(*)"]
        self.assertEqual(len(plan), 1)
        self.write(".cursor/cli-config.json", {"permissions": {"allow": ["Shell(ls)"]}, "new": 1})
        log = cr.apply_plan(plan)
        self.assertTrue(any(line.startswith("SKIP") for line in log), log)
        self.assertEqual(cr.load_json(p), {"permissions": {"allow": ["Shell(ls)"]}, "new": 1})
        self.assertEqual(self.manifest()["edits"], [])

    def test_file_turned_invalid_meanwhile_is_not_written(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {"command": "x"}}})
        plan = [i for i in self.items() if i.kind == "mcp"]
        self.assertEqual(len(plan), 1)
        p.write_text("{bad")
        log = cr.apply_plan(plan)
        self.assertEqual(p.read_bytes(), b"{bad")
        self.assertIn(f"SKIP {p}: unreadable", log)
        self.assertEqual(self.manifest()["edits"], [])

    def sandbox_off(self):
        p = self.write("code/app/.cursor/sandbox.json", {"type": "insecure_none"})
        plan = [i for i in self.items() if i.kind == "sandbox"]
        self.assertEqual([(i.op, i.jpath) for i in plan], [("reset", ["type"])])
        cr.apply_plan(plan)
        self.assertEqual(cr.load_json(p), {"type": "workspace_readwrite"})
        self.assertEqual(self.manifest()["edits"],
                         [{"file": str(p), "path": ["type"], "was": "insecure_none",
                           "now": "workspace_readwrite"}])
        return p

    def test_restore_undoes_untouched_reset(self):
        p = self.sandbox_off()
        self.restore_latest()
        self.assertEqual(cr.load_json(p), {"type": "insecure_none"})

    def test_restore_keeps_newer_changes(self):
        p = self.sandbox_off()
        cr.write_json_atomic(p, {"type": "workspace_readonly", "networkPolicy": {"allow": ["pypi.org"]}})
        self.restore_latest()
        self.assertEqual(cr.load_json(p), {"type": "workspace_readonly",
                                           "networkPolicy": {"allow": ["pypi.org"]}})

    def test_reset_skipped_when_field_already_default_or_gone(self):
        p = self.write(".cursor/sandbox.json", {"type": "insecure_none",
                                                "networkPolicy": {"default": "allow"}})
        plan = [i for i in self.items() if i.kind == "sandbox"]
        self.assertEqual(len(plan), 2)
        self.write(".cursor/sandbox.json", {"type": "workspace_readwrite"})
        log = cr.apply_plan(plan)
        self.assertEqual(sum(line.startswith("SKIP") for line in log), 2, log)
        self.assertEqual(cr.load_json(p), {"type": "workspace_readwrite"})
        self.assertEqual(self.manifest()["edits"], [])

    def test_sandbox_file_is_never_moved(self):
        p = self.write(".cursor/sandbox.json", {"type": "insecure_none",
                                                "additionalReadPaths": ["~/.ssh"]})
        plan = [i for i in self.items() if i.kind == "sandbox"]
        self.assertEqual(len(plan), 2)
        cr.apply_plan(plan)
        self.assertTrue(p.is_file())
        self.assertEqual(cr.load_json(p), {"type": "workspace_readwrite", "additionalReadPaths": []})
        self.assertEqual(self.manifest()["moves"], [])

    def test_harden_adds_deny_rules_and_keeps_existing(self):
        p = self.write(".cursor/cli-config.json", {"permissions": {"deny": ["Read(secret.txt)"]}}, perms=0o600)
        cr.apply_plan([i for i in self.items() if i.kind == "harden"])
        deny = cr.load_json(p)["permissions"]["deny"]
        self.assertEqual(deny, ["Read(secret.txt)"] + cr.DENY_RULES)
        self.assertEqual(mode(p), 0o600)
        data = cr.load_json(p)
        data["permissions"]["deny"].append("Read(mine)")
        cr.write_json_atomic(p, data)
        self.restore_latest()
        self.assertEqual(cr.load_json(p)["permissions"]["deny"], ["Read(secret.txt)", "Read(mine)"])

    def test_harden_adds_only_rules_still_missing(self):
        p = self.write(".cursor/cli-config.json", {})
        plan = [i for i in self.items() if i.kind == "harden"]
        self.write(".cursor/cli-config.json", {"permissions": {"deny": ["Read(**/.env)"]}})
        cr.apply_plan(plan)
        deny = cr.load_json(p)["permissions"]["deny"]
        self.assertEqual(sorted(deny), sorted(cr.DENY_RULES))
        self.assertEqual(self.manifest()["edits"][0]["remove"],
                         [r for r in cr.DENY_RULES if r != "Read(**/.env)"])

    def test_harden_creates_missing_global_file(self):
        plan = [i for i in self.items() if i.kind == "harden"]
        cr.apply_plan(plan)
        self.assertEqual(cr.load_json(cr.GLOBAL_CLI), {"permissions": {"deny": cr.DENY_RULES}})
        self.assertEqual(mode(cr.GLOBAL_CLI), 0o600)
        self.assertEqual(self.manifest()["backups"], [])
        self.restore_latest()
        self.assertEqual(cr.load_json(cr.GLOBAL_CLI), {"permissions": {"deny": []}})

    def test_restore_never_overwrites_a_file_that_turned_unreadable(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        cr.apply_plan([i for i in self.items() if i.kind == "mcp"])
        p.write_text('{"mcpServers": {}, // mine\n}')
        out = self.restore_latest()
        self.assertEqual(p.read_text(), '{"mcpServers": {}, // mine\n}')
        self.assertIn("SKIP", out)

    def test_restore_falls_back_to_backup_when_file_is_gone(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        cr.apply_plan([i for i in self.items() if i.kind == "mcp"])
        p.unlink()
        self.restore_latest()
        self.assertEqual(cr.load_json(p), {"mcpServers": {"srv": {}}})

    def test_describe_every_op_bearing_item(self):
        self.write(".cursor/cli-config.json", {"permissions": {"allow": ["Shell(*)"]}})
        self.write(".cursor/permissions.json", {"autoRun": {"allow_instructions": ["go"]},
                                                "terminalAllowlist": ["git status"]})
        self.write(".cursor/sandbox.json", {"type": "insecure_none", "networkPolicy": {"allow": ["*"]}})
        self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        self.write(".cursor/hooks.json", {"hooks": {"stop": []}})
        (cr.PROJECTS_DIR / "12345").mkdir(parents=True)
        items = [i for i in self.items() if i.op and not i.locked]
        self.assertEqual({i.kind for i in items},
                         {"allow", "autorun", "sandbox", "mcp", "hook", "harden", "projdir"})
        for i in items:
            d = cr.describe(i)
            self.assertTrue(d and "\n" not in d, i)
        by = {cr.describe(i) for i in items}
        self.assertTrue(any("Shell(*)" in d for d in by), by)
        self.assertTrue(any("srv" in d for d in by), by)
        self.assertTrue(any("workspace_readwrite" in d for d in by), by)


    def test_two_removals_from_one_list_come_back_in_order(self):
        orig = {"additionalReadwritePaths": ["~", "/", "build"]}
        p = self.write("code/app/.cursor/sandbox.json", orig)
        plan = [i for i in self.items() if i.kind == "sandbox"]
        self.assertEqual([i.value for i in plan], ["~", "/"])
        cr.apply_plan(plan)
        self.assertEqual(cr.load_json(p), {"additionalReadwritePaths": ["build"]})
        self.restore_latest()
        self.assertEqual(cr.load_json(p), orig)

    @unittest.skipIf(os.geteuid() == 0, "root ignores permissions")
    def test_failed_write_is_logged_and_the_rest_is_restorable(self):
        a = self.write("code/a/.cursor/cli.json", {"permissions": {"allow": ["Shell(*)"]}})
        b = self.write("code/b/.cursor/cli.json", {"permissions": {"allow": ["Shell(*)"]}})
        plan = [i for i in self.items() if i.kind == "allow"]
        self.assertEqual(len(plan), 2)
        os.chmod(b.parent, 0o555)
        try:
            log = cr.apply_plan(plan)
        finally:
            os.chmod(b.parent, 0o755)
        self.assertTrue(any(line.startswith(f"FAIL {b}") for line in log), log)
        self.assertEqual(cr.load_json(a), {"permissions": {"allow": []}})
        self.assertEqual(cr.load_json(b), {"permissions": {"allow": ["Shell(*)"]}})
        self.assertEqual({e["file"] for e in self.manifest()["edits"]}, {str(a)})
        self.restore_latest()
        self.assertEqual(cr.load_json(a), {"permissions": {"allow": ["Shell(*)"]}})

    @unittest.skipIf(os.geteuid() == 0, "root ignores permissions")
    def test_failed_move_is_logged_and_manifest_written(self):
        ok = cr.PROJECTS_DIR / "12345"
        bad = cr.PROJECTS_DIR / "67890"
        for d in (ok, bad):
            (d / "x").mkdir(parents=True)
        plan = [i for i in self.items() if i.kind == "projdir"]
        with mock.patch.object(cr.shutil, "move", side_effect=[None, OSError("no")]):
            log = cr.apply_plan(plan)
        self.assertTrue(any(line.startswith("FAIL") for line in log), log)
        self.assertEqual(len(self.manifest()["moves"]), 1)

    def test_backups_of_lookalike_paths_do_not_collide(self):
        a = self.write("code/my-app/.cursor/cli.json", {"permissions": {"allow": ["Shell(*)"]}, "n": "a"})
        b = self.write("code/my/app/.cursor/cli.json", {"permissions": {"allow": ["Shell(*)"]}, "n": "b"})
        self.assertEqual(cr.encode_path(a), cr.encode_path(b))
        cr.apply_plan([i for i in self.items() if i.kind == "allow"])
        copies = [b_["copy"] for b_ in self.manifest()["backups"]]
        self.assertEqual(len(set(copies)), 2)
        a.unlink()
        b.unlink()
        self.restore_latest()
        self.assertEqual(cr.load_json(a)["n"], "a")
        self.assertEqual(cr.load_json(b)["n"], "b")

    def test_two_runs_in_the_same_second_get_their_own_folders(self):
        self.write(".cursor/mcp.json", {"mcpServers": {"a": {}, "b": {}}})
        items = [i for i in self.items() if i.kind == "mcp"]
        with mock.patch.object(cr.time, "strftime", return_value="20260101-000000"):
            cr.apply_plan(items[:1])
            cr.apply_plan(items[1:])
        dirs = sorted(cr.QUARANTINE_ROOT.iterdir())
        self.assertEqual(len(dirs), 2)
        for d in dirs:
            self.assertEqual(len(cr.load_json(d / "manifest.json")["edits"]), 1)

    def test_restore_does_not_write_through_a_dangling_symlink(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        cr.apply_plan([i for i in self.items() if i.kind == "mcp"])
        p.unlink()
        target = self.home / "elsewhere" / "target.json"
        target.parent.mkdir()
        os.symlink(target, p)
        out = self.restore_latest()
        self.assertFalse(os.path.lexists(target))
        self.assertTrue(p.is_symlink())
        self.assertIn(f"SKIP {p}", out)

    def test_quarantine_folders_are_private(self):
        self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        (cr.PROJECTS_DIR / "12345").mkdir(parents=True)
        cr.QUARANTINE_ROOT.mkdir(mode=0o775)
        os.chmod(cr.QUARANTINE_ROOT, 0o775)
        cr.apply_plan([i for i in self.items() if i.kind in ("mcp", "projdir")])
        qdir = self.latest_quarantine()
        for d in (cr.QUARANTINE_ROOT, qdir, qdir / "backup", qdir / "projects"):
            self.assertEqual(mode(d), 0o700, d)


class CliBase(FakeHome):
    def run_cli(self, *args):
        env = dict(os.environ, CURSOR_REVOKE_HOME=str(self.home), PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, str(SCRIPT), *args], input="\n", env=env,
                              capture_output=True, text=True, timeout=60)

    def snapshot(self):
        return {str(p): p.stat().st_mtime_ns for p in self.home.rglob("*")}


class TestReport(CliBase):
    def setUp(self):
        super().setUp()
        self.write(".cursor/cli-config.json",
                   {"permissions": {"allow": ["Shell(sudo)", "Read(src/**)"], "deny": []},
                    "approvalMode": "yolo"})
        self.write_text(".cursor/mcp.json", "{ // comment\n}")

    def test_report_lists_categories_and_legend(self):
        r = self.run_cli("--report", "--roots", str(self.home))
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("Agent permissions", "Sandbox settings", "MCP servers and hooks",
                     "Project data folders"):
            self.assertIn(name, r.stdout)
        self.assertIn("! risky   ~ stale   # locked (shown only)", r.stdout)
        self.assertTrue(any(l.startswith(" # ") for l in r.stdout.splitlines()), r.stdout)
        self.assertTrue(any(l.startswith(" ! ") for l in r.stdout.splitlines()), r.stdout)

    def test_report_only_risky_hides_ok_items(self):
        r = self.run_cli("--report", "--only", "risky", "--roots", str(self.home))
        self.assertIn("Shell(sudo)", r.stdout)
        self.assertNotIn("Read(src/**)", r.stdout)
        self.assertNotIn("unknown format", r.stdout)

    def test_version_prints_0_1_0(self):
        r = self.run_cli("--version")
        self.assertEqual(r.stdout.strip(), "cursor-revoke 0.1.0")

    def test_report_never_writes(self):
        before = self.snapshot()
        r = self.run_cli("--report", "--roots", str(self.home))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.home / ".cursor-revoke-quarantine").exists())

    def test_report_does_not_touch_sqlite(self):
        db = self.home / ".config/Cursor/User/globalStorage/state.vscdb"
        db.parent.mkdir(parents=True)
        db.write_bytes(b"x")
        os.chmod(db, 0o000)
        try:
            r = self.run_cli("--report", "--roots", str(self.home))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Traceback", r.stderr)
        finally:
            os.chmod(db, 0o600)

    def test_pause_waits_for_enter(self):
        r = self.run_cli("--report", "--pause", "--roots", str(self.home))
        self.assertIn("Press Enter", r.stdout)

    def test_restore_missing_manifest_errors(self):
        r = self.run_cli("--restore", str(self.home / "nope"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("No manifest.json", r.stderr)


class TestSummarize(unittest.TestCase):
    def test_none_when_ok(self):
        self.assertIsNone(cr.summarize([cr.Category("A", "", [cr.Item("allow", "k", "t")])]))

    def test_counts_skip_locked_and_stale_first(self):
        cats = [cr.Category("A", "", [cr.Item("allow", "k", "t", stale=True, risky=True),
                                      cr.Item("allow", "k2", "t", risky=True),
                                      cr.Item("unknown", "k3", "t", locked=True)])]
        self.assertEqual(cr.summarize(cats), "A: 1 stale, 1 risky")


class TestRunningCursor(unittest.TestCase):
    def fake_proc(self, procs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for pid, (comm, cmd) in procs.items():
            d = root / str(pid)
            d.mkdir()
            if comm is not None:
                (d / "comm").write_text(comm + "\n")
            if cmd is not None:
                (d / "cmdline").write_bytes(cmd.replace(" ", "\0").encode())
        (root / "self").mkdir()
        return root

    def test_detects_cursor_processes(self):
        root = self.fake_proc({
            101: ("cursor", "/usr/share/cursor/cursor --no-sandbox"),
            102: ("bash", "bash"),
            103: ("Cursor-0.50.AppIm", "/opt/Cursor-0.50.AppImage"),
            104: ("vim", "vim cursor.txt"),
            105: (None, None),
        })
        with mock.patch.object(cr, "PROC", root):
            self.assertEqual(sorted(cr.running_cursor()), [101, 103])

    def test_missing_proc_is_empty(self):
        with mock.patch.object(cr, "PROC", Path("/nonexistent-proc")):
            self.assertEqual(cr.running_cursor(), [])

    def test_warning_text(self):
        with mock.patch.object(cr, "running_cursor", return_value=[7]):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                cr.warn_if_running()
        self.assertIn("Cursor is running", buf.getvalue())


class TestTui(unittest.TestCase):
    def test_bulk_tick_skips_locked(self):
        items = [cr.Item("allow", "a", "a"), cr.Item("block", "b", "b", locked=True),
                 cr.Item("allow", "c", "c", stale=True), cr.Item("unknown", "d", "d", locked=True)]
        self.assertEqual(cr.tick(items, lambda it: True, True), 2)
        self.assertEqual([i.selected for i in items], [True, False, True, False])
        self.assertEqual(cr.tick(items, lambda it: True, True), 0)
        self.assertEqual(cr.chosen(items), [items[0], items[2]])
        self.assertEqual(cr.tick(items, lambda it: it.stale, False), 1)
        self.assertEqual(cr.chosen(items), [items[0]])

    def test_chosen_ignores_a_locked_item_marked_selected(self):
        items = [cr.Item("block", "b", "b", locked=True, selected=True)]
        self.assertEqual(cr.chosen(items), [])


class TestClean(unittest.TestCase):
    def test_control_characters_become_question_marks(self):
        self.assertEqual(cr.clean("a\x1b[2Kb"), "a?[2Kb")
        self.assertEqual(cr.clean("a\rb"), "a?b")
        self.assertEqual(cr.clean("a\x07b"), "a?b")
        self.assertEqual(cr.clean("a\tb"), "a b")
        self.assertEqual(cr.clean("caf\u00e9 \u65e5\u672c ~/x-y"), "caf\u00e9 \u65e5\u672c ~/x-y")


class TestReportControlChars(CliBase):
    def test_report_strips_escape_and_carriage_return(self):
        self.write(".cursor/mcp.json",
                   {"mcpServers": {"evil\x1b[2Kx": {"command": "node\rfake", "args": ["a\x07"]}}})
        r = subprocess.run([sys.executable, str(SCRIPT), "--report", "--roots", str(self.home)],
                           env=dict(os.environ, CURSOR_REVOKE_HOME=str(self.home),
                                    PYTHONDONTWRITEBYTECODE="1"),
                           capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"evil?[2Kx", r.stdout)
        self.assertIn(b"node?fake", r.stdout)
        for bad in (b"\x1b", b"\r", b"\x07"):
            self.assertNotIn(bad, r.stdout)


class FakeScreen:
    """Just enough of a curses window for App: records every string drawn."""

    def __init__(self, keys, h=40, w=140):
        self.keys, self.h, self.w, self.drawn = list(keys), h, w, []

    def getmaxyx(self):
        return self.h, self.w

    def addstr(self, y, x, s, attr=0):
        self.drawn.append(s)

    def erase(self):
        pass

    def getch(self):
        return self.keys.pop(0) if self.keys else 27


class TestTuiDrawing(unittest.TestCase):
    BAD = "\x1b[2K\r\x07"

    def app(self, keys):
        it = cr.Item("mcp", "k", f"MCP server: ev{self.BAD}il", badge=f"B{self.BAD}",
                     where=f"~/code/x{self.BAD}y", file="/home/user/.cursor/mcp.json",
                     jpath=["mcpServers"], value=f"ev{self.BAD}il", op="pop_key", risky=True,
                     selected=True, detail=[f"In /x{self.BAD}", f"Runs: node{self.BAD}"])
        app = cr.App.__new__(cr.App)
        app.scr, app.cats, app.dry_run, app.final, app.colors = (
            FakeScreen(keys), [cr.Category("MCP servers and hooks", "help", [it])], True, [], False)
        return app

    def assert_clean(self, drawn):
        for ch in "".join(drawn):
            self.assertNotEqual(unicodedata.category(ch)[0], "C", repr(ch))

    def test_checklist_row_and_detail_are_sanitized(self):
        app = self.app([ord("j"), 27])   # move onto the item row (detail pane), then back
        app.checklist(app.cats[0])
        text = "".join(app.scr.drawn)
        self.assertIn("ev?[2K??il", text)
        self.assertIn("Runs: node?[2K??", text)
        self.assert_clean(app.scr.drawn)

    def test_review_lines_are_sanitized(self):
        app = self.app([ord("q")])
        with mock.patch.object(cr, "running_cursor", return_value=[]):
            self.assertIsNone(app.review())
        self.assertIn("Remove MCP server: ev?[2K??il", "".join(app.scr.drawn))
        self.assert_clean(app.scr.drawn)


class TestRestoreOutput(FakeHome):
    def test_restore_output_has_no_escape(self):
        bad = "ev\x1b[2Kil"
        self.write(f"code/{bad}/.cursor/cli.json", {"permissions": {"allow": ["Shell(curl)"]}})
        self.write(f".cursor/projects/{bad}/terminals/1.txt", {})
        items = [i for c in cr.scan_all([self.home]) for i in c.items]
        hit = [i for i in items if "\x1b" in i.file]
        self.assertEqual({i.op for i in hit}, {"drop_entry", "move"})
        cr.tick(hit, lambda it: True, True)
        with contextlib.redirect_stdout(io.StringIO()):
            cr.apply_plan(hit)
        out = self.restore_latest()
        self.assertIn("put 1 entry back", out)
        self.assertIn("OK   restored", out)
        self.assertIn("ev?[2Kil", out)
        self.assertNotIn("\x1b", out)
        self.assertTrue((self.home / ".cursor/projects" / bad / "terminals/1.txt").exists())


class TestNotifyFlag(FakeHome):
    """--notify is what the systemd timer runs: scan, one summary line, desktop notification."""

    def run_notify(self, with_notify_send=True):
        bindir = self.home / "bin"
        bindir.mkdir(exist_ok=True)
        log = self.home / "notify.log"
        if with_notify_send:
            stub = bindir / "notify-send"
            stub.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" >> "$NOTIFY_LOG"\n')
            stub.chmod(0o755)
        env = dict(os.environ, CURSOR_REVOKE_HOME=str(self.home), PYTHONDONTWRITEBYTECODE="1",
                   PATH=str(bindir), NOTIFY_LOG=str(log),
                   XDG_STATE_HOME=str(self.home / ".local/state"))
        r = subprocess.run([sys.executable, str(SCRIPT), "--notify", "--roots", str(self.home / "nowhere")],
                           env=env, capture_output=True, text=True, timeout=60)
        return r, (log.read_text() if log.exists() else "")

    def stale(self, *names):
        for n in names:
            d = self.home / ".cursor/projects" / n
            (d / "mcps").mkdir(parents=True, exist_ok=True)
            (d / "mcps" / "x.json").write_text("{}")

    def test_notification_text_has_real_counts(self):
        self.stale("1792207849851", "1792207849852")
        self.write(".cursor/mcp.json", {"mcpServers": {"srv": {"command": "npx"}}})
        r, sent = self.run_notify()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--app-name=cursor-revoke", sent)
        self.assertIn("Cursor: 2 stale, 1 risky. Run cursor-revoke to review.", sent)

    def test_notifies_once_per_change(self):
        self.stale("1792207849851")
        _, first = self.run_notify()
        self.assertIn("1 stale", first)
        r, second = self.run_notify()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(second, first)
        self.assertIn("unchanged", r.stdout)
        self.assertTrue((self.home / ".local/state/cursor-revoke/last-notified").is_file())
        self.stale("1792207849852")
        _, third = self.run_notify()
        self.assertIn("2 stale", third)

    def test_quiet_when_nothing_found(self):
        r, sent = self.run_notify()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nothing stale or risky", r.stdout)
        self.assertEqual(sent, "")

    def test_still_exits_zero_without_notify_send(self):
        self.stale("1792207849851")
        r, sent = self.run_notify(with_notify_send=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("libnotify", r.stderr)
        self.assertEqual(sent, "")


class TestScheduleFlag(FakeHome):
    """--schedule weekly|daily|off drives the systemd user timer through systemctl."""

    def run_schedule(self, choice, with_systemctl=True, fail=False, extra=(), config_home=None):
        bindir = self.home / "bin"
        bindir.mkdir(exist_ok=True)
        log = self.home / "systemctl.log"
        if with_systemctl:
            stub = bindir / "systemctl"
            stub.write_text('#!/bin/sh\necho "$*" >> "$SYSTEMCTL_LOG"\n[ -z "$SYSTEMCTL_FAIL" ] || exit 1\n')
            stub.chmod(0o755)
        env = dict(os.environ, CURSOR_REVOKE_HOME=str(self.home), PYTHONDONTWRITEBYTECODE="1",
                   PATH=str(bindir), SYSTEMCTL_LOG=str(log), SYSTEMCTL_FAIL="1" if fail else "",
                   XDG_CONFIG_HOME=str(config_home or self.home / ".config"))
        r = subprocess.run([sys.executable, str(SCRIPT), *extra, "--schedule", choice], env=env,
                           capture_output=True, text=True, timeout=60)
        calls = log.read_text().splitlines() if log.exists() else []
        return r, calls

    def dropin(self, config_home=None):
        return (config_home or self.home / ".config") / "systemd/user/cursor-revoke-audit.timer.d/schedule.conf"

    def test_respects_xdg_config_home(self):
        cfg = self.home / "cfg"
        r, _ = self.run_schedule("daily", config_home=cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.dropin(cfg).is_file())
        self.assertFalse(self.dropin().exists())

    def test_enable_failure_leaves_nothing_behind_and_explains(self):
        r, calls = self.run_schedule("weekly", fail=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.dropin().exists())
        self.assertIn("systemd user session", r.stderr)
        self.assertEqual(calls, ["--user daemon-reload"])

    def test_off_failure_explains(self):
        r, _ = self.run_schedule("off", fail=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("systemd user session", r.stderr)

    def test_dry_run_changes_nothing(self):
        r, calls = self.run_schedule("daily", extra=("--dry-run",))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.dropin().exists())
        self.assertEqual(calls, [])
        self.assertIn("would", r.stdout)

    def test_mentions_that_scan_options_are_not_carried_over(self):
        r, _ = self.run_schedule("weekly", extra=("--roots", str(self.home / "x")))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("default options", r.stderr)

    def test_daily_writes_dropin_and_enables_timer(self):
        r, calls = self.run_schedule("daily")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.dropin().read_text(), "[Timer]\nOnCalendar=\nOnCalendar=daily\n")
        self.assertEqual(calls, ["--user daemon-reload", "--user enable --now cursor-revoke-audit.timer"])
        self.assertIn("daily", r.stdout)

    def test_weekly_overrides_an_earlier_choice(self):
        self.run_schedule("daily")
        r, _ = self.run_schedule("weekly")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("OnCalendar=weekly", self.dropin().read_text())

    def test_off_disables_timer(self):
        r, calls = self.run_schedule("off")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls, ["--user disable --now cursor-revoke-audit.timer"])
        self.assertIn("off", r.stdout)

    def test_rejects_other_values(self):
        r, calls = self.run_schedule("hourly")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(calls, [])

    def test_fails_clearly_without_systemctl(self):
        r, calls = self.run_schedule("weekly", with_systemctl=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("systemctl", r.stderr)
        self.assertFalse(self.dropin().exists())


class TestSpecialFiles(FakeHome):
    """I1/I2: symlinked, non-regular, oversized or pathological config files."""

    def items(self, roots=None):
        return [i for c in cr.scan_all(roots or [self.home]) for i in c.items]

    def for_file(self, p):
        return [i for i in self.items() if i.file == str(p)]

    def assert_special(self, got):
        self.assertEqual(len(got), 1, [i.title for i in got])
        self.assertEqual((got[0].kind, got[0].locked, got[0].op), ("unknown", True, ""))
        self.assertIn("symlink or not a regular file, not touched", got[0].title)

    def test_project_mcp_symlinked_to_global_is_one_locked_item(self):
        g = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {"env": {"TOKEN": "x"}}}})
        link = self.home / "code/evil/.cursor/mcp.json"
        link.parent.mkdir(parents=True)
        os.symlink(g, link)
        self.assert_special(self.for_file(link))
        self.assertEqual(len([i for i in self.items() if i.kind == "mcp"]), 1)

    def test_global_symlinked_file_is_one_locked_item_and_no_harden(self):
        real = self.write("dotfiles/cli-config.json", {"permissions": {"allow": ["Shell(*)"]}})
        cr.GLOBAL_CLI.parent.mkdir(parents=True)
        os.symlink(real, cr.GLOBAL_CLI)
        self.assert_special(self.for_file(cr.GLOBAL_CLI))

    def test_device_and_fifo_are_one_locked_item(self):
        d = self.home / "code/app/.cursor"
        d.mkdir(parents=True)
        os.symlink("/dev/null", d / "hooks.json")
        os.mkfifo(d / "mcp.json")
        self.assert_special(self.for_file(d / "hooks.json"))
        self.assert_special(self.for_file(d / "mcp.json"))

    def test_oversized_file_is_unknown_and_not_read_whole(self):
        p = self.write_text("code/app/.cursor/hooks.json",
                            json.dumps({"hooks": {"stop": ["x" * (1024 * 1024)]}}))
        got = self.for_file(p)
        self.assertEqual(len(got), 1, [i.title for i in got])
        self.assertEqual((got[0].kind, got[0].locked), ("unknown", True))
        self.assertIn("unknown format, not touched", got[0].title)
        self.assertIsNone(cr.load_json(p, cr.MAX_CONFIG_BYTES))

    def test_deep_nesting_is_unknown_not_a_crash(self):
        p = self.write_text("code/app/.cursor/hooks.json", "[" * 200000 + "]" * 200000)
        got = self.for_file(p)
        self.assertEqual([(i.kind, i.locked) for i in got], [("unknown", True)])

    def test_memory_error_while_parsing_is_unknown(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {}})
        with mock.patch.object(cr.json, "load", side_effect=MemoryError), \
                mock.patch.object(cr.json, "loads", side_effect=MemoryError):
            data, items = cr.load_config(p)
        self.assertIsNone(data)
        self.assertEqual([(i.kind, i.locked) for i in items], [("unknown", True)])

    def test_apply_skips_a_file_turned_into_a_symlink(self):
        p = self.write("code/app/.cursor/mcp.json", {"mcpServers": {"srv": {}}})
        plan = [i for i in self.items() if i.kind == "mcp"]
        self.assertEqual(len(plan), 1)
        target = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}, "other": {"t": 1}}})
        before = target.read_bytes()
        p.unlink()
        os.symlink(target, p)
        log = cr.apply_plan(plan)
        self.assertIn(f"SKIP {p}: symlink or not a regular file", log)
        self.assertTrue(p.is_symlink())
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(self.manifest()["edits"], [])
        self.assertEqual(self.manifest()["backups"], [])

    def test_apply_rechecks_right_before_writing(self):
        p = self.write("code/app/.cursor/mcp.json", {"mcpServers": {"srv": {}}})
        plan = [i for i in self.items() if i.kind == "mcp"]
        target = self.write("elsewhere.json", {"mcpServers": {"srv": {}}})
        before = target.read_bytes()
        real_load = cr.load_json

        def load_then_swap(f, *a, **kw):
            data = real_load(f, *a, **kw)
            if Path(f) == p:
                p.unlink()
                os.symlink(target, p)
            return data

        with mock.patch.object(cr, "load_json", side_effect=load_then_swap):
            log = cr.apply_plan(plan)
        self.assertIn(f"SKIP {p}: symlink or not a regular file", log)
        self.assertTrue(p.is_symlink())
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(self.manifest()["edits"], [])

    def test_restore_skips_a_file_turned_into_a_symlink(self):
        p = self.write("code/app/.cursor/mcp.json", {"mcpServers": {"srv": {}}})
        cr.apply_plan([i for i in self.items() if i.kind == "mcp"])
        target = self.write("elsewhere.json", {"mcpServers": {}})
        before = target.read_bytes()
        p.unlink()
        os.symlink(target, p)
        out = self.restore_latest()
        self.assertIn(f"SKIP {p}: symlink or not a regular file", out)
        self.assertTrue(p.is_symlink())
        self.assertEqual(target.read_bytes(), before)


class TestSpecialFilesCli(CliBase):
    def test_report_survives_fifo_deep_nesting_and_huge_file(self):
        d = self.home / "code/app/.cursor"
        d.mkdir(parents=True)
        os.mkfifo(d / "mcp.json")
        (d / "hooks.json").write_text("[" * 200000 + "]" * 200000)
        (d / "cli.json").write_text(json.dumps({"permissions": {"allow": ["x" * (1024 * 1024)]}}))
        for flag in ("--report", "--notify"):
            r = self.run_cli(flag, "--roots", str(self.home / "code"))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("Traceback", r.stderr)


class TestRestoreRobust(FakeHome):
    def items(self):
        return [i for c in cr.scan_all([self.home]) for i in c.items]

    def setup_run(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        proj = cr.PROJECTS_DIR / "12345"
        (proj / "mcps").mkdir(parents=True)
        (proj / "mcps" / "a.json").write_text("{}")
        cr.apply_plan([i for i in self.items() if i.kind in ("mcp", "projdir")])
        return p, proj

    def test_failed_move_back_does_not_stop_json_restore(self):
        p, proj = self.setup_run()
        import shutil
        shutil.rmtree(self.manifest()["moves"][0]["quarantined"])
        out = self.restore_latest()
        self.assertIn(f"FAIL {proj}", out)
        self.assertEqual(cr.load_json(p), {"mcpServers": {"srv": {}}})

    def test_failed_move_back_output_is_sanitized(self):
        p, proj = self.setup_run()
        with mock.patch.object(cr.shutil, "move", side_effect=OSError("bad\x1b[2K")):
            out = self.restore_latest()
        self.assertIn("FAIL", out)
        self.assertNotIn("\x1b", out)
        self.assertEqual(cr.load_json(p), {"mcpServers": {"srv": {}}})


class TestRestoreDryRun(CliBase):
    def test_restore_dry_run_changes_nothing(self):
        p = self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}, "b": {}}})
        proj = cr.PROJECTS_DIR / "12345"
        (proj / "mcps").mkdir(parents=True)
        items = [i for c in cr.scan_all([self.home]) for i in c.items]
        cr.apply_plan([i for i in items if i.kind in ("mcp", "projdir")])
        qdir = self.latest_quarantine()
        layout = sorted(str(x) for x in self.home.rglob("*"))
        data = {x: x.read_bytes() for x in self.home.rglob("*") if x.is_file()}
        r = self.run_cli("--restore", str(qdir), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(str(x) for x in self.home.rglob("*")), layout)
        self.assertEqual({x: x.read_bytes() for x in self.home.rglob("*") if x.is_file()}, data)
        self.assertIn(str(proj), r.stdout)
        self.assertIn("2 entries", r.stdout)
        self.assertIn("would", r.stdout)


class TestGuardHooks(FakeHome):
    def hooks(self):
        self.write(".cursor/hooks.json", {"hooks": {"beforeShellExecution": [{"command": "./guard.sh"}],
                                                    "beforeMCPExecution": ["./g2.sh"],
                                                    "stop": [{"command": "./x.sh"}]}})
        cats = cr.scan_all([self.home / "nowhere"])
        return cats[2], {i.value: i for i in cats[2].items}

    def test_before_hooks_carry_a_warning(self):
        _, by = self.hooks()
        for ev in ("beforeShellExecution", "beforeMCPExecution"):
            self.assertIn("may be a safety check; removing it can allow what it blocked", by[ev].detail)
            self.assertEqual((by[ev].op, by[ev].locked), ("pop_key", False))
        self.assertFalse(any("safety check" in d for d in by["stop"].detail))

    def test_r_key_skips_guard_hooks_space_still_ticks(self):
        cat, by = self.hooks()
        app = cr.App.__new__(cr.App)
        app.scr, app.cats, app.dry_run, app.final, app.colors = (
            FakeScreen([ord("r"), 27]), [cat], True, [], False)
        app.checklist(cat)
        self.assertEqual([i.value for i in cr.chosen(cat.items)], ["stop"])
        cr.tick([by["beforeShellExecution"]], lambda it: True, True)
        self.assertTrue(by["beforeShellExecution"].selected)


class TestAllowlistKeysOnly(FakeHome):
    def test_only_allow_named_keys_are_removable(self):
        self.write(".cursor/permissions.json", {"fooList": ["x"], "trustedThings": ["y"],
                                                "commandAllowList": ["git"], "denyList": ["rm"],
                                                "disallowed": ["z"]})
        items = [i for c in cr.scan_all([self.home / "nowhere"]) for i in c.items
                 if i.file.endswith("permissions.json")]
        removable = {i.value for i in items if i.op and not i.locked}
        self.assertEqual(removable, {"git"})
        other = [i for i in items if i.kind == "other"]
        self.assertEqual(len(other), 1)
        self.assertIn("fooList", other[0].title)
        self.assertIn("trustedThings", other[0].title)
        self.assertEqual({i.value for i in items if i.kind == "block"}, {"rm", "z"})


class TestResolveProject(FakeHome):
    def test_existing_candidate_wins_over_missing_lookalike(self):
        live = self.home / "my-app"
        live.mkdir()
        gone = self.home / "my" / "app"
        name = cr.encode_project(str(live))
        self.assertEqual(cr.encode_project(str(gone)), name)
        for known in ([str(gone), str(live)], [str(live), str(gone)]):
            self.assertEqual(cr.resolve_project(name, known), str(live))

    def test_no_existing_candidate_is_deterministic(self):
        a, b = str(self.home / "x" / "y-z"), str(self.home / "x-y" / "z")
        name = cr.encode_project(a)
        self.assertEqual(cr.resolve_project(name, [b, a]), min(a, b))
        self.assertEqual(cr.resolve_project(name, [a, b]), min(a, b))


class TestSmallFixes(unittest.TestCase):
    def test_home_level_wildcards_are_broad(self):
        home = str(cr.HOME).rstrip("/")
        for tool in ("Read", "Write"):
            for arg in ("~/*", "~/.*", f"{home}/*", f"{home}/.*"):
                self.assertTrue(cr.is_broad(f"{tool}({arg})"), f"{tool}({arg})")
        self.assertFalse(cr.is_broad("Read(~/code/*)"))

    def test_yes_prompt_comes_before_running_warning(self):
        it = cr.Item("mcp", "k", "MCP server: a", file="/home/user/.cursor/mcp.json",
                     jpath=["mcpServers"], value="a", op="pop_key", selected=True)
        app = cr.App.__new__(cr.App)
        app.scr, app.cats, app.dry_run, app.final, app.colors = (
            FakeScreen([ord("y")]), [cr.Category("C", "", [it])], True, [], False)
        app.prompt = mock.Mock(return_value="")
        with mock.patch.object(cr, "running_cursor", return_value=[42]):
            app.review()
        msg = app.prompt.call_args[0][0]
        self.assertTrue(msg.startswith("Type YES to apply"), msg)
        self.assertIn("Cursor is running", msg)


if __name__ == "__main__":
    unittest.main()
