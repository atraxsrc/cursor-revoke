"""Tests for cursor_revoke, run against a throwaway home folder.

    python3 -m unittest discover -s tests
"""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
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

    def test_quarantine_folders_are_private(self):
        self.write(".cursor/mcp.json", {"mcpServers": {"srv": {}}})
        (cr.PROJECTS_DIR / "12345").mkdir(parents=True)
        cr.QUARANTINE_ROOT.mkdir(mode=0o775)
        os.chmod(cr.QUARANTINE_ROOT, 0o775)
        cr.apply_plan([i for i in self.items() if i.kind in ("mcp", "projdir")])
        qdir = self.latest_quarantine()
        for d in (cr.QUARANTINE_ROOT, qdir, qdir / "backup", qdir / "projects"):
            self.assertEqual(mode(d), 0o700, d)


if __name__ == "__main__":
    unittest.main()
