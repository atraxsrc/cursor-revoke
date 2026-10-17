"""Tests for cursor_revoke, run against a throwaway home folder.

    python3 -m unittest discover -s tests
"""
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

    def test_symlink_not_followed_in_size(self):
        d = self.proj("1792207849852")
        big = self.home / "big"
        big.mkdir()
        (big / "f").write_bytes(b"x" * 5000)
        os.symlink(big, d / "link")
        self.assertLess(self.only("1792207849852").size, 5000)


if __name__ == "__main__":
    unittest.main()
