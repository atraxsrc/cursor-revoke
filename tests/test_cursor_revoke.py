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


if __name__ == "__main__":
    unittest.main()
