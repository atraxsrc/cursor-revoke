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


class TestItem(unittest.TestCase):
    def test_locked_defaults_false(self):
        it = cr.Item("allow", "Shell(ls)", "x")
        self.assertIs(it.locked, False)
        self.assertEqual(it.op, "")
        self.assertEqual(it.jpath, [])


if __name__ == "__main__":
    unittest.main()
