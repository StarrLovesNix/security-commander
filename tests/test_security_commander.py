"""
Tests for security_commander.py

Covers:
  - _is_admin() cross-platform behaviour
  - LOCK_FILE uses system temp directory (not /tmp hardcoded)
  - acquire_lock / release_lock lifecycle
  - load_config error handling
"""

import sys
import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import security_commander


# ---------------------------------------------------------------------------
# _is_admin
# ---------------------------------------------------------------------------

class TestIsAdmin(unittest.TestCase):

    def test_linux_root_is_admin(self):
        with patch('platform.system', return_value='Linux'), \
             patch('os.geteuid', return_value=0):
            self.assertTrue(security_commander._is_admin())

    def test_linux_non_root_not_admin(self):
        with patch('platform.system', return_value='Linux'), \
             patch('os.geteuid', return_value=1000):
            self.assertFalse(security_commander._is_admin())

    def test_macos_root_is_admin(self):
        with patch('platform.system', return_value='Darwin'), \
             patch('os.geteuid', return_value=0):
            self.assertTrue(security_commander._is_admin())

    def test_windows_admin_via_ctypes(self):
        mock_ctypes = MagicMock()
        mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
        with patch('platform.system', return_value='Windows'), \
             patch.dict('sys.modules', {'ctypes': mock_ctypes}):
            result = security_commander._is_admin()
        self.assertTrue(result)

    def test_windows_non_admin(self):
        mock_ctypes = MagicMock()
        mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 0
        with patch('platform.system', return_value='Windows'), \
             patch.dict('sys.modules', {'ctypes': mock_ctypes}):
            result = security_commander._is_admin()
        self.assertFalse(result)

    def test_windows_ctypes_exception_returns_false(self):
        mock_ctypes = MagicMock()
        mock_ctypes.windll.shell32.IsUserAnAdmin.side_effect = Exception("ctypes error")
        with patch('platform.system', return_value='Windows'), \
             patch.dict('sys.modules', {'ctypes': mock_ctypes}):
            result = security_commander._is_admin()
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# LOCK_FILE path
# ---------------------------------------------------------------------------

class TestLockFilePath(unittest.TestCase):

    def test_lock_file_is_in_temp_dir(self):
        lock = security_commander.LOCK_FILE
        expected_dir = Path(tempfile.gettempdir())
        self.assertEqual(lock.parent, expected_dir,
                         f"LOCK_FILE should be in system temp dir, got: {lock}")
        self.assertEqual(lock.name, 'security_commander.lock')

    def test_lock_file_not_in_slash_tmp_hardcoded(self):
        """Verify the lock file path was not left as the old Linux-only hardcoded /tmp."""
        # /tmp is only valid on POSIX; Windows uses e.g. C:\Users\<user>\AppData\Local\Temp
        lock_str = str(security_commander.LOCK_FILE)
        # The path should NOT be exactly '/tmp/security_commander.lock' anymore
        # (it's OK if tempfile.gettempdir() happens to return /tmp on this system,
        # but the constant should have been set via tempfile, not a hardcoded string)
        import inspect
        source = inspect.getsource(security_commander)
        self.assertNotIn('Path("/tmp/security_commander.lock")', source,
                         "Hardcoded /tmp path should have been removed")


# ---------------------------------------------------------------------------
# acquire_lock / release_lock
# ---------------------------------------------------------------------------

class TestLockLifecycle(unittest.TestCase):

    def setUp(self):
        # Point LOCK_FILE at a temp location for testing
        self._tmpdir = tempfile.mkdtemp()
        self._orig_lock = security_commander.LOCK_FILE
        security_commander.LOCK_FILE = Path(self._tmpdir) / 'test.lock'

    def tearDown(self):
        security_commander.LOCK_FILE = self._orig_lock
        # Clean up any leftover lock file
        lock = Path(self._tmpdir) / 'test.lock'
        if lock.exists():
            lock.unlink()
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_acquire_creates_lock_file(self):
        security_commander.acquire_lock()
        self.assertTrue(security_commander.LOCK_FILE.exists())
        pid = security_commander.LOCK_FILE.read_text().strip()
        self.assertEqual(pid, str(os.getpid()))
        security_commander.release_lock()

    def test_release_removes_lock_file(self):
        security_commander.acquire_lock()
        security_commander.release_lock()
        self.assertFalse(security_commander.LOCK_FILE.exists())

    def test_stale_lock_from_dead_process_is_removed(self):
        # Write a PID that definitely doesn't exist
        security_commander.LOCK_FILE.write_text('999999999')
        # acquire_lock should detect the stale lock and overwrite it
        try:
            security_commander.acquire_lock()
            self.assertTrue(security_commander.LOCK_FILE.exists())
            new_pid = security_commander.LOCK_FILE.read_text().strip()
            self.assertEqual(new_pid, str(os.getpid()))
        finally:
            security_commander.release_lock()


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig(unittest.TestCase):

    def test_missing_config_exits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = security_commander.CONFIG_FILE
            security_commander.CONFIG_FILE = Path(tmpdir) / 'config.json'
            # Also point away from the example so it can't fall back
            orig_example = getattr(security_commander, 'CONFIG_FILE', None)
            try:
                with self.assertRaises(SystemExit) as ctx:
                    security_commander.load_config()
                self.assertEqual(ctx.exception.code, 1)
            finally:
                security_commander.CONFIG_FILE = orig

    def test_valid_config_loads(self):
        cfg = {
            "email": {"enabled": False, "sender": "test@example.com",
                      "smtp_server": "smtp.gmail.com", "smtp_port": 587,
                      "app_password": "test"},
            "scan": {"network_interface": "auto"},
            "thresholds": {},
            "remediation": {},
            "alert_history": {"enabled": True}
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(cfg, f)
            fname = f.name
        orig = security_commander.CONFIG_FILE
        try:
            security_commander.CONFIG_FILE = Path(fname)
            loaded = security_commander.load_config()
            self.assertEqual(loaded['email']['sender'], 'test@example.com')
        finally:
            security_commander.CONFIG_FILE = orig
            os.unlink(fname)


if __name__ == '__main__':
    unittest.main(verbosity=2)
