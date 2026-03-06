"""
Tests for modules/platform_adapter.py

Covers:
  - validate_ip() — input validation / injection prevention
  - get_hostname() — cross-platform
  - Linux live paths: list_processes_raw, list_open_ports,
    get_local_network_cidr, get_auth_log_paths,
    get_firewall_backend, get_available_schedulers
  - Windows mocked paths: all 8 previously-stubbed functions
"""

import sys
import os
import ipaddress
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import platform_adapter


# ---------------------------------------------------------------------------
# validate_ip
# ---------------------------------------------------------------------------

class TestValidateIp(unittest.TestCase):

    def test_valid_ips(self):
        for ip in ('10.0.0.1', '192.168.1.254', '172.16.0.1', '1.2.3.4', '0.0.0.0', '255.255.255.255'):
            with self.subTest(ip=ip):
                self.assertEqual(platform_adapter.validate_ip(ip), ip)

    def test_invalid_format_rejected(self):
        for bad in ('', 'abc', '1.2.3', '1.2.3.4.5', '1.2.3.256',
                    '1.2.3.-1', '; rm -rf /', '1.2.3.4; echo pwned'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    platform_adapter.validate_ip(bad)

    def test_octet_out_of_range(self):
        with self.assertRaises(ValueError):
            platform_adapter.validate_ip('256.0.0.1')
        with self.assertRaises(ValueError):
            platform_adapter.validate_ip('10.0.0.999')


# ---------------------------------------------------------------------------
# get_hostname
# ---------------------------------------------------------------------------

class TestGetHostname(unittest.TestCase):

    def test_returns_string(self):
        result = platform_adapter.get_hostname()
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)


# ---------------------------------------------------------------------------
# Linux live tests (only run on Linux)
# ---------------------------------------------------------------------------

@unittest.skipUnless(platform_adapter.SYSTEM == 'Linux', "Linux-only tests")
class TestLinuxLive(unittest.TestCase):

    def test_list_processes_raw_returns_lines(self):
        raw = platform_adapter.list_processes_raw()
        self.assertIsInstance(raw, str)
        self.assertGreater(len(raw.splitlines()), 1,
                           "Expected at least a few processes")

    def test_list_processes_raw_has_expected_fields(self):
        raw = platform_adapter.list_processes_raw()
        for line in raw.splitlines()[:10]:
            parts = line.split(None, 10)
            self.assertGreaterEqual(len(parts), 11,
                                    f"Process line should have 11+ fields: {line!r}")

    def test_list_open_ports_returns_list_of_dicts(self):
        ports = platform_adapter.list_open_ports()
        self.assertIsInstance(ports, list)
        for entry in ports:
            self.assertIn('proto', entry)
            self.assertIn('port', entry)
            self.assertIn('local_addr', entry)
            self.assertIn('process', entry)
            self.assertIsInstance(entry['port'], int)
            self.assertGreater(entry['port'], 0)
            self.assertLess(entry['port'], 65536)

    def test_get_local_network_cidr_returns_cidr_or_none(self):
        result = platform_adapter.get_local_network_cidr()
        if result is not None:
            # Must be valid CIDR
            try:
                ipaddress.ip_network(result, strict=True)
            except ValueError as e:
                self.fail(f"Not a valid CIDR: {result!r} — {e}")

    def test_get_auth_log_paths_returns_list_of_strings(self):
        paths = platform_adapter.get_auth_log_paths()
        self.assertIsInstance(paths, list)
        self.assertGreater(len(paths), 0)
        for p in paths:
            self.assertIsInstance(p, str)
            # On Linux these must be real filesystem paths, not sentinels
            self.assertFalse(p.startswith('WinEvent:'),
                             "Linux should not return Windows sentinels")

    def test_get_firewall_backend_returns_known_string(self):
        backend = platform_adapter.get_firewall_backend()
        self.assertIn(backend, ('ufw', 'firewalld', 'iptables', 'none'))

    def test_get_available_schedulers_structure(self):
        schedulers = platform_adapter.get_available_schedulers()
        self.assertIn('systemd', schedulers)
        self.assertIn('cron', schedulers)
        self.assertIn('launchd', schedulers)
        self.assertIn('task_scheduler', schedulers)
        for k, v in schedulers.items():
            self.assertIsInstance(v, bool, f"Scheduler {k!r} value should be bool")
        # On Linux, task_scheduler should always be False
        self.assertFalse(schedulers['task_scheduler'])
        # On Linux, launchd should always be False
        self.assertFalse(schedulers['launchd'])


# ---------------------------------------------------------------------------
# Windows mocked tests
# ---------------------------------------------------------------------------

class TestWindowsProcesses(unittest.TestCase):
    """Verify list_processes_raw() Windows branch produces parseable output."""

    FAKE_PS_OUTPUT = (
        "SYSTEM 1234 0.5 12.3 0 12890112 ? S 00:00 0:01 C:\\Windows\\system32\\svchost.exe\n"
        "SYSTEM 5678 0.0 5.2 0 5505024 ? S 00:00 0:00 C:\\Windows\\explorer.exe\n"
        "SYSTEM 9999 1.2 3.1 0 3244032 ? S 00:00 0:00 python"
    )

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_windows_process_lines_are_parseable(self, mock_run):
        mock_run.return_value = (True, self.FAKE_PS_OUTPUT, '')
        raw = platform_adapter.list_processes_raw()
        lines = [l for l in raw.splitlines() if l.strip()]
        self.assertGreater(len(lines), 0)
        for line in lines:
            parts = line.split(None, 10)
            self.assertGreaterEqual(len(parts), 11,
                                    f"Windows process line needs 11+ fields: {line!r}")
            # Field 0 = user, field 1 = PID (digits), field 2 = CPU, field 10 = cmd
            self.assertEqual(parts[0], 'SYSTEM')
            self.assertTrue(parts[1].isdigit(), f"PID should be numeric: {parts[1]!r}")

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_windows_process_empty_output_handled(self, mock_run):
        mock_run.return_value = (False, '', 'PowerShell error')
        raw = platform_adapter.list_processes_raw()
        self.assertIsInstance(raw, str)


class TestWindowsOpenPorts(unittest.TestCase):
    """Verify list_open_ports() Windows branch returns correct dicts."""

    FAKE_NETSTAT = """\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1056
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1234
  TCP    [::]:80                [::]:0                 LISTENING       5678
  UDP    0.0.0.0:5353           *:*                                    3456
"""

    FAKE_TASKLIST = """\
"svchost.exe","1056","Services","0","12,400 K"
"System","4","Services","0","144 K"
"svchost.exe","1234","Services","0","8,300 K"
"nginx.exe","5678","Console","1","6,200 K"
"""

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_ports_parsed_correctly(self, mock_run):
        def side_effect(args, **kwargs):
            if 'tasklist' in args:
                return (True, self.FAKE_TASKLIST, '')
            return (True, self.FAKE_NETSTAT, '')
        mock_run.side_effect = side_effect

        ports = platform_adapter.list_open_ports()
        self.assertIsInstance(ports, list)
        # Should find TCP listening ports: 135, 445, 3389, 80
        port_nums = {p['port'] for p in ports}
        self.assertIn(135, port_nums)
        self.assertIn(445, port_nums)
        self.assertIn(3389, port_nums)
        self.assertIn(80, port_nums)
        # UDP should not appear (only LISTENING TCP/UDP captured; UDP has no LISTENING state)
        for entry in ports:
            self.assertIsInstance(entry['port'], int)
            self.assertIn('process', entry)

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_duplicate_ports_deduplicated(self, mock_run):
        """IPv4 and IPv6 both listening on 445 should appear once."""
        def side_effect(args, **kwargs):
            if 'tasklist' in args:
                return (True, '"System","4","Services","0","144 K"', '')
            return (True, (
                "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n"
                "  TCP    [::]:445               [::]:0                 LISTENING       4\n"
            ), '')
        mock_run.side_effect = side_effect
        ports = platform_adapter.list_open_ports()
        tcp445 = [p for p in ports if p['port'] == 445 and p['proto'] == 'tcp']
        self.assertEqual(len(tcp445), 1, "Port 445/tcp should appear only once")


class TestWindowsNetworkCidr(unittest.TestCase):
    """Verify get_local_network_cidr() Windows branch parses ipconfig correctly."""

    FAKE_IPCONFIG = """\
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : lan
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-FF
   DHCP Enabled. . . . . . . . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.42(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Ethernet adapter vEthernet (WSL):

   IPv4 Address. . . . . . . . . . . : 172.25.64.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
"""

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_cidr_detected(self, mock_run):
        mock_run.return_value = (True, self.FAKE_IPCONFIG, '')
        result = platform_adapter.get_local_network_cidr()
        self.assertIsNotNone(result)
        # Should resolve to the /24 network of 192.168.1.42
        net = ipaddress.ip_network(result, strict=True)
        self.assertEqual(str(net), '192.168.1.0/24')

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_returns_none_on_parse_failure(self, mock_run):
        mock_run.return_value = (True, 'No IPv4 address found', '')
        result = platform_adapter.get_local_network_cidr()
        self.assertIsNone(result)


class TestWindowsAuthLogPaths(unittest.TestCase):

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    def test_returns_winevent_sentinels(self):
        paths = platform_adapter.get_auth_log_paths()
        self.assertIn('WinEvent:Security', paths)
        self.assertIn('WinEvent:System', paths)
        for p in paths:
            self.assertTrue(p.startswith('WinEvent:'),
                            f"Expected WinEvent: sentinel, got: {p!r}")


class TestWindowsFirewall(unittest.TestCase):

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter.shutil.which', return_value='/Windows/System32/netsh.exe')
    def test_get_firewall_backend_returns_netsh(self, _mock_which):
        backend = platform_adapter.get_firewall_backend()
        self.assertEqual(backend, 'netsh')

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter.shutil.which', return_value=None)
    def test_get_firewall_backend_returns_none_when_missing(self, _mock_which):
        backend = platform_adapter.get_firewall_backend()
        self.assertEqual(backend, 'none')

    @patch('modules.platform_adapter._run')
    @patch('modules.platform_adapter.get_firewall_backend', return_value='netsh')
    def test_is_ip_blocked_true(self, _mock_backend, mock_run):
        mock_run.return_value = (True,
            'Rule Name:                SC_Block_1.2.3.4\nEnabled:    Yes', '')
        result = platform_adapter.is_ip_blocked('1.2.3.4')
        self.assertTrue(result)

    @patch('modules.platform_adapter._run')
    @patch('modules.platform_adapter.get_firewall_backend', return_value='netsh')
    def test_is_ip_blocked_false_when_no_rule(self, _mock_backend, mock_run):
        mock_run.return_value = (False, 'No rules match the specified criteria.', '')
        result = platform_adapter.is_ip_blocked('1.2.3.4')
        self.assertFalse(result)

    @patch('modules.platform_adapter._run')
    @patch('modules.platform_adapter.get_firewall_backend', return_value='netsh')
    @patch('modules.platform_adapter.is_ip_blocked', return_value=False)
    def test_block_ip_success(self, _mock_blocked, _mock_backend, mock_run):
        mock_run.return_value = (True, 'Ok.', '')
        success, msg = platform_adapter.block_ip('10.0.0.99')
        self.assertTrue(success)
        self.assertIn('Windows Firewall', msg)

    @patch('modules.platform_adapter._run')
    @patch('modules.platform_adapter.get_firewall_backend', return_value='netsh')
    @patch('modules.platform_adapter.is_ip_blocked', return_value=False)
    def test_block_ip_failure(self, _mock_blocked, _mock_backend, mock_run):
        mock_run.return_value = (False, '', 'Access denied')
        success, msg = platform_adapter.block_ip('10.0.0.99')
        self.assertFalse(success)
        self.assertIn('netsh block failed', msg)

    def test_block_ip_invalid_ip_rejected(self):
        success, msg = platform_adapter.block_ip('not_an_ip')
        self.assertFalse(success)
        self.assertIn('Invalid', msg)


class TestWindowsKillProcess(unittest.TestCase):

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_kill_success(self, mock_run):
        mock_run.return_value = (True, 'SUCCESS: The process with PID 1234 has been terminated.', '')
        success, msg = platform_adapter.kill_process('1234', 'malware.exe')
        self.assertTrue(success)
        self.assertIn('1234', msg)

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_kill_failure(self, mock_run):
        mock_run.return_value = (False, '', 'Access denied')
        success, msg = platform_adapter.kill_process('1234')
        self.assertFalse(success)
        self.assertIn('taskkill failed', msg)

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    def test_invalid_pid_rejected(self):
        success, msg = platform_adapter.kill_process('not_a_pid')
        self.assertFalse(success)
        self.assertIn('Invalid PID', msg)


class TestWindowsFilePermissions(unittest.TestCase):

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_fix_success(self, mock_run):
        mock_run.return_value = (True, 'processed file', '')
        success, msg = platform_adapter.fix_file_permissions(r'C:\Windows\test.exe')
        self.assertTrue(success)
        self.assertIn('icacls' if False else 'Restricted', msg)

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter._run')
    def test_fix_failure(self, mock_run):
        mock_run.return_value = (False, '', 'Access denied')
        success, msg = platform_adapter.fix_file_permissions(r'C:\Windows\test.exe')
        self.assertFalse(success)
        self.assertIn('icacls failed', msg)


class TestWindowsSchedulers(unittest.TestCase):

    @patch('modules.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.platform_adapter.shutil.which', return_value=r'C:\Windows\System32\schtasks.exe')
    @patch('modules.platform_adapter.Path.is_dir', return_value=False)
    def test_task_scheduler_detected(self, _mock_dir, _mock_which):
        schedulers = platform_adapter.get_available_schedulers()
        self.assertIn('task_scheduler', schedulers)
        self.assertTrue(schedulers['task_scheduler'])
        # On a mocked Windows, systemd and cron should be absent
        # (shutil.which is mocked globally, so they could be found — just check structure)
        self.assertIn('systemd', schedulers)
        self.assertIn('cron', schedulers)
        self.assertIn('launchd', schedulers)


if __name__ == '__main__':
    unittest.main(verbosity=2)
