"""
Tests for modules/log_analyzer.py

Covers:
  - _is_local_ip() — RFC-1918 / loopback detection
  - read_recent_log_lines() — file reading + WinEvent sentinel routing
  - Linux regex parsers: SSH brute force, accepted logins, sudo commands
  - analyze_logs() Linux path — end-to-end with a temporary fake log file
  - Windows mocked path: _read_windows_event_log() and analyze_windows_event_log()
"""

import sys
import os
import unittest
import tempfile
import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import platform_adapter, log_analyzer


# ---------------------------------------------------------------------------
# _is_local_ip
# ---------------------------------------------------------------------------

class TestIsLocalIp(unittest.TestCase):

    def test_rfc1918_10(self):
        for ip in ('10.0.0.1', '10.255.255.255', '10.1.2.3'):
            with self.subTest(ip=ip):
                self.assertTrue(log_analyzer._is_local_ip(ip))

    def test_rfc1918_192_168(self):
        for ip in ('192.168.0.1', '192.168.1.254', '192.168.100.50'):
            with self.subTest(ip=ip):
                self.assertTrue(log_analyzer._is_local_ip(ip))

    def test_rfc1918_172_16_31(self):
        for ip in ('172.16.0.1', '172.31.255.254', '172.20.5.10'):
            with self.subTest(ip=ip):
                self.assertTrue(log_analyzer._is_local_ip(ip))

    def test_loopback(self):
        self.assertTrue(log_analyzer._is_local_ip('127.0.0.1'))
        self.assertTrue(log_analyzer._is_local_ip('127.0.0.254'))

    def test_public_ips_not_local(self):
        for ip in ('8.8.8.8', '1.1.1.1', '185.0.0.1', '203.0.113.5'):
            with self.subTest(ip=ip):
                self.assertFalse(log_analyzer._is_local_ip(ip))

    def test_invalid_ip_does_not_raise(self):
        # Should return False without raising
        self.assertFalse(log_analyzer._is_local_ip('not_an_ip'))
        self.assertFalse(log_analyzer._is_local_ip(''))
        self.assertFalse(log_analyzer._is_local_ip('::1'))   # IPv6


# ---------------------------------------------------------------------------
# read_recent_log_lines — WinEvent sentinel routing
# ---------------------------------------------------------------------------

class TestReadRecentLogLines(unittest.TestCase):

    @patch('modules.log_analyzer._read_windows_event_log')
    def test_winevent_sentinel_routed_to_windows_reader(self, mock_reader):
        mock_reader.return_value = ['fake line 1', 'fake line 2']
        result = log_analyzer.read_recent_log_lines('WinEvent:Security', hours=12)
        mock_reader.assert_called_once_with('Security', 12)
        self.assertEqual(result, ['fake line 1', 'fake line 2'])

    @patch('modules.log_analyzer._read_windows_event_log')
    def test_system_sentinel_routed(self, mock_reader):
        mock_reader.return_value = []
        log_analyzer.read_recent_log_lines('WinEvent:System')
        mock_reader.assert_called_once_with('System', 25)

    def test_nonexistent_file_returns_empty(self):
        result = log_analyzer.read_recent_log_lines('/nonexistent/path/auth.log')
        self.assertEqual(result, [])

    def test_real_file_read(self):
        content = "Jan 01 00:00:00 host sshd: test line\n" * 5
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(content)
            fname = f.name
        try:
            lines = log_analyzer.read_recent_log_lines(fname)
            self.assertEqual(len(lines), 5)
        finally:
            os.unlink(fname)


# ---------------------------------------------------------------------------
# Linux analyze_logs — regex path
# ---------------------------------------------------------------------------

class TestAnalyzeLogsLinux(unittest.TestCase):

    FAKE_AUTH_LOG = """\
Jan 01 06:00:01 host sshd[1234]: Failed password for invalid user root from 203.0.113.5 port 22 ssh2
Jan 01 06:00:02 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jan 01 06:00:03 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jan 01 06:00:04 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jan 01 06:00:05 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jan 01 06:00:06 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2
Jan 01 06:01:00 host sshd[5678]: Accepted password for alice from 192.168.1.10 port 54321 ssh2
Jan 01 06:02:00 host sshd[5679]: Accepted password for bob from 8.8.8.8 port 12345 ssh2
Jan 01 06:03:00 host sudo:  charlie : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/useradd newuser
Jan 01 06:04:00 host sudo: pam_unix(sudo:auth): authentication failure; logname=dave uid=1001 tty=/dev/pts/1 ruser=dave rhost= user=dave
Jan 01 06:04:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=dave uid=1001 tty=/dev/pts/1 ruser=dave rhost= user=dave
Jan 01 06:04:02 host sudo: pam_unix(sudo:auth): authentication failure; logname=dave uid=1001 tty=/dev/pts/1 ruser=dave rhost= user=dave
"""

    def _analyze(self, log_content, warn=5, block=20):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            fname = f.name
        try:
            config = {
                'thresholds': {
                    'failed_ssh_attempts_warning': warn,
                    'failed_ssh_attempts_block': block,
                }
            }
            with patch('modules.platform_adapter.SYSTEM', 'Linux'), \
                 patch('modules.log_analyzer.platform_adapter.SYSTEM', 'Linux'), \
                 patch('modules.log_analyzer.platform_adapter.get_auth_log_paths',
                       return_value=[fname]):
                findings, stats = log_analyzer.analyze_logs(config)
        finally:
            os.unlink(fname)
        return findings, stats

    def test_brute_force_warning_detected(self):
        findings, stats = self._analyze(self.FAKE_AUTH_LOG, warn=5, block=20)
        ssh_fails = [f for f in findings if f['type'] == 'ssh_failed_attempts']
        self.assertEqual(len(ssh_fails), 1)
        self.assertEqual(ssh_fails[0]['ip'], '203.0.113.5')
        self.assertEqual(ssh_fails[0]['severity'], 'HIGH')
        self.assertEqual(ssh_fails[0]['count'], 6)

    def test_brute_force_block_threshold(self):
        # 6 attempts, block threshold = 5
        findings, _ = self._analyze(self.FAKE_AUTH_LOG, warn=3, block=5)
        criticals = [f for f in findings if f['type'] == 'brute_force_ssh']
        self.assertEqual(len(criticals), 1)
        self.assertTrue(criticals[0]['auto_remediate'])
        self.assertEqual(criticals[0]['severity'], 'CRITICAL')

    def test_local_login_not_flagged(self):
        findings, _ = self._analyze(self.FAKE_AUTH_LOG)
        external_logins = [f for f in findings if f['type'] == 'ssh_login_external_ip']
        ips = {f['ip'] for f in external_logins}
        # 192.168.1.10 is internal — should NOT be flagged
        self.assertNotIn('192.168.1.10', ips)

    def test_external_login_flagged(self):
        findings, _ = self._analyze(self.FAKE_AUTH_LOG)
        external_logins = [f for f in findings if f['type'] == 'ssh_login_external_ip']
        ips = {f['ip'] for f in external_logins}
        # 8.8.8.8 is external — should be flagged
        self.assertIn('8.8.8.8', ips)

    def test_dangerous_sudo_command_flagged(self):
        findings, _ = self._analyze(self.FAKE_AUTH_LOG)
        dangerous = [f for f in findings if f['type'] == 'dangerous_sudo_command']
        self.assertEqual(len(dangerous), 1)
        self.assertIn('useradd', dangerous[0]['command'])
        self.assertEqual(dangerous[0]['user'], 'charlie')

    def test_sudo_auth_failures_flagged(self):
        findings, _ = self._analyze(self.FAKE_AUTH_LOG)
        sudo_fails = [f for f in findings if f['type'] == 'sudo_auth_failure']
        self.assertEqual(len(sudo_fails), 1)
        self.assertEqual(sudo_fails[0]['user'], 'dave')
        self.assertEqual(sudo_fails[0]['count'], 3)

    def test_stats_returned(self):
        _, stats = self._analyze(self.FAKE_AUTH_LOG)
        self.assertIn('failed_ssh_by_ip', stats)
        self.assertIn('accepted_logins_count', stats)
        self.assertIn('sudo_commands_count', stats)
        self.assertEqual(stats['accepted_logins_count'], 2)
        self.assertEqual(stats['sudo_commands_count'], 1)

    def test_no_findings_on_clean_log(self):
        clean = "Jan 01 00:00:00 host kernel: Started session\n"
        findings, _ = self._analyze(clean)
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# Windows Event Log XML parsing — mocked wevtutil
# ---------------------------------------------------------------------------

def _make_event_xml(event_id, ip='203.0.113.99', user='baduser',
                    logon_type='3', cmd='', hostname='TESTPC'):
    """Build a minimal wevtutil XML event fragment."""
    NS = 'http://schemas.microsoft.com/win/2004/08/events/event'
    ts = '2024-01-01T06:00:00.000000000Z'

    if event_id == 4625:
        data = (f'<Data Name="IpAddress">{ip}</Data>'
                f'<Data Name="TargetUserName">{user}</Data>')
    elif event_id == 4624:
        data = (f'<Data Name="IpAddress">{ip}</Data>'
                f'<Data Name="TargetUserName">{user}</Data>'
                f'<Data Name="LogonType">{logon_type}</Data>')
    elif event_id == 4720:
        data = (f'<Data Name="TargetUserName">{user}</Data>'
                f'<Data Name="SubjectUserName">Admin</Data>')
    elif event_id == 4732:
        data = (f'<Data Name="MemberName">{user}</Data>'
                f'<Data Name="TargetUserName">Administrators</Data>'
                f'<Data Name="SubjectUserName">Admin</Data>')
    elif event_id == 4688:
        data = (f'<Data Name="SubjectUserName">{user}</Data>'
                f'<Data Name="CommandLine">{cmd}</Data>')
    elif event_id == 6008:
        data = ''
    else:
        data = ''

    return f"""<Event xmlns="{NS}">
  <System>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{ts}"/>
    <Computer>{hostname}</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""


class TestWindowsEventLogReader(unittest.TestCase):

    def _fake_wevtutil(self, events_xml):
        """Return a mock subprocess result containing the given XML events."""
        mock_result = MagicMock()
        mock_result.stdout = events_xml
        mock_result.returncode = 0
        return mock_result

    @patch('subprocess.run')
    def test_failed_logon_becomes_pseudo_syslog_line(self, mock_subproc):
        xml = _make_event_xml(4625, ip='185.0.0.1')
        mock_subproc.return_value = self._fake_wevtutil(xml)
        lines = log_analyzer._read_windows_event_log('Security', hours=25)
        self.assertGreater(len(lines), 0)
        found = any('Failed password' in l and '185.0.0.1' in l for l in lines)
        self.assertTrue(found, f"Expected 4625 → 'Failed password' line. Got: {lines}")

    @patch('subprocess.run')
    def test_network_logon_becomes_accepted_line(self, mock_subproc):
        xml = _make_event_xml(4624, ip='8.8.8.8', user='alice', logon_type='3')
        mock_subproc.return_value = self._fake_wevtutil(xml)
        lines = log_analyzer._read_windows_event_log('Security', hours=25)
        found = any('Accepted password for alice' in l and '8.8.8.8' in l for l in lines)
        self.assertTrue(found, f"Expected 4624 → 'Accepted password' line. Got: {lines}")

    @patch('subprocess.run')
    def test_local_logon_not_emitted_as_accepted(self, mock_subproc):
        """Logon type 2 (interactive/local) should not produce an accepted-login line."""
        xml = _make_event_xml(4624, ip='127.0.0.1', user='alice', logon_type='2')
        mock_subproc.return_value = self._fake_wevtutil(xml)
        lines = log_analyzer._read_windows_event_log('Security', hours=25)
        found = any('Accepted password' in l for l in lines)
        self.assertFalse(found, "Local interactive logon should not produce an accepted-login line")

    @patch('subprocess.run')
    def test_wevtutil_not_found_returns_empty(self, mock_subproc):
        mock_subproc.side_effect = FileNotFoundError("wevtutil not found")
        lines = log_analyzer._read_windows_event_log('Security')
        self.assertEqual(lines, [])

    @patch('subprocess.run')
    def test_empty_output_returns_empty(self, mock_subproc):
        mock_subproc.return_value = self._fake_wevtutil('')
        lines = log_analyzer._read_windows_event_log('Security')
        self.assertEqual(lines, [])

    @patch('subprocess.run')
    def test_bad_xml_returns_empty(self, mock_subproc):
        mock_subproc.return_value = self._fake_wevtutil('<not valid xml')
        lines = log_analyzer._read_windows_event_log('Security')
        self.assertEqual(lines, [])


class TestAnalyzeWindowsEventLog(unittest.TestCase):

    def _run_analysis(self, security_events_xml, system_events_xml='',
                      warn=5, block=20):
        config = {
            'thresholds': {
                'failed_ssh_attempts_warning': warn,
                'failed_ssh_attempts_block': block,
            }
        }

        def fake_subproc(args, **kwargs):
            result = MagicMock()
            result.returncode = 0
            if 'Security' in args:
                result.stdout = security_events_xml
            else:
                result.stdout = system_events_xml
            return result

        with patch('subprocess.run', side_effect=fake_subproc), \
             patch('modules.log_analyzer.platform_adapter.get_hostname',
                   return_value='TESTPC'):
            findings, stats = log_analyzer.analyze_windows_event_log(config)

        return findings, stats

    def test_brute_force_warning(self):
        # 6 failed logons from same IP, warn threshold = 5
        events = ''.join(_make_event_xml(4625, ip='185.0.0.1') for _ in range(6))
        findings, stats = self._run_analysis(events, warn=5, block=20)
        fails = [f for f in findings if f['type'] == 'ssh_failed_attempts']
        self.assertEqual(len(fails), 1)
        self.assertEqual(fails[0]['ip'], '185.0.0.1')
        self.assertEqual(fails[0]['count'], 6)

    def test_brute_force_critical(self):
        events = ''.join(_make_event_xml(4625, ip='1.2.3.4') for _ in range(25))
        findings, _ = self._run_analysis(events, warn=5, block=20)
        criticals = [f for f in findings if f['type'] == 'brute_force_ssh']
        self.assertEqual(len(criticals), 1)
        self.assertTrue(criticals[0]['auto_remediate'])

    def test_external_network_logon_flagged(self):
        event = _make_event_xml(4624, ip='8.8.8.8', user='alice', logon_type='3')
        findings, _ = self._run_analysis(event)
        ext_logins = [f for f in findings if f['type'] == 'ssh_login_external_ip']
        self.assertEqual(len(ext_logins), 1)
        self.assertEqual(ext_logins[0]['ip'], '8.8.8.8')

    def test_local_logon_not_flagged(self):
        event = _make_event_xml(4624, ip='192.168.1.5', user='alice', logon_type='3')
        findings, _ = self._run_analysis(event)
        ext = [f for f in findings if f['type'] == 'ssh_login_external_ip']
        self.assertEqual(ext, [])

    def test_new_user_account_flagged(self):
        event = _make_event_xml(4720, user='newuser')
        findings, _ = self._run_analysis(event)
        new_users = [f for f in findings if f['type'] == 'new_user_account']
        self.assertEqual(len(new_users), 1)
        self.assertIn('newuser', new_users[0]['detail'])

    def test_group_membership_change_flagged(self):
        event = _make_event_xml(4732, user='hacker')
        findings, _ = self._run_analysis(event)
        group_changes = [f for f in findings if f['type'] == 'new_sudo_user']
        self.assertEqual(len(group_changes), 1)
        self.assertEqual(group_changes[0]['severity'], 'CRITICAL')

    def test_encoded_powershell_process_flagged(self):
        event = _make_event_xml(4688, user='alice',
                                cmd='powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAY')
        findings, _ = self._run_analysis(event)
        procs = [f for f in findings if f['type'] == 'dangerous_sudo_command']
        self.assertEqual(len(procs), 1, "Encoded PowerShell should trigger dangerous process finding")

    def test_stats_returned(self):
        events = _make_event_xml(4625, ip='5.6.7.8')
        _, stats = self._run_analysis(events)
        self.assertIn('failed_logons_by_ip', stats)
        self.assertIn('remote_logons_count', stats)
        self.assertIn('new_users_count', stats)
        self.assertIn('group_changes_count', stats)

    def test_empty_event_log_no_findings(self):
        findings, _ = self._run_analysis('')
        self.assertEqual(findings, [])


# ---------------------------------------------------------------------------
# analyze_logs dispatch — Windows vs Linux
# ---------------------------------------------------------------------------

class TestAnalyzeLogsDispatch(unittest.TestCase):

    @patch('modules.log_analyzer.analyze_windows_event_log')
    def test_dispatches_to_windows_on_windows(self, mock_win):
        mock_win.return_value = ([], {})
        with patch('modules.log_analyzer.platform_adapter.SYSTEM', 'Windows'):
            log_analyzer.analyze_logs({})
        mock_win.assert_called_once()

    @patch('modules.log_analyzer.platform_adapter.get_auth_log_paths',
           return_value=['/nonexistent/auth.log'])
    def test_does_not_dispatch_to_windows_on_linux(self, _mock_paths):
        with patch('modules.log_analyzer.platform_adapter.SYSTEM', 'Linux'), \
             patch('modules.log_analyzer.analyze_windows_event_log') as mock_win:
            log_analyzer.analyze_logs({})
        mock_win.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
