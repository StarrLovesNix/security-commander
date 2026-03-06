"""
Local system security scanner.
Checks: open ports, running processes, user accounts, SSH keys,
SUID files, cron jobs, listening services.
"""

import csv
import io
import subprocess
import os
import re
import logging
import hashlib
from pathlib import Path

from modules import platform_adapter

logger = logging.getLogger(__name__)

# Process names commonly associated with crypto miners / malware
SUSPICIOUS_PROCESS_PATTERNS = [
    # Cross-platform miners / shells
    r'\bxmrig\b', r'\bminerd\b', r'\bcgminer\b', r'\bbfgminer\b',
    r'\bcp?uminer\b', r'\bstratumd\b', r'\bnc\b.*\-[el]\b', r'\bncat\b',
    r'\bmsf\b', r'\bmeterpreter\b', r'\bbind.*shell\b', r'\breverse.*shell\b',
    r'\bpython.*-c.*socket\b', r'\bpython.*pty\.spawn\b',
    # Windows-specific LOLBins and obfuscation techniques
    r'\bpowershell.*-e(nc)?\b',            # Base64-encoded PowerShell payload
    r'\bpowershell.*-nop(rofile)?\b',      # No-profile PowerShell (evasion)
    r'\bpowershell.*-w(indowstyle)?\s+hid', # Hidden-window PowerShell
    r'\bmshta\b',                           # HTML Application host (malware vector)
    r'\bwscript\b', r'\bcscript\b',        # Windows Script Hosts
    r'\bregsvr32.*scrobj\b',               # Squiblydoo COM scriptlet bypass
    r'\bCertUtil.*-decode\b',              # CertUtil base64 decode (AV bypass)
    r'\bbitsadmin.*\/transfer\b',          # BITS job for stealthy download
    r'\bwmic.*process.*call.*create\b',    # WMIC lateral-movement pattern
]

SUSPICIOUS_PROCESS_REGEX = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PROCESS_PATTERNS]

EXPECTED_PRIVILEGED_PROCESSES = {
    # Linux kernel threads and daemons
    'systemd', 'init', 'kthreadd', 'kswapd0', 'ksoftirqd', 'migration',
    'watchdog', 'cpuhp', 'netns', 'kworker', 'kdevtmpfs', 'inet_frag_wq',
    'khungtaskd', 'oom_reaper', 'writeback', 'kcompactd', 'kblockd',
    'irq', 'mmcqd', 'jbd2', 'ext4', 'scsi', 'usb', 'i2c', 'nvme',
    # Windows system processes (always expected to run as SYSTEM)
    'System', 'smss', 'csrss', 'wininit', 'winlogon', 'lsass', 'services',
    'svchost', 'spoolsv', 'dwm', 'fontdrvhost', 'sihost', 'taskhostw',
    'ctfmon', 'conhost', 'dllhost', 'WmiPrvSE', 'msdtc', 'vds',
    'MsMpEng',          # Windows Defender antivirus engine
    'NisSrv',           # Windows Defender network inspection
    'SearchIndexer',    # Windows Search indexer
    'TrustedInstaller', # Windows Update / component servicing
    'wuauclt',          # Windows Update client
    'audiodg',          # Windows Audio Device Graph
    'RuntimeBroker',    # Runtime Broker (UWP app trust)
}


def _run(args, timeout=30):
    """Run a command as a list of arguments (no shell=True)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {args}")
        return ""
    except Exception as e:
        logger.error(f"Command failed: {args} — {e}")
        return ""


def get_open_ports():
    """Return list of locally listening ports with process info."""
    return platform_adapter.list_open_ports()


def get_running_processes():
    """Return list of running processes with user and command."""
    raw = platform_adapter.list_processes_raw()
    processes = []
    for line in raw.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        processes.append({
            "user": parts[0],
            "pid": parts[1],
            "cpu": parts[2],
            "mem": parts[3],
            "cmd": parts[10],
        })
    return processes


def detect_suspicious_processes(processes):
    """Flag processes that match known malware/miner patterns."""
    findings = []
    for proc in processes:
        cmd = proc.get("cmd", "")
        for pattern in SUSPICIOUS_PROCESS_REGEX:
            if pattern.search(cmd):
                findings.append({
                    "type": "suspicious_process",
                    "severity": "HIGH",
                    "pid": proc["pid"],
                    "user": proc["user"],
                    "cmd": cmd,
                    "detail": f"Process matches suspicious pattern: {pattern.pattern}",
                })
                break
        # Flag privileged processes (root / SYSTEM) with unusually high CPU
        if proc["user"].upper() in ("ROOT", "SYSTEM"):
            name = cmd.split()[0].split('/')[-1].split('\\')[-1] if cmd else ""
            if name and name not in EXPECTED_PRIVILEGED_PROCESSES and not name.startswith('['):
                try:
                    cpu = float(proc.get("cpu", 0))
                except ValueError:
                    cpu = 0.0
                if cpu > 80:
                    findings.append({
                        "type": "high_cpu_root_process",
                        "severity": "MEDIUM",
                        "pid": proc["pid"],
                        "user": proc["user"],
                        "cmd": cmd,
                        "detail": f"Privileged process consuming {cpu}% CPU",
                    })
    return findings


def get_user_accounts():
    """Return non-system user accounts."""
    if platform_adapter.SYSTEM == 'Windows':
        return _get_user_accounts_windows()

    # Linux / macOS: parse /etc/passwd
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                uid = int(parts[2]) if parts[2].isdigit() else -1
                if uid >= 1000 and uid != 65534:
                    users.append({
                        "username": parts[0],
                        "uid": uid,
                        "gid": parts[3],
                        "home": parts[5],
                        "shell": parts[6],
                    })
    except Exception as e:
        logger.error(f"Failed to read /etc/passwd: {e}")
    return users


def _get_user_accounts_windows():
    """List local user accounts on Windows using 'net user'."""
    users = []
    output = _run(['net', 'user'])
    # net user output:
    #   User accounts for \\HOSTNAME
    #   -------------------------
    #   Administrator  DefaultAccount  Guest  WDAGUtilityAccount  alice
    #   The command completed successfully.
    in_user_section = False
    for line in output.splitlines():
        if '---' in line:
            in_user_section = True
            continue
        if not in_user_section:
            continue
        if 'The command completed' in line or not line.strip():
            continue
        for name in line.split():
            name = name.strip()
            if name:
                users.append({
                    "username": name,
                    "uid": 0,   # Windows uses SIDs, not Unix UIDs
                    "gid": "",
                    "home": str(Path('C:/Users') / name),
                    "shell": "",
                })
    return users


def get_sudo_users():
    """Return users with elevated privileges (sudo on Linux, Administrators on Windows)."""
    if platform_adapter.SYSTEM == 'Windows':
        return _get_admin_users_windows()

    # Linux / macOS
    output = _run(['getent', 'group', 'sudo', 'wheel'])
    sudo_users = set()
    for line in output.splitlines():
        parts = line.split(':')
        if len(parts) >= 4 and parts[3]:
            for u in parts[3].split(','):
                if u.strip():
                    sudo_users.add(u.strip())
    return list(sudo_users)


def _get_admin_users_windows():
    """Return members of the local Administrators group on Windows."""
    output = _run(['net', 'localgroup', 'Administrators'])
    # net localgroup Administrators output:
    #   Alias name     Administrators
    #   Comment        ...
    #   Members
    #   -------------------------
    #   Administrator
    #   alice
    #   The command completed successfully.
    admins = []
    in_members = False
    for line in output.splitlines():
        if '---' in line:
            in_members = True
            continue
        if not in_members:
            continue
        line = line.strip()
        if not line or 'The command completed' in line:
            continue
        admins.append(line)
    return admins


def get_ssh_authorized_keys():
    """Return all SSH authorized keys found on the system."""
    if platform_adapter.SYSTEM == 'Windows':
        return _get_ssh_keys_windows()

    # Linux / macOS
    keys = []
    home_dirs = ['/root', '/home']
    for base in home_dirs:
        try:
            if base == '/root':
                key_file = Path('/root/.ssh/authorized_keys')
                if key_file.exists():
                    content = key_file.read_text()
                    for line in content.splitlines():
                        if line.strip() and not line.startswith('#'):
                            keys.append({"user": "root", "key": line.strip()[:80]})
            else:
                for user_dir in Path(base).iterdir():
                    key_file = user_dir / '.ssh' / 'authorized_keys'
                    if key_file.exists():
                        content = key_file.read_text()
                        for line in content.splitlines():
                            if line.strip() and not line.startswith('#'):
                                keys.append({
                                    "user": user_dir.name,
                                    "key": line.strip()[:80],
                                })
        except Exception as e:
            logger.debug(f"SSH key scan error in {base}: {e}")
    return keys


def _get_ssh_keys_windows():
    """
    Return SSH authorized keys from Windows OpenSSH locations:
    - C:\\ProgramData\\ssh\\administrators_authorized_keys (system-wide admin keys)
    - C:\\Users\\<user>\\.ssh\\authorized_keys (per-user keys)
    OpenSSH for Windows is included by default in Windows 10 1803+ / Windows 11.
    """
    keys = []

    # System-wide administrator keys (used by OpenSSH when user is in Administrators)
    admin_keys = Path(r'C:\ProgramData\ssh\administrators_authorized_keys')
    if admin_keys.exists():
        try:
            for line in admin_keys.read_text(errors='replace').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    keys.append({"user": "Administrator", "key": line[:80]})
        except Exception as e:
            logger.debug(f"SSH admin key scan error: {e}")

    # Per-user authorized_keys in each profile directory
    users_dir = Path(r'C:\Users')
    if users_dir.exists():
        try:
            for user_dir in users_dir.iterdir():
                if not user_dir.is_dir():
                    continue
                key_file = user_dir / '.ssh' / 'authorized_keys'
                if key_file.exists():
                    try:
                        for line in key_file.read_text(errors='replace').splitlines():
                            line = line.strip()
                            if line and not line.startswith('#'):
                                keys.append({"user": user_dir.name, "key": line[:80]})
                    except Exception as e:
                        logger.debug(f"SSH key scan error for {user_dir.name}: {e}")
        except Exception as e:
            logger.debug(f"SSH key scan error in C:\\Users: {e}")

    return keys


def get_suid_files():
    """
    Find SUID/SGID files (Linux/macOS only).
    Windows does not have the SUID/SGID concept; returns empty list.
    """
    if platform_adapter.SYSTEM == 'Windows':
        return []   # No SUID/SGID on Windows

    try:
        result = subprocess.run(
            ['find',
             '/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin', '/tmp', '/var/tmp',
             '-perm', '/6000', '-type', 'f'],
            capture_output=True, text=True, timeout=30
        )
        return [f for f in result.stdout.strip().splitlines() if f]
    except Exception as e:
        logger.debug(f"SUID scan error: {e}")
        return []


def get_world_writable_sensitive():
    """
    Check for overly permissive files in sensitive system directories.
    Linux/macOS: world-writable files (chmod o+w) in /etc, /usr/bin, etc.
    Windows: files granting Everyone full or write control in System32 / Program Files.
    """
    if platform_adapter.SYSTEM == 'Windows':
        return _get_world_writable_windows()

    # Linux / macOS
    try:
        result = subprocess.run(
            ['find', '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
             '-perm', '-o+w', '-type', 'f'],
            capture_output=True, text=True, timeout=30
        )
        return [f for f in result.stdout.strip().splitlines() if f]
    except Exception as e:
        logger.debug(f"World-writable scan error: {e}")
        return []


def _get_world_writable_windows():
    """
    Find files in critical Windows directories where Everyone has write access.
    Uses icacls to query ACEs; looks for 'Everyone:(W)' or 'Everyone:(F)' entries.
    Scans non-recursively to limit scan time (deep recursive icacls is slow).
    """
    suspicious = []
    sensitive_dirs = [
        Path(r'C:\Windows\System32'),
        Path(r'C:\Program Files'),
        Path(r'C:\Program Files (x86)'),
    ]
    everyone_pattern = re.compile(r'Everyone:.*[WFM]', re.IGNORECASE)

    for directory in sensitive_dirs:
        if not directory.exists():
            continue
        try:
            # Scan immediate children of the sensitive directory (not recursive)
            # to keep runtime reasonable.
            result = subprocess.run(
                ['icacls', str(directory), '/C', '/Q'],
                capture_output=True, text=True, timeout=30
            )
            current_file = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # icacls output: first token of a new entry is the file path
                if not line.startswith(' ') and ':' not in line[:2]:
                    current_file = line.split(':')[0].strip() if ':' in line else line
                if everyone_pattern.search(line) and current_file:
                    suspicious.append(current_file)
                    current_file = None  # report each file once
        except Exception as e:
            logger.debug(f"icacls scan error for {directory}: {e}")

    return suspicious


def get_cron_jobs():
    """
    Collect scheduled tasks.
    Linux/macOS: cron directories and user crontabs.
    Windows: Task Scheduler tasks via schtasks.
    """
    if platform_adapter.SYSTEM == 'Windows':
        return _get_scheduled_tasks_windows()

    # Linux / macOS
    crons = []
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
                 '/etc/cron.weekly', '/etc/cron.monthly']
    for d in cron_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                crons.append(f"{d}/{f}")
    # User crontabs
    output = _run(['crontab', '-l'])
    if output:
        crons.append(f"user_crontab: {output[:200]}")
    return crons


def _get_scheduled_tasks_windows():
    """
    List Windows Task Scheduler tasks using 'schtasks /query /fo CSV /v'.
    Returns a deduplicated list of 'schtask:<name> -> <command>' strings
    so the existing baseline-diff logic in scan() works unchanged.
    """
    tasks = []
    output = _run(['schtasks', '/query', '/fo', 'CSV', '/v'], timeout=60)
    if not output:
        return tasks

    try:
        reader = csv.DictReader(io.StringIO(output))
        seen: set = set()
        for row in reader:
            name = (row.get('TaskName') or '').strip()
            cmd = (row.get('Task To Run') or '').strip()
            if name and name not in seen:
                seen.add(name)
                tasks.append(f"schtask:{name} -> {cmd[:120]}")
    except Exception as e:
        logger.debug(f"schtasks parse error: {e}")

    return tasks


def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def scan(baseline=None):
    """Run full local scan and return findings + current state snapshot."""
    logger.info("Starting local system scan...")
    findings = []
    snapshot = {}

    # --- Open ports ---
    ports = get_open_ports()
    snapshot['open_ports'] = ports
    if baseline:
        baseline_ports = {p['port'] for p in baseline.get('open_ports', [])}
        current_ports = {p['port'] for p in ports}
        new_ports = current_ports - baseline_ports
        for port in new_ports:
            port_info = next((p for p in ports if p['port'] == port), {})
            findings.append({
                "type": "new_open_port",
                "severity": "MEDIUM",
                "port": port,
                "detail": f"New listening port detected: {port} ({port_info.get('process', 'unknown')})",
            })

    # --- Processes ---
    processes = get_running_processes()
    snapshot['process_names'] = list({p['cmd'].split()[0] for p in processes if p['cmd']})
    process_findings = detect_suspicious_processes(processes)
    findings.extend(process_findings)

    # --- Users ---
    users = get_user_accounts()
    snapshot['users'] = [u['username'] for u in users]
    if baseline:
        baseline_users = set(baseline.get('users', []))
        current_users = {u['username'] for u in users}
        new_users = current_users - baseline_users
        for user in new_users:
            user_info = next((u for u in users if u['username'] == user), {})
            findings.append({
                "type": "new_user_account",
                "severity": "HIGH",
                "user": user,
                "detail": f"New user account created: {user} (UID {user_info.get('uid')})",
            })

    # --- Sudo users ---
    sudo_users = get_sudo_users()
    snapshot['sudo_users'] = sudo_users
    if baseline:
        baseline_sudo = set(baseline.get('sudo_users', []))
        new_sudo = set(sudo_users) - baseline_sudo
        for user in new_sudo:
            findings.append({
                "type": "new_sudo_user",
                "severity": "CRITICAL",
                "user": user,
                "detail": f"User gained sudo privileges: {user}",
            })

    # --- SSH keys ---
    ssh_keys = get_ssh_authorized_keys()
    snapshot['ssh_keys'] = ssh_keys
    if baseline:
        baseline_keys = {k['key'][:80] for k in baseline.get('ssh_keys', [])}
        for key_entry in ssh_keys:
            if key_entry['key'][:80] not in baseline_keys:
                findings.append({
                    "type": "new_ssh_key",
                    "severity": "HIGH",
                    "user": key_entry['user'],
                    "detail": f"New SSH authorized key added for user: {key_entry['user']}",
                })

    # --- SUID files ---
    suid_files = get_suid_files()
    snapshot['suid_files'] = suid_files
    if baseline:
        baseline_suid = set(baseline.get('suid_files', []))
        new_suid = set(suid_files) - baseline_suid
        for f in new_suid:
            findings.append({
                "type": "new_suid_file",
                "severity": "HIGH",
                "file": f,
                "detail": f"New SUID/SGID file detected: {f}",
            })

    # --- World-writable sensitive files ---
    ww_files = get_world_writable_sensitive()
    snapshot['world_writable_sensitive'] = ww_files
    for f in ww_files:
        findings.append({
            "type": "world_writable_sensitive",
            "severity": "HIGH",
            "file": f,
            "detail": f"World-writable file in sensitive location: {f}",
        })

    # --- Cron jobs / Scheduled tasks ---
    crons = get_cron_jobs()
    snapshot['cron_jobs'] = crons
    if baseline:
        baseline_crons = set(baseline.get('cron_jobs', []))
        new_crons = set(crons) - baseline_crons
        for c in new_crons:
            findings.append({
                "type": "new_cron_job",
                "severity": "MEDIUM",
                "detail": f"New cron job detected: {c}",
            })

    logger.info(f"Local scan complete: {len(findings)} findings")
    return findings, snapshot
