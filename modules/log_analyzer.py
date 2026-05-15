"""
Auth log and syslog analyzer.
Detects: brute force SSH/logon, unusual logins, privilege abuse, auth failures.

On Linux/macOS: parses text-based auth log files (syslog format).
On Windows: queries the Windows Security Event Log via wevtutil, then maps
            Event IDs to the same finding types used by the Linux path.

Log file paths / sources are resolved via platform_adapter.get_auth_log_paths()
so this module works on Debian/Ubuntu, RHEL/Fedora, macOS, and Windows 10/11.
"""

import re
import os
import logging
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from modules import platform_adapter

logger = logging.getLogger(__name__)


def _sanitize(value: str, max_len: int = 300) -> str:
    """Strip control characters from strings derived from log/event data."""
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', str(value))
    return cleaned[:max_len]


SSH_FAILED_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(?:Failed password|Invalid user|authentication failure).*from\s+([\d\.a-fA-F:]+)',
    re.IGNORECASE
)
SSH_ACCEPTED_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted\s+\w+\s+for\s+(\w+)\s+from\s+([\d\.a-fA-F:]+)',
    re.IGNORECASE
)
SUDO_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*:\s+(\w+)\s+:.*COMMAND=(.*)',
    re.IGNORECASE
)
SUDO_FAIL_RE = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*authentication failure.*user=(\w+)',
    re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Windows Event Log reader
# ---------------------------------------------------------------------------

# Windows Security Event IDs of interest
_WIN_SECURITY_EVENT_IDS = {
    4625,   # Failed logon (brute force / failed auth)
    4624,   # Successful logon
    4720,   # User account created
    4726,   # User account deleted
    4728,   # Member added to security-enabled global group (Admins)
    4732,   # Member added to security-enabled local group (Admins)
    4756,   # Member added to security-enabled universal group
    4672,   # Special privileges assigned to new logon (admin logon)
    4688,   # New process created (command execution tracking)
}

_WIN_SYSTEM_EVENT_IDS = {
    6005,   # Event Log service started (system boot)
    6006,   # Event Log service stopped (system shutdown)
    6008,   # Unexpected shutdown
}

# WinEvent XML namespace used by wevtutil
_NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


def _xml_text(element, *path):
    """
    Safely extract text from an XML element using a chain of tag names.
    Returns empty string if any step is missing.
    """
    node = element
    for tag in path:
        node = node.find(f'{{{_NS}}}{tag}')
        if node is None:
            return ''
    return (node.text or '').strip()


def _get_event_data(event_element, name):
    """Extract a named Data element from the EventData section."""
    event_data = event_element.find(f'{{{_NS}}}EventData')
    if event_data is None:
        return ''
    for data in event_data.findall(f'{{{_NS}}}Data'):
        if data.get('Name') == name:
            return (data.text or '').strip()
    return ''


def _read_windows_event_log(channel: str, hours: int = 25) -> list:
    """
    Query a Windows Event Log channel via wevtutil and return a list of
    pseudo-syslog lines that the existing regex patterns can match, plus
    raw event dicts for Windows-specific findings.

    Returns a list of strings (for the regex-based analysis path) AND
    stores parsed events in a module-level cache used by analyze_windows_event_log().

    Args:
        channel: Event Log channel name ('Security' or 'System')
        hours: How far back to look (approximate — uses wevtutil time filter)

    Returns:
        List of synthetic syslog-style strings for the existing regex parsers.
    """
    if channel == 'Security':
        ids_filter = ' or '.join(f'EventID={eid}' for eid in _WIN_SECURITY_EVENT_IDS)
    else:
        ids_filter = ' or '.join(f'EventID={eid}' for eid in _WIN_SYSTEM_EVENT_IDS)

    # wevtutil time filter: milliseconds since event, SystemTime comparison
    ms_window = hours * 3600 * 1000
    xpath_query = (
        f"*[System[({ids_filter}) and "
        f"TimeCreated[timediff(@SystemTime) <= {ms_window}]]]"
    )

    try:
        result = subprocess.run(
            ['wevtutil', 'qe', channel,
             f'/q:{xpath_query}',
             '/f:XML',
             '/c:2000',        # cap at 2000 events per channel
             '/rd:true'],      # most recent first
            capture_output=True, text=True, timeout=60,
            errors='replace'
        )
    except FileNotFoundError:
        logger.warning("wevtutil not found — Windows Event Log analysis skipped")
        return []
    except subprocess.TimeoutExpired:
        logger.warning(f"wevtutil timed out reading {channel} log")
        return []
    except Exception as e:
        logger.error(f"wevtutil error for {channel}: {e}")
        return []

    if not result.stdout.strip():
        return []

    # wevtutil returns multiple root-level <Event> elements; wrap in a root tag
    xml_blob = f'<Events>{result.stdout}</Events>'
    try:
        root = ET.fromstring(xml_blob)
    except ET.ParseError as e:
        logger.warning(f"Failed to parse Event Log XML from {channel}: {e}")
        return []

    pseudo_lines = []
    for event in root.findall(f'{{{_NS}}}Event'):
        system = event.find(f'{{{_NS}}}System')
        if system is None:
            continue

        eid_el = system.find(f'{{{_NS}}}EventID')
        eid = int(eid_el.text or 0) if eid_el is not None else 0

        time_el = system.find(f'{{{_NS}}}TimeCreated')
        ts_raw = time_el.get('SystemTime', '') if time_el is not None else ''
        # Normalise to "Mon DD HH:MM:SS" for regex compatibility
        try:
            dt = datetime.fromisoformat(ts_raw.rstrip('Z')).replace(tzinfo=timezone.utc)
            ts = dt.strftime('%b %d %H:%M:%S')
        except (ValueError, AttributeError):
            ts = 'Jan 01 00:00:00'

        # ---- Map Event IDs to pseudo-syslog lines ----

        if eid == 4625:
            # Failed logon — map to SSH failed password pattern
            ip = _get_event_data(event, 'IpAddress') or '0.0.0.0'
            ip = ip.lstrip(':').strip() or '0.0.0.0'  # strip IPv6-mapped prefix
            if ip == '-':
                ip = '127.0.0.1'
            pseudo_lines.append(
                f"{ts} {platform_adapter.get_hostname()} sshd[0]: "
                f"Failed password for invalid user from {ip} port 0 ssh2"
            )

        elif eid == 4624:
            # Successful logon — map to SSH accepted pattern
            user = _get_event_data(event, 'TargetUserName') or 'unknown'
            ip = _get_event_data(event, 'IpAddress') or '0.0.0.0'
            ip = ip.lstrip(':').strip() or '0.0.0.0'
            if ip == '-':
                ip = '127.0.0.1'
            logon_type = _get_event_data(event, 'LogonType')
            # Type 3 = Network, Type 10 = RemoteInteractive (RDP) — flag as remote
            if logon_type in ('3', '10'):
                pseudo_lines.append(
                    f"{ts} {platform_adapter.get_hostname()} sshd[0]: "
                    f"Accepted password for {user} from {ip} port 0 ssh2"
                )

        elif eid == 4688:
            # New process — map to sudo command pattern for suspicious-command detection
            user = _get_event_data(event, 'SubjectUserName') or 'unknown'
            cmd = _get_event_data(event, 'CommandLine') or _get_event_data(event, 'NewProcessName')
            if cmd:
                pseudo_lines.append(
                    f"{ts} {platform_adapter.get_hostname()} sudo: "
                    f" {user} : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND={cmd}"
                )

        # EventIDs 4720, 4726, 4728, 4732, 4756, 4672, 6005, 6006, 6008
        # are handled by analyze_windows_event_log() directly as structured findings,
        # so we don't need pseudo-syslog lines for them.

    return pseudo_lines


# ---------------------------------------------------------------------------
# File-based log reader (Linux / macOS)
# ---------------------------------------------------------------------------

def read_recent_log_lines(path, hours=25):
    """
    Read log lines from the last N hours (approximate, last 50k lines max).

    If `path` starts with 'WinEvent:' it is a Windows Event Log sentinel
    value returned by platform_adapter.get_auth_log_paths() on Windows.
    In that case the Windows Event Log reader is invoked instead of file I/O.
    """
    if path.startswith('WinEvent:'):
        channel = path[len('WinEvent:'):]
        return _read_windows_event_log(channel, hours)

    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
        return lines[-50000:]  # Cap to avoid huge reads
    except PermissionError:
        logger.warning(f"No permission to read {path}")
        return []
    except Exception as e:
        logger.error(f"Failed to read {path}: {e}")
        return []


# ---------------------------------------------------------------------------
# Windows-specific structured event analysis
# ---------------------------------------------------------------------------

def analyze_windows_event_log(config):
    """
    Analyse Windows Security and System Event Logs directly.

    This function queries the Windows Event Log via wevtutil, parses the XML,
    and produces findings for the same categories as the Linux log_analyzer
    (brute force, unusual logins, privilege changes) plus Windows-specific ones
    (new user accounts, group membership changes, unexpected shutdowns).

    Returns (findings, stats) matching the interface of analyze_logs().
    """
    findings = []
    failed_attempts: dict = defaultdict(int)    # IP -> count
    accepted_logins: list = []
    new_users: list = []
    group_changes: list = []
    suspicious_procs: list = []

    brute_threshold_warn = config.get('thresholds', {}).get('failed_ssh_attempts_warning', 5)
    brute_threshold_block = config.get('thresholds', {}).get('failed_ssh_attempts_block', 20)

    hours = 25  # analyse last 25 hours (matches Linux path)
    ms_window = hours * 3600 * 1000

    def _query_channel(channel, event_ids):
        ids_filter = ' or '.join(f'EventID={eid}' for eid in event_ids)
        xpath = (
            f"*[System[({ids_filter}) and "
            f"TimeCreated[timediff(@SystemTime) <= {ms_window}]]]"
        )
        try:
            res = subprocess.run(
                ['wevtutil', 'qe', channel,
                 f'/q:{xpath}', '/f:XML', '/c:2000', '/rd:true'],
                capture_output=True, text=True, timeout=60, errors='replace'
            )
            if not res.stdout.strip():
                return []
            root = ET.fromstring(f'<Events>{res.stdout}</Events>')
            return root.findall(f'{{{_NS}}}Event')
        except FileNotFoundError:
            logger.warning("wevtutil not found — Windows Event Log analysis skipped")
            return []
        except (subprocess.TimeoutExpired, ET.ParseError) as e:
            logger.warning(f"Event Log query failed for {channel}: {e}")
            return []
        except Exception as e:
            logger.error(f"wevtutil error ({channel}): {e}")
            return []

    hostname = platform_adapter.get_hostname()

    # ---- Security channel ----
    for event in _query_channel('Security', _WIN_SECURITY_EVENT_IDS):
        system_el = event.find(f'{{{_NS}}}System')
        if system_el is None:
            continue
        eid_el = system_el.find(f'{{{_NS}}}EventID')
        eid = int(eid_el.text or 0) if eid_el is not None else 0
        time_el = system_el.find(f'{{{_NS}}}TimeCreated')
        ts = time_el.get('SystemTime', '') if time_el is not None else ''

        if eid == 4625:
            ip = _get_event_data(event, 'IpAddress') or '0.0.0.0'
            ip = ip.lstrip(':').strip() or '0.0.0.0'
            if ip == '-':
                ip = '127.0.0.1'
            failed_attempts[ip] += 1

        elif eid == 4624:
            user = _get_event_data(event, 'TargetUserName') or 'unknown'
            ip = _get_event_data(event, 'IpAddress') or '0.0.0.0'
            ip = ip.lstrip(':').strip() or '0.0.0.0'
            if ip == '-':
                ip = '127.0.0.1'
            logon_type = _get_event_data(event, 'LogonType')
            if logon_type in ('3', '10'):  # Network or RemoteInteractive
                accepted_logins.append({'ip': ip, 'user': user, 'timestamp': ts,
                                        'logon_type': logon_type})

        elif eid == 4720:
            new_user = _get_event_data(event, 'TargetUserName') or 'unknown'
            actor = _get_event_data(event, 'SubjectUserName') or 'unknown'
            new_users.append({'user': new_user, 'actor': actor, 'timestamp': ts})

        elif eid in (4728, 4732, 4756):
            member = _get_event_data(event, 'MemberName') or 'unknown'
            group = _get_event_data(event, 'TargetUserName') or 'unknown'
            actor = _get_event_data(event, 'SubjectUserName') or 'unknown'
            group_changes.append({
                'member': member, 'group': group, 'actor': actor, 'timestamp': ts
            })

        elif eid == 4688:
            user = _get_event_data(event, 'SubjectUserName') or 'unknown'
            cmd = (_get_event_data(event, 'CommandLine')
                   or _get_event_data(event, 'NewProcessName') or '')
            if cmd:
                suspicious_procs.append({'user': user, 'cmd': cmd, 'timestamp': ts})

    # ---- System channel (unexpected shutdowns) ----
    unexpected_shutdowns = 0
    for event in _query_channel('System', _WIN_SYSTEM_EVENT_IDS):
        system_el = event.find(f'{{{_NS}}}System')
        if system_el is None:
            continue
        eid_el = system_el.find(f'{{{_NS}}}EventID')
        eid = int(eid_el.text or 0) if eid_el is not None else 0
        if eid == 6008:
            unexpected_shutdowns += 1

    # ---- Build findings ----

    # Brute-force / failed logon
    for ip, count in failed_attempts.items():
        if count >= brute_threshold_block:
            findings.append({
                "type": "brute_force_ssh",
                "severity": "CRITICAL",
                "ip": ip,
                "count": count,
                "detail": f"Brute-force logon attack from {ip}: {count} failed attempts (Event 4625)",
                "auto_remediate": True,
            })
        elif count >= brute_threshold_warn:
            findings.append({
                "type": "ssh_failed_attempts",
                "severity": "HIGH",
                "ip": ip,
                "count": count,
                "detail": f"Multiple failed logons from {ip}: {count} attempts (Event 4625)",
                "auto_remediate": False,
            })

    # Unusual remote logins
    for login in accepted_logins:
        ip = login['ip']
        if not _is_local_ip(ip):
            logon_desc = 'RDP' if login['logon_type'] == '10' else 'Network'
            findings.append({
                "type": "ssh_login_external_ip",
                "severity": "HIGH",
                "ip": ip,
                "user": login['user'],
                "detail": (
                    f"{logon_desc} logon from external IP: {ip} "
                    f"as {login['user']} (Event 4624)"
                ),
            })

    # New user accounts created
    for entry in new_users:
        findings.append({
            "type": "new_user_account",
            "severity": "HIGH",
            "user": entry['user'],
            "detail": (
                f"New Windows user account created: {entry['user']} "
                f"by {entry['actor']} (Event 4720)"
            ),
        })

    # Privilege group changes (Administrators membership added)
    for change in group_changes:
        findings.append({
            "type": "new_sudo_user",
            "severity": "CRITICAL",
            "user": change['member'],
            "detail": (
                f"User added to privileged group '{change['group']}': "
                f"{change['member']} (by {change['actor']}, Event 4728/4732)"
            ),
        })

    # Dangerous process patterns (Windows LOLBins)
    dangerous_win_patterns = [
        re.compile(p, re.IGNORECASE) for p in [
            r'\bpowershell.*-e(nc)?\b',
            r'\bpowershell.*-nop(rofile)?\b',
            r'\bpowershell.*-w(indowstyle)?\s+hid',
            r'\bmshta\b',
            r'\bregsvr32.*scrobj\b',
            r'\bCertUtil.*-decode\b',
            r'\bbitsadmin.*\/transfer\b',
            r'\bwmic.*process.*call.*create\b',
            r'\bcmd.*\/c.*powershell\b',
        ]
    ]
    for proc in suspicious_procs:
        for pattern in dangerous_win_patterns:
            if pattern.search(proc['cmd']):
                findings.append({
                    "type": "dangerous_sudo_command",
                    "severity": "HIGH",
                    "user": proc['user'],
                    "command": proc['cmd'],
                    "detail": (
                        f"Suspicious process launched by {proc['user']}: "
                        f"{proc['cmd'][:120]} (Event 4688)"
                    ),
                })
                break

    # Unexpected system shutdowns
    if unexpected_shutdowns > 0:
        findings.append({
            "type": "unexpected_shutdown",
            "severity": "MEDIUM",
            "count": unexpected_shutdowns,
            "detail": (
                f"{unexpected_shutdowns} unexpected system shutdown(s) detected "
                f"in last {hours}h (Event 6008)"
            ),
        })

    logger.info(
        f"Windows Event Log analysis complete: {len(findings)} findings, "
        f"{sum(failed_attempts.values())} failed logons from {len(failed_attempts)} IPs"
    )
    return findings, {
        "failed_logons_by_ip": dict(failed_attempts),
        "remote_logons_count": len(accepted_logins),
        "new_users_count": len(new_users),
        "group_changes_count": len(group_changes),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_logs(config):
    """Analyze auth logs and return findings."""
    # Dispatch to Windows Event Log analysis on Windows
    if platform_adapter.SYSTEM == 'Windows':
        return analyze_windows_event_log(config)

    # ---- Linux / macOS: regex-based text log parsing ----
    findings = []
    failed_attempts = defaultdict(int)   # IP -> count
    accepted_logins = []
    sudo_commands = []
    sudo_failures = defaultdict(int)

    brute_threshold_warn = config.get('thresholds', {}).get('failed_ssh_attempts_warning', 5)
    brute_threshold_block = config.get('thresholds', {}).get('failed_ssh_attempts_block', 20)

    # Resolve log paths for this platform/distro
    log_files = platform_adapter.get_auth_log_paths()

    all_lines = []
    for log_file in log_files:
        all_lines.extend(read_recent_log_lines(log_file))

    for line in all_lines:
        # Failed SSH
        m = SSH_FAILED_RE.search(line)
        if m:
            ip = m.group(2)
            failed_attempts[ip] += 1
            continue

        # Accepted SSH login
        m = SSH_ACCEPTED_RE.search(line)
        if m:
            accepted_logins.append({
                "timestamp": m.group(1),
                "user": m.group(2),
                "ip": m.group(3),
            })
            continue

        # Sudo command
        m = SUDO_RE.search(line)
        if m:
            sudo_commands.append({
                "timestamp": m.group(1),
                "user": m.group(2),
                "command": m.group(3).strip(),
            })
            continue

        # Sudo failure
        m = SUDO_FAIL_RE.search(line)
        if m:
            sudo_failures[m.group(2)] += 1

    # --- Brute force findings ---
    for ip, count in failed_attempts.items():
        safe_ip = _sanitize(ip)
        if count >= brute_threshold_block:
            findings.append({
                "type": "brute_force_ssh",
                "severity": "CRITICAL",
                "ip": safe_ip,
                "count": count,
                "detail": f"Brute force SSH attack from {safe_ip}: {count} failed attempts",
                "auto_remediate": True,
            })
        elif count >= brute_threshold_warn:
            findings.append({
                "type": "ssh_failed_attempts",
                "severity": "HIGH",
                "ip": safe_ip,
                "count": count,
                "detail": f"Multiple SSH failures from {safe_ip}: {count} attempts",
                "auto_remediate": False,
            })

    # --- Unusual logins ---
    for login in accepted_logins:
        ip = _sanitize(login['ip'])
        user = _sanitize(login['user'])
        timestamp = _sanitize(login['timestamp'])
        if not _is_local_ip(ip):
            findings.append({
                "type": "ssh_login_external_ip",
                "severity": "HIGH",
                "ip": ip,
                "user": user,
                "detail": f"SSH login from external IP: {ip} as user {user} at {timestamp}",
            })

    # --- Sudo failures ---
    for user, count in sudo_failures.items():
        safe_user = _sanitize(user)
        if count >= 3:
            findings.append({
                "type": "sudo_auth_failure",
                "severity": "MEDIUM",
                "user": safe_user,
                "count": count,
                "detail": f"Repeated sudo authentication failures for user: {safe_user} ({count} times)",
            })

    # --- Privileged sudo commands (informational) ---
    dangerous_sudo_patterns = [
        r'\bchmod\b.*\b\+s\b',
        r'\buseradd\b', r'\busermod\b', r'\bpasswd\b',
        r'\bcurl\b.*\|.*sh\b', r'\bwget\b.*\|.*sh\b',
        r'\bdd\b.*of=/dev/', r'\bnc\b.*-[el]\b',
    ]
    dangerous_re = [re.compile(p, re.IGNORECASE) for p in dangerous_sudo_patterns]
    for cmd_entry in sudo_commands:
        safe_user = _sanitize(cmd_entry['user'])
        safe_cmd = _sanitize(cmd_entry['command'])
        for pattern in dangerous_re:
            if pattern.search(safe_cmd):
                findings.append({
                    "type": "dangerous_sudo_command",
                    "severity": "HIGH",
                    "user": safe_user,
                    "command": safe_cmd,
                    "detail": f"Potentially dangerous sudo command by {safe_user}: {safe_cmd[:100]}",
                })
                break

    logger.info(f"Log analysis complete: {len(findings)} findings, "
                f"{sum(failed_attempts.values())} SSH failures from {len(failed_attempts)} IPs")
    return findings, {
        "failed_ssh_by_ip": dict(failed_attempts),
        "accepted_logins_count": len(accepted_logins),
        "sudo_commands_count": len(sudo_commands),
    }


def _is_local_ip(ip):
    """Heuristic check if IP is RFC1918 / loopback."""
    try:
        parts = list(map(int, ip.split('.')))
        if parts[0] == 10:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 127:
            return True
    except Exception:
        pass
    return False
