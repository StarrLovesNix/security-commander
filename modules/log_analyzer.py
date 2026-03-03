"""
Auth log and syslog analyzer.
Detects: brute force SSH, unusual logins, sudo abuse, auth failures.

Log file paths are resolved via platform_adapter.get_auth_log_paths()
so this module works on Debian/Ubuntu, RHEL/Fedora, macOS, etc.
"""

import re
import os
import logging
from collections import defaultdict

from modules import platform_adapter

logger = logging.getLogger(__name__)

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


def read_recent_log_lines(path, hours=25):
    """Read log lines from the last N hours (approximate, last 50k lines max)."""
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


def analyze_logs(config):
    """Analyze auth logs and return findings."""
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
        if count >= brute_threshold_block:
            findings.append({
                "type": "brute_force_ssh",
                "severity": "CRITICAL",
                "ip": ip,
                "count": count,
                "detail": f"Brute force SSH attack from {ip}: {count} failed attempts",
                "auto_remediate": True,
            })
        elif count >= brute_threshold_warn:
            findings.append({
                "type": "ssh_failed_attempts",
                "severity": "HIGH",
                "ip": ip,
                "count": count,
                "detail": f"Multiple SSH failures from {ip}: {count} attempts",
                "auto_remediate": False,
            })

    # --- Unusual logins ---
    for login in accepted_logins:
        ip = login['ip']
        if not _is_local_ip(ip):
            findings.append({
                "type": "ssh_login_external_ip",
                "severity": "HIGH",
                "ip": ip,
                "user": login['user'],
                "detail": f"SSH login from external IP: {ip} as user {login['user']} at {login['timestamp']}",
            })

    # --- Sudo failures ---
    for user, count in sudo_failures.items():
        if count >= 3:
            findings.append({
                "type": "sudo_auth_failure",
                "severity": "MEDIUM",
                "user": user,
                "count": count,
                "detail": f"Repeated sudo authentication failures for user: {user} ({count} times)",
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
        for pattern in dangerous_re:
            if pattern.search(cmd_entry['command']):
                findings.append({
                    "type": "dangerous_sudo_command",
                    "severity": "HIGH",
                    "user": cmd_entry['user'],
                    "command": cmd_entry['command'],
                    "detail": f"Potentially dangerous sudo command by {cmd_entry['user']}: {cmd_entry['command'][:100]}",
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
