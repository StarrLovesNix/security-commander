"""
Auto-remediation engine.
Handles: blocking IPs via firewall, killing suspicious processes,
fixing file permissions.

All remediation actions go through platform_adapter so they work
correctly on any supported OS/firewall combination (ufw, firewalld,
iptables). Input validation is enforced before any system call.
"""

import logging

from modules import platform_adapter

logger = logging.getLogger(__name__)


def block_ip(ip):
    """Block an IP via the available firewall backend. Returns (success, message)."""
    return platform_adapter.block_ip(ip)


def kill_process(pid, cmd_hint=""):
    """Kill a suspicious process. Returns (success, message)."""
    return platform_adapter.kill_process(pid, cmd_hint)


def fix_world_writable(filepath):
    """Remove world-write permission from a sensitive file."""
    return platform_adapter.fix_file_permissions(filepath)


def remediate(auto_remediate_findings, config):
    """
    Execute auto-remediation for eligible findings.
    Returns list of remediation action result dicts.
    """
    actions = []
    remediation_config = config.get('remediation', {})

    for finding in auto_remediate_findings:
        ftype = finding.get('type')
        severity = finding.get('severity', 'LOW')

        # Skip CRITICAL findings unless explicitly configured for auto-remediation
        if severity == 'CRITICAL' and remediation_config.get('require_approval_for_high', True):
            actions.append({
                "finding_type": ftype,
                "action": "skipped",
                "reason": "CRITICAL severity requires manual approval",
                "finding": finding,
            })
            continue

        if ftype == 'brute_force_ssh' and remediation_config.get('auto_block_brute_force', True):
            ip = finding.get('ip')
            if ip:
                success, message = block_ip(ip)
                actions.append({
                    "finding_type": ftype,
                    "action": "block_ip",
                    "target": ip,
                    "success": success,
                    "message": message,
                    "finding": finding,
                })

        elif ftype == 'ssh_failed_attempts':
            count = finding.get('count', 0)
            block_threshold = remediation_config.get('auto_block_threshold', 20)
            ip = finding.get('ip')
            if ip and count >= block_threshold:
                success, message = block_ip(ip)
                actions.append({
                    "finding_type": ftype,
                    "action": "block_ip",
                    "target": ip,
                    "success": success,
                    "message": message,
                    "finding": finding,
                })

        elif ftype == 'suspicious_process' and remediation_config.get('auto_kill_cryptominers', True):
            pid = finding.get('pid')
            cmd = finding.get('cmd', '')
            if pid:
                success, message = kill_process(pid, cmd)
                actions.append({
                    "finding_type": ftype,
                    "action": "kill_process",
                    "target": pid,
                    "success": success,
                    "message": message,
                    "finding": finding,
                })

        elif ftype == 'world_writable_sensitive':
            filepath = finding.get('file')
            if filepath:
                success, message = fix_world_writable(filepath)
                actions.append({
                    "finding_type": ftype,
                    "action": "fix_permissions",
                    "target": filepath,
                    "success": success,
                    "message": message,
                    "finding": finding,
                })

    return actions
