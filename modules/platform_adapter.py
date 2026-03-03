"""
platform_adapter.py — OS abstraction layer for Security Commander.

Provides a single interface for every platform-specific system call so that
adding support for a new OS means editing exactly one file.

Current support:
  Linux  — full implementation (Debian/Ubuntu/Mint, RHEL/Fedora, Arch)
  macOS  — partial (hostname, processes, network CIDR, log paths, kill, chmod)
  Windows — stubs only (NotImplementedError with helpful messages)

To add a new platform:
  1. Add an `elif SYSTEM == 'YourOS':` branch to the relevant functions below.
  2. Return the same data structures as the Linux implementation.
  3. Run: python3 -m py_compile modules/platform_adapter.py
"""

import ipaddress
import logging
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Detected at import time — treat as read-only constants.
SYSTEM = platform.system()   # 'Linux', 'Darwin', 'Windows'
_DISTRO_ID = ""              # e.g. 'ubuntu', 'fedora', 'arch'

if SYSTEM == 'Linux':
    try:
        with open('/etc/os-release') as _f:
            for _line in _f:
                if _line.startswith('ID='):
                    _DISTRO_ID = _line.split('=', 1)[1].strip().strip('"').lower()
                    break
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Internal helpers (not part of the public API)
# ---------------------------------------------------------------------------

def _run(args: List[str], timeout: int = 30) -> Tuple[bool, str, str]:
    """
    Run a command as an argument list (never shell=True).
    Returns (success, stdout, stderr).
    """
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return False, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout}s"
    except Exception as exc:
        return False, "", str(exc)


def _not_implemented(fn_name: str) -> None:
    raise NotImplementedError(
        f"{fn_name}() is not yet implemented for {SYSTEM}. "
        "See modules/platform_adapter.py to add support."
    )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def validate_ip(ip: str) -> str:
    """
    Validate an IPv4 address string. Raises ValueError if invalid.
    Always call this before passing any network-derived value into a
    system command — it prevents command injection.
    """
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', str(ip)):
        raise ValueError(f"Invalid IPv4 address: {ip!r}")
    if not all(0 <= int(o) <= 255 for o in ip.split('.')):
        raise ValueError(f"IPv4 octet out of range: {ip!r}")
    return ip


# ---------------------------------------------------------------------------
# General system info
# ---------------------------------------------------------------------------

def get_hostname() -> str:
    """Return the machine hostname (cross-platform via stdlib)."""
    return platform.node()


# ---------------------------------------------------------------------------
# Process enumeration
# ---------------------------------------------------------------------------

def list_processes_raw() -> str:
    """
    Return raw text of the running process list.
    Output format: one process per line, space-separated:
      USER  PID  %CPU  %MEM  VSZ  RSS  TTY  STAT  START  TIME  COMMAND

    This matches `ps aux --no-headers` so the existing parser in
    local_scanner.py works unchanged on both Linux and macOS.
    """
    if SYSTEM == 'Linux':
        _, out, _ = _run(['ps', 'aux', '--no-headers'])
        return out
    elif SYSTEM == 'Darwin':
        _, out, _ = _run(['ps', 'aux'])
        lines = out.splitlines()
        # Strip the BSD ps header line
        return '\n'.join(lines[1:]) if len(lines) > 1 else ''
    else:
        _not_implemented('list_processes_raw')


# ---------------------------------------------------------------------------
# Open port enumeration
# ---------------------------------------------------------------------------

def list_open_ports() -> List[Dict]:
    """
    Return a structured list of locally listening ports.
    Each entry: {'proto': str, 'port': int, 'local_addr': str, 'process': str}

    This is the preferred cross-platform API; callers should not parse
    raw `ss` or `netstat` output directly.
    """
    if SYSTEM == 'Linux':
        _, raw, _ = _run(['ss', '-tulpn'])
        ports = []
        for line in raw.splitlines()[1:]:      # skip ss header
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local_addr = parts[4]
            process = parts[-1] if 'pid=' in parts[-1] else 'unknown'
            if ':' in local_addr:
                port_str = local_addr.rsplit(':', 1)[-1]
                if port_str.isdigit():
                    ports.append({
                        'proto': proto,
                        'port': int(port_str),
                        'local_addr': local_addr,
                        'process': process,
                    })
        return ports

    elif SYSTEM == 'Darwin':
        _, out, _ = _run(['lsof', '-iTCP', '-sTCP:LISTEN', '-n', '-P'])
        ports = []
        for line in out.splitlines()[1:]:      # skip lsof header
            parts = line.split()
            if len(parts) < 9:
                continue
            addr_field = parts[8]              # e.g. '*:22' or '127.0.0.1:631'
            if ':' in addr_field:
                port_str = addr_field.rsplit(':', 1)[-1]
                if port_str.isdigit():
                    ports.append({
                        'proto': 'tcp',
                        'port': int(port_str),
                        'local_addr': addr_field,
                        'process': parts[0],
                    })
        return ports

    else:
        _not_implemented('list_open_ports')


# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------

def get_local_network_cidr() -> Optional[str]:
    """
    Detect the local LAN network in CIDR notation (e.g., '192.168.1.0/24').
    Returns None if detection fails; callers should fall back to '192.168.1.0/24'.
    """
    if SYSTEM == 'Linux':
        # Step 1: find default-route interface
        _, out, _ = _run(['ip', 'route', 'show', 'default'])
        iface = None
        for line in out.splitlines():
            parts = line.split()
            if 'dev' in parts:
                iface = parts[parts.index('dev') + 1]
                break

        # Step 2: fallback — any non-default route that is a valid network
        if not iface:
            _, out, _ = _run(['ip', 'route', 'show'])
            for line in out.splitlines():
                parts = line.split()
                if parts and not line.startswith('default') and 'src' in parts:
                    try:
                        ipaddress.ip_network(parts[0], strict=False)
                        return parts[0]
                    except ValueError:
                        continue

        # Step 3: get CIDR from the interface address
        if iface:
            _, out, _ = _run(['ip', 'addr', 'show', iface])
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('inet ') and 'inet6' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            return str(ipaddress.ip_interface(parts[1]).network)
                        except ValueError:
                            continue
        return None

    elif SYSTEM == 'Darwin':
        _, out, _ = _run(['route', '-n', 'get', 'default'])
        iface = None
        for line in out.splitlines():
            if 'interface:' in line:
                iface = line.split(':', 1)[1].strip()
                break
        if iface:
            _, out, _ = _run(['ifconfig', iface])
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('inet ') and not line.startswith('inet6'):
                    parts = line.split()
                    # macOS: inet ADDR netmask HEXMASK broadcast BCAST
                    if len(parts) >= 4 and parts[2] == 'netmask':
                        try:
                            hex_mask = int(parts[3], 16)
                            mask_str = '.'.join(
                                str((hex_mask >> (8 * i)) & 0xFF)
                                for i in (3, 2, 1, 0)
                            )
                            return str(
                                ipaddress.ip_interface(f'{parts[1]}/{mask_str}').network
                            )
                        except (ValueError, OverflowError):
                            continue
        return None

    else:
        _not_implemented('get_local_network_cidr')


# ---------------------------------------------------------------------------
# Authentication log paths
# ---------------------------------------------------------------------------

def get_auth_log_paths() -> List[str]:
    """
    Return an ordered list of auth/syslog file paths to analyse.
    Handles the main Linux distribution families and macOS.
    Non-existent paths are skipped silently by log_analyzer.py.
    """
    if SYSTEM == 'Linux':
        # RHEL family (Fedora, CentOS, AlmaLinux, Rocky, Amazon Linux, openSUSE)
        if _DISTRO_ID in {
            'rhel', 'fedora', 'centos', 'almalinux', 'rocky',
            'ol', 'amzn', 'opensuse', 'sles', 'opensuse-leap', 'opensuse-tumbleweed',
        }:
            return ['/var/log/secure', '/var/log/secure.1', '/var/log/messages']

        # Arch / Manjaro — journald-first; text logs may not exist
        if _DISTRO_ID in {'arch', 'manjaro', 'endeavouros', 'garuda'}:
            return ['/var/log/auth.log']    # best effort; may be absent

        # Debian / Ubuntu / Mint / Pop!_OS / Kali / Raspberry Pi OS (default)
        return ['/var/log/auth.log', '/var/log/auth.log.1', '/var/log/syslog']

    elif SYSTEM == 'Darwin':
        return ['/var/log/auth.log', '/var/log/system.log']

    else:
        _not_implemented('get_auth_log_paths')


# ---------------------------------------------------------------------------
# Firewall operations
# ---------------------------------------------------------------------------

def get_firewall_backend() -> str:
    """
    Detect the available firewall management tool.
    Returns one of: 'ufw', 'firewalld', 'iptables', 'pfctl', 'none'.
    Priority order: ufw > firewalld > iptables (Linux), pfctl (macOS).
    """
    if SYSTEM == 'Linux':
        if shutil.which('ufw'):
            return 'ufw'
        if shutil.which('firewall-cmd'):
            return 'firewalld'
        if shutil.which('iptables'):
            return 'iptables'
        return 'none'
    elif SYSTEM == 'Darwin':
        return 'pfctl'
    else:
        return 'none'


def is_ip_blocked(ip: str) -> bool:
    """Return True if the IP address already has a deny rule in the firewall."""
    try:
        ip = validate_ip(ip)
    except ValueError:
        return False

    backend = get_firewall_backend()
    if backend == 'ufw':
        _, out, _ = _run(['ufw', 'status'])
        return ip in out and 'DENY' in out
    elif backend == 'firewalld':
        _, out, _ = _run(['firewall-cmd', '--list-rich-rules'])
        return ip in out
    elif backend == 'iptables':
        _, out, _ = _run(['iptables', '-L', 'INPUT', '-n'])
        return ip in out
    return False


def block_ip(ip: str) -> Tuple[bool, str]:
    """
    Add a deny rule for the given IP using the available firewall backend.
    Returns (success, message).
    """
    try:
        ip = validate_ip(ip)
    except ValueError as exc:
        logger.error(str(exc))
        return False, str(exc)

    if is_ip_blocked(ip):
        return True, f"IP {ip} is already blocked"

    backend = get_firewall_backend()

    if backend == 'ufw':
        ok, out, err = _run([
            'ufw', 'deny', 'from', ip, 'to', 'any',
            'comment', 'SecurityCommander auto-block',
        ])
        if ok or 'Rule added' in out or 'Skipping' in out:
            logger.warning(f"REMEDIATION: Blocked {ip} via ufw")
            return True, f"Blocked {ip} via ufw"
        return False, f"ufw block failed: {err}"

    elif backend == 'firewalld':
        rule = f'rule family="ipv4" source address="{ip}" reject'
        ok, _, err = _run(['firewall-cmd', '--add-rich-rule', rule, '--permanent'])
        if ok:
            _run(['firewall-cmd', '--reload'])
            logger.warning(f"REMEDIATION: Blocked {ip} via firewalld")
            return True, f"Blocked {ip} via firewalld"
        return False, f"firewalld block failed: {err}"

    elif backend == 'iptables':
        ok, _, err = _run(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'])
        if ok:
            logger.warning(f"REMEDIATION: Blocked {ip} via iptables")
            return True, f"Blocked {ip} via iptables"
        return False, f"iptables block failed: {err}"

    elif backend == 'pfctl':
        _not_implemented('block_ip via pfctl (macOS)')

    return False, f"No supported firewall found (detected: {backend!r})"


# ---------------------------------------------------------------------------
# Process termination
# ---------------------------------------------------------------------------

def kill_process(pid: str, cmd_hint: str = '') -> Tuple[bool, str]:
    """
    Forcefully terminate a process by PID.
    Returns (success, message).
    """
    if not re.match(r'^\d+$', str(pid)):
        return False, f"Invalid PID: {pid!r}"

    if SYSTEM in ('Linux', 'Darwin'):
        ok, _, err = _run(['kill', '-9', str(pid)])
        if ok:
            logger.warning(f"REMEDIATION: Killed PID {pid} ({cmd_hint[:50]})")
            return True, f"Killed PID {pid}"
        return False, f"Failed to kill PID {pid}: {err}"
    else:
        _not_implemented('kill_process')


# ---------------------------------------------------------------------------
# File permission repair
# ---------------------------------------------------------------------------

def fix_file_permissions(filepath: str) -> Tuple[bool, str]:
    """
    Remove world-write permission from a file (chmod o-w).
    Returns (success, message).
    """
    if SYSTEM in ('Linux', 'Darwin'):
        ok, _, err = _run(['chmod', 'o-w', filepath])
        if ok:
            logger.warning(f"REMEDIATION: Removed world-write from {filepath}")
            return True, f"Removed world-writable permission from {filepath}"
        return False, f"chmod failed for {filepath}: {err}"
    else:
        _not_implemented('fix_file_permissions')


# ---------------------------------------------------------------------------
# Scheduler detection (used by setup.py)
# ---------------------------------------------------------------------------

def get_available_schedulers() -> Dict[str, bool]:
    """
    Detect which scheduling mechanisms are available.
    Returns: {'systemd': bool, 'cron': bool, 'launchd': bool}
    """
    return {
        'systemd': (
            Path('/etc/systemd/system').is_dir()
            and bool(shutil.which('systemctl'))
        ),
        'cron': bool(shutil.which('crontab')),
        'launchd': SYSTEM == 'Darwin' and Path('/Library/LaunchDaemons').is_dir(),
    }
