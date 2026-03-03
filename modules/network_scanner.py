"""
Network scanner: LAN device discovery and port scanning.
Uses nmap and ARP to detect devices and open services.
"""

import subprocess
import socket
import logging
import re
import ipaddress

from modules import platform_adapter

logger = logging.getLogger(__name__)

COMMON_DANGEROUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}


def _run_nmap(args, timeout=120):
    """Run nmap with a list of arguments (no shell=True)."""
    try:
        result = subprocess.run(
            ['nmap'] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip(), result.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"nmap timed out: {args}")
        return "", 1
    except FileNotFoundError:
        logger.error("nmap not found. Install with: sudo apt install nmap")
        return "", 1
    except Exception as e:
        logger.error(f"nmap failed: {e}")
        return "", 1


def get_local_network():
    """Detect the local network CIDR (e.g., 192.168.1.0/24)."""
    cidr = platform_adapter.get_local_network_cidr()
    if cidr:
        return cidr
    logger.warning("Could not auto-detect local network; falling back to 192.168.1.0/24")
    return "192.168.1.0/24"


def discover_devices(network_cidr, timeout=60):
    """Use nmap ping scan to discover live hosts on the LAN."""
    logger.info(f"Scanning network: {network_cidr}")
    output, rc = _run_nmap(
        ['-sn', '--host-timeout', '5s', network_cidr],
        timeout=timeout,
    )
    devices = []
    current = {}
    for line in output.splitlines():
        if line.startswith('Nmap scan report for'):
            if current:
                devices.append(current)
            parts = line.split()
            ip = parts[-1].strip('()')
            hostname = parts[-2] if len(parts) > 4 and parts[-2] != 'for' else ip
            if hostname.startswith('('):
                hostname = hostname.strip('()')
            current = {"ip": ip, "hostname": hostname, "mac": "", "vendor": ""}
        elif 'MAC Address:' in line:
            m = re.search(r'MAC Address: ([0-9A-Fa-f:]+)\s*\(([^)]+)\)', line)
            if m:
                current["mac"] = m.group(1)
                current["vendor"] = m.group(2)
    if current:
        devices.append(current)
    return devices


def scan_device_ports(ip, timeout=60):
    """Quick port scan of a device for common ports."""
    # Validate IP before using it in a command
    try:
        platform_adapter.validate_ip(ip)
    except ValueError:
        logger.warning(f"Skipping port scan for invalid IP: {ip!r}")
        return []

    common_ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,6379,8080,8443,27017"
    output, rc = _run_nmap(
        ['-p', common_ports, '--open', '--host-timeout', '10s', '-T3', ip],
        timeout=timeout,
    )
    open_ports = []
    for line in output.splitlines():
        m = re.match(r'(\d+)/(\w+)\s+open\s+(.*)', line)
        if m:
            open_ports.append({
                "port": int(m.group(1)),
                "proto": m.group(2),
                "service": m.group(3).strip(),
            })
    return open_ports


def scan(baseline=None, config=None):
    """Full network scan: discover devices, check ports, compare to baseline."""
    config = config or {}
    findings = []
    snapshot = {}

    network_cidr = get_local_network()
    snapshot['network_cidr'] = network_cidr
    logger.info(f"Detected local network: {network_cidr}")

    # Discover devices
    devices = discover_devices(network_cidr)
    logger.info(f"Discovered {len(devices)} devices on {network_cidr}")
    snapshot['devices'] = devices

    # Compare to baseline
    if baseline:
        baseline_ips = {d['ip'] for d in baseline.get('devices', [])}
        current_ips = {d['ip'] for d in devices}

        for ip in current_ips - baseline_ips:
            device_info = next((d for d in devices if d['ip'] == ip), {})
            findings.append({
                "type": "new_network_device",
                "severity": "MEDIUM",
                "ip": ip,
                "hostname": device_info.get('hostname', ip),
                "mac": device_info.get('mac', ''),
                "vendor": device_info.get('vendor', ''),
                "detail": f"New device on network: {ip} ({device_info.get('hostname', 'unknown')}) [{device_info.get('vendor', '')}]",
            })

        for ip in baseline_ips - current_ips:
            device_info = next((d for d in baseline.get('devices', []) if d['ip'] == ip), {})
            findings.append({
                "type": "device_disappeared",
                "severity": "LOW",
                "ip": ip,
                "detail": f"Device no longer visible on network: {ip} ({device_info.get('hostname', 'unknown')})",
            })

    # Scan ports on all discovered devices
    all_device_ports = {}
    for device in devices:
        ip = device['ip']
        ports = scan_device_ports(ip)
        all_device_ports[ip] = ports

        for port_info in ports:
            port = port_info['port']
            if port in COMMON_DANGEROUS_PORTS:
                service_name = COMMON_DANGEROUS_PORTS[port]
                is_new = True
                if baseline:
                    for b_device in baseline.get('device_ports', {}).get(ip, []):
                        if b_device['port'] == port:
                            is_new = False
                            break
                if is_new:
                    findings.append({
                        "type": "dangerous_port_open",
                        "severity": "HIGH",
                        "ip": ip,
                        "port": port,
                        "service": service_name,
                        "detail": f"Dangerous service exposed on network: {ip}:{port} ({service_name})",
                    })

    snapshot['device_ports'] = all_device_ports

    # Check for ARP spoofing indicators (duplicate MACs)
    mac_to_ips = {}
    for device in devices:
        mac = device.get('mac', '')
        if mac:
            mac_to_ips.setdefault(mac, []).append(device['ip'])
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            findings.append({
                "type": "arp_spoofing_indicator",
                "severity": "CRITICAL",
                "mac": mac,
                "ips": ips,
                "detail": f"Possible ARP spoofing: MAC {mac} appears at multiple IPs: {', '.join(ips)}",
            })

    logger.info(f"Network scan complete: {len(findings)} findings")
    return findings, snapshot
