# Security Commander

A lightweight, daily security scanner for **Linux and Windows 10/11**. Scans the local machine and LAN, auto-remediates low-risk threats, sends email alerts, and suppresses recurring findings via a cooldown system.

## Features

- **Local system scan** — open ports, running processes, user accounts, SSH keys, SUID files, cron/scheduled jobs
- **Network scan** — LAN device discovery (nmap), dangerous exposed ports, ARP spoofing detection
- **Log analysis** — SSH / Windows logon brute force, external logins, privilege escalation, dangerous commands
- **Auto-remediation** — block IPs via firewall (ufw / firewalld / iptables / Windows Firewall), kill suspicious processes, fix world-writable files
- **Alert deduplication** — per-severity cooldowns prevent email flooding for persistent findings
- **Acknowledge mode** — suppress known-good findings without disabling alerts
- **HTML email reports** — categorised by New / Recurring / Resolved

---

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Debian / Ubuntu / Linux Mint | **Full** | Primary target; ufw, systemd |
| RHEL / Fedora / CentOS / AlmaLinux | **Full** | `/var/log/secure`, firewalld / iptables |
| Arch / Manjaro | **Partial** | Log scanning may be limited (journald) |
| macOS | **Partial** | Processes, network, kill, chmod work; firewall remediation not yet implemented |
| **Windows 10 / 11** | **Full** | PowerShell, netstat, wevtutil, netsh, icacls, Task Scheduler |

---

## Requirements

### Linux

| Requirement | Notes |
|---|---|
| Python 3.10+ | No third-party packages needed |
| `nmap` | Network scanning |
| `ufw` / `firewalld` / `iptables` | Auto-remediation (any one is sufficient) |
| Root / sudo | Full functionality (some checks degrade gracefully without it) |
| Gmail account | For email alerts (uses App Passwords) |

**Install system dependencies:**

```bash
# Debian / Ubuntu / Linux Mint
sudo apt install nmap ufw python3

# RHEL / Fedora / CentOS
sudo dnf install nmap firewalld python3
```

### Windows 10 / 11

| Requirement | Notes |
|---|---|
| Python 3.10+ | Download from [python.org](https://www.python.org/downloads/) — check "Add Python to PATH" |
| `nmap` | Download from [nmap.org/download](https://nmap.org/download.html) — check "Add to PATH" |
| Administrator account | Full functionality; some checks degrade gracefully without it |
| Gmail account | For email alerts (uses App Passwords) |
| Windows Firewall | Built into Windows 10/11 — always available |
| OpenSSH (optional) | For SSH key monitoring; built into Windows 10 1803+ |

Windows Event Log analysis, process enumeration (PowerShell), firewall management (netsh), and scheduled tasks (Task Scheduler) are all built into Windows 10/11 and require no additional installation.

---

## Installation

### Linux

```bash
# 1. Clone or download
git clone https://github.com/StarrLovesNix/security-commander.git
cd security-commander

# 2. Run setup (configures email, installs scheduler, runs baseline scan)
sudo python3 setup.py
```

Setup will:
1. Prompt for your Gmail address and App Password
2. Install a **systemd timer** (or cron job on non-systemd systems) to run daily at 06:00
3. Run an initial baseline scan to establish normal state

### Windows 10 / 11

```
1. Clone or download the repository
2. Double-click setup_windows.bat
   — automatically requests UAC elevation
   — verifies Python is installed
   — runs the interactive setup wizard
```

Or from an **elevated** Command Prompt / PowerShell:

```powershell
python setup.py
```

Setup will:
1. Prompt for your Gmail address and App Password
2. Install a **Windows Task Scheduler** task (`SecurityCommander`) that runs daily at 06:00 as SYSTEM
3. Run an initial baseline scan

---

## Configuration

`config.json` is created automatically by setup from `config.json.example`. Edit it directly if you need to change settings after setup:

| Setting | Default | Description |
|---|---|---|
| `email.sender` | — | Your Gmail address |
| `email.recipient` | sender | Where alert emails are sent |
| `email.app_password` | — | 16-character Gmail App Password |
| `thresholds.failed_ssh_attempts_warning` | 5 | Failed logins triggering a warning |
| `thresholds.failed_ssh_attempts_block` | 20 | Failed logins triggering auto-block |
| `remediation.auto_block_brute_force` | true | Automatically block brute-force IPs |
| `remediation.auto_kill_cryptominers` | true | Automatically kill identified miners |
| `remediation.require_approval_for_high` | true | Require confirmation for HIGH findings |
| `alert_history.enabled` | true | Enable cross-scan deduplication |
| `alert_history.cooldown_days` | see below | Days between repeat alerts per severity |
| `logging.report_dir` | `reports/` | Where HTML scan reports are written |

---

## Usage

### Linux

```bash
# Daily scan (run by scheduler automatically)
sudo python3 security_commander.py

# Force a fresh baseline (after major system changes)
sudo python3 security_commander.py --baseline

# Skip email (report to log file only)
sudo python3 security_commander.py --no-email

# Acknowledge persistent findings (suppress from future emails)
python3 security_commander.py --acknowledge

# Verbose output
sudo python3 security_commander.py --verbose
```

### Windows (run as Administrator)

```powershell
# Daily scan (run by Task Scheduler automatically)
python security_commander.py

# Force a fresh baseline
python security_commander.py --baseline

# Skip email
python security_commander.py --no-email

# Acknowledge persistent findings
python security_commander.py --acknowledge

# View / manage the scheduled task
schtasks /query /tn SecurityCommander
schtasks /run /tn SecurityCommander
schtasks /delete /tn SecurityCommander /f
```

---

## Alert cooldowns

Prevents email flooding for persistent issues:

| Severity | Default cooldown | Behaviour |
|---|---|---|
| CRITICAL | 0 days | Alerts every scan |
| HIGH | 3 days | Re-alerts after 3 days |
| MEDIUM | 7 days | Re-alerts after 7 days |
| LOW | 14 days | Re-alerts after 14 days |
| Acknowledged | — | Always suppressed |

Cooldowns are configurable in `config.json` under `alert_history.cooldown_days`.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings above LOW |
| 1 | HIGH findings present |
| 2 | CRITICAL findings present |
| 3 | Unexpected error |
| 130 | Interrupted by user |

---

## What Windows monitors

| Category | What's checked |
|---|---|
| **Processes** | All running processes via PowerShell `Get-Process`; suspicious patterns (crypto miners, encoded PowerShell, mshta, regsvr32 scrobj, CertUtil decode, BITS abuse, wscript/cscript) |
| **Open ports** | Listening TCP/UDP ports via `netstat -ano` with process names |
| **Users** | Local accounts via `net user`; Administrators group via `net localgroup` |
| **SSH keys** | `C:\ProgramData\ssh\administrators_authorized_keys` + per-user `C:\Users\*\.ssh\authorized_keys` |
| **Scheduled tasks** | All Task Scheduler tasks via `schtasks /query`; new tasks since baseline |
| **File permissions** | World-writable files in `System32` / `Program Files` via `icacls` |
| **Event Log — Security** | Event 4625 (failed logons / brute force), 4624 (remote logons), 4720 (new user created), 4728/4732 (Administrators group changes), 4688 (dangerous process execution) |
| **Event Log — System** | Event 6008 (unexpected shutdown) |
| **Firewall** | IP blocking via `netsh advfirewall firewall` (Windows Firewall) |
| **Network** | LAN CIDR via `ipconfig`; nmap-based LAN discovery and port scanning |

---

## Project structure

```
security-commander/
├── security_commander.py     # Main entry point and orchestrator
├── setup.py                  # Cross-platform installation wizard
├── setup_windows.bat         # Windows UAC-elevation launcher for setup
├── config.json               # Your configuration (gitignored — contains credentials)
├── config.json.example       # Template — copied to config.json by setup
├── security-commander.service # systemd service unit (Linux)
├── security-commander.timer   # systemd timer unit (Linux, daily at 06:00)
├── modules/
│   ├── platform_adapter.py   # OS abstraction layer — ALL platform-specific calls live here
│   ├── local_scanner.py      # Local system checks (ports, processes, users, files)
│   ├── network_scanner.py    # LAN discovery and port scanning (nmap)
│   ├── log_analyzer.py       # Auth log / Windows Event Log analysis
│   ├── threat_assessor.py    # Finding prioritisation and deduplication
│   ├── remediator.py         # Auto-remediation actions
│   ├── notifier.py           # Email and HTML report generation
│   └── alert_history.py      # Cross-scan deduplication and cooldowns
├── tests/
│   ├── test_platform_adapter.py  # 28 tests — all platform_adapter functions
│   ├── test_local_scanner.py     # 28 tests — scanner + Windows branches
│   ├── test_log_analyzer.py      # 33 tests — Linux regex + Windows Event Log XML
│   └── test_security_commander.py # 17 tests — admin check, lock, config
├── data/
│   ├── baseline.json         # Security baseline (auto-generated)
│   └── alert_history.json    # Alert state (auto-generated)
└── reports/                  # Scan reports (auto-generated, HTML + text)
```

---

## Security notes

- `config.json` contains your Gmail App Password — it is gitignored by default. Never commit it.
- Auto-remediation requires elevated privileges (root on Linux, Administrator on Windows).
- IP addresses from scan results are validated before use in any system command (prevents injection).
- All `subprocess` calls use argument lists, never `shell=True` (prevents shell injection).
- Windows firewall rules created by auto-remediation are named `SC_Block_<ip>` for easy identification.

---

## Running the tests

The test suite uses Python's built-in `unittest` — no third-party test runner needed:

```bash
# Run all 106 tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# Run a single test file
python3 -m unittest tests.test_platform_adapter -v
```

Windows code paths are tested everywhere via `unittest.mock` — no Windows machine is required to run the full test suite.

---

## Contributing

Pull requests welcome. Guidelines:

1. **Platform-specific code goes in `platform_adapter.py` only.** Every other module calls through it. This keeps the rest of the codebase platform-agnostic.
2. **No third-party Python packages.** The stdlib-only constraint is intentional for security and portability.
3. **All subprocess calls must use argument lists** (never `shell=True`).
4. **Validate any network-derived value** before passing it to a system command — use `validate_ip()` or equivalent.
5. **Tests are required.** Add tests to the relevant file in `tests/`. Run `python3 -m unittest discover -s tests` before submitting.
6. Run `python3 -m py_compile modules/*.py security_commander.py` before submitting.

---

## License

MIT — see [LICENSE](LICENSE).
