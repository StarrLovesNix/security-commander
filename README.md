# Security Commander

A lightweight, daily security scanner for Linux systems. Scans the local machine and LAN, auto-remediates low-risk threats, sends email alerts, and suppresses recurring findings via a cooldown system.

## Features

- **Local system scan** — open ports, running processes, user accounts, SSH keys, SUID files, cron jobs
- **Network scan** — LAN device discovery (nmap), dangerous exposed ports, ARP spoofing detection
- **Log analysis** — SSH brute force, external logins, sudo failures and dangerous commands
- **Auto-remediation** — block IPs via firewall (ufw / firewalld / iptables), kill suspicious processes, fix world-writable files
- **Alert deduplication** — per-severity cooldowns prevent email flooding for persistent findings
- **Acknowledge mode** — suppress known-good findings without disabling alerts
- **HTML email reports** — categorised by New / Recurring / Resolved

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | No third-party packages needed |
| `nmap` | Network scanning |
| `ufw` / `firewalld` / `iptables` | Auto-remediation (any one is sufficient) |
| Root / sudo | Full functionality (some checks degrade gracefully without it) |
| Gmail account | For email alerts (uses App Passwords) |

### Install system dependencies

**Debian / Ubuntu / Linux Mint:**
```bash
sudo apt install nmap ufw python3
```

**RHEL / Fedora / CentOS:**
```bash
sudo dnf install nmap firewalld python3
```

## Installation

```bash
# 1. Clone or download
git clone https://github.com/your-org/security-commander.git
cd security-commander

# 2. Run setup (configures email, installs scheduler, runs baseline scan)
sudo python3 setup.py
```

Setup will:
1. Prompt for your Gmail address and App Password
2. Install a systemd timer (or cron job on non-systemd systems) to run daily at 06:00
3. Run an initial baseline scan to establish normal state

## Configuration

Copy `config.json.example` to `config.json` and edit as needed (setup does this automatically):

```bash
cp config.json.example config.json
```

Key settings:

| Setting | Description |
|---|---|
| `email.sender` | Your Gmail address |
| `email.app_password` | 16-character Gmail App Password |
| `thresholds.failed_ssh_attempts_block` | SSH failures before auto-block (default: 20) |
| `remediation.auto_block_brute_force` | Enable/disable automatic IP blocking |
| `alert_history.cooldown_days` | Days between repeat alerts per severity |
| `logging.report_dir` | Where scan reports are written (default: `reports/`) |

## Usage

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

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings above LOW |
| 1 | HIGH findings present |
| 2 | CRITICAL findings present |
| 3 | Unexpected error |
| 130 | Interrupted by user |

## Project structure

```
security-commander/
├── security_commander.py     # Main entry point
├── setup.py                  # Installation script
├── config.json               # Your configuration (gitignored)
├── config.json.example       # Template — copy this to config.json
├── modules/
│   ├── platform_adapter.py   # OS abstraction layer (add new platforms here)
│   ├── local_scanner.py      # Local system checks
│   ├── network_scanner.py    # LAN discovery and port scanning
│   ├── log_analyzer.py       # Auth log analysis
│   ├── threat_assessor.py    # Prioritisation and deduplication
│   ├── remediator.py         # Auto-remediation actions
│   ├── notifier.py           # Email and report generation
│   └── alert_history.py      # Cross-scan deduplication and cooldowns
├── data/
│   ├── baseline.json         # Security baseline (auto-generated)
│   └── alert_history.json    # Alert state (auto-generated)
└── reports/                  # Scan reports (auto-generated)
```

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Debian / Ubuntu / Linux Mint | **Full** | Primary target |
| RHEL / Fedora / CentOS / AlmaLinux | **Full** | Uses `/var/log/secure`, firewalld/iptables |
| Arch / Manjaro | **Partial** | Log scanning may be limited (journald) |
| macOS | **Partial** | Network detection, processes, kill, chmod work; firewall not yet implemented |
| Windows | **Stub** | Not supported |

To add support for a new platform, edit `modules/platform_adapter.py` — it's the single file that owns all OS-specific calls.

## Security notes

- `config.json` contains your Gmail App Password — do not commit it to version control. Add it to `.gitignore`.
- Auto-remediation requires root. Run with `sudo` for full functionality.
- IP addresses from scan results are validated before use in system commands.
- All subprocess calls use argument lists (not shell strings) to prevent command injection.

## Contributing

Pull requests welcome. When adding features:

1. If the feature requires OS-specific calls, add them to `platform_adapter.py`
2. Keep the Linux implementation complete; add macOS/Windows stubs
3. Run `python3 -m py_compile modules/*.py security_commander.py` before submitting

## License

MIT — see [LICENSE](LICENSE).
