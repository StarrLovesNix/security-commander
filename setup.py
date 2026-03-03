#!/usr/bin/env python3
"""
Security Commander — Setup Script
Configures email credentials, installs a scheduler (systemd or cron),
and runs the initial security baseline scan.

Usage: sudo python3 setup.py
"""

import json
import os
import shutil
import subprocess
import sys
from getpass import getpass
from pathlib import Path

# Add project root to path so platform_adapter is importable
sys.path.insert(0, str(Path(__file__).parent))
from modules.platform_adapter import get_available_schedulers

BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
CONFIG_EXAMPLE = BASE_DIR / "config.json.example"
SERVICE_TEMPLATE = BASE_DIR / "security-commander.service"
TIMER_FILE = BASE_DIR / "security-commander.timer"
SYSTEMD_DIR = Path("/etc/systemd/system")
CRON_FILE = Path("/etc/cron.d/security-commander")


def print_banner():
    print("\n" + "=" * 60)
    print("  SECURITY COMMANDER — Setup")
    print("=" * 60)


def check_root():
    if os.geteuid() != 0:
        print("ERROR: This setup script must be run as root.")
        print("       sudo python3 setup.py")
        sys.exit(1)


def ensure_config():
    """Create config.json from the example template if it doesn't exist."""
    if not CONFIG_FILE.exists():
        if CONFIG_EXAMPLE.exists():
            shutil.copy(CONFIG_EXAMPLE, CONFIG_FILE)
            print(f"Created config.json from template.")
        else:
            print(f"ERROR: Neither {CONFIG_FILE} nor {CONFIG_EXAMPLE} found.")
            sys.exit(1)


def configure_email():
    print("\n  Email Configuration")
    print("-" * 40)
    print("Security Commander uses Gmail App Passwords to send alerts.")
    print("To create an App Password:")
    print("  1. Go to: https://myaccount.google.com/apppasswords")
    print("  2. Sign in to your Google account")
    print("  3. Create a new App Password (name it 'Security Commander')")
    print("  4. Enter the details below\n")

    with open(CONFIG_FILE) as f:
        config = json.load(f)

    current_addr = config['email'].get('sender', '')
    if current_addr and current_addr != 'YOUR_EMAIL@gmail.com':
        change = input(f"Email already set to {current_addr}. Change it? [y/N]: ").strip().lower()
        if change != 'y':
            return config

    email_addr = input("Your Gmail address: ").strip()
    if not email_addr or '@' not in email_addr:
        print("Invalid email address. Skipping email setup.")
        return config

    app_password = getpass("Gmail App Password (16 chars, input hidden): ").strip().replace(" ", "")
    if len(app_password) < 16:
        print("WARNING: App password seems short. Make sure to copy all 16 characters.")

    recipient = input(f"Alert recipient email [{email_addr}]: ").strip() or email_addr

    config['email']['sender'] = email_addr
    config['email']['recipient'] = recipient
    config['email']['app_password'] = app_password
    config['email']['enabled'] = True

    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

    print("  Gmail credentials saved to config.json")
    return config


def install_systemd(config):
    print("\n  Installing systemd timer")
    print("-" * 40)

    # Write the service file with the actual install path substituted
    service_content = f"""[Unit]
Description=Security Commander Daily Security Scan
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStart={sys.executable} {BASE_DIR}/security_commander.py
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-commander
PrivateTmp=false
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
"""
    dest_service = SYSTEMD_DIR / "security-commander.service"
    dest_service.write_text(service_content)
    shutil.copy(TIMER_FILE, SYSTEMD_DIR / "security-commander.timer")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "security-commander.timer"], check=True)
    subprocess.run(["systemctl", "start", "security-commander.timer"], check=True)

    result = subprocess.run(
        ["systemctl", "status", "security-commander.timer"],
        capture_output=True, text=True
    )
    print(result.stdout[:500])
    print("  systemd timer installed — daily scans at 06:00")


def install_cron():
    print("\n  Installing cron job (daily at 06:00)")
    print("-" * 40)
    cron_line = f"0 6 * * * root {sys.executable} {BASE_DIR}/security_commander.py\n"
    CRON_FILE.write_text(f"# Security Commander — daily scan\n{cron_line}")
    print(f"  Cron job installed: {CRON_FILE}")


def install_scheduler(config):
    schedulers = get_available_schedulers()
    if schedulers['systemd']:
        install_systemd(config)
    elif schedulers['cron']:
        install_cron()
    else:
        print("\n  WARNING: No supported scheduler found (systemd or cron).")
        print(f"  Run manually: sudo python3 {BASE_DIR}/security_commander.py")


def run_baseline():
    print("\n  Running initial security baseline scan...")
    print("-" * 40)
    print("This may take a few minutes (network scan in progress)...\n")
    result = subprocess.run(
        [sys.executable, str(BASE_DIR / "security_commander.py"),
         "--baseline", "--no-email", "--verbose"],
        capture_output=False
    )
    if result.returncode in (0, 1, 2):
        print("\n  Baseline scan complete.")
    else:
        print(f"\n  Warning: scan exited with code {result.returncode}")


def main():
    print_banner()
    check_root()
    ensure_config()

    print("\nThis setup will:")
    print("  1. Configure your Gmail App Password for alert emails")
    print("  2. Install a scheduler (systemd timer or cron)")
    print("  3. Run an initial security baseline scan")
    print()
    confirm = input("Proceed? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("Setup cancelled.")
        sys.exit(0)

    config = configure_email()
    install_scheduler(config)
    run_baseline()

    with open(CONFIG_FILE) as f:
        final_config = json.load(f)
    recipient = final_config.get('email', {}).get('recipient', '(not configured)')
    report_dir = final_config.get('logging', {}).get('report_dir', str(BASE_DIR / 'reports'))

    print("\n" + "=" * 60)
    print("  Security Commander is installed!")
    print("=" * 60)
    print(f"\n  Daily scans:  06:00 every day")
    print(f"  Email alerts: {recipient}")
    print(f"  Reports:      {report_dir}")
    print(f"\n  Manual scan:  sudo python3 {BASE_DIR}/security_commander.py")
    print(f"  Acknowledge:  python3 {BASE_DIR}/security_commander.py --acknowledge")

    schedulers = get_available_schedulers()
    if schedulers['systemd']:
        print(f"  View logs:    journalctl -u security-commander -f")
        print(f"  Timer status: systemctl status security-commander.timer")
    elif schedulers['cron']:
        print(f"  Cron job:     {CRON_FILE}")
    print()


if __name__ == '__main__':
    main()
