#!/usr/bin/env python3
"""
Security Commander — Daily Security Agent
==========================================
Scans local system and LAN for security threats, auto-remediates
low-risk issues, and sends email + log reports.

Usage:
    python3 security_commander.py [--baseline] [--no-email] [--verbose]
    python3 security_commander.py --acknowledge

    --baseline     Force rebuild of security baseline (run on first setup)
    --no-email     Skip email notification (report to log file only)
    --verbose      Verbose logging output
    --acknowledge  Interactive: acknowledge/suppress persistent findings
"""

import argparse
import json
import logging
import os
import platform
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Ensure modules directory is importable
sys.path.insert(0, str(Path(__file__).parent))

from modules import local_scanner, network_scanner, log_analyzer, threat_assessor, remediator, notifier
from modules import alert_history

# Paths
BASE_DIR = Path(__file__).parent
CONFIG_FILE = BASE_DIR / "config.json"
DATA_DIR = BASE_DIR / "data"
BASELINE_FILE = DATA_DIR / "baseline.json"
LOCK_FILE = Path(tempfile.gettempdir()) / "security_commander.lock"
HISTORY_FILE = DATA_DIR / "alert_history.json"


def setup_logging(verbose=False, report_dir=None):
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]

    if report_dir:
        log_file = Path(report_dir) / "security_commander.log"
        Path(report_dir).mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def load_config():
    if not CONFIG_FILE.exists():
        example = CONFIG_FILE.parent / "config.json.example"
        logging.error(f"Config file not found: {CONFIG_FILE}")
        if example.exists():
            logging.error(f"Copy the example and edit it: cp {example} {CONFIG_FILE}")
        else:
            logging.error("Run setup.py to configure, or create config.json manually.")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        config = json.load(f)
    # Resolve report_dir: if absent or relative, anchor it to BASE_DIR/reports
    log_section = config.setdefault('logging', {})
    rd = log_section.get('report_dir', '')
    if not rd or not Path(rd).is_absolute():
        log_section['report_dir'] = str(BASE_DIR / (rd or 'reports'))
    return config


def load_baseline():
    if BASELINE_FILE.exists():
        with open(BASELINE_FILE) as f:
            return json.load(f)
    return None


def save_baseline(snapshot):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    snapshot['baseline_created'] = datetime.now().isoformat()
    with open(BASELINE_FILE, 'w') as f:
        json.dump(snapshot, f, indent=2)
    logging.getLogger(__name__).info(f"Baseline saved to {BASELINE_FILE}")


def acquire_lock():
    try:
        # Exclusive create — atomic, no TOCTOU window
        with open(LOCK_FILE, 'x') as f:
            f.write(str(os.getpid()))
    except FileExistsError:
        try:
            pid = int(LOCK_FILE.read_text().strip())
            os.kill(pid, 0)  # Raises OSError if process is gone
            logging.error(f"Security Commander is already running (PID {pid}). Exiting.")
            sys.exit(1)
        except (OSError, ValueError):
            # Stale lock — previous run crashed without cleanup
            LOCK_FILE.unlink(missing_ok=True)
            acquire_lock()


def release_lock():
    LOCK_FILE.unlink(missing_ok=True)


def run_acknowledge(config):
    """Interactive mode: list active findings and let the user acknowledge (suppress) them."""
    hist_cfg = config.get('alert_history', {})
    hist_path = BASE_DIR / hist_cfg.get('history_file', 'data/alert_history.json')
    history = alert_history.load_history(hist_path)

    active = alert_history.list_active_findings_for_ack(history)
    if not active:
        print("No active findings to acknowledge.")
        return

    print()
    print("=== Active Findings — Enter numbers to acknowledge ===")
    for idx, (key, entry) in enumerate(active, start=1):
        sev = entry.get('severity', 'LOW')
        print(f"  [{idx:2d}] [{sev:<8}] {key}")
        print(f"        First seen: {entry.get('first_seen', '?')}  |  "
              f"Alert count: {entry.get('alert_count', 0)}")
        if entry.get('detail'):
            print(f"        {entry['detail']}")
        print()

    raw = input("Enter numbers to acknowledge (comma-separated, or 'all'): ").strip()
    if not raw:
        print("No selection made. Exiting.")
        return

    if raw.lower() == 'all':
        selected_keys = [key for key, _ in active]
    else:
        try:
            indices = [int(x.strip()) for x in raw.split(',') if x.strip()]
            selected_keys = [active[i - 1][0] for i in indices if 1 <= i <= len(active)]
        except (ValueError, IndexError):
            print("Invalid input. Exiting.")
            return

    if not selected_keys:
        print("No valid findings selected. Exiting.")
        return

    note = input("Optional note (leave blank to skip): ").strip()
    count = alert_history.acknowledge_findings(history, selected_keys, note)
    alert_history.save_history(history, hist_path)
    print(f"\nAcknowledged {count} finding(s). Suppressed from future emails.")


def run_scan(config, baseline, no_email=False, force_baseline=False):
    logger = logging.getLogger(__name__)
    start_time = time.time()
    all_findings = []
    combined_snapshot = {}

    logger.info("=" * 60)
    logger.info("Security Commander — Starting daily scan")
    logger.info("=" * 60)

    # ---- 1. Local System Scan ----
    logger.info("[1/3] Running local system scan...")
    try:
        local_findings, local_snapshot = local_scanner.scan(baseline)
        all_findings.extend(local_findings)
        combined_snapshot.update(local_snapshot)
        logger.info(f"      → {len(local_findings)} local findings")
    except Exception as e:
        logger.error(f"Local scanner error: {e}", exc_info=True)

    # ---- 2. Log Analysis ----
    logger.info("[2/3] Analyzing system logs...")
    try:
        log_findings, log_stats = log_analyzer.analyze_logs(config)
        all_findings.extend(log_findings)
        logger.info(f"      → {len(log_findings)} log findings")
    except Exception as e:
        logger.error(f"Log analyzer error: {e}", exc_info=True)

    # ---- 3. Network Scan ----
    logger.info("[3/3] Scanning local network...")
    try:
        net_findings, net_snapshot = network_scanner.scan(baseline, config)
        all_findings.extend(net_findings)
        combined_snapshot.update(net_snapshot)
        logger.info(f"      → {len(net_findings)} network findings")
    except Exception as e:
        logger.error(f"Network scanner error: {e}", exc_info=True)

    scan_duration = time.time() - start_time

    # ---- 4. Assess Threats ----
    logger.info("Assessing threats...")
    prioritized, auto_remediate, notify_only, summary = threat_assessor.assess(all_findings)

    logger.info(f"Threat summary: {summary}")

    # ---- 4b. Alert History — deduplicate and categorise ----
    hist_cfg = config.get('alert_history', {})
    categories = None
    history = {}
    hist_path = BASE_DIR / hist_cfg.get('history_file', 'data/alert_history.json')

    if hist_cfg.get('enabled', True):
        history = alert_history.load_history(hist_path)
        alert_history.update_history(history, prioritized, hist_cfg.get('cooldown_days'))
        categories = alert_history.categorize_findings(
            history, prioritized, hist_cfg.get('cooldown_days')
        )
        cat_summary = alert_history.build_email_summary(categories)
        logger.info(
            f"Alert categories: {cat_summary['new_count']} new, "
            f"{cat_summary['recurring_count']} recurring, "
            f"{cat_summary['resolved_count']} resolved, "
            f"{cat_summary['suppressed_count']} suppressed"
        )

    # ---- 5. Auto-Remediation ----
    remediation_actions = []
    if auto_remediate and not force_baseline:
        logger.info(f"Running auto-remediation for {len(auto_remediate)} findings...")
        remediation_actions = remediator.remediate(auto_remediate, config)
        for action in remediation_actions:
            status = "SUCCESS" if action.get('success') else "FAILED"
            logger.info(f"  [{status}] {action.get('action')} -> {action.get('target')}: {action.get('message')}")

    # ---- 6. Save/Update Baseline ----
    if force_baseline or baseline is None:
        logger.info("Saving security baseline...")
        save_baseline(combined_snapshot)
    else:
        # Update baseline with current state for next comparison
        merged = {**baseline, **combined_snapshot}
        save_baseline(merged)

    # ---- 7. Send Notifications ----
    if no_email:
        config_copy = json.loads(json.dumps(config))
        config_copy['email']['enabled'] = False
    else:
        config_copy = config

    logger.info("Sending notifications and writing report...")
    result = notifier.write_report(
        config_copy, summary, prioritized, remediation_actions, scan_duration,
        categories=categories,
    )

    logger.info(f"Report saved to: {result['report_file']}")
    if result.get('email_sent'):
        logger.info(f"Email sent: {result.get('subject')}")
        # Mark alerted findings and persist history
        if categories is not None:
            alerted_keys = (
                [alert_history.finding_key(f) for f in categories.get('new', [])]
                + [alert_history.finding_key(f) for f in categories.get('recurring', [])]
            )
            alert_history.mark_alerted(history, alerted_keys)
            alert_history.save_history(history, hist_path)
            pruned = alert_history.prune_old_resolved(
                history, hist_cfg.get('resolved_retention_days', 30)
            )
            alert_history.save_history(history, hist_path)
            if pruned:
                logger.info(f"Pruned {pruned} old resolved finding(s) from history")
    elif not no_email:
        logger.warning(f"Email not sent: {result.get('email_error', 'unknown')}")
        # Still persist history state (update_history ran) even without email
        if categories is not None:
            alert_history.save_history(history, hist_path)

    logger.info("=" * 60)
    logger.info(f"Scan complete in {scan_duration:.1f}s | "
                f"CRITICAL:{summary['CRITICAL']} HIGH:{summary['HIGH']} "
                f"MEDIUM:{summary['MEDIUM']} LOW:{summary['LOW']}")
    logger.info("=" * 60)

    return summary


def _is_admin() -> bool:
    """Cross-platform check for elevated / administrator privileges."""
    if platform.system() == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Security Commander — Daily Security Agent")
    parser.add_argument('--baseline', action='store_true',
                        help='Force rebuild baseline (use on first run)')
    parser.add_argument('--no-email', action='store_true',
                        help='Skip email notification')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--acknowledge', action='store_true',
                        help='Interactive mode: acknowledge/suppress persistent findings')
    args = parser.parse_args()

    config = load_config()
    report_dir = config.get('logging', {}).get('report_dir', str(BASE_DIR / 'reports'))
    setup_logging(verbose=args.verbose, report_dir=report_dir)
    logger = logging.getLogger(__name__)

    # --acknowledge does not require root or lock
    if args.acknowledge:
        run_acknowledge(config)
        sys.exit(0)

    # Check for elevated privileges
    if not _is_admin():
        logger.warning(
            "Not running as administrator / root. Some scans (SUID files, auth logs, "
            "firewall rules) may be incomplete. "
            "Run with sudo (Linux/macOS) or as Administrator (Windows) for full functionality."
        )

    acquire_lock()
    try:
        baseline = load_baseline()
        if args.baseline or baseline is None:
            if baseline is None:
                logger.info("No baseline found. Creating initial baseline on this scan.")
            else:
                logger.info("Forcing baseline rebuild as requested.")

        summary = run_scan(
            config=config,
            baseline=baseline if not args.baseline else None,
            no_email=args.no_email,
            force_baseline=args.baseline,
        )

        # Exit code reflects severity
        if summary.get('CRITICAL', 0) > 0:
            sys.exit(2)
        elif summary.get('HIGH', 0) > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(3)
    finally:
        release_lock()


if __name__ == '__main__':
    main()
