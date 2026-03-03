"""
Alert history — persistent cross-scan deduplication and cooldown suppression.

Manages data/alert_history.json to prevent flooding repeated alerts.
Cooldown defaults: CRITICAL=0 days (always), HIGH=3, MEDIUM=7, LOW=14.
"""

import json
import logging
from datetime import date, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_HISTORY_FILE = Path(__file__).parent.parent / "data" / "alert_history.json"

# Default cooldown per severity (days between re-alerts)
DEFAULT_COOLDOWN = {"CRITICAL": 0, "HIGH": 3, "MEDIUM": 7, "LOW": 14}


def finding_key(f):
    """
    Canonical string key for a finding — mirrors threat_assessor.py deduplication,
    extended with pid: tie-breaker for process findings.
    """
    ftype = f.get('type', 'unknown')
    if ftype == 'suspicious_process':
        tiebreaker = f.get('pid', f.get('ip', f.get('port', f.get('user', f.get('file', '')))))
    else:
        tiebreaker = f.get('ip', f.get('port', f.get('user', f.get('file', ''))))
    return f"{ftype}:{tiebreaker}"


def load_history(path=None):
    """Load alert history from JSON. Returns {} if file missing or unreadable."""
    path = Path(path) if path else DEFAULT_HISTORY_FILE
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Could not load alert history from {path}: {e}")
        return {}


def save_history(history, path=None):
    """Atomically write alert history to JSON file."""
    path = Path(path) if path else DEFAULT_HISTORY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    try:
        with open(tmp, 'w') as f:
            json.dump(history, f, indent=2, default=str)
        tmp.replace(path)
    except IOError as e:
        logger.error(f"Failed to save alert history to {path}: {e}")
        tmp.unlink(missing_ok=True)
        raise


def update_history(history, current_findings, cooldown_cfg=None):
    """
    Reconcile current scan findings against history:
    - Adds new entries with first_seen today
    - Updates last_seen on existing entries
    - Un-resolves findings that re-appeared
    - Marks absent findings as resolved

    Returns history (mutated in place).
    """
    today = date.today().isoformat()
    current_keys = set()

    for f in current_findings:
        key = finding_key(f)
        current_keys.add(key)

        if key not in history:
            history[key] = {
                "key": key,
                "first_seen": today,
                "last_seen": today,
                "alert_count": 0,
                "last_alerted": None,
                "acknowledged": False,
                "acknowledged_note": "",
                "severity": f.get('severity', 'LOW'),
                "detail": f.get('detail', ''),
                "resolved": False,
                "resolved_date": None,
            }
        else:
            entry = history[key]
            entry["last_seen"] = today
            entry["severity"] = f.get('severity', entry.get('severity', 'LOW'))
            entry["detail"] = f.get('detail', entry.get('detail', ''))
            if entry.get("resolved"):
                entry["resolved"] = False
                entry["resolved_date"] = None
                logger.info(f"Finding re-appeared after resolution: {key}")

    # Mark absent findings as resolved
    for key, entry in history.items():
        if key not in current_keys and not entry.get("resolved"):
            entry["resolved"] = True
            entry["resolved_date"] = today
            logger.info(f"Finding resolved: {key}")

    return history


def _days_since(date_str):
    """Return number of days since date_str (ISO format). None if unparseable."""
    try:
        return (date.today() - date.fromisoformat(date_str)).days
    except (ValueError, TypeError):
        return None


def _is_in_cooldown(entry, cooldown_cfg):
    """
    Return True if the finding should be suppressed (still within cooldown period).
    """
    cooldown = cooldown_cfg if cooldown_cfg else DEFAULT_COOLDOWN
    severity = entry.get("severity", "LOW")
    cooldown_days = cooldown.get(severity, DEFAULT_COOLDOWN.get(severity, 14))

    if cooldown_days == 0:
        return False  # CRITICAL: always re-alert

    last_alerted = entry.get("last_alerted")
    if not last_alerted:
        return False  # Never alerted — not in cooldown

    days_since = _days_since(last_alerted)
    if days_since is None:
        return False
    return days_since < cooldown_days


def categorize_findings(history, current_findings, cooldown_cfg=None):
    """
    Classify current findings for email rendering.

    Returns:
        new        — never alerted before (alert_count == 0); always email
        recurring  — previously alerted, outside cooldown; re-alert
        suppressed — within cooldown or acknowledged; skip email
        resolved   — absent this scan, resolved today
    """
    new = []
    recurring = []
    suppressed = []
    today = date.today().isoformat()

    for f in current_findings:
        key = finding_key(f)
        entry = history.get(key, {})

        if entry.get("acknowledged"):
            suppressed.append(f)
            continue

        if entry.get("alert_count", 0) == 0:
            new.append(f)
            continue

        if _is_in_cooldown(entry, cooldown_cfg):
            suppressed.append(f)
        else:
            recurring.append(f)

    resolved = [
        {
            "key": key,
            "severity": entry.get("severity", "LOW"),
            "detail": entry.get("detail", ""),
            "first_seen": entry.get("first_seen", ""),
        }
        for key, entry in history.items()
        if entry.get("resolved") and entry.get("resolved_date") == today
    ]

    return {"new": new, "recurring": recurring, "suppressed": suppressed, "resolved": resolved}


def mark_alerted(history, keys):
    """
    Advance last_alerted and increment alert_count for given keys.
    Call only after a successful email send.
    """
    today = date.today().isoformat()
    for key in keys:
        if key in history:
            history[key]["last_alerted"] = today
            history[key]["alert_count"] = history[key].get("alert_count", 0) + 1


def build_email_summary(categories):
    """Return count dict for each category."""
    return {
        "new_count": len(categories.get("new", [])),
        "recurring_count": len(categories.get("recurring", [])),
        "resolved_count": len(categories.get("resolved", [])),
        "suppressed_count": len(categories.get("suppressed", [])),
    }


def list_active_findings_for_ack(history):
    """Return list of (key, entry) for findings that can be acknowledged."""
    return [
        (key, entry)
        for key, entry in history.items()
        if not entry.get("resolved") and not entry.get("acknowledged")
    ]


def acknowledge_findings(history, keys, note=""):
    """Mark specified findings as acknowledged (suppressed from future emails)."""
    today = date.today().isoformat()
    count = 0
    for key in keys:
        if key in history:
            history[key]["acknowledged"] = True
            history[key]["acknowledged_note"] = note
            history[key]["acknowledged_date"] = today
            count += 1
    return count


def prune_old_resolved(history, retention_days=30):
    """Remove resolved findings older than retention_days. Returns count removed."""
    cutoff = (date.today() - timedelta(days=retention_days)).isoformat()
    to_remove = [
        key for key, entry in history.items()
        if entry.get("resolved") and (entry.get("resolved_date") or "9999") < cutoff
    ]
    for key in to_remove:
        del history[key]
        logger.debug(f"Pruned old resolved finding: {key}")
    return len(to_remove)
