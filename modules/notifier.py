"""
Notification module: sends email alerts and writes log reports.
Email uses Gmail SMTP with App Password authentication.
"""

import smtplib
import ssl
import logging
import json
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

from modules import platform_adapter

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}

SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}


def _build_category_findings_html(label, emoji, findings, bg_color, border_color):
    """Render a single category section (New / Recurring / Resolved) as HTML rows."""
    if not findings:
        return ""
    rows = ""
    for f in findings:
        sev = f.get('severity', 'LOW')
        color = SEVERITY_COLOR.get(sev, '#6b7280')
        sev_emoji = SEVERITY_EMOJI.get(sev, '')
        detail = f.get('detail', '')
        ftype = f.get('type', '').replace('_', ' ').upper()
        rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;">
                <span style="color:{color};font-weight:bold;">{sev_emoji} {sev}</span>
            </td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px;">{ftype}</td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;">{detail}</td>
        </tr>"""
    return f"""
        <h3 style="color:#1f2937;margin-top:20px;padding:8px 12px;
                   background:{bg_color};border-left:4px solid {border_color};border-radius:4px;">
            {emoji} {label} ({len(findings)})
        </h3>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#e5e7eb;">
                <th style="padding:8px;text-align:left;">Severity</th>
                <th style="padding:8px;text-align:left;">Type</th>
                <th style="padding:8px;text-align:left;">Detail</th>
            </tr>
            {rows}
        </table>"""


def _build_html_report(summary, prioritized_findings, remediation_actions, scan_duration,
                       categories=None):
    """Build an HTML email body."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = platform_adapter.get_hostname()

    total = summary.get('total', 0)
    critical = summary.get('CRITICAL', 0)
    high = summary.get('HIGH', 0)
    medium = summary.get('MEDIUM', 0)
    low = summary.get('LOW', 0)

    overall_status = "ALL CLEAR" if total == 0 else (
        "CRITICAL ALERT" if critical > 0 else
        "WARNING" if high > 0 else
        "ADVISORY"
    )
    status_color = "#16a34a" if total == 0 else (
        "#dc2626" if critical > 0 else
        "#ea580c" if high > 0 else
        "#ca8a04"
    )

    # Build findings section — categorised or flat depending on whether categories were passed
    if categories is not None:
        new_count = len(categories.get('new', []))
        recurring_count = len(categories.get('recurring', []))
        resolved_count = len(categories.get('resolved', []))
        suppressed_count = len(categories.get('suppressed', []))
        summary_bar = (
            f'<p style="font-size:13px;color:#6b7280;margin:0 0 15px;">'
            f'<strong>{new_count} new</strong> | {recurring_count} recurring | '
            f'{resolved_count} resolved | {suppressed_count} suppressed</p>'
        )
        findings_inner = (
            summary_bar
            + _build_category_findings_html("New", "🆕", categories.get('new', []),
                                            "#fef9c3", "#ca8a04")
            + _build_category_findings_html("Recurring", "🔁", categories.get('recurring', []),
                                            "#fff7ed", "#ea580c")
            + _build_category_findings_html("Resolved", "✅", categories.get('resolved', []),
                                            "#f0fdf4", "#16a34a")
        )
        if not any([categories.get('new'), categories.get('recurring'), categories.get('resolved')]):
            findings_inner = '<p style="color:#16a34a;padding:16px;">No new or recurring findings to report.</p>'
        findings_html = None  # unused in categorised mode
    else:
        findings_inner = None
        findings_html = ""
        for f in prioritized_findings:
            sev = f.get('severity', 'LOW')
            color = SEVERITY_COLOR.get(sev, '#6b7280')
            emoji = SEVERITY_EMOJI.get(sev, '')
            findings_html += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;">
                <span style="color:{color};font-weight:bold;">{emoji} {sev}</span>
            </td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:13px;">
                {f.get('type', '').replace('_', ' ').upper()}
            </td>
            <td style="padding:8px;border-bottom:1px solid #e5e7eb;">{f.get('detail', '')}</td>
        </tr>"""

    actions_html = ""
    if remediation_actions:
        for a in remediation_actions:
            status = "✅ Success" if a.get('success') else "❌ Failed"
            actions_html += f"""
            <tr>
                <td style="padding:6px;border-bottom:1px solid #e5e7eb;">{a.get('action', '').replace('_', ' ').title()}</td>
                <td style="padding:6px;border-bottom:1px solid #e5e7eb;font-family:monospace;">{a.get('target', '')}</td>
                <td style="padding:6px;border-bottom:1px solid #e5e7eb;">{status}</td>
                <td style="padding:6px;border-bottom:1px solid #e5e7eb;">{a.get('message', '')}</td>
            </tr>"""
        actions_section = f"""
        <h2 style="color:#1f2937;margin-top:30px;">Auto-Remediation Actions</h2>
        <table style="width:100%;border-collapse:collapse;background:#f9fafb;">
            <tr style="background:#e5e7eb;">
                <th style="padding:8px;text-align:left;">Action</th>
                <th style="padding:8px;text-align:left;">Target</th>
                <th style="padding:8px;text-align:left;">Result</th>
                <th style="padding:8px;text-align:left;">Message</th>
            </tr>
            {actions_html}
        </table>"""
    else:
        actions_section = ""

    if categories is not None:
        findings_section = f"""
        <h2 style="color:#1f2937;margin-top:30px;">Security Findings ({total} total)</h2>
        {findings_inner}"""
    else:
        findings_section = f"""
        <h2 style="color:#1f2937;margin-top:30px;">Security Findings ({total} total)</h2>
        <table style="width:100%;border-collapse:collapse;">
            <tr style="background:#e5e7eb;">
                <th style="padding:8px;text-align:left;">Severity</th>
                <th style="padding:8px;text-align:left;">Type</th>
                <th style="padding:8px;text-align:left;">Detail</th>
            </tr>
            {findings_html if findings_html else '<tr><td colspan="3" style="padding:16px;text-align:center;color:#16a34a;">No security issues detected.</td></tr>'}
        </table>"""

    html = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;max-width:900px;margin:0 auto;color:#1f2937;background:#f3f4f6;padding:20px;">
    <div style="background:white;border-radius:8px;padding:30px;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
        <div style="border-left:5px solid {status_color};padding-left:15px;margin-bottom:25px;">
            <h1 style="margin:0;color:{status_color};">Security Commander — {overall_status}</h1>
            <p style="color:#6b7280;margin:5px 0 0;">Host: <strong>{hostname}</strong> | Scan: {timestamp} | Duration: {scan_duration:.1f}s</p>
        </div>

        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:25px;">
            <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:15px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#dc2626;">{critical}</div>
                <div style="color:#991b1b;font-size:13px;">CRITICAL</div>
            </div>
            <div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:15px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#ea580c;">{high}</div>
                <div style="color:#9a3412;font-size:13px;">HIGH</div>
            </div>
            <div style="background:#fefce8;border:1px solid #fde68a;border-radius:6px;padding:15px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#ca8a04;">{medium}</div>
                <div style="color:#92400e;font-size:13px;">MEDIUM</div>
            </div>
            <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:15px;text-align:center;">
                <div style="font-size:28px;font-weight:bold;color:#2563eb;">{low}</div>
                <div style="color:#1e40af;font-size:13px;">LOW</div>
            </div>
        </div>

        {findings_section}
        {actions_section}

        <hr style="border:none;border-top:1px solid #e5e7eb;margin:30px 0;">
        <p style="color:#9ca3af;font-size:12px;text-align:center;">
            Security Commander | Linux Mint | Auto-generated daily security report
        </p>
    </div>
</body>
</html>"""
    return html


def _build_text_report(summary, prioritized_findings, remediation_actions, scan_duration,
                       categories=None):
    """Build a plain-text version of the report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = platform_adapter.get_hostname()
    lines = [
        "=" * 70,
        "SECURITY COMMANDER — DAILY SCAN REPORT",
        "=" * 70,
        f"Host: {hostname}",
        f"Timestamp: {timestamp}",
        f"Scan duration: {scan_duration:.1f}s",
        "",
        "SUMMARY",
        "-" * 40,
        f"  CRITICAL : {summary.get('CRITICAL', 0)}",
        f"  HIGH     : {summary.get('HIGH', 0)}",
        f"  MEDIUM   : {summary.get('MEDIUM', 0)}",
        f"  LOW      : {summary.get('LOW', 0)}",
        f"  TOTAL    : {summary.get('total', 0)}",
        "",
    ]

    if categories is not None:
        def _text_category(label, emoji, findings):
            if not findings:
                return []
            out = [f"{emoji} {label} ({len(findings)})", "-" * 40]
            for f in findings:
                sev = f.get('severity', 'LOW')
                ftype = f.get('type', '').replace('_', ' ').upper()
                detail = f.get('detail', '')
                out.append(f"  [{sev}] {ftype}")
                out.append(f"         {detail}")
            out.append("")
            return out

        new_count = len(categories.get('new', []))
        recurring_count = len(categories.get('recurring', []))
        resolved_count = len(categories.get('resolved', []))
        suppressed_count = len(categories.get('suppressed', []))
        lines.append(f"ALERT SUMMARY: {new_count} new | {recurring_count} recurring | "
                     f"{resolved_count} resolved | {suppressed_count} suppressed")
        lines.append("")
        lines.extend(_text_category("NEW FINDINGS", ">>", categories.get('new', [])))
        lines.extend(_text_category("RECURRING FINDINGS", "~~", categories.get('recurring', [])))
        lines.extend(_text_category("RESOLVED", "OK", categories.get('resolved', [])))
    elif prioritized_findings:
        lines.append("FINDINGS")
        lines.append("-" * 40)
        for f in prioritized_findings:
            sev = f.get('severity', 'LOW')
            ftype = f.get('type', '').replace('_', ' ').upper()
            detail = f.get('detail', '')
            lines.append(f"  [{sev}] {ftype}")
            lines.append(f"         {detail}")
        lines.append("")

    if remediation_actions:
        lines.append("AUTO-REMEDIATION ACTIONS")
        lines.append("-" * 40)
        for a in remediation_actions:
            status = "SUCCESS" if a.get('success') else "FAILED"
            lines.append(f"  [{status}] {a.get('action', '').upper()} -> {a.get('target', '')}")
            lines.append(f"           {a.get('message', '')}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def send_email(config, subject, html_body, text_body):
    """Send email via Gmail SMTP. Returns (success, error_message)."""
    email_config = config.get('email', {})
    if not email_config.get('enabled', False):
        logger.info("Email notifications disabled in config")
        return False, "Email disabled"

    app_password = email_config.get('app_password', '')
    if not app_password or app_password == 'YOUR_GMAIL_APP_PASSWORD_HERE':
        logger.warning("Gmail App Password not configured. Skipping email.")
        return False, "App password not configured"

    sender = email_config.get('sender', '')
    recipient = email_config.get('recipient', '')
    smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
    smtp_port = email_config.get('smtp_port', 587)

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        tls_context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=tls_context)
            server.login(sender, app_password)
            server.sendmail(sender, recipient, msg.as_string())

        logger.info(f"Email report sent to {recipient}")
        return True, ""
    except smtplib.SMTPAuthenticationError:
        err = "Gmail authentication failed. Check your App Password in config.json."
        logger.error(err)
        return False, err
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False, str(e)


def write_report(config, summary, prioritized_findings, remediation_actions, scan_duration,
                 categories=None):
    """Write report to file and optionally send email. categories=None uses legacy flat rendering."""
    report_dir = Path(config.get('logging', {}).get('report_dir') or
                      (Path.home() / 'security-commander-reports'))
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = report_dir / f"scan_{timestamp}.txt"

    text_body = _build_text_report(summary, prioritized_findings, remediation_actions,
                                   scan_duration, categories)
    html_body = _build_html_report(summary, prioritized_findings, remediation_actions,
                                   scan_duration, categories)

    # Write text report
    report_file.write_text(text_body)
    logger.info(f"Report written to {report_file}")

    # Write JSON report for programmatic access
    json_file = report_dir / f"scan_{timestamp}.json"
    json_file.write_text(json.dumps({
        "timestamp": timestamp,
        "summary": summary,
        "findings": prioritized_findings,
        "remediation_actions": remediation_actions,
        "scan_duration_seconds": scan_duration,
    }, indent=2))

    # Purge old reports
    keep_days = config.get('logging', {}).get('keep_reports_days', 30)
    _purge_old_reports(report_dir, keep_days)

    # Build email subject
    critical = summary.get('CRITICAL', 0)
    high = summary.get('HIGH', 0)
    total = summary.get('total', 0)
    hostname = platform_adapter.get_hostname()

    if categories is not None:
        nc = len(categories.get('new', []))
        rc = len(categories.get('recurring', []))
        xc = len(categories.get('resolved', []))
        cat_stats = f"[{nc} new, {rc} recurring, {xc} resolved]"
    else:
        cat_stats = ""

    if total == 0 and not (categories and (categories.get('new') or categories.get('recurring'))):
        subject = f"[Security Commander] ✅ All Clear — {hostname}"
        if cat_stats:
            subject += f" {cat_stats}"
    elif critical > 0:
        subject = f"[Security Commander] 🔴 CRITICAL: {critical} critical issue(s) on {hostname}"
        if cat_stats:
            subject += f" {cat_stats}"
    elif high > 0:
        subject = f"[Security Commander] 🟠 WARNING: {high} high-severity issue(s) on {hostname}"
        if cat_stats:
            subject += f" {cat_stats}"
    else:
        subject = f"[Security Commander] 🟡 Advisory: {total} finding(s) on {hostname}"
        if cat_stats:
            subject += f" {cat_stats}"

    # Send email
    email_success, email_error = send_email(config, subject, html_body, text_body)

    return {
        "report_file": str(report_file),
        "email_sent": email_success,
        "email_error": email_error,
        "subject": subject,
    }


def _purge_old_reports(report_dir, keep_days):
    """Delete reports older than keep_days."""
    import time
    cutoff = time.time() - (keep_days * 86400)
    for f in report_dir.glob("scan_*"):
        if f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                logger.debug(f"Deleted old report: {f}")
            except Exception:
                pass
