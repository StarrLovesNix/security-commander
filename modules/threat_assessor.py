"""
Threat assessment engine.
Consolidates findings, deduplicates, assigns priority scores,
and classifies what should be auto-remediated vs human-reviewed.
"""

SEVERITY_SCORE = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# These finding types can be auto-remediated safely
AUTO_REMEDIATE_TYPES = {
    "brute_force_ssh",       # Block IP via ufw
    "suspicious_process",    # Kill process + alert
}

# These always require human review
HUMAN_REVIEW_TYPES = {
    "new_sudo_user",
    "ssh_login_external_ip",
    "arp_spoofing_indicator",
    "dangerous_sudo_command",
}


def assess(all_findings):
    """
    Takes combined findings list, returns:
    - prioritized_findings: sorted by severity
    - auto_remediate: findings that can be auto-fixed
    - notify_only: findings requiring human review
    - summary: dict with counts per severity
    """
    seen = set()
    unique_findings = []

    for f in all_findings:
        # Deduplicate by type + key field
        key = f"{f.get('type')}:{f.get('ip', f.get('port', f.get('user', f.get('file', ''))))}"
        if key not in seen:
            seen.add(key)
            # Add priority score
            f['score'] = SEVERITY_SCORE.get(f.get('severity', 'LOW'), 1)
            unique_findings.append(f)

    # Sort by score descending
    prioritized = sorted(unique_findings, key=lambda x: x['score'], reverse=True)

    auto_remediate = []
    notify_only = []

    for f in prioritized:
        ftype = f.get('type', '')
        severity = f.get('severity', 'LOW')

        if ftype in AUTO_REMEDIATE_TYPES or f.get('auto_remediate'):
            auto_remediate.append(f)
        elif ftype in HUMAN_REVIEW_TYPES or severity in ('CRITICAL', 'HIGH'):
            notify_only.append(f)
        else:
            notify_only.append(f)

    summary = {
        "total": len(prioritized),
        "CRITICAL": sum(1 for f in prioritized if f.get('severity') == 'CRITICAL'),
        "HIGH": sum(1 for f in prioritized if f.get('severity') == 'HIGH'),
        "MEDIUM": sum(1 for f in prioritized if f.get('severity') == 'MEDIUM'),
        "LOW": sum(1 for f in prioritized if f.get('severity') == 'LOW'),
        "auto_remediate_count": len(auto_remediate),
    }

    return prioritized, auto_remediate, notify_only, summary
