# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (current) | Yes |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you find a vulnerability in Security Commander — particularly anything that could allow privilege escalation, command injection, or credential exposure — please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/StarrLovesNix/security-commander/security/advisories/new) (preferred — keeps the report private until patched)
2. Or email the maintainer directly via the contact on the GitHub profile

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce
- Any suggested mitigations or patches

You can expect an acknowledgement within **48 hours** and a resolution or status update within **7 days**.

## Security design notes

These are intentional design decisions — not vulnerabilities:

- **`config.json` contains credentials** (Gmail App Password). It is gitignored. Never commit it.
- **Root / Administrator access is required** for full functionality (firewall rules, process killing, auth log access). The tool degrades gracefully without elevated privileges.
- **Auto-remediation is conservative by default.** IP blocking and process termination only trigger on findings that explicitly set `"auto_remediate": True`. HIGH-severity findings additionally require `remediation.require_approval_for_high = false` to auto-remediate (default: true = requires approval).
- **All `subprocess` calls use argument lists**, never `shell=True`. Network-derived values (IPs) are validated through `platform_adapter.validate_ip()` before use in any system command.
