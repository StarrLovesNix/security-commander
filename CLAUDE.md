# Security Commander — Claude Session Memory

This file helps Claude Code orient quickly in new sessions. Read it before making any changes.

---

## What this project is

A daily security scanner for **Linux and Windows 10/11**. It scans the local machine and LAN, auto-remediates low-risk threats (IP blocking, process killing, file permission repair), sends HTML email alerts, and suppresses recurring findings via cooldowns. Zero third-party Python dependencies — stdlib only.

---

## Critical constraints (never violate these)

1. **No third-party Python packages.** stdlib only. This is intentional for security and portability. The dev dependencies in `pyproject.toml` (`pytest`, `mypy`) are never imported by the application itself.
2. **No `shell=True` in subprocess calls.** All system commands use argument lists.
3. **Validate IPs before use.** Call `platform_adapter.validate_ip(ip)` before passing any network-derived value to a system command. This prevents injection.
4. **All platform-specific code belongs in `modules/platform_adapter.py` only.** Every other module calls through it. Exception: `local_scanner.py` and `log_analyzer.py` contain Windows branches for functions whose entire logic is platform-specific (user enumeration, Event Log parsing).

---

## Architecture

```
security_commander.py          Orchestrator: loads config, acquires lock,
                               calls all 3 scanners, assesses, remediates, notifies.
                               Cross-platform: _is_admin() via ctypes on Windows,
                               os.geteuid() on Linux/macOS. Lock file uses
                               tempfile.gettempdir() (not hardcoded /tmp).

modules/
  platform_adapter.py          THE OS abstraction layer. Contains every
                               platform-specific subprocess call. Adding a new
                               platform means only editing this file (plus Windows
                               branches in local_scanner.py and log_analyzer.py).

  local_scanner.py             Open ports, processes, users, SSH keys, SUID files,
                               cron/scheduled jobs, world-writable files.
                               Has Windows branches for all Unix-specific functions.

  network_scanner.py           LAN discovery and port scanning via nmap.
                               Uses platform_adapter.get_local_network_cidr().
                               FileNotFoundError shows platform-specific install
                               instructions (apt/dnf/pacman on Linux; nmap.org on
                               Windows). Detects missing Npcap via stderr check.

  log_analyzer.py              Linux: regex on /var/log/auth.log-style files.
                               Windows: wevtutil XML → Event IDs 4625/4624/4720/
                               4728/4732/4688/6008. Dispatches based on SYSTEM.

  threat_assessor.py           Pure Python. Deduplicates findings, assigns severity
                               scores, identifies auto-remediable items.

  remediator.py                Calls platform_adapter block_ip / kill_process /
                               fix_file_permissions. No platform logic here.

  notifier.py                  HTML email via Gmail SMTP. No platform logic here.

  alert_history.py             JSON-based cross-scan deduplication and cooldowns.
                               Pure Python. No platform logic here.
```

### Finding lifecycle

```
Scanners → threat_assessor → alert_history → remediator → notifier
```

Each scanner returns `(findings: list[dict], snapshot: dict)`. Snapshot is diffed against `data/baseline.json` to detect changes.

---

## Platform support status

| Platform | Status |
|---|---|
| Debian/Ubuntu/Mint/RHEL/Fedora/Arch | Full |
| macOS | Partial (no firewall remediation — pfctl not implemented) |
| Windows 10/11 | Full |

### Windows tool mapping

| Linux tool | Windows equivalent | Function |
|---|---|---|
| `ps aux` | PowerShell `Get-Process` | `list_processes_raw()` |
| `ss -tulpn` | `netstat -ano` + `tasklist` | `list_open_ports()` |
| `ip addr show` | `ipconfig /all` | `get_local_network_cidr()` |
| `/var/log/auth.log` | `wevtutil qe Security` (XML) | `get_auth_log_paths()` → sentinel |
| `ufw` / `firewalld` | `netsh advfirewall` | `block_ip()` |
| `kill -9` | `taskkill /PID /F` | `kill_process()` |
| `chmod o-w` | `icacls /inheritance:r` | `fix_file_permissions()` |
| systemd timer | `schtasks /create /ru SYSTEM` | `get_available_schedulers()` |
| `/etc/passwd` | `net user` | `get_user_accounts()` |
| `getent group sudo` | `net localgroup Administrators` | `get_sudo_users()` |
| `/var/log/auth.log` regex | Event IDs 4625/4624/etc. | `analyze_windows_event_log()` |
| nmap (apt) | nmap.org + Npcap | `_run_nmap()` |

### Windows Event Log sentinel pattern

`get_auth_log_paths()` returns `['WinEvent:Security', 'WinEvent:System']` on Windows.
`read_recent_log_lines(path)` detects paths starting with `'WinEvent:'` and routes to
`_read_windows_event_log(channel, hours)` instead of opening a file.
`analyze_logs(config)` dispatches entirely to `analyze_windows_event_log(config)` on Windows.

---

## Key files to read first when resuming

1. `modules/platform_adapter.py` — understand what each function returns before touching anything
2. `modules/log_analyzer.py` — Windows path is `analyze_windows_event_log()`; Linux path uses regex
3. `modules/local_scanner.py` — every Unix-specific function has a Windows branch at the top
4. `security_commander.py` — start at `_is_admin()` and `acquire_lock()` for cross-platform concerns
5. `modules/network_scanner.py` — `_run_nmap()` has platform-aware error handling and Npcap detection

---

## Running tests

```bash
# Linux / macOS
python3 -m unittest discover -s tests -p "test_*.py" -v

# Windows
python -m unittest discover -s tests -p "test_*.py" -v

# Single module (Linux example)
python3 -m unittest tests.test_platform_adapter -v

# Syntax check all modules
python3 -m py_compile modules/*.py security_commander.py setup.py
```

106 tests total. All pass on Linux. Tests use only `unittest` + `unittest.mock` (stdlib).
Windows code paths are fully tested via mocking — no Windows machine required for the test suite.
GitHub Actions runs the full matrix (Python 3.10/3.11/3.12 × Ubuntu + Windows) on every push.

---

## Current branch and PR status

**Branch:** `claude/security-commander-windows-2FdBx`

**PR:** Open against `master` — not yet merged.
PR URL: `https://github.com/StarrLovesNix/security-commander/pull/new/claude/security-commander-windows-2FdBx`

**Commit history on this branch (newest first):**
```
be0fd8d  Pre-release polish: nmap Windows guidance, SECURITY.md, directory scaffolding
54e5b0a  Add documentation, CLAUDE.md session memory, and CI workflow
5aec3af  Add comprehensive test suite (106 tests, stdlib unittest)
9e826cc  Add full Windows 10/11 support to Security Commander
623e0b3  Initial release — Security Commander v1.0.0  ← master HEAD
```

### Windows testing checklist (pending — to be verified before merging PR)

- [ ] `setup_windows.bat` → UAC elevation works, wizard completes, Task Scheduler task (`SecurityCommander`) created
- [ ] `python security_commander.py --baseline --no-email --verbose` → full scan completes, `reports/` populated
- [ ] Second scan → baseline diff detection works (new findings vs baseline)
- [ ] `python security_commander.py --acknowledge` → interactive suppress works
- [ ] `wevtutil qe Security` returns events (requires running as Administrator)
- [ ] GitHub Actions CI passes on `windows-latest` runners (automatic on push)

---

## Config file

`config.json` is gitignored (contains Gmail App Password). Copy from `config.json.example` or run `setup.py` / `setup_windows.bat`. Minimum required fields: `email.sender`, `email.app_password`.

---

## Data files (auto-generated, gitignored)

- `data/baseline.json` — snapshot of system state from the last baseline scan. If missing, the next scan creates it automatically (first run).
- `data/alert_history.json` — cross-scan finding deduplication and cooldown state.
- `reports/` — HTML scan reports written after each scan.
- `data/.gitkeep` and `reports/.gitkeep` are tracked so both directories exist after a fresh clone.

---

## Common development tasks

### Add a new scanner check
1. Add detection logic to the appropriate scanner (`local_scanner.py`, `network_scanner.py`, or `log_analyzer.py`)
2. Return a finding dict: `{"type": str, "severity": str, "detail": str, ...}`
3. If it needs OS-specific calls, add them to `platform_adapter.py`
4. If it should be auto-remediable, mark it `"auto_remediate": True` and handle it in `remediator.py`
5. Add tests to `tests/test_<module>.py`

### Add a new platform
1. Add `elif SYSTEM == 'YourOS':` branches to every function in `platform_adapter.py`
2. Add platform branches to the Unix-specific functions in `local_scanner.py`
3. Add log parsing for the new platform in `log_analyzer.py`
4. Update `get_available_schedulers()` with the new scheduler
5. Update `setup.py` with the new installer
6. Update `pyproject.toml` classifiers
7. Update `README.md` platform support table
8. Update this file

### Severity levels
`CRITICAL` → `HIGH` → `MEDIUM` → `LOW`

Auto-remediation only runs on findings with `"auto_remediate": True`. HIGH findings with `remediation.require_approval_for_high = true` (default) are not auto-remediated.

---

## Known limitations / future work

- **macOS firewall** (`pfctl`) not implemented — `block_ip()` raises `NotImplementedError` for macOS. Medium priority.
- **Windows Event Log 4688** (process creation) requires enabling "Audit Process Creation" in Local Security Policy; not on by default. The scanner handles missing events gracefully (no crash, just no process findings from Event Log).
- **IPv6 support** — `validate_ip()` only handles IPv4. IPv6 addresses from Event Log are stripped of their `::ffff:` prefix before use.
- **nmap Npcap on Windows** — Npcap is required for raw-packet scans (ARP spoofing detection, SYN scans). The scanner now detects and warns when Npcap is missing. Ping-based host discovery (`-sn`) works without Npcap.
