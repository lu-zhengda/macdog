# macdog

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-lightgrey.svg)](https://github.com/lu-zhengda/macdog)
[![Homebrew](https://img.shields.io/badge/Homebrew-lu--zhengda/tap-orange.svg)](https://github.com/lu-zhengda/homebrew-tap)

macOS security & privacy suite — audit your security posture, manage firewall rules, review privacy permissions, and harden your system.

## Install

```bash
brew tap lu-zhengda/tap
brew install macdog
```

## Usage

```
$ macdog audit
Security Grade: B (75/100)

CHECK                        STATUS
-----                        ------
System Integrity Protection  enabled
Firewall                     off
FileVault                    on
Gatekeeper                   enabled
Remote Login                 off
```

## Commands

| Command | Description |
|---------|-------------|
| `status` | **Concise overall security status summary** (exit 0/1/2) |
| `audit` | Full security audit with letter grade (A-F) |
| `firewall` | Show firewall status and application rules |
| `firewall enable` | Enable the application firewall (sudo) |
| `firewall disable` | Disable the application firewall (sudo) |
| `firewall allow <path>` | Allow an app through the firewall (sudo) |
| `firewall block <path>` | Block an app in the firewall (sudo) |
| `privacy` | List TCC privacy permissions |
| `privacy revoke <service> <bundle-id>` | Revoke a TCC permission |
| `login` | List login items and launch agents |
| `login remove <name>` | Remove a login item or disable a launch agent |
| `harden` | Apply security hardening preset |
| `harden --dry-run` | Preview hardening changes without applying |

## Status Command

`macdog status` gives you a fast, read-only overview of your security posture without running slow operations like event-log scanning.

```
$ macdog status

Security Status: WARNING   Grade B (75/100)

DOMAIN        STATUS  DETAIL
------        ------  ------
SIP           on      enabled
Firewall      off     off, 3 rules
FileVault     on      on
Gatekeeper    on      enabled
Remote Login  off     off
Login Items   OK      12 items
Privacy       OK      47 granted, 3 denied (50 total)

Generated: 2026-02-18T08:30:00Z
```

```bash
# Machine-readable JSON (ideal for CI / AI agents)
macdog status --json
```

```json
{
  "overall": "warning",
  "score": 75,
  "grade": "B",
  "generated_at": "2026-02-18T08:30:00Z",
  "audit": {
    "sip": "enabled",
    "firewall": "off",
    "file_vault": "on",
    "gatekeeper": "enabled",
    "remote_login": "off",
    "score": 75,
    "grade": "B"
  },
  "firewall": { "enabled": false, "stealth_mode": false, "block_all": false, "rule_count": 3 },
  "login_items": { "count": 12 },
  "privacy": { "granted": 47, "denied": 3, "total": 50 }
}
```

### Status Exit Codes

| Code | Overall | Meaning |
|------|---------|---------|
| `0` | `ok` | Score ≥ 90 — all checks passing |
| `1` | `warning` | Score 60–89 — one or more checks failing |
| `2` | `critical` | Score < 60 — multiple critical checks failing |

> **Privacy note:** The `privacy` field requires Full Disk Access for Terminal. If unavailable, the field includes an `"error"` key and counts are 0.

## Security Audit Scoring

| Check | Points |
|-------|--------|
| SIP enabled | 25 |
| Firewall on | 25 |
| FileVault on | 25 |
| Gatekeeper enabled | 15 |
| Remote Login off | 10 |

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 75-89 |
| C | 60-74 |
| D | 40-59 |
| F | 0-39 |

## TUI Dashboard

Launch `macdog` without arguments to open the interactive dashboard:

- **Audit tab** — Security grade with check status for SIP, Firewall, FileVault, Gatekeeper, and Remote Login
- **Firewall tab** — Firewall state, stealth mode, block-all, and application rules
- **Privacy tab** — TCC permissions (Camera, Microphone, Contacts, etc.) per app
- **Login Items tab** — Login items and launch agents with their type
- **Harden tab** — Recommended hardening actions with current vs. desired state

| Key | Action |
|-----|--------|
| `Tab` / `l` | Next tab |
| `Shift+Tab` / `h` | Previous tab |
| `j` / `k` | Navigate up/down |
| `Enter` | Apply action (Harden tab) |
| `q` | Quit |

## Notes

- Firewall enable/disable and hardening actions require `sudo`
- Reading TCC permissions requires Full Disk Access for Terminal
- Some checks may show "unknown" in sandboxed or restricted environments

## Claude Code

Available as a skill in the [macos-toolkit](https://github.com/lu-zhengda/macos-toolkit) Claude Code plugin.

## License

[MIT](LICENSE)
