# macdog

macOS security and privacy suite — audit your security posture, manage firewall rules, review privacy permissions, and harden your system.

## Install

### Homebrew

```bash
brew install lu-zhengda/tap/macdog
```

### From Source

```bash
go install github.com/zhengda-lu/macdog@latest
```

### Binary

Download from [Releases](https://github.com/lu-zhengda/macdog/releases).

## Quick Start

```bash
# Launch the interactive TUI dashboard
macdog

# Run a security audit
macdog audit

# Check firewall status
macdog firewall

# Apply hardening recommendations (dry-run first)
macdog harden --dry-run
```

## Commands

| Command | Description |
|---------|-------------|
| `macdog` | Launch interactive TUI dashboard |
| `macdog audit` | Full security audit with letter grade (A-F) |
| `macdog firewall` | Show firewall status and application rules |
| `macdog firewall enable` | Enable the application firewall (sudo) |
| `macdog firewall disable` | Disable the application firewall (sudo) |
| `macdog firewall allow <path>` | Allow an app through the firewall (sudo) |
| `macdog firewall block <path>` | Block an app in the firewall (sudo) |
| `macdog privacy` | List TCC privacy permissions |
| `macdog privacy revoke <service> <bundle-id>` | Revoke a TCC permission |
| `macdog login` | List login items and launch agents |
| `macdog login remove <name>` | Remove a login item or disable a launch agent |
| `macdog harden` | Apply security hardening preset |
| `macdog harden --dry-run` | Preview hardening changes without applying |
| `macdog version` | Show version |

## TUI Dashboard

Launch `macdog` without arguments to open the interactive dashboard:

- **Audit tab**: Security grade (A-F) with big ASCII art letter, check status for SIP, Firewall, FileVault, Gatekeeper, and Remote Login
- **Firewall tab**: Firewall state, stealth mode, block-all, and application rules
- **Privacy tab**: TCC permissions (Camera, Microphone, Contacts, etc.) per app
- **Login Items tab**: Login items and launch agents with their type
- **Harden tab**: Recommended hardening actions with current vs. desired state

### Keys

| Key | Action |
|-----|--------|
| `Tab` / `l` | Next tab |
| `Shift+Tab` / `h` | Previous tab |
| `j` / `Down` | Move cursor down |
| `k` / `Up` | Move cursor up |
| `Enter` | Apply action (Harden tab) |
| `q` | Quit |

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

## Notes

- Firewall enable/disable and hardening actions require `sudo`
- Reading TCC permissions requires Full Disk Access for Terminal
- Some checks may show "unknown" in sandboxed or restricted environments

## License

MIT
