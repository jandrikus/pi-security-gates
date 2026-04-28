# pi-security-gates

Tiered permissions gate and project-boundary security gate extensions for the [Pi coding agent harness](https://pi.dev).

## What it does

Two companion extensions that let you control **what** the agent can do and **where** it can do it:

### Permissions Gate (`--permissions-gate=<level>`)

Four tiers of restriction:

| Tier | Behavior |
|------|----------|
| `open` | No restrictions, but force-flags (`-f`, `--force`) still require confirmation |
| `standard` | Confirms dangerous operations: `rm -rf`, `sudo`, `chmod 777`, destructive git, piped curl-to-shell, system path writes |
| `strict` | Confirms every `write`, `edit`, and non-read-only `bash` command |
| `read-only` | Blocks all file mutations. Bash restricted to a read-only command allowlist |

**Force-flag override:** Regardless of tier, any `-f`, `--force`, `-rf`, `-fr` flag triggers a confirmation. Always on (configurable).

### Security Gate (`--security-gate`)

Blocks file modifications **outside the project directory**:

- Intercepts `write`, `edit`, and file-mutating `bash` commands
- Scans for redirects (`>`, `>>`), `mv`, `cp`, `ln`, `mkdir`, `touch`, `sed -i`, `dd`
- Symlink resolution to prevent escape attacks
- Protected internal paths (`.env`, `*.pem`, `*/.git/*`)
- Pre-approved external paths (`/tmp`, `/var/tmp`, `~/.cache`, `/dev/null`)

### Persistent Memory

When you approve or deny an operation, you can choose **"and remember"** — stored to `.pi/*-memory.json` in the project root. Survives `/new`, `/reload`, and fresh launches.

## Defaults — what happens when you just type `pi`

After installing, both extensions auto-load on every `pi` launch. Here's what you get **without any flags**:

| Extension | Default | What it does |
|-----------|---------|-------------|
| **Permissions Gate** | `standard` tier, active | Confirms dangerous operations before they run. You'll see a dialog for `rm -rf`, `sudo`, `chmod 777`, destructive git, piped curl-to-shell, and writes to system paths (`/etc`, `/usr`, etc.). Regular file edits and safe commands pass through freely. |
| **Security Gate** | **inactive** (off) | Requires `--security-gate` flag or `enabled: true` in `.pi/security-gate.json` to activate. When off, the agent can write anywhere. |
| **Force-flag check** | Active | Even at `open` tier, any `-f`/`--force`/`-rf` flag triggers a confirmation dialog. You can disable this per-project via `forceFlagRequiresConfirm: false` in config. |
| **Memory** | Active | Approvals and denials you "remember" persist to `.pi/` and survive restarts. |

### Quick-start: what you'll see

```bash
pi                          # Permissions gate at standard tier, security gate off
                            # Agent blocked from rm -rf, sudo, etc.
                            # File writes allowed normally

pi --security-gate          # Standard permissions + boundary protection
                            # Agent can't write outside the project

pi --permissions-gate=open  # No restrictions except force-flag checks
                            # Security gate still off

pi --no-permissions-gate    # Permissions gate disabled entirely
                            # (security gate loads but stays off by default)
```

## Install

```bash
pi install npm:pi-security-gates
# or from GitHub
pi install git:github.com/<user>/pi-security-gates
```

## Usage

```bash
# Launch with both gates
pi --permissions-gate=standard --security-gate

# Disable permissions gate, keep security
pi --no-permissions-gate --security-gate

# Disable both
pi --no-permissions-gate --no-security-gate
```

## Commands

### Permissions Gate

| Command | Action |
|---------|--------|
| `/permissions` | Show current level, config, memory stats |
| `/permissions set <level>` | Change tier (`open`/`standard`/`strict`/`read-only`) |
| `/permissions memory` | List remembered approvals/denials |
| `/permissions forget <index>` | Remove a remembered entry |
| `/permissions clear-memory` | Reset all memory |

### Security Gate

| Command | Action |
|---------|--------|
| `/security` | Show config, project root, allowlists |
| `/security toggle` | Enable/disable at runtime |
| `/security memory` | List remembered external paths |
| `/security forget <index>` | Remove a remembered entry |
| `/security clear-memory` | Reset all memory |

## Configuration

Optional per-project config files:

**.pi/permissions-gate.json:**
```json
{
  "version": 1,
  "level": "standard",
  "alwaysAllow": ["npm test"],
  "alwaysDeny": ["rm -rf <root>"],
  "forceFlagRequiresConfirm": true,
  "forceFlagExceptions": [],
  "requireConfirmationFor": ["git push --force <ref> <ref>"],
  "memoryEnabled": true
}
```

**.pi/security-gate.json:**
```json
{
  "version": 1,
  "enabled": true,
  "allowWriteOutside": ["/tmp", "/var/tmp", "~/.cache", "/dev/null"],
  "denyWriteInside": [".env", "*.pem", "*/.git/*", "secrets.*"],
  "interactiveConfirmOutside": true,
  "checkSymlinks": true,
  "memoryEnabled": true
}
```

Global fallbacks at `~/.pi/agent/extensions/permissions-gate.json` and `~/.pi/agent/extensions/security-gate.json`.

## License

Apache-2.0
