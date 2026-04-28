# Permissions Gate & Security Gate Extensions — Design Spec

**Date:** 2026-04-28
**Status:** Draft

## 1. Overview

Two companion Pi extensions providing tiered permission control and project-boundary
protection for the Pi coding agent harness. Both are configurable via JSON files,
togglable via CLI flags, and controllable interactively via commands.

## 2. Permissions Gate

### 2.1 Permission Tiers

| Level | Name | Behavior |
|-------|------|----------|
| `open` (0) | No restrictions | Gate loaded but does nothing except the force-flag override |
| `standard` (1) | Confirm dangerous operations | Prompts on operations matching danger criteria in Section 2.3 |
| `strict` (2) | Confirm all mutations | Standard + confirm every `write`, `edit`, and non-read-only `bash` |
| `read-only` (3) | No modifications | Blocks all `write`, `edit`. Bash restricted to read-only allowlist (Section 2.3) |

### 2.2 Force-Flag Override

The force-flag check is always active when the permissions gate is loaded
(`--permissions-gate=<any>`). It can be disabled by setting
`forceFlagRequiresConfirm: false` in config. When enabled, two regex checks
run on every bash command fingerprint:

**Check 1 — Long form:** `--force` or any `--force-*` like `--force-with-lease`.
Regex: `/--force\b/`.

**Check 2 — Short form:** Single-dash flags containing `f` with destructive
semantics. Regex: `/(?:\s|^)-[a-zA-Z]*f[a-zA-Z]*\b/`.

Together they catch: `-f`, `--force`, `-rf`, `-rm`, `-fr`,
`--force-with-lease`, `--force-create`.

**`forceFlagExceptions`** lists fingerprints of commands that match the force-flag
regexes but are harmless. Examples:
- `npm run build -- -f` — the `-f` here is not a force flag, the `--` separator
causes the parsed fingerprint to include the `-f` token. Adding this fingerprint
to exceptions means `npm run build -- -f` won't trigger the force-flag dialog.

### 2.3 Command Classification for Standard Tier

The standard tier uses a concrete, algorithmic classification. A command is
**dangerous** (triggers confirmation) if ANY of these rules match:

**Rule A — Destructive base commands:**
The base command is one of: `rm`, `sudo`, `chmod`, `chown`, `chgrp`, `dd`,
`mkfs`, `fdisk`, `parted`, `shred`, `wipe`, `kill`, `killall`, `pkill`,
`reboot`, `shutdown`, `halt`, `poweroff`, `init`, `systemctl` (stop/disable/mask),
`iptables`, `ip6tables`, `nft`, `ufw`, `firewall-cmd`.

**Rule B — Destructive git subcommands:**
Base command is `git` AND subcommand matches `reset`, `clean`, `rebase`, `push`,
`filter-branch`, `gc`, `prune` AND the fingerprint contains a force-flag or a
flag like `--hard`, `--mixed`.

**Rule C — Recursive deletion:**
The fingerprint matches `/rm\b.*\b-r/` (rm with `-r`, `-rf`, `--recursive`).

**Rule D — Permission escalation:**
The fingerprint contains `sudo`, `su -`, `doas`.

**Rule E — Permission-wide-open:**
The fingerprint matches `/chmod\b.*\b777\b/` or `/chmod\b.*\b0777\b/`.

**Rule F — Piped installation:**
Command body contains `curl` or `wget` AND is piped (`|`) to `sh`, `bash`,
`python`, `perl`, `ruby`.

**Rule G — System paths target:**
The fingerprint or any extracted path resolves to an absolute path under `/etc`,
`/usr`, `/boot`, `/lib`, `/bin`, `/sbin`, `/opt`, `/var`, `/root`, `/home` (but
excluding `/home/<current-user>` and project-relative paths).

**Rule H — Config override:** The fingerprint matches any entry in
`requireConfirmationFor`.

**All other commands:** Treated as safe at standard tier.

### 2.4 Read-Only Bash Allowlist

At `read-only` tier, only these base commands are allowed:
`cat`, `ls`, `find`, `grep`, `rg`, `head`, `tail`, `wc`, `du`, `df`, `file`,
`stat`, `sort`, `uniq`, `cut`, `tr`, `awk`, `echo`, `printf`, `which`, `type`,
`whereis`, `diff`, `cmp`, `comm`, `man`, `info`, `hl`, `git log`, `git diff`,
`git show`, `git status`, `git branch`, `git tag`, `git remote`, `git blame`,
`git grep`, `cargo check`, `npm ls`, `npm test`, `npm run lint`, `npm run typecheck`,
`node --version`, `python --version`, `rustc --version`, `go version`,
`npx --version`, `cargo --version`, `pip list`, `pip show`, `gem list`,
`ps`, `pwd`, `env`, `printenv`, `uname`, `hostname`, `uptime`, `free`.

Commands with pipes are allowed only if BOTH sides of the pipe are allowlisted.

### 2.5 Command Fingerprinting

Before any classification or matching, bash commands are normalized to fingerprints:

1. Strip leading path from the base command (e.g., `/usr/bin/git` → `git`)
2. Replace path-like arguments (those that start with `.`, `/`, `~` or look like
   a file path) with `<path>` placeholder — **except** the literal filesystem
   root `/` which becomes `<root>` to distinguish it from other absolute paths
3. Replace branch/tag/ref-like arguments (git refs, commit hashes) with `<ref>` placeholder
4. Replace numeric arguments with `<num>` placeholder
5. Normalize whitespace to single spaces, trim
6. Preserve `--separator` boundaries

Examples:
- `rm -rf ./build/` → `rm -rf <path>`
- `rm -rf /` → `rm -rf <root>` (the literal filesystem root is preserved)
- `rm -rf /tmp/cache` → `rm -rf <path>`
- `git push --force origin main` → `git push --force <ref> <ref>`
- `mkdir -p /tmp/foo/bar` → `mkdir -p <path>`
- `npm run build -- --force --output dist` → `npm run build -- --force --output <path>`
- `sudo systemctl stop nginx` → `sudo systemctl stop <ref>`

### 2.6 Session Memory (Disk-Persisted)

Stored at `.pi/permissions-gate-memory.json` in the project root. Survives `/new`,
`/reload`, and fresh pi launches.

**Memory file format:**
```json
{
  "version": 1,
  "approvals": [
    { "fingerprint": "rm -rf <path>", "original": "rm -rf ./build/", "approvedAt": 1714320000000 },
    { "fingerprint": "git push --force <ref> <ref>", "original": "git push --force origin main", "approvedAt": 1714320100000 }
  ],
  "denials": [
    { "fingerprint": "rm -rf <path>", "original": "rm -rf /", "deniedAt": 1714320000000 }
  ]
}
```

**Confirmation dialog (4 options):**
1. **Yes, this once** — allow; ask again next time
2. **Yes, and remember** — allow; write fingerprint to memory; auto-allow matching ops
3. **No, this once** — block; ask again next time
4. **No, and always deny** — block; write to memory; auto-block matching ops

### 2.7 Configuration

`.pi/permissions-gate.json` (project) or `~/.pi/agent/extensions/permissions-gate.json` (global):

```json
{
  "version": 1,
  "level": "standard",
  "alwaysAllow": ["npm test"],
  "alwaysDeny": ["rm -rf <root>" /* blocks rm -rf of the filesystem root */],
  "forceFlagRequiresConfirm": true,
  "forceFlagExceptions": ["npm run build -- -f"],
  "requireConfirmationFor": [
    "git push --force <ref> <ref>",
    "git reset --hard <ref>"
  ],
  "memoryEnabled": true
}
```

All pattern fields use fingerprint format. Project config overrides global;
CLI flags override both.

**Array merging:** When both global and project config define array fields
(`alwaysAllow`, `alwaysDeny`, etc.), the project array **replaces** the global
array entirely (not unioned). Use global for org-wide defaults and project
for site-specific overrides.

### 2.8 CLI Flags & Commands

| Interface | Description |
|-----------|-------------|
| `--permissions-gate=<level>` | Set tier on launch |
| `--no-permissions-gate` | Disable entirely (extension not loaded) |
| `/permissions` | Show current level, config, memory stats |
| `/permissions-set <level>` | Change tier interactively |
| `/permissions memory` | List all remembered entries |
| `/permissions forget <index>` | Remove a remembered entry |
| `/permissions clear-memory` | Reset all memory |

## 3. Security Gate

### 3.1 Project Boundary Enforcement

Records the cwd at session start as the project root. Blocks any tool operation that
would write to or modify files outside this boundary.

**Intercepted tools:**
- `write` — resolve target path → block if outside project root
- `edit` — resolve target path → block if outside project root
- `bash` — scan command for file-mutating operations and resolve paths → block if
  target falls outside project root

**Allowed without restriction:**
- `read`, `grep`, `find`, `ls` — these are read-only and can access anywhere

### 3.2 Bash Command Classification

Commands are classified into two categories:

**Known-safe** (no path scanning needed — these don't modify files):
`cat`, `ls`, `find`, `grep`, `rg`, `head`, `tail`, `wc`, `du`, `df`, `file`,
`stat`, `sort`, `uniq`, `cut`, `tr`, `awk`, `echo`, `printf`, `which`, `type`,
`whereis`, `ps`, `top`, `htop`, `free`, `uptime`, `uname`, `hostname`, `pwd`,
`env`, `printenv`, `git log`, `git diff`, `git show`, `git status`, `git branch`,
`git tag`, `git remote`, `git blame`, `git grep`, `diff`, `cmp`, `comm`,
`cargo check`, `npm ls`, `node --version`, `python --version`, `rustc --version`,
`go version`, `npx --version`, `cargo --version`, `pip list`, `pip show`,
`gem list`, `man`, `info`.

**In-place editors are NOT on the safe list.** `sed`, `perl`, and `ruby`
are classified as potentially-mutating (they can modify files in-place with
`-i`). `awk` IS on the safe list — it has no `-i` flag. The redirect scanner
catches `sed 's/x/y/' file > file`, and the base-command classification
catches `sed -i /etc/hosts`.

**Potentially mutating** (everything else): Path-scanned for targets outside
the boundary.

### 3.3 Bash Path Extraction Strategy

A best-effort regex-based extractor with documented limitations. Three extraction
methods applied in order:

**Method 1 — Explicit operators:** Extract paths after `>`, `>>`, `>&`, `2>`,
`1>&2`, etc. Also extract dest paths from `mv <src> <dest>`, `cp [-r] <...srcs> <dest>`,
`ln [-s] <src> <dest>`, `install <src> <dest>`, `mkdir [-p] <path>`,
`touch <path...>`, `tee <path...>`, `dd ... of=<path>`.

Path extraction uses a simple state machine per operator type. Patterns:
- Redirect: `>FILENAME` or `>>FILENAME` (capture after `>`)
- mv: last non-flag argument is dest
- cp: last non-flag argument is dest
- ln: last non-flag argument is dest
- install: last non-flag argument is dest
- mkdir/touch/tee: all non-flag arguments are targets

**Method 2 — Trailing positional arguments:** For commands not matching known
operators, treat the last positional argument as a potential file destination
(e.g., `some-tool --output /tmp/out`).

**Method 3 — Unknown command fallback:** If the base command is completely
unrecognized, block the entire command (conservative default).

**Potentially-mutating with no extracted paths:** If a command is classified
as potentially-mutating but the path extractor finds zero targets (e.g.,
`npm install -g`, or an all-flags invocation with no positional paths),
conservatively treat as unknown — block the command. This prevents
pathless mutations from leaking (e.g., a tool that writes to a default
system location without an explicit path argument).

**Known limitations (documented):**
- Shell loops (`for f in ...; do ... $f > /tmp/$f; done`) — the redirect
  parser catches the `>` but might misidentify `$f`. Paths with unresolved
  variables are conservatively blocked.
- `find ... -exec cp {} /tmp/ \;` — the `-exec` nested command is not analyzed.
  `find` is on the known-safe list, but with `-exec` it could mutate files.
  Users who use `find -exec` with external targets must add the path to
  `allowWriteOutside`.
- Pipes (`|`) — each side is classified independently. If either side is
  mutating, paths are extracted from that side.
- Process substitution `<()` creates FIFOs for reading — NOT checked.
  `>()` creates FIFOs for writing — ARE checked.

### 3.4 Protected Internal Paths

Even within the project root, certain paths can be marked as write-protected:
`.env`, `*.pem`, `*/.git/*`, `*.key`, `secrets.*`. Configured via `denyWriteInside`.
Glob matching uses `minimatch`-style patterns.

### 3.5 External Write Allowlist

Specific external paths can be pre-approved for writes: `/tmp`, `/var/tmp`,
`~/.cache`, `/dev/null` by default. Paths support tilde expansion. Configured
via `allowWriteOutside`.

### 3.6 Symlink Handling (`checkSymlinks`)

When `checkSymlinks: true` (default): before allowing a write to any path,
the path is resolved via `fs.realpathSync()` to its canonical location. If the
resolved canonical path falls outside the project root, the write is blocked
even though the apparent path was inside the project.

This prevents symlink-escape attacks like:
- `ln -s /etc/passwd ./safe-looking-file` → write to `./safe-looking-file` is blocked

When `checkSymlinks: false`: only the apparent path is checked. Faster but
less secure.

### 3.7 Session Memory (Disk-Persisted)

Stored at `.pi/security-gate-memory.json`. Survives `/new`, `/reload`, and fresh
pi launches.

**Memory file format:**
```json
{
  "version": 1,
  "allowedExternalPaths": [
    { "path": "/tmp/my-scripts", "approvedAt": 1714320000000 }
  ],
  "allowedExternalPatterns": [
    { "fingerprint": "cp <path...> <path>", "targetPattern": "/tmp/*", "approvedAt": 1714320100000 }
  ]
}
```

When a boundary violation is detected, user gets:
1. **Allow this once** — allow this specific operation
2. **Allow and remember path** — write external path to memory; auto-allow forever
3. **Block** — block the operation

### 3.8 Configuration

`.pi/security-gate.json` (project) or `~/.pi/agent/extensions/security-gate.json` (global):

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

### 3.9 CLI Flags & Commands

| Interface | Description |
|-----------|-------------|
| `--security-gate` | Enable security gate on launch |
| `--no-security-gate` | Disable entirely (extension not loaded) |
| `/security` | Show config, project root, recent blocks |
| `/security toggle` | Enable/disable at runtime |
| `/security memory` | List remembered external paths/patterns |
| `/security forget <index>` | Remove a remembered entry |
| `/security clear-memory` | Reset all memory |

## 4. Non-Interactive Mode Behavior

When `ctx.hasUI` is `false` (print mode, JSON mode, or RPC without UI protocol):

**Permissions Gate:**
| Tier | Non-interactive behavior |
|------|--------------------------|
| `open` | Force-flagged commands blocked (no UI to confirm). All other operations allowed. |
| `standard` | Force-flagged commands are blocked. Dangerous commands (per Section 2.3 rules) are blocked. All other operations allowed. |
| `strict` | All writes, edits, and non-read-only bash blocked. |
| `read-only` | All writes, edits, non-read-only bash blocked. |

In other words: standard tier blocks force-flagged **or** dangerous (union),
not only operations that are both.

**Security Gate:**
- All external writes blocked without prompting.
- If `interactiveConfirmOutside: false`, block silently.

**Memory override takes precedence:** In all non-interactive modes, remembered
approvals and denials from disk-based memory are evaluated **before** the tier
rules. If a fingerprint is in the approvals memory, it is allowed regardless of
tier. If it is in the denials memory, it is blocked regardless of tier. The tier
rules only apply to operations that have no memory entry.

This ensures that operations the user explicitly approved or denied in previous
interactive sessions are always respected, even when running unattended.

## 5. Performance Considerations

Both extensions add a processing pipeline to every `tool_call` for bash commands:
fingerprinting, classification, and path scanning. To minimize overhead:

- Fingerprinting and classification run on strings, not filesystem operations.
  Expected latency: <1ms per command.
- Path scanning runs on already-fingerprinted commands. Regex-based extraction
  is sub-ms for typical commands.
- `checkSymlinks` performs `realpathSync()` — this IS a filesystem call and may
  add 1-5ms per path. Disable if latency is a concern.
- Memory files are read once at session start and cached in memory. Writes are
  asynchronous.
- All classification is early-exit: the first blocking rule triggers the dialog
  immediately without running remaining rules.

Expected worst-case per-command overhead: ~10ms (with symlink checking), <1ms
(without). Acceptable for a local development tool.

## 6. Extension Interactions

Both extensions fire on the `tool_call` event. Pi's handler chain runs in
extension load order; the first handler to return `{ block: true }` blocks
the tool. Subsequent handlers still receive the event but cannot unblock.

**Intended load order:** permissions-gate first, security-gate second.
In practice, either order works correctly, but the error message shown to the
agent differs:
- Permissions-gate-first: if both would block, the agent sees the permissions
  refusal ("what" is blocked). The agent never sees the "where" refusal.
- Security-gate-first: the agent sees the boundary refusal ("where" is blocked).
  The agent never sees the "what" refusal.

Both orders are safe. Neither allows a blocked operation through. The
recommended order ensures the higher-level "what" gate answers first, with the
boundary gate as a second opinion.

## 7. Error Handling

**Corrupted config files:** If JSON fails to parse, log warning via
`console.error` and fall back to hardcoded defaults. Extension continues.
Default tier: `standard`. Default security: `enabled: false` (fail-safe).

**Corrupted memory files:** If `.pi/*-memory.json` fails to parse, log warning,
treat memory as empty. Do NOT silently allow previously-approved operations
from a corrupted file.

**File I/O failures:** If a memory/config file cannot be written (disk full,
permissions), show notification and continue. In-memory state for current
session remains valid; future sessions will not see the failed write.

**Concurrent sessions:** Two pi sessions writing memory simultaneously is a
known race condition. Mitigation: atomic write (write to temp file, rename).
Last writer wins. Acceptable for a local dev tool.

**Schema migration:** Memory and config files include a `version` field (default: 1).
If older format detected on read, migrate silently on write (write current format).
Unknown fields in config are ignored.

**Path resolution errors:** If `resolve()` or `realpathSync()` throws (ENOENT
for non-existent path), conservative: block writes to new files outside the
project root, allow writes to new files inside the project root.

**Tool call handler errors:** Errors thrown in `tool_call` handlers are caught
by Pi and block the tool (fail-safe). Wrap in try/catch for explicit messages.

## 8. Architecture: Unit Interfaces

### 8.1 Permissions Gate Pipeline

The permissions gate processes each `tool_call` event through this pipeline
(in `index.ts`):

```
1. tool_call event fires
2. If tool is `write`/`edit`: jump to Step 5 (tier check with tool name)
3. If tool is `bash`: fingerprint the command
4. Check memory: if fingerprint is approved → allow (skip tier rules)
   if fingerprint is denied → block
5. Tier check: isAllowedAtTier(fingerprint, tier, config)
   - `open`: force-flag check only (unless forceFlagRequiresConfirm: false)
   - `standard`: classifyBashCommand() → if dangerous, show dialog
   - `strict`: always show dialog for writes/edits/non-read-only bash
   - `read-only`: block writes/edits/non-read-only bash
6. If tier allows: allow, tool executes
7. If tier requires confirmation: show dialog →
   - Allow once: allow
   - Allow + remember: add to memory, allow
   - Deny once: block
   - Deny + remember: add to memory, block
```

Memory is checked before tier rules so that user-approved operations bypass
all tier restrictions.

**`config.ts`**
```typescript
export type PermissionLevel = "open" | "standard" | "strict" | "read-only";

export interface PermissionsConfig {
  version: number;
  level: PermissionLevel;
  alwaysAllow: string[];
  alwaysDeny: string[];
  forceFlagRequiresConfirm: boolean;
  forceFlagExceptions: string[];
  requireConfirmationFor: string[];
  memoryEnabled: boolean;
}

export const DEFAULT_CONFIG: PermissionsConfig;
export function loadConfig(cwd: string): PermissionsConfig;
export function mergeConfigs(base: PermissionsConfig, override: Partial<PermissionsConfig>): PermissionsConfig;
```

**`classifier.ts`**
```typescript
export type DangerLevel = "safe" | "force-flagged" | "dangerous";

export interface ClassificationResult {
  level: DangerLevel;
  fingerprint: string;
  reason?: string; // human-readable reason (e.g., "recursive deletion")
}

export function classifyBashCommand(command: string, cwd: string): ClassificationResult;
export function fingerprintCommand(command: string): string;
export function isAllowedAtTier(fingerprint: string, tier: PermissionLevel, config: PermissionsConfig): boolean;
export function isAlwaysAllowed(fingerprint: string, config: PermissionsConfig): boolean;
export function isAlwaysDenied(fingerprint: string, config: PermissionsConfig): boolean;
export function isReadOnlyAllowed(command: string): boolean;
```

**`memory.ts`**
```typescript
export interface MemoryEntry {
  fingerprint: string;
  original: string;
  approvedAt?: number; // present on approvals
  deniedAt?: number;   // present on denials
}

export interface PermissionsMemory {
  version: number;
  approvals: MemoryEntry[];
  denials: MemoryEntry[];
}

export function loadMemory(cwd: string): PermissionsMemory;
export function saveMemory(cwd: string, memory: PermissionsMemory): void;
export function isApprovedInMemory(fingerprint: string, memory: PermissionsMemory): boolean;
export function isDeniedInMemory(fingerprint: string, memory: PermissionsMemory): boolean;
export function addApproval(memory: PermissionsMemory, fingerprint: string, original: string): void;
export function addDenial(memory: PermissionsMemory, fingerprint: string, original: string): void;
export function forgetEntry(memory: PermissionsMemory, index: number): boolean;
export function clearMemory(memory: PermissionsMemory): void;
```

**`dialogs.ts`**
```typescript
export interface DialogResult {
  action: "allow-once" | "allow-remember" | "deny-once" | "deny-remember";
}

export async function confirmDangerous(
  ctx: ExtensionContext, command: string, fingerprint: string,
  memory: PermissionsMemory, memoryEnabled: boolean, reason: string
): Promise<DialogResult>;

export async function confirmForce(
  ctx: ExtensionContext, command: string, fingerprint: string,
  memory: PermissionsMemory, memoryEnabled: boolean
): Promise<DialogResult>;

export async function confirmMutation(
  ctx: ExtensionContext, toolName: string, target: string,
  fingerprint: string, memory: PermissionsMemory, memoryEnabled: boolean
): Promise<DialogResult>;
```

### 8.2 Security Gate

**`config.ts`**
```typescript
export interface SecurityConfig {
  version: number;
  enabled: boolean;
  allowWriteOutside: string[];
  denyWriteInside: string[];
  interactiveConfirmOutside: boolean;
  checkSymlinks: boolean;
  memoryEnabled: boolean;
}

export const DEFAULT_CONFIG: SecurityConfig;
export function loadConfig(cwd: string): SecurityConfig;
export function mergeConfigs(base: SecurityConfig, override: Partial<SecurityConfig>): SecurityConfig;
```

**`boundary.ts`**
```typescript
export function isInsideProject(path: string, projectRoot: string, checkSymlinks: boolean): boolean;
export function isDeniedInside(path: string, projectRoot: string, deniedGlobs: string[]): boolean;
export function isAllowedOutside(path: string, allowedPaths: string[], cwd: string): boolean;
export function resolveWriteTarget(rawPath: string, cwd: string): string;
```

**`command-scanner.ts`**
```typescript
export type CommandClassification = "safe" | "potentially-mutating";

export function classifyBaseCommand(command: string): CommandClassification;
export function extractTargetPaths(command: string, cwd: string): string[];
export function hasFileRedirects(command: string): boolean;
export function extractRedirectPaths(command: string, cwd: string): string[];
```

**`memory.ts`**
```typescript
export interface AllowedPath {
  path: string;
  approvedAt: number;
}

export interface AllowedPattern {
  fingerprint: string;
  targetPattern: string;
  approvedAt: number;
}

export interface SecurityMemory {
  version: number;
  allowedExternalPaths: AllowedPath[];
  allowedExternalPatterns: AllowedPattern[];
}

export function loadSecurityMemory(cwd: string): SecurityMemory;
export function saveSecurityMemory(cwd: string, memory: SecurityMemory): void;
export function isPathRemembered(path: string, memory: SecurityMemory): boolean;
export function addAllowedPath(memory: SecurityMemory, path: string): void;
export function addAllowedPattern(memory: SecurityMemory, fingerprint: string, targetPattern: string): void;
export function forgetEntry(memory: SecurityMemory, index: number, kind: "path" | "pattern"): boolean;
export function clearMemory(memory: SecurityMemory): void;
```

**`dialogs.ts`**
```typescript
export async function confirmBoundaryViolation(
  ctx: ExtensionContext, toolName: string, targetPath: string,
  projectRoot: string, memory: SecurityMemory, memoryEnabled: boolean
): Promise<{ action: "allow-once" | "allow-remember" | "block" }>;
```

## 9. File Structure

```
.pi/extensions/
├── permissions-gate/
│   ├── index.ts          # Entry point: registerFlag, registerCommand, tool_call handler
│   ├── config.ts         # Config loading/merging, PermissionsConfig type
│   ├── memory.ts         # Disk-backed memory persistence
│   ├── classifier.ts     # Command fingerprinting and danger classification
│   └── dialogs.ts        # Confirmation dialog logic
│
├── security-gate/
│   ├── index.ts          # Entry point: registerFlag, registerCommand, tool_call handler
│   ├── config.ts         # Config loading, SecurityConfig type
│   ├── boundary.ts       # Path resolution, boundary checking, symlink handling
│   ├── command-scanner.ts # Bash command classification and path extraction
│   ├── memory.ts         # Disk-backed memory persistence
│   └── dialogs.ts        # Boundary violation confirmation logic

# Config files (in .pi/, not .pi/extensions/ — user configuration, not extension code)
.pi/
├── permissions-gate.json          # Project config (optional)
├── permissions-gate-memory.json   # Persistent memory
├── security-gate.json             # Project config (optional)
└── security-gate-memory.json      # Persistent memory

# Global config fallback
~/.pi/agent/extensions/
├── permissions-gate.json          # Global config (fallback)
└── security-gate.json             # Global config (fallback)
```

## 10. Non-Goals

Explicitly out of scope:
- Process-level sandboxing (use the separate `sandbox/` extension)
- Network restriction (use the separate `sandbox/` extension)
- Container/VM isolation
- Audit logging to external systems
- Multi-user permission models
- Remote agent security (use SSH extension)
- Provider-level API key restriction

## 11. Status Display

Both extensions use `ctx.ui.setStatus()` to show current gate state in the
Pi footer:

- Permissions: `🔓 open` / `⚠️ standard` / `🔒 strict` / `🚫 read-only`
- Security: `🏠 boundary: active` / `🏠 boundary: off`
