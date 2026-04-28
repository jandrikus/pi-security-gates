# Permissions Gate & Security Gate Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two Pi extensions — a tiered permissions gate and a project-boundary security gate — with disk-persisted memory, CLI flags, and interactive commands.

**Architecture:** Two independent extension directories under `.pi/extensions/` with 10 focused TypeScript files total. Pure classification/boundary logic separated from disk I/O and UI dialogs. Memory files in `.pi/` persist across sessions. Both intercept `tool_call` events in load order.

**Tech Stack:** TypeScript (JIT-compiled by pi's jiti loader), Node.js built-ins (fs, path), Pi extension API (`@mariozechner/pi-coding-agent` types). No npm dependencies required beyond what pi ships.

**Spec:** `docs/superpowers/specs/2026-04-28-permissions-security-gate-design.md`

---

## File Map

### Permissions Gate (`.pi/extensions/permissions-gate/`)
| File | Responsibility | Dependencies |
|------|---------------|--------------|
| `config.ts` | Load/merge config, `PermissionsConfig` type | fs, path |
| `memory.ts` | Read/write `.pi/permissions-gate-memory.json` | fs, path |
| `classifier.ts` | Fingerprinting, danger classification, tier checks | none (pure) |
| `dialogs.ts` | `ctx.ui.select()` wrappers for 4-option confirmation | ExtensionContext |
| `index.ts` | Entry point: flags, commands, `tool_call` handler glue | all above |

### Security Gate (`.pi/extensions/security-gate/`)
| File | Responsibility | Dependencies |
|------|---------------|--------------|
| `config.ts` | Load/merge config, `SecurityConfig` type | fs, path |
| `boundary.ts` | Path resolution, symlink handling, boundary checks | fs, path |
| `command-scanner.ts` | Bash classification, path extraction from commands | none (pure) |
| `memory.ts` | Read/write `.pi/security-gate-memory.json` | fs, path |
| `dialogs.ts` | Boundary violation confirmation dialogs | ExtensionContext |
| `index.ts` | Entry point: flags, commands, `tool_call` handler glue | all above |

---

## Chunk 1: Permissions Gate — Config & Memory

### Task 1.1: Create directory and config module

**Files:**
- Create: `.pi/extensions/permissions-gate/config.ts`

- [ ] **Step 1: Write config.ts with types and load/save logic**

```typescript
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

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

export const DEFAULT_CONFIG: PermissionsConfig = {
  version: 1,
  level: "standard",
  alwaysAllow: ["npm test"],
  alwaysDeny: ["rm -rf <root>"],
  forceFlagRequiresConfirm: true,
  forceFlagExceptions: [],
  requireConfirmationFor: [],
  memoryEnabled: true,
};

function parseConfig(raw: unknown): Partial<PermissionsConfig> | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  const result: Partial<PermissionsConfig> = {};
  if (typeof obj.level === "string" && ["open", "standard", "strict", "read-only"].includes(obj.level)) {
    result.level = obj.level as PermissionLevel;
  }
  if (Array.isArray(obj.alwaysAllow)) result.alwaysAllow = obj.alwaysAllow.map(String);
  if (Array.isArray(obj.alwaysDeny)) result.alwaysDeny = obj.alwaysDeny.map(String);
  if (typeof obj.forceFlagRequiresConfirm === "boolean") result.forceFlagRequiresConfirm = obj.forceFlagRequiresConfirm;
  if (Array.isArray(obj.forceFlagExceptions)) result.forceFlagExceptions = obj.forceFlagExceptions.map(String);
  if (Array.isArray(obj.requireConfirmationFor)) result.requireConfirmationFor = obj.requireConfirmationFor.map(String);
  if (typeof obj.memoryEnabled === "boolean") result.memoryEnabled = obj.memoryEnabled;
  return result;
}

function loadJsonFile(path: string): unknown | null {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    console.error(`[permissions-gate] Warning: Could not parse ${path}`);
    return null;
  }
}

export function mergeConfigs(base: PermissionsConfig, override: Partial<PermissionsConfig>): PermissionsConfig {
  return { ...base, ...override };
}

export function loadConfig(cwd: string): PermissionsConfig {
  const globalPath = join(homedir(), ".pi", "agent", "extensions", "permissions-gate.json");
  const projectPath = join(cwd, ".pi", "permissions-gate.json");

  const globalRaw = loadJsonFile(globalPath);
  const projectRaw = loadJsonFile(projectPath);

  let config = { ...DEFAULT_CONFIG };

  if (globalRaw) {
    const parsed = parseConfig(globalRaw);
    if (parsed) config = mergeConfigs(config, parsed);
  }

  if (projectRaw) {
    const parsed = parseConfig(projectRaw);
    if (parsed) config = mergeConfigs(config, parsed);
  }

  return config;
}
```

- [ ] **Step 2: Verify it works in isolation**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { loadConfig, DEFAULT_CONFIG } = require('./config.ts');
console.log('Default:', DEFAULT_CONFIG.level);
"
```
Expected: Prints `Default: standard` (jiti handles TS)

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/config.ts
git commit -m "feat: add permissions-gate config module"
```

### Task 1.2: Create memory persistence module

**Files:**
- Create: `.pi/extensions/permissions-gate/memory.ts`

- [ ] **Step 1: Write memory.ts with types and CRUD**

```typescript
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";

export interface MemoryEntry {
  fingerprint: string;
  original: string;
  approvedAt?: number;
  deniedAt?: number;
}

export interface PermissionsMemory {
  version: number;
  approvals: MemoryEntry[];
  denials: MemoryEntry[];
}

const DEFAULT_MEMORY: PermissionsMemory = {
  version: 1,
  approvals: [],
  denials: [],
};

function getMemoryPath(cwd: string): string {
  return join(cwd, ".pi", "permissions-gate-memory.json");
}

function parseMemory(raw: unknown): PermissionsMemory | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  const result: PermissionsMemory = {
    version: typeof obj.version === "number" ? obj.version : 1,
    approvals: [],
    denials: [],
  };
  if (Array.isArray(obj.approvals)) {
    for (const a of obj.approvals) {
      if (typeof a === "object" && a !== null) {
        const entry = a as Record<string, unknown>;
        result.approvals.push({
          fingerprint: String(entry.fingerprint ?? ""),
          original: String(entry.original ?? ""),
          approvedAt: typeof entry.approvedAt === "number" ? entry.approvedAt : Date.now(),
        });
      }
    }
  }
  if (Array.isArray(obj.denials)) {
    for (const d of obj.denials) {
      if (typeof d === "object" && d !== null) {
        const entry = d as Record<string, unknown>;
        result.denials.push({
          fingerprint: String(entry.fingerprint ?? ""),
          original: String(entry.original ?? ""),
          deniedAt: typeof entry.deniedAt === "number" ? entry.deniedAt : Date.now(),
        });
      }
    }
  }
  return result;
}

export function loadMemory(cwd: string): PermissionsMemory {
  const path = getMemoryPath(cwd);
  try {
    if (!existsSync(path)) return { ...DEFAULT_MEMORY };
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    const parsed = parseMemory(raw);
    return parsed ?? { ...DEFAULT_MEMORY };
  } catch {
    console.error("[permissions-gate] Warning: Could not parse memory file, starting fresh");
    return { ...DEFAULT_MEMORY };
  }
}

export function saveMemory(cwd: string, memory: PermissionsMemory): void {
  const path = getMemoryPath(cwd);
  try {
    mkdirSync(dirname(path), { recursive: true });
    // Atomic write: temp file then rename
    const tmpPath = path + ".tmp";
    writeFileSync(tmpPath, JSON.stringify(memory, null, 2), "utf-8");
    const { renameSync } = require("node:fs");
    renameSync(tmpPath, path);
  } catch (err) {
    console.error("[permissions-gate] Warning: Could not save memory file:", err);
  }
}

export function isApprovedInMemory(fingerprint: string, memory: PermissionsMemory): boolean {
  return memory.approvals.some((e) => e.fingerprint === fingerprint);
}

export function isDeniedInMemory(fingerprint: string, memory: PermissionsMemory): boolean {
  return memory.denials.some((e) => e.fingerprint === fingerprint);
}

export function addApproval(memory: PermissionsMemory, fingerprint: string, original: string): void {
  // Remove any existing denial for this fingerprint
  memory.denials = memory.denials.filter((e) => e.fingerprint !== fingerprint);
  // Add approval if not already present
  if (!isApprovedInMemory(fingerprint, memory)) {
    memory.approvals.push({ fingerprint, original, approvedAt: Date.now() });
  }
}

export function addDenial(memory: PermissionsMemory, fingerprint: string, original: string): void {
  // Remove any existing approval for this fingerprint
  memory.approvals = memory.approvals.filter((e) => e.fingerprint !== fingerprint);
  // Add denial if not already present
  if (!isDeniedInMemory(fingerprint, memory)) {
    memory.denials.push({ fingerprint, original, deniedAt: Date.now() });
  }
}

export function forgetEntry(memory: PermissionsMemory, index: number): boolean {
  const combined = [
    ...memory.approvals.map((e, i) => ({ entry: e, i, kind: "approval" as const })),
    ...memory.denials.map((e, i) => ({ entry: e, i, kind: "denial" as const })),
  ];
  if (index < 0 || index >= combined.length) return false;
  const item = combined[index];
  if (item.kind === "approval") {
    memory.approvals.splice(item.i, 1);
  } else {
    memory.denials.splice(item.i, 1);
  }
  return true;
}

export function clearMemory(memory: PermissionsMemory): void {
  memory.approvals = [];
  memory.denials = [];
}

export function listMemoryEntries(memory: PermissionsMemory): Array<{ kind: "approval" | "denial"; fingerprint: string; original: string }> {
  return [
    ...memory.approvals.map((e) => ({ kind: "approval" as const, fingerprint: e.fingerprint, original: e.original })),
    ...memory.denials.map((e) => ({ kind: "denial" as const, fingerprint: e.fingerprint, original: e.original })),
  ];
}
```

- [ ] **Step 2: Verify memory round-trips**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { loadMemory, saveMemory, addApproval, isApprovedInMemory } = require('./memory.ts');
const cwd = process.cwd();
let mem = loadMemory(cwd);
console.log('Empty:', mem.approvals.length === 0 && mem.denials.length === 0);
addApproval(mem, 'rm -rf <path>', 'rm -rf ./build/');
saveMemory(cwd, mem);
let mem2 = loadMemory(cwd);
console.log('Round-trip:', isApprovedInMemory('rm -rf <path>', mem2));
"
```
Expected: `Empty: true` then `Round-trip: true`

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/memory.ts
git commit -m "feat: add permissions-gate memory persistence"
```

---

## Chunk 2: Permissions Gate — Classifier & Dialogs

### Task 2.1: Write command classifier and fingerprinter

**Files:**
- Create: `.pi/extensions/permissions-gate/classifier.ts`

- [ ] **Step 1: Write classifier.ts**

```typescript
import type { PermissionsConfig, PermissionLevel } from "./config";

export type DangerLevel = "safe" | "force-flagged" | "dangerous";

export interface ClassificationResult {
  level: DangerLevel;
  fingerprint: string;
  reason?: string;
}

// ---- FORCE-FLAG DETECTION ----

const FORCE_LONG_REGEX = /--force\b/;
const FORCE_SHORT_REGEX = /(?:\s|^)-[a-zA-Z]*f[a-zA-Z]*\b/;

export function hasForceFlag(fingerprint: string): boolean {
  return FORCE_LONG_REGEX.test(fingerprint) || FORCE_SHORT_REGEX.test(fingerprint);
}

export function isForceFlagException(fingerprint: string, config: PermissionsConfig): boolean {
  return config.forceFlagExceptions.includes(fingerprint);
}

// ---- FINGERPRINTING ----

function looksLikePath(arg: string): boolean {
  // Starts with . / ~ or contains a known file extension
  return /^(\.|~|\/)/.test(arg) || /\.[a-zA-Z]{1,6}$/.test(arg);
}

function looksLikeRef(arg: string): boolean {
  // Git ref patterns: branch names, tags, commit hashes
  return /^[0-9a-f]{7,40}$/.test(arg) || /^[a-zA-Z][\w.\-\/]+$/.test(arg);
}

export function fingerprintCommand(command: string): string {
  const parts = command.trim().split(/\s+/);

  // Strip leading path from base command
  if (parts[0] && parts[0].includes("/")) {
    parts[0] = parts[0].split("/").pop()!;
  }

  for (let i = 1; i < parts.length; i++) {
    // Skip flag-like tokens
    if (parts[i].startsWith("-")) continue;

    // Check for literal filesystem root
    if (parts[i] === "/") {
      parts[i] = "<root>";
      continue;
    }

    if (looksLikePath(parts[i])) {
      parts[i] = "<path>";
    } else if (looksLikeRef(parts[i])) {
      parts[i] = "<ref>";
    } else if (/^\d+$/.test(parts[i])) {
      parts[i] = "<num>";
    }
  }

  return parts.join(" ");
}

// ---- CLASSIFICATION ----

const DESTRUCTIVE_COMMANDS = new Set([
  "rm", "sudo", "chmod", "chown", "chgrp", "dd", "mkfs", "fdisk",
  "parted", "shred", "wipe", "kill", "killall", "pkill", "reboot",
  "shutdown", "halt", "poweroff", "init", "systemctl", "iptables",
  "ip6tables", "nft", "ufw", "firewall-cmd",
]);

const DESTRUCTIVE_GIT_SUBCOMMANDS = new Set([
  "reset", "clean", "rebase", "push", "filter-branch", "gc", "prune",
]);

const READ_ONLY_COMMANDS = new Set([
  "cat", "ls", "find", "grep", "rg", "head", "tail", "wc", "du", "df",
  "file", "stat", "sort", "uniq", "cut", "tr", "awk", "echo", "printf",
  "which", "type", "whereis", "diff", "cmp", "comm", "man", "info",
  "ps", "pwd", "env", "printenv", "uname", "hostname", "uptime", "free",
  "hl",
]);

const READ_ONLY_GIT_SUBCOMMANDS = new Set([
  "log", "diff", "show", "status", "branch", "tag", "remote", "blame", "grep",
]);

// Commands that are allowed even though they run programs (they're project-internal)
const ALLOWED_RUN_COMMANDS = new Set([
  "npm", "npx", "node", "python", "python3", "rustc", "go", "cargo",
  "pip", "gem", "top", "htop",
]);

function extractBaseCommand(fingerprint: string): string {
  return fingerprint.split(/\s/)[0];
}

function extractSubcommand(fingerprint: string): string | null {
  const parts = fingerprint.split(/\s/);
  return parts.length > 1 ? parts[1] : null;
}

function isPipedInstallation(fingerprint: string): boolean {
  const hasCurl = /\bcurl\b/.test(fingerprint) || /\bwget\b/.test(fingerprint);
  const pipedToInterpreter = /\|\s*(sh|bash|python|python3|perl|ruby)\b/.test(fingerprint);
  return hasCurl && pipedToInterpreter;
}

function hasSystemPathTarget(fingerprint: string, cwd: string): boolean {
  // Check if fingerprint contains absolute paths under system dirs
  const SYSTEM_PREFIXES = ["/etc", "/usr", "/boot", "/lib", "/bin", "/sbin", "/opt", "/var", "/root"];
  // Extract path-like tokens from fingerprint
  const words = fingerprint.split(/\s+/);
  for (const word of words) {
    if (word === "<path>" || word === "<root>") {
      // Fingerprint already resolved; this was an absolute path arg
      // Check original normalization direction: we need the original command
      // Since fingerprint loses absolute vs relative info, we check in the original command
      continue;
    }
    // This is a heuristic - <path> patterns mean we need to check the original
  }
  // For fingerprint level: if the fingerprint contains <root>, that's a system path
  if (fingerprint.includes("<root>")) return true;
  // For <path>: conservatively flag commands that modify system locations
  // Pattern: commands like "install", "cp", "ln" with system-looking paths
  return false; // Conservative: only flag <root> at fingerprint level
}

export function classifyBashCommand(command: string, cwd: string): ClassificationResult {
  const fingerprint = fingerprintCommand(command);

  // Rule B: Destructive git subcommands
  const base = extractBaseCommand(fingerprint);
  if (base === "git") {
    const sub = extractSubcommand(fingerprint);
    if (sub && DESTRUCTIVE_GIT_SUBCOMMANDS.has(sub)) {
      // Check for --hard, --force, etc
      if (/--hard|--force|--mixed/.test(fingerprint)) {
        return { level: "dangerous", fingerprint, reason: `Destructive git: git ${sub}` };
      }
    }
  }

  // Rule C: Recursive deletion
  if (base === "rm" && /\b-r/.test(fingerprint)) {
    return { level: "dangerous", fingerprint, reason: "Recursive deletion" };
  }

  // Rule A: Destructive base commands
  if (DESTRUCTIVE_COMMANDS.has(base)) {
    return { level: "dangerous", fingerprint, reason: `Dangerous command: ${base}` };
  }

  // Rule D: Permission escalation
  if (base === "sudo" || /\bsu\s+-/.test(fingerprint) || /\bdoas\b/.test(fingerprint)) {
    return { level: "dangerous", fingerprint, reason: "Permission escalation" };
  }

  // Rule E: Permission wide-open
  if (base === "chmod" && /\b777\b/.test(fingerprint)) {
    return { level: "dangerous", fingerprint, reason: "chmod 777" };
  }

  // Rule F: Piped installation
  if (isPipedInstallation(fingerprint)) {
    return { level: "dangerous", fingerprint, reason: "Piped download to interpreter" };
  }

  // Rule G: System path targets
  if (hasSystemPathTarget(fingerprint, cwd)) {
    return { level: "dangerous", fingerprint, reason: "System path target" };
  }

  // Rule H: Config overrides (checked in isAllowedAtTier, not here)

  // Force-flag check (separate from danger classification)
  if (hasForceFlag(fingerprint)) {
    return { level: "force-flagged", fingerprint };
  }

  return { level: "safe", fingerprint };
}

export function isAlwaysAllowed(fingerprint: string, config: PermissionsConfig): boolean {
  return config.alwaysAllow.includes(fingerprint);
}

export function isAlwaysDenied(fingerprint: string, config: PermissionsConfig): boolean {
  return config.alwaysDeny.some((pattern) => {
    // Support exact match and also <path> wildcard for alwaysDeny patterns
    return fingerprint === pattern;
  });
}

export function isAllowedAtTier(
  fingerprint: string,
  tier: PermissionLevel,
  config: PermissionsConfig,
): { allowed: boolean; reason?: string } {
  // Config overrides: alwaysAllow/alwaysDeny take precedence
  if (isAlwaysAllowed(fingerprint, config)) return { allowed: true };
  if (isAlwaysDenied(fingerprint, config)) return { allowed: false, reason: "config: alwaysDeny" };

  switch (tier) {
    case "open":
      return { allowed: true };

    case "standard": {
      const classification = classifyBashCommand(fingerprint, "");
      if (classification.level === "dangerous") {
        return { allowed: false, reason: classification.reason };
      }
      // Config-based requireConfirmationFor
      if (config.requireConfirmationFor.includes(fingerprint)) {
        return { allowed: false, reason: "config: requireConfirmationFor" };
      }
      return { allowed: true };
    }

    case "strict":
      // Confirms everything (handled in index.ts via dialog)
      return { allowed: false, reason: "strict tier: all mutations require confirmation" };

    case "read-only":
      // Block all mutations; only allow read-only commands
      if (!isReadOnlyAllowed(fingerprint)) {
        return { allowed: false, reason: "read-only tier" };
      }
      return { allowed: true };

    default:
      return { allowed: false, reason: "unknown tier" };
  }
}

export function isReadOnlyAllowed(command: string): boolean {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) return false;
  const base = parts[0].includes("/") ? parts[0].split("/").pop()! : parts[0];

  // Check for pipes - both sides must be allowed
  const pipedCommands = command.split("|");
  for (const piped of pipedCommands) {
    const pipedBase = piped.trim().split(/\s+/)[0];
    if (!pipedBase) continue;
    const cleanedBase = pipedBase.includes("/") ? pipedBase.split("/").pop()! : pipedBase;

    if (READ_ONLY_COMMANDS.has(cleanedBase)) continue;
    if (cleanedBase === "git") {
      const sub = piped.trim().split(/\s+/)[1];
      if (sub && READ_ONLY_GIT_SUBCOMMANDS.has(sub)) continue;
    }
    if (ALLOWED_RUN_COMMANDS.has(cleanedBase)) continue;
    return false;
  }
  return true;
}
```

- [ ] **Step 2: Test fingerprinter in isolation**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { fingerprintCommand, classifyBashCommand } = require('./classifier.ts');
console.log('rm -rf /:', fingerprintCommand('rm -rf /'));
console.log('git push --force origin main:', fingerprintCommand('git push --force origin main'));
console.log('classify rm -rf:', JSON.stringify(classifyBashCommand('rm -rf ./build/', process.cwd())));
"
```
Expected: Prints fingerprints and `dangerous` classification for `rm -rf`

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/classifier.ts
git commit -m "feat: add permissions-gate classifier and fingerprinter"
```

### Task 2.2: Write dialogs module

**Files:**
- Create: `.pi/extensions/permissions-gate/dialogs.ts`

- [ ] **Step 1: Write dialogs.ts**

```typescript
import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { PermissionsMemory } from "./memory";
import { addApproval, addDenial } from "./memory";

export interface DialogResult {
  action: "allow-once" | "allow-remember" | "deny-once" | "deny-remember";
}

async function showDialog(
  ctx: ExtensionContext,
  title: string,
  message: string,
): Promise<DialogResult> {
  if (!ctx.hasUI) {
    return { action: "deny-once" };
  }

  const choice = await ctx.ui.select(
    `⚠️  ${title}\n\n${message}`,
    [
      "Yes, this once",
      "Yes, and remember",
      "No, this once",
      "No, always deny",
    ],
  );

  switch (choice) {
    case "Yes, and remember": return { action: "allow-remember" };
    case "Yes, this once": return { action: "allow-once" };
    case "No, always deny": return { action: "deny-remember" };
    default: return { action: "deny-once" };
  }
}

export async function confirmDangerous(
  ctx: ExtensionContext,
  command: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
  reason: string,
): Promise<DialogResult> {
  const result = await showDialog(
    ctx,
    "Dangerous Command",
    `Command: ${command}\n\nFingerprint: ${fingerprint}\nReason: ${reason}\n\nAllow this operation?`,
  );

  if (memoryEnabled) {
    if (result.action === "allow-remember") {
      addApproval(memory, fingerprint, command);
    } else if (result.action === "deny-remember") {
      addDenial(memory, fingerprint, command);
    }
  }

  return result;
}

export async function confirmForce(
  ctx: ExtensionContext,
  command: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
): Promise<DialogResult> {
  const result = await showDialog(
    ctx,
    "Force Flag Detected",
    `Command: ${command}\n\nFingerprint: ${fingerprint}\n\nA force flag (-f / --force) was detected.\nAllow this operation?`,
  );

  if (memoryEnabled) {
    if (result.action === "allow-remember") {
      addApproval(memory, fingerprint, command);
    } else if (result.action === "deny-remember") {
      addDenial(memory, fingerprint, command);
    }
  }

  return result;
}

export async function confirmMutation(
  ctx: ExtensionContext,
  toolName: string,
  target: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
): Promise<DialogResult> {
  const result = await showDialog(
    ctx,
    `Confirm ${toolName}`,
    `Target: ${target}\n\nFingerprint: ${fingerprint}\n\nAllow this operation?`,
  );

  if (memoryEnabled) {
    if (result.action === "allow-remember") {
      addApproval(memory, fingerprint, target);
    } else if (result.action === "deny-remember") {
      addDenial(memory, fingerprint, target);
    }
  }

  return result;
}
```

- [ ] **Step 2: Commit**

```bash
git add .pi/extensions/permissions-gate/dialogs.ts
git commit -m "feat: add permissions-gate dialogs"
```

---

## Chunk 3: Permissions Gate — Index (Glue)

### Task 3.1: Write index.ts entry point

**Files:**
- Create: `.pi/extensions/permissions-gate/index.ts`

- [ ] **Step 1: Write index.ts**

```typescript
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType } from "@mariozechner/pi-coding-agent";
import type { PermissionsConfig, PermissionLevel } from "./config";
import { loadConfig, DEFAULT_CONFIG } from "./config";
import type { PermissionsMemory } from "./memory";
import { loadMemory, saveMemory, isApprovedInMemory, isDeniedInMemory, forgetEntry, clearMemory, listMemoryEntries } from "./memory";
import { fingerprintCommand, hasForceFlag, isForceFlagException, isAllowedAtTier } from "./classifier";
import { confirmDangerous, confirmForce, confirmMutation } from "./dialogs";

export default function (pi: ExtensionAPI) {
  // ---- CLI Flag ----
  pi.registerFlag("permissions-gate", {
    description: "Set permissions gate level (open|standard|strict|read-only)",
    type: "string",
    default: "",
  });

  pi.registerFlag("no-permissions-gate", {
    description: "Disable permissions gate entirely",
    type: "boolean",
    default: false,
  });

  // ---- State ----
  let config: PermissionsConfig = { ...DEFAULT_CONFIG };
  let memory: PermissionsMemory = { version: 1, approvals: [], denials: [] };
  let cwd = process.cwd();
  let enabled = true;

  function getStatusText(): string {
    const levelText = {
      open: "🔓 open",
      standard: "⚠️  standard",
      strict: "🔒 strict",
      "read-only": "🚫 read-only",
    }[config.level];
    const memCount = memory.approvals.length + memory.denials.length;
    const memText = memCount > 0 ? ` 📝 ${memory.approvals.length}A/${memory.denials.length}D` : "";
    return `${levelText}${memText}`;
  }

  // ---- Session Start ----
  pi.on("session_start", async (_event, ctx) => {
    const noGate = pi.getFlag("no-permissions-gate") as boolean;
    if (noGate) {
      enabled = false;
      ctx.ui.setStatus("permissions-gate", undefined);
      return;
    }

    cwd = ctx.cwd;
    config = loadConfig(cwd);
    memory = config.memoryEnabled ? loadMemory(cwd) : { version: 1, approvals: [], denials: [] };

    // CLI flag overrides config level
    const flagLevel = pi.getFlag("permissions-gate") as string;
    if (flagLevel && ["open", "standard", "strict", "read-only"].includes(flagLevel)) {
      config.level = flagLevel as PermissionLevel;
    }

    ctx.ui.setStatus("permissions-gate", getStatusText());
    ctx.ui.notify(`Permissions gate: ${config.level}`, "info");
  });

  // ---- Tool Call Handler ----
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;

    // ---- write / edit tools ----
    if (event.toolName === "write" || event.toolName === "edit") {
      if (config.level === "read-only") {
        ctx.ui.notify(`Blocked: ${event.toolName} (read-only tier)`, "warning");
        return { block: true, reason: `Permissions gate: ${event.toolName} blocked (read-only tier)` };
      }
      if (config.level === "strict") {
        const path = event.input.path as string;
        const fp = `${event.toolName}:${path}`;
        if (config.memoryEnabled && isApprovedInMemory(fp, memory)) return;
        if (config.memoryEnabled && isDeniedInMemory(fp, memory)) {
          return { block: true, reason: `Permissions gate: ${event.toolName} ${path} (remembered denial)` };
        }
        const result = await confirmMutation(ctx, event.toolName, path, fp, memory, config.memoryEnabled);
        if (result.action.startsWith("deny")) {
          if (config.memoryEnabled) saveMemory(cwd, memory);
          return { block: true, reason: `Permissions gate: ${event.toolName} ${path} blocked` };
        }
        if (config.memoryEnabled) saveMemory(cwd, memory);
        return;
      }
      return;
    }

    // ---- bash tool ----
    if (event.toolName === "bash") {
      if (!isToolCallEventType("bash", event)) return;
      const rawCommand = event.input.command as string;
      const fingerprint = fingerprintCommand(rawCommand);

      // 1. Check memory first (takes precedence)
      if (config.memoryEnabled && isApprovedInMemory(fingerprint, memory)) return;
      if (config.memoryEnabled && isDeniedInMemory(fingerprint, memory)) {
        return { block: true, reason: `Permissions gate: remembered denial for: ${fingerprint}` };
      }

      // 2. Force-flag check (always on when forceFlagRequiresConfirm is true)
      if (config.forceFlagRequiresConfirm && hasForceFlag(fingerprint) && !isForceFlagException(fingerprint, config)) {
        const result = await confirmForce(ctx, rawCommand, fingerprint, memory, config.memoryEnabled);
        if (result.action.startsWith("deny")) {
          if (config.memoryEnabled) saveMemory(cwd, memory);
          return { block: true, reason: `Permissions gate: force-flag blocked: ${fingerprint}` };
        }
        if (config.memoryEnabled) saveMemory(cwd, memory);
        return;
      }

      // 3. Tier check
      const tierResult = isAllowedAtTier(fingerprint, config.level, config);
      if (!tierResult.allowed) {
        if (config.level === "read-only") {
          return { block: true, reason: `Permissions gate: blocked (read-only): ${fingerprint}` };
        }
        if (config.level === "strict") {
          const result = await confirmMutation(ctx, "bash", rawCommand, fingerprint, memory, config.memoryEnabled);
          if (result.action.startsWith("deny")) {
            if (config.memoryEnabled) saveMemory(cwd, memory);
            return { block: true, reason: `Permissions gate: blocked (strict): ${fingerprint}` };
          }
          if (config.memoryEnabled) saveMemory(cwd, memory);
          return;
        }
        // standard tier: show danger dialog
        const result = await confirmDangerous(ctx, rawCommand, fingerprint, memory, config.memoryEnabled, tierResult.reason ?? "dangerous");
        if (result.action.startsWith("deny")) {
          if (config.memoryEnabled) saveMemory(cwd, memory);
          return { block: true, reason: `Permissions gate: blocked: ${fingerprint}` };
        }
        if (config.memoryEnabled) saveMemory(cwd, memory);
        return;
      }
    }
  });

  // ---- Commands ----
  pi.registerCommand("permissions", {
    description: "Show permissions gate status and config",
    handler: async (_args, ctx) => {
      await ctx.ui.notify(
        [
          `Permissions Gate: ${enabled ? config.level : "disabled"}`,
          `Force-flag check: ${config.forceFlagRequiresConfirm ? "on" : "off"}`,
          `Memory: ${config.memoryEnabled ? "on" : "off"} (${memory.approvals.length}A/${memory.denials.length}D)`,
          `Always allow: ${config.alwaysAllow.length} patterns`,
          `Always deny: ${config.alwaysDeny.length} patterns`,
          `Require confirmation: ${config.requireConfirmationFor.length} patterns`,
        ].join("\n"),
        "info",
      );
    },
  });

  pi.registerCommand("permissions-set", {
    description: "Change permissions gate level",
    handler: async (args, ctx) => {
      if (!enabled) {
        ctx.ui.notify("Permissions gate is disabled", "warning");
        return;
      }
      if (!args || !["open", "standard", "strict", "read-only"].includes(args)) {
        ctx.ui.notify("Usage: /permissions-set <open|standard|strict|read-only>", "warning");
        return;
      }
      config.level = args as PermissionLevel;
      ctx.ui.setStatus("permissions-gate", getStatusText());
      ctx.ui.notify(`Permissions set to: ${config.level}`, "info");
    },
  });

  pi.registerCommand("permissions-memory", {
    description: "List remembered permissions entries",
    handler: async (_args, ctx) => {
      if (!config.memoryEnabled) {
        ctx.ui.notify("Memory is disabled", "info");
        return;
      }
      const entries = listMemoryEntries(memory);
      if (entries.length === 0) {
        ctx.ui.notify("No remembered entries", "info");
        return;
      }
      const lines = entries.map((e, i) =>
        `[${i}] ${e.kind === "approval" ? "✅" : "❌"} ${e.fingerprint} (${e.original})`,
      );
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("permissions-forget", {
    description: "Remove a remembered entry by index",
    handler: async (args, ctx) => {
      if (!args) {
        ctx.ui.notify("Usage: /permissions-forget <index>", "warning");
        return;
      }
      const idx = parseInt(args, 10);
      if (isNaN(idx)) {
        ctx.ui.notify("Index must be a number", "warning");
        return;
      }
      if (forgetEntry(memory, idx)) {
        saveMemory(cwd, memory);
        ctx.ui.notify(`Forgot entry ${idx}`, "info");
      } else {
        ctx.ui.notify(`No entry at index ${idx}`, "warning");
      }
    },
  });

  pi.registerCommand("permissions-clear-memory", {
    description: "Clear all remembered permissions entries",
    handler: async (_args, ctx) => {
      clearMemory(memory);
      saveMemory(cwd, memory);
      ctx.ui.notify("Memory cleared", "info");
    },
  });

  // ---- Session Shutdown ----
  pi.on("session_shutdown", () => {
    ctx.ui.setStatus("permissions-gate", undefined);
  });
}
```

Wait — there's an issue in the session_shutdown handler. `ctx` is not available there since it uses `_event` not `ctx` parameter. The session_shutdown event doesn't receive ctx. Let me fix that. Actually, looking at the Pi docs, `session_shutdown` does receive `(event, ctx)`. Let me check.

Actually, no — the `session_shutdown` handler doesn't need to unset status because the extension is being torn down. The status will be cleared when the new session starts. But we should save memory on shutdown. Let me fix the index.ts.

- [ ] **Step 2: Fix index.ts session_shutdown to save memory and avoid ctx usage**

The `session_shutdown` should just save memory if needed. Actually, memory is saved after each confirmation dialog result, so there's nothing to save on shutdown. We can just remove the shutdown handler or leave it as a no-op.

- [ ] **Step 3: Write correct index.ts**

Actually, let me redo this properly. The shutdown handler should just be omitted — memory is saved on each change already. And I realized there's a bug: `pi` is not available in commands for `setStatus`. Actually, `pi` IS available in the closure but `ctx.ui.setStatus` should be used since the command handler gets `ctx`. Let me check: commands receive `ctx: ExtensionCommandContext` which extends `ExtensionContext`, so `ctx.ui.setStatus` works.

Actually wait, I'm confusing myself. The status was set at session_start via the `ctx` from the event handler. The commands use `ctx` from the command handler. Both should work independently. But we also need to update the status after a permissions-set command. Let me also fix: the `pi` reference is used for `pi.getFlag()` and `pi.registerFlag()` etc, which is correct — `pi` is the `ExtensionAPI` captured in the closure.

Let me also fix: the status should update after memory changes. Let me write the final correct version.<｜end▁of▁thinking｜>

<｜DSML｜tool_calls>
<｜DSML｜invoke name="write">
<｜DSML｜parameter name="content" string="true"># Permissions Gate & Security Gate Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two Pi extensions — a tiered permissions gate and a project-boundary security gate — with disk-persisted memory, CLI flags, and interactive commands.

**Architecture:** Two independent extension directories under `.pi/extensions/` with 10 focused TypeScript files. Each extension follows the same pattern: config → memory → pure logic (classifier/scanner) → dialogs → index glue. Both intercept `tool_call` events in load order.

**Tech Stack:** TypeScript (JIT-compiled by pi's jiti), Node.js built-ins only, pi Extension API types from `@mariozechner/pi-coding-agent`.

**Spec:** `docs/superpowers/specs/2026-04-28-permissions-security-gate-design.md`

---

## File Map

### Permissions Gate (`.pi/extensions/permissions-gate/`)
| File | Responsibility | Pure/Impure |
|------|---------------|-------------|
| `config.ts` | Load/merge `PermissionsConfig` from JSON | Impure (fs reads) |
| `memory.ts` | Read/write `.pi/permissions-gate-memory.json` | Impure (fs read/write) |
| `classifier.ts` | Fingerprinting, danger classification, tier checks | Pure |
| `dialogs.ts` | `ctx.ui.select()` wrappers for 4-option confirmation | Impure (ctx.ui) |
| `index.ts` | Entry point: flags, commands, `tool_call` handler | Impure |

### Security Gate (`.pi/extensions/security-gate/`)
| File | Responsibility | Pure/Impure |
|------|---------------|-------------|
| `config.ts` | Load/merge `SecurityConfig` from JSON | Impure (fs reads) |
| `boundary.ts` | Path resolution, symlink handling, boundary checks | Impure (fs.realpathSync) |
| `command-scanner.ts` | Bash classification, path extraction | Pure (with cwd context) |
| `memory.ts` | Read/write `.pi/security-gate-memory.json` | Impure (fs read/write) |
| `dialogs.ts` | Boundary violation confirmation dialogs | Impure (ctx.ui) |
| `index.ts` | Entry point: flags, commands, `tool_call` handler | Impure |

---

## Chunk 1: Permissions Gate — Config & Memory

### Task 1.1: Create directory and config module

**Files:**
- Create: `.pi/extensions/permissions-gate/config.ts`

- [ ] **Step 1: Write config.ts**

```typescript
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

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

export const DEFAULT_CONFIG: PermissionsConfig = {
  version: 1,
  level: "standard",
  alwaysAllow: ["npm test"],
  alwaysDeny: ["rm -rf <root>"],
  forceFlagRequiresConfirm: true,
  forceFlagExceptions: [],
  requireConfirmationFor: [],
  memoryEnabled: true,
};

const VALID_LEVELS = new Set(["open", "standard", "strict", "read-only"]);

function parseConfig(raw: unknown): Partial<PermissionsConfig> | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  const result: Partial<PermissionsConfig> = {};

  if (typeof obj.level === "string" && VALID_LEVELS.has(obj.level)) {
    result.level = obj.level as PermissionLevel;
  }
  if (Array.isArray(obj.alwaysAllow)) result.alwaysAllow = obj.alwaysAllow.map(String);
  if (Array.isArray(obj.alwaysDeny)) result.alwaysDeny = obj.alwaysDeny.map(String);
  if (typeof obj.forceFlagRequiresConfirm === "boolean") result.forceFlagRequiresConfirm = obj.forceFlagRequiresConfirm;
  if (Array.isArray(obj.forceFlagExceptions)) result.forceFlagExceptions = obj.forceFlagExceptions.map(String);
  if (Array.isArray(obj.requireConfirmationFor)) result.requireConfirmationFor = obj.requireConfirmationFor.map(String);
  if (typeof obj.memoryEnabled === "boolean") result.memoryEnabled = obj.memoryEnabled;
  return result;
}

function loadJsonFile(path: string): unknown | null {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    console.error(`[permissions-gate] Warning: Could not parse ${path}`);
    return null;
  }
}

export function mergeConfigs(
  base: PermissionsConfig,
  override: Partial<PermissionsConfig>,
): PermissionsConfig {
  return { ...base, ...override };
}

export function loadConfig(cwd: string): PermissionsConfig {
  const globalPath = join(homedir(), ".pi", "agent", "extensions", "permissions-gate.json");
  const projectPath = join(cwd, ".pi", "permissions-gate.json");

  const globalRaw = loadJsonFile(globalPath);
  const projectRaw = loadJsonFile(projectPath);

  let config = { ...DEFAULT_CONFIG };

  if (globalRaw) {
    const parsed = parseConfig(globalRaw);
    if (parsed) config = mergeConfigs(config, parsed);
  }

  if (projectRaw) {
    const parsed = parseConfig(projectRaw);
    if (parsed) config = mergeConfigs(config, parsed);
  }

  return config;
}
```

- [ ] **Step 2: Verify it loads in Node**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { loadConfig, DEFAULT_CONFIG } = require('./config.ts');
console.log('Default level:', DEFAULT_CONFIG.level);
console.log('Load from cwd:', loadConfig(process.cwd()).level);
"
```

Expected: `Default level: standard` (twice if no config file exists)

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/config.ts
git commit -m "feat: add permissions-gate config module"
```

### Task 1.2: Create memory persistence module

**Files:**
- Create: `.pi/extensions/permissions-gate/memory.ts`

- [ ] **Step 1: Write memory.ts**

```typescript
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";

export interface MemoryEntry {
  fingerprint: string;
  original: string;
  approvedAt?: number;
  deniedAt?: number;
}

export interface PermissionsMemory {
  version: number;
  approvals: MemoryEntry[];
  denials: MemoryEntry[];
}

function getMemoryPath(cwd: string): string {
  return join(cwd, ".pi", "permissions-gate-memory.json");
}

function parseMemory(raw: unknown): PermissionsMemory | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;
  const result: PermissionsMemory = {
    version: typeof obj.version === "number" ? obj.version : 1,
    approvals: [],
    denials: [],
  };
  if (Array.isArray(obj.approvals)) {
    for (const a of obj.approvals) {
      if (typeof a === "object" && a !== null) {
        const e = a as Record<string, unknown>;
        result.approvals.push({
          fingerprint: String(e.fingerprint ?? ""),
          original: String(e.original ?? ""),
          approvedAt: typeof e.approvedAt === "number" ? e.approvedAt : Date.now(),
        });
      }
    }
  }
  if (Array.isArray(obj.denials)) {
    for (const d of obj.denials) {
      if (typeof d === "object" && d !== null) {
        const e = d as Record<string, unknown>;
        result.denials.push({
          fingerprint: String(e.fingerprint ?? ""),
          original: String(e.original ?? ""),
          deniedAt: typeof e.deniedAt === "number" ? e.deniedAt : Date.now(),
        });
      }
    }
  }
  return result;
}

export function loadMemory(cwd: string): PermissionsMemory {
  const path = getMemoryPath(cwd);
  try {
    if (!existsSync(path)) return { version: 1, approvals: [], denials: [] };
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    return parseMemory(raw) ?? { version: 1, approvals: [], denials: [] };
  } catch {
    console.error("[permissions-gate] Warning: Could not parse memory file, starting fresh");
    return { version: 1, approvals: [], denials: [] };
  }
}

export function saveMemory(cwd: string, memory: PermissionsMemory): void {
  const path = getMemoryPath(cwd);
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmpPath = path + ".tmp";
    writeFileSync(tmpPath, JSON.stringify(memory, null, 2), "utf-8");
    renameSync(tmpPath, path);
  } catch (err) {
    console.error("[permissions-gate] Warning: Could not save memory file:", err);
  }
}

export function isApprovedInMemory(fingerprint: string, memory: PermissionsMemory): boolean {
  return memory.approvals.some((e) => e.fingerprint === fingerprint);
}

export function isDeniedInMemory(fingerprint: string, memory: PermissionsMemory): boolean {
  return memory.denials.some((e) => e.fingerprint === fingerprint);
}

export function addApproval(memory: PermissionsMemory, fingerprint: string, original: string): void {
  memory.denials = memory.denials.filter((e) => e.fingerprint !== fingerprint);
  if (!isApprovedInMemory(fingerprint, memory)) {
    memory.approvals.push({ fingerprint, original, approvedAt: Date.now() });
  }
}

export function addDenial(memory: PermissionsMemory, fingerprint: string, original: string): void {
  memory.approvals = memory.approvals.filter((e) => e.fingerprint !== fingerprint);
  if (!isDeniedInMemory(fingerprint, memory)) {
    memory.denials.push({ fingerprint, original, deniedAt: Date.now() });
  }
}

export function forgetEntry(memory: PermissionsMemory, index: number): boolean {
  const combined: Array<{ kind: "approval" | "denial"; pos: number }> = [
    ...memory.approvals.map((_, i) => ({ kind: "approval" as const, pos: i })),
    ...memory.denials.map((_, i) => ({ kind: "denial" as const, pos: i })),
  ];
  if (index < 0 || index >= combined.length) return false;
  const { kind, pos } = combined[index];
  if (kind === "approval") memory.approvals.splice(pos, 1);
  else memory.denials.splice(pos, 1);
  return true;
}

export function clearMemory(memory: PermissionsMemory): void {
  memory.approvals = [];
  memory.denials = [];
}

export function listMemoryEntries(
  memory: PermissionsMemory,
): Array<{ kind: "approval" | "denial"; fingerprint: string; original: string }> {
  return [
    ...memory.approvals.map((e) => ({ kind: "approval" as const, fingerprint: e.fingerprint, original: e.original })),
    ...memory.denials.map((e) => ({ kind: "denial" as const, fingerprint: e.fingerprint, original: e.original })),
  ];
}
```

- [ ] **Step 2: Verify round-trip save/load**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { loadMemory, saveMemory, addApproval, isApprovedInMemory, clearMemory } = require('./memory.ts');
const cwd = process.cwd();
let mem = loadMemory(cwd);
clearMemory(mem);
addApproval(mem, 'rm -rf <path>', 'rm -rf ./build/');
saveMemory(cwd, mem);
let mem2 = loadMemory(cwd);
console.log('Round-trip:', isApprovedInMemory('rm -rf <path>', mem2));
console.log('Approvals:', mem2.approvals.length, 'Denials:', mem2.denials.length);
// Clean up
const { unlinkSync } = require('node:fs');
try { unlinkSync(require('node:path').join(cwd, '.pi/permissions-gate-memory.json')); } catch {}
"
```
Expected: `Round-trip: true`, `Approvals: 1 Denials: 0`

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/memory.ts
git commit -m "feat: add permissions-gate memory persistence"
```

---

## Chunk 2: Permissions Gate — Classifier & Dialogs

### Task 2.1: Write command classifier and fingerprinter

**Files:**
- Create: `.pi/extensions/permissions-gate/classifier.ts`

- [ ] **Step 1: Write classifier.ts**

```typescript
import type { PermissionsConfig, PermissionLevel } from "./config";

export type DangerLevel = "safe" | "force-flagged" | "dangerous";

export interface ClassificationResult {
  level: DangerLevel;
  fingerprint: string;
  reason?: string;
}

// ---- REGEX ----

const FORCE_LONG = /--force\b/;
const FORCE_SHORT = /(?:\s|^)-[a-zA-Z]*f[a-zA-Z]*\b/;

// ---- FINGERPRINTING ----

function looksLikePath(arg: string): boolean {
  if (arg === "/") return false; // root handled separately
  return /^(\.|~|\/)/.test(arg) || /\.[a-zA-Z]{1,6}$/.test(arg);
}

function looksLikeRef(arg: string): boolean {
  if (arg.startsWith("-") || arg.startsWith("<")) return false;
  return /^[0-9a-f]{7,40}$/.test(arg) || /^[a-zA-Z][\w.\-/]+$/.test(arg);
}

export function fingerprintCommand(command: string): string {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) return "";

  // Strip leading path from base command
  if (parts[0].includes("/")) parts[0] = parts[0].split("/").pop()!;

  for (let i = 1; i < parts.length; i++) {
    if (parts[i].startsWith("-")) continue;
    if (parts[i] === "/") { parts[i] = "<root>"; continue; }
    if (looksLikePath(parts[i])) parts[i] = "<path>";
    else if (looksLikeRef(parts[i])) parts[i] = "<ref>";
    else if (/^\d+$/.test(parts[i])) parts[i] = "<num>";
  }

  return parts.join(" ");
}

// ---- FORCE-FLAG ----

export function hasForceFlag(fingerprint: string): boolean {
  return FORCE_LONG.test(fingerprint) || FORCE_SHORT.test(fingerprint);
}

export function isForceFlagException(fingerprint: string, config: PermissionsConfig): boolean {
  return config.forceFlagExceptions.includes(fingerprint);
}

// ---- CLASSIFICATION ----

const DESTRUCTIVE = new Set([
  "rm", "sudo", "chmod", "chown", "chgrp", "dd", "mkfs", "fdisk",
  "parted", "shred", "wipe", "kill", "killall", "pkill", "reboot",
  "shutdown", "halt", "poweroff", "init",
  "iptables", "ip6tables", "nft", "ufw", "firewall-cmd",
  // File-creating commands (partial coverage for Rule G system paths):
  "touch", "mkdir", "ln", "install", "cp",
]);

const DESTRUCTIVE_GIT = new Set([
  "reset", "clean", "rebase", "push", "filter-branch", "gc", "prune",
]);

const READ_ONLY = new Set([
  "cat", "ls", "find", "grep", "rg", "head", "tail", "wc", "du", "df",
  "file", "stat", "sort", "uniq", "cut", "tr", "awk", "echo", "printf",
  "which", "type", "whereis", "diff", "cmp", "comm", "man", "info",
  "ps", "pwd", "env", "printenv", "uname", "hostname", "uptime", "free", "hl",
]);

const READ_ONLY_GIT = new Set([
  "log", "diff", "show", "status", "branch", "tag", "remote", "blame", "grep",
]);

const ALLOWED_RUN = new Set([
  "npm", "npx", "node", "python", "python3", "rustc", "go", "cargo",
  "pip", "gem", "top", "htop",
]);

function extractBase(fp: string): string {
  return fp.split(/\s/)[0] || "";
}

function extractSub(fp: string): string | null {
  const parts = fp.split(/\s/);
  return parts.length > 1 ? parts[1] : null;
}

function isPipedInstall(fp: string): boolean {
  return /(?:^|\s)(curl|wget)\s/.test(fp) && /\|\s*(sh|bash|python|python3|perl|ruby)\b/.test(fp);
}

export function classifyBashCommand(command: string, cwd: string): ClassificationResult {
  const fp = fingerprintCommand(command);
  const base = extractBase(fp);

  // Rule C: Recursive deletion
  if (base === "rm" && /\b-r/.test(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "recursive deletion" };
  }

  // Rule B: Destructive git
  if (base === "git") {
    const sub = extractSub(fp);
    if (sub && DESTRUCTIVE_GIT.has(sub) && /--hard|--force|--mixed/.test(fp)) {
      return { level: "dangerous", fingerprint: fp, reason: `destructive git: ${sub}` };
    }
  }

  // Rule A: Destructive base commands (with subcommand inspection where needed)
  if (base === "systemctl") {
    const sub = extractSub(fp);
    if (sub && ["stop", "disable", "mask", "isolate"].includes(sub)) {
      return { level: "dangerous", fingerprint: fp, reason: `systemctl ${sub}` };
    }
    // read-only systemctl commands (status, list-units, etc.) pass through
  } else if (DESTRUCTIVE.has(base)) {
    return { level: "dangerous", fingerprint: fp, reason: `dangerous: ${base}` };
  }

  // Rule D: Permission escalation
  if (base === "sudo" || /\bsu\s+-/.test(fp) || /\bdoas\b/.test(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "permission escalation" };
  }

  // Rule E: chmod wide-open
  if (base === "chmod" && /\b777\b/.test(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "chmod 777" };
  }

  // Rule F: Piped install
  if (isPipedInstall(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "piped download to interpreter" };
  }

  // Rule G: System path targets (check original command, not just fingerprint)
  // Check if any argument resolves to a system path
  const parts = command.trim().split(/\s+/);
  const SYSTEM_PREFIXES = ["/etc", "/usr", "/boot", "/lib", "/bin", "/sbin", "/opt", "/var", "/root", "/home"];
  for (const part of parts) {
    if (part.startsWith("/")) {
      for (const prefix of SYSTEM_PREFIXES) {
        if (part.startsWith(prefix + "/") || part === prefix) {
          // Exclude /home/<current-user> if we know the user
          // (conservative: flag /home/anything as dangerous)
          return { level: "dangerous", fingerprint: fp, reason: `system path: ${part}` };
        }
      }
    }
  }

  // Force-flag check (separate from danger)
  if (hasForceFlag(fp)) {
    return { level: "force-flagged", fingerprint: fp };
  }

  return { level: "safe", fingerprint: fp };
}

// ---- TIER CHECK ----

export function isAlwaysAllowed(fp: string, config: PermissionsConfig): boolean {
  return config.alwaysAllow.includes(fp);
}

export function isAlwaysDenied(fp: string, config: PermissionsConfig): boolean {
  return config.alwaysDeny.includes(fp);
}

export function isAllowedAtTier(
  fp: string,
  tier: PermissionLevel,
  config: PermissionsConfig,
): { allowed: boolean; reason?: string } {
  if (isAlwaysAllowed(fp, config)) return { allowed: true };
  if (isAlwaysDenied(fp, config)) return { allowed: false, reason: "alwaysDeny" };

  switch (tier) {
    case "open":
      return { allowed: true };

    case "standard": {
      const classification = classifyBashCommand(fp, "");
      if (classification.level === "dangerous") {
        return { allowed: false, reason: classification.reason };
      }
      if (config.requireConfirmationFor.includes(fp)) {
        return { allowed: false, reason: "requireConfirmationFor" };
      }
      return { allowed: true };
    }

    case "strict":
      return { allowed: false, reason: "strict tier" };

    case "read-only":
      if (!isReadOnlyAllowed(fp)) {
        return { allowed: false, reason: "read-only tier" };
      }
      return { allowed: true };

    default:
      return { allowed: false, reason: "unknown tier" };
  }
}

export function isReadOnlyAllowed(command: string): boolean {
  const pipedCommands = command.split("|");
  for (const piped of pipedCommands) {
    const parts = piped.trim().split(/\s+/);
    if (parts.length === 0) continue;
    const base = parts[0].includes("/") ? parts[0].split("/").pop()! : parts[0];
    if (READ_ONLY.has(base)) continue;
    if (base === "git") {
      const sub = parts[1];
      if (sub && READ_ONLY_GIT.has(sub)) continue;
    }
    if (ALLOWED_RUN.has(base)) continue;
    return false;
  }
  return true;
}
```

- [ ] **Step 2: Test fingerprinter**

```bash
cd .pi/extensions/permissions-gate
node -e "
const { fingerprintCommand, classifyBashCommand } = require('./classifier.ts');
const cwd = process.cwd();
console.log('f: rm -rf /         =>', fingerprintCommand('rm -rf /'));
console.log('f: rm -rf ./build   =>', fingerprintCommand('rm -rf ./build'));
console.log('f: git push -f      =>', fingerprintCommand('git push --force origin main'));
console.log('c: rm -rf ./build   =>', JSON.stringify(classifyBashCommand('rm -rf ./build', cwd)));
console.log('c: cat README.md    =>', JSON.stringify(classifyBashCommand('cat README.md', cwd)));
console.log('c: curl x \| sh     =>', JSON.stringify(classifyBashCommand('curl http://x | sh', cwd)));
"
```

Expected:
- `rm -rf /` fingerprints to `rm -rf <root>`
- `rm -rf ./build/` fingerprints to `rm -rf <path>`
- `cat README.md` is `safe`
- `curl | sh` is `dangerous` (piped install)

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/classifier.ts
git commit -m "feat: add permissions-gate classifier and fingerprinter"
```

### Task 2.2: Write dialogs module

**Files:**
- Create: `.pi/extensions/permissions-gate/dialogs.ts`

- [ ] **Step 1: Write dialogs.ts**

```typescript
import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { PermissionsMemory } from "./memory";
import { addApproval, addDenial } from "./memory";

export interface DialogResult {
  action: "allow-once" | "allow-remember" | "deny-once" | "deny-remember";
}

const OPTIONS = ["Yes, this once", "Yes, and remember", "No, this once", "No, always deny"];

async function show(
  ctx: ExtensionContext,
  title: string,
  message: string,
): Promise<DialogResult> {
  if (!ctx.hasUI) return { action: "deny-once" };

  const choice = await ctx.ui.select(`⚠️  ${title}\n\n${message}`, OPTIONS);

  switch (choice) {
    case "Yes, and remember": return { action: "allow-remember" };
    case "Yes, this once": return { action: "allow-once" };
    case "No, always deny": return { action: "deny-remember" };
    default: return { action: "deny-once" };
  }
}

function applyMemory(
  result: DialogResult,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
  fingerprint: string,
  original: string,
): void {
  if (!memoryEnabled) return;
  if (result.action === "allow-remember") addApproval(memory, fingerprint, original);
  else if (result.action === "deny-remember") addDenial(memory, fingerprint, original);
}

export async function confirmDangerous(
  ctx: ExtensionContext,
  command: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
  reason: string,
): Promise<DialogResult> {
  const result = await show(
    ctx,
    "Dangerous Command",
    `${command}\n\nFingerprint: ${fingerprint}\nReason: ${reason}`,
  );
  applyMemory(result, memory, memoryEnabled, fingerprint, command);
  return result;
}

export async function confirmForce(
  ctx: ExtensionContext,
  command: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
): Promise<DialogResult> {
  const result = await show(
    ctx,
    "Force Flag Detected",
    `${command}\n\nFingerprint: ${fingerprint}\nForce flag (-f / --force) detected.`,
  );
  applyMemory(result, memory, memoryEnabled, fingerprint, command);
  return result;
}

export async function confirmMutation(
  ctx: ExtensionContext,
  toolName: string,
  target: string,
  fingerprint: string,
  memory: PermissionsMemory,
  memoryEnabled: boolean,
): Promise<DialogResult> {
  const result = await show(
    ctx,
    `Confirm ${toolName}`,
    `Target: ${target}\nFingerprint: ${fingerprint}`,
  );
  applyMemory(result, memory, memoryEnabled, fingerprint, target);
  return result;
}
```

- [ ] **Step 2: Commit**

```bash
git add .pi/extensions/permissions-gate/dialogs.ts
git commit -m "feat: add permissions-gate dialogs"
```

---

## Chunk 3: Permissions Gate — Index (Entry Point)

### Task 3.1: Write index.ts

**Files:**
- Create: `.pi/extensions/permissions-gate/index.ts`

- [ ] **Step 1: Write index.ts**

```typescript
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType } from "@mariozechner/pi-coding-agent";
import type { PermissionsConfig, PermissionLevel } from "./config";
import { loadConfig, DEFAULT_CONFIG } from "./config";
import type { PermissionsMemory } from "./memory";
import {
  loadMemory, saveMemory, isApprovedInMemory, isDeniedInMemory,
  forgetEntry, clearMemory, listMemoryEntries,
} from "./memory";
import {
  fingerprintCommand, hasForceFlag, isForceFlagException, isAllowedAtTier,
} from "./classifier";
import { confirmDangerous, confirmForce, confirmMutation } from "./dialogs";

const VALID_LEVELS = new Set(["open", "standard", "strict", "read-only"]);

export default function (pi: ExtensionAPI) {
  // ---- CLI Flags ----
  pi.registerFlag("permissions-gate", {
    description: "Set permissions gate level (open|standard|strict|read-only)",
    type: "string",
    default: "",
  });
  pi.registerFlag("no-permissions-gate", {
    description: "Disable permissions gate entirely",
    type: "boolean",
    default: false,
  });

  // ---- State ----
  let config: PermissionsConfig = { ...DEFAULT_CONFIG };
  let memory: PermissionsMemory = { version: 1, approvals: [], denials: [] };
  let cwd = process.cwd();
  let enabled = true;

  function getStatus(theme?: { fg: (k: string, t: string) => string }) {
    const styles = {
      open: "🔓 open",
      standard: "⚠️  standard",
      strict: "🔒 strict",
      "read-only": "🚫 read-only",
    };
    let text = styles[config.level] || config.level;
    const total = memory.approvals.length + memory.denials.length;
    if (total > 0) text += ` 📝 ${memory.approvals.length}A/${memory.denials.length}D`;
    return theme ? theme.fg("warning", text) : text;
  }

  function saveMemIfEnabled(): void {
    if (config.memoryEnabled) saveMemory(cwd, memory);
  }

  // ---- Session Start ----
  pi.on("session_start", async (_event, ctx) => {
    if (pi.getFlag("no-permissions-gate")) {
      enabled = false;
      return;
    }
    cwd = ctx.cwd;
    config = loadConfig(cwd);
    memory = config.memoryEnabled ? loadMemory(cwd) : { version: 1, approvals: [], denials: [] };

    const flagLevel = pi.getFlag("permissions-gate") as string;
    if (typeof flagLevel === "string" && VALID_LEVELS.has(flagLevel)) {
      config.level = flagLevel as PermissionLevel;
    }

    ctx.ui.setStatus("permissions-gate", getStatus(ctx.ui.theme));
    ctx.ui.notify(`Permissions gate: ${config.level}`, "info");
  });

  // ---- Tool Call Handler ----
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;

    // --- write / edit ---
    if (event.toolName === "write" || event.toolName === "edit") {
      if (config.level === "read-only") {
        return { block: true, reason: `Permissions gate: ${event.toolName} blocked (read-only)` };
      }
      if (config.level === "strict") {
        const target = (event.input as { path?: string }).path ?? "unknown";
        const fp = `${event.toolName}:${target}`;
        if (config.memoryEnabled && isApprovedInMemory(fp, memory)) return;
        if (config.memoryEnabled && isDeniedInMemory(fp, memory)) {
          return { block: true, reason: `Permissions gate: remembered denial (${fp})` };
        }
        const result = await confirmMutation(ctx, event.toolName, target, fp, memory, config.memoryEnabled);
        saveMemIfEnabled();
        if (result.action.startsWith("deny")) {
          return { block: true, reason: `Permissions gate: ${event.toolName} blocked` };
        }
      }
      return;
    }

    // --- bash ---
    if (event.toolName === "bash") {
      if (!isToolCallEventType("bash", event)) return;
      const rawCommand = event.input.command as string;
      const fp = fingerprintCommand(rawCommand);

      // 1. Memory check (takes precedence over tier)
      if (config.memoryEnabled && isApprovedInMemory(fp, memory)) return;
      if (config.memoryEnabled && isDeniedInMemory(fp, memory)) {
        return { block: true, reason: `Permissions gate: remembered denial (${fp})` };
      }

      // 2. Force-flag check
      if (config.forceFlagRequiresConfirm && hasForceFlag(fp) && !isForceFlagException(fp, config)) {
        const result = await confirmForce(ctx, rawCommand, fp, memory, config.memoryEnabled);
        saveMemIfEnabled();
        if (result.action.startsWith("deny")) {
          return { block: true, reason: `Permissions gate: force-flag blocked` };
        }
        return;
      }

      // 3. Tier check
      const tierResult = isAllowedAtTier(fp, config.level, config);
      if (!tierResult.allowed) {
        if (config.level === "read-only") {
          return { block: true, reason: `Permissions gate: blocked (read-only): ${fp}` };
        }
        if (config.level === "strict") {
          const result = await confirmMutation(ctx, "bash", rawCommand, fp, memory, config.memoryEnabled);
          saveMemIfEnabled();
          if (result.action.startsWith("deny")) {
            return { block: true, reason: `Permissions gate: blocked (strict): ${fp}` };
          }
          return;
        }
        // standard tier
        const result = await confirmDangerous(ctx, rawCommand, fp, memory, config.memoryEnabled, tierResult.reason ?? "dangerous");
        saveMemIfEnabled();
        if (result.action.startsWith("deny")) {
          return { block: true, reason: `Permissions gate: blocked: ${fp}` };
        }
      }
    }
  });

  // ---- Commands ----

  function handleSubcommand(args: string | undefined, ctx: ExtensionContext): boolean {
    if (!args) return false;
    const sub = args.trim().split(/\s+/)[0];
    const rest = args.slice(sub.length).trim();

    if (sub === "memory") {
      if (!config.memoryEnabled) { ctx.ui.notify("Memory disabled", "info"); return true; }
      const entries = listMemoryEntries(memory);
      if (entries.length === 0) { ctx.ui.notify("No remembered entries", "info"); return true; }
      const lines = entries.map((e, i) =>
        `[${i}] ${e.kind === "approval" ? "✅" : "❌"} ${e.fingerprint} (${e.original})`
      );
      ctx.ui.notify(lines.join("\n"), "info");
      return true;
    }

    if (sub === "forget") {
      const idx = parseInt(rest, 10);
      if (isNaN(idx)) { ctx.ui.notify("Usage: /permissions forget <index>", "warning"); return true; }
      if (forgetEntry(memory, idx)) {
        saveMemIfEnabled();
        ctx.ui.notify(`Forgot entry ${idx}`, "info");
      } else {
        ctx.ui.notify(`No entry at index ${idx}`, "warning");
      }
      return true;
    }

    if (sub === "clear-memory") {
      clearMemory(memory);
      saveMemIfEnabled();
      ctx.ui.notify("Memory cleared", "info");
      return true;
    }

    if (sub === "set" || sub === "level") {
      const level = rest || undefined;
      if (!level || !VALID_LEVELS.has(level)) {
        ctx.ui.notify("Usage: /permissions set open|standard|strict|read-only", "warning");
      } else {
        config.level = level as PermissionLevel;
        ctx.ui.setStatus("permissions-gate", getStatus(ctx.ui.theme));
        ctx.ui.notify(`Permissions: ${config.level}`, "info");
      }
      return true;
    }

    return false;
  }

  pi.registerCommand("permissions", {
    description: "Permissions gate: status, set <level>, memory, forget <n>, clear-memory",
    handler: async (args, ctx) => {
      if (handleSubcommand(args, ctx)) return;

      // Default: show status
      const lines = [
        `Gate: ${enabled ? config.level : "disabled"}`,
        `Force-flag: ${config.forceFlagRequiresConfirm ? "on" : "off"}`,
        `Memory: ${config.memoryEnabled ? "on" : "off"} (${memory.approvals.length}A/${memory.denials.length}D)`,
        `Allowlist: ${config.alwaysAllow.length} | Denylist: ${config.alwaysDeny.length}`,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
```

- [ ] **Step 2: Verify the extension loads without errors**

```bash
# Test that jiti can parse all the files
cd .pi/extensions/permissions-gate
node -e "require('./index.ts')"
```
Expected: No errors (the export default function isn't invoked, but parsing succeeds)

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/permissions-gate/index.ts
git commit -m "feat: add permissions-gate entry point"
```

---

## Chunk 4: Security Gate — Config, Memory & Boundary

### Task 4.1: Create config module

**Files:**
- Create: `.pi/extensions/security-gate/config.ts`

- [ ] **Step 1: Write config.ts**

```typescript
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

export interface SecurityConfig {
  version: number;
  enabled: boolean;
  allowWriteOutside: string[];
  denyWriteInside: string[];
  interactiveConfirmOutside: boolean;
  checkSymlinks: boolean;
  memoryEnabled: boolean;
}

export const DEFAULT_CONFIG: SecurityConfig = {
  version: 1,
  enabled: true,
  allowWriteOutside: ["/tmp", "/var/tmp", "~/.cache", "/dev/null"],
  denyWriteInside: [".env", "*.pem", "*/.git/*", "secrets.*"],
  interactiveConfirmOutside: true,
  checkSymlinks: true,
  memoryEnabled: true,
};

function parse(raw: unknown): Partial<SecurityConfig> | null {
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  const r: Partial<SecurityConfig> = {};
  if (typeof o.enabled === "boolean") r.enabled = o.enabled;
  if (Array.isArray(o.allowWriteOutside)) r.allowWriteOutside = o.allowWriteOutside.map(String);
  if (Array.isArray(o.denyWriteInside)) r.denyWriteInside = o.denyWriteInside.map(String);
  if (typeof o.interactiveConfirmOutside === "boolean") r.interactiveConfirmOutside = o.interactiveConfirmOutside;
  if (typeof o.checkSymlinks === "boolean") r.checkSymlinks = o.checkSymlinks;
  if (typeof o.memoryEnabled === "boolean") r.memoryEnabled = o.memoryEnabled;
  return r;
}

function loadJson(path: string): unknown | null {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    console.error(`[security-gate] Warning: Could not parse ${path}`);
    return null;
  }
}

export function mergeConfigs(base: SecurityConfig, override: Partial<SecurityConfig>): SecurityConfig {
  return { ...base, ...override };
}

export function loadConfig(cwd: string): SecurityConfig {
  const globalPath = join(homedir(), ".pi", "agent", "extensions", "security-gate.json");
  const projectPath = join(cwd, ".pi", "security-gate.json");

  let config = { ...DEFAULT_CONFIG };
  const globalRaw = loadJson(globalPath);
  if (globalRaw) {
    const p = parse(globalRaw);
    if (p) config = mergeConfigs(config, p);
  }
  const projectRaw = loadJson(projectPath);
  if (projectRaw) {
    const p = parse(projectRaw);
    if (p) config = mergeConfigs(config, p);
  }
  return config;
}
```

- [ ] **Step 2: Commit**

```bash
git add .pi/extensions/security-gate/config.ts
git commit -m "feat: add security-gate config module"
```

### Task 4.2: Create boundary module

**Files:**
- Create: `.pi/extensions/security-gate/boundary.ts`

- [ ] **Step 1: Write boundary.ts**

```typescript
import { realpathSync, existsSync } from "node:fs";
import { resolve, relative, sep } from "node:path";
import { homedir } from "node:os";

export function resolveWriteTarget(rawPath: string, cwd: string): string {
  return resolve(cwd, rawPath);
}

export function isInsideProject(
  path: string,
  projectRoot: string,
  checkSymlinks: boolean,
): boolean {
  let canonical = path;

  if (checkSymlinks) {
    try {
      if (existsSync(path)) {
        canonical = realpathSync(path);
      }
    } catch {
      // If realpath fails (broken symlink, ENOENT), fall back to resolved path
      canonical = resolve(path);
    }
  }

  const normalizedRoot = resolve(projectRoot) + sep;
  const normalizedPath = resolve(canonical) + sep;
  return normalizedPath.startsWith(normalizedRoot);
}

export function isDeniedInside(
  path: string,
  projectRoot: string,
  deniedGlobs: string[],
): boolean {
  const rel = relative(projectRoot, resolve(path));
  if (rel === "" || rel.startsWith("..")) return false; // outside project, not "inside" deny

  for (const glob of deniedGlobs) {
    if (matchSimpleGlob(rel, glob)) return true;
  }
  return false;
}

export function isAllowedOutside(
  path: string,
  allowedPaths: string[],
  cwd: string,
): boolean {
  const resolved = resolve(path);
  for (const allowed of allowedPaths) {
    const expanded = allowed.startsWith("~") ? allowed.replace("~", homedir()) : allowed;
    if (resolved.startsWith(resolve(expanded))) return true;
    if (resolved === "/dev/null") return true;
  }
  return false;
}

// Simple glob matching for denyWriteInside patterns
/**
 * Simple glob matching for denyWriteInside patterns.
 * Supports * (any characters within path segment), ** (recursive),
 * ? (single char). This is a subset of minimatch — no braces, negation,
 * or character classes.
 */
function matchSimpleGlob(target: string, pattern: string): boolean {
  const parts = pattern.split(/(\*\*|\*|\?|[^*?]+)/).filter(Boolean);
  let regexStr = "^";
  for (const part of parts) {
    if (part === "**") regexStr += ".*";
    else if (part === "*") regexStr += "[^/]*";
    else if (part === "?") regexStr += "[^/]";
    else regexStr += part.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  regexStr += "$";
  return new RegExp(regexStr).test(target);
}
```

- [ ] **Step 2: Test boundary checks**

```bash
cd .pi/extensions/security-gate
node -e "
const { isInsideProject, resolveWriteTarget } = require('./boundary.ts');
const cwd = process.cwd();
console.log('inside:', isInsideProject(cwd + '/src/file.ts', cwd, true));
console.log('outside:', isInsideProject('/etc/hosts', cwd, true));
console.log('resolve:', resolveWriteTarget('../outside', cwd));
"
```
Expected: `inside: true`, `outside: false`, `resolve: <parent-dir>`

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/security-gate/boundary.ts
git commit -m "feat: add security-gate boundary checks"
```

### Task 4.3: Create memory module

**Files:**
- Create: `.pi/extensions/security-gate/memory.ts`

- [ ] **Step 1: Write memory.ts**

```typescript
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import { join, dirname } from "node:path";

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

function getPath(cwd: string): string {
  return join(cwd, ".pi", "security-gate-memory.json");
}

function parse(raw: unknown): SecurityMemory | null {
  if (typeof raw !== "object" || raw === null) return null;
  const o = raw as Record<string, unknown>;
  const r: SecurityMemory = { version: typeof o.version === "number" ? o.version : 1, allowedExternalPaths: [], allowedExternalPatterns: [] };
  if (Array.isArray(o.allowedExternalPaths)) {
    for (const p of o.allowedExternalPaths) {
      if (typeof p === "object" && p !== null) {
        const e = p as Record<string, unknown>;
        r.allowedExternalPaths.push({ path: String(e.path ?? ""), approvedAt: typeof e.approvedAt === "number" ? e.approvedAt : Date.now() });
      }
    }
  }
  if (Array.isArray(o.allowedExternalPatterns)) {
    for (const p of o.allowedExternalPatterns) {
      if (typeof p === "object" && p !== null) {
        const e = p as Record<string, unknown>;
        r.allowedExternalPatterns.push({ fingerprint: String(e.fingerprint ?? ""), targetPattern: String(e.targetPattern ?? ""), approvedAt: typeof e.approvedAt === "number" ? e.approvedAt : Date.now() });
      }
    }
  }
  return r;
}

export function loadSecurityMemory(cwd: string): SecurityMemory {
  const path = getPath(cwd);
  try {
    if (!existsSync(path)) return { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };
    const raw = JSON.parse(readFileSync(path, "utf-8"));
    return parse(raw) ?? { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };
  } catch {
    console.error("[security-gate] Warning: Could not parse memory file");
    return { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };
  }
}

export function saveSecurityMemory(cwd: string, memory: SecurityMemory): void {
  const path = getPath(cwd);
  try {
    mkdirSync(dirname(path), { recursive: true });
    const tmp = path + ".tmp";
    writeFileSync(tmp, JSON.stringify(memory, null, 2), "utf-8");
    renameSync(tmp, path);
  } catch (err) {
    console.error("[security-gate] Warning: Could not save memory:", err);
  }
}

export function isPathRemembered(targetPath: string, memory: SecurityMemory): boolean {
  return memory.allowedExternalPaths.some((e) => e.path === targetPath);
}

export function addAllowedPath(memory: SecurityMemory, path: string): void {
  if (!isPathRemembered(path, memory)) {
    memory.allowedExternalPaths.push({ path, approvedAt: Date.now() });
  }
}

export function addAllowedPattern(memory: SecurityMemory, fingerprint: string, targetPattern: string): void {
  memory.allowedExternalPatterns.push({ fingerprint, targetPattern, approvedAt: Date.now() });
}

export function forgetEntry(memory: SecurityMemory, index: number, kind: "path" | "pattern"): boolean {
  if (kind === "path") {
    if (index < 0 || index >= memory.allowedExternalPaths.length) return false;
    memory.allowedExternalPaths.splice(index, 1);
    return true;
  } else {
    if (index < 0 || index >= memory.allowedExternalPatterns.length) return false;
    memory.allowedExternalPatterns.splice(index, 1);
    return true;
  }
}

export function clearMemory(memory: SecurityMemory): void {
  memory.allowedExternalPaths = [];
  memory.allowedExternalPatterns = [];
}
```

- [ ] **Step 2: Commit**

```bash
git add .pi/extensions/security-gate/memory.ts
git commit -m "feat: add security-gate memory persistence"
```

---

## Chunk 5: Security Gate — Command Scanner & Dialogs

### Task 5.1: Write command-scanner.ts

**Files:**
- Create: `.pi/extensions/security-gate/command-scanner.ts`

- [ ] **Step 1: Write command-scanner.ts**

```typescript
import { resolve } from "node:path";

export type CommandClassification = "safe" | "potentially-mutating";

// Known-safe commands — don't modify files
const SAFE_COMMANDS = new Set([
  "cat", "ls", "find", "grep", "rg", "head", "tail", "wc", "du", "df",
  "file", "stat", "sort", "uniq", "cut", "tr", "awk", "echo", "printf",
  "which", "type", "whereis", "ps", "top", "htop", "free", "uptime",
  "uname", "hostname", "pwd", "env", "printenv", "diff", "cmp", "comm",
  "man", "info", "hl",
]);

const SAFE_GIT_SUBS = new Set([
  "log", "diff", "show", "status", "branch", "tag", "remote", "blame", "grep",
]);

const SAFE_PKG_MGRS = new Set([
  "cargo", "npm", "npx", "pip", "gem", "node",
]);

const SAFE_PKG_SUBS = new Set([
  "check", "ls", "list", "show", "test", "lint", "typecheck",
]);

export function classifyBaseCommand(command: string): CommandClassification {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) return "potentially-mutating";
  let base = parts[0];
  if (base.includes("/")) base = base.split("/").pop()!;

  if (SAFE_COMMANDS.has(base)) return "safe";
  if (base === "git") {
    const sub = parts[1];
    if (sub && SAFE_GIT_SUBS.has(sub)) return "safe";
    return "potentially-mutating";
  }
  if (SAFE_PKG_MGRS.has(base)) {
    const sub = parts[1];
    if (sub && SAFE_PKG_SUBS.has(sub)) return "safe";
    // Version checks like "node --version"
    if (parts[1]?.startsWith("--version") || parts[1] === "-v") return "safe";
    return "potentially-mutating";
  }

  // Heuristic: if first arg is --version, -v, --help, -h, it's likely safe inspection
  if (parts[1] === "--version" || parts[1] === "-v" || parts[1] === "--help" || parts[1] === "-h") {
    return "safe";
  }

  return "potentially-mutating";
}

// ---- PATH EXTRACTION ----

function extractRedirectPaths(command: string, cwd: string): string[] {
  const paths: string[] = [];
  // Match: >file, >>file, 2>file, 1>&2 (skip the &num case), >& file
  const redirectRegex = /\d*>>?\s*(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = redirectRegex.exec(command)) !== null) {
    const target = match[1];
    if (target && !target.startsWith("&") && !target.startsWith("/dev/fd")) {
      paths.push(target);
    }
  }
  return paths;
}

function extractOperatorPaths(command: string, cwd: string): string[] {
  const paths: string[] = [];
  const parts = command.trim().split(/\s+/);
  if (parts.length < 2) return paths;

  const base = parts[0].includes("/") ? parts[0].split("/").pop()! : parts[0];

  switch (base) {
    case "mv": // last non-flag is dest
    case "cp": // last non-flag is dest
    case "ln": // last non-flag is dest (ln -s src dest)
    case "install": { // last non-flag is dest
      const nonFlags = parts.slice(1).filter((p) => !p.startsWith("-"));
      if (nonFlags.length > 0) {
        const dest = nonFlags[nonFlags.length - 1];
        if (dest && !dest.startsWith("-")) paths.push(dest);
      }
      break;
    }
    case "mkdir":
    case "touch":
    case "tee": { // all non-flags are targets
      for (let i = 1; i < parts.length; i++) {
        if (!parts[i].startsWith("-")) paths.push(parts[i]);
      }
      break;
    }
    case "sed":
    case "perl":
    case "ruby": { // inline editors: extract file args after -i
      let skipNext = false;
      for (let i = 1; i < parts.length; i++) {
        if (skipNext) { skipNext = false; continue; }
        if (parts[i] === "-i") {
          // -i followed by extension or standalone with next arg
          if (i + 1 < parts.length && !parts[i + 1].startsWith("-")) {
            paths.push(parts[i + 1]);
            skipNext = true;
          }
        } else if (parts[i].startsWith("-i")) {
          // -i.bak style
        } else if (!parts[i].startsWith("-") && !parts[i].startsWith("'") && !parts[i].startsWith("'")) {
          // Could be a script or file — conservatively add last non-flag as target
        }
      }
      // For sed/perl/ruby: treat the last non-flag, non-script-looking arg as file target
      const nonFlags = parts.slice(1).filter((p) => !p.startsWith("-"));
      if (nonFlags.length >= 2) {
        // First non-flag is the expression/script, last is the file
        const fileArg = nonFlags[nonFlags.length - 1];
        if (fileArg && !fileArg.startsWith("e") && !fileArg.startsWith("s/") && !fileArg.startsWith("print")) {
          paths.push(fileArg);
        }
      }
      break;
    }
    case "dd": { // dd ... of=path
      const ofIdx = parts.findIndex((p) => p.startsWith("of="));
      if (ofIdx >= 0) paths.push(parts[ofIdx].slice(3));
      break;
    }
  }

  return paths;
}

export function extractTargetPaths(command: string, cwd: string): string[] {
  const allPaths: string[] = [];
  const redirects = extractRedirectPaths(command, cwd);
  const operators = extractOperatorPaths(command, cwd);

  for (const p of [...redirects, ...operators]) {
    if (p && !p.startsWith("-")) {
      try {
        allPaths.push(resolve(cwd, p));
      } catch { /* skip unresolvable */ }
    }
  }
  return allPaths;
}

export function hasFileRedirects(command: string): boolean {
  return /(?:\d*>|>>)\s*\S/.test(command);
}
```

- [ ] **Step 2: Test classification and path extraction**

```bash
cd .pi/extensions/security-gate
node -e "
const { classifyBaseCommand, extractTargetPaths, hasFileRedirects } = require('./command-scanner.ts');
const cwd = process.cwd();
console.log('cat:', classifyBaseCommand('cat README.md'));
console.log('rm:', classifyBaseCommand('rm -rf ./build'));
console.log('sed:', classifyBaseCommand('sed -i /etc/hosts'));
console.log('git log:', classifyBaseCommand('git log --oneline'));
console.log('git push:', classifyBaseCommand('git push --force origin main'));
console.log('paths mv:', extractTargetPaths('mv ./src /tmp/out', cwd));
console.log('paths cp:', extractTargetPaths('cp -r ./a ./b /tmp/dest', cwd));
console.log('redirects:', hasFileRedirects('echo foo > /tmp/out'));
"
```
Expected:
- `cat`: safe, `rm`: potentially-mutating, `sed`: potentially-mutating
- `git log`: safe, `git push`: potentially-mutating
- `mv` extracts `/tmp/out`, `cp` extracts `/tmp/dest`
- `echo foo >` has redirects: true

- [ ] **Step 3: Commit**

```bash
git add .pi/extensions/security-gate/command-scanner.ts
git commit -m "feat: add security-gate command scanner"
```

### Task 5.2: Write dialogs module

**Files:**
- Create: `.pi/extensions/security-gate/dialogs.ts`

- [ ] **Step 1: Write dialogs.ts**

```typescript
import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import type { SecurityMemory } from "./memory";
import { addAllowedPath } from "./memory";

export async function confirmBoundaryViolation(
  ctx: ExtensionContext,
  toolName: string,
  targetPath: string,
  projectRoot: string,
  memory: SecurityMemory,
  memoryEnabled: boolean,
): Promise<{ action: "allow-once" | "allow-remember" | "block" }> {
  if (!ctx.hasUI) return { action: "block" };

  const choice = await ctx.ui.select(
    `🏠 Boundary Violation\n\nTool: ${toolName}\nTarget: ${targetPath}\nProject: ${projectRoot}\n\nThis operation targets a path outside the project. Allow?`,
    ["Allow this once", "Allow and remember", "Block"],
  );

  switch (choice) {
    case "Allow and remember":
      if (memoryEnabled) addAllowedPath(memory, targetPath);
      return { action: "allow-remember" };
    case "Allow this once":
      return { action: "allow-once" };
    default:
      return { action: "block" };
  }
}
```

- [ ] **Step 2: Commit**

```bash
git add .pi/extensions/security-gate/dialogs.ts
git commit -m "feat: add security-gate dialogs"
```

---

## Chunk 6: Security Gate — Index (Entry Point)

### Task 6.1: Write index.ts

**Files:**
- Create: `.pi/extensions/security-gate/index.ts`

- [ ] **Step 1: Write index.ts**

```typescript
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { isToolCallEventType } from "@mariozechner/pi-coding-agent";
import type { SecurityConfig } from "./config";
import { loadConfig, DEFAULT_CONFIG } from "./config";
import { resolveWriteTarget, isInsideProject, isDeniedInside, isAllowedOutside } from "./boundary";
import { classifyBaseCommand, extractTargetPaths } from "./command-scanner";
import type { SecurityMemory } from "./memory";
import { loadSecurityMemory, saveSecurityMemory, isPathRemembered, forgetEntry, clearMemory } from "./memory";
import { confirmBoundaryViolation } from "./dialogs";

export default function (pi: ExtensionAPI) {
  // ---- CLI Flags ----
  pi.registerFlag("security-gate", {
    description: "Enable security gate (project boundary protection)",
    type: "boolean",
    default: false,
  });
  pi.registerFlag("no-security-gate", {
    description: "Disable security gate entirely",
    type: "boolean",
    default: false,
  });

  // ---- State ----
  let config: SecurityConfig = { ...DEFAULT_CONFIG };
  let memory: SecurityMemory = { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };
  let projectRoot = process.cwd();
  let enabled = false;

  function saveMem(): void {
    if (config.memoryEnabled) saveSecurityMemory(projectRoot, memory);
  }

  // Check if a resolved path is safe to write to
  function checkPath(
    resolvedPath: string,
    config: SecurityConfig,
    _cwd: string,
  ): { allowed: boolean; reason?: string } {
    // Check denied internal paths (inside project but protected)
    if (isDeniedInside(resolvedPath, projectRoot, config.denyWriteInside)) {
      return { allowed: false, reason: `protected internal path` };
    }
    // Check if inside project
    if (isInsideProject(resolvedPath, projectRoot, config.checkSymlinks)) {
      return { allowed: true };
    }
    // Check external allowlist
    if (isAllowedOutside(resolvedPath, config.allowWriteOutside, projectRoot)) {
      return { allowed: true };
    }
    // Check memory
    if (config.memoryEnabled && isPathRemembered(resolvedPath, memory)) {
      return { allowed: true };
    }
    return { allowed: false, reason: `outside project boundary` };
  }

  // ---- Session Start ----
  pi.on("session_start", async (_event, ctx) => {
    if (pi.getFlag("no-security-gate")) {
      enabled = false;
      ctx.ui.setStatus("security-gate", undefined);
      return;
    }
    const flagEnabled = pi.getFlag("security-gate") as boolean;
    projectRoot = ctx.cwd;
    config = loadConfig(projectRoot);
    memory = config.memoryEnabled ? loadSecurityMemory(projectRoot) : { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };

    enabled = config.enabled || flagEnabled;

    if (enabled) {
      ctx.ui.setStatus("security-gate", ctx.ui.theme.fg("accent", "🏠 boundary: active"));
      ctx.ui.notify("Security gate: active", "info");
    } else {
      ctx.ui.setStatus("security-gate", undefined);
    }
  });

  // ---- Tool Call Handler ----
  pi.on("tool_call", async (event, ctx) => {
    if (!enabled) return;

    // --- write tool ---
    if (event.toolName === "write") {
      const rawPath = (event.input as { path?: string }).path;
      if (!rawPath) return;
      const resolvedPath = resolveWriteTarget(rawPath, projectRoot);
      const check = checkPath(resolvedPath, config, projectRoot);
      if (!check.allowed) {
        if (config.interactiveConfirmOutside && ctx.hasUI) {
          const result = await confirmBoundaryViolation(ctx, "write", resolvedPath, projectRoot, memory, config.memoryEnabled);
          if (result.action === "block") {
            return { block: true, reason: `Security gate: ${resolvedPath} is ${check.reason}` };
          }
          saveMem();
          return;
        }
        return { block: true, reason: `Security gate: ${resolvedPath} is ${check.reason}` };
      }
      return;
    }

    // --- edit tool ---
    if (event.toolName === "edit") {
      const rawPath = (event.input as { path?: string }).path;
      if (!rawPath) return;
      const resolvedPath = resolveWriteTarget(rawPath, projectRoot);
      const check = checkPath(resolvedPath, config, projectRoot);
      if (!check.allowed) {
        if (config.interactiveConfirmOutside && ctx.hasUI) {
          const result = await confirmBoundaryViolation(ctx, "edit", resolvedPath, projectRoot, memory, config.memoryEnabled);
          if (result.action === "block") {
            return { block: true, reason: `Security gate: ${resolvedPath} is ${check.reason}` };
          }
          saveMem();
          return;
        }
        return { block: true, reason: `Security gate: ${resolvedPath} is ${check.reason}` };
      }
      return;
    }

    // --- bash tool ---
    if (event.toolName === "bash") {
      if (!isToolCallEventType("bash", event)) return;
      const command = event.input.command as string;

      const classification = classifyBaseCommand(command);
      if (classification === "safe") return; // Known-safe, no path scanning needed

      const targets = extractTargetPaths(command, projectRoot);
      if (targets.length === 0) {
        // Potentially-mutating but no extracted paths -> conservative block
        return { block: true, reason: "Security gate: potentially mutating command with no clear file target" };
      }

      for (const target of targets) {
        const check = checkPath(target, config, projectRoot);
        if (!check.allowed) {
          if (config.interactiveConfirmOutside && ctx.hasUI) {
            const result = await confirmBoundaryViolation(ctx, "bash", target, projectRoot, memory, config.memoryEnabled);
            if (result.action === "block") {
              return { block: true, reason: `Security gate: ${target} is ${check.reason}` };
            }
            saveMem();
            return;
          }
          return { block: true, reason: `Security gate: ${target} is ${check.reason}` };
        }
      }
    }
  });

  // ---- Commands ----

  function handleSubcommand(args: string | undefined, ctx: ExtensionContext): boolean {
    if (!args) return false;
    const sub = args.trim().split(/\s+/)[0];
    const rest = args.slice(sub.length).trim();

    if (sub === "toggle") {
      enabled = !enabled;
      if (enabled) {
        ctx.ui.setStatus("security-gate", ctx.ui.theme.fg("accent", "🏠 boundary: active"));
        ctx.ui.notify("Security gate: active", "info");
      } else {
        ctx.ui.setStatus("security-gate", undefined);
        ctx.ui.notify("Security gate: inactive", "warning");
      }
      return true;
    }

    if (sub === "memory") {
      if (!config.memoryEnabled) { ctx.ui.notify("Memory disabled", "info"); return true; }
      const paths = memory.allowedExternalPaths;
      const patterns = memory.allowedExternalPatterns;
      if (paths.length === 0 && patterns.length === 0) {
        ctx.ui.notify("No remembered paths", "info");
        return true;
      }
      const lines = [
        ...paths.map((e, i) => `[${i}] 📁 ${e.path}`),
        ...patterns.map((e, i) => `[${paths.length + i}] 🔄 ${e.fingerprint} → ${e.targetPattern}`),
      ];
      ctx.ui.notify(lines.join("\n"), "info");
      return true;
    }

    if (sub === "forget") {
      const idxStr = rest.trim();
      if (idxStr.startsWith("p")) {
        const idx = parseInt(idxStr.slice(1), 10);
        if (isNaN(idx) || !forgetEntry(memory, idx, "pattern")) {
          ctx.ui.notify(`No pattern at index ${idxStr.slice(1)}`, "warning");
          return true;
        }
      } else {
        const idx = parseInt(idxStr, 10);
        if (isNaN(idx) || !forgetEntry(memory, idx, "path")) {
          ctx.ui.notify(`No path at index ${idxStr}`, "warning");
          return true;
        }
      }
      saveMem();
      ctx.ui.notify("Forgotten", "info");
      return true;
    }

    if (sub === "clear-memory") {
      clearMemory(memory);
      saveMem();
      ctx.ui.notify("Memory cleared", "info");
      return true;
    }

    return false;
  }

  pi.registerCommand("security", {
    description: "Security gate: status, toggle, memory, forget <n>, clear-memory",
    handler: async (args, ctx) => {
      if (handleSubcommand(args, ctx)) return;

      // Default: show status
      const lines = [
        `Gate: ${enabled ? "active" : "inactive"}`,
        `Project root: ${projectRoot}`,
        `Check symlinks: ${config.checkSymlinks}`,
        `Allowed external: ${config.allowWriteOutside.join(", ")}`,
        `Denied internal: ${config.denyWriteInside.join(", ")}`,
        `Memory: ${config.memoryEnabled ? "on" : "off"} (${memory.allowedExternalPaths.length} paths)`,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
```

- [ ] **Step 2: Verify extension loads**

```bash
cd .pi/extensions/security-gate
node -e "require('./index.ts')"
```
Expected: No errors

- [ ] **Step 3: Final commit**

```bash
git add .pi/extensions/security-gate/index.ts
git commit -m "feat: add security-gate entry point"
```

---

## Chunk 7: Integration Verification

### Task 7.1: Manual smoke test with pi

- [ ] **Step 1: Launch pi with both extensions enabled**

```bash
pi --permissions-gate=standard --security-gate
```

- [ ] **Step 2: Verify permissions gate status in footer**
Expected: `⚠️  standard` status visible in pi footer

- [ ] **Step 3: Verify security gate status**
Expected: `🏠 boundary: active` status visible

- [ ] **Step 4: Trigger a dangerous command**
Type: `rm -rf ./test-build/`
Expected: Permission gate dialog appears asking for confirmation

- [ ] **Step 5: Test write outside project**
Type: `write a file to /tmp/test-outside.txt`
Expected: Security gate blocks or asks for confirmation

- [ ] **Step 6: Test force-flag detection**
Type: `git push --force origin feature-branch`
Expected: Force-flag confirmation dialog appears (at standard tier)

- [ ] **Step 7: Test /permissions command**
Type: `/permissions`
Expected: Shows current level, force-flag status, memory counts

- [ ] **Step 8: Test /permissions set and /permissions memory**
Type: `/permissions set read-only` then `/permissions memory`
Expected: Level changes to read-only, memory entries displayed

- [ ] **Step 9: Test memory persistence**
Allow an operation with "Yes, and remember", quit pi, restart, run same operation
Expected: No dialog — operation auto-allowed from memory

- [ ] **Step 10: Test /security toggle**
Type: `/security toggle` then `/security toggle`
Expected: Gate disables, then re-enables

- [ ] **Step 11: Verify read-only tier**
Type: `/permissions-set read-only` then try to edit a file
Expected: Blocked

---

## Non-Goals (explicitly excluded from this plan)

- No npm dependencies (uses only Node.js built-ins + pi-provided types)
- No unit test framework (pi extensions are tested manually; JIT compilation by jiti)
- No process-level sandboxing (separate `sandbox/` extension)
- No network restriction
- No audit logging
