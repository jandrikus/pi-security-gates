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
  // Don't fingerprint git subcommands or known command words
  const KNOWN_WORDS = new Set([
    "--force", "--hard", "--mixed", "--force-with-lease", "--force-create",
    "-f", "-rf", "-r", "-fr", "-rm", "-i", "-p",
  ]);
  if (KNOWN_WORDS.has(arg)) return false;
  return /^[0-9a-f]{7,40}$/.test(arg) || /^[a-zA-Z][\w.\-/]+$/.test(arg);
}

export function fingerprintCommand(command: string): string {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) return "";

  // Known git subcommands — don't fingerprint these
  const GIT_SUBS = new Set([
    "push", "pull", "fetch", "merge", "rebase", "reset", "checkout",
    "commit", "add", "rm", "mv", "branch", "tag", "log", "diff", "show",
    "status", "stash", "clean", "clone", "init", "remote", "config",
    "bisect", "blame", "cherry-pick", "revert", "gc", "prune", "grep",
    "filter-branch", "submodule", "worktree", "switch", "restore",
  ]);

  // Strip leading path from base command
  const base = parts[0].includes("/") ? parts[0].split("/").pop()! : parts[0];
  parts[0] = base;

  for (let i = 1; i < parts.length; i++) {
    if (parts[i].startsWith("-")) continue;
    if (parts[i] === "/") { parts[i] = "<root>"; continue; }
    // Don't fingerprint git subcommands
    if (base === "git" && i === 1 && GIT_SUBS.has(parts[i])) continue;
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

function isPipedInstall(command: string): boolean {
  // Check the ORIGINAL command (before fingerprinting) for piped install patterns
  return /(?:^|\s)(curl|wget)\s/.test(command) && /\|\s*(sh|bash|python|python3|perl|ruby)\b/.test(command);
}

export function classifyBashCommand(command: string, cwd: string): ClassificationResult {
  const fp = fingerprintCommand(command);
  const base = extractBase(fp);

  // Rule C: Recursive deletion
  if (base === "rm" && /\b-r/.test(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "recursive deletion" };
  }

  // Rule B: Destructive git (check original command for subcommand)
  if (base === "git") {
    const origParts = command.trim().split(/\s+/);
    const gitSub = origParts.length > 1 ? origParts[1] : null;
    if (gitSub && DESTRUCTIVE_GIT.has(gitSub) && /--hard|--force|--mixed/.test(fp)) {
      return { level: "dangerous", fingerprint: fp, reason: `destructive git: ${gitSub}` };
    }
  }

  // Rule A: Destructive base commands (with subcommand inspection where needed)
  if (base === "systemctl") {
    const origParts = command.trim().split(/\s+/);
    const sub = origParts.length > 1 ? origParts[1] : null;
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
  if (base === "chmod" && /[0]?777\b/.test(fp)) {
    return { level: "dangerous", fingerprint: fp, reason: "chmod 777" };
  }

  // Rule F: Piped install (check original command before fingerprinting)
  if (isPipedInstall(command)) {
    return { level: "dangerous", fingerprint: fp, reason: "piped download to interpreter" };
  }

  // Rule G: System path targets (check original command, not just fingerprint)
  const parts = command.trim().split(/\s+/);
  const SYSTEM_PREFIXES = ["/etc", "/usr", "/boot", "/lib", "/bin", "/sbin", "/opt", "/var", "/root", "/home"];
  for (const part of parts) {
    if (part.startsWith("/")) {
      for (const prefix of SYSTEM_PREFIXES) {
        if (part.startsWith(prefix + "/") || part === prefix) {
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
