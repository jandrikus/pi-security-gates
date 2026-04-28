import { resolve } from "node:path";

export type CommandClassification = "safe" | "potentially-mutating";

// Known-safe commands — don't modify files
const SAFE_COMMANDS = new Set([
  "cat", "ls", "find", "grep", "rg", "head", "tail", "wc", "du", "df",
  "file", "stat", "sort", "uniq", "cut", "tr", "awk", "echo", "printf",
  "which", "type", "whereis", "ps", "top", "htop", "free", "uptime",
  "uname", "hostname", "pwd", "env", "printenv", "diff", "cmp", "comm",
  "man", "info", "hl", "cd", "true", "false", "test", "[",
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

/**
 * Classify a single command segment (no chaining operators).
 */
function classifySegment(command: string): CommandClassification {
  const parts = command.trim().split(/\s+/);
  if (parts.length === 0) return "potentially-mutating";
  let base = parts[0];
  if (base.includes("/")) base = base.split("/").pop()!;

  // Shell builtins that don't modify files
  if (base === "cd" || base === "true" || base === "false" || base === "test" || base === "[") {
    return "safe";
  }

  if (SAFE_COMMANDS.has(base)) return "safe";
  if (base === "git") {
    // Skip flags that take a value (-C, -c, --git-dir, --work-tree) to find the subcommand
    let subIdx = 1;
    while (subIdx < parts.length) {
      const p = parts[subIdx];
      if (p === "-C" || p === "-c" || p === "--git-dir" || p === "--work-tree") {
        subIdx += 2; // skip flag + value
      } else if (p.startsWith("-c")) {
        subIdx += 1; // skip -c=value
      } else if (p.startsWith("-")) {
        subIdx += 1; // skip bare flag
      } else {
        break;
      }
    }
    const sub = parts[subIdx];
    if (sub && SAFE_GIT_SUBS.has(sub)) return "safe";
    return "potentially-mutating";
  }
  if (SAFE_PKG_MGRS.has(base)) {
    const sub = parts[1];
    if (sub && SAFE_PKG_SUBS.has(sub)) return "safe";
    if (parts[1]?.startsWith("--version") || parts[1] === "-v") return "safe";
    return "potentially-mutating";
  }
  if (parts[1] === "--version" || parts[1] === "-v" || parts[1] === "--help" || parts[1] === "-h") {
    return "safe";
  }
  return "potentially-mutating";
}

/**
 * Classify a full command line, handling chained commands (&& || ; |).
 * Returns "safe" only if ALL segments are safe.
 */
export function classifyBaseCommand(command: string): CommandClassification {
  // Split on chaining operators: &&, ||, ; (but not | which is piped to the same logical operation)
  // Also handle newlines as command separators
  const segments = command.split(/&&|\|\||;/);

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed) continue;
    const classification = classifySegment(trimmed);
    if (classification === "potentially-mutating") return "potentially-mutating";
  }

  return "safe";
}

// ---- PATH EXTRACTION ----

function extractRedirectPaths(command: string): string[] {
  const paths: string[] = [];
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

function extractOperatorPaths(command: string): string[] {
  const paths: string[] = [];
  const parts = command.trim().split(/\s+/);
  if (parts.length < 2) return paths;

  const base = parts[0].includes("/") ? parts[0].split("/").pop()! : parts[0];

  switch (base) {
    case "mv":
    case "cp":
    case "ln":
    case "install": {
      const nonFlags = parts.slice(1).filter((p) => !p.startsWith("-"));
      if (nonFlags.length > 0) {
        const dest = nonFlags[nonFlags.length - 1];
        if (dest && !dest.startsWith("-")) paths.push(dest);
      }
      break;
    }
    case "mkdir":
    case "touch":
    case "tee": {
      for (let i = 1; i < parts.length; i++) {
        if (!parts[i].startsWith("-")) paths.push(parts[i]);
      }
      break;
    }
    case "sed":
    case "perl":
    case "ruby": {
      // Inline editors: extract file args after -i, or last non-script argument
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
    case "dd": {
      const ofIdx = parts.findIndex((p) => p.startsWith("of="));
      if (ofIdx >= 0) paths.push(parts[ofIdx].slice(3));
      break;
    }
  }

  return paths;
}

export function extractTargetPaths(command: string, cwd: string): string[] {
  const allPaths: string[] = [];
  const redirects = extractRedirectPaths(command);
  const operators = extractOperatorPaths(command);

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
