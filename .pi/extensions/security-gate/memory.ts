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
  const r: SecurityMemory = {
    version: typeof o.version === "number" ? o.version : 1,
    allowedExternalPaths: [],
    allowedExternalPatterns: [],
  };
  if (Array.isArray(o.allowedExternalPaths)) {
    for (const p of o.allowedExternalPaths) {
      if (typeof p === "object" && p !== null) {
        const e = p as Record<string, unknown>;
        r.allowedExternalPaths.push({
          path: String(e.path ?? ""),
          approvedAt: typeof e.approvedAt === "number" ? e.approvedAt : Date.now(),
        });
      }
    }
  }
  if (Array.isArray(o.allowedExternalPatterns)) {
    for (const p of o.allowedExternalPatterns) {
      if (typeof p === "object" && p !== null) {
        const e = p as Record<string, unknown>;
        r.allowedExternalPatterns.push({
          fingerprint: String(e.fingerprint ?? ""),
          targetPattern: String(e.targetPattern ?? ""),
          approvedAt: typeof e.approvedAt === "number" ? e.approvedAt : Date.now(),
        });
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
