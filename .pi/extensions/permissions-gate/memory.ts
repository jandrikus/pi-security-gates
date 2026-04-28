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
