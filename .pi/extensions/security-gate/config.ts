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
