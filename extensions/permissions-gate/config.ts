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
