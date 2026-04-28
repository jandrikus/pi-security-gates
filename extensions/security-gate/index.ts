import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";
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

  function checkPath(
    resolvedPath: string,
  ): { allowed: boolean; reason?: string } {
    if (isDeniedInside(resolvedPath, projectRoot, config.denyWriteInside)) {
      return { allowed: false, reason: "protected internal path" };
    }
    if (isInsideProject(resolvedPath, projectRoot, config.checkSymlinks)) {
      return { allowed: true };
    }
    if (isAllowedOutside(resolvedPath, config.allowWriteOutside, projectRoot)) {
      return { allowed: true };
    }
    if (config.memoryEnabled && isPathRemembered(resolvedPath, memory)) {
      return { allowed: true };
    }
    return { allowed: false, reason: "outside project boundary" };
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
    memory = config.memoryEnabled
      ? loadSecurityMemory(projectRoot)
      : { version: 1, allowedExternalPaths: [], allowedExternalPatterns: [] };

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

    try {
      // --- write tool ---
      if (event.toolName === "write" || event.toolName === "edit") {
        const rawPath = (event.input as { path?: string }).path;
        if (!rawPath) return;
        const resolvedPath = resolveWriteTarget(rawPath, projectRoot);
        const check = checkPath(resolvedPath);
        if (!check.allowed) {
          if (config.interactiveConfirmOutside && ctx.hasUI) {
            const result = await confirmBoundaryViolation(
              ctx, event.toolName, resolvedPath, projectRoot, memory, config.memoryEnabled,
            );
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
        if (classification === "safe") return;

        const targets = extractTargetPaths(command, projectRoot);
        if (targets.length === 0) {
          // Potentially mutating but no clear file target — ask the user
          if (config.interactiveConfirmOutside && ctx.hasUI) {
            const shortCmd = command.split(/&&|;|\|\|/)[0].trim().slice(0, 80);
            const choice = await ctx.ui.select(
              `🤔 Unclear Command

Command: ${shortCmd}...

The security gate can't determine which files this command would touch.
Allow it to run?`,
              ["Allow this once", "Block"],
            );
            if (choice === "Allow this once") {
              return;
            }
            return { block: true, reason: "Security gate: unclear command blocked" };
          }
          return {
            block: true,
            reason: "Security gate: potentially mutating command with no clear file target",
          };
        }

        for (const target of targets) {
          const check = checkPath(target);
          if (!check.allowed) {
            if (config.interactiveConfirmOutside && ctx.hasUI) {
              const result = await confirmBoundaryViolation(
                ctx, "bash", target, projectRoot, memory, config.memoryEnabled,
              );
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
    } catch (err) {
      console.error("[security-gate] Error in tool_call handler:", err);
      return { block: true, reason: "Security gate: internal error" };
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
