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
    const styles: Record<string, string> = {
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

    try {
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
            return { block: true, reason: "Permissions gate: force-flag blocked" };
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
    } catch (err) {
      console.error("[permissions-gate] Error in tool_call handler:", err);
      return { block: true, reason: `Permissions gate: internal error` };
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

    if (sub === "set") {
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
