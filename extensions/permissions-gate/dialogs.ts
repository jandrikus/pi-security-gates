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
