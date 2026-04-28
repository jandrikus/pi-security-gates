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
