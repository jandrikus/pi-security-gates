import { realpathSync, existsSync } from "node:fs";
import { resolve, relative, sep } from "node:path";
import { homedir } from "node:os";

export function resolveWriteTarget(rawPath: string, cwd: string): string {
  return resolve(cwd, rawPath);
}

export function isInsideProject(
  path: string,
  projectRoot: string,
  checkSymlinks: boolean,
): boolean {
  let canonical = path;

  if (checkSymlinks) {
    try {
      if (existsSync(path)) {
        canonical = realpathSync(path);
      }
    } catch {
      // Broken symlink or ENOENT → fall back to resolved path
      canonical = resolve(path);
    }
  }

  const normalizedRoot = resolve(projectRoot) + sep;
  const normalizedPath = resolve(canonical) + sep;
  return normalizedPath.startsWith(normalizedRoot);
}

export function isDeniedInside(
  path: string,
  projectRoot: string,
  deniedGlobs: string[],
): boolean {
  const rel = relative(projectRoot, resolve(path));
  if (rel === "" || rel.startsWith("..")) return false; // outside project, not "inside" deny

  for (const glob of deniedGlobs) {
    if (matchGlob(rel, glob)) return true;
  }
  return false;
}

export function isAllowedOutside(
  path: string,
  allowedPaths: string[],
  cwd: string,
): boolean {
  const resolved = resolve(path);
  for (const allowed of allowedPaths) {
    const expanded = allowed.startsWith("~") ? allowed.replace("~", homedir()) : allowed;
    if (resolved.startsWith(resolve(expanded))) return true;
    if (resolved === "/dev/null") return true;
  }
  return false;
}

/**
 * Simple glob matching for denyWriteInside patterns.
 * Supports * (any chars within segment), ** (recursive), ? (single char).
 * Subset of minimatch — no braces, negation, or character classes.
 */
function matchGlob(target: string, pattern: string): boolean {
  const parts = pattern.split(/(\*\*|\*|\?|[^*?]+)/).filter(Boolean);
  let regexStr = "^";
  for (const part of parts) {
    if (part === "**") regexStr += ".*";
    else if (part === "*") regexStr += "[^/]*";
    else if (part === "?") regexStr += "[^/]";
    else regexStr += part.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  regexStr += "$";
  return new RegExp(regexStr).test(target);
}
