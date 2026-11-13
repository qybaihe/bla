import { relative, resolve, sep } from "node:path";
import { walkBounded } from "./walk.js";

/**
 * Compiles a forward-slash glob (`*`, `?`, double-star) anchored to a root
 * directory into an anchored regular expression over POSIX-style relative
 * paths.
 *
 * - double-star followed by a slash matches zero or more directory segments
 * - double-star matches across directory separators
 * - `*` matches within one segment
 * - `?` matches a single non-separator character
 */
export function globToRegExp(pattern: string): RegExp {
  let out = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]!;
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        if (pattern[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
      continue;
    }
    if (ch === "?") {
      out += "[^/]";
      continue;
    }
    if ("\\^$.|+()[]{}".includes(ch)) {
      out += `\\${ch}`;
      continue;
    }
    out += ch;
  }
  return new RegExp(`^${out}$`);
}

/**
 * Expands glob patterns against files under `root` (bounded, symlink-safe
 * walk). Returns absolute paths sorted by the stable walk order.
 */
export function expandSiblingGlobs(
  root: string,
  patterns: readonly string[],
): string[] {
  const clean = patterns.filter((p) => p.length > 0);
  if (clean.length === 0) return [];
  const absRoot = resolve(root);
  const regexes = clean.map(globToRegExp);
  const files = walkBounded(absRoot, {
    maxDepth: 16,
    maxFiles: 100_000,
    skipHiddenDirs: true,
    sortEntries: true,
  });
  const matches: string[] = [];
  for (const abs of files) {
    const rel = relative(absRoot, abs).split(sep).join("/");
    if (regexes.some((re) => re.test(rel))) matches.push(abs);
  }
  return matches;
}
