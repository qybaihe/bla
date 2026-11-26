import { relative, resolve, sep } from "node:path";
import { walkBounded } from "./walk.js";

const restrictedDirectories = new Set(["node_modules", ".git"]);

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
      // Consume the whole run first. Emitting one fragment per `*` chains
      // nested quantifiers, and `**********x` then backtracks exponentially on
      // a name that does not match.
      let end = i;
      while (pattern[end] === "*") end += 1;
      if (end - i >= 2) {
        if (pattern[end] === "/") {
          out += "(?:.*/)?";
          i = end;
        } else {
          out += ".*";
          i = end - 1;
        }
      } else {
        out += "[^/]*";
        i = end - 1;
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
  const rules = patterns.filter((pattern) => pattern.length > 0).map((pattern) => {
    const parts = pattern.split("/");
    const explicitDirectories = parts.slice(0, -1).flatMap((part, index) =>
      restrictedDirectories.has(part) ? [globToRegExp(parts.slice(0, index + 1).join("/"))] : [],
    );
    return { file: globToRegExp(pattern), explicitDirectories };
  });
  if (rules.length === 0) return [];
  const absRoot = resolve(root);
  const relativeParts = (path: string): string[] => relative(absRoot, path).split(sep);
  const restrictedPrefixes = (parts: string[]): string[] => parts.flatMap((part, index) =>
    restrictedDirectories.has(part) ? [parts.slice(0, index + 1).join("/")] : [],
  );
  const explicitlyAllows = (prefixes: string[], directories: RegExp[]): boolean =>
    prefixes.every((prefix) => directories.some((re) => re.test(prefix)));
  return walkBounded(absRoot, {
    maxDepth: 16,
    maxFiles: 100_000,
    sortEntries: true,
    skipDir: (path, name) => {
      if (!restrictedDirectories.has(name)) return name.startsWith(".");
      const prefixes = restrictedPrefixes(relativeParts(path));
      return !rules.some((rule) => explicitlyAllows(prefixes, rule.explicitDirectories));
    },
    accept: (path) => {
      const parts = relativeParts(path);
      const rel = parts.join("/");
      const prefixes = restrictedPrefixes(parts.slice(0, -1));
      return rules.some((rule) => rule.file.test(rel) && explicitlyAllows(prefixes, rule.explicitDirectories));
    },
  });
}
