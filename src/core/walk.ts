import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export interface BoundedWalkOptions {
  /** Maximum directory depth to descend (root = 0). */
  readonly maxDepth: number;
  /** Stop after this many accepted files. Use Number.MAX_SAFE_INTEGER for no cap. */
  readonly maxFiles: number;
  readonly skipDirs?: ReadonlySet<string>;
  /** Skip directories whose name starts with "." (hidden files are still allowed). */
  readonly skipHiddenDirs?: boolean;
  /** Sort directory entries by name for stable, platform-independent paging. */
  readonly sortEntries?: boolean;
  /**
   * Descend into a directory at exactly `maxDepth`. Default true. Set false to
   * match walkers that treat `maxDepth` as the last depth they inspect.
   */
  readonly descendAtMaxDepth?: boolean;
  /** When set, files larger than this are skipped (requires an extra stat). */
  readonly maxFileBytes?: number;
  /** Final filter; called only for regular files before they are pushed. */
  readonly accept?: (fullPath: string, name: string) => boolean;
}

/**
 * Bounded, symlink-safe directory walk shared by discovery and packaging lints.
 * Directory symlinks are not descended because `Dirent.isDirectory()` is false
 * for them, and read errors are treated as an empty directory.
 */
export function walkBounded(root: string, options: BoundedWalkOptions): string[] {
  const out: string[] = [];
  const {
    maxDepth,
    maxFiles,
    skipDirs,
    skipHiddenDirs = false,
    sortEntries = false,
    descendAtMaxDepth = true,
    maxFileBytes,
    accept,
  } = options;

  const visit = (dir: string, depth: number): void => {
    if (out.length >= maxFiles || depth > maxDepth) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    if (sortEntries) {
      entries = entries.slice().sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) return;
      if (entry.isDirectory()) {
        if (skipDirs?.has(entry.name)) continue;
        if (skipHiddenDirs && entry.name.startsWith(".")) continue;
        if (!descendAtMaxDepth && depth >= maxDepth) continue;
        visit(join(dir, entry.name), depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const full = join(dir, entry.name);
      if (maxFileBytes !== undefined) {
        let size: number;
        try {
          const stat = statSync(full);
          if (!stat.isFile()) continue;
          size = stat.size;
        } catch {
          continue;
        }
        if (size > maxFileBytes) continue;
      }
      if (accept !== undefined && !accept(full, entry.name)) continue;
      out.push(full);
    }
  };

  visit(root, 0);
  return out;
}