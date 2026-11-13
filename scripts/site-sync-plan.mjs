/**
 * Pure planning helpers for scripts/sync-site.mjs so the dry-run decision is
 * unit-testable without cloning or pushing anything.
 */

/**
 * @param {readonly string[]} argv
 * @returns {{ dryRun: boolean }}
 */
export function parseSiteSyncArgs(argv) {
  return { dryRun: argv.includes("--dry-run") };
}

/**
 * @param {string} porcelainOutput `git status --porcelain` text
 * @returns {{ upToDate: boolean, changedPaths: readonly string[] }}
 */
export function planSiteSync(porcelainOutput) {
  const changedPaths = porcelainOutput
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0)
    // Porcelain lines look like "XY path" — drop the 3-character status prefix.
    .map((line) => line.slice(3));
  return { upToDate: changedPaths.length === 0, changedPaths };
}
