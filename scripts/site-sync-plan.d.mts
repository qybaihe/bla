export function parseSiteSyncArgs(argv: readonly string[]): { dryRun: boolean };
export function planSiteSync(porcelainOutput: string): {
  upToDate: boolean;
  changedPaths: readonly string[];
};
