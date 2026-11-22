export interface SyncSiteOptions {
  readonly websiteDir?: string;
  readonly repoUrl?: string;
  readonly tmpBaseDir?: string;
  readonly dryRun?: boolean;
  readonly quiet?: boolean;
  readonly gitEnv?: NodeJS.ProcessEnv;
}

export interface SyncSiteResult {
  readonly action: "up-to-date" | "dry-run" | "pushed";
  readonly changedPaths: readonly string[];
}

export function syncSite(options?: SyncSiteOptions): SyncSiteResult;
