import { describe, expect, it } from "vitest";
import { parseSiteSyncArgs, planSiteSync } from "../scripts/site-sync-plan.mjs";

describe("site sync dry-run planning", () => {
  it("parses --dry-run from argv", () => {
    expect(parseSiteSyncArgs(["node", "sync-site.mjs", "--dry-run"]).dryRun).toBe(
      true,
    );
    expect(parseSiteSyncArgs(["node", "sync-site.mjs"]).dryRun).toBe(false);
  });

  it("treats an empty porcelain status as up to date", () => {
    const plan = planSiteSync("");
    expect(plan.upToDate).toBe(true);
    expect(plan.changedPaths).toEqual([]);
  });

  it("extracts changed paths from porcelain status lines", () => {
    const plan = planSiteSync(" M website/index.html\n?? website/new.md\n");
    expect(plan.upToDate).toBe(false);
    expect(plan.changedPaths).toEqual(["website/index.html", "website/new.md"]);
  });
});
