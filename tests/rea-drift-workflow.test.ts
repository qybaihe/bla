import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const workflow = readFileSync(
  join(process.cwd(), ".github", "workflows", "rea-drift.yml"),
  "utf8",
);

/**
 * `npm run verify:rea` needs a REA checkout on disk. On a hosted runner the
 * sibling-directory fallback in `ci.yml` can never resolve, so that step always
 * skips and the gate is effectively dead. This workflow is the only place the
 * gate actually runs, which makes it worth pinning down.
 */
describe("REA drift workflow", () => {
  it("pins REA to a full commit SHA", () => {
    const pinned = /REA_PINNED_REVISION:\s*([0-9a-f]+)/.exec(workflow)?.[1];
    expect(pinned).toMatch(/^[0-9a-f]{40}$/);
  });

  it("checks out REA and points the harness at it", () => {
    expect(workflow).toMatch(/repository:\s*morluto\/rea/);
    expect(workflow).toMatch(/ref:\s*\$\{\{\s*env\.REA_PINNED_REVISION\s*\}\}/);
    expect(workflow).toMatch(/REA_ROOT:\s*\$\{\{\s*github\.workspace\s*\}\}\/rea/);
    expect(workflow).toMatch(/npm run verify:rea/);
  });

  it("runs the informational upstream comparison without failing the workflow", () => {
    expect(workflow).toMatch(/ref:\s*main/);
    expect(workflow).toMatch(/continue-on-error:\s*true/);
  });

  it("pins third-party actions by SHA, like the other workflows", () => {
    const used = [...workflow.matchAll(/uses:\s*([^\s]+)/g)].map((m) => m[1]!);
    expect(used.length).toBeGreaterThan(0);
    for (const action of used) expect(action).toMatch(/@[0-9a-f]{40}$/);
  });

  it("declares read-only permissions", () => {
    expect(workflow).toMatch(/permissions:\s*\n\s*contents:\s*read/);
  });
});
