import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  computeHardenRunId,
  HARDEN_SUMMARY_FILE_NAME,
  HARDEN_SUMMARY_SCHEMA,
  readHardenRunSummary,
} from "../src/engine/run-evidence.js";
import { hardenProject } from "../src/engine/harden.js";
import { handleMcpRequest } from "../src/mcp/server.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const JS = `export function unlockPremium(token) { return token === "LIVE-KEY"; }\n`;

async function call(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  return res!;
}

describe("harden run evidence (C1)", () => {
  it("computeHardenRunId is stable for identical planned work", () => {
    const identity = {
      blaVersion: "1.6.4",
      directory: "/tmp/proj",
      intensity: "bankrupt",
      weaveDecoys: false,
      selfSeal: false,
      artifacts: [
        { relativePath: "b.js", format: "javascript", outputPath: "/out/b.js" },
        { relativePath: "a.js", format: "javascript", outputPath: "/out/a.js" },
      ],
    };
    const shuffled = {
      ...identity,
      artifacts: [...identity.artifacts].reverse(),
    };
    expect(computeHardenRunId(identity)).toBe(computeHardenRunId(shuffled));
    expect(computeHardenRunId(identity)).toMatch(/^bla-run-[0-9a-f]{24}$/);
  });

  it("hardenProject emits runId + unsigned summary; lookup round-trips", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-run-ev-"));
    tempDirs.push(dir);
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist", "app.js"), JS, "utf8");

    const report = hardenProject({
      directory: dir,
      seed: "run-ev-1",
      intensity: "stealth",
    });
    expect(report.runId).toMatch(/^bla-run-[0-9a-f]{24}$/);
    expect(report.summaryPath).toBeDefined();
    expect(existsSync(report.summaryPath!)).toBe(true);

    const disk = JSON.parse(readFileSync(report.summaryPath!, "utf8")) as {
      schema: string;
      runId: string;
      signature: string;
    };
    expect(disk.schema).toBe(HARDEN_SUMMARY_SCHEMA);
    expect(disk.runId).toBe(report.runId);
    expect(disk.signature).toBe("unsigned");

    const byFile = readHardenRunSummary(report.summaryPath!, report.runId);
    expect(byFile.runId).toBe(report.runId);
    expect(byFile.runIdMatches).toBe(true);

    const byDir = readHardenRunSummary(report.outputDirectory);
    expect(byDir.runId).toBe(report.runId);
    expect(byDir.summaryPath).toContain(HARDEN_SUMMARY_FILE_NAME);

    // Dry-run still gets a runId (same planned work → same id) but no summary file.
    const dry = hardenProject({
      directory: dir,
      seed: "run-ev-1",
      intensity: "stealth",
      dryRun: true,
    });
    expect(dry.runId).toBe(report.runId);
    expect(dry.summaryPath).toBeUndefined();
  });

  it("readHardenRunSummary fails clearly on missing / bad id / pre-v2", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-run-bad-"));
    tempDirs.push(dir);
    expect(() => readHardenRunSummary(join(dir, "missing.json"))).toThrow(
      /Run summary not found/,
    );

    const v1 = join(dir, "old.json");
    writeFileSync(
      v1,
      JSON.stringify({
        schema: "bla-harden-summary/v1",
        directory: dir,
        artifacts: [],
      }),
      "utf8",
    );
    expect(() => readHardenRunSummary(v1)).toThrow(/no runId/);

    const v2 = join(dir, HARDEN_SUMMARY_FILE_NAME);
    writeFileSync(
      v2,
      JSON.stringify({
        schema: HARDEN_SUMMARY_SCHEMA,
        runId: "bla-run-aaaaaaaaaaaaaaaaaaaaaaaa",
        signature: "unsigned",
        artifacts: [],
      }),
      "utf8",
    );
    expect(() =>
      readHardenRunSummary(dir, "bla-run-bbbbbbbbbbbbbbbbbbbbbbbb"),
    ).toThrow(/Run id mismatch/);
  });

  it("MCP bla_run_lookup + bla_verify correlation; defend/protect carry runId", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-run-mcp-"));
    tempDirs.push(dir);
    mkdirSync(join(dir, "dist"));
    const input = join(dir, "dist", "app.js");
    writeFileSync(input, JS, "utf8");

    const hardenRes = await call("bla_harden", {
      directory: dir,
      seed: "run-mcp-1",
      intensity: "stealth",
      confirm_overwrite: true,
    });
    expect(hardenRes.error).toBeUndefined();
    const harden = (hardenRes.result as { structuredContent: Record<string, unknown> })
      .structuredContent;
    expect(harden.runId).toMatch(/^bla-run-[0-9a-f]{24}$/);
    const summaryPath = harden.summaryPath as string;
    expect(existsSync(summaryPath)).toBe(true);

    const lookupOk = await call("bla_run_lookup", {
      summary_path: harden.outputDirectory as string,
      run_id: harden.runId as string,
    });
    expect(lookupOk.error).toBeUndefined();
    expect((lookupOk.result as { isError?: boolean }).isError).not.toBe(true);
    const looked = (lookupOk.result as { structuredContent: { runId: string } })
      .structuredContent;
    expect(looked.runId).toBe(harden.runId);

    const lookupBad = await call("bla_run_lookup", {
      summary_path: summaryPath,
      run_id: "bla-run-000000000000000000000000",
    });
    expect((lookupBad.result as { isError: boolean }).isError).toBe(true);

    const missing = await call("bla_run_lookup", {
      summary_path: join(dir, "no-such-summary.json"),
    });
    expect((missing.result as { isError: boolean }).isError).toBe(true);

    const out = join(dir, "protected.js");
    const protectRes = await call("bla_protect", {
      input_path: input,
      output_path: out,
      seed: "run-mcp-protect",
      intensity: "stealth",
    });
    expect(protectRes.error).toBeUndefined();
    expect((protectRes.result as { isError?: boolean }).isError).not.toBe(true);
    const protectedPayload = (
      protectRes.result as { structuredContent: Record<string, unknown> }
    ).structuredContent;
    expect(protectedPayload.runId).toMatch(/^bla-run-[0-9a-f]{24}$/);
    expect(protectedPayload.runEvidence).toMatchObject({
      signature: "unsigned",
      schema: "bla-artifact-run/v1",
    });

    const verifyRes = await call("bla_verify", {
      target_path: out,
      summary_path: summaryPath,
      run_id: harden.runId as string,
    });
    expect(verifyRes.error).toBeUndefined();
    expect((verifyRes.result as { isError?: boolean }).isError).not.toBe(true);
    const verified = (
      verifyRes.result as {
        structuredContent: { runCorrelation: { runId: string; signature: string } };
      }
    ).structuredContent;
    expect(verified.runCorrelation.runId).toBe(harden.runId);
    expect(verified.runCorrelation.signature).toBe("unsigned");

    const verifyOrphanId = await call("bla_verify", {
      target_path: out,
      run_id: harden.runId as string,
    });
    expect((verifyOrphanId.result as { isError: boolean }).isError).toBe(true);
  });
});
