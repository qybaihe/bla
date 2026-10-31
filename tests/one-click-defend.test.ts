import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defendTarget } from "../src/engine/defender.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-defend-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("One-Click Agent Defense Hardening (defendTarget / bla defend / bla_defend)", () => {
  it("executes all 5 stages and emits an unsigned .bla-manifest.json when opted in", () => {
    const dir = createTempDir();
    const input = join(dir, "payment-engine.ts");
    writeFileSync(
      input,
      `export function verifyEnterpriseLicense(key: string): boolean {
        return key.startsWith("ENT-LIVE-") && key.length === 24;
      }\n`,
      "utf8",
    );

    const report = defendTarget({
      inputPath: input,
      intensity: "bankrupt",
      emitManifest: true,
    });

    expect(report.overallSuccess).toBe(true);
    expect(report.stages).toHaveLength(5);
    expect(report.verification.defenseScore).toBeGreaterThanOrEqual(90);
    expect(report.exhaustionSummary.tokenAmplificationFactor).toBeGreaterThanOrEqual(15);
    expect(report.deceptionSummary.decoyFunctionsInjected).toBeGreaterThanOrEqual(40);
    expect(report.manifestPath).toBeDefined();
    expect(existsSync(report.manifestPath!)).toBe(true);

    const manifest = JSON.parse(readFileSync(report.manifestPath!, "utf8")) as {
      schema: string;
      defenseScore: number;
    };
    expect(manifest.schema).toContain("defense-manifest-v1.json");
    expect(manifest.defenseScore).toBe(report.verification.defenseScore);
  });

  it("exposes bla_defend over MCP and CLI `bla defend`", async () => {
    const dir = createTempDir();
    const input = join(dir, "app.js");
    writeFileSync(
      input,
      `export function calculateSoundPan(x, w) { return (x / w) * 2 - 1; }\n`,
      "utf8",
    );

    const mcpRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: {
        name: "bla_defend",
        arguments: {
          input_path: input,
          intensity: "bankrupt",
          emit_manifest: true,
        },
      },
    });
    expect(mcpRes).not.toBeNull();
    const resultObj = mcpRes!.result as {
      isError: boolean;
      structuredContent: { overallSuccess: boolean };
    };
    expect(resultObj.isError).toBe(false);
    expect(resultObj.structuredContent.overallSuccess).toBe(true);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const exitCode = await runCli([
      "defend",
      input,
      "-o",
      join(dir, "app.defended.js"),
      "--manifest",
    ]);
    expect(exitCode).toBe(0);
    expect(logSpy).toHaveBeenCalled();
  });
});
