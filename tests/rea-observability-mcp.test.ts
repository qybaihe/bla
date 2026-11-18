import {
  mkdtempSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  getRedteamReport,
  reaCheckoutPresent,
  reaDistReady,
  resolveReaRoot,
  runReaDriftCheck,
} from "../src/engine/rea-observability.js";
import { handleMcpRequest } from "../src/mcp/server.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function call(name: string, args: Record<string, unknown> = {}) {
  return handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
}

describe("REA observability engine (C2)", () => {
  it("runReaDriftCheck returns explicit unverified when REA is absent", () => {
    const missing = join(tmpdir(), `no-rea-${Date.now()}-${Math.random()}`);
    const report = runReaDriftCheck({ reaRoot: missing });
    expect(report.status).toBe("unverified");
    expect(report.notRedTeamEvidence).toBe(true);
    expect(report.reason).toMatch(/not found/i);
    expect(report.exitCode).toBeNull();
    expect(reaCheckoutPresent(missing)).toBe(false);
  });

  it("getRedteamReport returns unverified when report missing and REA unready", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-missing-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "no-report.json");
    const fakeRea = join(dir, "rea");
    mkdirSync(fakeRea);
    // No src/ → checkout absent; no dist → unready.
    const result = getRedteamReport({
      reaRoot: fakeRea,
      reportPath,
      execute: false,
    });
    expect(result.status).toBe("unverified");
    expect(result.reason).toMatch(/No empirical report/);
    expect(result.executed).toBe(false);
  });

  it("getRedteamReport reads a fixture report without needing REA", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-fixture-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    const fixture = {
      generatedAt: "test",
      pairs: [{ format: "wasm", before: { status: "ok" }, after: { status: "ok" } }],
      unverified: [],
    };
    writeFileSync(reportPath, JSON.stringify(fixture), "utf8");
    const fakeRea = join(dir, "rea-absent");
    const result = getRedteamReport({
      reaRoot: fakeRea,
      reportPath,
    });
    expect(result.status).toBe("available");
    expect(result.report).toMatchObject(fixture);
    expect(result.executed).toBe(false);
  });

  it("execute:true without REA dist is unverified (never silent pass)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-exec-"));
    tempDirs.push(dir);
    const fakeRea = join(dir, "rea");
    mkdirSync(join(fakeRea, "src"), { recursive: true });
    expect(reaDistReady(fakeRea)).toBe(false);
    const result = getRedteamReport({
      reaRoot: fakeRea,
      execute: true,
      reportPath: join(dir, "out.json"),
    });
    expect(result.status).toBe("unverified");
    expect(result.reason).toMatch(/dist not ready/i);
    expect(result.executed).toBe(false);
  });

  it("execute:true against a REA checkout the harness cannot call is unverified, not fail", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-moved-"));
    tempDirs.push(dir);
    // Built as far as the readiness check can tell, but REA's analyzers are not
    // where the harness names them — what a REA refactor looks like from here.
    const fakeRea = join(dir, "rea");
    mkdirSync(join(fakeRea, "src"), { recursive: true });
    mkdirSync(join(fakeRea, "dist", "go"), { recursive: true });
    writeFileSync(join(fakeRea, "dist", "go", "GoBinaryImage.js"), "// placeholder\n", "utf8");
    expect(reaDistReady(fakeRea)).toBe(true);

    const result = getRedteamReport({
      reaRoot: fakeRea,
      execute: true,
      reportPath: join(dir, "out.json"),
    });

    expect(result.executed).toBe(true);
    expect(result.exitCode).toBe(2);
    // `fail` would tell the caller REA read a hardened sample. Nothing was read.
    expect(result.status).toBe("unverified");
    expect(result.reason).toMatch(/could not call REA/);
    expect(result.reason).toMatch(/not a verdict on a shield/);
    expect(result.stderr).toMatch(/UNVERIFIED: the harness could not load REA's analyzers/);
    expect(result.report).toBeUndefined();
  });

  it("a report on disk that records harness errors reads as unverified, report attached", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-unmeasured-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    const fixture = {
      schema: "bla-redteam-rea/v1",
      status: "unverified",
      pairs: [],
      harnessErrors: [
        { format: "javascript", reason: "rea.analyzeJavaScriptStaticSource is not a function" },
      ],
    };
    writeFileSync(reportPath, JSON.stringify(fixture), "utf8");

    const result = getRedteamReport({ reaRoot: join(dir, "rea-absent"), reportPath });

    expect(result.status).toBe("unverified");
    expect(result.executed).toBe(false);
    expect(result.reason).toContain("could not call REA for 1 probe:");
    expect(result.reason).toContain(
      "javascript (rea.analyzeJavaScriptStaticSource is not a function)",
    );
    expect(result.reason).toMatch(/not measured/);
    expect(result.report).toMatchObject(fixture);
  });

  it("a measured report on disk still reads as available", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-measured-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    writeFileSync(
      reportPath,
      JSON.stringify({ schema: "bla-redteam-rea/v1", status: "measured", pairs: [], harnessErrors: [] }),
      "utf8",
    );

    const result = getRedteamReport({ reaRoot: join(dir, "rea-absent"), reportPath });

    expect(result.status).toBe("available");
    expect(result.reason).toBeUndefined();
  });

  it("a report on disk names the formats whose plant REA read through", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-not-stopped-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    writeFileSync(
      reportPath,
      JSON.stringify({
        schema: "bla-redteam-rea/v1",
        status: "measured",
        pairs: [],
        notStopped: ["pcap_capture"],
        harnessErrors: [],
      }),
      "utf8",
    );

    const result = getRedteamReport({ reaRoot: join(dir, "rea-absent"), reportPath });

    // Still an on-disk read, not a fresh verdict — but it says what it found.
    expect(result.status).toBe("available");
    expect(result.reason).toContain("pcap_capture");
    expect(result.reason).toContain("REA read the hardened sample");
  });
});

describe("REA observability MCP tools (C2)", () => {
  it("bla_rea_drift surfaces unverified as isError when REA absent", async () => {
    const missing = join(tmpdir(), `mcp-no-rea-${Date.now()}`);
    const res = await call("bla_rea_drift", { rea_root: missing });
    expect(res?.error).toBeUndefined();
    const result = res!.result as {
      isError: boolean;
      structuredContent: { status: string; notRedTeamEvidence: boolean };
    };
    expect(result.isError).toBe(true);
    expect(result.structuredContent.status).toBe("unverified");
    expect(result.structuredContent.notRedTeamEvidence).toBe(true);
  });

  it("bla_redteam_report reads fixture; missing path is unverified isError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-mcp-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    writeFileSync(
      reportPath,
      JSON.stringify({ generatedAt: "fixture", pairs: [], unverified: ["demo"] }),
      "utf8",
    );
    const ok = await call("bla_redteam_report", {
      report_path: reportPath,
      rea_root: join(dir, "no-rea"),
    });
    expect(ok?.error).toBeUndefined();
    const okResult = ok!.result as {
      isError?: boolean;
      structuredContent: { status: string; report: { generatedAt: string } };
    };
    expect(okResult.isError).not.toBe(true);
    expect(okResult.structuredContent.status).toBe("available");
    expect(okResult.structuredContent.report.generatedAt).toBe("fixture");

    const missing = await call("bla_redteam_report", {
      report_path: join(dir, "absent.json"),
      rea_root: join(dir, "no-rea"),
    });
    const missResult = missing!.result as {
      isError: boolean;
      structuredContent: { status: string };
    };
    expect(missResult.isError).toBe(true);
    expect(missResult.structuredContent.status).toBe("unverified");
  });

  it("bla_redteam_report is an error for a report whose probes never reached REA", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-rt-mcp-unmeasured-"));
    tempDirs.push(dir);
    const reportPath = join(dir, "empirical.json");
    writeFileSync(
      reportPath,
      JSON.stringify({
        schema: "bla-redteam-rea/v1",
        status: "unverified",
        pairs: [],
        harnessErrors: [{ format: "electron_asar", reason: "AsarHeader.js not found" }],
      }),
      "utf8",
    );

    const res = await call("bla_redteam_report", {
      report_path: reportPath,
      rea_root: join(dir, "no-rea"),
    });

    const result = res!.result as {
      isError: boolean;
      structuredContent: { status: string; reason: string };
    };
    expect(result.isError).toBe(true);
    expect(result.structuredContent.status).toBe("unverified");
    expect(result.structuredContent.reason).toContain("electron_asar (AsarHeader.js not found)");
  });

  it("resolveReaRoot honors REA_ROOT override path shape", () => {
    const custom = join(tmpdir(), "custom-rea-root");
    expect(resolveReaRoot(custom)).toBe(custom);
  });
});
