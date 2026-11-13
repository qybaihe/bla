import { afterEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ failWasm: false }));

vi.mock("../src/shields/formats/wasm.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/shields/formats/wasm.js")>();
  return {
    ...actual,
    protectWasmBinary: (...args: Parameters<typeof actual.protectWasmBinary>) => {
      if (state.failWasm) throw new Error("wasm probe failure");
      return actual.protectWasmBinary(...args);
    },
  };
});

import { runDoctor } from "../src/setup/doctor.js";
import { formatDoctorReport } from "../src/ui/reporter.js";

const stripAnsi = (text: string): string => text.replace(/\x1b\[[0-9;]*m/g, "");
const readinessLine = (text: string): string =>
  stripAnsi(text).split("\n").find((line) => line.includes("BLA Doctor Readiness")) ?? "";

describe("doctor text report reflects the real readiness verdict", () => {
  afterEach(() => {
    state.failWasm = false;
  });

  it("prints HEALTHY and no issues section when every check passes", () => {
    const doc = runDoctor({ homeDir: "/nonexistent-bla-home", sqliteAvailableOverride: true });
    expect(doc.status).toBe("pass");
    const text = formatDoctorReport(doc);
    expect(readinessLine(text)).toContain("HEALTHY");
    expect(readinessLine(text)).not.toContain("UNHEALTHY");
    expect(stripAnsi(text)).not.toContain("Issues (");
  });

  it("prints UNHEALTHY and lists the issues when an engine is unavailable", () => {
    const doc = runDoctor({ homeDir: "/nonexistent-bla-home", sqliteAvailableOverride: false });
    expect(doc.healthy).toBe(false);
    const text = formatDoctorReport(doc);
    expect(readinessLine(text)).toContain("UNHEALTHY");
    expect(stripAnsi(text)).toContain(`Issues (${doc.issues.length}):`);
    for (const issue of doc.issues) {
      expect(stripAnsi(text)).toContain(issue);
    }
  });

  it("colors an unavailable engine red instead of green", () => {
    const doc = runDoctor({ homeDir: "/nonexistent-bla-home", sqliteAvailableOverride: false });
    const sqliteLine =
      formatDoctorReport(doc)
        .split("\n")
        .find((line) => line.includes("SQLite Honey-Table")) ?? "";
    expect(sqliteLine).toContain("\x1b[31munavailable");
    expect(sqliteLine).not.toContain("\x1b[32munavailable");
  });

  it("reports an aliased engine failure once, under its primary name", () => {
    state.failWasm = true;
    const doc = runDoctor({ homeDir: "/nonexistent-bla-home", sqliteAvailableOverride: true });
    expect(doc.engines.wasmBinaryShield).toBe("unavailable");
    expect(doc.engines.wasmLeb128).toBe("unavailable");
    const engineIssues = doc.issues.filter((issue) => issue.startsWith("Engine '"));
    expect(engineIssues).toHaveLength(1);
    expect(engineIssues[0]).toContain("'wasmBinaryShield'");
    expect(doc.issues.some((issue) => issue.includes("'wasmLeb128'"))).toBe(false);
  });
});
