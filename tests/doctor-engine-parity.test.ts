import { describe, expect, it } from "vitest";
import { runDoctor } from "../src/setup/doctor.js";
import { formatDoctorReport } from "../src/ui/reporter.js";

describe("doctor reports every empirically-verified shield", () => {
  const report = runDoctor({ homeDir: "/nonexistent-bla-home" });

  it("probes the AI model, Erlang BEAM and EVM bytecode engines", () => {
    expect(report.engines.aiModelShield).toBe("ready");
    expect(report.engines.erlangBeamShield).toBe("ready");
    expect(report.engines.evmBytecodeShield).toBe("ready");
  });

  it("keeps every pure-TypeScript shield engine available", () => {
    const unavailable = Object.entries(report.engines)
      .filter(([name]) => name !== "sqliteRuntime")
      .filter(([, status]) => status === "unavailable");
    expect(unavailable).toEqual([]);
  });

  it("surfaces the newly-probed subsystems in the CLI readiness report", () => {
    const text = formatDoctorReport(report);
    expect(text).toContain("AI Model (Safetensors / GGUF)");
    expect(text).toContain("Erlang BEAM");
    expect(text).toContain("EVM Bytecode");
    expect(text).toContain("SQLite");
  });
});
