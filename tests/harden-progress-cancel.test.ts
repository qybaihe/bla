import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initBlaConfig } from "../src/core/config.js";
import { inspectReleaseExposure } from "../src/core/release-exposure.js";
import { auditTarget } from "../src/engine/auditor.js";
import { runShowcaseBenchmark } from "../src/engine/benchmark.js";
import { defendTarget } from "../src/engine/defender.js";
import {
  formatHardenProjectReport,
  hardenProject,
  type HardenProgressEvent,
} from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { emitCompileTimeNativeHeader } from "../src/shields/formats/headers.js";
import { runDoctor } from "../src/setup/doctor.js";
import {
  handleMcpRequest,
  type McpEngineHandlers,
} from "../src/mcp/server.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-harden-cancel-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function writeTinyJsTree(root: string, names: string[]): void {
  const dist = join(root, "dist");
  mkdirSync(dist, { recursive: true });
  for (const name of names) {
    writeFileSync(
      join(dist, name),
      `export function probe_${name.replace(/\W/g, "_")}(x){return x===1}\n`,
      "utf8",
    );
  }
}

function baseHandlers(
  hardenOverride?: McpEngineHandlers["hardenProject"],
): McpEngineHandlers {
  return {
    hardenProject: hardenOverride ?? hardenProject,
    defendTarget,
    auditTarget,
    protectTarget,
    verifyTarget,
    runShowcaseBenchmark,
    emitCompileTimeNativeHeader,
    runDoctor,
    inspectReleaseExposure,
    initBlaConfig,
  };
}

describe("bla_harden progress + cooperative cancel (#75)", () => {
  it("emits start/artifact/done progress and lists written on success", () => {
    const root = createTempDir();
    writeTinyJsTree(root, ["a.js", "b.js"]);
    const events: HardenProgressEvent[] = [];
    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "progress-ok",
      onProgress: (ev) => events.push(ev),
    });
    expect(report.cancelled).toBeUndefined();
    expect(report.overallSuccess).toBe(true);
    expect(report.written?.length).toBe(2);
    expect(events[0]?.phase).toBe("start");
    expect(events.some((e) => e.phase === "artifact")).toBe(true);
    expect(events.at(-1)?.phase).toBe("done");
    expect(events.at(-1)?.written.length).toBe(2);
  });

  it("abort mid-run sets cancelled and lists only already-written paths", () => {
    const root = createTempDir();
    writeTinyJsTree(root, ["one.js", "two.js", "three.js"]);
    const ctl = new AbortController();
    const events: HardenProgressEvent[] = [];
    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "progress-cancel",
      signal: ctl.signal,
      onProgress: (ev) => {
        events.push(ev);
        if (ev.phase === "artifact" && ev.index === 0) ctl.abort("test-cancel");
      },
    });
    expect(report.cancelled).toBe(true);
    expect(report.overallSuccess).toBe(false);
    expect(report.written?.length).toBe(1);
    expect(existsSync(report.written![0]!)).toBe(true);
    const outRoot = report.outputDirectory;
    expect(existsSync(join(outRoot, "dist", "two.js"))).toBe(false);
    expect(existsSync(join(outRoot, "dist", "three.js"))).toBe(false);
    expect(events.some((e) => e.phase === "cancelled")).toBe(true);
    const text = formatHardenProjectReport(report);
    expect(text).toContain("CANCELLED");
    expect(text).toContain("written:");
  });

  it("MCP notifications/cancelled aborts in-flight bla_harden via requestId", async () => {
    const root = createTempDir();
    writeTinyJsTree(root, ["alpha.js", "beta.js"]);
    const reqId = "harden-cancel-1";
    const handlers = baseHandlers((opts = {}) =>
      hardenProject({
        ...opts,
        onProgress: (ev) => {
          opts.onProgress?.(ev);
          if (ev.phase === "artifact" && ev.index === 0) {
            void handleMcpRequest({
              jsonrpc: "2.0",
              method: "notifications/cancelled",
              params: { requestId: reqId, reason: "client-cancel" },
            });
          }
        },
      }),
    );
    const res = await handleMcpRequest(
      {
        jsonrpc: "2.0",
        id: reqId,
        method: "tools/call",
        params: {
          name: "bla_harden",
          arguments: {
            directory: root,
            intensity: "bankrupt",
            seed: "mcp-cancel",
            confirm_overwrite: true,
          },
          _meta: { progressToken: "tok-1" },
        },
      },
      handlers,
    );

    expect(res).not.toBeNull();
    const structured = (
      res as {
        result: {
          structuredContent: {
            cancelled?: boolean;
            written?: string[];
            overallSuccess: boolean;
          };
        };
      }
    ).result.structuredContent;
    expect(structured.cancelled).toBe(true);
    expect(structured.overallSuccess).toBe(false);
    expect(structured.written?.length).toBe(1);
  });

  it("notifications/cancelled without id returns null and is a no-op when idle", async () => {
    const res = await handleMcpRequest({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId: "nobody" },
    });
    expect(res).toBeNull();
  });
});
