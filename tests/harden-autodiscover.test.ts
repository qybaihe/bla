import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  discoverHardenableArtifacts,
  formatHardenProjectReport,
  hardenProject,
} from "../src/engine/harden.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { runCli } from "../src/cli.js";
import { writeZipArchive } from "../src/shields/formats/archive.js";
import { buildSampleSqliteDatabase } from "../src/shields/formats/sqlite.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-harden-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function minimalDex(): Buffer {
  const dex = Buffer.alloc(112, 0);
  dex.write("dex\n035\0", 0, "ascii");
  dex.writeUInt32LE(112, 32);
  dex.writeUInt32LE(112, 36);
  dex.writeUInt32LE(0x12345678, 40);
  return dex;
}

function minimalWasm(): Buffer {
  // \0asm + version 1
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
}

describe("bla_harden auto-discovery + one-sentence UX", () => {
  it("discovers mixed artifact types under dist/ and hardens them all", () => {
    const root = createTempDir();
    const dist = join(root, "dist");
    mkdirSync(dist, { recursive: true });

    writeFileSync(
      join(dist, "app.js"),
      `export function unlockPremium(token) { return token === "LIVE-KEY"; }\n`,
      "utf8",
    );
    writeFileSync(join(dist, "module.wasm"), minimalWasm());
    writeFileSync(join(dist, "classes.dex"), minimalDex());
    // Erlang BEAM (FOR1/BEAM)
    const beamForm = Buffer.concat([
      Buffer.from("BEAM", "latin1"),
      Buffer.from("AtU8", "latin1"),
      Buffer.from([0, 0, 0, 5, 0, 0, 0, 1, 1, 0x61, 0, 0]),
    ]);
    const beam = Buffer.concat([
      Buffer.from("FOR1", "latin1"),
      (() => { const b = Buffer.alloc(4); b.writeUInt32BE(beamForm.length); return b; })(),
      beamForm,
    ]);
    writeFileSync(join(dist, "mod.beam"), beam);
    writeFileSync(join(dist, "Vault.evm"), Buffer.from("00", "hex"));
    // Classic pcap global header
    const pcap = Buffer.alloc(24, 0);
    pcap.writeUInt32LE(0xa1b2c3d4, 0);
    pcap.writeUInt16LE(2, 4);
    pcap.writeUInt16LE(4, 6);
    pcap.writeUInt32LE(65535, 16);
    pcap.writeUInt32LE(1, 20);
    writeFileSync(join(dist, "traffic.pcap"), pcap);
    writeFileSync(
      join(dist, "kernels.ptx"),
      `.version 7.5\n.target sm_70\n.address_size 64\n.visible .entry k(.param .u64 a){ ret; }\n`,
    );
    // Minimal well-formed UF2 block (not-main-flash decoy carrier)
    const uf2 = Buffer.alloc(512, 0);
    uf2.writeUInt32LE(0x0a324655, 0);
    uf2.writeUInt32LE(0x9e5d5157, 4);
    uf2.writeUInt32LE(0x00002001, 8); // familyId | notMainFlash
    uf2.writeUInt32LE(0, 12);
    uf2.writeUInt32LE(16, 16);
    uf2.writeUInt32LE(0, 20);
    uf2.writeUInt32LE(1, 24);
    uf2.writeUInt32LE(0xe48bff56, 28);
    uf2.writeUInt32LE(0x0ab16f30, 508);
    writeFileSync(join(dist, "board.uf2"), uf2);

    writeFileSync(
      join(dist, "payload.py"),
      "def verify_license(key: str) -> bool:\n    return key.startswith('ENT-')\n",
      "utf8",
    );
    // Noise that must be ignored
    mkdirSync(join(root, "node_modules", "left-pad"), { recursive: true });
    writeFileSync(join(root, "node_modules", "left-pad", "index.js"), "module.exports=1\n");
    writeFileSync(join(root, "README.md"), "# demo\n");

    const discovered = discoverHardenableArtifacts(root);
    const formats = discovered.map((d) => d.format).sort();
    expect(formats).toEqual(
      expect.arrayContaining([
        "javascript",
        "wasm",
        "android-dex",
        "python-source",
        "erlang-beam",
        "evm-bytecode",
        "pcap-capture",
        "gpu-ptx",
        "firmware-uf2",
      ]),
    );
    expect(discovered.every((d) => !d.path.includes("node_modules"))).toBe(true);

    const report = hardenProject({
      directory: root,
      intensity: "bankrupt",
      seed: "harden-mix-v1",
      emitManifest: true,
    });

    expect(report.discoveredCount).toBeGreaterThanOrEqual(4);
    expect(report.hardenedCount).toBe(report.discoveredCount);
    expect(report.failedCount).toBe(0);
    expect(report.overallSuccess).toBe(true);
    expect(report.oneSentenceUsage).toContain("bla_harden");

    for (const a of report.artifacts) {
      expect(a.success).toBe(true);
      expect(a.defenseScore).toBeGreaterThanOrEqual(50);
      expect(existsSync(a.outputPath)).toBe(true);
      const bytes = readFileSync(a.outputPath);
      // Every hardened format should still be loadable / magic-valid
      if (a.format === "wasm") {
        expect(bytes.subarray(0, 4).toString("latin1")).toBe("\0asm");
      }
      if (a.format === "android-dex") {
        expect(bytes.subarray(0, 4).toString("latin1")).toBe("dex\n");
        expect(bytes.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
      }
      if (a.format === "javascript") {
        expect(bytes.toString("utf8")).toContain("unlockPremium");
      }
      if (a.format === "python-source") {
        expect(bytes.toString("utf8")).toContain("verify_license");
      }
    }
  });

  it("exposes bla_harden over MCP and CLI `bla harden`", async () => {
    const root = createTempDir();
    const dist = join(root, "dist");
    mkdirSync(dist, { recursive: true });
    writeFileSync(
      join(dist, "core.js"),
      `export const secret = (k) => k.length > 8;\n`,
      "utf8",
    );

    const mcpRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: {
        name: "bla_harden",
        arguments: { directory: root, intensity: "bankrupt" },
      },
    });
    expect(mcpRes?.result).toBeDefined();
    const structured = (mcpRes!.result as { structuredContent: { overallSuccess: boolean; hardenedCount: number; discoveredCount: number } }).structuredContent;
    expect(structured.discoveredCount).toBeGreaterThanOrEqual(1);
    expect(structured.hardenedCount).toBe(structured.discoveredCount);
    expect(structured.overallSuccess).toBe(true);

    const promptRes = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 8,
      method: "prompts/get",
      params: {
        name: "bla-harden-project",
        arguments: { directory: "." },
      },
    });
    const messages = (promptRes!.result as { messages: Array<{ content: { text: string } }> }).messages;
    expect(messages[0]!.content.text).toContain("bla_harden");

    const log: string[] = [];
    const originalLog = console.log;
    console.log = (...args: unknown[]) => {
      log.push(args.map(String).join(" "));
    };
    try {
      const code = await runCli(["harden", root, "--json"]);
      expect(code).toBe(0);
    } finally {
      console.log = originalLog;
    }
    const cliReport = JSON.parse(log.join("\n")) as {
      overallSuccess: boolean;
      hardenedCount: number;
    };
    expect(cliReport.overallSuccess).toBe(true);
    expect(cliReport.hardenedCount).toBeGreaterThanOrEqual(1);
  });

  it("also discovers root-level artifacts when dist/ already exists", () => {
    const root = createTempDir();
    const dist = join(root, "dist");
    mkdirSync(dist, { recursive: true });
    writeFileSync(join(dist, "app.js"), `export const x = 1;\n`, "utf8");
    writeFileSync(join(root, "tools.py"), "def helper():\n    return 1\n", "utf8");
    writeFileSync(join(root, "local.sqlite"), buildSampleSqliteDatabase());
    // Source tree must NOT be swept when dist/ exists
    mkdirSync(join(root, "src"), { recursive: true });
    writeFileSync(join(root, "src", "internal.js"), `export const secret = 1;\n`, "utf8");

    const discovered = discoverHardenableArtifacts(root);
    const rels = discovered.map((d) => d.relativePath).sort();
    expect(rels).toEqual(expect.arrayContaining(["dist/app.js", "tools.py", "local.sqlite"]));
    expect(rels.some((r) => r.includes("src/"))).toBe(false);

    const report = hardenProject({
      directory: root,
      intensity: "stealth",
      seed: "root-supplemental",
      emitManifest: false,
    });
    expect(report.overallSuccess).toBe(true);
    expect(report.hardenedCount).toBeGreaterThanOrEqual(3);
    expect(report.outputDirectory).toContain(".bla-hardened");
    expect(formatHardenProjectReport(report)).toContain("Output:");
  });

  it("hardens DEX members inside an unsigned APK-shaped ZIP discovered under release/", () => {
    const root = createTempDir();
    const release = join(root, "release");
    mkdirSync(release, { recursive: true });
    const apk = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest package='com.demo'/>") },
      { name: "classes.dex", data: minimalDex() },
    ]);
    writeFileSync(join(release, "app-unsigned.apk"), apk);

    const report = hardenProject({
      directory: root,
      intensity: "stealth",
      seed: "apk-discover",
      emitManifest: false,
    });
    expect(report.discoveredCount).toBeGreaterThanOrEqual(1);
    const apkArtifact = report.artifacts.find((a) => a.format === "android-apk");
    expect(apkArtifact).toBeDefined();
    expect(apkArtifact!.success).toBe(true);
  });
});
