import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  auditTarget,
  buildSarifReport,
  defendTarget,
  detectArtifactFormat,
  handleMcpRequest,
  initBlaConfig,
  loadBlaConfig,
  protectTarget,
  verifyTarget,
} from "../src/index.js";

describe("BLA Config, SARIF 2.1.0, JVM Bytecode & 22-Format Directory Pipeline", () => {
  it("initializes and loads bla.config.json cleanly", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-cfg-"));
    try {
      const initRes = initBlaConfig(dir);
      expect(initRes.created).toBe(true);
      expect(initRes.config.intensity).toBe("bankrupt");

      const loaded = loadBlaConfig(dir);
      expect(loaded.sourcePath).toBe(initRes.configPath);
      expect(loaded.config.minDefenseScore).toBe(90);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("emits valid SARIF 2.1.0 reports for audit findings", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-sarif-"));
    try {
      const jsFile = join(dir, "app.js");
      writeFileSync(
        jsFile,
        `export function verifyLicense(key) { return fetch("/api/v1/license/verify?k=" + key); }\n`,
        "utf8",
      );
      const audit = auditTarget(jsFile);
      const sarif = buildSarifReport(audit);

      expect(sarif.version).toBe("2.1.0");
      expect(sarif.$schema).toContain("sarif-2.1.0.json");
      expect(sarif.runs[0].tool.driver.name).toBe("bla-agents");
      expect(sarif.runs[0].results.length).toBeGreaterThan(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("disambiguates 0xCAFEBABE between JVM .class files and Mach-O Universal binaries", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-magic-"));
    try {
      // 1. JVM .class (magic 0xCAFEBABE, minor=0, major=65 [Java 21], cp_count=1)
      const jvmBuf = Buffer.alloc(32, 0);
      jvmBuf.writeUInt32BE(0xcafebabe, 0);
      jvmBuf.writeUInt16BE(0, 4);
      jvmBuf.writeUInt16BE(65, 6);
      jvmBuf.writeUInt16BE(1, 8);
      const jvmPath = join(dir, "LicenseVerifier.bin");
      writeFileSync(jvmPath, jvmBuf);
      expect(detectArtifactFormat(jvmPath)).toBe("jvm-class");

      // 2. Mach-O Universal fat binary (magic 0xCAFEBABE, nfat_arch=2)
      const fatBuf = Buffer.alloc(32, 0);
      fatBuf.writeUInt32BE(0xcafebabe, 0);
      fatBuf.writeUInt32BE(2, 4);
      const fatPath = join(dir, "UniversalDaemon");
      writeFileSync(fatPath, fatBuf);
      expect(detectArtifactFormat(fatPath)).toBe("native-macho");

      // 3. .NET Managed CLR assembly (MZ + BSJB)
      const clrBuf = Buffer.alloc(128, 0);
      clrBuf.write("MZ", 0, "ascii");
      clrBuf.write("BSJB", 48, "ascii");
      const clrPath = join(dir, "ManagedCore.dll");
      writeFileSync(clrPath, clrBuf);
      expect(detectArtifactFormat(clrPath)).toBe("dotnet-managed");

      // 4. Apple Binary PropertyList (bplist00)
      const bplistPath = join(dir, "Embedded.bin");
      writeFileSync(bplistPath, Buffer.from("bplist00\x00\x08", "latin1"));
      expect(detectArtifactFormat(bplistPath)).toBe("apple-plist");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protects and verifies JVM .class, Apple .plist, and .NET Managed assemblies inside a unified directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-unified-dir-"));
    try {
      const srcDir = join(dir, "dist");
      const outDir = join(dir, "dist-shielded");
      const { mkdirSync } = await import("node:fs");
      mkdirSync(srcDir, { recursive: true });

      writeFileSync(
        join(srcDir, "index.js"),
        `export function computePrice(units) { return units * 49; }\n`,
        "utf8",
      );
      writeFileSync(
        join(srcDir, "Info.plist"),
        `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleName</key><string>BLAApp</string></dict></plist>`,
        "utf8",
      );
      const jvmBuf = Buffer.from(
        "cafebabe000000370005" + // Java 11, four constant pool entries
        "010008436f726541757468070001" + // CoreAuth
        "0100106a6176612f6c616e672f4f626a656374070003" + // java/lang/Object
        "0021000200040000000000000000",
        "hex",
      );
      writeFileSync(join(srcDir, "CoreAuth.class"), jvmBuf);

      const report = defendTarget({
        inputPath: srcDir,
        outputPath: outDir,
        intensity: "bankrupt",
        emitManifest: true,
      });

      expect(report.overallSuccess).toBe(true);
      expect(report.protection.counteredReaVectors).toContain("apple-plist-budget");
      expect(report.protection.counteredReaVectors).toContain("jvm-bytecode-decompilation");

      const verClass = verifyTarget(join(outDir, "CoreAuth.class"), join(srcDir, "CoreAuth.class"));
      expect(verClass.overallPassed).toBe(true);

      const mcpRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 99,
        method: "tools/call",
        params: {
          name: "bla_inspect_release",
          arguments: { path: srcDir },
        },
      });
      expect(mcpRes?.result).toBeDefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
