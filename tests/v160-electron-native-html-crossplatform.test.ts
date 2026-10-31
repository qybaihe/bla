import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import vm from "node:vm";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import * as t from "@babel/types";
import { afterEach, describe, expect, it } from "vitest";
import { assertNoForbiddenMarkers } from "../src/core/identifiers.js";
import { buildSarifReport } from "../src/core/sarif.js";
import type { AuditReport } from "../src/core/types.js";
import { defendTarget } from "../src/engine/defender.js";
import { detectBunStandaloneGraph } from "../src/shields/formats/bun-standalone.js";
import {
  detectNativeEofAppendHazard,
  inspectNativeBinary,
  protectNativeBinary,
} from "../src/shields/formats/native.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

type TraverseFn = (typeof _traverse)["default"];
const traverse: TraverseFn =
  typeof _traverse === "function"
    ? (_traverse as unknown as TraverseFn)
    : _traverse.default;

const tempDirs: string[] = [];

function makeTempDir(prefix = "bla-v160-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function buildMinimalMachO64(options: { readonly includeCodeSignature: boolean }): Buffer {
  // Mach-O 64-bit little-endian header (32 bytes) + 1 or 2 load commands
  const ncmds = options.includeCodeSignature ? 2 : 1;
  const cmd1Size = 72; // LC_SEGMENT_64 (0x19)
  const cmd2Size = options.includeCodeSignature ? 16 : 0; // LC_CODE_SIGNATURE (0x1d)
  const sizeofcmds = cmd1Size + cmd2Size;
  const buf = Buffer.alloc(256);
  buf.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  buf.writeUInt32LE(0x0100000c, 4); // CPU_TYPE_ARM64
  buf.writeUInt32LE(0, 8); // cpusubtype
  buf.writeUInt32LE(2, 12); // MH_EXECUTE
  buf.writeUInt32LE(ncmds, 16);
  buf.writeUInt32LE(sizeofcmds, 20);
  buf.writeUInt32LE(0, 24);
  buf.writeUInt32LE(0, 28);

  // Command 0: LC_SEGMENT_64
  buf.writeUInt32LE(0x19, 32);
  buf.writeUInt32LE(cmd1Size, 36);
  Buffer.from("__TEXT\0", "ascii").copy(buf, 40);

  if (options.includeCodeSignature) {
    // Command 1: LC_CODE_SIGNATURE (0x1d)
    const off = 32 + cmd1Size;
    buf.writeUInt32LE(0x1d, off);
    buf.writeUInt32LE(cmd2Size, off + 4);
    buf.writeUInt32LE(192, off + 8); // dataoff
    buf.writeUInt32LE(64, off + 12); // datasize
  }
  return buf;
}

function buildMinimalPe64(options: { readonly includeAuthenticode: boolean }): Buffer {
  const buf = Buffer.alloc(512);
  buf.write("MZ", 0, "ascii");
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  buf.write("PE\0\0", peOff, "ascii");
  // COFF File Header (20 bytes at peOff + 4)
  buf.writeUInt16LE(0x8664, peOff + 4); // IMAGE_FILE_MACHINE_AMD64
  buf.writeUInt16LE(1, peOff + 6); // NumberOfSections
  buf.writeUInt16LE(240, peOff + 20); // SizeOfOptionalHeader (PE32+)
  buf.writeUInt16LE(0x0022, peOff + 22); // Characteristics
  // Optional Header (PE32+ magic 0x20b at peOff + 24)
  const optOff = peOff + 24;
  buf.writeUInt16LE(0x020b, optOff);
  buf.writeUInt32LE(16, optOff + 108); // NumberOfRvaAndSizes
  if (options.includeAuthenticode) {
    // DataDirectory[4] (Certificate Table) is at optOff + 112 + 4 * 8 = optOff + 144
    buf.writeUInt32LE(384, optOff + 144); // file offset
    buf.writeUInt32LE(128, optOff + 148); // size
  }
  return buf;
}

describe("v1.6.0 Counter-REA Electron Custom URL Protocol (47fa6ab37) & Boundary Blackout", () => {
  it("de-literalizes custom URL protocols (including 1-2 char schemes), privileged scheme booleans, contextBridge members, and BrowserWindow webPreferences while preserving exact runtime values", () => {
    const cjsElectronSource = `
      const path = require("node:path");
      const { app, protocol, session, contextBridge, BrowserWindow } = require("electron");

      protocol.registerSchemesAsPrivileged([
        {
          scheme: "vault",
          privileges: {
            secure: true,
            standard: true,
            supportFetchAPI: true,
            bypassCSP: false,
            stream: true,
          },
        },
        {
          scheme: "x",
          privileges: {
            corsEnabled: true,
            allowServiceWorkers: false,
          },
        },
      ]);

      function registerHandlers() {
        const ok1 = app.setAsDefaultProtocolClient("ab");
        const ok2 = app.isDefaultProtocolClient("vault");
        protocol.handle("vault", (req) => req);
        session.defaultSession.protocol.registerFileProtocol("x", (req, cb) => cb(req));
        contextBridge.exposeInMainWorld("desktopVault", {
          openVault(id) { return "vault:" + id; },
          sealKey(k) { return k.toUpperCase(); },
        });
        const win = new BrowserWindow({
          width: 1024,
          webPreferences: {
            preload: path.join(__dirname, "preload.cjs"),
            contextIsolation: true,
            sandbox: true,
            nodeIntegration: false,
          },
        });
        return { ok1, ok2, win };
      }

      module.exports = { registerHandlers };
    `;

    const res = transformJavaScriptWithBlaShield(cjsElectronSource, {
      intensity: "bankrupt",
      seed: "v160-electron-protocol-cjs",
      filename: "main.cjs",
      sourceType: "script",
    });

    assertNoForbiddenMarkers(res.code, "Electron CJS shielded output");
    expect(res.electronProtocolsProtected).toBeGreaterThanOrEqual(6);

    // Static AST verification simulating REA's electronStaticAnalysisProtocol.ts & Browser.ts
    const ast = parse(res.code, { sourceType: "unambiguous" });
    let literalUserVaultSchemeFound = false;
    let literalShortSchemeFound = false;
    let literalPrivilegeBooleanFound = false;
    let directContextBridgeObjectFound = false;
    let provenElectronDecoyProtocolFound = false;

    traverse(ast, {
      CallExpression(p) {
        const callee = p.node.callee;
        if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
          const method = callee.property.name;
          if (
            method === "setAsDefaultProtocolClient" ||
            method === "isDefaultProtocolClient" ||
            method === "handle" ||
            method === "registerFileProtocol"
          ) {
            const firstArg = p.node.arguments[0];
            if (t.isStringLiteral(firstArg)) {
              if (firstArg.value === "vault") literalUserVaultSchemeFound = true;
              if (firstArg.value === "ab" || firstArg.value === "x") {
                literalShortSchemeFound = true;
              }
              if (
                firstArg.value === "enclave-vsock" ||
                firstArg.value === "tee-attest" ||
                firstArg.value === "quorum-kms" ||
                firstArg.value === "sgx-bridge"
              ) {
                provenElectronDecoyProtocolFound = true;
              }
            }
          }
          if (method === "registerSchemesAsPrivileged") {
            const arr = p.node.arguments[0];
            if (t.isArrayExpression(arr)) {
              for (const elem of arr.elements) {
                if (!t.isObjectExpression(elem)) continue;
                for (const prop of elem.properties) {
                  if (!t.isObjectProperty(prop) || !t.isIdentifier(prop.key)) continue;
                  if (prop.key.name === "scheme" && t.isStringLiteral(prop.value)) {
                    if (prop.value.value === "vault" || prop.value.value === "x") {
                      literalUserVaultSchemeFound = true;
                    }
                    if (
                      prop.value.value === "enclave-vsock" ||
                      prop.value.value === "tee-attest" ||
                      prop.value.value === "quorum-kms" ||
                      prop.value.value === "sgx-bridge"
                    ) {
                      provenElectronDecoyProtocolFound = true;
                    }
                  }
                  if (prop.key.name === "privileges" && t.isObjectExpression(prop.value)) {
                    for (const priv of prop.value.properties) {
                      if (
                        t.isObjectProperty(priv) &&
                        t.isBooleanLiteral(priv.value) &&
                        // Dead-branch decoy privileges intentionally carry literal booleans,
                        // whereas live user privileges ("vault" / "x") are de-literalized.
                        !elem.properties.some(
                          (sp) =>
                            t.isObjectProperty(sp) &&
                            t.isIdentifier(sp.key, { name: "scheme" }) &&
                            t.isStringLiteral(sp.value),
                        )
                      ) {
                        literalPrivilegeBooleanFound = true;
                      }
                    }
                  }
                }
              }
            }
          }
          if (method === "exposeInMainWorld") {
            const apiKey = p.node.arguments[0];
            const secondArg = p.node.arguments[1];
            // User's live exposeInMainWorld has a de-literalized 1st arg and opaque-wrapped 2nd arg
            if (!t.isStringLiteral(apiKey) && t.isObjectExpression(secondArg)) {
              directContextBridgeObjectFound = true;
            }
          }
        }
      },
    });

    expect(literalUserVaultSchemeFound).toBe(false);
    expect(literalShortSchemeFound).toBe(false);
    expect(literalPrivilegeBooleanFound).toBe(false);
    expect(directContextBridgeObjectFound).toBe(false);
    expect(provenElectronDecoyProtocolFound).toBe(true);

    // Runtime equivalence verification in Node VM
    const recordedPrivileged: unknown[] = [];
    const recordedProtocols: string[] = [];
    const recordedBridges: Array<{ key: string; api: Record<string, (v: string) => string> }> = [];
    const recordedWindows: Array<Record<string, unknown>> = [];

    const mockElectron = {
      app: {
        setAsDefaultProtocolClient(scheme: string) {
          recordedProtocols.push(`set:${scheme}`);
          return true;
        },
        isDefaultProtocolClient(scheme: string) {
          recordedProtocols.push(`is:${scheme}`);
          return false;
        },
      },
      protocol: {
        registerSchemesAsPrivileged(entries: unknown[]) {
          recordedPrivileged.push(...entries);
        },
        handle(scheme: string) {
          recordedProtocols.push(`handle:${scheme}`);
        },
      },
      session: {
        defaultSession: {
          protocol: {
            registerFileProtocol(scheme: string) {
              recordedProtocols.push(`sessionFile:${scheme}`);
            },
          },
        },
      },
      contextBridge: {
        exposeInMainWorld(key: string, api: Record<string, (v: string) => string>) {
          recordedBridges.push({ key, api });
        },
      },
      BrowserWindow: class MockBrowserWindow {
        opts: Record<string, unknown>;
        constructor(opts: Record<string, unknown>) {
          this.opts = opts;
          recordedWindows.push(opts);
        }
      },
    };

    const mod = { exports: {} as { registerHandlers: () => { ok1: boolean; ok2: boolean } } };
    const ctx = vm.createContext({
      module: mod,
      exports: mod.exports,
      __dirname: "/app/dist",
      process,
      Buffer,
      Math,
      Date,
      Array,
      Object,
      String,
      Number,
      Boolean,
      Uint8Array,
      Int32Array,
      WeakMap,
      Map,
      Set,
      Symbol,
      Proxy,
      Reflect,
      Error,
      TypeError,
      require(id: string) {
        if (id === "electron") return mockElectron;
        if (id === "node:path" || id === "path") return { join: (...p: string[]) => p.join("/") };
        throw new Error(`Unexpected require: ${id}`);
      },
    });

    vm.runInContext(res.code, ctx);
    const out = mod.exports.registerHandlers();
    expect(out.ok1).toBe(true);
    expect(out.ok2).toBe(false);
    expect(recordedPrivileged).toEqual([
      {
        scheme: "vault",
        privileges: {
          secure: true,
          standard: true,
          supportFetchAPI: true,
          bypassCSP: false,
          stream: true,
        },
      },
      {
        scheme: "x",
        privileges: {
          corsEnabled: true,
          allowServiceWorkers: false,
        },
      },
    ]);
    expect(recordedProtocols).toEqual([
      "set:ab",
      "is:vault",
      "handle:vault",
      "sessionFile:x",
    ]);
    expect(recordedBridges).toHaveLength(1);
    expect(recordedBridges[0]!.key).toBe("desktopVault");
    expect(recordedBridges[0]!.api.openVault!("42")).toBe("vault:42");
    expect(recordedBridges[0]!.api.sealKey!("abc")).toBe("ABC");
    expect(recordedWindows).toHaveLength(1);
    expect(recordedWindows[0]!.webPreferences).toEqual({
      preload: "/app/dist/preload.cjs",
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
    });
  });

  it("never injects require('electron') into non-Electron web modules and preserves TypeScript `as const` assertions", () => {
    const webTsModule = `
      export const PRIVILEGE_PRESET = {
        scheme: "vault",
        privileges: { secure: true, standard: true },
      } as const;
      export function greet(name: string): string {
        return "hi " + name;
      }
    `;
    const res = transformJavaScriptWithBlaShield(webTsModule, {
      intensity: "balanced",
      seed: "v160-non-electron-ts",
      filename: "preset.ts",
      sourceType: "module",
    });
    assertNoForbiddenMarkers(res.code);
    expect(res.code).not.toContain('require("electron")');
    expect(res.code).not.toContain("from \"electron\"");
    // `as const` literal booleans/strings must remain untouched so tsc never raises TS1355
    expect(res.code).toContain("as const");
    expect(res.code).toContain("secure: true");
  });
});

describe("v1.6.0 Signed & Standalone Native Binary Integrity Guard + Sidecar Decoy Graph", () => {
  it("detects and byte-exact preserves signed Mach-O (LC_CODE_SIGNATURE), Authenticode PE, PyInstaller, Deno standalone, and ZIP-SFX binaries while shielding unsigned binaries", () => {
    // 1. Signed Mach-O (LC_CODE_SIGNATURE 0x1d)
    const signedMacho = buildMinimalMachO64({ includeCodeSignature: true });
    expect(detectNativeEofAppendHazard(signedMacho)).toBe("macho-code-signature");
    const machoRes = protectNativeBinary(signedMacho, { intensity: "bankrupt" });
    expect(machoRes.nativeBinaryPreserved).toBe(true);
    expect(machoRes.nativeAppendHazard).toBe("macho-code-signature");
    expect(machoRes.buffer.equals(signedMacho)).toBe(true);

    // Unsigned Mach-O still receives full in-binary chaff
    const unsignedMacho = buildMinimalMachO64({ includeCodeSignature: false });
    expect(detectNativeEofAppendHazard(unsignedMacho)).toBe("none");
    const unsignedMachoRes = protectNativeBinary(unsignedMacho, { intensity: "balanced" });
    expect(unsignedMachoRes.nativeBinaryPreserved).toBe(false);
    expect(inspectNativeBinary(unsignedMachoRes.buffer).blaProtected).toBe(true);

    // 2. Authenticode-signed PE (DataDirectory[4])
    const signedPe = buildMinimalPe64({ includeAuthenticode: true });
    expect(detectNativeEofAppendHazard(signedPe)).toBe("pe-authenticode-signature");
    const peRes = protectNativeBinary(signedPe, { intensity: "bankrupt" });
    expect(peRes.nativeBinaryPreserved).toBe(true);
    expect(peRes.buffer.equals(signedPe)).toBe(true);

    // Unsigned PE still receives full in-binary chaff
    const unsignedPe = buildMinimalPe64({ includeAuthenticode: false });
    expect(detectNativeEofAppendHazard(unsignedPe)).toBe("none");
    const unsignedPeRes = protectNativeBinary(unsignedPe, { intensity: "balanced" });
    expect(unsignedPeRes.nativeBinaryPreserved).toBe(false);
    expect(inspectNativeBinary(unsignedPeRes.buffer).blaProtected).toBe(true);

    // 3. PyInstaller PKG CArchive magic (`MEI\x0c\x0b\x0a\x0b\x0e`)
    const pyi = Buffer.concat([
      unsignedPe,
      Buffer.alloc(32),
      Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]),
      Buffer.alloc(24),
    ]);
    expect(detectNativeEofAppendHazard(pyi)).toBe("pyinstaller-archive");
    expect(protectNativeBinary(pyi).buffer.equals(pyi)).toBe(true);

    // 4. Deno compile trailer (`d3n0l4nd`)
    const deno = Buffer.concat([
      unsignedPe,
      Buffer.from("d3n0l4nd", "ascii"),
      Buffer.alloc(24),
    ]);
    expect(detectNativeEofAppendHazard(deno)).toBe("deno-standalone");
    expect(protectNativeBinary(deno).buffer.equals(deno)).toBe(true);

    // 5. ZIP-SFX trailer (valid EOCD `PK\x05\x06` at EOF)
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    const sfx = Buffer.concat([unsignedPe, eocd]);
    expect(detectNativeEofAppendHazard(sfx)).toBe("zip-sfx-trailer");
    expect(protectNativeBinary(sfx).buffer.equals(sfx)).toBe(true);
  });

  it("defendTarget preserves executable mode bits (0o755), emits .bunfs-snapshot sidecar, passes verification, and passes strict macOS codesign when clang/codesign exist", () => {
    const dir = makeTempDir("bla-native-signed-");

    // Always verify synthetic Authenticode PE end-to-end across all OSes
    const peIn = join(dir, "signed-app.exe");
    const peOut = join(dir, "signed-app.shielded.exe");
    const signedPeBytes = buildMinimalPe64({ includeAuthenticode: true });
    writeFileSync(peIn, signedPeBytes);
    const peReport = defendTarget({
      inputPath: peIn,
      outputPath: peOut,
      intensity: "balanced",
    });
    expect(readFileSync(peOut).equals(signedPeBytes)).toBe(true);
    expect(existsSync(`${peOut}.bunfs-snapshot`)).toBe(true);
    expect(detectBunStandaloneGraph(readFileSync(`${peOut}.bunfs-snapshot`)).kind).not.toBe("none");
    expect(peReport.protection.afterAudit.protectionStatus).toBe("BLA_PROTECTED");
    expect(peReport.verification.overallPassed).toBe(true);

    // On macOS with clang + codesign, verify a real compiled Mach-O binary under `codesign --strict`
    if (process.platform === "darwin") {
      const hasClang = spawnSync("clang", ["--version"], { stdio: "pipe" }).status === 0;
      const hasCodesign = spawnSync("codesign", ["--help"], { stdio: "pipe" }).status !== null;
      if (hasClang && hasCodesign) {
        const cFile = join(dir, "hello.c");
        const machoIn = join(dir, "hello-macho");
        const machoOut = join(dir, "hello-macho-defended");
        writeFileSync(cFile, "int main(void) { return 0; }\n", "utf8");
        execFileSync("clang", ["-O2", cFile, "-o", machoIn], { stdio: "pipe" });
        chmodSync(machoIn, 0o755);

        const origBytes = readFileSync(machoIn);
        expect(detectNativeEofAppendHazard(origBytes)).toBe("macho-code-signature");

        const machoReport = defendTarget({
          inputPath: machoIn,
          outputPath: machoOut,
          intensity: "bankrupt",
        });

        expect(readFileSync(machoOut).equals(origBytes)).toBe(true);
        expect((statSync(machoOut).mode & 0o111) !== 0).toBe(true);
        expect(existsSync(`${machoOut}.bunfs-snapshot`)).toBe(true);
        expect(machoReport.verification.overallPassed).toBe(true);

        // Strict Apple code-signature verification + actual execution must both succeed!
        const verifySign = spawnSync("codesign", ["-vvv", "--strict", machoOut], {
          encoding: "utf8",
        });
        expect(verifySign.status).toBe(0);
        const runBin = spawnSync(machoOut, [], { stdio: "pipe" });
        expect(runBin.status).toBe(0);
      }
    }
  });
});

describe("v1.6.0 HTML Bundle Multi-Script Isolation, Importmap/JSON Preservation & External Bootstrap", () => {
  it("protects multi-script HTML bundles without global scope identifier collisions, preserves importmap/json tags, escapes </script>, and passes verification", () => {
    const dir = makeTempDir("bla-html-bundle-");
    const htmlIn = join(dir, "index.html");
    const htmlOut = join(dir, "index.shielded.html");

    const rawHtml = `<!DOCTYPE html>
<html>
<head>
  <script type="importmap">
  {
    "imports": {
      "@app/core": "/assets/core.mjs"
    }
  }
  </script>
  <script id="boot-config" type="application/json">{"env":"prod","version":160}</script>
</head>
<body>
  <script>
    globalThis.__part1 = "alpha:" + "<\\/script>";
  </script>
  <script>
    globalThis.__part2 = globalThis.__part1 + ":omega";
  </script>
</body>
</html>`;

    writeFileSync(htmlIn, rawHtml, "utf8");
    const report = defendTarget({
      inputPath: htmlIn,
      outputPath: htmlOut,
      intensity: "balanced",
      seed: "v160-html-multi",
    });

    expect(report.protection.afterAudit.protectionStatus).toBe("BLA_PROTECTED");
    expect(report.protection.afterAudit.reaSimulation.parseStatus).toBe("complete");
    expect(report.verification.overallPassed).toBe(true);

    const outHtml = readFileSync(htmlOut, "utf8");
    assertNoForbiddenMarkers(outHtml, "protected HTML bundle");

    // 1. importmap and application/json blocks must remain valid untouched JSON
    const importMapMatch = /<script\s+type="importmap">([\s\S]*?)<\/script>/i.exec(outHtml);
    expect(importMapMatch).not.toBeNull();
    expect(JSON.parse(importMapMatch![1]!)).toEqual({
      imports: { "@app/core": "/assets/core.mjs" },
    });

    const jsonConfigMatch = /<script\s+id="boot-config"\s+type="application\/json">([\s\S]*?)<\/script>/i.exec(outHtml);
    expect(jsonConfigMatch).not.toBeNull();
    expect(JSON.parse(jsonConfigMatch![1]!)).toEqual({ env: "prod", version: 160 });

    // 2. Extract executable plain `<script>` blocks and run them sequentially in ONE shared global VM scope
    const execBodies: string[] = [];
    const tagRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    let m: RegExpExecArray | null;
    while ((m = tagRe.exec(outHtml)) !== null) {
      const attrs = m[1] ?? "";
      if (/\btype\s*=/i.test(attrs) || /\bsrc\s*=/i.test(attrs)) continue;
      execBodies.push(m[2]!);
    }
    expect(execBodies).toHaveLength(2);

    const sharedGlobal: Record<string, unknown> = {
      Math,
      Date,
      Array,
      Object,
      String,
      Number,
      Boolean,
      Uint8Array,
      Int32Array,
      WeakMap,
      Map,
      Set,
      Symbol,
      Proxy,
      Reflect,
    };
    sharedGlobal.globalThis = sharedGlobal;
    const ctx = vm.createContext(sharedGlobal);
    for (const body of execBodies) {
      expect(() => vm.runInContext(body, ctx)).not.toThrow();
    }
    expect(sharedGlobal.__part1).toBe("alpha:</script>");
    expect(sharedGlobal.__part2).toBe("alpha:</script>:omega");
  });

  it("injects an inert bootstrap shield into Vite-style external-only `<script src=...>` HTML bundles", () => {
    const dir = makeTempDir("bla-html-vite-");
    const htmlIn = join(dir, "index.html");
    const htmlOut = join(dir, "index.shielded.html");
    writeFileSync(
      htmlIn,
      `<!DOCTYPE html><html><head><script type="module" crossorigin src="/assets/index-D8f2a.js"></script></head><body><div id="root"></div></body></html>`,
      "utf8",
    );

    const report = defendTarget({
      inputPath: htmlIn,
      outputPath: htmlOut,
      intensity: "balanced",
      seed: "v160-html-vite",
    });

    expect(report.protection.afterAudit.protectionStatus).toBe("BLA_PROTECTED");
    expect(report.verification.overallPassed).toBe(true);
    const outHtml = readFileSync(htmlOut, "utf8");
    expect(outHtml).toContain('src="/assets/index-D8f2a.js"');
  });
});

describe("v1.6.0 Cross-Platform Windows SARIF & CrackMe v5.2 Anti-Virtualization Self-Seal", () => {
  it("preserves Windows drive-letter paths (C:/...) and extracts trailing line numbers in SARIF 2.1.0 output", () => {
    const fakeAudit: AuditReport = {
      targetPath: "C:\\Users\\runner\\project\\dist\\main.js",
      detectedFormat: "javascript",
      sha256: "0".repeat(64),
      byteSize: 1024,
      timestamp: new Date().toISOString(),
      exposureScore: 88,
      protectionStatus: "UNPROTECTED",
      reaSimulation: {
        parseStatus: "complete",
        examinationStatus: "complete",
        triggeredResourceLimits: [],
        semanticUncertainties: [],
        visitedAstNodes: 50,
        totalFunctions: 2,
        decoyFunctionsDetectedAsReal: 0,
        staticStringsResolved: 4,
        staticStringsOpaque: 0,
        ipcChannelsTotal: 1,
        ipcChannelsPairedUniquely: 1,
        ipcChannelsAmbiguousOrDynamic: 0,
        routesDiscovered: 0,
        decoyRoutesHarvested: 0,
        obligationLedgerNodes: 2,
        architecturalChaffPayloads: 0,
      },
      exposedItems: [
        {
          id: "fn_1",
          name: "verifyLicense",
          kind: "function",
          location: "C:\\Users\\runner\\project\\dist\\main.js:42",
          riskLevel: "critical",
          reaToolUsed: "inspect_javascript_module",
          estimatedTokensToReconstruct: 800,
          estimatedCostUsd: 0.04,
          reason: "Exposed function",
        },
        {
          id: "fn_2",
          name: "boot",
          kind: "export",
          location: "D:\\artifacts\\preload.cjs",
          riskLevel: "high",
          reaToolUsed: "inspect_javascript_module",
          estimatedTokensToReconstruct: 600,
          estimatedCostUsd: 0.03,
          reason: "Exposed export",
        },
      ],
      vulnerableReaVectors: ["js-static-semantics"],
      agentEstimates: [],
      headlineWarning: "DANGER",
      recommendedCommand: "npx bla-agents protect",
    };

    const sarif = buildSarifReport(fakeAudit, {
      evidenceBasis: "static-file-observation",
      status: "complete",
      scope: "local-map-and-js-ts-css-files-only",
      filesInspected: 1,
      bytesRead: 128,
      findings: [
        {
          file: "dist\\assets\\app.js.map",
          kind: "embedded-source-text",
          evidenceBasis: "static-file-observation",
          representation: "standalone-map",
          embeddedSourceCount: 1,
          embeddedSourceBytes: 64,
        },
      ],
      limitations: [],
      networkAccessed: false,
      targetModified: false,
    });

    const locs = sarif.runs[0]!.results.map(
      (r) => r.locations[0]!.physicalLocation,
    );
    expect(locs[0]!.artifactLocation.uri).toBe("C:/Users/runner/project/dist/main.js");
    expect(locs[0]!.region?.startLine).toBe(42);
    expect(locs[1]!.artifactLocation.uri).toBe("D:/artifacts/preload.cjs");
    expect(locs[1]!.region).toBeUndefined();
    expect(locs[2]!.artifactLocation.uri).toBe("dist/assets/app.js.map");
  });

  it("verifies CrackMe v5.2 unlocks identically under LF and Windows CRLF checkouts while rejecting fs.readFileSync redirect virtualization", () => {
    const crackmePath = resolve(process.cwd(), "challenge/v5/bla-crackme.cjs");
    const rawLf = readFileSync(crackmePath, "utf8").replace(/\r\n/g, "\n");
    const cleanEnv = { ...process.env };
    delete cleanEnv.NODE_OPTIONS;

    const dir = makeTempDir("bla-crackme-v52-");
    const crlfCopy = join(dir, "bla-crackme-crlf.cjs");
    writeFileSync(crlfCopy, rawLf.replace(/\n/g, "\r\n"), "utf8");

    for (const candidate of [crackmePath, crlfCopy]) {
      const out = execFileSync(process.execPath, [candidate, "W9$mK3#pT7!vQ2@z"], {
        encoding: "utf8",
        env: cleanEnv,
      });
      const flagMatch = /FLAG\{[^}]+\}/.exec(out);
      expect(flagMatch).not.toBeNull();
      const sha = createHash("sha256").update(flagMatch![0]).digest("hex");
      expect(sha).toBe("1884551c04263e216989cae238468ac988e57e772d8aaf739ff2b9913909609a");
    }

    // Attempted fs.readFileSync(__filename) redirection to untouched original file must fail closed
    const redirectedCopy = join(dir, "bla-crackme-redirected.cjs");
    writeFileSync(
      redirectedCopy,
      rawLf.replace(
        "readFileSync(__filename,",
        `readFileSync(${JSON.stringify(crackmePath)},`,
      ),
      "utf8",
    );
    const redirectedRun = spawnSync(
      process.execPath,
      [redirectedCopy, "W9$mK3#pT7!vQ2@z"],
      { encoding: "utf8", env: cleanEnv },
    );
    expect(redirectedRun.status).not.toBe(0);
    expect(redirectedRun.stdout ?? "").not.toContain(
      "FLAG{b1ind_llm_4g3nts_b4nkrupt3d_r3a_2026_m4st3r}",
    );
  });
});
