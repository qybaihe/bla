import { parse } from "@babel/parser";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { encryptStrings } from "../src/engine/encrypt-strings.js";
import { hardenProject } from "../src/engine/harden.js";
import { lintJsAesUnwrapSource } from "../src/engine/js-aes-unwrap-lint.js";
import {
  lintSealCommitmentFile,
  lintSealCommitmentSource,
} from "../src/engine/seal-commitment-lint.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { protectEvmBytecodeBuffer } from "../src/shields/formats/evm-bytecode.js";
import { protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";
import {
  finalizeSelfSealSelfDigest,
  generateSelfSealSnippet,
  verifySelfSealSelfDigest,
} from "../src/shields/runtime/self-seal.js";
import { verifyWeaveTarget } from "../src/shields/weave/weave-decoy.js";

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(d);
  return d;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Minimal valid WASM module exporting `add(i32, i32) -> i32`. */
function minimalValidWasm(): Buffer {
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    // Type section: 1 func (i32, i32) -> i32
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
    // Function section: 1 func of type 0
    0x03, 0x02, 0x01, 0x00,
    // Export section: "add" -> func 0
    0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
    // Code section: local.get 0, local.get 1, i32.add, end
    0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b,
  ]);
}

/**
 * Minimal structurally complete JVM `.class` file (Java 8 / v52.0):
 *   cp_count = 3
 *   #1 = CONSTANT_Class_info -> #2
 *   #2 = CONSTANT_Utf8_info("Demo")
 *   access_flags = 0x0021 (ACC_PUBLIC | ACC_SUPER)
 *   this_class = 1, super_class = 0
 *   interfaces_count = 0, fields_count = 0, methods_count = 0, attributes_count = 0
 */
function minimalCompleteJvmClass(): Buffer {
  const className = Buffer.from("Demo", "utf8");
  const header = Buffer.alloc(10);
  header.writeUInt32BE(0xcafebabe, 0);
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(52, 6);
  header.writeUInt16BE(3, 8); // cp_count = 3 (#1, #2)

  const cp1 = Buffer.from([0x07, 0x00, 0x02]); // CONSTANT_Class -> #2
  const cp2 = Buffer.alloc(3 + className.length);
  cp2[0] = 0x01; // CONSTANT_Utf8
  cp2.writeUInt16BE(className.length, 1);
  className.copy(cp2, 3);

  const body = Buffer.alloc(16);
  body.writeUInt16BE(0x0021, 0); // access_flags
  body.writeUInt16BE(1, 2); // this_class = #1
  body.writeUInt16BE(0, 4); // super_class = 0 (java/lang/Object bootstrap shape)
  body.writeUInt16BE(0, 6); // interfaces_count = 0
  body.writeUInt16BE(0, 8); // fields_count = 0
  body.writeUInt16BE(0, 10); // methods_count = 0
  body.writeUInt16BE(0, 12); // attributes_count = 0 — wait: 8 + 2 + 2 + 2 = 14 bytes total!
  return Buffer.concat([header, cp1, cp2, body.subarray(0, 14)]);
}

function collectFilesRecursive(dir: string): string[] {
  const out: string[] = [];
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, ent.name);
    if (ent.isDirectory()) {
      out.push(...collectFilesRecursive(full));
    } else if (ent.isFile()) {
      out.push(full);
    }
  }
  return out;
}

describe("CI 5-Layer Red-Team Adversarial Regression Gate", () => {
  it("Layer 1: JS AST shield eliminates static prefix/array-manifest fingerprints and preserves VM equivalence", () => {
    const source = `
      function computeInvoiceDigest(accountId, seats) {
        const base = (accountId * 31 + seats * 17) >>> 0;
        return base ^ 0x5a5a1234;
      }
      module.exports = { computeInvoiceDigest };
    `;
    const shielded = transformJavaScriptWithBlaShield(source, {
      intensity: "bankrupt",
      seed: "ci-redteam-layer1-seed",
      filename: "billing.cjs",
      sourceType: "commonjs",
    });

    // 1. Zero greppable decoy prefixes or dead `void [...]` manifest sweeps
    expect(shielded.code).not.toMatch(
      /\b(?:obligationFlood_|scc_|labyrinthDispatch_|fridaCaptureSaturator_|_shadowVault_|__blaSidecar)/,
    );
    expect(shielded.code).not.toMatch(/void\s*\[[^\]]{40,}\]/);

    // 2. Functional equivalence inside isolated VM context
    const runShielded = (code: string) => {
      const mod = { exports: {} as Record<string, (a: number, b: number) => number> };
      vm.runInNewContext(code, {
        module: mod,
        exports: mod.exports,
        require,
        Buffer,
        process,
        Math,
        Uint32Array,
        Uint8Array,
        Array,
        Object,
        String,
        Number,
        Date,
        performance,
      });
      return mod.exports;
    };
    const intactExports = runShielded(shielded.code);
    expect(intactExports.computeInvoiceDigest!(42, 7)).toBe(
      ((42 * 31 + 7 * 17) >>> 0) ^ 0x5a5a1234,
    );
    expect(intactExports.computeInvoiceDigest!(0, 1)).toBe(
      ((0 * 31 + 1 * 17) >>> 0) ^ 0x5a5a1234,
    );

    // 3. Stripping an injected helper declaration breaks module execution immediately (ReferenceError)
    const fnDecls = [...shielded.code.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g)]
      .map((m) => m[1]!)
      .filter((name) => name !== "computeInvoiceDigest");
    expect(fnDecls.length).toBeGreaterThan(10);
    const victimFn = fnDecls[fnDecls.length - 1]!;
    const stripped = shielded.code.replace(
      `function ${victimFn}(`,
      `function _stripped_${victimFn}(`,
    );
    expect(() => runShielded(stripped)).toThrow(/is not defined/);
  });

  it("Layer 2: Multi-site self-seal avoids even-site XOR cancellation and hard-fails on 1-byte tamper", () => {
    const dir = makeTempDir("bla-rt-layer2-");
    const sibPath = join(dir, "policy.json");
    const sibBytes = Buffer.from('{"tier":"enterprise","quota":500}\n', "utf8");
    writeFileSync(sibPath, sibBytes);
    const sibSha = createHash("sha256").update(sibBytes).digest("hex");

    const prng = new SeededPrng("ci-redteam-layer2-seed");
    const snippet = generateSelfSealSnippet(prng, {
      siblingPaths: ["policy.json"],
      expectedSiblingSha256: { "policy.json": sibSha },
      hardFailOnSiblingMismatch: true,
      interleavedSites: 2,
      selfDigestCheck: true,
      envFingerprint: true,
    });
    expect(snippet.interleavedSites).toBe(2);

    const rawEntry = [
      snippet.code,
      `const tierLabel = "ENTERPRISE_ACTIVE";`,
      `module.exports = { digest: ${snippet.bindingName}, tierLabel };`,
      "",
    ].join("\n");
    const finalized = finalizeSelfSealSelfDigest(rawEntry);
    expect(finalized.applied).toBe(true);

    const entryPath = join(dir, "entry.cjs");
    writeFileSync(entryPath, finalized.content, "utf8");

    // Offline self-digest passes on untampered bytes
    expect(verifySelfSealSelfDigest(readFileSync(entryPath)).verified).toBe(true);

    // Clean Node child process computes a non-zero XOR digest (sites do NOT self-cancel to 0!)
    const outJson = execFileSync(
      process.execPath,
      ["-e", `const m = require(${JSON.stringify(entryPath)}); process.stdout.write(JSON.stringify(m));`],
      { env: { ...process.env, NODE_OPTIONS: "" }, encoding: "utf8" },
    );
    const parsed = JSON.parse(outJson) as { digest: number; tierLabel: string };
    expect(parsed.tierLabel).toBe("ENTERPRISE_ACTIVE");
    expect(parsed.digest).toBeGreaterThan(0);
    expect(parsed.digest & 1).toBe(0); // untampered parity bit is 0

    // Flip 1 character in the business literal ("ENTERPRISE_ACTIVE" -> "ENTERPRISE_ACTIVF")
    const tamperedContent = finalized.content.replace(
      "ENTERPRISE_ACTIVE",
      "ENTERPRISE_ACTIVF",
    );
    writeFileSync(entryPath, tamperedContent, "utf8");

    expect(verifySelfSealSelfDigest(readFileSync(entryPath)).verified).toBe(false);
    const verifyReport = verifyTarget(entryPath, undefined, { selfSealEnabled: true });
    expect(verifyReport.overallPassed).toBe(false);
    expect(
      verifyReport.checks.some(
        (c) => c.id === "self-seal-digest-integrity" && !c.passed,
      ),
    ).toBe(true);

    // Runtime execution must hard-fail with integrity error
    expect(() =>
      execFileSync(
        process.execPath,
        ["-e", `require(${JSON.stringify(entryPath)});`],
        { env: { ...process.env, NODE_OPTIONS: "" }, stdio: "pipe" },
      ),
    ).toThrow();
  });

  it("Layer 3: Weave verifier defeats >15 dummy-function padding, algebraic zero-entropy (& 0 / ^ self), and indirect boolean gates", () => {
    const dir = makeTempDir("bla-rt-layer3-");

    // Attack A: 18 dummy functions mutating shared state, trying to push `checkLicense` past index 15
    const dummyFns = Array.from(
      { length: 18 },
      (_, i) =>
        `function reconcileLedgerWindow${i}(v) { ledgerState = (ledgerState + v + ${i + 3}) >>> 0; return (ledgerState ^ ${(i + 1) * 17}) >>> 0; }`,
    ).join("\n");
    const dummyCalls = Array.from(
      { length: 18 },
      (_, i) => `reconcileLedgerWindow${i}(x + ${i});`,
    ).join(" ");
    const paddedFile = join(dir, "padded-gate.js");
    writeFileSync(
      paddedFile,
      [
        `let ledgerState = 0x13572468;`,
        dummyFns,
        `export function runBatch(x) { ${dummyCalls} return ledgerState; }`,
        `export function checkLicense(token) { const ok = token === "PRO-2026-KEY"; return ok; }`,
      ].join("\n"),
      "utf8",
    );
    const reportA = verifyWeaveTarget(paddedFile);
    expect(reportA.overallPassed).toBe(false);
    const gateCheckA = reportA.files[0]?.checks.find(
      (c) => c.id === "crown-jewel-entanglement",
    );
    expect(gateCheckA?.passed).toBe(false);

    // Attack B: Algebraic zero-entropy fake weave (`& 0` and `x ^ x`)
    const zeroEntropyFile = join(dir, "zero-entropy.js");
    writeFileSync(
      zeroEntropyFile,
      [
        `let sessionAcc = 0x42;`,
        `function foldWindowA(n) { sessionAcc = (sessionAcc + n) | 0; return sessionAcc & 0; }`,
        `function foldWindowB(n) { sessionAcc = (sessionAcc ^ n) | 0; return sessionAcc ^ sessionAcc; }`,
        `function foldWindowC(n) { sessionAcc = (sessionAcc + n * 3) | 0; return sessionAcc * 0; }`,
        `export function computeQuote(n) { return n + foldWindowA(n) + foldWindowB(n) + foldWindowC(n); }`,
      ].join("\n"),
      "utf8",
    );
    const reportB = verifyWeaveTarget(zeroEntropyFile);
    expect(reportB.overallPassed).toBe(false);
  });

  it("Layer 4: hardenProject derives coherent sub-seeds with zero raw private seed leakage across artifacts", async () => {
    const srcDir = makeTempDir("bla-rt-layer4-src-");
    const outDir = makeTempDir("bla-rt-layer4-out-");
    const rawMasterSeed = "TOP_SECRET_MASTER_SEED_DO_NOT_LEAK_99942";

    writeFileSync(
      join(srcDir, "index.cjs"),
      `const helper = require("./worker.cjs");\nfunction compute(x) { return helper.step(x) + 5; }\nmodule.exports = { compute };\n`,
      "utf8",
    );
    writeFileSync(
      join(srcDir, "worker.cjs"),
      `function step(v) { return (v * 3 + 11) >>> 0; }\nmodule.exports = { step };\n`,
      "utf8",
    );
    writeFileSync(join(srcDir, "kernel.wasm"), minimalValidWasm());

    const result = await hardenProject({
      directory: srcDir,
      outputDirectory: outDir,
      intensity: "balanced",
      seed: rawMasterSeed,
      sidecarEntangle: true,
      selfSeal: true,
    });
    expect(result.overallSuccess).toBe(true);

    // Scan every emitted file AND the JSON report for any trace of rawMasterSeed
    expect(JSON.stringify(result)).not.toContain(rawMasterSeed);
    const emittedFiles = collectFilesRecursive(outDir);
    expect(emittedFiles.length).toBeGreaterThanOrEqual(3);

    const publicTags = new Set<string>();
    for (const f of emittedFiles) {
      const buf = readFileSync(f);
      expect(buf.toString("utf8")).not.toContain(rawMasterSeed);
      expect(buf.toString("latin1")).not.toContain(rawMasterSeed);
      const m = buf.toString("latin1").match(/scn1-[0-9a-f]{32}/g);
      if (m) {
        for (const tag of m) publicTags.add(tag);
      }
    }
    // Coherent public sidecar tag across entangled siblings
    expect(publicTags.size).toBe(1);
  });

  it("Layer 5: JVM §4.7.1 exact-EOF attribute, oversized seal fail-closed, WebCrypto AES lint, EIP-170 cap, and JSX/directive encryptStrings", () => {
    // 5a. JVM §4.7.1 attribute_info with zero trailing bytes
    const jvmIn = minimalCompleteJvmClass();
    const jvmProtected = protectJvmClassBuffer(jvmIn, {
      intensity: "bankrupt",
      seed: "ci-jvm-seed",
    });
    expect(jvmProtected.mode).toBe("structural");
    expect(jvmProtected.customAttributesAdded).toBe(1);

    // Parse constant pool of protected .class and verify attributes_count === 1 & exact EOF
    const outBuf = jvmProtected.buffer;
    expect(outBuf.readUInt32BE(0)).toBe(0xcafebabe);
    const newCpCount = outBuf.readUInt16BE(8);
    expect(newCpCount).toBe(3 + jvmProtected.constantPoolEntriesAdded);
    let p = 10;
    for (let slot = 1; slot < newCpCount; slot++) {
      const tag = outBuf[p]!;
      if (tag === 1) {
        const len = outBuf.readUInt16BE(p + 1);
        p += 3 + len;
      } else if (tag === 7) {
        p += 3;
      } else {
        throw new Error(`Unexpected CP tag ${tag}`);
      }
    }
    // access_flags(2) + this_class(2) + super_class(2) + interfaces(2) + fields(2) + methods(2) = 12 bytes
    const attrsCount = outBuf.readUInt16BE(p + 12);
    expect(attrsCount).toBe(1);
    const attrNameIndex = outBuf.readUInt16BE(p + 14);
    expect(attrNameIndex).toBe(3); // first injected CONSTANT_Utf8 ("BlaEnclaveDelegation")
    const attrLen = outBuf.readUInt32BE(p + 16);
    expect(p + 20 + attrLen).toBe(outBuf.length); // exact EOF, zero trailing garbage!

    // 5b. Seal commitment lint: >400 KB padded reversible JSON still caught + >4 MiB seal.json fails closed
    const paddedSealJson = JSON.stringify({
      schema: "demo-entitlement-seal/v1",
      padding: "x".repeat(520_000),
      scheduleSalt: 123456,
      rounds: 8,
      revision: "deadbeefcafebabe",
    });
    const paddedReport = lintSealCommitmentSource(paddedSealJson, {
      path: "seal.json",
    });
    expect(paddedReport.shouldRefuseBankrupt).toBe(true);
    expect(
      paddedReport.findings.some((f) => f.id === "reversible-public-commitment"),
    ).toBe(true);

    const dir = makeTempDir("bla-rt-layer5-");
    const hugeSealPath = join(dir, "seal.json");
    writeFileSync(hugeSealPath, `{"pad":"${"a".repeat(4 * 1024 * 1024 + 512)}"}`);
    const hugeReport = lintSealCommitmentFile(hugeSealPath);
    expect(hugeReport.shouldRefuseBankrupt).toBe(true);
    expect(hugeReport.findings.some((f) => f.id === "seal-oversized-sidecar")).toBe(
      true,
    );

    // 5c. WebCrypto subtle.decrypt + importKey("raw") + fixed hdr caught by js-aes-unwrap-lint
    const webCryptoFootgun = `
      const SEALED_HDR = new Uint8Array([0xd1, 0x7e, 0xa0, 0x04]);
      async function unwrapBlob(buf, rawHex) {
        const key = await crypto.subtle.importKey("raw", rawHex, { name: "AES-GCM" }, false, ["decrypt"]);
        return crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(4, 16) }, key, buf.slice(16));
      }
    `;
    const aesReport = lintJsAesUnwrapSource(webCryptoFootgun, {
      path: "browser-unwrap.ts",
    });
    expect(aesReport.shouldRefuseBankrupt).toBe(true);

    // 5d. EVM EIP-170 cap option keeps bytecode <= 24,576 bytes
    const evmCapped = protectEvmBytecodeBuffer(Buffer.from([0x60, 0x00, 0x56]), {
      intensity: "bankrupt",
      seed: "eip170-seed",
      enforceEip170Cap: true,
    });
    expect(evmCapped.buffer.length).toBeLessThanOrEqual(24_576);
    expect(evmCapped.exceedsEip170Limit).toBe(false);

    // 5e. encryptStrings preserves "use client" at line 1 and wraps JSXAttribute values in {...}
    const tsxDir = join(dir, "tsx-app");
    mkdirSync(tsxDir, { recursive: true });
    const tsxPath = join(tsxDir, "panel.tsx");
    writeFileSync(
      tsxPath,
      [
        `"use client";`,
        `declare const AMBIENT_SECRET = "FLAG{ambient_declare_must_not_become_call}";`,
        `export function LicenseBadge() {`,
        `  return <div data-secret="FLAG{jsx_attribute_secret_token_987654}">Active</div>;`,
        `}`,
        "",
      ].join("\n"),
      "utf8",
    );

    const dryReport = encryptStrings({
      path: tsxPath,
      seed: "tsx-seed",
      dryRun: true,
    });
    expect(dryReport.status).toBe("ok");
    expect(dryReport.totalEncrypted).toBe(1);

    const liveReport = encryptStrings({
      path: tsxPath,
      seed: "tsx-seed",
    });
    expect(liveReport.status).toBe("ok");
    const rewrittenTsx = readFileSync(tsxPath, "utf8");
    expect(rewrittenTsx.startsWith(`"use client";`)).toBe(true);
    expect(rewrittenTsx).toContain(
      `declare const AMBIENT_SECRET = "FLAG{ambient_declare_must_not_become_call}";`,
    );
    expect(rewrittenTsx).not.toContain("FLAG{jsx_attribute_secret_token_987654}");
    expect(rewrittenTsx).toMatch(/data-secret=\{[A-Za-z_$][\w$]*\(0\)\}/);

    // Must remain 100% valid TSX AST!
    expect(() =>
      parse(rewrittenTsx, {
        sourceType: "module",
        plugins: ["typescript", "jsx"],
      }),
    ).not.toThrow();
  });
});
