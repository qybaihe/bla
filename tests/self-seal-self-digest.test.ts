/**
 * Entry self-coverage (CrackMe v8 red team 2026-11-05).
 *
 * Red finding: the bla-integrity-coverage/v1 matrix claimed `license.cjs#siteN`
 * hard-fail-verify `license.cjs`, but runtime only folded the entry's own bytes
 * into the opaque digest — appending to the entry was indistinguishable from an
 * intact run. These tests pin the canonical self-digest runtime fix.
 */
import { describe, expect, it } from "vitest";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { SeededPrng } from "../src/core/prng.js";
import {
  SELF_DIGEST_PLACEHOLDER,
  canonicalSelfDigest,
  finalizeSelfSealSelfDigest,
  generateSelfSealSnippet,
  verifySelfSealSelfDigest,
} from "../src/shields/runtime/self-seal.js";
import { protectTarget } from "../src/engine/protector.js";

function run(path: string) {
  return spawnSync(process.execPath, [path], { encoding: "utf8" });
}

describe("self-seal canonical self-digest", () => {
  it("placeholder is 64 chars and never valid hex (un-finalized → soft-skip)", () => {
    expect(SELF_DIGEST_PLACEHOLDER).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/.test(SELF_DIGEST_PLACEHOLDER)).toBe(false);
  });

  it("finalize is a no-op without placeholder and verifies after replacement", () => {
    const plain = "console.log(1);\n";
    const noop = finalizeSelfSealSelfDigest(plain);
    expect(noop.applied).toBe(false);
    expect(noop.content).toBe(plain);

    const src = `var a = "${SELF_DIGEST_PLACEHOLDER}"; var b = "${SELF_DIGEST_PLACEHOLDER}";\n`;
    const fin = finalizeSelfSealSelfDigest(src);
    expect(fin.applied).toBe(true);
    expect(fin.occurrences).toBe(2);
    expect(fin.content).not.toContain(SELF_DIGEST_PLACEHOLDER);
    const bytes = Buffer.from(fin.content, "utf8");
    expect(canonicalSelfDigest(bytes, fin.digest!)).toBe(fin.digest);
    expect(verifySelfSealSelfDigest(bytes)).toEqual({ verified: true, digest: fin.digest });

    // Any byte outside the digest literal breaks verification.
    expect(verifySelfSealSelfDigest(Buffer.from(`${fin.content}//x`)).verified).toBe(false);
    // Buffer input round-trips as Buffer.
    const finBuf = finalizeSelfSealSelfDigest(Buffer.from(src, "utf8"));
    expect(Buffer.isBuffer(finBuf.content)).toBe(true);
    expect(finBuf.digest).toBe(fin.digest);
  });

  it("un-finalized snippet soft-skips the self check (never bricks a build)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfdig-soft-"));
    try {
      writeFileSync(join(dir, "asset.bin"), "a");
      const snip = generateSelfSealSnippet(new SeededPrng("selfdig-soft"), {
        siblingPaths: ["./asset.bin"],
        bindingName: "integrityDigestSoft",
        envFingerprint: false,
      });
      expect(snip.selfDigestCheck).toBe(true);
      expect(snip.code).toContain(SELF_DIGEST_PLACEHOLDER);
      const main = join(dir, "main.cjs");
      writeFileSync(main, `"use strict";\n${snip.code}\nconsole.log("ok");\n`);
      appendFileSync(main, "// edited\n");
      const r = run(main);
      expect(r.status, r.stderr).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("protect+self-seal hard-fails when the ENTRY itself is tampered", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-selfdig-hf-"));
    try {
      writeFileSync(join(dir, "core.wasm"), Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0, 0xaa]));
      const entry = join(dir, "gate.cjs");
      writeFileSync(
        entry,
        ['"use strict";', "function main() { return 42; }", "module.exports = { main };",
          "if (require.main === module) console.log(main());", ""].join("\n"),
      );
      const out = join(dir, "gate.out.cjs");
      protectTarget({
        inputPath: entry,
        outputPath: out,
        intensity: "balanced",
        seed: "selfdig-protect",
        selfSeal: true,
        selfSealSiblingPaths: ["core.wasm"],
      });
      const shipped = readFileSync(out);
      expect(shipped.includes(Buffer.from(SELF_DIGEST_PLACEHOLDER))).toBe(false);
      expect(verifySelfSealSelfDigest(shipped).verified).toBe(true);

      const intact = run(out);
      expect(intact.status, intact.stderr).toBe(0);
      expect(intact.stdout.trim()).toBe("42");

      appendFileSync(out, "\n// patched\n");
      const tampered = run(out);
      expect(tampered.status).not.toBe(0);
      expect(`${tampered.stderr}${tampered.stdout}`).toMatch(/integrity check failed/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
