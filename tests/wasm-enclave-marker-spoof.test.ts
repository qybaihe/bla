import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { auditTarget } from "../src/engine/auditor.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { readWasmCustomSectionContent } from "../src/shields/formats/wasm.js";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-wasm-enclave-spoof-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

const WASM_HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function leb(n: number): Buffer {
  const out: number[] = [];
  let value = n;
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value) byte |= 0x80;
    out.push(byte);
  } while (value);
  return Buffer.from(out);
}

/** A structurally valid custom section: id 0, encoded size, name, payload. */
function customSection(name: string, payload: Buffer): Buffer {
  const nameBytes = Buffer.from(name, "utf8");
  const body = Buffer.concat([leb(nameBytes.length), nameBytes, payload]);
  return Buffer.concat([Buffer.from([0x00]), leb(body.length), body]);
}

/** Header + the three marker-named sections a real hardened WASM carries. */
function spoofedWasm(payloadFor: (name: string) => Buffer): Buffer {
  return Buffer.concat([
    WASM_HEADER,
    customSection("bla.enclave.manifest", payloadFor("bla.enclave.manifest")),
    customSection("bla.canary.credentials", payloadFor("bla.canary.credentials")),
    customSection("bla.wasm.interface.exhaustion", payloadFor("bla.wasm.interface.exhaustion")),
  ]);
}

/** Minimal valid module (type + function + export + code) accepted by WebAssembly.validate(). */
function minimalWasm(): Buffer {
  return Buffer.concat([
    WASM_HEADER,
    Buffer.from([0x01, 0x04, 0x01, 0x60, 0x00, 0x00]), // type: () -> ()
    Buffer.from([0x03, 0x02, 0x01, 0x00]), // function: one of type 0
    Buffer.from([0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00]), // export "run"
    Buffer.from([0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b]), // code: locals 0, end
  ]);
}

function auditStatusFor(path: string): string {
  return auditTarget(path).protectionStatus;
}

describe("WASM enclave-shield sections must carry real payloads, not just the marker names", () => {
  it("does not treat three empty marker sections as protection", () => {
    const dir = makeTempDir();
    const base = join(dir, "mod.wasm");
    const spoof = join(dir, "mod.spoof.wasm");
    writeFileSync(base, minimalWasm());
    writeFileSync(spoof, spoofedWasm(() => Buffer.alloc(0)));

    expect(auditStatusFor(spoof)).not.toBe("BLA_PROTECTED");
    expect(verifyTarget(spoof, base).overallPassed).toBe(false);
  });

  it("does not treat marker sections with unrelated JSON payloads as protection", () => {
    const dir = makeTempDir();
    const base = join(dir, "mod.wasm");
    const spoof = join(dir, "mod.spoof.wasm");
    writeFileSync(base, minimalWasm());
    writeFileSync(spoof, spoofedWasm(() => Buffer.from('{"note":"not a bla payload"}', "utf8")));

    expect(auditStatusFor(spoof)).not.toBe("BLA_PROTECTED");
    expect(verifyTarget(spoof, base).overallPassed).toBe(false);
  });

  it("still reports a genuinely hardened WASM as protected", () => {
    const dir = makeTempDir();
    const base = join(dir, "mod.wasm");
    const real = join(dir, "mod.real.wasm");
    writeFileSync(base, minimalWasm());
    protectTarget({ inputPath: base, outputPath: real, seed: "wasm-enclave-structural" });

    const protectedBytes = readFileSync(real);
    expect(readWasmCustomSectionContent(protectedBytes, "bla.enclave.manifest")).not.toBeNull();
    expect(auditStatusFor(real)).toBe("BLA_PROTECTED");
    expect(verifyTarget(real, base).overallPassed).toBe(true);
  });
});
