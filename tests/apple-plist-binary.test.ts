import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";
import { protectApplePlistBuffer } from "../src/shields/formats/apple-plist.js";

function bplistWithArrayRoot(): Buffer {
  const header = Buffer.from("bplist00", "ascii");
  const objects = Buffer.concat([
    Buffer.from([0xa1, 0x01]),
    Buffer.from([0x51, 0x61]),
  ]);
  const offsetTableOffset = header.length + objects.length;
  const offsets = Buffer.from([header.length, header.length + 2]);
  const trailer = Buffer.alloc(32);
  trailer[6] = 1;
  trailer[7] = 1;
  trailer.writeBigUInt64BE(2n, 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(offsetTableOffset), 24);
  return Buffer.concat([header, objects, offsets, trailer]);
}

const ARRAY_XML_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array>
  <string>a</string>
</array>
</plist>`;

describe("binary Apple plist protection", () => {
  it("refuses a trailer claiming an absent offset table", () => {
    const raw = Buffer.concat([Buffer.from("bplist00"), Buffer.from([0xd0]), Buffer.alloc(32)]);
    expect(() => protectApplePlistBuffer(raw)).toThrow(/invalid offset table or trailer/i);
  });

  it("refuses a binary plist without room for a header and trailer", () => {
    expect(() =>
      protectApplePlistBuffer(Buffer.from("bplist00", "latin1")),
    ).toThrow(/binary Apple property list/i);
  });

  it("names the skip when a binary plist root is not a dictionary", () => {
    const raw = bplistWithArrayRoot();
    const res = protectApplePlistBuffer(raw, { intensity: "balanced", seed: "plist-skip" });
    expect(res.protectionSkipped).toMatch(/root object is not a dictionary/i);
    expect(res.buffer.equals(raw)).toBe(true);
    expect(res.decoyEnclaveEntitlementsAdded).toBe(0);
  });

  it("names the skip when an XML plist root is not a dictionary", () => {
    const res = protectApplePlistBuffer(Buffer.from(ARRAY_XML_PLIST, "utf8"), {
      intensity: "balanced",
      seed: "plist-skip",
    });
    expect(res.protectionSkipped).toMatch(/root element is not a <dict>/i);
    expect(res.decoyEnclaveEntitlementsAdded).toBe(0);
  });

  it("does not report planted decoys or patched sections when the plist was skipped", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-plist-skip-"));
    try {
      const inputPath = join(dir, "input.plist");
      writeFileSync(inputPath, bplistWithArrayRoot());
      const res = protectTarget({
        inputPath,
        outputPath: join(dir, "out.plist"),
        intensity: "balanced",
        seed: "plist-skip",
      });
      expect(res.protectionSkipped).toMatch(/root object is not a dictionary/i);
      expect(res.metrics.decoyFunctionsInjected).toBe(0);
      expect(res.metrics.binarySectionsPatched).toBe(0);
      expect(res.counteredReaVectors).not.toContain("apple-plist-budget");
      expect(readFileSync(join(dir, "out.plist")).equals(readFileSync(inputPath))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});