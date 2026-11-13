import { describe, expect, it } from "vitest";
import { inspectWasmBinary, protectWasmBinary } from "../src/shields/formats/wasm.js";

const HEADER = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

function leb(n: number): Buffer {
  const out: number[] = [];
  let v = n;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    out.push(byte);
  } while (v !== 0);
  return Buffer.from(out);
}

function customSection(name: string, content: string): Buffer {
  const nameBytes = Buffer.from(name, "utf8");
  const payload = Buffer.concat([leb(nameBytes.length), nameBytes, Buffer.from(content, "utf8")]);
  return Buffer.concat([Buffer.from([0x00]), leb(payload.length), payload]);
}

const LINKING_SECTIONS = ["dylink.0", "linking", "reloc.CODE", "target_features"] as const;

describe("WASM protection preserves linking-critical custom sections", () => {
  const input = Buffer.concat([
    HEADER,
    customSection("name", "debug-module-name"),
    customSection("producers", "producer=toolchain"),
    ...LINKING_SECTIONS.map((name) => customSection(name, `payload-for-${name}`)),
  ]);

  it("keeps dylink/linking/reloc/target_features and still drops debug metadata", () => {
    const res = protectWasmBinary(input, { intensity: "balanced", seed: "wasm-preserve" });
    const out = Buffer.isBuffer(res) ? res : res.buffer;

    for (const name of LINKING_SECTIONS) {
      expect(out.toString("latin1")).toContain(`payload-for-${name}`);
    }
    expect(out.toString("latin1")).not.toContain("producer=toolchain");

    // The module must still be a parseable WASM binary with the preserved sections listed.
    const inspected = inspectWasmBinary(out);
    expect(inspected.validMagic).toBe(true);
    for (const name of LINKING_SECTIONS) {
      expect(inspected.customSectionNames).toContain(name);
    }
  });

  it("still drops unrelated custom sections", () => {
    const res = protectWasmBinary(
      Buffer.concat([HEADER, customSection("producers", "producer=other")]),
      { intensity: "balanced", seed: "wasm-drop" },
    );
    const out = Buffer.isBuffer(res) ? res : res.buffer;
    expect(out.toString("latin1")).not.toContain("producer=other");
  });
});