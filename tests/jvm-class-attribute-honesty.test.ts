import { describe, expect, it } from "vitest";
import { protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";

/**
 * A minimal class whose structure parses far enough for structural mode:
 * magic + minor + major + constant_pool_count(=1) + access_flags..attributes_count.
 * Class-level `attributes_count` sits at byte 24 and is 0.
 */
function structuralClass(): Buffer {
  const cls = Buffer.alloc(26, 0);
  cls.writeUInt32BE(0xcafebabe, 0);
  cls.writeUInt16BE(0, 4); // minor
  cls.writeUInt16BE(65, 6); // major
  cls.writeUInt16BE(1, 8); // constant_pool_count (empty pool)
  cls.writeUInt16BE(0, 24); // attributes_count
  return cls;
}

describe("JVM structural protection reports only what it actually emits", () => {
  it("does not claim a class attribute when the decoy corpus is appended after the class body", () => {
    const input = structuralClass();
    const res = protectJvmClassBuffer(input, { intensity: "balanced", seed: "jvm-honesty" });

    expect(res.mode).toBe("structural");
    expect(res.constantPoolEntriesAdded).toBeGreaterThan(0);

    // The constant pool really did grow in the class header.
    expect(res.buffer.readUInt16BE(8)).toBe(1 + res.constantPoolEntriesAdded);

    // No §4.7.1 class attribute is emitted, so the counter must be 0.
    expect(res.customAttributesAdded).toBe(0);

    // The bytes after the class body are a JSON trailer, not an attribute table.
    const jsonStart = res.buffer.indexOf(Buffer.from('{"schema":"bla-jvm-enclave-v1"'));
    expect(jsonStart).toBeGreaterThan(0);
    expect(res.buffer.readUInt16BE(jsonStart - 2)).toBe(0); // attributes_count still 0
    // A real attribute would start with an in-range name_index; JSON cannot.
    expect(res.buffer.readUInt16BE(jsonStart)).toBeGreaterThan(res.buffer.readUInt16BE(8));
  });

  it("keeps reporting zero structural counters on the trailer fallback path", () => {
    const cls = Buffer.alloc(24, 0);
    cls.writeUInt32BE(0xcafebabe, 0);
    cls.writeUInt16BE(0, 4);
    cls.writeUInt16BE(55, 6);
    cls.writeUInt16BE(1, 8);
    const res = protectJvmClassBuffer(cls, { intensity: "balanced", seed: "jvm-honesty-trailer" });

    expect(res.mode).toBe("trailer");
    expect(res.constantPoolEntriesAdded).toBe(0);
    expect(res.customAttributesAdded).toBe(0);
  });
});