import { describe, expect, it } from "vitest";
import { protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";

describe("JVM structural protection reports only what it actually emits", () => {
  it("refuses an incomplete class body with an otherwise valid constant pool", () => {
    const cls = Buffer.from("cafebabe0000003700030100014107000100210002", "hex");
    expect(() => protectJvmClassBuffer(cls, { intensity: "balanced", seed: "jvm-honesty" }))
      .toThrow(/JVM class/);
  });

  it("refuses an unframed EOF tail on a complete class structure", () => {
    const cls = Buffer.from("cafebabe000000370003010001410700010021000200000000000000000000", "hex");
    const rawTail = Buffer.concat([cls, Buffer.from('{"schema":"bla-jvm-enclave-v1"}')]);
    expect(() => protectJvmClassBuffer(rawTail, { intensity: "balanced", seed: "jvm-honesty-tail" }))
      .toThrow(/JVM class attribute table/);
  });
});
