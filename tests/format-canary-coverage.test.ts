import { describe, expect, it } from "vitest";
import { protectAndroidDexBuffer, protectIl2cppMetadataBuffer } from "../src/shields/formats/mobile-game.js";
import { protectApplePlistBuffer, REA_MAX_BINARY_PLIST_NESTING_DEPTH } from "../src/shields/formats/apple-plist.js";
import {
  protectDotnetManagedBuffer,
  REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES,
} from "../src/shields/formats/dotnet-managed.js";
import { protectJvmClassBuffer } from "../src/shields/formats/jvm-bytecode.js";
import { protectZipOrApkBuffer, readZipEntries, writeZipArchive } from "../src/shields/formats/archive.js";

describe("Canary + system-diagnostic coverage on remaining formats", () => {
  it("embeds canary/diagnostic text in Android DEX string-pool trailer and keeps checksums valid", () => {
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);
    const res = protectAndroidDexBuffer(dex, { intensity: "balanced", seed: "dex-canary" });
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    expect(res.buffer.readUInt32LE(32)).toBe(res.buffer.length);
    expect(res.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(res.buffer.toString("latin1")).toMatch(/\[.*ERROR|FAULT|DIAG|SYSTEM/i);
  });

  it("embeds canary/diagnostic literals in IL2CPP global-metadata.dat trailer", () => {
    const meta = Buffer.alloc(256, 0);
    meta.writeUInt32LE(0xfab11baf, 0);
    meta.writeInt32LE(29, 4);
    const res = protectIl2cppMetadataBuffer(meta, { intensity: "balanced", seed: "il2-canary" });
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    expect(res.buffer.readUInt32LE(0)).toBe(0xfab11baf);
    expect(res.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
  });

  it(`claims bplist nesting past REA_MAX_BINARY_PLIST_NESTING_DEPTH (${REA_MAX_BINARY_PLIST_NESTING_DEPTH}) with canaries`, () => {
    const bplist = Buffer.concat([
      Buffer.from("bplist00", "latin1"),
      Buffer.alloc(32, 0),
    ]);
    const res = protectApplePlistBuffer(bplist, { intensity: "balanced", seed: "bplist-canary" });
    expect(res.exceedsBinaryPlistNestingDepth).toBe(true);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    expect(res.buffer.subarray(0, 6).toString("latin1")).toBe("bplist");
    expect(res.buffer.toString("latin1")).toContain(`BLA_BPLIST_DEPTH_GUARD_${REA_MAX_BINARY_PLIST_NESTING_DEPTH + 4}`);
  });

  it(`embeds canary/diagnostic into .NET managed assemblies under ${REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES} cap`, () => {
    const pe = Buffer.concat([
      Buffer.from("MZ", "ascii"),
      Buffer.alloc(64, 0),
      Buffer.from("BSJB", "ascii"),
      Buffer.alloc(32, 0),
    ]);
    const res = protectDotnetManagedBuffer(pe, { intensity: "balanced", seed: "dotnet-canary" });
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    expect(res.plan.totalReaRepresentationChargeBytes).toBeLessThan(
      REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES,
    );
    expect(res.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(res.buffer.toString("latin1")).toContain(`maxRepresentationBytes:${REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES}`);
  });

  it("embeds canary/diagnostic UTF-8 into JVM .class constant-pool / trailer", () => {
    // Minimal CAFEBABE header (not a full valid class — falls back to trailer path)
    const cls = Buffer.alloc(24, 0);
    cls.writeUInt32BE(0xcafebabe, 0);
    cls.writeUInt16BE(0, 4); // minor
    cls.writeUInt16BE(55, 6); // major
    cls.writeUInt16BE(1, 8); // cp count
    const res = protectJvmClassBuffer(cls, { intensity: "balanced", seed: "jvm-canary" });
    expect(res.mode).toBe("trailer");
    expect(res.constantPoolEntriesAdded).toBe(0);
    expect(res.customAttributesAdded).toBe(0);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    expect(res.buffer.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
  });

  it("reports structural constant-pool injection only for a parseable class layout", () => {
    const cls = Buffer.alloc(26, 0);
    cls.writeUInt32BE(0xcafebabe, 0);
    cls.writeUInt16BE(0, 4);
    cls.writeUInt16BE(55, 6);
    cls.writeUInt16BE(1, 8); // empty constant pool
    const res = protectJvmClassBuffer(cls, { intensity: "balanced", seed: "jvm-structural" });
    expect(res.mode).toBe("structural");
    expect(res.constantPoolEntriesAdded).toBeGreaterThan(0);
    expect(res.customAttributesAdded).toBe(1);
  });

  it("embeds canary decoys into ZIP members and recursively hardens nested DEX", () => {
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);
    const zip = writeZipArchive([
      { name: "readme.txt", data: Buffer.from("hello archive") },
      { name: "lib/classes.dex", data: dex },
    ]);
    const res = protectZipOrApkBuffer(zip, { intensity: "balanced", seed: "zip-canary" });
    expect(res.membersHardened).toBe(1);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    const entries = readZipEntries(res.buffer);
    expect(entries.find((e) => e.name === "readme.txt")?.data.toString()).toBe("hello archive");
    const outDex = entries.find((e) => e.name === "lib/classes.dex")!.data;
    expect(outDex.toString("latin1")).toContain("BLA-DEX-SHIELD");
    expect(outDex.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(entries.some((e) => e.name.includes("bla-canary-tokens"))).toBe(true);
  });
});
