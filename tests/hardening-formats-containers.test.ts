import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";
import {
  planAsarHeaderAmplification,
  REA_ASAR_HEADER_LIMITS,
} from "../src/shields/exhaustion/asar-header-amplifier.js";
import { packAsarBuffer, unpackAsarBuffer } from "../src/shields/formats/asar.js";
import { protectApplePlistBuffer } from "../src/shields/formats/apple-plist.js";
import { protectZipOrApkBuffer, readZipEntries, writeZipArchive } from "../src/shields/formats/archive.js";
import {
  encodeGgufString,
  encodeGgufStringKv,
  GGUF_TYPE_ARRAY,
  GGUF_TYPE_UINT32,
  parseGgufLayout,
} from "../src/shields/formats/gguf-layout.js";
import { inspectModelBuffer, protectGgufBuffer } from "../src/shields/formats/model.js";
import {
  extractSqliteSidecarSchemaCommentJson,
  plantSqliteSidecarSchemaComment,
  protectSqliteBuffer,
  stripSqliteSidecarSchemaComment,
} from "../src/shields/formats/sqlite.js";
import {
  appendWasmCustomSection,
  createWasmCustomSection,
  protectWasmBinary,
  renameWasmExports,
  stripWasmCustomSectionByName,
} from "../src/shields/formats/wasm.js";
import { generateSidecarSqliteSchemaComment } from "../src/shields/runtime/sidecar-entangle.js";

const WASM_HEADER = Buffer.from("0061736d01000000", "hex");
const MEMORY_ONLY = Buffer.concat([WASM_HEADER, Buffer.from("0503010001070a01066d656d6f72790200", "hex")]);
const EXPORTED_FUNCTION = Buffer.concat([WASM_HEADER, Buffer.from("01040160000003020100070501016600000a040102000b", "hex")]);

describe("WASM protection", () => {
  it("preserves an executable memory-only module and emits no function aliases", () => {
    const output = protectWasmBinary(MEMORY_ONLY, { intensity: "maximum" });
    const module = new WebAssembly.Module(new Uint8Array(output.buffer));
    expect(WebAssembly.validate(new Uint8Array(output.buffer))).toBe(true);
    expect(output.exportDecoysInjected).toBe(0);
    expect(WebAssembly.Module.exports(module)).toEqual([{ name: "memory", kind: "memory" }]);
    expect(new WebAssembly.Instance(module).exports.memory).toBeInstanceOf(WebAssembly.Memory);
    expect(() => protectWasmBinary(Buffer.concat([WASM_HEADER, Buffer.from([7])])))
      .toThrow(/WebAssembly validation/i);
  });

  it("retains the section ordinals and offsets of relocatable WASM", () => {
    // A DATA section defining a 4-byte symbol, followed by a custom section
    // with a MEMORY_ADDR_I32 relocation against that symbol.
    const object = Buffer.concat([
      WASM_HEADER,
      Buffer.from("05030100010b0a010041000b0400000000", "hex"),
      createWasmCustomSection(".debug_info", Buffer.alloc(4)),
      createWasmCustomSection("producers", Buffer.from([0])),
      createWasmCustomSection("linking", Buffer.from([
        2,             // linking metadata version
        8, 8,          // symbol table subsection and length
        1, 1, 0,       // one defined data symbol
        1, 0x78,       // name "x"
        0, 0, 4,       // segment, offset, size
      ])),
      createWasmCustomSection("reloc..debug_info", Buffer.from([2, 1, 5, 0, 0, 0])),
    ]);
    const output = protectWasmBinary(object, { intensity: "maximum" });
    expect(WebAssembly.validate(new Uint8Array(output.buffer))).toBe(true);
    expect(output.buffer.subarray(0, object.length)).toEqual(object);
    const module = new WebAssembly.Module(new Uint8Array(output.buffer));
    expect(Buffer.from(WebAssembly.Module.customSections(module, "reloc..debug_info")[0]!))
      .toEqual(Buffer.from([2, 1, 5, 0, 0, 0]));
    expect(Buffer.from(WebAssembly.Module.customSections(module, ".debug_info")[0]!)).toEqual(Buffer.alloc(4));
    expect(stripWasmCustomSectionByName(output.buffer, ".debug_info")).toEqual(output.buffer);
    expect(() => appendWasmCustomSection(output.buffer, ".debug_info", Buffer.alloc(8))).toThrow(/relocatable/i);
    const withNote = appendWasmCustomSection(output.buffer, "test.note", Buffer.from("note"));
    expect(stripWasmCustomSectionByName(withNote, "test.note")).toEqual(output.buffer);
  });

  it("reserves all existing names when renaming and appending aliases", () => {
    const funcExport = Buffer.from([1, 1, 0x66, 0, 0]);
    const seed = "rename-collision";
    const rename = renameWasmExports(funcExport, new SeededPrng(seed), { onlyInternal: false }).renames[0]!;
    const existingName = Buffer.from(rename.to);
    const colliding = Buffer.concat([funcExport, Buffer.from([existingName.length]), existingName, Buffer.from([0, 0])]);
    colliding[0] = 2;
    const renamed = renameWasmExports(colliding, new SeededPrng(seed), {
      onlyInternal: false,
      preserveExports: [rename.to],
    });
    expect(renamed.renames[0]!.to).not.toBe(rename.to);

    const aliasOptions = { seed: "alias-collision", intensity: "balanced" as const };
    const reference = protectWasmBinary(EXPORTED_FUNCTION, aliasOptions);
    const module = new WebAssembly.Module(new Uint8Array(reference.buffer));
    const alias = Buffer.from(WebAssembly.Module.exports(module)[1]!.name);
    const payload = Buffer.concat([colliding.subarray(0, 5), Buffer.from([alias.length]), alias, Buffer.from([0, 0])]);
    const input = Buffer.concat([
      EXPORTED_FUNCTION.subarray(0, 18),
      Buffer.from([7, payload.length]),
      payload,
      EXPORTED_FUNCTION.subarray(25),
    ]);
    const protectedModule = new WebAssembly.Module(new Uint8Array(protectWasmBinary(input, aliasOptions).buffer));
    const names = WebAssembly.Module.exports(protectedModule).map((entry) => entry.name);
    expect(names).toHaveLength(4);
    expect(new Set(names).size).toBe(names.length);
    expect(names).toContain(alias.toString());
  });
});

function rawAsar(files: object, payload = Buffer.alloc(0)): Buffer {
  const json = Buffer.from(JSON.stringify({ files }));
  const alignedLength = Math.ceil(json.length / 4) * 4;
  const header = Buffer.alloc(16 + alignedLength);
  header.writeUInt32LE(4, 0);
  header.writeUInt32LE(alignedLength + 8, 4);
  header.writeUInt32LE(alignedLength + 4, 8);
  header.writeUInt32LE(json.length, 12);
  json.copy(header, 16);
  return Buffer.concat([header, payload]);
}

describe("ASAR protection", () => {
  it("grows the serialized header beyond the target with portable basenames", () => {
    const plan = planAsarHeaderAmplification(new SeededPrng("asar-header"), "bankrupt");
    const packed = packAsarBuffer(plan.files);
    expect(plan.exceedsDefaultAdmission).toBe(true);
    expect(packed.readUInt32LE(4)).toBeGreaterThan(REA_ASAR_HEADER_LIMITS.DEFAULT_ASAR_MAX_HEADER_BYTES);
    for (const { relativePath } of unpackAsarBuffer(packed)) {
      if (relativePath.split("/").some((name) => Buffer.byteLength(name) > 200)) {
        throw new Error(`Oversized ASAR component: ${relativePath}`);
      }
    }
  });

  it("preserves special filenames and gives the decoys a free directory", () => {
    const plan = planAsarHeaderAmplification(new SeededPrng("asar-tree"), "stealth");
    const content = Buffer.from("customer content");
    const input = [
      { relativePath: "__proto__", content },
      { relativePath: "constructor/__proto__", content },
      { relativePath: "enclave/shards", content },
      { relativePath: "enclave/SHARDS-1/kept", content },
    ];
    const entries = unpackAsarBuffer(packAsarBuffer([...plan.files, ...input]));
    for (const member of input) expect(entries).toContainEqual({ ...member, size: content.length });
    expect(entries.filter((entry) => entry.relativePath.startsWith("enclave/shards-2/")))
      .toHaveLength(plan.files.length);

    const empty = unpackAsarBuffer(rawAsar({ enclave: { files: { shards: { files: {} } } } }));
    const repacked = unpackAsarBuffer(packAsarBuffer([...empty, ...plan.files]));
    expect(repacked[0]).toMatchObject({ relativePath: "enclave/shards", directory: true });
    expect(repacked[1]?.relativePath).toMatch(/^enclave\/shards-1\//);

    const rootFile = [{ relativePath: "enclave", content }, ...plan.files];
    expect(unpackAsarBuffer(packAsarBuffer(rootFile))[1]?.relativePath).toMatch(/^enclave-shards\//);
  });

  it("rejects duplicate leaves and file/directory conflicts in both insertion orders", () => {
    const leaf = { relativePath: "asset", content: Buffer.from("a") };
    const nested = { ...leaf, relativePath: "asset/details" };
    expect(() => packAsarBuffer([leaf, { ...leaf, relativePath: "/asset" }])).toThrow(/duplicate/i);
    expect(() => packAsarBuffer([leaf, nested])).toThrow(/conflict/i);
    expect(() => packAsarBuffer([nested, leaf])).toThrow(/conflict/i);
  });

  it("validates links at the archive root and bounds depth and overlapping file copies", () => {
    const target = { relativePath: "real", content: Buffer.from("x") };
    const link = { relativePath: "sub/link", link: "real", content: Buffer.alloc(0) };
    expect(unpackAsarBuffer(packAsarBuffer([target, link]))).toContainEqual(link);
    expect(() => packAsarBuffer([target, { ...link, link: "../real" }])).toThrow(/link target/i);
    expect(() => unpackAsarBuffer(rawAsar({ sub: { files: { link: { link: "../real" } } } })))
      .toThrow(/link target/i);
    const shared = unpackAsarBuffer(rawAsar({
      first: { size: 4, offset: "0" },
      second: { size: 4, offset: "0" },
    }, Buffer.from("same")));
    expect(shared.map((entry) => entry.content.toString())).toEqual(["same", "same"]);
    expect(() => unpackAsarBuffer(rawAsar({
      a: { size: 3, offset: "0" },
      b: { size: 3, offset: "1" },
      c: { size: 3, offset: "0" },
    }, Buffer.alloc(4)))).toThrow(/aggregate packed payload/i);

    let tree: object = { real: { size: 0, offset: "0" } };
    for (let i = 0; i < 70; i++) tree = { dir: { files: tree } };
    expect(() => unpackAsarBuffer(rawAsar(tree))).toThrow(/directory depth/i);
  });
});

function withScratch<T>(run: (directory: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "bla-containers-"));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withDatabase<T>(path: string, run: (db: InstanceType<ReturnType<typeof getDatabaseSyncClass>>) => T): T {
  const DatabaseSync = getDatabaseSyncClass();
  const db = new DatabaseSync(path);
  try {
    return run(db);
  } finally {
    db.close();
  }
}

const customerSql = `
  CREATE TABLE enclave_customer(id INTEGER PRIMARY KEY, value TEXT);
  CREATE VIEW customer_view AS SELECT value FROM enclave_customer;
  CREATE INDEX customer_index ON enclave_customer(value);
  CREATE TRIGGER customer_trigger AFTER INSERT ON enclave_customer
    BEGIN UPDATE enclave_customer SET value = upper(new.value) WHERE id = new.id; END;
  INSERT INTO enclave_customer VALUES (1, 'Customer value');
`;

describe("SQLite protection", () => {
  it("refuses a case-insensitive reserved table collision before replacing customer rows", () => withScratch((dir) => {
    const path = join(dir, "customer.sqlite");
    withDatabase(path, (db) => db.exec(`
      CREATE TABLE CanAry_Transport_Redaction (
        canary_id INTEGER PRIMARY KEY, canary_token TEXT NOT NULL, ambiguous_transport_url TEXT NOT NULL,
        conflicting_query_url TEXT NOT NULL, policy_notice TEXT NOT NULL
      );
      INSERT INTO CanAry_Transport_Redaction VALUES (1, 'customer token', 'a', 'b', 'policy');
    `));
    const raw = readFileSync(path);
    expect(() => protectSqliteBuffer(raw)).toThrow(/reserved SQLite object name/i);
    expect(readFileSync(path)).toEqual(raw);
  }));

  it("refuses customer triggers attached even to a recognized reserved schema", () => withScratch((dir) => {
    const path = join(dir, "customer.sqlite");
    withDatabase(path, (db) => db.exec(customerSql));
    writeFileSync(path, protectSqliteBuffer(readFileSync(path)).buffer);
    withDatabase(path, (db) => db.exec(`
      CREATE TRIGGER custom_canary_trigger AFTER INSERT ON canary_transport_redaction
      BEGIN UPDATE enclave_customer SET value = new.canary_token; END;
    `));
    expect(() => protectSqliteBuffer(readFileSync(path))).toThrow(/custom_canary_trigger/i);
  }));

  it("preserves customer views, triggers and indexes and refuses a reserved sidecar view", () => withScratch((dir) => {
    const path = join(dir, "customer.sqlite");
    withDatabase(path, (db) => db.exec(customerSql + `
      CREATE VIEW BLA_Sidecar_V1 AS SELECT value FROM enclave_customer;
    `));
    const raw = readFileSync(path);
    const note = generateSidecarSqliteSchemaComment({
      entryPath: "customer.sqlite",
      sidecarPaths: ["extra"],
      expectedHex: "a".repeat(64),
    }).noteJson;
    expect(extractSqliteSidecarSchemaCommentJson(raw)).toBeNull();
    expect(stripSqliteSidecarSchemaComment(raw)).toEqual(raw);
    expect(() => plantSqliteSidecarSchemaComment(raw, note)).toThrow(/reserved SQLite object name/i);

    const shielded = protectSqliteBuffer(raw, { intensity: "stealth" }).buffer;
    const output = join(dir, "out.sqlite");
    writeFileSync(output, shielded);
    const snapshot = (file: string) => withDatabase(file, (db) => ({
      schema: db.prepare(`
        SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name IN ('enclave_customer', 'customer_view', 'customer_index', 'customer_trigger', 'BLA_Sidecar_V1')
        ORDER BY name
      `).all(),
      view: db.prepare("SELECT * FROM bla_sidecar_v1").all(),
    }));
    expect(snapshot(output)).toEqual(snapshot(path));
    withDatabase(output, (db) => {
      db.exec("INSERT INTO enclave_customer VALUES (2, 'still runs')");
      expect(db.prepare("SELECT * FROM customer_view WHERE value = 'STILL RUNS'").get()).toEqual({ value: "STILL RUNS" });
    });
  }));
});

const XML_PLIST = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>
<plist version="1.0"><dict>
<!-- </dict> -->
<key>nested</key><dict><key>app</key><string>software</string></dict>
<key>BLAEnclaveAttestation&#65;uthority</key><string>customer value</string>
</dict></plist>`;
const BINARY_PLIST = Buffer.from(
  "YnBsaXN0MDDSAQIDBlZuZXN0ZWRWc3RhdHVz0QQFU2FwcFhzb2Z0d2FyZQkIDRQbHiIrAAAAAAAAAQEAAAAAAAAABwAAAAAAAAAAAAAAAAAAACw=",
  "base64",
);

function binaryPlistNearReferenceLimit(): Buffer {
  // A root dictionary referencing an array with 250 one-byte object IDs.
  const array = Buffer.alloc(253);
  Buffer.from([0xaf, 0x10, 250]).copy(array);
  for (let i = 0; i < 250; i++) array[3 + i] = i + 3;
  const objects = [Buffer.from([0xd1, 1, 2]), Buffer.from("\x55items"), array];
  for (let i = 0; i < 250; i++) objects.push(Buffer.from([0x10, i]));
  const table = Buffer.alloc(objects.length * 2);
  let offset = 8;
  objects.forEach((object, i) => {
    table.writeUInt16BE(offset, 2 * i);
    offset += object.length;
  });
  const trailer = Buffer.alloc(32);
  trailer[6] = 2;
  trailer[7] = 1;
  trailer.writeBigUInt64BE(BigInt(objects.length), 8);
  trailer.writeBigUInt64BE(BigInt(offset), 24);
  return Buffer.concat([Buffer.from("bplist00"), ...objects, table, trailer]);
}

describe("Apple plist protection", () => {
  it("inserts valid XML entries after the nested dict and avoids customer key aliases", () => {
    const result = protectApplePlistBuffer(Buffer.from(XML_PLIST));
    const xml = result.buffer.toString("utf8");
    expect(result.triggersBudgetAbort).toBe(false);
    expect(xml).toContain("<!DOCTYPE plist PUBLIC");
    expect(xml).not.toContain("[]>");
    expect(xml).toContain("<!-- </dict> -->");
    expect(xml).toContain("<key>nested</key><dict><key>app</key><string>software</string></dict>");
    expect(xml).toContain("<key>BLAEnclaveAttestation&#65;uthority</key><string>customer value</string>");
    expect(xml).toContain("<key>BLAEnclaveAttestationAuthority_1</key>");
    expect(protectApplePlistBuffer(Buffer.from("<plist><dict/></plist>")).decoyEnclaveEntitlementsAdded)
      .toBeGreaterThan(0);
  });

  it("re-encodes the binary root and places the trailer immediately after the offset table", () => {
    const result = protectApplePlistBuffer(BINARY_PLIST);
    const { buffer } = result;
    const trailer = buffer.subarray(-32);
    const count = Number(trailer.readBigUInt64BE(8));
    const rootId = Number(trailer.readBigUInt64BE(16));
    const tableStart = Number(trailer.readBigUInt64BE(24));
    const offsetWidth = trailer[6]!;
    const refWidth = trailer[7]!;
    const objectOffset = (id: number) => buffer.readUIntBE(tableStart + id * offsetWidth, offsetWidth);
    const root = objectOffset(rootId);
    const rootCount = 2 + result.decoyEnclaveEntitlementsAdded;
    const largeCount = rootCount >= 15;
    expect(result.triggersBudgetAbort).toBe(false);
    expect(tableStart + count * offsetWidth + 32).toBe(buffer.length);
    expect(count).toBe(7 + result.decoyEnclaveEntitlementsAdded * 2);
    expect(buffer[root]).toBe(0xd0 | Math.min(15, rootCount));
    if (largeCount) expect(buffer.readUInt8(root + 2)).toBe(rootCount);
    const keyRefStart = root + (largeCount ? 3 : 1);
    const keyIds = Array.from({ length: rootCount }, (_, i) => buffer.readUIntBE(keyRefStart + i * refWidth, refWidth));
    expect(keyIds.slice(0, 2)).toEqual([1, 2]);
    const valueRefStart = keyRefStart + rootCount * refWidth;
    expect(buffer.readUIntBE(valueRefStart, refWidth)).toBe(3);
    expect(buffer.subarray(objectOffset(3), objectOffset(4))).toEqual(Buffer.from([0xd1, 4, 5]));
    expect(buffer.includes("BLAEnclaveAttestationAuthority")).toBe(true);
  });

  it("widens nested collection references when the binary object count crosses 255", () => {
    const { buffer } = protectApplePlistBuffer(binaryPlistNearReferenceLimit());
    const trailer = buffer.subarray(-32);
    expect(trailer[7]).toBe(2);
    const tableStart = Number(trailer.readBigUInt64BE(24));
    const offsetWidth = trailer[6]!;
    const arrayOffset = buffer.readUIntBE(tableStart + 2 * offsetWidth, offsetWidth);
    expect(buffer.subarray(arrayOffset, arrayOffset + 3)).toEqual(Buffer.from([0xaf, 0x10, 250]));
    expect(buffer.readUInt16BE(arrayOffset + 3)).toBe(3);
    expect(buffer.readUInt16BE(arrayOffset + 3 + 249 * 2)).toBe(252);
  });

  const plutil = process.platform === "darwin" && spawnSync("plutil", ["-help"]).status === 0;
  it.skipIf(!plutil)("passes macOS plutil lint and keeps nested values in XML and binary output", () => withScratch((dir) => {
    const utf16 = Buffer.from(`\uFEFF${XML_PLIST.replace("UTF-8", "UTF-16")}`, "utf16le").swap16();
    for (const [index, input] of [Buffer.from(XML_PLIST), BINARY_PLIST, utf16].entries()) {
      const path = join(dir, `output-${index}.plist`);
      writeFileSync(path, protectApplePlistBuffer(input).buffer);
      const lint = spawnSync("plutil", ["-lint", path], { encoding: "utf8" });
      expect(lint.status, lint.stdout + lint.stderr).toBe(0);
      const nested = spawnSync("plutil", ["-extract", "nested.app", "raw", path], { encoding: "utf8" });
      expect(nested.stdout.trim()).toBe("software");
    }
    const widePath = join(dir, "wide.plist");
    writeFileSync(widePath, protectApplePlistBuffer(binaryPlistNearReferenceLimit()).buffer);
    expect(spawnSync("plutil", ["-lint", widePath]).status).toBe(0);
  }));
});

function ggufFixture(type = 0, elements = 4n, dataBytes = 16, metadata: readonly Buffer[] = []): Buffer {
  const header = Buffer.alloc(24);
  header.write("GGUF");
  header.writeUInt32LE(3, 4);
  header.writeBigUInt64LE(1n, 8);
  header.writeBigUInt64LE(BigInt(metadata.length), 16);
  const descriptor = Buffer.alloc(24);
  descriptor.writeUInt32LE(1, 0);
  descriptor.writeBigUInt64LE(elements, 4);
  descriptor.writeUInt32LE(type, 12);
  const infos = Buffer.concat([header, ...metadata, encodeGgufString("tensor"), descriptor]);
  return Buffer.concat([infos, Buffer.alloc((32 - (infos.length % 32)) % 32), Buffer.alloc(dataBytes, 0x7a)]);
}

describe("GGUF protection", () => {
  it("emits flat, fixed-width arrays and preserves the aligned weight data", () => {
    const input = ggufFixture(2, 32n, 18);
    const { buffer, triggeredMetadataNestingBreaker } = protectGgufBuffer(input);
    const layout = parseGgufLayout(buffer)!;
    const slot = layout.kvs.find((kv) => kv.key === "enclave.topology.slots")!;
    expect(triggeredMetadataNestingBreaker).toBe(false);
    expect(slot.valueType).toBe(GGUF_TYPE_ARRAY);
    expect(buffer.readUInt32LE(slot.valueStart)).toBe(GGUF_TYPE_UINT32);
    expect(buffer.readBigUInt64LE(slot.valueStart + 4) * 4n + 12n)
      .toBe(BigInt(slot.end - slot.valueStart));
    expect(buffer.subarray(layout.dataStart)).toEqual(input.subarray(-18));
    expect(inspectModelBuffer(buffer)).toMatchObject({ validModel: true, blaProtected: true });
  });

  it("refuses missing, partial, or overflowing tensor extents", () => {
    for (const input of [
      ggufFixture(0, 4n, 0),
      ggufFixture(0, 4n, 15),
      ggufFixture(2, 32n, 17),
      ggufFixture(2, 33n, 36),
      ggufFixture(28, 2n ** 64n - 1n),
    ]) {
      expect(parseGgufLayout(input)).toBeNull();
      expect(() => protectGgufBuffer(input)).toThrow(/tensor layout/i);
    }
  });

  it("reads only metadata for protection markers even on a buffer beyond the string limit", () => {
    const weightSize = 512 * 1024 * 1024 + 32;
    const metadata = [encodeGgufStringKv("general.description", "[BLA-MODEL-SHIELD] metadata")];
    const prefix = ggufFixture(24, BigInt(weightSize), 0, metadata);
    const large = Buffer.allocUnsafe(prefix.length + weightSize);
    prefix.copy(large);
    const wholeBufferDecode = vi.spyOn(large, "toString");
    try {
      expect(inspectModelBuffer(large)).toMatchObject({ validModel: true, blaProtected: true });
      expect(wholeBufferDecode).not.toHaveBeenCalled();
    } finally {
      wholeBufferDecode.mockRestore();
    }
    const fake = ggufFixture(24, 32n, 32);
    fake.write("bla.sidecar.v1", fake.length - 32);
    expect(inspectModelBuffer(fake).blaProtected).toBe(false);
  });
});

describe("APK ZIP protection", () => {
  it("preserves the original compression method for large stored and small deflated members", () => {
    const lib = Buffer.alloc(4096, 0xff);
    const small = Buffer.from("small text");
    const apk = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest/>") },
      { name: "lib/arm64-v8a/libexample.so", data: lib, storeOnly: true },
      { name: "assets/small.txt", data: small, compressionMethod: 8 },
    ]);
    const output = readZipEntries(protectZipOrApkBuffer(apk, { intensity: "stealth", isApk: true }).buffer);
    expect(output.find((entry) => entry.name.endsWith("/libexample.so"))).toMatchObject({ compressionMethod: 0, data: lib });
    expect(output.find((entry) => entry.name === "assets/small.txt")).toMatchObject({ compressionMethod: 8, data: small });
  });

  it("rejects drive-qualified paths and duplicate normalized entry names", () => {
    const data = Buffer.from("asset");
    for (const name of ["C:/drop.bin", "C:\\drop.bin", "C:drop.bin", "./C:/drop.bin"]) {
      expect(() => protectZipOrApkBuffer(writeZipArchive([{ name, data }]))).toThrow(/archive root/i);
    }
    const alias = writeZipArchive([{ name: "a/b", data }, { name: "./a//b", data }]);
    expect(() => readZipEntries(alias)).toThrow(/duplicate filenames/i);
  });
});
