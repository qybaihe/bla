import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectGgufBuffer, UnsupportedGgufProtectionError } from "../src/shields/formats/model.js";
import { protectTarget } from "../src/engine/protector.js";
import { runCli } from "../src/cli.js";
import { handleMcpRequest } from "../src/mcp/server.js";

// Minimal little-endian GGUF v3 with one F32 tensor and nonzero tensor data.
function tensorModel(): Buffer {
  const bytes = Buffer.alloc(80);
  bytes.write("GGUF");
  bytes.writeUInt32LE(3, 4);
  bytes.writeBigUInt64LE(1n, 8); // tensor count; metadata count remains zero
  bytes.writeBigUInt64LE(6n, 24);
  bytes.write("weight", 32);
  bytes.writeUInt32LE(1, 38); // dimension count
  bytes.writeBigUInt64LE(4n, 42); // dimension size
  bytes.writeUInt32LE(0, 50); // F32
  bytes.writeBigUInt64LE(0n, 54); // offset relative to aligned data at byte 64
  [1, 2, 3, 4].forEach((value, index) => bytes.writeFloatLE(value, 64 + index * 4));
  return bytes;
}

describe("GGUF protection fails closed without losing model data", () => {
  let dir: string;
  let input: string;
  let original: Buffer;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "bla-gguf-safety-"));
    input = join(dir, "model.gguf");
    original = tensorModel();
    writeFileSync(input, original);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it.each(["stealth", "balanced", "maximum", "bankrupt"] as const)("rejects the buffer API at %s intensity without mutating tensors", (intensity) => {
    const model = Buffer.from(original);
    expect(() => protectGgufBuffer(model, { intensity, seed: "safety" })).toThrow(UnsupportedGgufProtectionError);
    expect(model).toEqual(original);
    expect(model.readBigUInt64LE(8)).toBe(1n);
    expect(model.readFloatLE(64)).toBe(1);
  });

  it("rejects even an empty buffer rather than creating a fake model", () => {
    expect(() => protectGgufBuffer(Buffer.alloc(0))).toThrow(/GGUF protection is unsupported/);
  });

  it("does not create the default output or a requested output directory", () => {
    expect(() => protectTarget({ inputPath: input })).toThrow(UnsupportedGgufProtectionError);
    expect(existsSync(join(dir, "model.shielded.gguf"))).toBe(false);
    expect(() => protectTarget({ inputPath: input, outputPath: join(dir, "new", "out.gguf") })).toThrow(UnsupportedGgufProtectionError);
    expect(existsSync(join(dir, "new"))).toBe(false);
    expect(readFileSync(input)).toEqual(original);
  });

  it("preserves the input for in-place and same-path output requests", () => {
    expect(() => protectTarget({ inputPath: input, inPlace: true })).toThrow(UnsupportedGgufProtectionError);
    expect(readFileSync(input)).toEqual(original);
    expect(() => protectTarget({ inputPath: input, outputPath: input })).toThrow(UnsupportedGgufProtectionError);
    expect(readFileSync(input)).toEqual(original);
  });

  it("preserves an existing output and rejects GGUF detected by magic without its extension", () => {
    const renamed = join(dir, "model.bin");
    writeFileSync(renamed, original);
    const output = join(dir, "existing.gguf");
    const sentinel = Buffer.from("existing output must remain intact");
    writeFileSync(output, sentinel);
    expect(() => protectTarget({ inputPath: renamed, outputPath: output })).toThrow(UnsupportedGgufProtectionError);
    expect(readFileSync(output)).toEqual(sentinel);
    expect(readFileSync(renamed)).toEqual(original);
  });

  it("returns CLI failure with an actionable error and leaves the input intact", async () => {
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    expect(await runCli(["protect", input, "--in-place"])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining("GGUF protection is unsupported"));
    expect(log).not.toHaveBeenCalled();
    expect(readFileSync(input)).toEqual(original);
  });

  it("returns MCP isError without overwriting an existing output", async () => {
    const output = join(dir, "existing.gguf");
    writeFileSync(output, original);
    const response = await handleMcpRequest({
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: "bla_protect", arguments: { input_path: input, output_path: output } },
    });
    expect(response?.result).toMatchObject({
      isError: true,
      content: [{ type: "text", text: expect.stringContaining("GGUF protection is unsupported") }],
    });
    expect(readFileSync(input)).toEqual(original);
    expect(readFileSync(output)).toEqual(original);
  });
});
