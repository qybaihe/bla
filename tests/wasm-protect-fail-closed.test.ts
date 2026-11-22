import { describe, expect, it } from "vitest";
import { protectWasmBinary } from "../src/shields/formats/wasm.js";

/**
 * A module a host can actually instantiate: type + function + export + code.
 * (Header + export alone is not valid — the exported function index would not
 * exist — so it must not be used as the "valid" control.)
 */
function validWasm(): Buffer {
  return Buffer.concat([
    Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]),
    Buffer.from([0x01, 0x04, 0x01, 0x60, 0x00, 0x00]), // type: () -> ()
    Buffer.from([0x03, 0x02, 0x01, 0x00]), // function: one of type 0
    Buffer.from([0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00]), // export "run"
    Buffer.from([0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b]), // code: locals 0, end
  ]);
}

describe("protectWasmBinary fails closed on a malformed section table", () => {
  it("refuses a module whose section-size header is a truncated LEB128", () => {
    const truncated = Buffer.concat([validWasm(), Buffer.from([0x01, 0x80])]);
    expect(WebAssembly.validate(new Uint8Array(truncated))).toBe(false);
    expect(() => protectWasmBinary(truncated)).toThrow(/WebAssembly/i);
  });

  it("refuses a module whose section size runs past the end of the file", () => {
    const overlong = Buffer.concat([validWasm(), Buffer.from([0x01, 0x50, 0x00])]);
    expect(WebAssembly.validate(new Uint8Array(overlong))).toBe(false);
    expect(() => protectWasmBinary(overlong)).toThrow(/WebAssembly/i);
  });

  it("still protects a valid module and emits a module the runtime accepts", () => {
    const result = protectWasmBinary(validWasm(), { intensity: "balanced", seed: "wasm-fail-closed" });
    expect(result.buffer.length).toBeGreaterThan(validWasm().length);
    expect(WebAssembly.validate(new Uint8Array(result.buffer))).toBe(true);
  });
});
