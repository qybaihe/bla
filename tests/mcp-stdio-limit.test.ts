import { once } from "node:events";
import { createInterface } from "node:readline";
import { PassThrough, Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { createStdioLineProcessor, MAX_STDIO_LINE_CHARS, MAX_STDIO_PENDING_BYTES, MAX_STDIO_PENDING_REQUESTS, startMcpStdioServer } from "../src/mcp/server.js";

function collect() {
  const lines: string[] = [];
  let oversized = 0;
  const processor = createStdioLineProcessor({
    onLine: (line) => lines.push(line),
    onOversizedLine: () => {
      oversized++;
    },
  });
  return { lines, processor, oversizedCount: () => oversized };
}

describe("MCP stdio line processor", () => {
  it("delimits newline-framed JSON-RPC lines across chunk boundaries and skips framing lines", () => {
    const { lines, processor } = collect();
    processor.push('{"jsonrpc":"2.0","id":1,"method":"in');
    const framed = '{"jsonrpc":"2.0","id":2,"method":"ping"}';
    processor.push(`itialize"}\nContent-Length: ${Buffer.byteLength(framed)}\r\n\r\n`);
    processor.push(framed);
    expect(lines).toEqual([
      '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
      '{"jsonrpc":"2.0","id":2,"method":"ping"}',
    ]);
  });

  it("rejects an unterminated partial line past the cap and recovers at the next newline", () => {
    const { lines, processor, oversizedCount } = collect();
    processor.push("x".repeat(MAX_STDIO_LINE_CHARS + 1));
    expect(oversizedCount()).toBe(1);
    expect(lines).toEqual([]);
    // The rest of the oversized line drains silently, then a valid message flows through.
    processor.push("y".repeat(64) + '\n{"jsonrpc":"2.0","id":3,"method":"ping"}\n');
    expect(oversizedCount()).toBe(1);
    expect(lines).toEqual(['{"jsonrpc":"2.0","id":3,"method":"ping"}']);
  });

  it("rejects a complete single line past the cap instead of parsing it", () => {
    const { lines, processor, oversizedCount } = collect();
    processor.push("z".repeat(MAX_STDIO_LINE_CHARS + 1) + "\n");
    expect(oversizedCount()).toBe(1);
    expect(lines).toEqual([]);
    // Buffer must be empty again: the next small message is not poisoned.
    processor.push('{"id":4}\n');
    expect(lines).toEqual(['{"id":4}']);
  });

  it("keeps a partial line buffered until its newline arrives", () => {
    const { lines, processor, oversizedCount } = collect();
    processor.push('{"jsonrpc":"2.0","id":5,');
    expect(lines).toEqual([]);
    expect(oversizedCount()).toBe(0);
    processor.push('"method":"ping"}\n');
    expect(lines).toEqual(['{"jsonrpc":"2.0","id":5,"method":"ping"}']);
  });
});

describe("MCP stdio queue", () => {
  it.each([
    { accepted: MAX_STDIO_PENDING_REQUESTS, padding: "" },
    // Each UTF-8 payload uses just over half the byte budget.
    { accepted: 1, padding: "雪".repeat(Math.ceil(MAX_STDIO_PENDING_BYTES / 6)) },
  ])("rejects overflow and recovers after $accepted requests", async ({ accepted, padding }) => {
    const input = new PassThrough();
    const output = new PassThrough();
    const reader = createInterface({ input: output });
    const lines = reader[Symbol.asyncIterator]();
    startMcpStdioServer(input, output);
    const ping = (id: number) => JSON.stringify({
      jsonrpc: "2.0", method: "ping", id, params: { padding },
    }) + "\n";
    try {
      // One synchronous in-memory delivery admits the entire batch before any
      // queued dispatch microtask can run, independent of OS pipe scheduling.
      input.write(Array.from({ length: accepted + 1 }, (_, id) => ping(id)).join(""));
      const responses = new Map();
      for (let i = 0; i <= accepted; i++) {
        const response = JSON.parse((await lines.next()).value!);
        responses.set(response.id, response);
      }
      for (let id = 0; id < accepted; id++) expect(responses.get(id)?.result).toEqual({});
      expect(responses.get(accepted)?.error?.code).toBe(-32000);
      input.end(ping(accepted + 1));
      expect(JSON.parse((await lines.next()).value!)).toMatchObject({ id: accepted + 1, result: {} });
    } finally {
      reader.close();
      input.destroy();
      output.destroy();
    }
  });

  it.each(["close", "error"])("releases paused input when output emits %s", async (event) => {
    const input = new PassThrough();
    const output = new Writable({ highWaterMark: 1, write() { /* Hold the write until teardown. */ } });
    startMcpStdioServer(input, output);
    const paused = once(input, "pause");
    input.write('{"jsonrpc":"2.0","method":"ping","id":1}\n');
    await paused;
    const closed = new Promise<void>((resolve) => output.once("close", resolve));
    output.destroy(event === "error" ? new Error("output disconnected") : undefined);
    await closed;
    expect(input.isPaused()).toBe(false);
    expect(input.listenerCount("data")).toBe(0);
    expect(output.listenerCount("drain")).toBe(0);
    input.destroy();
  });
});
