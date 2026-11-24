import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createStdioLineProcessor, MAX_STDIO_LINE_CHARS, startMcpStdioServer } from "../src/mcp/server.js";

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
    { accepted: 16, padding: "" },
    // Three bytes per character: two such requests exceed the aggregate byte budget.
    { accepted: 1, padding: "雪".repeat(720_000) },
  ])("rejects overflow and recovers after $accepted requests", async ({ accepted, padding }) => {
    const input = new PassThrough();
    const output = new PassThrough();
    const responses = new Map<number, { result?: unknown; error?: { code: number } }>();
    output.on("data", (chunk: Buffer) => {
      const response = JSON.parse(chunk.toString());
      responses.set(response.id, response);
    });
    startMcpStdioServer(input, output);
    const ping = (id: number) => JSON.stringify({
      jsonrpc: "2.0", method: "ping", id, params: { padding },
    }) + "\n";
    for (let id = 0; id <= accepted; id++) input.write(ping(id));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(responses.size).toBe(accepted + 1);
    for (let id = 0; id < accepted; id++) expect(responses.get(id)?.result).toEqual({});
    expect(responses.get(accepted)?.error?.code).toBe(-32000);
    input.end(ping(accepted + 1));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(responses.get(accepted + 1)?.result).toEqual({});
  });
});
