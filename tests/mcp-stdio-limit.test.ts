import { describe, expect, it } from "vitest";
import { createStdioLineProcessor, MAX_STDIO_LINE_BYTES } from "../src/mcp/server.js";

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
    processor.push('itialize"}\nContent-Length: 64\r\n\r\n');
    processor.push('{"jsonrpc":"2.0","id":2,"method":"ping"}\n');
    expect(lines).toEqual([
      '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
      '{"jsonrpc":"2.0","id":2,"method":"ping"}',
    ]);
  });

  it("rejects an unterminated partial line past the cap and recovers at the next newline", () => {
    const { lines, processor, oversizedCount } = collect();
    processor.push("x".repeat(MAX_STDIO_LINE_BYTES + 1));
    expect(oversizedCount()).toBe(1);
    expect(lines).toEqual([]);
    // The rest of the oversized line drains silently, then a valid message flows through.
    processor.push("y".repeat(64) + '\n{"jsonrpc":"2.0","id":3,"method":"ping"}\n');
    expect(oversizedCount()).toBe(1);
    expect(lines).toEqual(['{"jsonrpc":"2.0","id":3,"method":"ping"}']);
  });

  it("rejects a complete single line past the cap instead of parsing it", () => {
    const { lines, processor, oversizedCount } = collect();
    processor.push("z".repeat(MAX_STDIO_LINE_BYTES + 1) + "\n");
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
