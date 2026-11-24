import { afterEach, describe, expect, it, vi } from "vitest";
import { runCli } from "../src/cli.js";

const CONTROL_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;

describe("CLI output sanitization", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sanitizes the unknown-command message printed to stderr", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await runCli(["\u001b]0;poc\u0007"]);
    expect(code).toBe(1);
    const text = errorSpy.mock.calls.map((args) => String(args[0])).join("\n");
    expect(text).toContain("Unknown command:");
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
    expect(CONTROL_CHARS.test(text)).toBe(false);
  });

  it("sanitizes arg-error messages printed to stderr", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await runCli(["--intensity", "\u001b"]);
    expect(code).toBe(1);
    const text = errorSpy.mock.calls.map((args) => String(args[0])).join("\n");
    expect(text).toMatch(/--intensity must be one of/);
    expect(text).not.toContain("\u001b");
    expect(CONTROL_CHARS.test(text)).toBe(false);
  });
});