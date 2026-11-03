import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { handleMcpRequest } from "../src/mcp/server.js";
import { protectTarget } from "../src/engine/protector.js";

const tempDirs: string[] = [];
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const JS = `export function unlockPremium(token) { return token === "LIVE-KEY"; }\n`;

async function call(name: string, args: Record<string, unknown>) {
  const res = await handleMcpRequest({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name, arguments: args },
  });
  expect(res?.error).toBeUndefined();
  return res!.result as {
    isError: boolean;
    structuredContent: {
      readonly [key: string]: unknown;
      status?: string;
      wouldOverwrite?: readonly string[];
      wrote?: readonly string[];
      writeReceipt?: Readonly<Record<string, unknown>>;
      outputDirectory?: string;
      metrics?: { honeySourceMapsGenerated?: number };
      defenseScore?: number;
      defenseScoreRaw?: number;
      defenseScoreGaps?: ReadonlyArray<{ id: string }>;
      outputPath?: string;
      selfSeal?: boolean;
    };
  };
}

describe("MCP param alignment: in_place / honey_source_maps / output_directory", () => {
  it("bla_protect in_place refuses without confirm_overwrite and succeeds with it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-inplace-"));
    tempDirs.push(dir);
    const input = join(dir, "app.js");
    writeFileSync(input, JS, "utf8");
    const before = readFileSync(input, "utf8");

    const refused = await call("bla_protect", {
      input_path: input,
      in_place: true,
      seed: "inplace-1",
    });
    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.status).toBe("confirmation_required");
    expect(refused.structuredContent.wouldOverwrite).toEqual([input]);
    expect(readFileSync(input, "utf8")).toBe(before);

    const ok = await call("bla_protect", {
      input_path: input,
      in_place: true,
      confirm_overwrite: true,
      seed: "inplace-1",
    });
    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.writeReceipt).toMatchObject({
      status: "written",
      wrote: [input],
      overwrote: [input],
      confirmed: true,
    });
    expect(readFileSync(input, "utf8")).not.toBe(before);
    expect(existsSync(join(dir, "app.shielded.js"))).toBe(false);
  });

  it("bla_defend in_place also requires confirm_overwrite before clobbering the input", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-defend-inplace-"));
    tempDirs.push(dir);
    const input = join(dir, "svc.js");
    writeFileSync(input, JS, "utf8");
    const refused = await call("bla_defend", {
      input_path: input,
      in_place: true,
      seed: "d-inplace",
    });
    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.wouldOverwrite).toEqual([input]);
    expect(readFileSync(input, "utf8")).toBe(JS);
  });

  it("bla_protect honey_source_maps:false skips honey map emission", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-honey-"));
    tempDirs.push(dir);
    const input = join(dir, "app.js");
    const output = join(dir, "out.js");
    writeFileSync(input, JS, "utf8");
    const off = await call("bla_protect", {
      input_path: input,
      output_path: output,
      honey_source_maps: false,
      seed: "honey-off",
    });
    expect(off.isError).toBe(false);
    expect(off.structuredContent.metrics?.honeySourceMapsGenerated).toBe(0);

    const onOut = join(dir, "out-on.js");
    const on = await call("bla_protect", {
      input_path: input,
      output_path: onOut,
      honey_source_maps: true,
      seed: "honey-on",
    });
    expect(on.isError).toBe(false);
    expect((on.structuredContent.metrics?.honeySourceMapsGenerated ?? 0) > 0).toBe(true);
  });

  it("bla_harden output_directory writes under the custom root", async () => {
    const root = mkdtempSync(join(tmpdir(), "bla-outdir-"));
    tempDirs.push(root);
    mkdirSync(join(root, "dist"), { recursive: true });
    writeFileSync(join(root, "dist", "m0.js"), JS, "utf8");
    const custom = join(root, "custom-out");
    const r = await call("bla_harden", {
      directory: root,
      output_directory: custom,
      seed: "outdir-1",
    });
    expect(r.isError).toBe(false);
    expect(r.structuredContent.outputDirectory).toBe(custom);
    expect(existsSync(join(custom, "dist", "m0.js"))).toBe(true);
    expect(existsSync(join(root, ".bla-hardened"))).toBe(false);
  });
});

describe("MCP bla_verify honesty metadata passthrough", () => {
  it("soft-caps JS verify without self_seal_enabled and lifts the gap when metadata says sealed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-verify-honesty-"));
    tempDirs.push(dir);
    const input = join(dir, "app.js");
    writeFileSync(input, JS, "utf8");
    const protectedRes = protectTarget({
      inputPath: input,
      intensity: "balanced",
      seed: "verify-honesty-1",
      selfSeal: true,
    });
    expect(protectedRes.selfSeal).toBe(true);

    const without = await call("bla_verify", {
      target_path: protectedRes.outputPath,
      original_path: input,
    });
    expect(without.isError).toBe(false);
    expect(
      without.structuredContent.defenseScoreGaps?.some((g) => g.id === "self-seal-not-enabled"),
    ).toBe(true);

    const withMeta = await call("bla_verify", {
      target_path: protectedRes.outputPath,
      original_path: input,
      self_seal_enabled: true,
    });
    expect(withMeta.isError).toBe(false);
    expect(
      withMeta.structuredContent.defenseScoreGaps?.some((g) => g.id === "self-seal-not-enabled"),
    ).toBe(false);
    expect(withMeta.structuredContent.defenseScoreRaw).toBeGreaterThanOrEqual(
      withMeta.structuredContent.defenseScore as number,
    );
  });
});
