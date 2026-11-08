import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ENCRYPT_STRINGS_SCHEMA,
  buildKeystream,
  encryptStrings,
  xorDecodeBytes,
  xorEncodeToBytes,
} from "../src/engine/encrypt-strings.js";
import { SeededPrng } from "../src/core/prng.js";
import { lintPlaintextSecretsSource } from "../src/engine/plaintext-secret-lint.js";

describe("encrypt-strings (Direction-2)", () => {
  it("XOR round-trip preserves UTF-8", () => {
    const prng = new SeededPrng("test-seed").derive("string.encrypt");
    const ks = buildKeystream(prng, 64);
    const plain = "FLAG{round_trip_demo_value}";
    const enc = xorEncodeToBytes(plain, ks);
    expect(xorDecodeBytes(enc, ks)).toBe(plain);
  });

  it("encrypts FLAG + high-entropy in license.cjs and clears refuse lint", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-"));
    const src = `
function unlock(key) {
  const flag = "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}";
  const token = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";
  return key === "DemoV8-AegisKey!" ? flag : token;
}
module.exports = { unlock };
`;
    writeFileSync(join(dir, "license.cjs"), src);
    const before = lintPlaintextSecretsSource(src, { path: "license.cjs" });
    expect(before.shouldRefuseBankrupt).toBe(true);

    const report = encryptStrings({
      path: dir,
      seed: "unit-test-seed-v1",
      outDir: join(dir, "out"),
    });
    expect(report.schema).toBe(ENCRYPT_STRINGS_SCHEMA);
    expect(report.status).toBe("ok");
    expect(report.totalEncrypted).toBeGreaterThanOrEqual(2);
    expect(report.postLintClean).toBe(true);

    const out = readFileSync(join(dir, "out", "license.cjs"), "utf8");
    expect(out).toContain("_blaS");
    expect(out).not.toContain("FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}");
    expect(out).not.toContain("7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c");

    const after = lintPlaintextSecretsSource(out, { path: "license.cjs" });
    expect(after.shouldRefuseBankrupt).toBe(false);

    // Functional equivalence: require the rewritten module and call unlock.
    const mod = require(join(dir, "out", "license.cjs"));
    expect(mod.unlock("DemoV8-AegisKey!")).toBe(
      "FLAG{bla_v8_aegis_demo_fixture_not_the_real_prize}",
    );
  });

  it("same seed is reproducible; different seed differs", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-repro-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports.flag = "FLAG{repro_check_value_xx}";\n`,
    );
    const a = encryptStrings({
      path: dir,
      seed: "seed-A",
      outDir: join(dir, "a"),
    });
    const b = encryptStrings({
      path: dir,
      seed: "seed-A",
      outDir: join(dir, "b"),
    });
    const c = encryptStrings({
      path: dir,
      seed: "seed-B",
      outDir: join(dir, "c"),
    });
    expect(a.status).toBe("ok");
    const outA = readFileSync(join(dir, "a", "license.cjs"), "utf8");
    const outB = readFileSync(join(dir, "b", "license.cjs"), "utf8");
    const outC = readFileSync(join(dir, "c", "license.cjs"), "utf8");
    expect(outA).toBe(outB);
    expect(outA).not.toBe(outC);
  });


  it("encrypted stub does not trip lane-independence byte-compare lint", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-lane-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `function unlock(key){return key==="x"?"FLAG{lane_lint_safe_value_xx}":"no";}\nmodule.exports={unlock};\n`,
    );
    const report = encryptStrings({ path: dir, seed: "lane-seed", outDir: join(dir, "out") });
    expect(report.status).toBe("ok");
    const out = readFileSync(join(dir, "out", "license.cjs"), "utf8");
    expect(out).not.toMatch(/\[\s*\d+\s*(?:,\s*\d+\s*){3,}\]/);
    const { lintLaneIndependence } = await import("../src/engine/lane-independence-lint.js");
    const lane = lintLaneIndependence(out);
    expect(lane.looksLaneIndependent).toBe(false);
  });

  it("leaves UI-only license alone (noop)", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-ui-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports = { title: "Enter license", hint: "16-char key" };\n`,
    );
    const report = encryptStrings({ path: dir, seed: "seed-ui" });
    expect(report.status).toBe("noop");
    expect(report.totalEncrypted).toBe(0);
  });

  it("encrypts backtick literals while preserving comments, object keys, and require() specifiers", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-ast-"));
    const src = [
      `// Comment mentioning "FLAG{bla_ast_safe_value_123456}" must stay intact`,
      `const path = require("node:path");`,
      `const obj = { "FLAG{bla_ast_safe_value_123456}": 42 };`,
      `const secret = \`FLAG{bla_ast_safe_value_123456}\`;`,
      `module.exports = { obj, secret, isAbs: Boolean(path) };`,
      ``,
    ].join("\n");
    writeFileSync(join(dir, "license.cjs"), src);

    const report = encryptStrings({
      path: dir,
      seed: "ast-safe-seed",
      outDir: join(dir, "out"),
    });
    expect(report.status).toBe("ok");
    expect(report.totalEncrypted).toBe(1);

    const out = readFileSync(join(dir, "out", "license.cjs"), "utf8");
    // Comment and object property key remain valid syntax; runtime evaluates cleanly.
    expect(out).toContain(`// Comment mentioning "FLAG{bla_ast_safe_value_123456}" must stay intact`);
    expect(out).toContain(`{ "FLAG{bla_ast_safe_value_123456}": 42 }`);
    expect(out).not.toContain("`FLAG{bla_ast_safe_value_123456}`");

    const mod = require(join(dir, "out", "license.cjs"));
    expect(mod.secret).toBe("FLAG{bla_ast_safe_value_123456}");
    expect(mod.obj["FLAG{bla_ast_safe_value_123456}"]).toBe(42);
  });

  it("rejects unsafe outDir pointing into .git or node_modules", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-unsafe-out-"));
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports.flag = "FLAG{unsafe_outdir_check_123456}";\n`,
    );
    const gitOut = encryptStrings({
      path: dir,
      seed: "seed-unsafe",
      outDir: join(dir, ".git", "hooks"),
    });
    expect(gitOut.status).toBe("error");
    expect(gitOut.error).toMatch(/protected directory segment "\.git"/);
  });

  it("enforces MCP confirm_overwrite when out_dir targets already exist or when re-encrypting", async () => {
    const { handleMcpRequest } = await import("../src/mcp/server.js");
    const dir = mkdtempSync(join(tmpdir(), "bla-enc-mcp-overwrite-"));
    const outDir = join(dir, "out");
    writeFileSync(
      join(dir, "license.cjs"),
      `module.exports.flag = "FLAG{mcp_confirm_overwrite_check}";\n`,
    );

    const first = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "bla_encrypt_strings",
        arguments: { path: dir, seed: "s1", out_dir: outDir },
      },
    });
    const firstRes = first!.result as {
      isError: boolean;
      structuredContent: { writeReceipt?: { status: string; wrote: string[] } };
    };
    expect(firstRes.isError).toBe(false);
    expect(firstRes.structuredContent.writeReceipt?.status).toBe("written");

    const secondRefused = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "bla_encrypt_strings",
        arguments: { path: dir, seed: "s2", out_dir: outDir },
      },
    });
    const refusedRes = secondRefused!.result as {
      isError: boolean;
      structuredContent: { status?: string; wouldOverwrite?: string[] };
    };
    expect(refusedRes.isError).toBe(true);
    expect(refusedRes.structuredContent.status).toBe("confirmation_required");
    expect(refusedRes.structuredContent.wouldOverwrite).toEqual([
      join(outDir, "license.cjs"),
    ]);

    const secondConfirmed = await handleMcpRequest({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "bla_encrypt_strings",
        arguments: {
          path: dir,
          seed: "s2",
          out_dir: outDir,
          confirm_overwrite: true,
        },
      },
    });
    const confirmedRes = secondConfirmed!.result as {
      isError: boolean;
      structuredContent: {
        writeReceipt?: { confirmed: boolean; overwrote: string[] };
      };
    };
    expect(confirmedRes.isError).toBe(false);
    expect(confirmedRes.structuredContent.writeReceipt?.confirmed).toBe(true);
    expect(confirmedRes.structuredContent.writeReceipt?.overwrote).toEqual([
      join(outDir, "license.cjs"),
    ]);
  });
});
