import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverHardenTargets, hardenProject } from "../src/engine/harden.js";
import { handleMcpRequest } from "../src/mcp/server.js";
import { runCli } from "../src/cli.js";

const tempDirs: string[] = [];
function tmp(): string {
  const d = mkdtempSync(join(tmpdir(), "bla-write-safety-"));
  tempDirs.push(d);
  return d;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const JS = `export function unlockPremium(token) { return token === "LIVE-KEY"; }\n`;

function project(jsFiles = 2): string {
  const root = tmp();
  mkdirSync(join(root, "dist"), { recursive: true });
  for (let i = 0; i < jsFiles; i++) writeFileSync(join(root, "dist", `m${i}.js`), JS, "utf8");
  return root;
}

/** path → sha256 + mtime for every entry, so any write is visible. */
function snapshot(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, e.name);
      const rel = relative(root, full);
      if (e.isDirectory()) {
        out[`${rel}/`] = "dir";
        walk(full);
      } else {
        out[rel] = `${createHash("sha256").update(readFileSync(full)).digest("hex")}@${statSync(full).mtimeMs}`;
      }
    }
  };
  walk(root);
  return out;
}

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
      artifacts?: ReadonlyArray<{ relativePath?: string; outputPath?: string }>;
      truncated?: boolean;
      offset?: number;
      nextOffset?: number;
      dryRun?: boolean;
      overallSuccess?: boolean;
      hardenedCount?: number;
      discoveredCount?: number;
      wouldOverwrite?: readonly string[];
      status?: string;
      writeReceipt?: Readonly<Record<string, unknown>>;
    };
  };
}

describe("read-only discover + zero-write dry-run", () => {
  it("bla_discover inventories targets without writing", async () => {
    const root = project(2);
    const before = snapshot(root);
    const r = await call("bla_discover", { directory: root });
    expect(r.isError).toBe(false);
    expect((r.structuredContent.artifacts ?? []).map((a) => a.relativePath).sort()).toEqual([
      "dist/m0.js",
      "dist/m1.js",
    ]);
    expect(r.structuredContent.truncated).toBe(false);
    expect(snapshot(root)).toEqual(before);
  });

  it("reports truncation explicitly instead of silently capping", () => {
    const root = project(5);
    const d = discoverHardenTargets(root, { maxArtifacts: 3 });
    expect(d.artifacts).toHaveLength(3);
    expect(d.truncated).toBe(true);
    expect(d.maxArtifacts).toBe(3);
    expect(discoverHardenTargets(root, { maxArtifacts: 5 }).truncated).toBe(false);
    const report = hardenProject({ directory: root, dryRun: true, maxArtifacts: 3 });
    expect(report.truncated).toBe(true);
  });

  it("bla_harden dry_run plans outputs and leaves the workspace byte-identical", async () => {
    const root = project(2);
    const before = snapshot(root);
    const r = await call("bla_harden", { directory: root, dry_run: true });
    expect(r.isError).toBe(false);
    const rep = r.structuredContent;
    expect(rep.dryRun).toBe(true);
    // Preview must not claim a successful harden.
    expect(rep.overallSuccess).toBe(false);
    expect(rep.hardenedCount).toBe(0);
    expect(rep.discoveredCount).toBe(2);
    expect(rep.artifacts?.[0]?.outputPath).toContain(".bla-hardened");
    expect(rep.wouldOverwrite).toEqual([]);
    expect(rep.writeReceipt).toBeUndefined();
    expect(existsSync(join(root, ".bla-hardened"))).toBe(false);
    expect(snapshot(root)).toEqual(before);
  });

  it("dry_run never demands confirm_overwrite even when planned outputs already exist", async () => {
    const root = project(1);
    const first = await call("bla_harden", { directory: root, seed: "pre" });
    expect(first.isError).toBe(false);
    const out = join(root, ".bla-hardened", "dist", "m0.js");
    const hardened = readFileSync(out, "utf8");
    const before = snapshot(root);

    const preview = await call("bla_harden", { directory: root, dry_run: true, seed: "pre2" });
    expect(preview.isError).toBe(false);
    expect(preview.structuredContent.status).not.toBe("confirmation_required");
    expect(preview.structuredContent.dryRun).toBe(true);
    expect(preview.structuredContent.overallSuccess).toBe(false);
    expect(preview.structuredContent.wouldOverwrite).toEqual([out]);
    expect(readFileSync(out, "utf8")).toBe(hardened);
    expect(snapshot(root)).toEqual(before);
  });

  it("CLI `harden --dry-run` writes nothing (no .bla-hardened, no .blarc)", async () => {
    const root = project(1);
    const before = snapshot(root);
    const code = await runCli(["harden", root, "--dry-run", "--json"]);
    expect(code).toBe(0);
    expect(snapshot(root)).toEqual(before);
  });
});

describe("overwrite confirmation boundary", () => {
  it("bla_harden refuses to clobber existing hardened outputs without confirm_overwrite", async () => {
    const root = project(1);
    const first = await call("bla_harden", { directory: root, seed: "s1" });
    expect(first.isError).toBe(false);
    expect(first.structuredContent.hardenedCount).toBe(1);
    const out = join(root, ".bla-hardened", "dist", "m0.js");
    expect(first.structuredContent.writeReceipt).toMatchObject({
      status: "written",
      wrote: expect.arrayContaining([out]),
      overwrote: [],
      confirmed: false,
    });
    const hardened = readFileSync(out, "utf8");

    const refused = await call("bla_harden", { directory: root, seed: "s2" });
    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.status).toBe("confirmation_required");
    expect(refused.structuredContent.wouldOverwrite).toEqual([out]);
    expect(readFileSync(out, "utf8")).toBe(hardened);

    const ok = await call("bla_harden", { directory: root, seed: "s2", confirm_overwrite: true });
    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.hardenedCount).toBe(1);
    expect(ok.structuredContent.wouldOverwrite).toEqual([out]);
    expect(ok.structuredContent.writeReceipt).toMatchObject({
      status: "written",
      overwrote: [out],
      confirmed: true,
    });
  });

  it("bla_protect refuses an existing output_path without confirmation and succeeds with it", async () => {
    const root = project(1);
    const input = join(root, "dist", "m0.js");
    const output = join(root, "out.js");
    writeFileSync(output, "// precious\n", "utf8");

    const refused = await call("bla_protect", { input_path: input, output_path: output });
    expect(refused.isError).toBe(true);
    expect(refused.structuredContent.status).toBe("confirmation_required");
    expect(readFileSync(output, "utf8")).toBe("// precious\n");

    const ok = await call("bla_protect", {
      input_path: input,
      output_path: output,
      confirm_overwrite: true,
    });
    expect(ok.isError).toBe(false);
    expect(ok.structuredContent.writeReceipt).toMatchObject({
      status: "written",
      wrote: [output],
      overwrote: [output],
      confirmed: true,
    });
    expect(readFileSync(output, "utf8")).not.toBe("// precious\n");
  });

  it("bla_defend writes a fresh default output without confirmation and returns a receipt", async () => {
    const root = project(1);
    const input = join(root, "dist", "m0.js");
    const r = await call("bla_defend", { input_path: input, seed: "x" });
    expect(r.isError).toBe(false);
    const expected = join(root, "dist", "m0.shielded.js");
    expect(r.structuredContent.writeReceipt).toMatchObject({ wrote: [expected], overwrote: [] });

    const again = await call("bla_defend", { input_path: input, seed: "x" });
    expect(again.isError).toBe(true);
    expect(again.structuredContent.wouldOverwrite).toEqual([expected]);
  });
});

describe("discover offset paging (issue #75)", () => {
  it("pages through a 70-artifact tree without losing the tail", () => {
    const root = project(70);
    const pageSize = 20;
    const seen = new Set<string>();
    let offset = 0;
    let pages = 0;
    for (;;) {
      const page = discoverHardenTargets(root, { maxArtifacts: pageSize, offset });
      expect(page.offset).toBe(offset);
      expect(page.artifacts.length).toBeGreaterThan(0);
      expect(page.artifacts.length).toBeLessThanOrEqual(pageSize);
      for (const a of page.artifacts) {
        expect(seen.has(a.relativePath)).toBe(false);
        seen.add(a.relativePath);
      }
      pages += 1;
      if (!page.truncated) {
        expect(page.nextOffset).toBeUndefined();
        break;
      }
      expect(page.nextOffset).toBe(offset + page.artifacts.length);
      offset = page.nextOffset!;
      expect(pages).toBeLessThan(10);
    }
    expect(seen.size).toBe(70);
    expect(pages).toBe(4); // 20+20+20+10
  });

  it("bla_discover MCP returns nextOffset when truncated", async () => {
    const root = project(5);
    const r1 = await call("bla_discover", {
      directory: root,
      max_artifacts: 2,
    });
    expect(r1.isError).toBe(false);
    expect(r1.structuredContent.truncated).toBe(true);
    expect(r1.structuredContent.offset).toBe(0);
    expect(r1.structuredContent.nextOffset).toBe(2);
    expect((r1.structuredContent.artifacts ?? []).length).toBe(2);

    const r2 = await call("bla_discover", {
      directory: root,
      max_artifacts: 2,
      offset: r1.structuredContent.nextOffset,
    });
    expect(r2.isError).toBe(false);
    expect((r2.structuredContent.artifacts ?? []).length).toBe(2);
    expect(r2.structuredContent.offset).toBe(2);
    expect(r2.structuredContent.truncated).toBe(true);
    expect(r2.structuredContent.nextOffset).toBe(4);

    const r3 = await call("bla_discover", {
      directory: root,
      max_artifacts: 2,
      offset: r2.structuredContent.nextOffset,
    });
    expect(r3.isError).toBe(false);
    expect((r3.structuredContent.artifacts ?? []).length).toBe(1);
    expect(r3.structuredContent.truncated).toBe(false);
    expect(r3.structuredContent.nextOffset).toBeUndefined();

    const all = [
      ...(r1.structuredContent.artifacts ?? []),
      ...(r2.structuredContent.artifacts ?? []),
      ...(r3.structuredContent.artifacts ?? []),
    ].map((a) => a.relativePath);
    expect(new Set(all).size).toBe(5);
  });
});
