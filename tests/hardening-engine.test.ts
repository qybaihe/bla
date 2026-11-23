import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { defendTarget } from "../src/engine/defender.js";
import { encryptStrings } from "../src/engine/encrypt-strings.js";
import { buildTestJsAesUnwrapFootgun } from "../src/engine/js-aes-unwrap-lint.js";
import { hardenProject, restoreHardenedProject } from "../src/engine/harden.js";
import { applyHardenedOutputs, resolveApplyStateDirectory, restoreAppliedOriginals } from "../src/engine/harden-apply.js";
import { protectTarget } from "../src/engine/protector.js";
import { verifyTarget } from "../src/engine/verifier.js";
import { verifySidecarTarget } from "../src/engine/verify-sidecar.js";
import { packAsarBuffer, unpackAsarBuffer } from "../src/shields/formats/asar.js";
import {
  bindBunSidecarEntanglement,
  BUN_SIDECAR_COMPANION_SUFFIX,
} from "../src/shields/runtime/sidecar-entangle.js";

vi.mock("node:fs", async (importOriginal) => ({ ...await importOriginal<typeof fs>() }));

const roots: string[] = [];
function scratch(): string {
  const root = fs.mkdtempSync(join(tmpdir(), "bla-engine-regression-"));
  roots.push(root);
  return root;
}

function put(path: string, bytes: string | Buffer): string {
  fs.mkdirSync(dirname(path), { recursive: true });
  fs.writeFileSync(path, bytes);
  return path;
}

function run(path: string): string {
  return execFileSync(process.execPath, [path], { encoding: "utf8" }).trim();
}

function linkDir(target: string, link: string): void {
  fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
}

const canLinkDirectories = (() => {
  const root = scratch();
  try {
    linkDir(root, join(root, "probe"));
    return true;
  } catch {
    return false;
  }
})();

afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

const seed = "engine-regression";
const app = 'console.log("hello");\n';
const secret = "FLAG{token_boundary_and_directives}";
const hex = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6ccb8c6be33429eaec8a718f90f9f51722";

describe("harden promotion confinement and recovery", () => {
  it.skipIf(!canLinkDirectories)("rejects a linked project ancestor, build root and staging ancestor", () => {
    const root = scratch();
    const project = join(root, "project");
    const source = put(join(project, "src", "main.cjs"), app);
    const outside = join(root, "outside");
    fs.mkdirSync(outside);
    linkDir(project, join(root, "alias"));
    linkDir(join(project, "src"), join(project, "dist"));
    const options = { apply: true, applyStateRoot: scratch(), seed, intensity: "balanced" as const };
    expect(() => hardenProject({ ...options, directory: join(root, "alias", "src") })).toThrow(/symlink/);
    expect(() => hardenProject({ ...options, directory: project })).toThrow(/symlink/);
    fs.rmSync(join(project, "dist"), { force: true });
    put(join(project, "dist", "main.cjs"), app);
    linkDir(outside, join(root, "stage-link"));
    const outputDirectory = join(root, "stage-link", "new");
    expect(() => hardenProject({ ...options, directory: project, outputDirectory })).toThrow(/symlink/);
    expect(() => protectTarget({ inputPath: source, outputPath: join(outputDirectory, "out.cjs") })).toThrow(/symlink/);
    expect(fs.readFileSync(source, "utf8")).toBe(app);
    expect(fs.readdirSync(outside)).toEqual([]);
  });

  it.skipIf(!canLinkDirectories)("refuses linked promotion destinations and keeps restore state when the build directory is replaced by a link", () => {
    const project = scratch();
    const stateRoot = scratch();
    const dist = join(project, "dist");
    const input = put(join(dist, "nested", "main.cjs"), app);
    const options = { directory: project, apply: true, applyStateRoot: stateRoot, seed, intensity: "balanced" as const };
    const report = hardenProject(options);
    expect(report.apply?.status).toBe("applied");
    const hardened = fs.readFileSync(input);
    const outside = scratch();
    const outsideFile = put(join(outside, "nested", "main.cjs"), hardened);
    const stateDirectory = resolveApplyStateDirectory(project, stateRoot);
    const statePath = join(stateDirectory, "apply-state.json");
    const state = fs.readFileSync(statePath);
    const moved = join(project, "real-dist");
    fs.renameSync(dist, moved);
    linkDir(outside, dist);
    expect(applyHardenedOutputs({
      projectDirectory: project,
      stateDirectory,
      runId: "blocked",
      buildDirNames: ["dist"],
      candidates: [{ outputPath: outsideFile, destinationPath: input }],
    }).status).toBe("failed");
    expect(restoreHardenedProject(project, { applyStateRoot: stateRoot })).toMatchObject({
      status: "failed", reason: expect.stringMatching(/symlink/),
    });
    expect(fs.readFileSync(outsideFile)).toEqual(hardened);
    expect(fs.readFileSync(statePath)).toEqual(state);

    fs.rmSync(dist, { force: true });
    fs.renameSync(moved, dist);
    expect(restoreHardenedProject(project, { applyStateRoot: stateRoot }).status).toBe("restored");
    expect(fs.readFileSync(input, "utf8")).toBe(app);
  });

  it("rolls back after a second promotion chmod fails and retains the prior backup and index", () => {
    const project = scratch();
    const mirror = scratch();
    const stateDirectory = scratch();
    const first = put(join(project, "dist", "a.cjs"), app);
    const second = put(join(project, "dist", "b.cjs"), app);
    const firstMirror = put(join(mirror, "a.cjs"), 'console.log("first promotion");\n');
    const secondMirror = put(join(mirror, "b.cjs"), 'console.log("first promotion b");\n');
    const candidates = [
      { outputPath: firstMirror, destinationPath: first },
      { outputPath: secondMirror, destinationPath: second },
    ];
    const options = { projectDirectory: project, stateDirectory, buildDirNames: ["dist"], candidates };
    const initial = applyHardenedOutputs({ ...options, runId: "first" });
    expect(initial.status).toBe("applied");
    const initialState = fs.readFileSync(join(stateDirectory, "apply-state.json"));
    const originalBackup = join(initial.backupDirectory!, "dist", "b.cjs");
    put(firstMirror, "console.log(2);\n");
    put(secondMirror, "console.log(3);\n");
    const chmod = fs.chmodSync;
    vi.spyOn(fs, "chmodSync").mockImplementation((path, mode) => {
      if (String(path).startsWith(`${second}.bla-tmp-`)) throw new Error("simulated chmod failure");
      return chmod(path, mode);
    });

    expect(applyHardenedOutputs({ ...options, runId: "second" })).toMatchObject({
      status: "failed", reason: expect.stringMatching(/simulated chmod failure/),
    });
    expect(run(first)).toBe("first promotion");
    expect(run(second)).toBe("first promotion b");
    expect(fs.readFileSync(originalBackup, "utf8")).toBe(app);
    expect(fs.readFileSync(join(stateDirectory, "apply-state.json"))).toEqual(initialState);
    vi.restoreAllMocks();
    expect(fs.readdirSync(dirname(first))).toEqual(["a.cjs", "b.cjs"]);
    expect(fs.readdirSync(stateDirectory).sort()).toEqual(["apply-state.json", expect.stringMatching(/^originals-/)]);
    expect(restoreAppliedOriginals(project, stateDirectory).status).toBe("restored");
    expect(run(first)).toBe("hello");
    expect(run(second)).toBe("hello");
  });

  it("restores the prior committed build after hardenProject fails during re-apply promotion", () => {
    const project = scratch();
    const stateRoot = scratch();
    const first = put(join(project, "dist", "a.cjs"), app);
    const second = put(join(project, "dist", "b.cjs"), app);
    const options = { directory: project, apply: true, applyStateRoot: stateRoot, seed, intensity: "balanced" as const };
    const initial = hardenProject(options);
    expect(initial.apply?.status).toBe("applied");
    const priorFirst = fs.readFileSync(first);
    const rebuilt = "console.log(42);\n";
    put(second, rebuilt);
    const statePath = join(resolveApplyStateDirectory(project, stateRoot), "apply-state.json");
    const committed = fs.readFileSync(statePath);
    const rename = fs.renameSync;
    let failed = false;
    vi.spyOn(fs, "renameSync").mockImplementation((source, destination) => {
      if (destination === second && !failed) {
        failed = true;
        throw new Error("simulated promotion rename failure");
      }
      return rename(source, destination);
    });
    expect(hardenProject({ ...options, seed: "second" }).apply).toMatchObject({
      status: "failed", reason: expect.stringMatching(/promotion rename failure/),
    });
    expect(fs.readFileSync(first)).toEqual(priorFirst);
    expect(fs.readFileSync(second, "utf8")).toBe(rebuilt);
    expect(fs.readFileSync(statePath)).toEqual(committed);
    expect(fs.readFileSync(join(initial.apply!.backupDirectory!, "dist", "b.cjs"), "utf8")).toBe(app);
    expect(restoreHardenedProject(project, { applyStateRoot: stateRoot })).toMatchObject({
      status: "restored", restored: ["dist/a.cjs"], skippedModified: ["dist/b.cjs"],
    });
    expect(fs.readFileSync(first, "utf8")).toBe(app);
    expect(fs.readFileSync(second, "utf8")).toBe(rebuilt);
  });

  it("restores ordinary selfExpected declarations byte-for-byte and keeps backups for corrupt state", () => {
    const project = scratch();
    const stateRoot = scratch();
    const stateDirectory = resolveApplyStateDirectory(project, stateRoot);
    const ordinary = `var selfExpected = "${hex}";\r\nconsole.log(selfExpected);\r\n`;
    const input = put(join(project, "dist", "app.cjs"), ordinary);
    const staged = put(join(scratch(), "app.cjs"), ordinary.replace("console.log", "console.info"));
    const options = {
      projectDirectory: project, stateDirectory, runId: "exact-bytes", buildDirNames: ["dist"],
      candidates: [{ outputPath: staged, destinationPath: input }],
    };
    const applied = applyHardenedOutputs(options);
    expect(applied.status).toBe("applied");
    expect(fs.readFileSync(input)).toEqual(fs.readFileSync(staged));
    expect(run(input)).toBe(hex);
    const statePath = join(stateDirectory, "apply-state.json");
    const committed = fs.readFileSync(statePath);
    for (const badState of ["{", '{"schema":"bla-apply-state/v1","files":[]}', JSON.stringify({
      ...JSON.parse(committed.toString("utf8")),
      files: [{ relativePath: "dist/../app.cjs", originalSha256: null, hardenedSha256: hex }],
    })]) {
      put(statePath, badState);
      expect(restoreHardenedProject(project, { applyStateRoot: stateRoot }).status).toBe("failed");
      expect(applyHardenedOutputs(options).status).toBe("failed");
      expect(fs.readFileSync(join(applied.backupDirectory!, "dist", "app.cjs"), "utf8")).toBe(ordinary);
      expect(fs.readFileSync(statePath, "utf8")).toBe(badState);
    }
    put(statePath, committed);
    const read = fs.readFileSync;
    vi.spyOn(fs, "readFileSync").mockImplementation((...args: Parameters<typeof read>) => {
      if (args[0] === statePath) throw Object.assign(new Error("simulated read error"), { code: "EACCES" });
      return read(...args);
    });
    expect(restoreHardenedProject(project, { applyStateRoot: stateRoot }).status).toBe("failed");
    vi.restoreAllMocks();
    expect(restoreHardenedProject(project, { applyStateRoot: stateRoot }).status).toBe("restored");
    expect(fs.readFileSync(input, "utf8")).toBe(ordinary);
  });

  it("refuses an incidental nested bin and discovers a configured build root", () => {
    const project = scratch();
    const source = put(join(project, "src", "plugin", "bin", "start.cjs"), app);
    const options = { directory: project, apply: true, applyStateRoot: scratch(), seed, intensity: "balanced" as const };
    expect(hardenProject(options).apply).toMatchObject({ status: "refused", sourceFiles: ["src/plugin/bin/start.cjs"] });
    put(join(project, ".blarc"), JSON.stringify({ input: "artifacts/production" }));
    const build = put(join(project, "artifacts", "production", "app.cjs"), app);
    expect(hardenProject(options).apply?.applied).toEqual(["artifacts/production/app.cjs"]);
    expect(fs.readFileSync(source, "utf8")).toBe(app);
    expect(run(build)).toBe("hello");
  });

  it("refuses incomplete discovery but preserves truncation in previews", () => {
    const project = scratch();
    const first = put(join(project, "dist", "a.cjs"), app);
    const second = put(join(project, "dist", "b.cjs"), app);
    const options = { directory: project, apply: true, applyStateRoot: scratch(), seed, maxArtifacts: 1, intensity: "balanced" as const };
    expect(hardenProject({ ...options, dryRun: true })).toMatchObject({ truncated: true, apply: { status: "planned" } });
    expect(hardenProject(options)).toMatchObject({
      truncated: true, overallSuccess: false, apply: { status: "refused", reason: expect.stringMatching(/Raise maxArtifacts/) },
    });
    for (const file of [first, second]) expect(fs.readFileSync(file, "utf8")).toBe(app);
  });

  it("only promotes artifacts and manifest files written by the current run", () => {
    const project = scratch();
    const stage = scratch();
    const input = put(join(project, "dist", "app.cjs"), app);
    put(join(stage, "dist", "app.cjs.unrelated"), "recent unrelated sibling");
    put(join(stage, "dist", "app.cjs.bla-manifest.json"), "recent stale manifest");
    const options = {
      directory: project, outputDirectory: stage, apply: true, applyStateRoot: scratch(),
      seed, intensity: "balanced" as const,
    };
    expect(hardenProject(options).apply?.status).toBe("applied");
    expect(fs.readdirSync(dirname(input))).toEqual(["app.cjs"]);
    expect(hardenProject({ ...options, emitManifest: true }).apply?.added).toEqual(["dist/app.cjs.bla-manifest.json"]);
    expect(fs.readdirSync(dirname(input)).sort()).toEqual(["app.cjs", "app.cjs.bla-manifest.json"]);
    expect(run(input)).toBe("hello");
  });
});

describe("engine transforms and verification", () => {
  it("executes compact returns and preserves every directive after a shebang and comments", () => {
    const root = scratch();
    const path = put(join(root, "license.cjs"), [
      "#!/usr/bin/env node", "/* License */", '"use client";', "// Directive follows",
      '"use strict"', `function reveal() { if (this !== undefined) throw Error("strict mode lost"); return"${secret}"; }`,
      "console.log(reveal());",
    ].join("\n"));
    const result = encryptStrings({ path, seed });
    expect(result).toMatchObject({ status: "ok", totalEncrypted: 1, postLintClean: true });
    expect(fs.readFileSync(path, "utf8")).toContain('/* License */\n"use client";\n// Directive follows\n"use strict"');
    expect(run(path)).toBe(secret);
  });

  it("keeps string-valued ESM names and dynamic import sources while transforming values", () => {
    const root = scratch();
    const exported = "FLAG{public_module_export_name}";
    const specifier = "./FLAG{public_dynamic_import_target}.mjs";
    put(join(root, specifier), `const value = 7; export { value as "${exported}" };\n`);
    const stable = "./public.mjs";
    const exporter = put(join(root, stable), `const value = "${secret}"; export { value as "${exported}" };\n`);
    const path = put(join(root, "app.mjs"), [
      `import { "${exported}" as value } from "${stable}";`,
      `const ns = await import("${specifier}");`,
      `console.log(value, ns["${exported}"]);`,
    ].join("\n"));
    expect(encryptStrings({ path: exporter, seed }).totalEncrypted).toBe(1);
    expect(encryptStrings({ path, seed }).totalEncrypted).toBe(1);
    expect(fs.readFileSync(path, "utf8")).toContain(`import("${specifier}")`);
    expect(run(path)).toBe(`${secret} 7`);
  });

  it("post-lints admitted files with zero replacements in both preview and write mode", () => {
    const root = scratch();
    put(join(root, "other.mjs"), `const x = 0; export { x as "${secret}" };\n`);
    put(join(root, "license.cjs"), "module.exports = 0;\n");
    for (const dryRun of [true, false]) {
      expect(encryptStrings({ path: root, outDir: join(root, "encoded"), seed, dryRun })).toMatchObject({
        status: "noop", totalEncrypted: 0, postLintClean: false,
      });
    }
  });

  it("skips Node bindings for HTML and for modules imported by its inline script", () => {
    const root = scratch();
    const html = put(join(root, "dist", "index.html"),
      '<script type="module">import { x } from "./chunk.mjs"; console.log(x);</script>');
    put(join(root, "dist", "chunk.mjs"), "export const x = 42;");
    const direct = defendTarget({ inputPath: html, intensity: "balanced", selfSeal: true, sidecarEntangle: true, seed });
    expect(direct).toMatchObject({ overallSuccess: true, selfSeal: false, sidecarEntangle: false });
    const report = hardenProject({ directory: root, intensity: "balanced", selfSeal: true, sidecarEntangle: true, seed });
    expect(report.overallSuccess).toBe(true);
    expect(report.integrityBindingSkipped?.map((file) => file.relativePath)).toEqual(
      expect.arrayContaining(["dist/index.html", "dist/chunk.mjs"]),
    );
    for (const path of [direct.outputPath, ...report.artifacts.map((file) => file.outputPath)]) {
      const content = fs.readFileSync(path, "utf8");
      expect(content).not.toMatch(/\b(?:from|require\()\s*["']node:|selfExpected\s*=/);
    }
  });

  it("preserves ASAR JavaScript and source-map links even with sidecar entanglement", () => {
    const root = scratch();
    const asar = put(join(root, "app.asar"), packAsarBuffer([
      { relativePath: "package.json", content: Buffer.from('{"main":"main.cjs"}') },
      { relativePath: "main.cjs", content: Buffer.from(app) },
      { relativePath: "main.cjs.map", content: Buffer.from("{}") },
      { relativePath: "alias.cjs", content: Buffer.alloc(0), link: "main.cjs" },
      { relativePath: "alias.map", content: Buffer.alloc(0), link: "main.cjs.map" },
    ]));
    const result = protectTarget({ inputPath: asar, sidecarEntangle: true, intensity: "balanced", seed });
    const members = unpackAsarBuffer(fs.readFileSync(result.outputPath));
    expect(members.filter((member) => member.link).map((member) => [member.relativePath, member.link])).toEqual(
      expect.arrayContaining([["alias.cjs", "main.cjs"], ["alias.map", "main.cjs.map"]]),
    );
  });

  it("fails required self-seal verification for a missing binding and checks WASM before companion notes", () => {
    const root = scratch();
    const input = put(join(root, "plain.cjs"), `var selfExpected = "${hex}";\n${app}`);
    const unsealed = defendTarget({ inputPath: input, sidecarEntangle: true, intensity: "balanced", seed });
    expect(unsealed.sidecarEntangle).toBe(false);
    expect(verifyTarget(unsealed.outputPath, input, { selfSealEnabled: true })).toMatchObject({
      overallPassed: false,
      checks: expect.arrayContaining([expect.objectContaining({
        id: "self-seal-digest-integrity", passed: false, details: expect.stringMatching(/absent/),
      })]),
    });
    const sealed = defendTarget({ inputPath: put(join(root, "seal.cjs"), app), selfSeal: true, intensity: "balanced", seed });
    expect(sealed).toMatchObject({ overallSuccess: true, selfSeal: true });
    expect(run(sealed.outputPath)).toBe("hello");

    const wasm = put(join(root, "plain.wasm"), Buffer.from("0061736d01000000", "hex"));
    const sidecar = Buffer.from("companion bytes");
    put(join(root, "snapshot"), sidecar);
    const companion = bindBunSidecarEntanglement({
      entryPath: "plain.wasm", entryBytes: fs.readFileSync(wasm),
      seedTag: seed, sidecarPaths: ["snapshot"], sidecarBytes: [sidecar],
    });
    put(wasm + BUN_SIDECAR_COMPANION_SUFFIX, companion.noteBytes);
    expect(verifySidecarTarget(wasm)).toMatchObject({ ok: false, verifier: "wasm-custom-section" });
  });

  it("uses the same packaging gates for directory members and honors release-hygiene override", () => {
    const root = scratch();
    const input = join(root, "input");
    const output = join(root, "output");
    const js = put(join(input, "nested", "app.cjs"), buildTestJsAesUnwrapFootgun({}));
    const options = { inputPath: input, outputPath: output, intensity: "bankrupt" as const, seed };
    expect(() => protectTarget({ ...options, inputPath: js, outputPath: join(root, "out.cjs") })).toThrow(/AES|wrap.key/i);
    expect(() => protectTarget(options)).toThrow(/AES|wrap.key/i);
    expect(fs.existsSync(output)).toBe(false);
    put(js, app);
    put(join(input, "nested", ".env"), "DEMO_TOKEN=fixture-value\n");
    expect(() => protectTarget(options)).toThrow(/release environment artifact/);
    expect(fs.existsSync(output)).toBe(false);
    expect(protectTarget({ ...options, allowReleaseHygieneLeak: true }).detectedFormat).toBe("directory");
    expect(run(join(output, "nested", "app.cjs"))).toBe("hello");
  });
});
