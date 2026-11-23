import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { generateManifestSigningKeyPair } from "../src/core/manifest-signing.js";
import { verifyManifestFile } from "../src/core/manifest-verify.js";
import { getDatabaseSyncClass } from "../src/core/sqlite-runtime.js";
import {
  hardenProject,
  type HardenProjectOptions,
  type HardenProjectReport,
} from "../src/engine/harden.js";
import { PY3, python3 } from "./helpers/python-interpreter.js";

/**
 * `self_seal` / `sidecar_entangle` promise "tamper with a hardened file and the
 * program refuses to start". These pin what the promise really covers: the
 * hardened program still runs, tampering is caught where a check exists, and
 * the report names every file and every way in that no check reaches.
 */

const tempDirs: string[] = [];
function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}
afterEach(() => {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function put(root: string, rel: string, content: string | Buffer, mode?: number): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content);
  if (mode !== undefined) chmodSync(join(root, rel), mode);
}
function tree(dir: string, prefix = ""): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) out.push(...tree(join(dir, entry.name), `${prefix}${entry.name}/`));
    else out.push(prefix + entry.name);
  }
  return out.sort();
}
const sha256 = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

function harden(dir: string, options: Partial<HardenProjectOptions> = {}) {
  return hardenProject({
    directory: dir,
    intensity: "bankrupt",
    seed: "integrity-seed",
    applyStateRoot: tempDir("bla-int-state-"),
    ...options,
  });
}
function node(args: string[], cwd: string) {
  const run = spawnSync(process.execPath, args, { cwd, encoding: "utf8", timeout: 60000 });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

/** A package that is both a library (`main`) and a CLI (`bin`), the CLI loading the library. */
function cliAndLibraryProject(): string {
  const dir = tempDir("bla-int-node-");
  put(
    dir,
    "package.json",
    JSON.stringify({ name: "n", version: "1.0.0", main: "dist/main.cjs", bin: { n: "dist/cli.cjs" } }),
  );
  put(dir, "dist/main.cjs", "const { add } = require('./util.cjs');\nmodule.exports = { run: () => add(2, 3) };\n");
  put(dir, "dist/util.cjs", "module.exports = { add: (a, b) => a + b };\n");
  put(
    dir,
    "dist/cli.cjs",
    "#!/usr/bin/env node\nconst { run } = require('./main.cjs');\nconsole.log('result', run());\n",
    0o755,
  );
  return dir;
}

// `python3`, or `python` where that is the real interpreter (Windows).
const hasPython = PY3 !== null;

describe("integrity bindings: what is checked, and what is not", () => {
  it("a Node build still runs, and every declared way in stops on a tampered sibling", () => {
    const dir = cliAndLibraryProject();
    const report = harden(dir, { selfSeal: true, sidecarEntangle: true });
    expect(report.overallSuccess).toBe(true);
    expect(report.hardenedCount).toBe(3);
    expect(report.integrityBindingSkipped).toBeUndefined();
    expect(report.integrityCoverageSelfVerified).toBe(true);

    // The check lives in one module. `bin` loads `main`, so `main` hosts it and
    // both the CLI and `require("n")` run it (alphabetical order picked the CLI,
    // which left library consumers unchecked).
    expect(report.integrityBindingEntry).toBe("dist/main.cjs");
    expect(report.integrityBindingUncoveredEntries).toBeUndefined();
    expect(report.nextSteps?.join("\n")).toMatch(
      /dist\/main\.cjs carries the cross-file integrity check .* runs whenever that module is loaded, and only then\./,
    );

    const out = join(dir, ".bla-hardened", "dist");
    expect(node(["cli.cjs"], out)).toMatchObject({ status: 0, stdout: "result 5\n" });
    expect(node(["-e", "console.log('lib', require('./main.cjs').run())"], out)).toMatchObject({
      status: 0,
      stdout: "lib 5\n",
    });

    writeFileSync(join(out, "util.cjs"), `${readFileSync(join(out, "util.cjs"), "utf8")}\n// tampered\n`);
    for (const args of [["cli.cjs"], ["-e", "require('./main.cjs').run()"]]) {
      const tampered = node(args, out);
      expect(tampered.status, args.join(" ")).not.toBe(0);
      expect(tampered.stderr, args.join(" ")).toMatch(/integrity binding mismatch/);
      expect(tampered.stdout).toBe("");
    }
  }, 240000);

  it("the coverage matrix lists only edges the hardened tree enforces", () => {
    const dir = cliAndLibraryProject();
    const report = harden(dir, { selfSeal: true, sidecarEntangle: true });
    const out = join(dir, ".bla-hardened");
    const matrix = JSON.parse(readFileSync(report.integrityCoveragePath!, "utf8")) as {
      nodes: string[];
      edges: Record<string, string[]>;
      expectedSha256: Record<string, string>;
    };
    // One checker (the entry), every other file a leaf: no file is drawn as a
    // checker that contains no check.
    const checkers = new Set(Object.keys(matrix.edges).map((site) => site.replace(/#site\d+$/, "")));
    expect([...checkers]).toEqual(["dist/main.cjs"]);
    for (const targets of Object.values(matrix.edges)) {
      expect(targets).toEqual(expect.arrayContaining(["dist/cli.cjs", "dist/util.cjs"]));
    }
    // The pinned digests are the bytes on disk after every post-pass.
    for (const file of ["dist/cli.cjs", "dist/main.cjs", "dist/util.cjs"]) {
      expect(matrix.expectedSha256[file], file).toBe(sha256(join(out, file)));
    }
  }, 240000);

  it("names a declared entry point that never loads the checking module", () => {
    const dir = tempDir("bla-int-node-");
    put(
      dir,
      "package.json",
      JSON.stringify({ name: "n", version: "1.0.0", main: "dist/main.cjs", bin: { n: "dist/tool.cjs" } }),
    );
    put(dir, "dist/main.cjs", "const { add } = require('./util.cjs');\nmodule.exports = { run: () => add(2, 3) };\n");
    put(dir, "dist/util.cjs", "module.exports = { add: (a, b) => a + b };\n");
    // A second program that shares only the helper.
    put(dir, "dist/tool.cjs", "const { add } = require('./util.cjs');\nconsole.log('tool', add(1, 1));\n");

    const report = harden(dir, { selfSeal: true, sidecarEntangle: true });
    expect(report.overallSuccess).toBe(true);
    expect(report.integrityBindingEntry).toBe("dist/main.cjs");
    expect(report.integrityBindingUncoveredEntries).toEqual(["dist/tool.cjs"]);
    expect(report.nextSteps?.join("\n")).toMatch(
      /dist\/tool\.cjs is also declared in package\.json but never loads it, so a replaced or removed sibling goes unnoticed when the program starts there/,
    );

    // And that is the truth. Under self-seal every file still checks its own
    // bytes, so an edit to the hardened helper is caught from either program …
    const out = join(dir, ".bla-hardened", "dist");
    const hardenedUtil = readFileSync(join(out, "util.cjs"), "utf8");
    writeFileSync(join(out, "util.cjs"), `${hardenedUtil}\n// tampered\n`);
    expect(node(["tool.cjs"], out).stderr).toMatch(/integrity check failed/);
    expect(node(["-e", "require('./main.cjs')"], out).stderr).toMatch(/integrity/);
    // … but a helper swapped wholesale is noticed only where the pin lives.
    writeFileSync(join(out, "util.cjs"), "module.exports = { add: (a, b) => a + b + 1000 };\n");
    expect(node(["tool.cjs"], out)).toMatchObject({ status: 0, stdout: "tool 1002\n" });
    const viaMain = node(["-e", "require('./main.cjs')"], out);
    expect(viaMain.status).not.toBe(0);
    expect(viaMain.stderr).toMatch(/integrity binding mismatch|integrity check failed/);
  }, 240000);

  it.skipIf(process.platform === "win32")("keeps the executable bit of a hardened CLI", () => {
    const dir = cliAndLibraryProject();
    harden(dir, { selfSeal: true, sidecarEntangle: true });
    const out = join(dir, ".bla-hardened", "dist");
    expect(statSync(join(out, "cli.cjs")).mode & 0o777).toBe(0o755);
    expect(statSync(join(out, "util.cjs")).mode & 0o111).toBe(0);
    expect(readFileSync(join(out, "cli.cjs"), "utf8").startsWith("#!/usr/bin/env node\n")).toBe(true);
  }, 240000);

  it("signed manifests describe the bytes that ship, after every post-pass", () => {
    const dir = cliAndLibraryProject();
    const keys = generateManifestSigningKeyPair();
    const keyDir = tempDir("bla-int-key-");
    writeFileSync(join(keyDir, "private.pem"), keys.privateKeyPem, { mode: 0o600 });
    writeFileSync(join(keyDir, "public.pem"), keys.publicKeyPem);

    const report = harden(dir, {
      selfSeal: true,
      sidecarEntangle: true,
      emitManifest: true,
      signManifest: true,
      manifestSigningKeyPath: join(keyDir, "private.pem"),
    });
    expect(report.overallSuccess).toBe(true);
    const out = join(dir, ".bla-hardened");
    const manifests = tree(out).filter((f) => f.endsWith(".bla-manifest.json"));
    expect(manifests).toEqual([
      "dist/cli.cjs.bla-manifest.json",
      "dist/main.cjs.bla-manifest.json",
      "dist/util.cjs.bla-manifest.json",
    ]);
    for (const manifestFile of manifests) {
      const artifact = join(out, manifestFile.replace(/\.bla-manifest\.json$/, ""));
      const manifest = JSON.parse(readFileSync(join(out, manifestFile), "utf8")) as {
        protectedSha256: string;
      };
      // The entry is rewritten after its own protect step (sidecar binding,
      // self-digest): a manifest signed before that would not verify.
      expect(manifest.protectedSha256, manifestFile).toBe(sha256(artifact));
      expect(verifyManifestFile(join(out, manifestFile), join(keyDir, "public.pem"))).toMatchObject({
        ok: true,
        signed: true,
        pinned: true,
        artifactVerified: true,
      });
    }
  }, 240000);

  it("hardens a browser build without the Node binding, and says so", () => {
    const dir = tempDir("bla-int-web-");
    put(dir, "package.json", JSON.stringify({ name: "w", version: "1.0.0" }));
    put(
      dir,
      "dist/index.html",
      "<!doctype html><html><body><div id=app></div><script type=module src=./assets/app.js></script></body></html>",
    );
    put(
      dir,
      "dist/assets/app.js",
      "import { label } from './chunk.js';\ndocument.getElementById('app').textContent = label();\n",
    );
    put(dir, "dist/assets/chunk.js", "export function label() { return window.location.hostname + ':ready'; }\n");
    const DatabaseSync = getDatabaseSyncClass();
    const seedDb = new DatabaseSync(join(dir, "dist", "data.sqlite"));
    seedDb.exec("CREATE TABLE settings (k TEXT PRIMARY KEY, v TEXT); INSERT INTO settings VALUES ('theme', 'dark');");
    seedDb.close();

    const report = harden(dir, { selfSeal: true, sidecarEntangle: true });
    expect(report.overallSuccess).toBe(true);
    expect(report.sidecarEntangleError).toBeUndefined();
    expect(report.integrityBindingSkipped).toEqual([
      {
        relativePath: "dist/assets/app.js",
        reason: expect.stringMatching(/^browser bundle \(loaded by index\.html\)/),
      },
      {
        relativePath: "dist/assets/chunk.js",
        reason: expect.stringMatching(/^browser bundle \(imported by app\.js, which a web page loads\)/),
      },
      { relativePath: "dist/index.html", reason: expect.stringMatching(/^browser bundle \(HTML bundle\)/) },
      { relativePath: "dist/data.sqlite", reason: expect.stringMatching(/^mutable data/) },
    ]);
    // Nothing hosts a check, so none is claimed.
    expect(report.integrityBindingEntry).toBeUndefined();
    expect(report.integrityCoveragePath).toBeUndefined();
    expect(report.nextSteps?.join("\n")).toMatch(/Subresource Integrity/);

    const out = join(dir, ".bla-hardened", "dist");
    for (const file of ["assets/app.js", "assets/chunk.js"]) {
      const code = readFileSync(join(out, file), "utf8");
      // The binding preamble would make the browser refuse the module.
      expect(code, file).not.toMatch(/integrity binding mismatch/);
      expect(code, file).not.toMatch(/^\s*import\b[^;]*["']node:/m);
      expect(code, file).not.toMatch(/\brequire\s*\(\s*["']node:/);
    }
    // The database is still the application's database.
    const db = new DatabaseSync(join(out, "data.sqlite"));
    expect(db.prepare("SELECT v FROM settings WHERE k = 'theme'").all()).toEqual([{ v: "dark" }]);
    db.close();

    // A pure front-end build is not told to switch on a Node-only binding.
    const plain = harden(dir, { dryRun: true });
    expect(plain.selfSealRecommended).toBe(false);
  }, 240000);

  it.skipIf(!hasPython)("a Python package checks its siblings even from a bytecode-only copy", () => {
    const dir = tempDir("bla-int-py-");
    put(dir, "pyproject.toml", "[project]\nname = 'p'\n");
    put(dir, "app/__init__.py", "");
    put(
      dir,
      "app/main.py",
      "from app.util import add\n\ndef run():\n    return add(2, 3)\n\nif __name__ == '__main__':\n    print('result', run())\n",
    );
    put(dir, "app/util.py", "def add(a, b):\n    return a + b\n");

    const report = harden(dir, { intensity: "balanced", sidecarEntangle: true });
    expect(report.overallSuccess).toBe(true);
    expect(report.pythonSidecarEntry).toBe("app/main.py");

    const out = join(dir, ".bla-hardened");
    const py = (cwd: string) => {
      const run = spawnSync(python3(), ["-c", "import app.main as m; print('result', m.run())"], {
        cwd,
        encoding: "utf8",
        timeout: 60000,
        env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
      });
      // (Python writes "\r\n" on Windows.)
      return { status: run.status, stdout: run.stdout.replace(/\r\n/g, "\n"), stderr: run.stderr };
    };
    expect(py(out)).toMatchObject({ status: 0, stdout: "result 5\n" });

    // A bytecode-only copy still requires the pinned sibling bytes.
    const bytecodeOnly = tempDir("bla-int-pyc-");
    cpSync(out, bytecodeOnly, { recursive: true });
    expect(
      spawnSync(python3(), ["-m", "compileall", "-q", "-b", "app"], { cwd: bytecodeOnly, encoding: "utf8" })
        .status,
    ).toBe(0);
    for (const file of tree(join(bytecodeOnly, "app")).filter((f) => f.endsWith(".py"))) {
      rmSync(join(bytecodeOnly, "app", file));
    }
    const missingSources = py(bytecodeOnly);
    expect(missingSources.status).not.toBe(0);
    expect(missingSources.stderr).toMatch(/integrity binding mismatch/);

    // Loose sources are still checked: a changed sibling and a missing one both stop it.
    const util = join(out, "app", "util.py");
    writeFileSync(util, `${readFileSync(util, "utf8")}\n# tampered\n`);
    expect(py(out).stderr).toMatch(/integrity binding mismatch/);
    rmSync(util);
    const missing = py(out);
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toMatch(/integrity binding mismatch/);
  }, 240000);
});

describe("plaintext survivors", () => {
  const DIGEST_IN_STRING = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
  const DIGEST_IN_KEY = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
  function licenseProject(): string {
    const dir = tempDir("bla-int-surv-");
    put(
      dir,
      "dist/license.cjs",
      [
        "const crypto = require('node:crypto');",
        `const EXPECTED = '${DIGEST_IN_STRING}';`,
        `const TABLE = { '${DIGEST_IN_KEY}': 'pro' };`,
        "function check(key) {",
        "  const h = crypto.createHash('sha256').update(String(key)).digest('hex');",
        "  return h === EXPECTED || TABLE[h] === 'pro';",
        "}",
        "module.exports = { check };",
        "",
      ].join("\n"),
    );
    return dir;
  }

  it("balanced does not encode strings, and the report says which literals are still readable", () => {
    const dir = licenseProject();
    const report = harden(dir, { intensity: "balanced" });
    expect(report.overallSuccess).toBe(true);
    const survivors = report.artifacts[0]!.plaintextSurvivors!;
    expect(survivors.count).toBe(2);
    expect(survivors.samples.map((s) => s.line)).toEqual([2, 3]);
    expect(report.nextSteps?.join("\n")).toMatch(
      /2 sensitive-looking literal\(s\) .* still readable in the hardened output of dist\/license\.cjs .* Intensity balanced does not encode string literals/,
    );
    // The report points at the literal without repeating it.
    for (const sample of survivors.samples) expect(sample.preview.length).toBeLessThanOrEqual(21);
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain(DIGEST_IN_STRING);
    expect(serialized).not.toContain(DIGEST_IN_KEY);

    const hardened = readFileSync(report.artifacts[0]!.outputPath, "utf8");
    expect(hardened).toContain(DIGEST_IN_STRING);
  }, 240000);

  it("maximum splits a secret wherever it is written, and then has nothing left to report", () => {
    const dir = licenseProject();
    const report = harden(dir, { intensity: "maximum" });
    expect(report.overallSuccess).toBe(true);
    const hardened = readFileSync(report.artifacts[0]!.outputPath, "utf8");
    expect(hardened).not.toContain(DIGEST_IN_STRING);
    expect(hardened).not.toContain(DIGEST_IN_KEY); // an object key is split like any other secret
    expect(report.artifacts[0]!.plaintextSurvivors).toBeUndefined();
    expect(report.nextSteps?.join("\n")).not.toMatch(/still readable/);

    // The hardened module still decides the same way.
    const out = dirname(report.artifacts[0]!.outputPath);
    const run = node(
      ["-e", "const { check } = require('./license.cjs'); console.log(check('password'), check('foo'), check('nope'))"],
      out,
    );
    expect(run).toMatchObject({ status: 0, stdout: "true true false\n" });
  }, 240000);

  it("rebuilds a regular expression that holds a digest — at maximum and bankrupt only", () => {
    function gateProject(): string {
      const dir = tempDir("bla-int-surv-");
      put(
        dir,
        "dist/gate.cjs",
        [
          "const crypto = require('node:crypto');",
          `const PRO = /^${DIGEST_IN_STRING}$/;`,
          "const check = (key) => PRO.test(crypto.createHash('sha256').update(String(key)).digest('hex'));",
          "module.exports = { check };",
          "",
        ].join("\n"),
      );
      return dir;
    }
    const decides = (report: HardenProjectReport): void => {
      const run = node(
        ["-e", "const { check } = require('./gate.cjs'); console.log(check('password'), check('nope'))"],
        dirname(report.artifacts[0]!.outputPath),
      );
      expect(run).toMatchObject({ status: 0, stdout: "true false\n" });
    };

    const bankrupt = harden(gateProject(), { intensity: "bankrupt" });
    expect(bankrupt.overallSuccess).toBe(true);
    expect(readFileSync(bankrupt.artifacts[0]!.outputPath, "utf8")).not.toContain(DIGEST_IN_STRING);
    expect(bankrupt.artifacts[0]!.plaintextSurvivors).toBeUndefined();
    decides(bankrupt);

    // Below maximum nothing is rewritten, and the report says the digest is still there.
    const balanced = harden(gateProject(), { intensity: "balanced" });
    expect(readFileSync(balanced.artifacts[0]!.outputPath, "utf8")).toContain(DIGEST_IN_STRING);
    const survivors = balanced.artifacts[0]!.plaintextSurvivors!;
    expect(survivors.count).toBe(1);
    expect(survivors.samples[0]).toMatchObject({ line: 2 });
    expect(balanced.nextSteps?.join("\n")).toMatch(/Intensity balanced does not encode string literals/);
    expect(JSON.stringify(balanced)).not.toContain(DIGEST_IN_STRING);
    decides(balanced);
  }, 240000);

  it("reports what maximum still cannot reach: a class member name, a value over 4,096 characters", () => {
    const dir = tempDir("bla-int-surv-");
    const oversized = DIGEST_IN_STRING.repeat(70); // 4,480 hex characters
    put(
      dir,
      "dist/tiers.cjs",
      [
        `class Tiers { static '${DIGEST_IN_KEY}' = 'pro'; }`,
        `const BLOB = '${oversized}';`,
        "module.exports = { tier: (h) => Tiers[h] ?? 'free', size: BLOB.length };",
        "",
      ].join("\n"),
    );
    const report = harden(dir, { intensity: "maximum" });
    expect(report.overallSuccess).toBe(true);
    const hardened = readFileSync(report.artifacts[0]!.outputPath, "utf8");
    expect(hardened).toContain(DIGEST_IN_KEY);
    expect(hardened).toContain(oversized);

    const survivors = report.artifacts[0]!.plaintextSurvivors!;
    expect(survivors.count).toBe(2);
    expect(survivors.samples.map((s) => s.line)).toEqual([1, 2]);
    expect(report.nextSteps?.join("\n")).toMatch(
      /a secret-looking value of up to 4,096 characters wherever it is written \(string, template, object key, regular expression\)\. It cannot reach HTML attributes, tagged templates, class member names, .* or anything longer: move the value into a plain string literal/,
    );
    expect(JSON.stringify(report)).not.toContain(DIGEST_IN_KEY);

    const run = node(
      [
        "-e",
        `const t = require('./tiers.cjs'); console.log(t.tier('${DIGEST_IN_KEY}'), t.tier('nope'), t.size)`,
      ],
      dirname(report.artifacts[0]!.outputPath),
    );
    expect(run).toMatchObject({ status: 0, stdout: "pro free 4480\n" });
  }, 240000);

  it("says nothing when there is nothing sensitive to find", () => {
    const dir = tempDir("bla-int-surv-");
    put(dir, "dist/app.cjs", "module.exports = { greet: (name) => 'hello ' + name };\n");
    const report = harden(dir, { intensity: "balanced" });
    expect(report.artifacts[0]!.plaintextSurvivors).toBeUndefined();
    expect(report.nextSteps?.join("\n")).not.toMatch(/still readable/);
  }, 240000);
});
