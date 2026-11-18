import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isDevToolingFile } from "../src/core/dev-tooling.js";
import { discoverHardenTargets } from "../src/engine/harden.js";

/**
 * Discovery decides what `bla_harden` touches. Two mistakes are expensive:
 * hardening the toolchain (a broken `vite.config.js` stops the next build) and
 * calling the product "tooling" (it silently ships unprotected). These pin both
 * directions on the project shapes an agent actually meets.
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

function put(root: string, rel: string, content: string | Buffer): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), content);
}

/** (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add) */
const ADD_WASM = Buffer.from(
  "0061736d0100000001070160027f7f017f030201000707010361646400000a09010700200020016a0b",
  "hex",
);

function discover(dir: string, options: { buildOutputOnly?: boolean } = {}) {
  // An empty, private state root: nothing here is "already BLA output".
  const result = discoverHardenTargets(dir, { stateRoot: tempDir("bla-disc-state-"), ...options });
  return {
    ...result,
    listed: result.artifacts.map((a) => `${a.relativePath} [${a.format}]`),
    paths: result.artifacts.map((a) => a.relativePath),
  };
}

function frontEndProject(): string {
  const dir = tempDir("bla-disc-fe-");
  put(
    dir,
    "package.json",
    JSON.stringify({
      name: "fe",
      version: "1.0.0",
      scripts: {
        build: "node tools/build.mjs",
        release: "node scripts/release.js",
        benchmark: "node dist/assets/app.js --bench",
      },
    }),
  );
  put(dir, "dist/index.html", "<!doctype html><script type=module src=./assets/app.js></script>");
  put(dir, "dist/assets/app.js", "document.getElementById('app').textContent = 'hi';\n");
  put(dir, "dist/assets/app.d.ts", "export declare const x: number;\n");
  put(dir, "dist/assets/app.d.mts", "export declare const x: number;\n");
  put(dir, "src/main.ts", "export const a = 1;\n");
  put(dir, "index.html", "<!doctype html><script type=module src=/src/main.ts></script>");
  put(dir, "vite.config.js", "export default {};\n");
  put(dir, "eslint.config.js", "export default [];\n");
  put(dir, "jest.config.cjs", "module.exports = {};\n");
  put(dir, "tools/build.mjs", "console.log('build');\n");
  put(dir, "scripts/release.js", "console.log('release');\n");
  put(dir, "public/sw.js", "self.addEventListener('fetch', () => {});\n");
  put(dir, "model.wasm", ADD_WASM);
  return dir;
}

describe("harden discovery targets the release artifact", () => {
  it("a built front-end project: build output plus root binaries, never the toolchain", () => {
    const dir = frontEndProject();
    const found = discover(dir);

    expect(found.listed).toEqual([
      "dist/assets/app.js [javascript]",
      "dist/index.html [html-bundle]",
      "model.wasm [wasm]",
    ]);
    // Tool configs and the script behind `npm run build` are reported, not hardened.
    expect(found.skippedDevTooling).toEqual([
      "eslint.config.js",
      "jest.config.cjs",
      "tools/build.mjs",
      "vite.config.js",
    ]);
    // `index.html` and `public/sw.js` are inputs of the build that produced dist/.
    expect(found.skippedSourceFiles).toBe(2);
    expect(found.truncated).toBe(false);
  });

  it("a tooling script that runs the product does not make the product tooling", () => {
    // "benchmark": "node dist/assets/app.js --bench" names the build output.
    const found = discover(frontEndProject());
    expect(found.paths).toContain("dist/assets/app.js");
    expect(found.skippedDevTooling).not.toContain("dist/assets/app.js");
  });

  it("build_output_only leaves the project root alone", () => {
    const found = discover(frontEndProject(), { buildOutputOnly: true });
    expect(found.paths).toEqual(["dist/assets/app.js", "dist/index.html"]);
    expect(found.skippedDevTooling).toBeUndefined();
    expect(found.skippedSourceFiles).toBeUndefined();
  });

  it("pointing at the build directory hardens everything in it, whatever it is called", () => {
    const dir = frontEndProject();
    // A bundler is free to emit a chunk named like a config or a test file.
    put(dir, "dist/assets/app.config.js", "export const flags = { beta: false };\n");
    put(dir, "dist/assets/checkout.test.js", "export const id = 'ab-test-checkout';\n");

    expect(discover(join(dir, "dist")).paths).toEqual([
      "assets/app.config.js",
      "assets/app.js",
      "assets/checkout.test.js",
      "index.html",
    ]);
    // The same holds when the project root is given: dist/ is a build walk.
    expect(discover(dir).paths).toEqual(
      expect.arrayContaining(["dist/assets/app.config.js", "dist/assets/checkout.test.js"]),
    );
  });

  it("a source-only Python project: the package ships, the release engineering does not", () => {
    const dir = tempDir("bla-disc-py-");
    put(dir, "pyproject.toml", "[project]\nname = 'x'\n");
    put(dir, "app/__init__.py", "VERSION = '1'\n");
    put(dir, "app/core.py", "def run():\n    return 1\n");
    put(dir, "manage.py", "print('manage')\n");
    put(dir, "setup.py", "from setuptools import setup\nsetup()\n");
    put(dir, "conftest.py", "import pytest\n");
    put(dir, "noxfile.py", "import nox\n");
    put(dir, "tests/test_core.py", "def test_x():\n    assert True\n");
    put(dir, "app/test_inline.py", "def test_y():\n    assert True\n");
    put(dir, "docs/conf.py", "project = 'x'\n");
    put(dir, "examples/demo.py", "print('demo')\n");
    put(dir, "scripts/deploy.py", "print('deploy')\n");
    put(dir, "scripts/report_tool.py", "print('report')\n");

    const found = discover(dir);
    expect(found.paths).toEqual([
      "app/__init__.py",
      "app/core.py",
      "manage.py",
      // A console script the project ships lives in scripts/ as often as tooling does.
      "scripts/report_tool.py",
    ]);
    expect(found.skippedDevTooling).toEqual([
      "app/test_inline.py",
      "conftest.py",
      "noxfile.py",
      "scripts/deploy.py",
      "setup.py",
    ]);
    // Whole trees of tests / docs / samples are skipped without being listed.
    expect(found.skippedSourceFiles).toBeUndefined();
  });

  it("a source-only Node project: declared entries are product code wherever they live", () => {
    const dir = tempDir("bla-disc-node-");
    put(
      dir,
      "package.json",
      JSON.stringify({
        name: "cli",
        version: "1.0.0",
        main: "index.js",
        bin: { cli: "scripts/cli.js", publish: "scripts/publish.js" },
        exports: { ".": "./index.js", "./feature": "./lib/feature.config.js", "./all/*": "./lib/*.js" },
        scripts: { test: "node index.js --self-test", build: "node build.js", start: "node server.js" },
      }),
    );
    put(dir, "index.js", "module.exports = 1;\n");
    put(dir, "server.js", "require('node:http').createServer().listen(0);\n");
    put(dir, "build.js", "console.log('bundle');\n");
    put(dir, "scripts/cli.js", "#!/usr/bin/env node\nconsole.log('cli');\n");
    put(dir, "scripts/publish.js", "#!/usr/bin/env node\nconsole.log('publish to the customer registry');\n");
    put(dir, "scripts/release.js", "console.log('tag and push');\n");
    put(dir, "lib/feature.config.js", "module.exports = { enabled: true };\n");
    put(dir, "test/index.test.js", "test('x', () => {});\n");
    put(dir, "examples/demo.js", "console.log('demo');\n");
    put(dir, "__mocks__/fs.js", "module.exports = {};\n");
    put(dir, ".eslintrc.cjs", "module.exports = {};\n");

    const found = discover(dir);
    expect(found.paths).toEqual([
      "index.js", // run by `npm test`, but it is `main`
      "lib/feature.config.js",
      "scripts/cli.js",
      "scripts/publish.js", // a release-task name, but declared in `bin`
      "server.js", // `npm start` runs the product
    ]);
    expect(found.skippedDevTooling).toEqual([".eslintrc.cjs", "build.js", "scripts/release.js"]);
  });

  it("the implicit index.js main is never tooling", () => {
    const dir = tempDir("bla-disc-implicit-");
    put(dir, "package.json", JSON.stringify({ name: "x", version: "1.0.0", scripts: { test: "node index.js" } }));
    put(dir, "index.js", "module.exports = 1;\n");
    const found = discover(dir);
    expect(found.paths).toEqual(["index.js"]);
    expect(found.skippedDevTooling).toBeUndefined();
  });

  it("walks a build directory once, under the name it has on disk", () => {
    // `release` and `Release` are one directory on macOS and Windows.
    const dir = tempDir("bla-disc-case-");
    put(dir, "Release/app.cjs", "module.exports = 1;\n");
    expect(discover(dir).paths).toEqual(["Release/app.cjs"]);
  });

  it("names tooling narrowly", () => {
    const root = tempDir("bla-disc-names-");
    put(root, "package.json", "{}");
    const at = (rel: string) => isDevToolingFile(join(root, rel), rel.split("/").pop()!);

    for (const tooling of [
      "vite.config.ts",
      "webpack.prod.config.js",
      "playwright.config.mts",
      "gulpfile.mjs",
      "karma.conf.js",
      "jest.setup.ts",
      ".eslintrc.js",
      ".pnp.cjs",
      "src/button.stories.tsx",
      "src/app.spec.ts",
      "src/test_parser.py",
      "src/parser_test.py",
      "scripts/deploy.py",
      "scripts/bump-version.mjs",
      "ci/publish.js",
      "hack/update_changelog.py",
    ]) {
      expect(at(tooling), tooling).toBe(true);
    }
    for (const product of [
      "config.js",
      "server.js",
      "manage.py",
      "tasks.py",
      // Only a package-root `*.config.*` is tool configuration; Angular's
      // src/app/app.config.ts is shipped application code.
      "src/app/app.config.ts",
      // Release-task names count only inside a helper-script directory.
      "release.js",
      "src/deploy.py",
      "app/publish.ts",
      "scripts/report_tool.py",
      "scripts/latest.js",
      "contest.py",
      "attest.js",
    ]) {
      expect(at(product), product).toBe(false);
    }
  });
});
