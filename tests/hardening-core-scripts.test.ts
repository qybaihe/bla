import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import {
  chmodSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  readSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { syncSite } from "../scripts/sync-site.mjs";
import { verifyWebsiteDirectory } from "../scripts/verify-website.mjs";
import { initBlaConfig, resolveProjectSeed } from "../src/core/config.js";
import { detectArtifactFormat, isTypeScriptDeclarationPath } from "../src/core/detector.js";
import {
  canonicalManifestJson, generateManifestSigningKeyPair, signManifestPayload, verifyManifestSignature,
} from "../src/core/manifest-signing.js";
import { verifyManifestFile } from "../src/core/manifest-verify.js";
import { assertSafeOutputPath } from "../src/core/output-path.js";
import { SeededPrng } from "../src/core/prng.js";
import { expandSiblingGlobs } from "../src/core/sibling-globs.js";

vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  return { ...fs, readSync: vi.fn(fs.readSync), readdirSync: vi.fn(fs.readdirSync) };
});

const tempDirs: string[] = [];
const windows = process.platform === "win32";
function scratch(): string {
  const dir = realpathSync.native(mkdtempSync(join(tmpdir(), "bla-core-hardening-")));
  tempDirs.push(dir);
  return dir;
}

function put(root: string, path: string, contents: string | Buffer): string {
  const file = join(root, path);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, contents);
  return file;
}

afterEach(() => {
  vi.clearAllMocks();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("website and version scripts", () => {
  it.each([
    ["translation function", 'window.BLA_I18N = { en: { hello: String("hello") } };'],
    ["computed key", 'window.BLA_I18N = { en: { ["hello"]: "Hello" } };'],
    ["getter", 'window.BLA_I18N = { en: { get hello() { return "Hello"; } } };'],
    ["spread", 'window.BLA_I18N = { en: { ...{ hello: "Hello" } } };'],
    ["numeric value", "window.BLA_I18N = { en: { hello: 42 } };"],
    ["trailing statement", 'window.BLA_I18N = { en: { hello: "Hello" } }; Object.keys(window);'],
    ["invalid syntax", "window.BLA_I18N = { en: {"],
  ])("rejects i18n with %s", (_case, source) => {
    const root = scratch();
    put(root, "assets/i18n.js", source);
    const result = verifyWebsiteDirectory(root);
    expect(result.i18nCoverage).toBeNull();
    expect(result.errors).toContainEqual(expect.stringMatching(/i18n\.js: invalid static dictionary/));
  });

  it("reads escaped and single-quoted keys as literals and counts each required locale", () => {
    const root = scratch();
    put(root, "assets/i18n.js", String.raw`
      window.BLA_I18N = {en: {'nav.m\u0065nu': 'Open'}, 'zh-CN': {'nav.menu': '打开'}};
      // "nav.menu" "nav.menu" "nav.menu" "nav.menu" "nav.menu" "nav.menu" "nav.menu"
    `);
    put(root, "index.html", '<span data-i18n="nav.menu"></span>');
    const result = verifyWebsiteDirectory(root);
    expect(result.i18nCoverage?.referenceKeys).toBe(1);
    expect(result.errors).not.toContainEqual(expect.stringMatching(/nav\.menu.*no English string/));
    expect(result.errors).toContainEqual(expect.stringMatching(/nav\.menu must exist.*found 2/));
  });

  it("preserves Git metadata and ignores source symlinks during site sync", () => {
    const root = scratch();
    const repo = join(root, "origin.git");
    const worktree = join(root, "seed");
    const git = (...args: string[]) => execFileSync("git", args, { encoding: "utf8", stdio: "pipe" });
    git("init", "--bare", "--initial-branch=main", repo);
    git("clone", pathToFileURL(repo).href, worktree);
    put(worktree, "index.html", "before");
    git("-C", worktree, "add", ".");
    git("-C", worktree, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "initial");
    git("-C", worktree, "push", "origin", "main");

    const websiteDir = join(root, "site");
    put(websiteDir, "index.html", "after");
    put(websiteDir, ".git/HEAD", "source metadata must not be copied");
    put(websiteDir, "nested/.GIT/config", "source metadata must not be copied");
    put(websiteDir, "nested/page.html", "new");
    if (!windows) {
      symlinkSync(join(worktree, "index.html"), join(websiteDir, "linked.html"));
      symlinkSync(worktree, join(websiteDir, "linked-dir"));
      symlinkSync(join(root, "missing"), join(websiteDir, "dangling.html"));
    }
    const result = syncSite({
      websiteDir, repoUrl: pathToFileURL(repo).href, tmpBaseDir: root, dryRun: true, quiet: true,
    });
    expect(result.action).toBe("dry-run");
    expect([...result.changedPaths].sort()).toEqual(["index.html", "nested/page.html"]);
  });

  it("replaces full prerelease and build tokens and preserves badge colors on rerun", () => {
    const root = scratch();
    const previous = "3.5.7-12rc.1+build.old";
    const next = "3.5.8-rc.1+build.new";
    const script = put(root, "scripts/sync-version.mjs", readFileSync("scripts/sync-version.mjs"));
    put(root, "package.json", JSON.stringify({ version: next }));
    put(root, "src/identity.ts", `  version: "${previous}"\n`);
    const surfaces = {
      "README.md": `https://img.shields.io/badge/npm-bla--agents_v${previous}-2563eb?style=flat`,
      "docs/readme/README_zh.md": `https://img.shields.io/badge/npm-bla--agents_v${previous}-blue?style=flat`,
      ".mcp.json": `{"args":["bla-agents@${previous}","mcp"]}`,
      ".claude-plugin/plugin.json": `{"version": "${previous}"}`,
      "STATE.md": `**Version:** ${previous} (release)\n`,
    };
    for (const [file, source] of Object.entries(surfaces)) put(root, file, source);
    for (let i = 0; i < 2; i++) {
      execFileSync(process.execPath, [script], { stdio: "pipe" });
      for (const [file, source] of Object.entries(surfaces)) {
        expect(readFileSync(join(root, file), "utf8")).toBe(source.replace(previous, next));
      }
    }
  });
});

describe("output and configuration safety", () => {
  it("rejects directory output under a case alias on a case-insensitive volume", () => {
    const root = scratch();
    const input = join(root, "dist");
    mkdirSync(input);
    const alias = join(root, "DIST");
    if (existsSync(alias)) {
      expect(() => assertSafeOutputPath(input, join(alias, "nested", "out"), true)).toThrow(/outside the input/);
    } else {
      expect(() => assertSafeOutputPath(input, join(alias, "nested", "out"), true)).not.toThrow();
    }
  });

  it("rejects output through a symlinked ancestor even when it points outside the input", () => {
    const root = scratch();
    const input = join(root, "dist");
    const outside = join(root, "outside");
    const link = join(root, "alias");
    mkdirSync(input);
    mkdirSync(join(outside, "existing"), { recursive: true });
    symlinkSync(outside, link, windows ? "junction" : "dir");
    const output = join(link, "existing", "new", "out.js");
    expect(() => assertSafeOutputPath(input, output, true)).toThrow(/symlinked output ancestor/);
    const file = put(input, "entry.js", "original");
    expect(() => assertSafeOutputPath(file, output, false)).toThrow(/symlinked output ancestor/);
  });

  it.skipIf(windows)("rejects both dangling and live config symlinks in initialization and seed persistence", () => {
    const root = scratch();
    const victim = join(root, "victim.json");
    const config = join(root, "bla.config.json");
    const rc = join(root, ".blarc");
    symlinkSync(victim, config);
    expect(() => initBlaConfig(root)).toThrow(/symlinked BLA config/);
    expect(() => initBlaConfig(root, true)).toThrow(/symlinked BLA config/);
    expect(() => resolveProjectSeed(root)).toThrow(/symlinked BLA config/);
    rmSync(config);
    symlinkSync(victim, rc);
    expect(() => resolveProjectSeed(root)).toThrow(/symlinked BLA config/);
    expect(existsSync(victim)).toBe(false);
    writeFileSync(victim, '{"intensity":"stealth"}');
    expect(() => resolveProjectSeed(root)).toThrow(/symlinked BLA config/);
    expect(() => resolveProjectSeed(root, undefined, rc)).toThrow(/symlinked BLA config/);
    symlinkSync(victim, config);
    expect(() => initBlaConfig(root, true)).toThrow(/symlinked BLA config/);
    expect(readFileSync(victim, "utf8")).toBe('{"intensity":"stealth"}');
  });

  it("atomically replaces existing configs, preserves values, and writes new configs privately", () => {
    const root = scratch();
    const original = '{"intensity":"stealth","unknownOption":42}';
    const config = put(root, ".blarc", original);
    const alias = join(root, "old-config");
    linkSync(config, alias);
    if (!windows) chmodSync(config, 0o640);
    const result = resolveProjectSeed(root);
    expect(result).toMatchObject({ persisted: true, sourcePath: config, seed: expect.stringMatching(/^bla-/) });
    expect(JSON.parse(readFileSync(config, "utf8"))).toMatchObject({
      intensity: "stealth", unknownOption: 42, seed: result.seed,
    });
    expect(readFileSync(alias, "utf8")).toBe(original);
    if (!windows) expect(statSync(config).mode & 0o777).toBe(0o640);
    expect(resolveProjectSeed(root)).toMatchObject({ persisted: false, seed: result.seed });
    expect(readdirSync(root).sort()).toEqual([".blarc", "old-config"]);

    const fresh = scratch();
    const initialized = initBlaConfig(fresh);
    if (!windows) expect(statSync(initialized.configPath).mode & 0o777).toBe(0o600);
    const overwritten = initBlaConfig(fresh, true);
    expect(overwritten.config.seed).not.toBe(initialized.config.seed);
    expect(initBlaConfig(fresh)).toMatchObject({ created: false, config: overwritten.config });
    expect(resolveProjectSeed(scratch())).toMatchObject({ persisted: true });
  });
});

describe("manifest verification", () => {
  it.each([
    ["RSA", () => generateKeyPairSync("rsa", { modulusLength: 2048 })],
    ["EC", () => generateKeyPairSync("ec", { namedCurve: "prime256v1" })],
    ["Ed448", () => generateKeyPairSync("ed448")],
  ] as const)("rejects %s keys under the Ed25519 signature label", (_algorithm, makePair) => {
    const { privateKey, publicKey } = makePair();
    const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
    const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
    const payload = { file: "sample" };
    const signature = {
      algorithm: "ed25519",
      publicKey: publicPem,
      value: sign(null, Buffer.from(JSON.stringify(payload)), privateKey).toString("base64"),
    };
    expect(() => signManifestPayload(payload, privatePem)).toThrow(/Ed25519 private key/);
    expect(verifyManifestSignature({ ...payload, signature })).toBe(false);
    const root = scratch();
    const manifest = put(root, "manifest.json", JSON.stringify({ ...payload, signature }));
    const key = put(root, "public.pem", publicPem);
    expect(verifyManifestFile(manifest, key)).toMatchObject({ ok: false, pinned: false });
  });

  it("accepts the two supported serialization forms and rejects unknown algorithms and wrong lengths", () => {
    const { privateKeyPem, publicKeyPem } = generateManifestSigningKeyPair();
    const payload = { z: "source", a: "sample" };
    const sorted = signManifestPayload(payload, privateKeyPem);
    expect(verifyManifestSignature(sorted, publicKeyPem)).toBe(true);
    const legacy = {
      ...payload,
      signature: {
        algorithm: "ed25519",
        publicKey: publicKeyPem,
        value: sign(null, Buffer.from(JSON.stringify(payload)), createPrivateKey(privateKeyPem)).toString("base64"),
      },
    };
    expect(verifyManifestSignature(legacy)).toBe(true);
    for (const canonicalization of ["", "unknown", null, false]) {
      expect(verifyManifestSignature({ ...legacy, signature: { ...legacy.signature, canonicalization } })).toBe(false);
    }
    expect(verifyManifestSignature({ ...legacy, signature: { ...legacy.signature, algorithm: "rsa" } })).toBe(false);
    const bytes = Buffer.from(sorted.signature.value, "base64");
    for (const invalid of [bytes.subarray(0, 63), Buffer.concat([bytes, Buffer.of(0)])]) {
      expect(verifyManifestSignature({ ...sorted, signature: { ...sorted.signature, value: invalid.toString("base64") } })).toBe(false);
    }
  });

  it.each([NaN, Infinity, -Infinity])("rejects the non-finite value %s in nested data", (value) => {
    const { privateKeyPem } = generateManifestSigningKeyPair();
    const payload = { nested: [{ number: value }] };
    expect(() => canonicalManifestJson(payload)).toThrow(/must be finite/);
    expect(() => signManifestPayload(payload, privateKeyPem)).toThrow(/must be finite/);
    const signed = signManifestPayload({ nested: [{ number: null }] }, privateKeyPem);
    expect(verifyManifestSignature({ ...signed, ...payload })).toBe(false);
    expect(verifyManifestSignature({ ...signed, ...payload, signature: { ...signed.signature, canonicalization: undefined } })).toBe(false);
  });

  it("only reports a key as pinned when it matches", () => {
    const root = scratch();
    const { privateKeyPem, publicKeyPem } = generateManifestSigningKeyPair();
    const manifest = put(root, "manifest.json", JSON.stringify(signManifestPayload({ a: 1 }, privateKeyPem)));
    const match = put(root, "match.pem", publicKeyPem);
    const mismatch = put(root, "mismatch.pem", generateManifestSigningKeyPair().publicKeyPem);
    expect(verifyManifestFile(manifest, match)).toMatchObject({ ok: true, pinned: true });
    expect(verifyManifestFile(manifest, mismatch)).toMatchObject({
      ok: false, pinned: false, reason: expect.stringMatching(/does not match/),
    });
  });
});

describe("detector, PRNG and bounded glob matching", () => {
  it.skipIf(windows)("ignores extension-based detection for a FIFO", () => {
    const fifo = join(scratch(), "module.js");
    execFileSync("mkfifo", [fifo]);
    expect(detectArtifactFormat(fifo)).toBe("unknown");
  });

  it("does not count zero padding as part of the bytes returned by readSync", () => {
    const path = put(scratch(), "sample", Buffer.from("SQLite format 3\0"));
    vi.mocked(readSync).mockImplementationOnce((_fd, buffer) => {
      Buffer.from("SQLite format 3").copy(buffer as Buffer);
      return 15;
    });
    expect(detectArtifactFormat(path)).toBe("unknown");
    expect(detectArtifactFormat(path)).toBe("sqlite");
  });

  it("matches standard and arbitrary-extension TypeScript declarations", () => {
    for (const file of ["index.d.ts", "index.d.cts", "index.d.mts", "style.d.foo-bar.ts", "style.d.foo_bar.ts", "style.d.foo.bar.ts"]) {
      expect(isTypeScriptDeclarationPath(file), file).toBe(true);
    }
    for (const file of ["style.d.css.mts", "style.d.css.cts", "runtime.dtsx.ts", "path.d.foo/runtime.ts", "style.D.css.ts"]) {
      expect(isTypeScriptDeclarationPath(file), file).toBe(false);
    }
  });

  it("retains 32-bit precision beyond the point where an unwrapped stream loses bits", () => {
    const seed = "long-stream";
    const draws = 5_000_000;
    const prng = new SeededPrng(seed);
    let actual = 0;
    for (let i = 0; i < draws; i++) actual = prng.nextUint32();
    const digest = createHash("sha256").update(seed).digest();
    const initial = digest.readUInt32LE(0) ^ digest.readUInt32LE(4) ^ 0x9e3779b9;
    let state = Number(BigInt.asUintN(32, BigInt(initial) + 0x6d2b79f5n * BigInt(draws)));
    state = Math.imul(state ^ (state >>> 15), state | 1);
    state ^= state + Math.imul(state ^ (state >>> 7), state | 61);
    expect(actual).toBe((state ^ (state >>> 14)) >>> 0);
  });

  it("allows restricted directories only at locations explicitly matched by each pattern", () => {
    const root = scratch();
    const app = put(root, "app.js", "");
    const dep = put(root, "node_modules/dep/index.js", "");
    const extra = put(root, "node_modules/dep/other.js", "");
    const git = put(root, "packages/site/.git/config.js", "");
    const nestedDep = put(root, "packages/site/node_modules/dep/index.js", "");
    const doublyNestedDep = put(root, "node_modules/dep/node_modules/sub/index.js", "");
    expect(expandSiblingGlobs(root, ["**/*.js"])).toEqual([app]);
    expect(expandSiblingGlobs(root, ["**/*.js", "node_modules/dep/index.js", "packages/*/.git/*.js"]))
      .toEqual([app, dep, git]);
    expect(expandSiblingGlobs(root, ["**/node_modules/**/*.js"])).toEqual([dep, doublyNestedDep, extra, nestedDep]);
  });

  it("counts only accepted matches toward the walk's file cap", () => {
    const root = scratch();
    const files = Array.from({ length: 100_000 }, (_, i) => ({
      name: `unrelated-${i}.txt`,
      isDirectory: () => false,
      isFile: () => true,
    }));
    files.push({ name: "z-target.js", isDirectory: () => false, isFile: () => true });
    vi.mocked(readdirSync as (path: string, options: { withFileTypes: true }) => typeof files)
      .mockReturnValueOnce(files);
    expect(expandSiblingGlobs(root, ["*.js"])).toEqual([join(root, "z-target.js")]);
  });
});

describe("release workflow", () => {
  const workflow = readFileSync(".github/workflows/release.yml", "utf8");
  const [build, publish] = workflow.split(/^  publish:$/m);

  function runReleaseStep(stepPrefix: string, root: string, env: NodeJS.ProcessEnv) {
    const lines = publish.split("\n");
    const step = lines.findIndex((line) => line.startsWith(`      - name: ${stepPrefix}`));
    expect(step).toBeGreaterThan(-1);
    const script = lines.slice(step).join("\n").match(/^        run: \|\n((?:^ {10}.*\n|^\n)+)/m)?.[1];
    expect(script).toBeDefined();
    return spawnSync("bash", ["-c", script!.replace(/^ {10}/gm, "")], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env, PATH: `${join(root, "bin")}:${process.env.PATH}`, VERSION: "1.2.3", ...env },
    });
  }

  function mockCommand(root: string, name: string, script: string): void {
    chmodSync(put(root, `bin/${name}`, `#!/bin/sh\nset -eu\n${script}\n`), 0o700);
  }

  it("separates unprivileged build steps from publishing the verified artifact", () => {
    expect(build).toMatch(/^  build-and-verify:$/m);
    expect(build).toMatch(/permissions:\n      contents: read\n/);
    expect(build).toContain("persist-credentials: false");
    expect(build).toMatch(/npm ci[\s\S]+npm run typecheck[\s\S]+npm run build[\s\S]+npm test[\s\S]+npm run benchmark/);
    expect(build).toMatch(/packDualReleaseTarballs[\s\S]+uses: actions\/upload-artifact@/);
    expect(build).not.toContain("id-token:");
    expect(publish).toMatch(/needs: build-and-verify\n    permissions:\n      contents: write\n      id-token: write/);
    expect(publish).toContain("artifact-ids: ${{ needs.build-and-verify.outputs.artifact_id }}");
    expect(publish).not.toMatch(/actions\/checkout|npm ci/);
    expect(publish).toMatch(/uses: actions\/download-artifact@[\s\S]+sha256sum --check[\s\S]+Create or verify the remote canonical tag[\s\S]+npm publish[\s\S]+Reconcile GitHub Release assets/);
  });

  it.skipIf(windows)("publishes only for a missing version and verifies the existing tarball on retry", () => {
    const root = scratch();
    const contents = "verified tarball";
    put(root, "release-assets/bla-agents-1.2.3.tgz", contents);
    const integrity = `sha512-${createHash("sha512").update(contents).digest("base64")}`;
    mockCommand(root, "npm", `
      case "$1" in
        view)
          printf '%s\\n' "$MOCK_NPM_METADATA"
          exit "$MOCK_NPM_STATUS"
          ;;
        publish)
          printf '%s\\n' "$@" > npm-publish.log
          ;;
      esac
    `);
    // Exercise the JSON checks independently of jq availability on local or CI hosts.
    chmodSync(put(root, "bin/jq", `#!${process.execPath}
      const fs = require("node:fs");
      const args = process.argv.slice(2);
      const raw = fs.readFileSync(0, "utf8");
      try {
        const metadata = JSON.parse(raw);
        const ok = args.includes("--arg")
          ? metadata === args[args.indexOf("expected") + 1]
          : metadata.error?.code === "E404";
        process.exit(ok ? 0 : 1);
      } catch { process.exit(1); }
    `), 0o700);
    const run = (metadata: unknown, status: number) => runReleaseStep("Publish bla-agents", root, {
      MOCK_NPM_METADATA: JSON.stringify(metadata),
      MOCK_NPM_STATUS: String(status),
    });
    const publishLog = join(root, "npm-publish.log");
    expect(run(integrity, 0).status).toBe(0);
    expect(run("sha512-different", 0).status).toBe(1);
    expect(run({ error: { code: "E503" } }, 1).status).toBe(1);
    expect(existsSync(publishLog)).toBe(false);
    const fresh = run({ error: { code: "E404" } }, 1);
    expect(fresh.status, fresh.stderr).toBe(0);
    expect(readFileSync(publishLog, "utf8")).toBe(
      "publish\n./release-assets/bla-agents-1.2.3.tgz\n--ignore-scripts\n--provenance\n--access\npublic\n",
    );
  });

  it.skipIf(windows)("verifies peeled remote tags and reads back a newly created tag", () => {
    const root = scratch();
    mockCommand(root, "git", `
      if [ -f created-tag ]; then
        printf '%s\\trefs/tags/bla-agents-1.2.3\\n' "$CREATED_SHA"
      else
        printf '%s' "$MOCK_REMOTE"
      fi
    `);
    mockCommand(root, "gh", `
      test "$*" = "api --method POST repos/owner/repo/git/refs -f ref=refs/tags/bla-agents-1.2.3 -f sha=$HEAD_SHA --silent"
      touch created-tag
    `);
    const head = "a".repeat(40);
    const tagObject = `${"b".repeat(40)}\trefs/tags/bla-agents-1.2.3\n`;
    const run = (remote: string, created = head) => runReleaseStep("Create or verify the remote canonical tag", root, {
      GH_REPO: "owner/repo", GITHUB_SERVER_URL: "https://github.com", HEAD_SHA: head,
      MOCK_REMOTE: remote, CREATED_SHA: created,
    });
    expect(run(tagObject).status).toBe(1);
    expect(run(`${tagObject}${head}\trefs/tags/bla-agents-1.2.3^{}\n`).status).toBe(0);
    expect(existsSync(join(root, "created-tag"))).toBe(false);
    expect(run("", "c".repeat(40)).status).toBe(1);
    rmSync(join(root, "created-tag"));
    expect(run("").status).toBe(0);
    expect(existsSync(join(root, "created-tag"))).toBe(true);
  });

  it.skipIf(windows)("uploads only missing GitHub assets and rejects a content conflict", () => {
    const root = scratch();
    put(root, "release-assets/bla-agents-1.2.3.tgz", "primary");
    put(root, "release-assets/bla-shield-1.2.3.tgz", "alias");
    put(root, "release-assets/SHA256SUMS.txt", "checksums");
    mockCommand(root, "gh", `
      case "$2" in
        view)
          printf '%s' "$MOCK_ASSETS"
          exit "$MOCK_VIEW_STATUS"
          ;;
        download)
          test "$4" = "--pattern"
          if [ "$5" = "bla-agents-1.2.3.tgz" ]; then
            printf '%s' "$MOCK_PRIMARY"
          else
            cat "release-assets/$5"
          fi
          ;;
        upload|create)
          printf '%s\\n' "$@" > release.log
          ;;
      esac
    `);
    const run = (assets: string, primary: string, status = 0) => runReleaseStep("Reconcile GitHub Release assets", root, {
      MOCK_ASSETS: assets, MOCK_PRIMARY: primary, MOCK_VIEW_STATUS: String(status),
    });
    const log = join(root, "release.log");
    expect(run("bla-agents-1.2.3.tgz", "conflict").status).toBe(1);
    expect(run("bla-agents-1.2.3.tgz\nbla-shield-1.2.3.tgz\nSHA256SUMS.txt", "primary").status).toBe(0);
    expect(existsSync(log)).toBe(false);
    expect(run("bla-agents-1.2.3.tgz", "primary").status).toBe(0);
    expect(readFileSync(log, "utf8")).toBe(
      "release\nupload\nbla-agents-1.2.3\nrelease-assets/bla-shield-1.2.3.tgz\nrelease-assets/SHA256SUMS.txt\n",
    );
    expect(run("", "", 1).status).toBe(0);
    expect(readFileSync(log, "utf8")).toContain("--verify-tag");
  });
});
