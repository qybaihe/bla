import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = resolveRepoRoot();
const scriptSource = readFileSync(
  join(repoRoot, "scripts", "sync-version.mjs"),
  "utf8",
);

function resolveRepoRoot(): string {
  // tests/ sits next to scripts/ at the repository root.
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

const tempDirs: string[] = [];

function makeSandbox(version: string): string {
  const root = mkdtempSync(join(tmpdir(), "bla-sync-version-"));
  tempDirs.push(root);
  mkdirSync(join(root, "scripts"), { recursive: true });
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "scripts", "sync-version.mjs"), scriptSource, "utf8");
  writeFileSync(
    join(root, "package.json"),
    `${JSON.stringify({ name: "fixture", version }, null, 2)}\n`,
    "utf8",
  );
  writeFileSync(
    join(root, "src", "identity.ts"),
    `export const BLA_IDENTITY = {\n  version: "0.0.0",\n};\n`,
    "utf8",
  );
  return root;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("sync-version.mjs semver guard", () => {
  it("refuses a non-semver package.json version without touching identity.ts", () => {
    const root = makeSandbox("not-a-version");
    const identityPath = join(root, "src", "identity.ts");
    const before = readFileSync(identityPath, "utf8");
    const run = spawnSync(process.execPath, [join(root, "scripts", "sync-version.mjs")], {
      encoding: "utf8",
    });
    expect(run.status).toBe(1);
    expect(`${run.stderr}${run.stdout}`).toContain("not valid semver");
    expect(readFileSync(identityPath, "utf8")).toBe(before);
  });

  it("syncs a valid semver version as before", () => {
    const root = makeSandbox("9.9.9");
    const identityPath = join(root, "src", "identity.ts");
    const run = spawnSync(process.execPath, [join(root, "scripts", "sync-version.mjs")], {
      encoding: "utf8",
    });
    expect(run.status).toBe(0);
    expect(readFileSync(identityPath, "utf8")).toContain('version: "9.9.9"');
  });

  it("keeps the website's structured data and the Actions example on the release", () => {
    const root = makeSandbox("9.9.9");
    mkdirSync(join(root, "website"), { recursive: true });
    mkdirSync(join(root, "examples"), { recursive: true });
    const site = [
      '{ "@type": "SoftwareApplication", "softwareVersion": "3.4.3",',
      '  "releaseNotes": "https://github.com/qybaihe/bla/releases/tag/bla-agents-3.4.3",',
      '  "offers": { "@type": "Offer", "price": "0" } },',
      '{ "@type": "SoftwareSourceCode", "name": "qybaihe/bla", "version": "3.4.1",',
      '  "author": { "@id": "#organization" } },',
      '{ "@type": "WebSite", "version": "1.2.3" }',
    ].join("\n");
    writeFileSync(join(root, "website", "index.html"), site, "utf8");
    writeFileSync(
      join(root, "examples", "github-actions-defend.yml"),
      'env:\n  BLA_VERSION: "3.4.3"\n',
      "utf8",
    );
    const run = spawnSync(process.execPath, [join(root, "scripts", "sync-version.mjs")], {
      encoding: "utf8",
    });
    expect(run.status).toBe(0);
    const synced = readFileSync(join(root, "website", "index.html"), "utf8");
    expect(synced).toContain('"softwareVersion": "9.9.9"');
    expect(synced).toContain("/releases/tag/bla-agents-9.9.9");
    expect(synced).toContain('"name": "qybaihe/bla", "version": "9.9.9"');
    // A version on any other node is not the package's.
    expect(synced).toContain('{ "@type": "WebSite", "version": "1.2.3" }');
    expect(synced).not.toContain("3.4.");
    expect(readFileSync(join(root, "examples", "github-actions-defend.yml"), "utf8")).toBe(
      'env:\n  BLA_VERSION: "9.9.9"\n',
    );
  });

  it("accepts prerelease and build-metadata versions", () => {
    const root = makeSandbox("4.0.0-nightly.2+sha.abc");
    const run = spawnSync(process.execPath, [join(root, "scripts", "sync-version.mjs")], {
      encoding: "utf8",
    });
    expect(run.status).toBe(0);
    expect(readFileSync(join(root, "src", "identity.ts"), "utf8")).toContain(
      'version: "4.0.0-nightly.2+sha.abc"',
    );
  });
});
