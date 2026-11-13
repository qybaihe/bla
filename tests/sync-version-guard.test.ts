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
