import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { blaEsbuildPlugin } from "../src/bundler/index.js";

interface EsbuildLoadResult {
  readonly contents: string;
  readonly loader: string;
}

interface FakeBuild {
  onLoad(
    opts: { filter: RegExp },
    cb: (args: { path: string }) => Promise<EsbuildLoadResult | null>,
  ): void;
  onEnd(cb: () => void): void;
}

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "bla-esbuild-"));
  tempDirs.push(dir);
  return dir;
}

function loadCallback(): (args: { path: string }) => Promise<EsbuildLoadResult | null> {
  const plugin = blaEsbuildPlugin({ seed: "segment-test", failBuildOnError: true }) as unknown as {
    setup(build: FakeBuild): void;
  };
  let onLoad: ((args: { path: string }) => Promise<EsbuildLoadResult | null>) | undefined;
  plugin.setup({
    onLoad(_opts, cb) {
      onLoad = cb;
    },
    onEnd() {
      /* not used */
    },
  });
  if (!onLoad) throw new Error("esbuild plugin did not register onLoad");
  return onLoad;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("esbuild plugin dependency skipping", () => {
  it("shields a project directory whose name merely contains node_modules", async () => {
    const dir = createTempDir();
    const project = join(dir, "my-node_modules-backup");
    mkdirSync(project, { recursive: true });
    const file = join(project, "app.js");
    const source = "export function unlock(token) { return token === 'KEY'; }\n";
    writeFileSync(file, source, "utf8");

    const result = await loadCallback()({ path: file });

    expect(result).not.toBeNull();
    expect(result!.contents).not.toBe(source);
  });

  it("still skips a real node_modules dependency", async () => {
    const dir = createTempDir();
    const dependency = join(dir, "node_modules", "pkg");
    mkdirSync(dependency, { recursive: true });
    const file = join(dependency, "index.js");
    writeFileSync(file, "module.exports = 1;\n", "utf8");

    const result = await loadCallback()({ path: file });

    expect(result).toBeNull();
  });
});