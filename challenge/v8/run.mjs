#!/usr/bin/env node
/**
 * Run CrackMe v8 (Aegis): gunzip core.wasm into a temp dir and invoke license.cjs.
 */
import { mkdtempSync, copyFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const root = dirname(fileURLToPath(import.meta.url));
const hardened = join(root, "hardened");
const dir = mkdtempSync(join(tmpdir(), "bla-crackme-v8-run-"));
try {
  copyFileSync(join(hardened, "license.cjs"), join(dir, "license.cjs"));
  copyFileSync(join(hardened, "panel.html"), join(dir, "panel.html"));
  copyFileSync(join(hardened, "seal.json"), join(dir, "seal.json"));
  writeFileSync(join(dir, "core.wasm"), gunzipSync(readFileSync(join(hardened, "core.wasm.gz"))));
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  const r = spawnSync(process.execPath, [join(dir, "license.cjs"), ...process.argv.slice(2)], {
    env,
    stdio: "inherit",
  });
  process.exit(r.status == null ? 1 : r.status);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
