#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const cli = join(root, "dist", "cli", "meridian.cjs");
const env = { ...process.env };
delete env.NODE_OPTIONS;
const r = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
  env,
  stdio: "inherit",
});
process.exit(r.status == null ? 1 : r.status);
