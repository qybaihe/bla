#!/usr/bin/env node
/** One-command runner: `npm run crackme:v6 -- '<16-char key>'` (or `node challenge/v6/run.mjs <key>`). */
import { execFileSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { HARDENED_DIR, prepareRunnable } from "../../scripts/crackme/lib.mjs";

const dir = prepareRunnable(HARDENED_DIR);
const env = { ...process.env };
delete env.NODE_OPTIONS;
let code = 0;
try {
  execFileSync(process.execPath, [join(dir, "vault.cjs"), ...process.argv.slice(2)], { stdio: "inherit", env });
} catch (err) {
  code = err.status ?? 1;
} finally {
  rmSync(dir, { recursive: true, force: true });
}
process.exit(code);
