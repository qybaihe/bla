#!/usr/bin/env node
/**
 * Make `npx bla-agents@<this version> …` work inside this repository.
 *
 * The checked-in `.mcp.json` and the plugin manifests start the MCP server with
 * `npx -y bla-agents@<version> mcp`. Everywhere else that downloads the
 * package. Here, npx sees that the checkout itself satisfies the spec, skips
 * the download and runs the `bla` binary from `node_modules/.bin` — where npm
 * never links a package's own binaries. Result: every agent session opened in
 * this repo lost its BLA server with `sh: bla: command not found`.
 *
 * Linking our own bins to the local build fixes that, and means a session in
 * this repo dogfoods the checkout instead of the published release. Runs at
 * the end of `npm run build`; a missing `node_modules` or `dist` is not an
 * error (nothing to link yet).
 */
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const binDir = join(root, "node_modules", ".bin");
const cliPath = join(root, "dist", "cli.js");

if (!existsSync(join(root, "node_modules")) || !existsSync(cliPath)) {
  process.exit(0);
}

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const binNames = Object.keys(
  typeof pkg.bin === "object" && pkg.bin !== null ? pkg.bin : {},
);
const relativeTarget = join("..", "..", "dist", "cli.js");

mkdirSync(binDir, { recursive: true });
let linked = 0;
for (const name of binNames) {
  const link = join(binDir, name);
  try {
    if (process.platform === "win32") {
      writeFileSync(
        `${link}.cmd`,
        `@ECHO off\r\nnode "%~dp0\\..\\..\\dist\\cli.js" %*\r\n`,
        "utf8",
      );
      linked += 1;
      continue;
    }
    let existing;
    try {
      existing = lstatSync(link);
    } catch {
      existing = undefined;
    }
    if (existing !== undefined) {
      // Only ever replace our own link — never another package's binary.
      if (!existing.isSymbolicLink() || readlinkSync(link) !== relativeTarget) {
        console.warn(`link-self-bin: left ${link} alone (not a link to this build)`);
        continue;
      }
      rmSync(link, { force: true });
    }
    symlinkSync(relativeTarget, link);
    linked += 1;
  } catch (err) {
    console.warn(
      `link-self-bin: could not link ${name}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
if (linked > 0) {
  console.log(`Linked ${linked} local bin(s) into node_modules/.bin (in-repo npx / .mcp.json)`);
}
