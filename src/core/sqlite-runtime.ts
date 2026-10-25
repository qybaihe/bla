import { createRequire } from "node:module";
import type { DatabaseSync } from "node:sqlite";

const require = createRequire(import.meta.url);

/** Load lazily so non-SQLite commands can still explain an unsupported setup. */
export function getDatabaseSyncClass(): typeof DatabaseSync {
  try {
    const mod = require("node:sqlite") as { DatabaseSync?: typeof DatabaseSync };
    if (
      typeof mod.DatabaseSync !== "function" ||
      typeof mod.DatabaseSync.prototype?.function !== "function"
    ) {
      throw new Error("node:sqlite is missing DatabaseSync.function");
    }
    return mod.DatabaseSync;
  } catch (cause) {
    throw new Error(
      `BLA SQLite support requires Node.js 22.x >=22.13.0 or Node.js >=24.0.0 ` +
        `with node:sqlite enabled (current runtime: ${process.version}). ` +
        "Upgrade Node.js and remove --no-experimental-sqlite if set.",
      { cause },
    );
  }
}
