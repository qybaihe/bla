import { accessSync, constants, existsSync, statSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const BLA_ROOT = resolve(__dirname, "../../..");
// Empty/whitespace REA_ROOT is unset (CI passes "" when sibling REA is absent).
const REA_ROOT_ENV = (process.env.REA_ROOT ?? "").trim();
export const REA_ROOT = resolve(REA_ROOT_ENV || join(BLA_ROOT, "..", "rea"));
export const REDTEAM_OUT_DIR = join(BLA_ROOT, "docs/redteam");
export const REDTEAM_REPORT_MD = join(
  REDTEAM_OUT_DIR,
  "empirical-rea-validation.md",
);
export const REDTEAM_REPORT_JSON = join(
  REDTEAM_OUT_DIR,
  "empirical-rea-validation.json",
);

export function resolveReaDist(rel) {
  return join(REA_ROOT, "dist", rel);
}

export function reaDistReady() {
  return existsSync(resolveReaDist("go/GoBinaryImage.js"));
}

function isExecutableFile(path) {
  try {
    if (!statSync(path).isFile()) return false;
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** First absolute PATH entry holding the tool, as REA itself selects it. */
function findOnPath(name) {
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    const candidate = join(dir, name);
    if (isExecutableFile(candidate)) return candidate;
  }
  return null;
}

/**
 * The tshark REA would run, in this order: `REA_TSHARK_COMMAND` (REA's own
 * setting, an absolute path), a user-local Linux extract under
 * `~/opt/wireshark`, `tshark` on PATH, then the Wireshark installer's default
 * location on macOS / Windows. `source` says which one was used.
 */
export function resolveTsharkEnv() {
  const home = process.env.HOME ?? "";
  const configured = (process.env.REA_TSHARK_COMMAND ?? "").trim();
  if (configured && isAbsolute(configured) && isExecutableFile(configured)) {
    return {
      available: true,
      bin: configured,
      env: process.env,
      source: "REA_TSHARK_COMMAND",
    };
  }
  const prefix = join(home, "opt/wireshark");
  const extracted = join(prefix, "usr/bin/tshark");
  if (existsSync(extracted)) {
    const lib = [
      join(prefix, "usr/lib/x86_64-linux-gnu"),
      join(prefix, "lib/x86_64-linux-gnu"),
    ].join(":");
    return {
      available: true,
      bin: extracted,
      env: {
        ...process.env,
        PATH: `${join(prefix, "usr/bin")}:${process.env.PATH ?? ""}`,
        LD_LIBRARY_PATH: `${lib}${process.env.LD_LIBRARY_PATH ? `:${process.env.LD_LIBRARY_PATH}` : ""}`,
      },
      source: "~/opt/wireshark",
    };
  }
  const onPath = findOnPath(
    process.platform === "win32" ? "tshark.exe" : "tshark",
  );
  if (onPath) {
    return { available: true, bin: onPath, env: process.env, source: "PATH" };
  }
  const installed =
    process.platform === "darwin"
      ? "/Applications/Wireshark.app/Contents/MacOS/tshark"
      : process.platform === "win32"
        ? join(process.env.ProgramFiles ?? "C:\\Program Files", "Wireshark", "tshark.exe")
        : null;
  if (installed && isExecutableFile(installed)) {
    return {
      available: true,
      bin: installed,
      env: process.env,
      source: "Wireshark installer",
    };
  }
  return { available: false, bin: null, env: process.env, source: null };
}

/** User-local WABT 1.0.42 tools (REA_WABT_BIN_DIRECTORY). Soft-skip when absent. */
export function resolveWabtEnv() {
  const fromEnv = process.env.REA_WABT_BIN_DIRECTORY;
  const home = process.env.HOME ?? "";
  const candidates = [
    fromEnv,
    join(home, "opt/wabt-1.0.42/bin"),
    join(home, "wabt/bin"),
  ].filter(Boolean);
  for (const dir of candidates) {
    const validate = join(dir, "wasm-validate");
    const objdump = join(dir, "wasm-objdump");
    const wasm2wat = join(dir, "wasm2wat");
    if (existsSync(validate) && existsSync(objdump) && existsSync(wasm2wat)) {
      return {
        available: true,
        directory: dir,
        env: { ...process.env, REA_WABT_BIN_DIRECTORY: dir },
      };
    }
  }
  return { available: false, directory: null, env: process.env };
}
