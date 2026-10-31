import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

export const ROOT = resolve(fileURLToPath(new URL("../..", import.meta.url)));
export const V6_DIR = join(ROOT, "challenge", "v6");
export const TEMPLATE_PATH = join(V6_DIR, "clean", "target.template.cjs");
export const PROFILES_PATH = join(V6_DIR, "profiles.json");
export const COMMITMENT_PATH = join(V6_DIR, "commitment.json");
export const ARTIFACTS_DIR = join(V6_DIR, "artifacts");
export const BUILD_REPORT_PATH = join(ARTIFACTS_DIR, "build-report.json");

export const FIXTURE_KEY = "DemoKey-CrackMe-V6-FIXTURE!";
export const FIXTURE_FLAG = "FLAG{bla_v6_demo_fixture_not_the_real_prize}";

export function sha256Hex(value) {
  return createHash("sha256").update(String(value), "utf8").digest("hex");
}

export function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function loadProfiles() {
  return JSON.parse(readFileSync(PROFILES_PATH, "utf8"));
}

export function resolveSecrets(options = {}) {
  if (options.fixture || process.env.CRACKME_V6_MODE === "fixture") {
    return {
      mode: "fixture",
      key: FIXTURE_KEY,
      flag: FIXTURE_FLAG,
    };
  }
  const key = process.env.CRACKME_V6_KEY;
  const flag = process.env.CRACKME_V6_FLAG;
  if (!key || !flag) {
    throw new Error(
      "Missing CRACKME_V6_KEY / CRACKME_V6_FLAG. Export them, or pass --fixture for the public demo secret.",
    );
  }
  if (!flag.startsWith("FLAG{") || !flag.endsWith("}")) {
    throw new Error("CRACKME_V6_FLAG must look like FLAG{...}");
  }
  if (key.length < 12) {
    throw new Error("CRACKME_V6_KEY must be at least 12 characters");
  }
  return { mode: "release", key, flag };
}

export function deriveFlagCipherHex(scope, key, flag) {
  const mask = createHash("sha256")
    .update(`bla-crackme-v6|${scope}|${key}`, "utf8")
    .digest();
  const plain = Buffer.from(flag, "utf8");
  const cipher = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) {
    cipher[i] = plain[i] ^ mask[i % mask.length];
  }
  return cipher.toString("hex");
}

export function materializeCleanTarget({ scope, key, flag, outputPath }) {
  const template = readFileSync(TEMPLATE_PATH, "utf8");
  const materialized = template
    .replaceAll("%%SCOPE%%", scope)
    .replaceAll("%%KEY_SHA256%%", sha256Hex(key))
    .replaceAll("%%FLAG_SHA256%%", sha256Hex(flag))
    .replaceAll("%%FLAG_CIPHER_HEX%%", deriveFlagCipherHex(scope, key, flag));
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, materialized, "utf8");
  return outputPath;
}

export function ensureDistBuilt() {
  const cli = join(ROOT, "dist", "cli.js");
  const protector = join(ROOT, "dist", "engine", "protector.js");
  if (!existsSync(cli) || !existsSync(protector)) {
    execFileSync("npm", ["run", "build"], { cwd: ROOT, stdio: "inherit" });
  }
}

export async function protectTier({ cleanPath, outPath, tier, seed }) {
  ensureDistBuilt();
  const protectorUrl = pathToFileURL(join(ROOT, "dist", "engine", "protector.js")).href;
  const { protectTarget } = await import(protectorUrl);
  mkdirSync(dirname(outPath), { recursive: true });
  const result = protectTarget({
    inputPath: cleanPath,
    outputPath: outPath,
    intensity: tier.intensity,
    seed: `${seed}:${tier.intensity}:${tier.llmDirectives ? "llm" : "std"}`,
    honeySourceMaps: tier.honeySourceMaps !== false,
    llmDirectives: tier.llmDirectives === true,
  });
  return result;
}

export function runCrackme(artifactPath, key) {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  try {
    const stdout = execFileSync(process.execPath, [artifactPath, key], {
      encoding: "utf8",
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { ok: true, status: 0, stdout, stderr: "" };
  } catch (err) {
    return {
      ok: false,
      status: err.status ?? 1,
      stdout: err.stdout?.toString?.() ?? "",
      stderr: err.stderr?.toString?.() ?? String(err),
    };
  }
}

export function extractFlag(text) {
  const m = String(text).match(/FLAG\{[A-Za-z0-9_\-]{12,}\}/);
  return m ? m[0] : null;
}

export function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}
