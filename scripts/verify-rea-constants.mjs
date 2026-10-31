#!/usr/bin/env node
/**
 * DRIFT HARNESS ONLY — tracks whether REA published constants moved.
 * This is NOT proof of protection and must NEVER be cited as red-team evidence.
 * Authoritative evidence is exclusively `npm run redteam:rea` (real in-process REA).
 */
/**
 * REA-drift verification harness.
 *
 * Reads the local REA checkout and asserts — by constant NAME, never by
 * brittle file:line citations — that every hard limit BLA depends on still
 * matches the expected value. Prints a clear PASS/FAIL drift report.
 *
 * Usage:
 *   node scripts/verify-rea-constants.mjs
 *   REA_ROOT=/path/to/rea node scripts/verify-rea-constants.mjs
 *
 * Exit code 0 = all asserted constants match, OR sibling REA absent (soft-skip).
 * Exit code 1 = drift detected when REA is present.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BLA_ROOT = resolve(__dirname, "..");
// Treat an empty/whitespace REA_ROOT as unset. CI passes `REA_ROOT=""` when the
// sibling checkout is absent; `??` would keep "" and resolve("") === cwd, which
// silently pointed this harness at BLA's OWN tree and produced bogus failures.
const REA_ROOT_ENV = (process.env.REA_ROOT ?? "").trim();
const REA_ROOT = resolve(REA_ROOT_ENV || join(BLA_ROOT, "..", "rea"));

/** Evaluate a simple numeric TS/Python initializer (`64 * 1024`, `1_048_576`, `65_536`). */
function evalNumericExpr(expr) {
  const cleaned = expr
    .replace(/_/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "")
    .trim();
  if (!/^[\d\s*+\-().]+$/.test(cleaned)) {
    throw new Error(`unsupported numeric expression: ${expr}`);
  }
  // eslint-disable-next-line no-new-func
  return Number(Function(`"use strict"; return (${cleaned});`)());
}

function walkFiles(root, exts, out = []) {
  if (!existsSync(root)) return out;
  for (const ent of readdirSync(root)) {
    if (ent === "node_modules" || ent === "dist" || ent === ".git") continue;
    const full = join(root, ent);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walkFiles(full, exts, out);
    else if (exts.some((e) => ent.endsWith(e))) out.push(full);
  }
  return out;
}

function findAssignments(files, name) {
  const hits = [];
  // Match: export const NAME = … / const NAME = … / NAME = … (Python)
  const re = new RegExp(
    String.raw`(?:(?:export\s+)?(?:const|let|var)\s+|)${name}\s*=\s*([^;\n]+)`,
    "g",
  );
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    // Skip pure test files for value assertions (still allow symbol presence)
    const isTest = /\.test\.[jt]s$|\.spec\.[jt]s$/.test(file);
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) {
      hits.push({
        file: file.slice(REA_ROOT.length + 1),
        expr: m[1].trim(),
        isTest,
      });
    }
  }
  return hits;
}

function findObjectProperty(files, objectName, propName) {
  const hits = [];
  // Accept both `{ ... } as const` and `Object.freeze({ ... })` forms.
  const objRe = new RegExp(
    String.raw`(?:export\s+)?const\s+${objectName}\s*=\s*(?:Object\.freeze\s*\()?\{([\s\S]*?)\n\}\s*\)?\s*(?:as\s+const)?\s*;`,
    "g",
  );
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    objRe.lastIndex = 0;
    let m;
    while ((m = objRe.exec(text))) {
      const body = m[1];
      const propRe = new RegExp(
        String.raw`(?:^|,|\n)\s*${propName}\s*:\s*([^,\n]+)`,
        "g",
      );
      let pm;
      while ((pm = propRe.exec(body))) {
        hits.push({
          file: file.slice(REA_ROOT.length + 1),
          expr: pm[1].trim(),
          isTest: /\.test\.[jt]s$/.test(file),
        });
      }
    }
  }
  return hits;
}

function countObligationFamilies(files) {
  const policyFile = files.find((f) =>
    f.endsWith("ReconstructionObligationPolicies.ts"),
  );
  if (!policyFile) return { count: 0, keys: [], file: null };
  const text = readFileSync(policyFile, "utf8");
  const keys = [];
  const re =
    /^\s+(?:"([^"]+)"|([A-Za-z][A-Za-z0-9_-]*))\s*:\s*(?:policy|nativePolicy|parserPolicy)\(/gm;
  let m;
  while ((m = re.exec(text))) keys.push(m[1] ?? m[2]);
  return {
    count: keys.length,
    keys,
    file: policyFile.slice(REA_ROOT.length + 1),
  };
}

/** Catalog of BLA-tracked REA constants (name → expected numeric value). */
const NUMERIC_EXPECTATIONS = [
  { name: "SEMANTIC_PRIMITIVE_CANDIDATE_LIMIT", expected: 256 },
  { name: "SEMANTIC_EXPRESSION_DEPTH_LIMIT", expected: 256 },
  { name: "SEMANTIC_GETTER_EXPANSION_LIMIT", expected: 512 },
  { name: "SEMANTIC_ALIAS_SELECTION_LIMIT", expected: 512 },
  { name: "SEMANTIC_PRIMITIVE_JSON_BYTES_LIMIT", expected: 1_048_576 },
  { name: "WASM_INTERFACE_REPRESENTATION_BYTES", expected: 32 * 1024 * 1024 },
  { name: "MODEL_JSON_NESTING", expected: 32 },
  { name: "MODEL_METADATA_NESTING", expected: 32 },
  { name: "MAX_JSON_DEPTH", expected: 64, fileHint: "fridaCaptureLimits" },
  { name: "MAX_MESSAGE_TEXT_BYTES", expected: 32 * 1024 },
  { name: "DEFAULT_ASAR_MAX_HEADER_BYTES", expected: 16 * 1024 * 1024 },
  { name: "DEFAULT_REGEX_MATCHING_DEADLINE_MS", expected: 5_000 },
  { name: "MAX_TRACE_FRAMES", expected: 65_536 },
  { name: "MAX_OTHER_STOPS", expected: 256 },
  { name: "MAX_TRACE_BYTES", expected: 8 * 1024 * 1024 },
  { name: "MAX_COMMAND_OUTPUT_RECORDS", expected: 16_384, fileHint: "GdbSessionManager" },
  { name: "MAX_COMMAND_FRAMES", expected: 4096, fileHint: "RizinDebugSessionManager" },
  { name: "STEP_DIFFERENCE_LIMIT", expected: 20 },
  { name: "MAX_RUSTC_HASHES", expected: 64 },
  { name: "MAX_SNAPSHOT_HASH_CANDIDATES", expected: 64 },
  { name: "PYTHON_PYC_CONST_PREVIEW_LIMIT", expected: 80 },
  { name: "MAX_BUILD_INFO_BYTES", expected: 1_048_576, fileHint: "GoBinaryImage" },
  { name: "MAX_HEADER_SEARCH_BYTES", expected: 256 * 1024 * 1024, fileHint: "GoBinaryImage" },
  { name: "MAX_POOL_URIS", expected: 500, fileHint: "FlutterBuildProvider" },
  { name: "MAX_POOL_TOKENS", expected: 2_000, fileHint: "FlutterBuildProvider" },
  { name: "MAX_INSPECT_ERLANG_BEAM_CHUNKS", expected: 256 },
  { name: "MAX_INSPECT_ERLANG_BEAM_ATOMS", expected: 65_536 },
  { name: "TSHARK_JSON_MAX_BYTES", expected: 8 * 1024 * 1024 },
  { name: "GPU_REPORT_BYTES", expected: 16 * 1024 * 1024 },
  { name: "GPU_OBJECT_BYTES", expected: 128 * 1024 * 1024 },
  { name: "MAX_FIRMWARE_STAGING_BYTES", expected: 512 * 1024 * 1024 },
  { name: "MAX_FIRMWARE_EXTRACTION_DEPTH", expected: 10 },
  { name: "ANDROID_JNI_REPORT_BYTES", expected: 16 * 1024 * 1024 },
  { name: "MAX_NATIVE_EXPORT_ROWS", expected: 262_144 },
  // Bun standalone module graph reader (REA #6998).
  // REA #8154 — external DEX invoke inventories (ReaJadxBridge.java)
  { name: "MAX_XREF_TEXT_BYTES", expected: 8 * 1024 * 1024 - 1024 },
  { name: "BUN_RECORD_BYTES_1_3_3", expected: 36 },
  { name: "BUN_RECORD_BYTES_1_3_9", expected: 52 },
  { name: "MAX_BUN_MODULE_COUNT", expected: 100_000 },
  { name: "MAX_BUN_RETAINED_BYTES", expected: 256 * 1024 * 1024 },
  { name: "MAX_LOGICAL_PATH_PARTS", expected: 256 },
  { name: "MAX_LOGICAL_PATH_NODES", expected: 250_000 },
  // UF2 firmware container (REA #8230)
  { name: "UF2_BLOCK_BYTES", expected: 512 },
  { name: "UF2_MAX_REGIONS", expected: 65_536 },
];

const OBJECT_PROP_EXPECTATIONS = [
  {
    objectName: "WEB_RUNTIME_LIMITS",
    propName: "sourceBytes",
    expected: 32 * 1024 * 1024,
    label: "WEB_RUNTIME_LIMITS.sourceBytes",
  },
  {
    objectName: "WEB_RUNTIME_LIMITS",
    propName: "retainedEventBytes",
    expected: 8 * 1024 * 1024,
    label: "WEB_RUNTIME_LIMITS.retainedEventBytes",
  },
  {
    objectName: "EVM_INTERFACE_LIMITS",
    propName: "inputBytes",
    expected: 4 * 1024 * 1024,
    label: "EVM_INTERFACE_LIMITS.inputBytes",
  },
  {
    objectName: "EVM_INTERFACE_LIMITS",
    propName: "outputBytes",
    expected: 16 * 1024 * 1024,
    label: "EVM_INTERFACE_LIMITS.outputBytes",
  },
  {
    objectName: "EVM_INTERFACE_LIMITS",
    propName: "diagnosticBytes",
    expected: 1 * 1024 * 1024,
    label: "EVM_INTERFACE_LIMITS.diagnosticBytes",
  },
  {
    objectName: "PROGUARD_MAPPING_LIMITS",
    propName: "indexBytes",
    expected: 128 * 1024 * 1024,
    label: "PROGUARD_MAPPING_LIMITS.indexBytes",
  },
  {
    objectName: "PROGUARD_MAPPING_LIMITS",
    propName: "projectionBytes",
    expected: 8 * 1024 * 1024,
    label: "PROGUARD_MAPPING_LIMITS.projectionBytes",
  },
  {
    objectName: "PROGUARD_MAPPING_LIMITS",
    propName: "malformedSamples",
    expected: 16,
    label: "PROGUARD_MAPPING_LIMITS.malformedSamples",
  },
  {
    objectName: "PROGUARD_MAPPING_LIMITS",
    propName: "candidates",
    expected: 8,
    label: "PROGUARD_MAPPING_LIMITS.candidates",
  },
  {
    objectName: "ANDROID_MAPPING_LIMITS",
    propName: "fileBytes",
    expected: 64 * 1024 * 1024,
    label: "ANDROID_MAPPING_LIMITS.fileBytes",
  },
  {
    objectName: "ANDROID_JNI_LIBRARY_LIMITS",
    propName: "libraryBytes",
    expected: 64 * 1024 * 1024,
    label: "ANDROID_JNI_LIBRARY_LIMITS.libraryBytes",
  },
  {
    objectName: "ANDROID_JNI_LIBRARY_LIMITS",
    propName: "totalBytes",
    expected: 256 * 1024 * 1024,
    label: "ANDROID_JNI_LIBRARY_LIMITS.totalBytes",
  },
  {
    objectName: "ANDROID_JNI_LIBRARY_LIMITS",
    propName: "factsBytes",
    expected: 16 * 1024 * 1024,
    label: "ANDROID_JNI_LIBRARY_LIMITS.factsBytes",
  },
  {
    objectName: "ANDROID_JNI_LIBRARY_LIMITS",
    propName: "entries",
    expected: 100_000,
    label: "ANDROID_JNI_LIBRARY_LIMITS.entries",
  },
  {
    objectName: "ANDROID_JNI_LIBRARY_LIMITS",
    propName: "libraries",
    expected: 2048,
    label: "ANDROID_JNI_LIBRARY_LIMITS.libraries",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "components",
    expected: 512,
    label: "ANDROID_MANIFEST_LIMITS.components",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "intentFilters",
    expected: 32,
    label: "ANDROID_MANIFEST_LIMITS.intentFilters",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "intentValues",
    expected: 64,
    label: "ANDROID_MANIFEST_LIMITS.intentValues",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "authorities",
    expected: 64,
    label: "ANDROID_MANIFEST_LIMITS.authorities",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "resolvedNameBytes",
    expected: 1024 * 1024,
    label: "ANDROID_MANIFEST_LIMITS.resolvedNameBytes",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "authorityBytes",
    expected: 1024 * 1024,
    label: "ANDROID_MANIFEST_LIMITS.authorityBytes",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "permissionBytes",
    expected: 1024 * 1024,
    label: "ANDROID_MANIFEST_LIMITS.permissionBytes",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "processBytes",
    expected: 1024 * 1024,
    label: "ANDROID_MANIFEST_LIMITS.processBytes",
  },
  {
    objectName: "ANDROID_MANIFEST_LIMITS",
    propName: "detailBytes",
    expected: 1024 * 1024,
    label: "ANDROID_MANIFEST_LIMITS.detailBytes",
  },
];

const SYMBOL_EXPECTATIONS = [
  "SqliteColumnEvaluationFailure",
  "parseRecordedTransportUrl",
  "singleQueryValues",
  "MAX_EXTERNAL_XREF_BYTES",
  "ReferenceLimit",
];

const EXPECTED_OBLIGATION_FAMILIES = [
  "package",
  "installer",
  "context-bridge-api",
  "ipc-channel",
  "ipc-handler",
  "endpoint",
  "storage",
  "worker",
  "service-worker",
  "native-addon",
  "native-export",
  "managed-pinvoke-import",
  "managed-native-implementation",
  "child-process",
  "stdio",
  "signal",
  "config-source",
  "request",
  "response",
  "boundary",
  "resource",
  "event",
  "timer",
  "promise",
  "task",
  "url-scheme",
];

function main() {
  console.log("BLA ↔ REA constant drift verification");
  console.log(`  BLA_ROOT = ${BLA_ROOT}`);
  console.log(`  REA_ROOT = ${REA_ROOT}`);

  if (
    REA_ROOT === BLA_ROOT ||
    !existsSync(REA_ROOT) ||
    !existsSync(join(REA_ROOT, "src"))
  ) {
    console.log(
      `SKIP: sibling REA checkout not found at ${REA_ROOT}. ` +
        "verify:rea requires a local REA tree; CI skips when absent.",
    );
    process.exit(0);
  }

  const files = [
    ...walkFiles(join(REA_ROOT, "src"), [".ts", ".js"]),
    ...walkFiles(join(REA_ROOT, "bridge"), [".ts", ".js", ".py", ".java"]),
  ];

  const rows = [];
  let failures = 0;

  for (const spec of NUMERIC_EXPECTATIONS) {
    let hits = findAssignments(files, spec.name).filter((h) => !h.isTest);
    if (spec.fileHint) {
      const hinted = hits.filter((h) => h.file.includes(spec.fileHint));
      if (hinted.length) hits = hinted;
    }
    if (hits.length === 0) {
      rows.push({
        status: "FAIL",
        label: spec.name,
        detail: "constant not found in REA source",
      });
      failures++;
      continue;
    }
    // Prefer non-test, first production hit
    const hit = hits[0];
    let actual;
    try {
      actual = evalNumericExpr(hit.expr);
    } catch (err) {
      rows.push({
        status: "FAIL",
        label: spec.name,
        detail: `cannot parse '${hit.expr}' in ${hit.file}: ${err.message}`,
      });
      failures++;
      continue;
    }
    if (actual === spec.expected) {
      rows.push({
        status: "PASS",
        label: spec.name,
        detail: `${actual}  (${hit.file})`,
      });
    } else {
      rows.push({
        status: "FAIL",
        label: spec.name,
        detail: `expected ${spec.expected}, found ${actual} in ${hit.file} (${hit.expr})`,
      });
      failures++;
    }
  }

  for (const spec of OBJECT_PROP_EXPECTATIONS) {
    const hits = findObjectProperty(files, spec.objectName, spec.propName).filter(
      (h) => !h.isTest,
    );
    if (hits.length === 0) {
      rows.push({
        status: "FAIL",
        label: spec.label,
        detail: "property not found",
      });
      failures++;
      continue;
    }
    const hit = hits[0];
    let actual;
    try {
      actual = evalNumericExpr(hit.expr);
    } catch (err) {
      rows.push({
        status: "FAIL",
        label: spec.label,
        detail: `cannot parse '${hit.expr}': ${err.message}`,
      });
      failures++;
      continue;
    }
    if (actual === spec.expected) {
      rows.push({
        status: "PASS",
        label: spec.label,
        detail: `${actual}  (${hit.file})`,
      });
    } else {
      rows.push({
        status: "FAIL",
        label: spec.label,
        detail: `expected ${spec.expected}, found ${actual} in ${hit.file}`,
      });
      failures++;
    }
  }

  for (const sym of SYMBOL_EXPECTATIONS) {
    const found = files.some((f) => {
      try {
        return readFileSync(f, "utf8").includes(sym);
      } catch {
        return false;
      }
    });
    if (found) {
      rows.push({ status: "PASS", label: sym, detail: "symbol present" });
    } else {
      rows.push({ status: "FAIL", label: sym, detail: "symbol missing" });
      failures++;
    }
  }

  const obl = countObligationFamilies(files);
  const missing = EXPECTED_OBLIGATION_FAMILIES.filter((k) => !obl.keys.includes(k));
  const extra = obl.keys.filter((k) => !EXPECTED_OBLIGATION_FAMILIES.includes(k));
  if (
    obl.count === EXPECTED_OBLIGATION_FAMILIES.length &&
    missing.length === 0 &&
    extra.length === 0
  ) {
    rows.push({
      status: "PASS",
      label: "ReconstructionObligationFamilies",
      detail: `${obl.count} families  (${obl.file})`,
    });
  } else {
    rows.push({
      status: "FAIL",
      label: "ReconstructionObligationFamilies",
      detail: `expected ${EXPECTED_OBLIGATION_FAMILIES.length}, found ${obl.count}; missing=[${missing}] extra=[${extra}] (${obl.file})`,
    });
    failures++;
  }

  // Asar integrity disclosure (recent REA commits) — presence check, not a numeric cap
  const asarListing = files.find((f) => f.endsWith("AsarListing.ts"));
  if (asarListing) {
    const text = readFileSync(asarListing, "utf8");
    const hasBlockLimitation =
      text.includes("ASAR block integrity declarations were not validated") ||
      text.includes("BLOCK_INTEGRITY_LIMITATION");
    const hasUnsupportedAlgo =
      text.includes("unsupported algorithm") ||
      text.includes("uses an unsupported algorithm");
    if (hasBlockLimitation && hasUnsupportedAlgo) {
      rows.push({
        status: "PASS",
        label: "AsarIntegrityDisclosure",
        detail:
          "REA discloses unverified block integrity + unsupported algorithms (no new numeric cap)",
      });
    } else {
      rows.push({
        status: "FAIL",
        label: "AsarIntegrityDisclosure",
        detail: "expected block-integrity / unsupported-algorithm disclosure text missing",
      });
      failures++;
    }
  } else {
    rows.push({
      status: "FAIL",
      label: "AsarIntegrityDisclosure",
      detail: "AsarListing.ts not found",
    });
    failures++;
  }

  console.log("");
  const labelWidth = Math.max(...rows.map((r) => r.label.length), 10);
  for (const row of rows) {
    const pad = " ".repeat(labelWidth - row.label.length);
    console.log(`${row.status.padEnd(4)}  ${row.label}${pad}  ${row.detail}`);
  }
  console.log("");
  console.log(
    failures === 0
      ? `OK  ${rows.length} checks passed — BLA catalog is aligned with REA.`
      : `DRIFT  ${failures}/${rows.length} checks failed — update src/identity.ts / rea-budget-matrix.ts / obligation-flooder.ts.`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main();
