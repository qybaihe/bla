import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  resolveReaDist,
  resolveTsharkEnv,
  resolveWabtEnv,
  reaDistReady,
} from "./paths.mjs";

const require = createRequire(import.meta.url);

/** Faithful replica of REA `projectStringPool` (private in FlutterBuildProvider). */
export function projectStringPoolReaFaithful(section, limits) {
  const MAX_POOL_URIS = limits.DART_MAX_POOL_URIS;
  const MAX_POOL_TOKENS = limits.DART_MAX_POOL_TOKENS;
  const COLLECTION_SLACK = 2;
  const MAX_RUN_BYTES = 1024;
  const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
  const packages = new Set();
  const darts = new Set();
  const tokens = new Set();
  let runCount = 0;
  let collectionCapped = false;
  const packageBudget = MAX_POOL_URIS * COLLECTION_SLACK;
  const dartBudget = MAX_POOL_URIS * COLLECTION_SLACK;
  const tokenBudget = MAX_POOL_TOKENS * COLLECTION_SLACK;
  if (section != null) {
    let run = "";
    let overflowed = false;
    const consider = (text) => {
      if (text.length < 5) return;
      runCount += 1;
      if (text.startsWith("package:")) {
        if (!packages.has(text) && packages.size >= packageBudget)
          collectionCapped = true;
        else packages.add(text);
      } else if (text.startsWith("dart:")) {
        if (!darts.has(text) && darts.size >= dartBudget)
          collectionCapped = true;
        else darts.add(text);
      } else if (
        text.length <= 128 &&
        text.length >= 5 &&
        IDENTIFIER_PATTERN.test(text)
      ) {
        if (!tokens.has(text) && tokens.size >= tokenBudget)
          collectionCapped = true;
        else tokens.add(text);
      }
    };
    for (const byte of section) {
      if (byte >= 0x20 && byte < 0x7f) {
        if (run.length < MAX_RUN_BYTES) run += String.fromCharCode(byte);
        else {
          overflowed = true;
          collectionCapped = true;
        }
      } else {
        if (!overflowed) consider(run);
        overflowed = false;
        run = "";
      }
    }
    if (!overflowed) consider(run);
  }
  return {
    packageUriCount: packages.size,
    dartUriCount: darts.size,
    classLikeTokenCount: tokens.size,
    printableRunCount: runCount,
    collectionCapped,
    reportWouldCap:
      packages.size > MAX_POOL_URIS ||
      darts.size > MAX_POOL_URIS ||
      tokens.size > MAX_POOL_TOKENS,
  };
}

function outcomeBase(format, phase, bytes) {
  return {
    format,
    phase,
    inputBytes: bytes.length,
    status: "ok",
    errorName: null,
    errorMessage: null,
    budgetHit: false,
    budgetName: null,
    redactionOrAmbiguity: null,
    metrics: {},
  };
}

/**
 * Record a REA-reported failure. budgetName may ONLY be set when the error
 * class / field / result value comes from REA's own limit enforcement, not
 * when the harness itself failed to call REA.
 */
function failOutcome(base, err, budgetName = null) {
  base.status = "error";
  base.errorName = err?.constructor?.name ?? "Error";
  base.errorMessage = String(err?.message ?? err).slice(0, 240);
  if (budgetName || err?.boundary || err?.failure?.limit?.name) {
    base.budgetHit = true;
    base.budgetName =
      budgetName ??
      err?.boundary ??
      err?.failure?.limit?.name ??
      "resource";
  }
  return base;
}

/**
 * Record a harness-internal failure (module missing, TypeError, API changed).
 * budgetHit is always false — the harness failing is not evidence of a REA
 * limit being hit.
 */
/** Placeholder for the capture path in REA's tshark arguments. */
const PCAP_PATH = Symbol("capture path");

/**
 * REA's tshark passes, read from its compiled provider: the field pass
 * (`-T json -e <field>…`, whose output over TSHARK_JSON_MAX_BYTES fails the
 * analysis) and the DNS pass (`-Y "dns || mdns || llmnr" -x -J …`, whose
 * failure only marks the result partial). Throws when the source no longer
 * has the shape this reads, instead of measuring something REA does not run.
 */
function readReaTsharkPasses(source, httpUriFields) {
  const block = /const FIELDS = \[([\s\S]*?)\];/.exec(source);
  if (!block) throw new Error("no `const FIELDS = [...]` list");
  const fields = [];
  for (const item of block[1].matchAll(
    /"([^"]+)"|\.\.\.Object\.keys\(PCAP_HTTP_URI_FIELDS\)/g,
  )) {
    if (item[1] !== undefined) fields.push(item[1]);
    else fields.push(...Object.keys(httpUriFields));
  }
  if (fields.length < 10 || !fields.includes("frame.number")) {
    throw new Error(`unexpected field list (${fields.length} fields)`);
  }
  for (const literal of [
    '"--no-duplicate-keys"',
    '"dns || mdns || llmnr"',
    '"frame dns mdns llmnr"',
    '"-x"',
    '"-J"',
  ]) {
    if (!source.includes(literal)) {
      throw new Error(`the DNS pass no longer passes ${literal}`);
    }
  }
  const common = ["-n", "-r", PCAP_PATH, "-T", "json", "--no-duplicate-keys"];
  return {
    fieldCount: fields.length,
    fieldPass: [...common, ...fields.flatMap((field) => ["-e", field])],
    dnsPass: [
      ...common,
      "-Y",
      "dns || mdns || llmnr",
      "-x",
      "-J",
      "frame dns mdns llmnr",
    ],
  };
}

function harnessErrorOutcome(base, err) {
  base.status = "harness_error";
  base.errorName = err?.constructor?.name ?? "Error";
  base.errorMessage = String(err?.message ?? err).slice(0, 240);
  base.budgetHit = false;
  base.budgetName = null;
  return base;
}

/** Track probes that failed due to harness issues (module missing, API changed). */
const _harnessErrors = [];
export function harnessErrors() {
  return _harnessErrors;
}

function recordHarnessError(format, reason) {
  _harnessErrors.push({ format, reason });
}

export async function loadReaProbes() {
  if (!reaDistReady()) {
    throw new Error(
      "REA dist missing — compile with: cd ../rea && npx tsc -p tsconfig.build.json",
    );
  }

  // Helper: try importing, return null on failure
  async function tryImport(rel) {
    try {
      return await import(resolveReaDist(rel));
    } catch {
      return null;
    }
  }

  const goMod = await import(resolveReaDist("go/GoBinaryImage.js"));
  const { readGoBinaryImage } = goMod;

  const beamMod = await import(resolveReaDist("erlang/BeamParser.js"));
  const { parseErlangBeam, BeamCapacityFailure } = beamMod;

  // EVM: EVM_INTERFACE_LIMITS removed from EvmoleRelease in REA HEAD.
  // The real limits now live in domain/evm/evmInterface.js as EVM_PRODUCER_LIMIT_DEFAULTS.
  let EVM_PRODUCER_LIMIT_DEFAULTS = null;
  try {
    const evmMod = await import(resolveReaDist("domain/evm/evmInterface.js"));
    EVM_PRODUCER_LIMIT_DEFAULTS = evmMod.EVM_PRODUCER_LIMIT_DEFAULTS;
  } catch {
    recordHarnessError("evm_bytecode", "domain/evm/evmInterface.js not loadable");
  }

  const { decodeEvmBytecodeCarrier } = await import(
    resolveReaDist("evm/EvmBytecodeCarrier.js")
  );
  const { inspectSolidityMetadata } = await import(
    resolveReaDist("evm/SolidityMetadata.js")
  );
  const { TSHARK_JSON_MAX_BYTES, parseTsharkJsonOutput } = await import(
    resolveReaDist("pcap/PcapOutput.js")
  );
  // REA analyses captures only where it can bound tshark's memory (Linux,
  // Windows), so the harness runs REA's two tshark passes itself — with the
  // arguments read from REA's own provider, so a change there is noticed.
  let PCAP_TSHARK_PASSES = null;
  try {
    const { PCAP_HTTP_URI_FIELDS } = await import(
      resolveReaDist("pcap/PcapHttpUri.js")
    );
    PCAP_TSHARK_PASSES = readReaTsharkPasses(
      readFileSync(resolveReaDist("pcap/PcapProvider.js"), "utf8"),
      PCAP_HTTP_URI_FIELDS,
    );
  } catch (err) {
    recordHarnessError(
      "pcap_capture",
      `REA's tshark arguments could not be read from pcap/PcapProvider.js: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Model: ModelFormatFailure removed; errors now use ParseFailureError with
  // failure.limit.name === "json-nesting" / "metadata-nesting".
  const modelMod = await import(resolveReaDist("model/ModelFormat.js"));
  const { MODEL_JSON_NESTING, MODEL_METADATA_NESTING } = modelMod;

  const { readSafetensorsHeader } = await import(
    resolveReaDist("model/SafetensorsHeader.js")
  );
  const { ModelHeaderReader } = await import(
    resolveReaDist("model/ModelHeaderReader.js")
  );
  const { GgufHeader } = await import(resolveReaDist("model/GgufHeader.js"));

  // ASAR: moved from artifacts/ to resources/.
  let admitAsarHeader = null;
  try {
    const asarMod = await import(resolveReaDist("resources/AsarHeader.js"));
    admitAsarHeader = asarMod.admitAsarHeader;
  } catch {
    // Fallback: try old path
    try {
      const asarMod = await import(resolveReaDist("artifacts/AsarHeader.js"));
      admitAsarHeader = asarMod.admitAsarHeader;
    } catch {
      recordHarnessError("electron_asar", "AsarHeader.js not found at resources/ or artifacts/");
    }
  }

  const { readAsarListing } = await import(
    resolveReaDist("artifacts/AsarListing.js")
  );

  // WASM: WasmInterfaceBudget moved from wasm/ to domain/wasm/wasmInterfaceBudget.
  let WasmInterfaceBudget = null;
  try {
    const wasmBudgetMod = await import(
      resolveReaDist("domain/wasm/wasmInterfaceBudget.js")
    );
    WasmInterfaceBudget = wasmBudgetMod.WasmInterfaceBudget;
  } catch {
    try {
      const wasmBudgetMod = await import(
        resolveReaDist("wasm/WasmInterfaceBudget.js")
      );
      WasmInterfaceBudget = wasmBudgetMod.WasmInterfaceBudget;
    } catch {
      recordHarnessError("wasm_module", "WasmInterfaceBudget not found");
    }
  }

  // WASM interface: WASM_INTERFACE_REPRESENTATION_BYTES renamed to DEFAULT_WASM_INTERFACE_REPRESENTATION_BYTES.
  const wasmIfaceMod = await import(
    resolveReaDist("domain/wasm/wasmInterface.js")
  );
  const { wasmInterfaceEntryRepresentationBytes } = wasmIfaceMod;
  const WASM_INTERFACE_REPRESENTATION_BYTES =
    wasmIfaceMod.DEFAULT_WASM_INTERFACE_REPRESENTATION_BYTES ??
    wasmIfaceMod.WASM_INTERFACE_REPRESENTATION_BYTES;

  const { readElectronFuseImage, ELECTRON_FUSE_LIMITS, ElectronFuseResourceFailure } =
    await import(resolveReaDist("electron/ElectronFuseReader.js"));

  let inspectSqliteDatabaseSnapshot = null;
  let SqliteInspectionFailure = null;
  let SqliteColumnEvaluationFailure = null;
  try {
    const sqliteMod = await import(
      resolveReaDist("sqlite/SqliteDatabaseInspection.js")
    );
    inspectSqliteDatabaseSnapshot = sqliteMod.inspectSqliteDatabaseSnapshot;
    SqliteInspectionFailure = sqliteMod.SqliteInspectionFailure;
  } catch {
    /* optional */
  }
  try {
    const limitsMod = await import(
      resolveReaDist("sqlite/SqliteDatabaseLimits.js")
    );
    SqliteColumnEvaluationFailure = limitsMod.SqliteColumnEvaluationFailure;
    SqliteInspectionFailure =
      SqliteInspectionFailure ?? limitsMod.SqliteInspectionFailure;
  } catch {
    /* optional */
  }
  let WabtArtifactProvider = null;
  try {
    ({ WabtArtifactProvider } = await import(
      resolveReaDist("wasm/WabtArtifactProvider.js")
    ));
  } catch {
    /* optional */
  }

  // JavaScript: static analysis now requires parseJavaScriptSource + step generator.
  // analyzeJavaScriptStaticSource is gone; analyzeJavaScriptSemantics wrapper still exists.
  let parseJavaScriptSource = null;
  let analyzeParsedJavaScriptStaticSourceSteps = null;
  let analyzeJavaScriptSemantics = null;
  try {
    const parserMod = await import(
      resolveReaDist("domain/javascript/javascriptSourceParser.js")
    );
    parseJavaScriptSource = parserMod.parseJavaScriptSource;
  } catch (err) {
    recordHarnessError("javascript", `javascriptSourceParser.js: ${String(err?.message ?? err).slice(0, 120)}`);
  }
  try {
    const staticMod = await import(
      resolveReaDist("domain/javascript/javascriptStaticAnalysis.js")
    );
    analyzeParsedJavaScriptStaticSourceSteps =
      staticMod.analyzeParsedJavaScriptStaticSourceSteps;
  } catch (err) {
    recordHarnessError("javascript", `javascriptStaticAnalysis.js: ${String(err?.message ?? err).slice(0, 120)}`);
  }
  try {
    const semMod = await import(
      resolveReaDist("domain/javascript/javascriptSemanticAnalysis.js")
    );
    analyzeJavaScriptSemantics = semMod.analyzeJavaScriptSemantics;
  } catch (err) {
    recordHarnessError("javascript", `javascriptSemanticAnalysis.js: ${String(err?.message ?? err).slice(0, 120)}`);
  }

  // The defaults of REA's per-call JavaScript budgets (`semantic_precision`).
  let JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS = null;
  try {
    const precisionMod = await import(
      resolveReaDist("domain/javascript/javascriptSemanticPrecision.js")
    );
    JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS =
      precisionMod.JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS ?? null;
  } catch {
    /* an REA revision with fixed limits: probeJavascriptStrings reports it */
  }

  return {
    JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS,
    readGoBinaryImage,
    parseErlangBeam,
    BeamCapacityFailure,
    EVM_PRODUCER_LIMIT_DEFAULTS,
    decodeEvmBytecodeCarrier,
    inspectSolidityMetadata,
    TSHARK_JSON_MAX_BYTES,
    parseTsharkJsonOutput,
    PCAP_TSHARK_PASSES,
    MODEL_JSON_NESTING,
    MODEL_METADATA_NESTING,
    readSafetensorsHeader,
    ModelHeaderReader,
    GgufHeader,
    admitAsarHeader,
    readAsarListing,
    WasmInterfaceBudget,
    wasmInterfaceEntryRepresentationBytes,
    WASM_INTERFACE_REPRESENTATION_BYTES,
    readElectronFuseImage,
    ELECTRON_FUSE_LIMITS,
    ElectronFuseResourceFailure,
    inspectSqliteDatabaseSnapshot,
    SqliteInspectionFailure,
    SqliteColumnEvaluationFailure,
    WabtArtifactProvider,
    parseJavaScriptSource,
    analyzeParsedJavaScriptStaticSourceSteps,
    analyzeJavaScriptSemantics,
  };
}

export async function probeGo(rea, bytes, phase) {
  const base = outcomeBase("go_buildinfo", phase, bytes);
  try {
    const img = rea.readGoBinaryImage(bytes);
    base.metrics = {
      hasBuildInfo: img.build_info != null,
      encoding: img.build_info?.encoding ?? null,
      goVersion: img.build_info?.go_version ?? null,
      moduleTextBytes: img.build_info?.module_text?.length ?? 0,
    };
    if (img.build_info == null) {
      base.redactionOrAmbiguity = "no_buildinfo_observed";
    }
  } catch (err) {
    // BinaryResourceFailure has .boundary (REA limit); BinaryFormatFailure does not.
    // Only mark budgetHit when the error is a BinaryResourceFailure with .boundary.
    const isResource = err?.constructor?.name === "BinaryResourceFailure" && err?.boundary;
    failOutcome(base, err, isResource ? `MAX_${err.boundary.toUpperCase().replace(/-/g, "_")}_BYTES` : null);
  }
  return base;
}

export async function probeFlutterPool(bla, bytes, phase, limits) {
  const base = outcomeBase("flutter_pool", phase, bytes);
  try {
    // validateElf64Layout throws on invalid; returns layout summary otherwise.
    const layout = bla.validateElf64Layout(bytes);
    const names = bla.resolveElf64SectionNames(bytes, layout);
    const iso = names.get(".isolate");
    if (!iso) {
      base.redactionOrAmbiguity = "no_isolate_section";
      return base;
    }
    const section = bytes.subarray(iso.offset, iso.offset + iso.size);
    const pool = projectStringPoolReaFaithful(section, limits);
    base.metrics = { isolateBytes: iso.size, ...pool };
    if (pool.reportWouldCap) {
      base.budgetHit = true;
      base.budgetName = "MAX_POOL_URIS|MAX_POOL_TOKENS";
      base.redactionOrAmbiguity =
        "REA would report truncated package_uris/dart_uris/class_like_tokens with 'at least N' limitations";
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probeBeam(rea, bytes, phase) {
  const base = outcomeBase("erlang_beam", phase, bytes);
  try {
    const artifact = {
      path: "sample.beam",
      bytes: bytes.length,
      sha256: "0".repeat(64),
    };
    const result = rea.parseErlangBeam(bytes, artifact, {
      max_chunks: 64,
      max_atoms: 4096,
    });
    base.metrics = {
      chunkCount: result.chunks.length,
      atomCount: result.atoms?.length ?? 0,
      limitations: (result.limitations ?? []).slice(0, 3),
    };
  } catch (err) {
    const name =
      err?.constructor?.name === "BeamCapacityFailure"
        ? err.resource === "chunks"
          ? "max_chunks"
          : err.resource === "atoms"
            ? "max_atoms"
            : "beam_capacity"
        : null;
    failOutcome(base, err, name);
  }
  return base;
}

export async function probeEvm(rea, bytes, phase) {
  const base = outcomeBase("evm_bytecode", phase, bytes);
  // Load the real limit from REA's EVM_PRODUCER_LIMIT_DEFAULTS.
  const defaults = rea.EVM_PRODUCER_LIMIT_DEFAULTS;
  if (!defaults) {
    harnessErrorOutcome(base, new Error(
      "EVM_PRODUCER_LIMIT_DEFAULTS not loaded (REA module unavailable)",
    ));
    recordHarnessError("evm_bytecode", "EVM_PRODUCER_LIMIT_DEFAULTS not loaded");
    return base;
  }
  const limit = defaults.input_bytes;
  base.metrics = {
    inputBytes: bytes.length,
    inputBytesLimit: limit,
    inputBytesLimitSource: "REA EVM_PRODUCER_LIMIT_DEFAULTS.input_bytes",
    approachesLimit: bytes.length >= limit - 8192,
    exceedsLimit: bytes.length > limit,
  };
  if (bytes.length > limit) {
    base.budgetHit = true;
    base.budgetName = "EVM_PRODUCER_LIMIT_DEFAULTS.input_bytes";
    base.status = "rejected_pre_worker";
    base.redactionOrAmbiguity =
      `REA would refuse to start the EVM worker (input ${bytes.length} exceeds limit ${limit})`;
    return base;
  }
  try {
    try {
      const carrier = rea.decodeEvmBytecodeCarrier(bytes, "raw");
      base.metrics.carrierBytes = carrier?.length;
    } catch (err) {
      base.metrics.carrierError = String(err.message).slice(0, 120);
    }
    try {
      const meta = rea.inspectSolidityMetadata(bytes);
      base.metrics.solidityMetadata = meta;
    } catch (err) {
      base.metrics.metadataError = String(err.message).slice(0, 120);
    }
    if (base.metrics.approachesLimit) {
      // Just under the cap is admitted, not rejected: REA's worker gets the
      // largest input it accepts. That is a cost, and it is not a budget hit.
      base.redactionOrAmbiguity =
        `admitted: ${bytes.length} of ${limit} bytes of REA's default input budget (approaches it, does not exceed it); the EVM worker itself is not run by this harness`;
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probePcap(rea, bytes, phase) {
  const base = outcomeBase("pcap_capture", phase, bytes);
  const tshark = resolveTsharkEnv();
  if (!tshark.available) {
    base.status = "skipped";
    base.redactionOrAmbiguity =
      "not empirically verified on this box (requires tshark)";
    return base;
  }
  if (!rea.PCAP_TSHARK_PASSES) {
    return harnessErrorOutcome(
      base,
      new Error("REA's tshark arguments could not be read"),
    );
  }
  const dir = mkdtempSync(join(tmpdir(), "bla-rt-pcap-"));
  const path = join(dir, `${phase}.pcap`);
  writeFileSync(path, bytes);
  const runTshark = (args) =>
    spawnSync(
      tshark.bin,
      [
        ...args.map((arg) => (arg === PCAP_PATH ? path : arg)),
        `--temp-dir=${dir}`,
      ],
      {
        encoding: "buffer",
        maxBuffer: 256 * 1024 * 1024,
        env: tshark.env,
        timeout: 300_000,
      },
    );
  const fieldPass = runTshark(rea.PCAP_TSHARK_PASSES.fieldPass);
  const dnsPass = runTshark(rea.PCAP_TSHARK_PASSES.dnsPass);
  // Context only: the full dissection is not what REA asks tshark for.
  const full = runTshark([
    "-n",
    "-r",
    PCAP_PATH,
    "-T",
    "json",
    "--no-duplicate-keys",
  ]);
  const cap = rea.TSHARK_JSON_MAX_BYTES;
  const fieldBytes = fieldPass.stdout ? fieldPass.stdout.length : 0;
  const dnsBytes = dnsPass.stdout ? dnsPass.stdout.length : 0;
  base.metrics = {
    tsharkSource: tshark.source,
    reaRunsPcapOnThisHost:
      process.platform === "linux" || process.platform === "win32",
    reaTsharkFieldCount: rea.PCAP_TSHARK_PASSES.fieldCount,
    tsharkStatus: fieldPass.status,
    tsharkJsonBytes: fieldBytes,
    tsharkDnsPassJsonBytes: dnsBytes,
    tsharkFullDissectionJsonBytes: full.stdout ? full.stdout.length : 0,
    tsharkJsonLimit: cap,
    exceedsTsharkJsonBudget: fieldBytes > cap,
    dnsPassExceedsTsharkJsonBudget: dnsBytes > cap,
  };
  const stderrHead = fieldPass.stderr
    ? Buffer.from(fieldPass.stderr).toString("utf8").slice(0, 160).trim()
    : "";
  if (stderrHead) base.metrics.stderrHead = stderrHead;
  if (fieldPass.error || dnsPass.error) {
    return harnessErrorOutcome(base, fieldPass.error ?? dnsPass.error);
  }
  if (fieldPass.status !== 0) {
    // REA reports a failed tool run as such; it is not a budget.
    failOutcome(
      base,
      new Error(`tshark exited ${fieldPass.status}: ${stderrHead}`),
    );
    return base;
  }
  if (fieldBytes > cap) {
    // REA captures at most `cap` bytes of the field pass, then fails the
    // analysis: "The packet-tool output capture allowance" (fixed).
    base.budgetHit = true;
    base.budgetName = "TSHARK_JSON_MAX_BYTES";
    base.status = "budget_rejected";
    base.redactionOrAmbiguity =
      "REA's tshark field pass exceeds its fixed output allowance; inspect_pcap_capture fails";
    return base;
  }
  // As REA does: parse the field pass (a failure here fails the analysis),
  // then parse it again with the DNS pass; when the DNS pass is over the
  // allowance or cannot be parsed, REA keeps the first result, marked partial.
  const fieldStdout = fieldPass.stdout.toString("utf8");
  let parsed;
  try {
    parsed = await rea.parseTsharkJsonOutput(fieldStdout);
  } catch (err) {
    failOutcome(
      base,
      err,
      err?.constructor?.name === "AnalysisResourceConstraintError"
        ? "TSHARK_JSON_DECODE"
        : null,
    );
    if (base.budgetHit) base.status = "budget_rejected";
    return base;
  }
  let dnsLimitation = null;
  if (dnsPass.status !== 0) {
    dnsLimitation = `the DNS pass exited ${dnsPass.status}`;
  } else if (dnsBytes > cap) {
    dnsLimitation = "the DNS pass exceeds the output allowance";
  } else {
    try {
      parsed = await rea.parseTsharkJsonOutput(
        fieldStdout,
        undefined,
        dnsPass.stdout.toString("utf8"),
      );
    } catch (err) {
      dnsLimitation = `the DNS pass was refused: ${String(err?.message ?? err).slice(0, 120)}`;
    }
  }
  base.metrics.reaPacketCount = parsed.packetCount;
  base.metrics.reaPartial = parsed.partial || dnsLimitation !== null;
  base.metrics.reaProtocolCount = parsed.protocolCount;
  base.metrics.reaHttpRequestUriCount = parsed.httpRequestUriCount;
  base.metrics.reaDnsQueryCount = parsed.dnsQueryCount;
  base.metrics.reaDnsLimitations = [
    ...(dnsLimitation ? [dnsLimitation] : []),
    ...parsed.dnsLimitations,
  ].slice(0, 2);
  return base;
}

export async function probeSafetensors(rea, bytes, phase) {
  const base = outcomeBase("safetensors", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "bla-rt-st-"));
  const path = join(dir, `${phase}.safetensors`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const reader = new rea.ModelHeaderReader(fh, bytes.length);
      const first = await reader.take(4);
      const result = await rea.readSafetensorsHeader(reader, first);
      base.metrics = {
        tensorCount: result.tensors?.length ?? 0,
        metadataCount: result.metadata?.length ?? 0,
        limitations: result.limitations ?? [],
      };
    } finally {
      await fh.close();
    }
  } catch (err) {
    // REA HEAD uses ParseFailureError with failure.limit.name for capacity failures.
    const limitName = err?.failure?.limit?.name ?? err?.limit ?? null;
    const budgetName = limitName === "json-nesting" ? "MODEL_JSON_NESTING"
      : limitName === "representation-bytes" ? "MODEL_REPRESENTATION_BYTES"
      : limitName ? limitName
      : null;
    failOutcome(base, err, budgetName);
  }
  return base;
}

export async function probeGguf(rea, bytes, phase) {
  const base = outcomeBase("gguf", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "bla-rt-gguf-"));
  const path = join(dir, `${phase}.gguf`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const reader = new rea.ModelHeaderReader(fh, bytes.length);
      // ModelArtifactProvider consumes the 4-byte GGUF magic before GgufHeader.
      const magic = await reader.take(4);
      if (!magic.equals(Buffer.from("GGUF"))) {
        base.status = "error";
        base.errorMessage = `expected GGUF magic, got ${magic.toString("hex")}`;
        return base;
      }
      const header = new rea.GgufHeader(reader);
      const result = await header.read();
      base.metrics = {
        version: result?.version,
        tensorCount: result?.tensors?.length ?? result?.tensor_count,
        metadataCount: result?.metadata?.length,
        limitations: result?.limitations ?? [],
      };
    } finally {
      await fh.close();
    }
  } catch (err) {
    // REA HEAD uses ParseFailureError with failure.limit.name for capacity failures.
    const limitName = err?.failure?.limit?.name ?? err?.limit ?? null;
    const budgetName = limitName === "metadata-nesting" ? "MODEL_METADATA_NESTING"
      : limitName === "representation-bytes" ? "MODEL_REPRESENTATION_BYTES"
      : limitName ? limitName
      : null;
    failOutcome(base, err, budgetName);
  }
  return base;
}

export async function probePtx(_rea, bytes, phase) {
  const base = outcomeBase("gpu_ptx", phase, bytes);
  const text = bytes.toString("utf8");
  const entries = [...text.matchAll(/\.entry\s+(\w+)/g)].map((m) => m[1]);
  base.metrics = {
    entryCount: entries.length,
    textBytes: bytes.length,
    note: "REA GPU object decode needs native tooling for fatbin/SPIR-V; PTX is text-scanned here",
  };
  return base;
}


export async function probeAsar(rea, bytes, phase) {
  const base = outcomeBase("electron_asar", phase, bytes);
  if (typeof rea.admitAsarHeader !== "function") {
    harnessErrorOutcome(base, new Error("admitAsarHeader not loaded (module moved or removed in REA HEAD)"));
    recordHarnessError("electron_asar", "admitAsarHeader not loaded");
    return base;
  }
  const dir = mkdtempSync(join(tmpdir(), "bla-rt-asar-"));
  const path = join(dir, `${phase}.asar`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const extents = await rea.admitAsarHeader(fh);
      base.metrics.headerBytes = extents.headerBytes;
      base.metrics.archiveBytes = extents.archiveBytes;
      base.metrics.jsonBytes = extents.jsonBytes ?? extents.headerBytes - 8;
      // Read JSON header for listing
      const jsonBuf = Buffer.alloc(extents.headerBytes);
      // header layout: 8 byte size pickle + headerBytes pickle payload; JSON starts at 16
      const headerRegion = Buffer.alloc(8 + extents.headerBytes);
      let off = 0;
      while (off < headerRegion.length) {
        const { bytesRead } = await fh.read(
          headerRegion,
          off,
          headerRegion.length - off,
          off,
        );
        if (bytesRead === 0) break;
        off += bytesRead;
      }
      const jsonSize = headerRegion.readUInt32LE(12);
      const json = headerRegion.subarray(16, 16 + jsonSize).toString("utf8");
      const root = JSON.parse(json);
      const listing = await rea.readAsarListing(root);
      base.metrics.listingEntries = listing.length;
      base.metrics.listingPathBytes = listing.reduce(
        (s, e) => s + (e.path?.length ?? 0),
        0,
      );
    } finally {
      await fh.close();
    }
  } catch (err) {
    const msg = String(err?.message ?? err);
    const isHeader =
      /header/i.test(msg) ||
      err?.constructor?.name?.includes("Asar") ||
      /max_header|admission/i.test(msg);
    failOutcome(
      base,
      err,
      isHeader ? "DEFAULT_ASAR_MAX_HEADER_BYTES" : err?.kind ?? "asar",
    );
    if (isHeader || /exceeds its .* representation budget/i.test(msg)) {
      base.budgetHit = true;
      base.budgetName = /listing|representation/i.test(msg)
        ? "ASAR_LISTING_BYTES"
        : "DEFAULT_ASAR_MAX_HEADER_BYTES";
    }
  }
  return base;
}

export async function probeWasm(rea, bla, bytes, phase, sampleMeta = {}) {
  const base = outcomeBase("wasm_module", phase, bytes);
  const wabt = resolveWabtEnv();
  try {
    const valid = WebAssembly.validate(bytes);
    const inspection = bla.inspectWasmBinary(bytes);
    base.metrics = {
      validates: valid,
      sectionCount: inspection.sectionCount,
      customSectionNames: inspection.customSectionNames,
      exportNames: inspection.exportNames,
      exportCount: inspection.exportNames?.length ?? 0,
      importCount: inspection.importCount,
      projectedChargeBytes: sampleMeta.projectedInterfaceChargeBytes ?? null,
      representationBudget: rea.WASM_INTERFACE_REPRESENTATION_BYTES,
      descriptorCount: sampleMeta.interfaceDescriptorsEmbedded ?? null,
      exportDecoysInjected: sampleMeta.exportDecoysInjected ?? null,
      exceedsRepresentationBudget:
        sampleMeta.exceedsRepresentationBudget === true,
      wabtAvailable: wabt.available,
    };

    // Prefer real Wabt E2E when REA_WABT_BIN_DIRECTORY (or ~/opt/wabt-1.0.42) is present.
    if (wabt.available && typeof rea.WabtArtifactProvider === "function") {
      const dir = mkdtempSync(join(tmpdir(), "bla-rt-wabt-"));
      const path = join(dir, `${phase}.wasm`);
      writeFileSync(path, bytes);
      const provider = new rea.WabtArtifactProvider(wabt.env);
      try {
        const result = await provider.inspect({
          path,
          glue_paths: [],
          candidate_paths: [],
        });
        if (!result.ok) {
          const err = result.error;
          const msg = String(err?.userMessage ?? err?.message ?? err);
          const isBudget =
            /representation budget|WABT output|capacity/i.test(msg) ||
            err?.kind === "capacity" ||
            err?.details?.maximum_bytes != null;
          failOutcome(
            base,
            err,
            isBudget ? "WASM_INTERFACE_REPRESENTATION_BYTES" : "WABT",
          );
          if (isBudget) {
            base.budgetHit = true;
            base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
            base.status = "budget_rejected";
          }
          base.metrics.wabtError = msg.slice(0, 240);
          return base;
        }
        const r = result.value.result ?? result.value;
        base.metrics.wabtValidation = r.validation;
        base.metrics.wabtExportForms = r.exports?.length ?? 0;
        base.metrics.wabtWatBytes = r.wat?.text?.length ?? 0;
        base.metrics.wabtInterfaceEntries = r.interface?.entries?.length ?? 0;
        base.metrics.wabtInterfaceState = r.interface?.state ?? null;
        base.metrics.wabtInterfaceIssues = (r.interface?.issues ?? []).slice(0, 2);
        const issues = r.interface?.issues ?? [];
        const tripped = issues.some((i) =>
          /representation budget|Typed WASM interface/i.test(String(i)),
        );
        if (tripped || r.interface?.state === "partial") {
          base.budgetHit = true;
          base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
          base.status = "budget_rejected";
          base.redactionOrAmbiguity =
            issues[0] ??
            "Wabt typed interface inventory partial: representation budget exceeded";
        }
      } finally {
        try {
          await provider.close();
        } catch {
          /* ignore */
        }
      }
      return base;
    }

    // Soft fallback: in-process WasmInterfaceBudget with projected descriptors.
    if (!rea.WasmInterfaceBudget) {
      base.metrics.wabtSkipped =
        "WasmInterfaceBudget not loaded and Wabt not available; WASM budget not empirically verified";
      return base;
    }
    base.metrics.wabtSkipped =
      "REA_WABT_BIN_DIRECTORY / ~/opt/wabt-1.0.42 not available; using projected WasmInterfaceBudget";
    if (phase === "after" && sampleMeta.exceedsRepresentationBudget) {
      const plan = bla.planWasmInterfaceBudgetExhaustion(
        new bla.SeededPrng("bla-redteam-empirical-v1"),
        "bankrupt",
      );
      const budget = new rea.WasmInterfaceBudget();
      let charged = 0;
      for (const d of plan.descriptors) {
        const entry = {
          direction: "export",
          module: null,
          name: d.exportName,
          kind: "func",
          index: 0,
          wat_form: `(export "${d.exportName}" (func 0))`,
          issue: null,
          signature: {
            kind: "func",
            params: Array(d.paramCount).fill("i64"),
            results: Array(d.resultCount).fill("i64"),
          },
        };
        try {
          const cost = rea.wasmInterfaceEntryRepresentationBytes(entry);
          budget.reserve(cost);
          charged += cost;
        } catch (err) {
          base.metrics.chargeWhenTripped = charged;
          failOutcome(base, err, "WASM_INTERFACE_REPRESENTATION_BYTES");
          base.status = "budget_rejected";
          base.budgetHit = true;
          base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
          base.redactionOrAmbiguity =
            "WasmInterfaceBudget refused projected interface inventory (install Wabt for full E2E)";
          return base;
        }
      }
      base.metrics.chargedBytes = charged;
      if (plan.exceedsRepresentationBudget) {
        base.budgetHit = true;
        base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
        base.status = "budget_rejected";
      }
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probeSqlite(rea, bla, bytes, phase) {
  const base = outcomeBase("sqlite_db", phase, bytes);
  if (!bytes.length) {
    base.status = "skipped";
    base.redactionOrAmbiguity = "sqlite sample unavailable (node:sqlite)";
    return base;
  }
  try {
    const inspection = bla.inspectSqliteBuffer(bytes);
    base.metrics.blaHoneyTables = inspection.honeyTablesCount;
    base.metrics.blaTableCount =
      inspection.tableNames?.length ?? inspection.tables?.length;
    base.metrics.blaProtected = inspection.blaProtected === true;
    base.metrics.hasGeneratedTrapColumns =
      inspection.hasGeneratedTrapColumns === true;
  } catch (err) {
    base.metrics.blaInspectError = String(err?.message ?? err).slice(0, 160);
  }

  if (typeof rea.inspectSqliteDatabaseSnapshot !== "function") {
    base.status = "skipped";
    base.redactionOrAmbiguity =
      "REA SqliteDatabaseInspection module not loadable";
    return base;
  }

  // Soft-skip when DatabaseSync.limits is absent (Node < 24.15).
  let hasLimits = false;
  try {
    const { DatabaseSync } = await import("node:sqlite");
    const probeDb = new DatabaseSync(":memory:");
    hasLimits = probeDb.limits != null && typeof probeDb.limits === "object";
    probeDb.close();
  } catch (err) {
    base.status = "capability_gated";
    base.redactionOrAmbiguity = `node:sqlite unavailable: ${String(err?.message ?? err).slice(0, 120)}`;
    return base;
  }
  base.metrics.nodeSqliteLimits = hasLimits;
  base.metrics.nodeVersion = process.version;
  if (!hasLimits) {
    base.status = "capability_gated";
    base.redactionOrAmbiguity =
      "REA SQLite inspection requires Node.js DatabaseSync.limits (24.15+ / 26+); honey/canary evidence recorded via BLA inspect instead";
    return base;
  }

  const dir = mkdtempSync(join(tmpdir(), "bla-rt-sqlite-"));
  const path = join(dir, `${phase}.sqlite`);
  writeFileSync(path, bytes);
  try {
    const result = rea.inspectSqliteDatabaseSnapshot(path, {
      schema: true,
      rows: { limit: 16 },
    });
    const tableNames =
      result?.schema?.tables?.map((t) => t.name) ??
      result?.tables?.map((t) => t.name) ??
      [];
    base.metrics.reaTables = tableNames.length;
    base.metrics.reaTableNames = tableNames.slice(0, 12);
    base.metrics.reaLimitations = (result?.limitations ?? []).slice(0, 3);
    const HONEY = new Set([
      "enclave_key_hierarchy",
      "tpm2_attestation_ledger",
      "zero_trust_session_leases",
      "canary_transport_redaction",
      "system_diagnostic_log",
      "v_enclave_active_topology",
    ]);
    const honeyVisible = tableNames.filter((n) => HONEY.has(String(n)));
    base.metrics.reaHoneyTablesVisible = honeyVisible.length;

    // After hardening: select a honey table with generated trap columns —
    // REA cannot evaluate enclave_unseal_payload() → SqliteColumnEvaluationFailure.
    if (phase === "after" && honeyVisible.length > 0) {
      const honey = "enclave_key_hierarchy";
      try {
        rea.inspectSqliteDatabaseSnapshot(path, {
          schema: true,
          table: honey,
          rows: { limit: 16 },
        });
        base.redactionOrAmbiguity =
          "Honey table row read succeeded unexpectedly (generated trap did not fire)";
      } catch (err) {
        const msg = String(err?.message ?? err);
        const isTrap =
          err?.constructor?.name === "SqliteColumnEvaluationFailure" ||
          /enclave_unseal_payload|cannot evaluate selected column/i.test(msg);
        if (isTrap) {
          base.budgetHit = true;
          base.budgetName = "SqliteColumnEvaluationFailure";
          base.status = "budget_rejected";
          base.redactionOrAmbiguity =
            "REA cannot evaluate BLA generated trap columns (unknown function enclave_unseal_payload); honey schema still disclosed";
          base.errorName = err?.constructor?.name ?? "SqliteColumnEvaluationFailure";
          base.errorMessage = msg.slice(0, 240);
          base.metrics.trapColumnFailure = true;
        } else {
          failOutcome(base, err);
        }
      }
    }
  } catch (err) {
    const msg = String(err?.message ?? err);
    if (/DatabaseSync\.limits|24\.15|unavailable/i.test(msg)) {
      base.status = "capability_gated";
      base.redactionOrAmbiguity =
        "REA SQLite inspection requires Node.js 24.15+ / 26+ DatabaseSync.limits; honey/canary evidence recorded via BLA inspect instead";
      base.errorName = err?.constructor?.name ?? "SqliteInspectionFailure";
      base.errorMessage = msg.slice(0, 240);
    } else if (/16 MiB|output-limit|reply budget/i.test(msg)) {
      failOutcome(base, err, "SQLITE_DATABASE_LIMITS.outputBytes");
      base.budgetHit = true;
      base.budgetName = "SQLITE_DATABASE_LIMITS.outputBytes";
      base.status = "budget_rejected";
    } else {
      failOutcome(base, err);
    }
  }
  return base;
}

export async function probeElectronFuses(rea, bytes, phase) {
  const base = outcomeBase("electron_fuses", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "bla-rt-fuse-"));
  const path = join(dir, `${phase}.elf`);
  writeFileSync(path, bytes);
  try {
    const image = await rea.readElectronFuseImage(path);
    base.metrics.sentinelCount = image?.sentinels?.length ?? image?.sentinel_count;
    base.metrics.sliceCount = image?.slices?.length;
  } catch (err) {
    const msg = String(err?.message ?? err);
    const isCap =
      err?.constructor?.name === "ElectronFuseResourceFailure" ||
      /more than \d+ Electron fuse sentinels/i.test(msg) ||
      err?.capacity === "capacity" ||
      /capacity/i.test(String(err?.boundary ?? err?.kind ?? ""));
    failOutcome(
      base,
      err,
      isCap ? "ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice" : null,
    );
    if (isCap) {
      base.budgetHit = true;
      base.budgetName = "ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice";
      base.status = "budget_rejected";
    }
  }
  return base;
}

/** Synchronously drive a step generator to completion. */
function completeStepsSync(gen) {
  for (;;) {
    const r = gen.next();
    if (r.done) return r.value;
  }
}

export async function probeJavascript(rea, bytes, phase) {
  const base = outcomeBase("javascript", phase, bytes);
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);

  // Check that the required REA JS analysis functions are available.
  if (typeof rea.parseJavaScriptSource !== "function") {
    harnessErrorOutcome(base, new Error(
      "parseJavaScriptSource not loaded (REA module unavailable or renamed)",
    ));
    recordHarnessError("javascript", "parseJavaScriptSource unavailable");
    return base;
  }
  if (typeof rea.analyzeParsedJavaScriptStaticSourceSteps !== "function") {
    harnessErrorOutcome(base, new Error(
      "analyzeParsedJavaScriptStaticSourceSteps not loaded (REA module unavailable or renamed)",
    ));
    recordHarnessError("javascript", "analyzeParsedJavaScriptStaticSourceSteps unavailable");
    return base;
  }

  try {
    // 1. Parse (the way REA's application layer does it).
    const parsed = rea.parseJavaScriptSource(text);

    // 2. Static analysis via step generator (REA's real analysis path).
    const st = completeStepsSync(
      rea.analyzeParsedJavaScriptStaticSourceSteps(text, parsed),
    );

    // 3. Semantic analysis via convenience wrapper (still exists in REA HEAD).
    let sem = null;
    if (typeof rea.analyzeJavaScriptSemantics === "function") {
      sem = rea.analyzeJavaScriptSemantics(text);
    }

    const staticLimits =
      st?.analysis_coverage?.examination?.semantic_resource_limits ?? [];
    const semLimits = sem?.coverage?.resourceLimits ?? [];
    const allLimits = [...new Set([...staticLimits, ...semLimits])];

    base.metrics.parseStatus = st?.parse_status;
    base.metrics.parseErrorCount = st?.parse_error_count ?? 0;
    base.metrics.visitedAstNodes = st?.visited_ast_nodes ?? 0;
    base.metrics.staticCoverage = st?.analysis_coverage?.examination?.status;
    base.metrics.staticLimits = staticLimits;
    base.metrics.semCoverage = sem?.coverage?.status;
    base.metrics.semOmittedCount = sem?.coverage?.omittedCount ?? 0;
    base.metrics.semLimits = semLimits;
    base.metrics.semanticResourceLimits = allLimits;
    base.metrics.unknownFindings =
      st?.analysis_coverage?.semantics?.unknown_findings ?? 0;
    base.metrics.referenceCount = st?.references?.length ?? 0;
    base.metrics.endpointCount = st?.endpoints?.length ?? 0;
    base.metrics.routeCount = st?.routes?.length ?? 0;
    base.metrics.semBindingCount = sem?.bindings?.length ?? 0;
    base.metrics.semCallableCount = sem?.callables?.length ?? 0;
    base.metrics.semReferenceCount = sem?.references?.length ?? 0;
    base.metrics.semExpressionFlowsTruncated =
      sem?.expressionFlowsTruncated ?? false;
    base.metrics.limitations = [
      ...(st?.limitations ?? []).slice(0, 3),
      ...(sem?.limitations ?? []).slice(0, 3),
    ];

    if (phase === "after" && allLimits.length > 0) {
      base.budgetHit = true;
      base.budgetName = allLimits.join("+");
      base.status = "budget_rejected";
      base.redactionOrAmbiguity =
        `REA JS semantic analysis degraded: resourceLimits=[${allLimits.join(", ")}] (real REA exceptions, not simulation)`;
    } else if (
      phase === "after" &&
      (st?.parse_status === "partial" ||
        sem?.coverage?.status === "partial")
    ) {
      base.budgetHit = true;
      base.budgetName = "javascript-semantic-partial";
      base.status = "budget_rejected";
      base.redactionOrAmbiguity =
        "REA JS analysis returned partial coverage without explicit resourceLimits";
    }
  } catch (err) {
    // Distinguish between harness errors and REA-reported errors.
    const name = err?.constructor?.name ?? "Error";
    if (name === "TypeError" || name === "ReferenceError") {
      harnessErrorOutcome(base, err);
      recordHarnessError("javascript", String(err?.message ?? err).slice(0, 160));
    } else {
      failOutcome(base, err);
    }
  }
  return base;
}

/** Every `semantic_precision` budget is multiplied by each of these in turn. */
const JS_STRING_BUDGET_MULTIPLIERS = [1, 4, 64];

/**
 * How REA's result holds `value`: 0 when it is nowhere in it, 1 when REA
 * resolved it exactly, n when it is one of n candidates REA lists for a
 * binding (it enumerates every combination of pieces once the budget allows).
 */
function candidateSetSize(result, value) {
  let best = 0;
  const visit = (node, siblings) => {
    if (typeof node === "string") {
      if (node === value) {
        const size = siblings ?? 1;
        best = best === 0 ? size : Math.min(best, size);
      }
      return;
    }
    if (node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) visit(item, node.length);
      return;
    }
    for (const child of Object.values(node)) visit(child, null);
  };
  visit(result, null);
  return best;
}

/**
 * What REA's semantic analysis recovers of known string values — at its
 * default budgets, and again with every budget raised. REA's budgets are
 * per-call inputs: a sample that only trips the defaults is read by whoever
 * raises them, so both are measured.
 */
export async function probeJavascriptStrings(rea, bytes, phase, values) {
  const base = outcomeBase("javascript_strings", phase, bytes);
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
  const defaults = rea.JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS;
  if (typeof rea.analyzeJavaScriptSemantics !== "function" || !defaults) {
    harnessErrorOutcome(
      base,
      new Error(
        "analyzeJavaScriptSemantics / JAVASCRIPT_SEMANTIC_PRECISION_DEFAULTS not loaded (REA module unavailable or renamed)",
      ),
    );
    recordHarnessError("javascript_strings", "REA semantic analysis or its precision defaults unavailable");
    return base;
  }
  const names = Object.keys(values);
  const runs = [];
  try {
    for (const multiplier of JS_STRING_BUDGET_MULTIPLIERS) {
      const precision =
        multiplier === 1
          ? undefined
          : {
              primitive_candidates: defaults.primitive_candidates * multiplier,
              primitive_bytes: defaults.primitive_bytes * multiplier,
              getter_expansions: defaults.getter_expansions * multiplier,
              alias_selections: defaults.alias_selections * multiplier,
            };
      const started = performance.now();
      const result = rea.analyzeJavaScriptSemantics(text, precision);
      const ms = Math.round(performance.now() - started);
      const recovered = {};
      for (const name of names) recovered[name] = candidateSetSize(result, values[name]);
      runs.push({
        budgetMultiplier: multiplier,
        ms,
        coverage: result?.coverage?.status ?? null,
        limits: result?.coverage?.resourceLimits ?? [],
        recovered,
      });
    }
  } catch (err) {
    const name = err?.constructor?.name ?? "Error";
    if (name === "TypeError" || name === "ReferenceError") {
      harnessErrorOutcome(base, err);
      recordHarnessError("javascript_strings", String(err?.message ?? err).slice(0, 160));
    } else {
      failOutcome(base, err);
    }
    return base;
  }
  const hidden = (run) => names.every((name) => run.recovered[name] === 0);
  base.metrics.budgetRuns = runs;
  base.metrics.valuesHiddenAtDefaultBudgets = hidden(runs[0]);
  base.metrics.valuesHiddenAtRaisedBudgets = runs.slice(1).every(hidden);
  if (phase === "after") {
    if (hidden(runs[0]) && runs[0].limits.length > 0) {
      base.budgetHit = true;
      base.budgetName = runs[0].limits.join("+");
      base.status = "budget_rejected";
    }
    const worst = runs.find((run) => !hidden(run));
    base.redactionOrAmbiguity =
      worst === undefined
        ? `none of ${names.length} known values is in REA's result at ${runs.map((r) => `${r.budgetMultiplier}x`).join(" / ")} budgets`
        : `REA holds ${names.filter((n) => worst.recovered[n] > 0).join(", ")} at ${worst.budgetMultiplier}x budgets (${names.map((n) => `${n}: ${worst.recovered[n] === 0 ? "absent" : worst.recovered[n] === 1 ? "exact" : `1 of ${worst.recovered[n]}`}`).join(", ")})`;
  }
  return base;
}

/** Catalog of analyzers that cannot run empirically on this box. */
export function unverifiedAnalyzers() {
  const list = [
    {
      analyzer: "Ghidra / Hopper native decompile",
      reason: "requires Ghidra/Hopper install (not available without root/GUI)",
    },
    {
      analyzer: "Frida dynamic instrumentation",
      reason: "requires frida-tools + attachable target process",
    },
    {
      analyzer: "LLDB / GDB native tracing",
      reason: "requires lldb/gdb + debuggee; not installed here",
    },
    {
      analyzer: "Rizin / Cutter",
      reason: "requires rizin binary",
    },
    {
      analyzer: "JADX Android decompile",
      reason: "requires JADX JVM tooling",
    },
    {
      analyzer: "EVM EVMole worker full interface recovery",
      reason:
        "Not pathable in-process: EvmoleInterfaceWorker refuses library import ('Owned worker request path missing') and only runs under REA's owned subprocess launcher (prlimit address-space/CPU/file-size, 256 MiB heap, IPC reply schema). The evmole npm package exists in the REA tree but cannot be driven without that ownership harness. inputBytes admission is checked in-process via probeEvm against EVM_PRODUCER_LIMIT_DEFAULTS.",
    },
    {
      analyzer: "WASM Wabt full WAT decode (wasm-objdump / wasm2wat)",
      reason: resolveWabtEnv().available
        ? "AVAILABLE this run — probeWasm drives WabtArtifactProvider end-to-end"
        : "Requires REA_WABT_BIN_DIRECTORY with WABT 1.0.42 (e.g. ~/opt/wabt-1.0.42/bin). Soft-skips to projected WasmInterfaceBudget when absent.",
    },
    {
      analyzer: "SQLite inspect_sqlite_database (DatabaseSync.limits)",
      reason:
        "Requires Node.js DatabaseSync.limits (24.15+ / 26+). Soft-skips as capability_gated on Node 22; under Node 24 probeSqlite records honey disclosure + SqliteColumnEvaluationFailure on generated trap columns.",
    },
    {
      analyzer: "SPIR-V / CUDA fatbinary / AMD GPU object",
      reason:
        "BLA skips these formats (GPU_OBJECT_HARDENING_SKIP_REASON); no shield to validate",
    },
    {
      analyzer: "Firmware analysis",
      reason:
        "BLA skips firmware (FIRMWARE_HARDENING_SKIP_REASON); needs vendor parsers",
    },
  ];
  // Append any harness-error probes that could not run.
  for (const he of harnessErrors()) {
    list.push({
      analyzer: `${he.format} (harness_error)`,
      reason: he.reason,
    });
  }
  return list;
}
