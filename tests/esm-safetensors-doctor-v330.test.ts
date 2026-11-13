import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyDefenseScoreHonesty } from "../src/engine/defense-score-honesty.js";
import { hardenProject } from "../src/engine/harden.js";
import { protectTarget } from "../src/engine/protector.js";
import { runDoctor } from "../src/setup/doctor.js";
import {
  buildSafetensorsBuffer,
  validateSafetensorsBuffer,
} from "../src/shields/formats/model.js";
import {
  bindSafetensorsSidecarEntanglement,
  extractSafetensorsSidecarMetadataNote,
  SAFETENSORS_SIDECAR_METADATA_KEY,
  SAFETENSORS_SIDECAR_METADATA_KIND,
  SIDECAR_ENTANGLE_SCHEMA,
  stripSafetensorsSidecarMetadataNote,
  verifySafetensorsSidecarMetadataNote,
} from "../src/shields/runtime/sidecar-entangle.js";

const dirs: string[] = [];
function makeDir(prefix: string): string {
  const d = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function minimalSafetensors(): { buf: Buffer; weights: Buffer } {
  const weights = Buffer.alloc(16);
  [1.5, -2.25, 3.75, 8.0].forEach((v, idx) => weights.writeFloatLE(v, idx * 4));
  const buf = buildSafetensorsBuffer(
    {
      weight: {
        dtype: "F32",
        shape: [2, 2],
        data_offsets: [0, 16],
      },
    },
    weights,
  );
  return { buf, weights };
}

describe("v3.3.0 Reinforcements: ESM self-seal + sidecar entangle, Safetensors sidecar note, honesty & doctor parity", () => {
  it("hardens a multi-artifact ES module project with --self-seal + --sidecar-entangle: intact runs, self-edit or sibling delete hard-fails", () => {
    const proj = makeDir("bla-esm-harden-");
    writeFileSync(join(proj, "package.json"), JSON.stringify({ type: "module" }) + "\n", "utf8");
    writeFileSync(
      join(proj, "entry.mjs"),
      [
        'export function computeQuote(units) {',
        '  return `QUOTE:${units * 15}`;',
        '}',
        'if (process.argv[2] === "run") {',
        '  console.log(computeQuote(4));',
        '}',
      ].join("\n") + "\n",
      "utf8",
    );
    writeFileSync(
      join(proj, "policy.py"),
      "def tier_rate(level: int) -> int:\n    return level * 10 + 3\n",
      "utf8",
    );

    const report = hardenProject({
      directory: proj,
      intensity: "bankrupt",
      seed: "esm-full-entangle-v330",
      selfSeal: true,
      sidecarEntangle: true,
      weaveDecoys: true,
    });

    expect(report.overallSuccess).toBe(true);
    expect(report.integrityCoverageSelfVerified).toBe(true);

    const outEntry = join(report.outputDirectory, "entry.mjs");
    const outPy = join(report.outputDirectory, "policy.py");
    expect(existsSync(outEntry)).toBe(true);
    expect(existsSync(outPy)).toBe(true);

    // Intact ESM bundle executes cleanly
    const intact = spawnSync(process.execPath, [outEntry, "run"], { encoding: "utf8" });
    expect(intact.status, intact.stderr).toBe(0);
    expect(intact.stdout).toContain("QUOTE:60");

    // Mutating entry.mjs itself triggers ESM self-seal hard-fail
    const origEntryText = readFileSync(outEntry, "utf8");
    writeFileSync(outEntry, origEntryText + "\n// unauthorized edit\n", "utf8");
    const selfTampered = spawnSync(process.execPath, [outEntry, "run"], { encoding: "utf8" });
    expect(selfTampered.status).not.toBe(0);
    expect(selfTampered.stderr).toMatch(/integrity/i);

    // Restore entry.mjs, delete sibling policy.py -> sidecarEntangle / self-seal hard-fails
    writeFileSync(outEntry, origEntryText, "utf8");
    rmSync(outPy);
    const sibDeleted = spawnSync(process.execPath, [outEntry, "run"], { encoding: "utf8" });
    expect(sibDeleted.status).not.toBe(0);
    expect(sibDeleted.stderr).toMatch(/integrity/i);
  });

  it("binds Safetensors __metadata__ sidecar note while keeping tensor bytes bit-exact", () => {
    const dir = makeDir("bla-safetensors-sidecar-");
    const { buf, weights } = minimalSafetensors();
    const modelIn = join(dir, "weights.safetensors");
    const modelOut = join(dir, "weights.hardened.safetensors");
    const sidecarPath = join(dir, "tokenizer-note.json");
    writeFileSync(modelIn, buf);
    writeFileSync(sidecarPath, '{"vocab":32000}\n', "utf8");

    const res = protectTarget({
      inputPath: modelIn,
      outputPath: modelOut,
      intensity: "balanced",
      seed: "st-sidecar-v330",
      sidecarEntangle: true,
      sidecarEntanglePaths: ["tokenizer-note.json"],
    });
    expect(res.sidecarEntangle).toBe(true);
    // Host-verify only: must not overclaim process-start strip⇒fail vector
    expect(res.counteredReaVectors).not.toContain("safetensors-sidecar-entangle");

    const outBytes = readFileSync(modelOut);
    const parsed = validateSafetensorsBuffer(outBytes);
    expect(parsed.tensorData.equals(weights)).toBe(true);

    const note = extractSafetensorsSidecarMetadataNote(outBytes);
    expect(note).not.toBeNull();
    expect(note?.schema).toBe(SIDECAR_ENTANGLE_SCHEMA);
    expect(note?.kind).toBe(SAFETENSORS_SIDECAR_METADATA_KIND);

    const okVerify = verifySafetensorsSidecarMetadataNote({
      entryBytes: outBytes,
      baseDir: dir,
    });
    expect(okVerify.ok).toBe(true);

    // Tampering with sidecar fails host verification
    writeFileSync(sidecarPath, '{"vocab":0}\n', "utf8");
    const tamperedVerify = verifySafetensorsSidecarMetadataNote({
      entryBytes: outBytes,
      baseDir: dir,
    });
    expect(tamperedVerify.ok).toBe(false);
    expect(tamperedVerify.reason).toMatch(/mismatch/);

    // Stripping note restores clean verification failure while preserving tensors
    const stripped = stripSafetensorsSidecarMetadataNote(outBytes);
    expect(extractSafetensorsSidecarMetadataNote(stripped)).toBeNull();
    expect(validateSafetensorsBuffer(stripped).tensorData.equals(weights)).toBe(true);

    // Direct bind helper check
    const direct = bindSafetensorsSidecarEntanglement({
      entryPath: "m.safetensors",
      sidecarPaths: ["s.bin"],
      seedTag: "direct-st",
      entryBytes: buf,
      sidecarBytes: [Buffer.from("abc")],
    });
    expect(direct.inject.metadataKey).toBe(SAFETENSORS_SIDECAR_METADATA_KEY);
  });

  it("annotates Safetensors and WASM host-verify-only sidecar notes in defenseScore honesty", () => {
    const stOff = applyDefenseScoreHonesty(99, {
      detectedFormat: "model-safetensors",
      sidecarEntangleEnabled: false,
    });
    expect(stOff.gaps.map((g) => g.id)).toContain("sidecar-entangle-not-enabled");
    expect(stOff.cappedScore).toBe(93);

    const stOn = applyDefenseScoreHonesty(99, {
      detectedFormat: "model-safetensors",
      sidecarEntangleEnabled: true,
    });
    expect(stOn.gaps.map((g) => g.id)).toContain("safetensors-sidecar-host-verify-only");
    expect(stOn.cappedScore).toBe(93);

    const wasmOn = applyDefenseScoreHonesty(99, {
      detectedFormat: "wasm",
      wasmExportRenameApplied: true,
      sidecarEntangleEnabled: true,
    });
    expect(wasmOn.gaps.map((g) => g.id)).toContain("wasm-sidecar-host-verify-only");
    expect(wasmOn.cappedScore).toBe(93);
  });

  it("reports AI model, Erlang BEAM, EVM bytecode, and Android DEX/R8 shield subsystems in bla doctor", () => {
    const home = makeDir("bla-doctor-subsystems-");
    const diag = runDoctor({ homeDir: home });
    expect(diag.engines.aiModelShield).toBe("ready");
    expect(diag.engines.erlangBeamShield).toBe("ready");
    expect(diag.engines.evmBytecodeShield).toBe("ready");
    expect(diag.engines.androidDexR8Shield).toBe("ready");
    expect(diag.healthy).toBe(true);
  });
});
