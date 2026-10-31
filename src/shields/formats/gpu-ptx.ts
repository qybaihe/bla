import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface GpuPtxInspection {
  readonly looksLikePtx: boolean;
  readonly entryCount: number;
  readonly blaProtected: boolean;
}

export function inspectGpuPtx(text: string): GpuPtxInspection {
  const looksLikePtx =
    /\.version\s+\d/.test(text) &&
    (/\.entry\s+\w/.test(text) || /\.target\s+sm_/.test(text));
  const entryCount = (text.match(/\.entry\s+/g) ?? []).length;
  return {
    looksLikePtx,
    entryCount,
    blaProtected: text.includes("[BLA-PTX-SHIELD]"),
  };
}

/**
 * Protects NVIDIA PTX text modules by appending decoy `.entry` kernels and
 * canary/diagnostic comments. Preserves the original module body verbatim so
 * existing kernels stay byte-identical (runtime-equivalent).
 *
 * SPIR-V / fatbinary / CUDA object mutation is intentionally NOT attempted —
 * those containers have brittle structural hashes; corrupting them would violate
 * the red line. Firmware images are likewise skipped (see module doc below).
 */
export function protectGpuPtxText(
  input: string,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string;
  } = {},
): {
  readonly text: string;
  readonly entriesInjected: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-ptx-shield");
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const base =
    input.trim().length > 0
      ? input.replace(/\s*$/, "\n")
      : `.version 7.5\n.target sm_70\n.address_size 64\n\n`;

  const entryTarget =
    intensity === "bankrupt" ? 128 : intensity === "maximum" ? 48 : 16;

  const parts: string[] = [
    base,
    `\n// [BLA-PTX-SHIELD] Counter-REA GPU exhaustion trailer\n`,
  ];
  for (const rec of deception.textRecords.slice(0, 8)) {
    parts.push(`// DIAG: ${rec.replace(/\n/g, " ")}\n`);
  }
  for (let i = 0; i < entryTarget; i++) {
    const name = `bla_tarpit_kernel_${i}_${prng.hex(4)}`;
    parts.push(
      `.visible .entry ${name}(.param .u64 ${name}_param_0)\n`,
      `{\n`,
      `  .reg .b64 %rd<2>;\n`,
      `  ld.param.u64 %rd1, [${name}_param_0];\n`,
      `  // canary=${prng.hex(8)}\n`,
      `  ret;\n`,
      `}\n\n`,
    );
  }

  return {
    text: parts.join(""),
    entriesInjected: entryTarget,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}

/**
 * Generic firmware images (raw flash dumps, U-Boot ITB, Android boot.img,
 * DfuSe with trailing CRC, signed ESP images, etc.) are NOT mutated by BLA:
 * boot signatures / CRCs / vendor headers would break. Microsoft UF2 is the
 * exception — see `firmware-uf2.ts` — because not-main-flash / file-container
 * blocks are ignored by bootloaders by spec (REA #8230).
 */
export const FIRMWARE_HARDENING_SKIP_REASON =
  "Generic firmware images are skipped (boot signatures/CRCs/vendor headers). UF2 is hardened separately via not-main-flash/file-container decoys (firmware-uf2).";

/**
 * SPIR-V modules, CUDA fatbinaries, and AMD GPU code objects are skipped:
 * their containers carry structural hashes / embedded ELF slices where a
 * generic trailer would break loader validation. PTX text remains the only
 * safely append-only GPU surface BLA hardens.
 */
export const GPU_OBJECT_HARDENING_SKIP_REASON =
  "SPIR-V / CUDA fatbinary / AMD GPU objects are skipped: brittle structural hashes and embedded ELF slices make generic mutation unsafe. Only PTX text is hardened.";
