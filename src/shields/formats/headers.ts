import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";

export type NativeHeaderLanguage = "c" | "rust" | "go";

/**
 * Issue #40 template hygiene: derive a per-decoy odd 32-bit mixing constant from
 * the project PRNG so the emitted native tarpit never ships the classic
 * `0x9e3779b9` golden-ratio probe bit-identically. Odd constants keep the
 * 32-bit multiply a bijection (full avalanche) just like the original value.
 */
function deriveMixConstant(prng: SeededPrng): number {
  let mix = (prng.nextUint32() | 1) >>> 0;
  if (mix === 0x9e3779b9 || mix === 2654435769) mix = (mix ^ 2) >>> 0;
  return mix >>> 0;
}

export interface EmittedNativeHeader {
  readonly language: NativeHeaderLanguage;
  readonly filename: string;
  readonly content: string;
  readonly decoyFunctionsCount: number;
  readonly chaffPayloadsCount: number;
}

/**
 * Generates compile-time C/C++ (`bla_shield.h`), Rust (`bla_shield.rs`), and Go (`bla_shield.go`)
 * adversarial defense headers that compile directly into native binaries so Ghidra, Hopper,
 * IDA Pro, Kuna, and `rea` native analyzers encounter:
 * 1. `__attribute__((used, noinline))` decoy tarpit functions with dense cross-references
 * 2. Read-only architectural chaff strings in `.rodata` / `__TEXT,__cstring`
 * 3. >64 distinct `/rustc/<40-hex>/` strings to trip REA's `MAX_RUSTC_HASHES` capacity gate
 */
export function emitCompileTimeNativeHeader(
  language: NativeHeaderLanguage,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): EmittedNativeHeader {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? `bla-header-${language}-v1`);
  const chaffPayloads = generateChaffPayloads(prng, intensity);
  const decoyCount = intensity === "stealth" ? 6 : intensity === "balanced" ? 12 : 20;

  if (language === "c") {
    const rustcAnchorStem = "rustc_path_anchor";
    const shadowHeapName = "shadow_heap_slots";
    const tarpitStem = "enclave_tarpit_fn";
    const dataTableCount = chaffPayloads.length * 2 + 1;
    const lines: string[] = [
      "/* ==========================================================================",
      " * BLA-SHIELD: Adversarial Defense Header for C/C++ Native Binaries",
      " * Compatible with GCC (__GNUC__), Clang (__clang__), and MSVC (_MSC_VER / cl.exe)",
      " * Counter-REA Native Decompilation Tarpit & Read-Only Section Shield",
      " * ========================================================================== */",
      "#ifndef BLA_SHIELD_H",
      "#define BLA_SHIELD_H",
      "#include <stdint.h>",
      "#include <stddef.h>",
      "",
      "#ifdef __cplusplus",
      'extern "C" {',
      "#endif",
      "",
      "#if defined(_MSC_VER) && !defined(__clang__)",
      "#pragma warning(push)",
      "#pragma warning(disable: 4100 4127 4189 4505)",
      "#define BLA_USED",
      "#define BLA_NOINLINE __declspec(noinline)",
      "#elif defined(__GNUC__) || defined(__clang__)",
      "#define BLA_USED __attribute__((used))",
      "#define BLA_NOINLINE __attribute__((used, noinline))",
      "#else",
      "#define BLA_USED",
      "#define BLA_NOINLINE",
      "#endif",
      "",
      "/* Architectural Chaff & Enclave Delegation Manifests */",
    ];

    const dataTableEntries: string[] = [];
    chaffPayloads.forEach((p, idx) => {
      lines.push(
        `static const char ${p.symbolName}[] BLA_USED = ${JSON.stringify(p.rawText)};`,
      );
      dataTableEntries.push(`(const void*)${p.symbolName}`);
      const hash = idx.toString(16).padStart(8, "0") + prng.hex(32);
      lines.push(
        `static const char ${rustcAnchorStem}_${idx}[] BLA_USED = "/rustc/${hash}/library/core/src/enclave.rs";`,
      );
      dataTableEntries.push(`(const void*)${rustcAnchorStem}_${idx}`);
    });

    // Mutable .data shadow heap slots to defeat GDB/Rizin/Frida/WinDbg before/after memory diffing
    const slotInit = Array.from(
      { length: 32 },
      () => `0x${prng.hex(8)}u`,
    ).join(", ");
    lines.push(
      `static volatile uint32_t ${shadowHeapName}[32] BLA_USED = { ${slotInit} };`,
    );
    dataTableEntries.push(`(const void*)${shadowHeapName}`);
    lines.push("");

    // Forward declarations for mutual cross-references (Fake XRefs in Ghidra/IDA)
    for (let i = 0; i < decoyCount; i++) {
      lines.push(`BLA_NOINLINE static uint32_t ${tarpitStem}_${i}(uint32_t seed, int depth);`);
    }
    lines.push("");

    // Keep-tables prevent MSVC (/O2 /GL + link.exe /OPT:REF), Clang, and GCC from stripping static symbols
    lines.push(`typedef uint32_t (*enclave_tarpit_fn_t)(uint32_t, int);`);
    lines.push(
      `static const void* const enclave_keep_data_table[${dataTableCount}] BLA_USED = { ${dataTableEntries.join(", ")} };`,
    );
    const fnTableEntries = Array.from(
      { length: decoyCount },
      (_, i) => `&${tarpitStem}_${i}`,
    ).join(", ");
    lines.push(
      `static const enclave_tarpit_fn_t enclave_keep_fn_table[${decoyCount}] BLA_USED = { ${fnTableEntries} };`,
    );
    lines.push("");

    for (let i = 0; i < decoyCount; i++) {
      const next1 = (i + 1) % decoyCount;
      const next2 = (i + 3) % decoyCount;
      const k = prng.nextInt(0x1000, 0xffff);
      const mix = deriveMixConstant(prng);
      const chaffSym = chaffPayloads[i % chaffPayloads.length]!.symbolName;
      lines.push(`BLA_NOINLINE static uint32_t ${tarpitStem}_${i}(uint32_t seed, int depth) {`);
      lines.push(`    const char* _anchor_str = (const char*)enclave_keep_data_table[(seed + ${i}u) % ${dataTableCount}u];`);
      lines.push(`    uint32_t acc = seed ^ 0x${k.toString(16)}u ^ (uint32_t)(unsigned char)${chaffSym}[0] ^ (uint32_t)(unsigned char)_anchor_str[0];`);
      lines.push(`    for (int r = 0; r < 4; ++r) {`);
      lines.push(`        acc = (acc * 0x${mix.toString(16)}u) ^ (acc >> 13) ^ (uint32_t)r;`);
      lines.push(`        ${shadowHeapName}[(${i} * 4 + r) & 31] ^= acc;`);
      lines.push(`    }`);
      lines.push(`    if (depth > 0 && ((7u * (seed | 3u) * (seed | 3u) - 1u) == (seed ^ 5u) * (seed ^ 5u))) {`);
      lines.push(`        enclave_tarpit_fn_t _fn_ptr = enclave_keep_fn_table[(seed ^ (uint32_t)depth) % ${decoyCount}u];`);
      lines.push(`        return ${tarpitStem}_${next1}(acc, depth - 1) ^ ${tarpitStem}_${next2}(acc ^ 0x5Au, depth - 1) ^ _fn_ptr(acc, depth - 1);`);
      lines.push(`    }`);
      lines.push(`    return acc;`);
      lines.push(`}`);
    }

    lines.push("");
    lines.push(`#define BLA_SHIELD_ANCHOR(x) (${tarpitStem}_0((uint32_t)(x), 0))`);
    lines.push("");
    lines.push("#if defined(_MSC_VER) && !defined(__clang__)", "#pragma warning(pop)", "#endif");
    lines.push("#ifdef __cplusplus", "}", "#endif");
    lines.push("#endif /* BLA_SHIELD_H */");
    return {
      language: "c",
      filename: "bla_shield.h",
      content: lines.join("\n") + "\n",
      decoyFunctionsCount: decoyCount,
      chaffPayloadsCount: chaffPayloads.length,
    };
  }

  if (language === "rust") {
    const lines: string[] = [
      "// ==========================================================================",
      "// BLA-SHIELD: Adversarial Defense Module for Rust Native Binaries",
      "// Counter-REA Native Decompilation Tarpit & Rust Hash Capacity Shield",
      "// ==========================================================================",
      "#![allow(dead_code, non_upper_case_globals)]",
      "",
    ];

    chaffPayloads.forEach((p) => {
      lines.push(`#[used]`);
      lines.push(
        `pub static ${p.symbolName.toUpperCase()}: &[u8] = ${JSON.stringify(p.rawText)}.as_bytes();`,
      );
    });

    // Inject 66 `/rustc/<40-hex>/` strings to trip REA's MAX_RUSTC_HASHES = 64 limit
    lines.push(`#[used]`);
    const rustcStrings = Array.from({ length: 66 }, (_, i) => {
      const h = i.toString(16).padStart(8, "0") + prng.hex(32);
      return `/rustc/${h}/library/core/src/enclave.rs`;
    }).join("\\0");
    lines.push(`pub static BLA_RUSTC_OVERFLOW_TABLE: &[u8] = b"${rustcStrings}";`);
    lines.push("");

    for (let i = 0; i < decoyCount; i++) {
      const next1 = (i + 1) % decoyCount;
      const next2 = (i + 2) % decoyCount;
      const k = prng.nextInt(0x1000, 0xffff);
      const mix = deriveMixConstant(prng);
      lines.push(`#[inline(never)]`);
      lines.push(`pub fn enclave_tarpit_${i}(seed: u32, depth: u32) -> u32 {`);
      lines.push(`    let mut acc = seed ^ 0x${k.toString(16)};`);
      lines.push(`    for r in 0..4u32 {`);
      lines.push(`        acc = acc.wrapping_mul(0x${mix.toString(16)}) ^ (acc >> 13) ^ r;`);
      lines.push(`    }`);
      lines.push(`    if depth > 0 && ((seed | 1).wrapping_mul(seed | 2) & 1) == 1 {`);
      lines.push(`        return enclave_tarpit_${next1}(acc, depth - 1) ^ enclave_tarpit_${next2}(acc ^ 0x5A, depth - 1);`);
      lines.push(`    }`);
      lines.push(`    std::hint::black_box(acc)`);
      lines.push(`}`);
    }

    return {
      language: "rust",
      filename: "bla_shield.rs",
      content: lines.join("\n") + "\n",
      decoyFunctionsCount: decoyCount,
      chaffPayloadsCount: chaffPayloads.length,
    };
  }

  // Go (`bla_shield.go`)
  const goSlots = Array.from({ length: 16 }, () => `0x${prng.hex(8)}`).join(", ");
  const lines: string[] = [
    "// Code generated by BLA-SHIELD. DO NOT EDIT.",
    "package main",
    "",
    `var ShadowHeapSlots = [16]uint32{${goSlots}}`,
    "",
    "var EnclaveManifests = []string{",
  ];
  for (const p of chaffPayloads) {
    lines.push(`\t${JSON.stringify(p.rawText)},`);
  }
  lines.push("}");
  lines.push("");

  for (let i = 0; i < decoyCount; i++) {
    const next1 = (i + 1) % decoyCount;
    const next2 = (i + 2) % decoyCount;
    const k = prng.nextInt(0x1000, 0xffff);
    const mix = deriveMixConstant(prng);
    lines.push(`//go:noinline`);
    lines.push(`func EnclaveTarpit${i}(seed uint32, depth int) uint32 {`);
    lines.push(`\tacc := seed ^ 0x${k.toString(16)} ^ uint32(len(EnclaveManifests[0]))`);
    lines.push(`\tfor r := uint32(0); r < 4; r++ {`);
    lines.push(`\t\tacc = (acc * 0x${mix.toString(16)}) ^ (acc >> 13) ^ r`);
    lines.push(`\t\tShadowHeapSlots[(${i}*4+int(r))&15] ^= acc`);
    lines.push(`\t}`);
    lines.push(`\tif depth > 0 && (((seed|1)*((seed|1)+1))&1) == 1 {`);
    lines.push(`\t\treturn EnclaveTarpit${next1}(acc, depth-1) ^ EnclaveTarpit${next2}(acc^0x5A, depth-1)`);
    lines.push(`\t}`);
    lines.push(`\treturn acc`);
    lines.push(`}`);
  }

  return {
    language: "go",
    filename: "bla_shield.go",
    content: lines.join("\n") + "\n",
    decoyFunctionsCount: decoyCount,
    chaffPayloadsCount: chaffPayloads.length,
  };
}
