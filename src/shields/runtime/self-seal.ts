/**
 * Opt-in self-seal / self-integrity helper (issue #40.5 + Direction-3).
 *
 * Generates a Node-oriented JS preamble that binds a runtime digest to:
 *   1. SHA-256 of the current module bytes (when fs + __filename / import.meta are available)
 *   2. SHA-256 of optional sibling module paths (customer-supplied)
 *   3. An optional environment fingerprint (inspector / NODE_OPTIONS / toString native check)
 *
 * The digest is exposed as a named binding so the AST shield can entangle it with
 * the opaque-predicate seed. Tampering with sibling modules or attaching an
 * inspector changes the digest → seed parity flips → opaque happy-path guards fail.
 *
 * When build-time `expectedSiblingSha256` hashes are embedded (harden/protect fills
 * these from siblings already on disk), runtime **hard-fails** on mismatch. Opaque
 * seed entanglement alone does not gate entitlement control flow that never reads
 * the seed (red/blue round-4 finding).
 *
 * Direction-3: when `interleavedSites >= 2` (default whenever siblings are present),
 * emit multiple independent measure helpers that each hard-fail on the same sibling
 * hashes. Pair with `buildInterleavedCoverageMatrix` so packaging gates can refuse
 * single-point topologies. Hash-only — no guessing.
 *
 * Entry self-coverage (CrackMe v8 red team 2026-11-05): in hard-fail mode each
 * site also hard-fails when the checker host's **own** bytes diverge. A file
 * cannot embed its own SHA-256, so the emitted literal starts as
 * {@link SELF_DIGEST_PLACEHOLDER} and {@link finalizeSelfSealSelfDigest} (run on
 * the final bytes at write time) replaces it with
 * `SHA-256(file with every digest occurrence → "0"×64)`. Runtime recomputes the
 * same canonical form. Until finalized the literal is not 64-hex and the self
 * check soft-skips (never bricks an un-finalized build).
 *
 * DEFENSIVE ONLY. Opt-in. No crack / RE advice. Browser builds soft-skip (digest=0).
 */

import { createHash } from "node:crypto";
import { isValidIdentifier } from "@babel/types";
import type { SeededPrng } from "../../core/prng.js";
import {
  buildInterleavedCoverageMatrix,
  type CoverageMatrix,
} from "../../engine/integrity-coverage.js";

export const SELF_SEAL_SCHEMA = "bla-self-seal/v1" as const;

/**
 * First-line static `data:` ESM module specifier that captures genuine
 * low-level `node:fs` (`openSync`/`fstatSync`/`readSync`/`closeSync`) and
 * `node:crypto` functions BEFORE any user sibling `import` executes (closing
 * both the ESM static-import hoisting monkey-patch bypass and `readFileSync`
 * AST/hook detectors).
 */
export const ESM_PREHOIST_CAPTURE_DATA_URL =
  "data:text/javascript," +
  encodeURIComponent(
    'import fs from "node:fs";import c from "node:crypto";' +
      "const o=fs.openSync.bind(fs),s=fs.fstatSync.bind(fs),k=fs.readSync.bind(fs),x=fs.closeSync.bind(fs);" +
      'export const r=(p)=>{const d=o(p,"r");try{const z=s(d).size,b=Buffer.allocUnsafe(z);let i=0;while(i<z){const n=k(d,b,i,z-i,i);if(n<=0)break;i+=n;}return i===z?b:b.subarray(0,i);}finally{x(d);}},h=c.createHash.bind(c);',
  );

/**
 * Build-time placeholder for the entry self-digest literal (exactly 64 chars,
 * deliberately non-hex so runtime soft-skips if a write path never finalized).
 * Never ships: {@link finalizeSelfSealSelfDigest} replaces every occurrence.
 */
export const SELF_DIGEST_PLACEHOLDER =
  "~self-digest-pending-finalize~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" as const;

const SELF_DIGEST_ZERO = "0".repeat(64);
const HEX64_LOWER = /^[0-9a-f]{64}$/;

function replaceAllBytes(buf: Buffer, needle: Buffer, replacement: Buffer): Buffer {
  if (needle.length !== replacement.length) {
    throw new Error("replaceAllBytes requires equal-length needle/replacement");
  }
  const out = Buffer.from(buf);
  let at = out.indexOf(needle);
  while (at !== -1) {
    replacement.copy(out, at);
    at = out.indexOf(needle, at + needle.length);
  }
  return out;
}

/** Canonical self-digest: SHA-256 of bytes with every `digestLiteral` → "0"×64. */
export function canonicalSelfDigest(bytes: Buffer, digestLiteral: string): string {
  const canon = replaceAllBytes(
    bytes,
    Buffer.from(digestLiteral, "latin1"),
    Buffer.from(SELF_DIGEST_ZERO, "latin1"),
  );
  return createHash("sha256").update(canon).digest("hex");
}

export interface SelfDigestFinalizeResult<T extends string | Buffer> {
  readonly content: T;
  /** True when at least one placeholder was replaced. */
  readonly applied: boolean;
  readonly digest?: string;
  readonly occurrences: number;
}

/**
 * Replace {@link SELF_DIGEST_PLACEHOLDER} with the canonical self-digest of the
 * **final** artifact bytes. Idempotent no-op when the placeholder is absent.
 * Must run after every other transform (string encryption, source-map
 * directives…) — any later byte change trips the runtime self check.
 */
export function finalizeSelfSealSelfDigest<T extends string | Buffer>(
  content: T,
): SelfDigestFinalizeResult<T> {
  let asBuf: Buffer =
    typeof content === "string" ? Buffer.from(content as string, "utf8") : Buffer.from(content as Buffer);
  const needle = Buffer.from(SELF_DIGEST_PLACEHOLDER, "latin1");
  let occurrences = 0;
  for (let at = asBuf.indexOf(needle); at !== -1; at = asBuf.indexOf(needle, at + needle.length)) {
    occurrences += 1;
  }
  if (occurrences === 0) {
    // Support re-finalizing an already-finalized self-seal buffer after a post-pass
    // (such as sidecarEntangle prepending a preamble in hardenProject).
    const text = asBuf.toString("latin1");
    const existingMatch = text.match(
      /(?:var\s+selfExpected|self_expected)\s*=\s*["']([0-9a-f]{64})["']/,
    );
    if (existingMatch && existingMatch[1]) {
      const oldHexBuf = Buffer.from(existingMatch[1], "latin1");
      asBuf = replaceAllBytes(asBuf, oldHexBuf, needle);
      for (let at = asBuf.indexOf(needle); at !== -1; at = asBuf.indexOf(needle, at + needle.length)) {
        occurrences += 1;
      }
    }
  }
  if (occurrences === 0) return { content, applied: false, occurrences };
  const zero = Buffer.from(SELF_DIGEST_ZERO, "latin1");
  const canon = replaceAllBytes(asBuf, needle, zero);
  const digest = createHash("sha256").update(canon).digest("hex");
  const finalBuf = replaceAllBytes(asBuf, needle, Buffer.from(digest, "latin1"));
  const out = (typeof content === "string" ? finalBuf.toString("utf8") : finalBuf) as T;
  return { content: out, applied: true, digest, occurrences };
}

/**
 * Offline check: does any 64-hex literal in `bytes` verify as the canonical
 * self-digest? Used by harden to keep the coverage matrix honest (only claim
 * entry self-coverage when the runtime check can actually hard-fail).
 */
export function verifySelfSealSelfDigest(bytes: Buffer): { readonly verified: boolean; readonly digest?: string } {
  const text = bytes.toString("latin1");
  const seen = new Set<string>();
  const re = /["'`]([0-9a-f]{64})["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const lit = m[1]!;
    if (seen.has(lit)) continue;
    seen.add(lit);
    if (canonicalSelfDigest(bytes, lit) === lit) return { verified: true, digest: lit };
  }
  return { verified: false };
}

export interface SelfSealOptions {
  /** Extra sibling module paths to hash at runtime (relative or absolute). */
  readonly siblingPaths?: readonly string[];
  /** When true (default), fold inspector / NODE_OPTIONS / Function#toString checks into the digest. */
  readonly envFingerprint?: boolean;
  /** Override the emitted binding name (tests). */
  readonly bindingName?: string;
  /**
   * Development escape hatch: skip the inspector / NODE_OPTIONS / Function#toString
   * fingerprint so a debugger can attach. Sibling and self-digest checks stay active.
   */
  readonly allowInspector?: boolean;
  /**
   * Optional build-time SHA-256 hex of sibling file bytes (keyed by the same
   * path strings listed in siblingPaths). When present, runtime hard-fails if
   * a sibling's bytes diverge — opaque-seed entanglement alone does not gate
   * entitlement control flow (red/blue round-4).
   */
  readonly expectedSiblingSha256?: Readonly<Record<string, string>>;
  /**
   * When true (default if expectedSiblingSha256 is non-empty), throw on sibling
   * hash mismatch instead of only poisoning the digest.
   */
  readonly hardFailOnSiblingMismatch?: boolean;
  /**
   * Number of colocated interleaved check sites (Direction-3). Default: 2 when
   * siblingPaths is non-empty, else 1 (legacy single preamble).
   */
  readonly interleavedSites?: number;
  /** Stable relative path of this checker host (for coverage matrix keys). */
  readonly checkerHostPath?: string;
  /** All protected file nodes (for coverage matrix); defaults to siblingPaths + host. */
  readonly coverageFileNodes?: readonly string[];
  /**
   * Emit the canonical self-digest check on the checker host's own bytes.
   * Default: true whenever siblings are present (hard-fail when
   * hardFailOnSiblingMismatch, else poison digest).
   */
  readonly selfDigestCheck?: boolean;
  /**
   * Optional ES module carrier bindings (`import { createRequire as <ident> } from "node:module"`
   * + `const <urlIdent> = import.meta.url;`) injected by the caller when protecting ESM entries.
   */
  readonly esmRequireHelperIdent?: string;
  readonly esmMetaUrlIdent?: string;
  /**
   * Optional pre-hoist ESM builtin captures imported from a first-line `data:` module
   * before any user `import` statements execute, defeating monkey-patched sibling imports.
   */
  readonly esmCapReadIdent?: string;
  readonly esmCapHashIdent?: string;
}

export interface SelfSealSnippet {
  readonly schema: typeof SELF_SEAL_SCHEMA;
  readonly code: string;
  readonly bindingName: string;
  /** Pure helper used by tests — not embedded in customer output. */
  readonly expectedDigestHelperName: string;
  readonly siblingCount: number;
  readonly envFingerprint: boolean;
  /** How many sibling expected hashes were embedded for hard-fail. */
  readonly expectedSiblingHashCount: number;
  readonly hardFailOnSiblingMismatch: boolean;
  /** Colocated interleaved site count actually emitted. */
  readonly interleavedSites: number;
  /** Coverage matrix for packaging gates / bla_lint_integrity_coverage. */
  readonly coverageMatrix: CoverageMatrix;
  /** True when sites embed {@link SELF_DIGEST_PLACEHOLDER} (finalize at write time). */
  readonly selfDigestCheck: boolean;
}

function emitMeasureFunction(
  helperName: string,
  siteIndex: number,
  siteSalt: string,
  siblingsLiteral: string,
  expectedLiteral: string,
  hardFailOnSiblingMismatch: boolean,
  envFingerprint: boolean,
  selfDigestCheck: boolean,
  softTamperFlag: string | null,
  esmRequireHelperIdent?: string,
  esmMetaUrlIdent?: string,
  esmCapReadIdent?: string,
  esmCapHashIdent?: string,
): string[] {
  const lines: string[] = [];
  const useLowLevelFdRead = siteIndex % 2 === 1 && !esmCapReadIdent;
  lines.push(`function ${helperName}() {`);
  lines.push(hardFailOnSiblingMismatch ? `  var digest;` : `  var digest = 0;`);
  lines.push(`  var _tampered = false;`);
  lines.push(`  try {`);
  if (esmRequireHelperIdent && esmMetaUrlIdent) {
    lines.push(`    var _req = ${esmRequireHelperIdent}(${esmMetaUrlIdent});`);
    lines.push(`    var _c = _req("node:crypto");`);
    lines.push(`    var _fs = _req("node:fs");`);
    lines.push(`    var _path = _req("node:path");`);
    lines.push(
      esmCapHashIdent
        ? `    var _mkHash = function() { return ${esmCapHashIdent}("sha256"); };`
        : `    var _mkHash = function() { return _c.createHash("sha256"); };`,
    );
    lines.push(`    var h = _mkHash();`);
    lines.push(
      `    var selfPath = _req("node:url").fileURLToPath(${esmMetaUrlIdent});`,
    );
    lines.push(`    var baseDir = _path.dirname(selfPath);`);
  } else {
    lines.push(`    var _req = require;`);
    lines.push(`    var _c = _req("node:crypto");`);
    lines.push(`    var _fs = _req("node:fs");`);
    lines.push(`    var _path = _req("node:path");`);
    lines.push(`    var _mkHash = function() { return _c.createHash("sha256"); };`);
    lines.push(`    var h = _mkHash();`);
    lines.push(
      `    var selfPath = (typeof __filename === "string" ? __filename : null);`,
    );
    if (!hardFailOnSiblingMismatch) {
      lines.push(`    if (!selfPath && typeof __dirname === "string") selfPath = _path.join(__dirname, "index.js");`);
    }
    lines.push(`    var baseDir = (typeof __dirname === "string" ? __dirname : selfPath ? _path.dirname(selfPath) : null);`);
  }
  if (esmCapReadIdent) {
    lines.push(`    var _readRaw = function(p) { return ${esmCapReadIdent}(p); };`);
  } else {
    // Always read through low-level openSync/fstatSync/readSync/closeSync so
    // hooks and static AST detectors targeting `readFileSync` fail on all sites.
    const fdVar = useLowLevelFdRead ? "fd1" : "fd0";
    const bufVar = useLowLevelFdRead ? "buf1" : "buf0";
    lines.push(`    var _readRaw = function(p) {`);
    lines.push(`      var ${fdVar} = _fs.openSync(p, "r");`);
    lines.push(`      try {`);
    lines.push(`        var sz = _fs.fstatSync(${fdVar}).size;`);
    lines.push(`        var ${bufVar} = Buffer.allocUnsafe(sz);`);
    lines.push(`        var off = 0;`);
    lines.push(`        while (off < sz) {`);
    lines.push(`          var n = _fs.readSync(${fdVar}, ${bufVar}, off, sz - off, off);`);
    lines.push(`          if (n <= 0) break;`);
    lines.push(`          off += n;`);
    lines.push(`        }`);
    if (hardFailOnSiblingMismatch) {
      lines.push(`        if (off !== sz) throw new Error("integrity check failed");`);
      lines.push(`        return ${bufVar};`);
    } else {
      lines.push(`        return off === sz ? ${bufVar} : ${bufVar}.subarray(0, off);`);
    }
    lines.push(`      } finally { _fs.closeSync(${fdVar}); }`);
    lines.push(`    };`);
  }
  lines.push(`    h.update(${JSON.stringify(siteSalt)});`);
  lines.push(`    var selfBuf = null;`);
  if (hardFailOnSiblingMismatch) {
    lines.push(`    if (!selfPath) throw new Error("integrity check failed");`);
    lines.push(`    selfBuf = _readRaw(selfPath); h.update(selfBuf);`);
  } else {
    lines.push(`    if (selfPath) { try { selfBuf = _readRaw(selfPath); h.update(selfBuf); } catch (_e) { selfBuf = null; } }`);
  }
  if (selfDigestCheck) {
    // Canonical self-digest: zero every occurrence of the embedded literal, hash,
    // compare. Only the exact build-time unfinalized placeholder soft-skips;
    // mutating even 1 char of a finalized hex literal or blocking self-read fails closed.
    lines.push(`    var selfExpected = ${JSON.stringify(SELF_DIGEST_PLACEHOLDER)};`);
    lines.push(`    var _ph = "~self-digest-" + "pending-finalize" + "~".repeat(35);`);
    lines.push(`    if (selfExpected !== _ph) {`);
    lines.push(`      if (!/^[0-9a-f]{64}$/.test(selfExpected) || (selfPath && !selfBuf)) {`);
    if (hardFailOnSiblingMismatch) {
      lines.push(`        throw new Error("integrity check failed");`);
    } else {
      lines.push(`        _tampered = true;`);
    }
    lines.push(`      } else if (selfBuf) {`);
    lines.push(`        var _lit = Buffer.from(selfExpected, "latin1");`);
    lines.push(`        var _zero = Buffer.alloc(64, 0x30);`);
    lines.push(`        var _canon = Buffer.from(selfBuf);`);
    lines.push(`        for (var _at = _canon.indexOf(_lit); _at !== -1; _at = _canon.indexOf(_lit, _at + 64)) _zero.copy(_canon, _at);`);
    lines.push(
      `        if (_mkHash().update(_canon).digest("hex") !== selfExpected) {`,
    );
    if (hardFailOnSiblingMismatch) {
      lines.push(`          throw new Error("integrity check failed");`);
    } else {
      lines.push(`          _tampered = true;`);
    }
    lines.push(`        }`);
    lines.push(`      }`);
    lines.push(`    }`);
  }
  lines.push(`    var siblings = ${siblingsLiteral};`);
  lines.push(`    var expected = ${expectedLiteral};`);
  lines.push(`    for (var i = 0; i < siblings.length; i++) {`);
  if (!hardFailOnSiblingMismatch) lines.push(`      try {`);
  lines.push(`        var spKey = siblings[i];`);
  lines.push(`        var sp = spKey;`);
  lines.push(
    `        if (!_path.isAbsolute(sp) && typeof baseDir === "string") sp = _path.join(baseDir, sp);`,
  );
  lines.push(`        var sibBuf = _readRaw(sp);`);
  lines.push(
    `        var sibHex = _mkHash().update(sibBuf).digest("hex");`,
  );
  lines.push(`        if (expected[spKey] && expected[spKey] !== sibHex) {`);
  if (hardFailOnSiblingMismatch) {
    lines.push(`          throw new Error("integrity check failed");`);
  } else {
    lines.push(`          _tampered = true;`);
  }
  lines.push(`        }`);
  lines.push(`        h.update(sp);`);
  lines.push(`        h.update(sibBuf);`);
  if (!hardFailOnSiblingMismatch) {
    lines.push(`      } catch (_e2) {`);
    lines.push(`        if (_e2 && _e2.message === "integrity check failed") throw _e2;`);
    lines.push(`        if (expected[String(siblings[i])]) _tampered = true;`);
    lines.push(`        h.update("missing:" + String(siblings[i]));`);
    lines.push(`      }`);
  }
  lines.push(`    }`);
  if (envFingerprint) {
    lines.push(`    var envNote = "";`);
    lines.push(`    try {`);
    lines.push(`      var _nodeOpts = String((typeof process !== "undefined" && process && process.env && process.env.NODE_OPTIONS) || "");`);
    lines.push(`      var _execArgv = (typeof process !== "undefined" && process && Array.isArray(process.execArgv)) ? process.execArgv.join(",") : "";`);
    lines.push(`      envNote += _nodeOpts + "|" + _execArgv;`);
    lines.push(`      if (/--inspect(?:-brk|-port|-publish-uid|=|\\b)|--debug(?:-brk|-port|=|\\b)/.test(_nodeOpts + " " + _execArgv)) _tampered = true;`);
    lines.push(`      var _fnToStr = Function.prototype.toString;`);
    lines.push(`      var _nativeToStr = /\\[native code\\]/.test(_fnToStr.call(_fnToStr)) && /\\[native code\\]/.test(_fnToStr.call(Math.imul));`);
    lines.push(`      var _isElectron = Boolean(typeof process !== "undefined" && process && process.versions && process.versions.electron);`);
    lines.push(`      var _bf = (typeof process !== "undefined" && process && typeof process.getBuiltinModule === "function") ? process.getBuiltinModule("node:fs") : null;`);
    lines.push(`      var _rfKey = "read" + "FileSync";`);
    lines.push(`      var _nativeFs = _isElectron || !_bf || (_fs.openSync === _bf.openSync && _fs.readSync === _bf.readSync && _fs.fstatSync === _bf.fstatSync && _fs[_rfKey] === _bf[_rfKey]);`);
    lines.push(`      if (!_nativeToStr || !_nativeFs) _tampered = true;`);
    lines.push(`      envNote += (_nativeToStr && _nativeFs ? "N" : "T");`);
    lines.push(`      try { var _ins = _req("node:inspector"); if (_ins && typeof _ins.url === "function" && _ins.url()) { envNote += "I"; _tampered = true; } } catch (_ei) {}`);
    lines.push(hardFailOnSiblingMismatch
      ? `    } catch (_e3) { throw _e3; }`
      : `    } catch (_e3) { envNote += "E"; }`);
    lines.push(`    h.update(envNote);`);
  }
  if (hardFailOnSiblingMismatch) {
    // Hard-fail mode previously left `_tampered` unread (dead store) when
    // --inspect / node:inspector / patched toString tripped; enforce fail-closed!
    lines.push(`    if (_tampered) throw new Error("integrity check failed");`);
  }
  lines.push(`    var hex = h.digest("hex");`);
  // Keep 24 bits of real SHA-256 digest entropy in bits 8..31 while reserving
  // low 8 bits = 0x00 on intact runs so ast-shield can couple a build-time
  // 8-bit key byte into string decoding (defeating `const seed = 1` collapse).
  lines.push(`    digest = (parseInt(hex.slice(0, 8), 16) & 0xffffff00) >>> 0;`);
  if (siteIndex === 0) {
    lines.push(`    if (digest === 0) digest = 0x40000100;`);
  }
  if (softTamperFlag !== null) {
    // One shared flag, applied once to the folded digest. Flipping a bit inside
    // every site would XOR-cancel for an even number of sites, and flipping it
    // at site 0 only lets a single-site patch disable soft-mode parity.
    lines.push(`    if (_tampered) ${softTamperFlag} = true;`);
  }
  lines.push(`  } catch (_e4) {`);
  if (hardFailOnSiblingMismatch) {
    lines.push(`    throw new Error("integrity check failed");`);
  } else {
    lines.push(`    if (_e4 && _e4.message === "integrity check failed") throw _e4;`);
    lines.push(`    digest = 0;`);
  }
  lines.push(`  }`);
  lines.push(`  return digest >>> 0;`);
  lines.push(`}`);
  return lines;
}

/**
 * Build a deterministic, greppable-marker-free self-seal preamble.
 * Identifiers come from the project PRNG so hardened artifacts stay mixed-vocab.
 */
export function generateSelfSealSnippet(
  prng: SeededPrng,
  options: SelfSealOptions = {},
): SelfSealSnippet {
  const bindingName =
    options.bindingName ??
    prng.identifier({ style: "camel", hint: "integrityDigest", entropy: 4 });
  // The name is interpolated verbatim into `var <name> = …` declarations, so
  // anything that is not a plain identifier would break or inject into the
  // generated preamble.
  for (const [option, name] of Object.entries({
    bindingName,
    esmRequireHelperIdent: options.esmRequireHelperIdent,
    esmMetaUrlIdent: options.esmMetaUrlIdent,
    esmCapReadIdent: options.esmCapReadIdent,
    esmCapHashIdent: options.esmCapHashIdent,
  })) {
    if (name !== undefined && (!isValidIdentifier(name) || name === "eval" || name === "arguments")) {
      throw new Error(`self-seal ${option} must be a valid JavaScript identifier`);
    }
  }
  const envFingerprint =
    options.envFingerprint !== false && options.allowInspector !== true;
  const siblings = (options.siblingPaths ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  const expectedSiblingSha256 = options.expectedSiblingSha256 ?? {};
  const expectedEntries = Object.entries(expectedSiblingSha256).filter(
    ([k, v]) =>
      typeof k === "string" &&
      k.length > 0 &&
      typeof v === "string" &&
      /^[0-9a-f]{64}$/i.test(v),
  );
  const hardFailOnSiblingMismatch =
    options.hardFailOnSiblingMismatch !== undefined
      ? options.hardFailOnSiblingMismatch
      : expectedEntries.length > 0;

  const interleavedSites =
    options.interleavedSites !== undefined
      ? Math.max(1, Math.floor(options.interleavedSites))
      : siblings.length > 0
        ? 2
        : 1;

  const selfDigestCheck =
    options.selfDigestCheck !== undefined ? options.selfDigestCheck : siblings.length > 0;

  const siblingsLiteral = JSON.stringify(siblings);
  const expectedLiteral = JSON.stringify(
    Object.fromEntries(expectedEntries.map(([k, v]) => [k, v.toLowerCase()])),
  );

  // Soft mode collects tamper signals in one flag and applies them once to the
  // folded digest. A per-site bit flip XOR-cancels on an even site count, and a
  // site-0-only flip is disabled by patching that single helper.
  const softTamperFlag = hardFailOnSiblingMismatch
    ? null
    : prng.identifier({ style: "camel", hint: "integrityTampered", entropy: 4 });
  const helperNames: string[] = [];
  const lines: string[] = [];
  if (softTamperFlag !== null) lines.push(`var ${softTamperFlag} = false;`);
  for (let site = 0; site < interleavedSites; site++) {
    const helperName = prng.identifier({
      style: "camel",
      hint: site === 0 ? "measureIntegrity" : `measureIntegrity${site}`,
      entropy: 4,
    });
    const siteSalt = `s${site}:${prng.hex(6)}`;
    helperNames.push(helperName);
    lines.push(
      ...emitMeasureFunction(
        helperName,
        site,
        siteSalt,
        siblingsLiteral,
        expectedLiteral,
        hardFailOnSiblingMismatch,
        envFingerprint,
        selfDigestCheck,
        softTamperFlag,
        options.esmRequireHelperIdent,
        options.esmMetaUrlIdent,
        options.esmCapReadIdent,
        options.esmCapHashIdent,
      ),
    );
  }

  // Invoke every site; fold digests so NOP-ing one still leaves others running
  // (hard mode throws inside each helper; soft mode shares the tamper flag).
  const folded = helperNames.map((h) => `${h}()`).join(" ^ ");
  const tamperFold = softTamperFlag !== null ? ` ^ (${softTamperFlag} ? 1 : 0)` : "";
  lines.push(`var ${bindingName} = ((${folded})${tamperFold}) >>> 0;`);

  const host = options.checkerHostPath ?? "entry.js";
  const fileNodes =
    options.coverageFileNodes && options.coverageFileNodes.length > 0
      ? options.coverageFileNodes
      : [...siblings, host];
  const expectedForMatrix: Record<string, string> = {
    ...Object.fromEntries(
      expectedEntries.map(([k, v]) => [k, v.toLowerCase()]),
    ),
  };
  // Host / colocated-site hashes are filled by finalizeCoverageMatrixHashes after
  // the checker file is written — never invent placeholder digests.

  const coverageMatrix = buildInterleavedCoverageMatrix({
    fileNodes,
    checkerHosts: [host],
    expectedSha256: expectedForMatrix,
    colocatedSites: interleavedSites,
  });

  return {
    schema: SELF_SEAL_SCHEMA,
    code: lines.join("\n"),
    bindingName,
    expectedDigestHelperName: helperNames[0]!,
    siblingCount: siblings.length,
    envFingerprint,
    expectedSiblingHashCount: expectedEntries.length,
    hardFailOnSiblingMismatch,
    interleavedSites,
    coverageMatrix,
    selfDigestCheck,
  };
}

/**
 * Offline helper for tests / tooling: SHA-256 first-8-hex → u32 of concatenated
 * path‖bytes pairs (mirrors the runtime happy path without env fingerprint).
 */
export function measureSelfSealDigestOffline(
  parts: readonly { readonly pathLabel: string; readonly bytes: Buffer }[],
): number {
  const h = createHash("sha256");
  for (const part of parts) {
    h.update(part.pathLabel);
    h.update(part.bytes);
  }
  return parseInt(h.digest("hex").slice(0, 8), 16) >>> 0;
}
