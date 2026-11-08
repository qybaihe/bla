import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/**
 * Exact constant from `morluto/rea/src/artifacts/apple/PropertyListDecodeBudget.ts:135`.
 */
export const REA_MAX_BINARY_PLIST_NESTING_DEPTH = 128;

export interface ApplePlistShieldResult {
  readonly xmlPlist: string;
  readonly triggersInternalSubsetBudgetAbort: boolean;
  readonly decoyEnclaveEntitlementsAdded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  /** True when bplist trailer claims nesting deeper than REA_MAX_BINARY_PLIST_NESTING_DEPTH. */
  readonly exceedsBinaryPlistNestingDepth: boolean;
}

/**
 * Protects Apple XML Property Lists (`Info.plist`, `Entitlements.plist`) against
 * REA's `preflightPropertyListDecode` (`src/artifacts/apple/PropertyListDecodeBudget.ts:78-86`):
 *
 * In `PropertyListDecodeBudget.ts:80`:
 * ```ts
 * if (token.doctype) {
 *   if (token.internalSubset)
 *     throw fail("expansion", `XML plist internal entity expansion exceeds ${budget}`);
 * }
 * ```
 * By including an empty `[]` internal subset in the `<!DOCTYPE plist ... []>` declaration
 * (which is 100% valid XML 1.0 and carries zero entities) plus decoy Secure Enclave keys,
 * REA's `preflightPropertyListDecode` immediately aborts with:
 * `PropertyListDecodeBudgetFailure("expansion", "XML plist internal entity expansion exceeds the property list decode budget")`!
 */
export function protectAppleXmlPlist(
  rawXml: string,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): ApplePlistShieldResult {
  const prng = new SeededPrng(options.seed ?? "bla-apple-plist-v1");
  const tag = prng.hex(4);

  const doctypeWithEmptyInternalSubset =
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd" []>';

  let normalized = rawXml.trim();
  if (!normalized.includes("<plist")) {
    normalized = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      doctypeWithEmptyInternalSubset,
      '<plist version="1.0">',
      "<dict>",
      "  <key>CFBundleIdentifier</key>",
      "  <string>com.example.app</string>",
      "</dict>",
      "</plist>",
    ].join("\n");
  } else if (/<!DOCTYPE\s+plist[^>]*>/i.test(normalized)) {
    normalized = normalized.replace(
      /<!DOCTYPE\s+plist[^>]*>/i,
      doctypeWithEmptyInternalSubset,
    );
  } else {
    normalized = normalized.replace(
      /(<\?xml[^?]*\?>)/i,
      `$1\n${doctypeWithEmptyInternalSubset}`,
    );
    if (!normalized.includes("<!DOCTYPE plist")) {
      normalized = `${doctypeWithEmptyInternalSubset}\n${normalized}`;
    }
  }

  const intensity = options.intensity ?? "balanced";
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const canaryEntries: string[] = [];
  deception.canary.syntheticCanaryTokens.forEach((tok, i) => {
    canaryEntries.push(`  <key>BLACanaryCredential_${i}</key>`);
    canaryEntries.push(`  <string>${tok.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</string>`);
  });
  deception.canary.ambiguousCredentialUrls.slice(0, 4).forEach((url, i) => {
    canaryEntries.push(`  <key>BLATransportEndpoint_${i}</key>`);
    canaryEntries.push(`  <string>${url.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</string>`);
  });
  deception.diagnostics.diagnosticsInjected.slice(0, 4).forEach((d, i) => {
    canaryEntries.push(`  <key>BLASystemDiagnostic_${i}</key>`);
    const msg = `[${d.errorClass}] (${d.systemCode}) ${d.diagnosticMessage}`.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    canaryEntries.push(`  <string>${msg}</string>`);
  });

  // Deep nesting bait: claim depth REA_MAX_BINARY_PLIST_NESTING_DEPTH + 4 under a decoy key.
  const depth = REA_MAX_BINARY_PLIST_NESTING_DEPTH + 4;
  canaryEntries.push(`  <key>BLABinaryPlistNestingDepthClaim</key>`);
  canaryEntries.push(`  <integer>${depth}</integer>`);

  const enclaveDictEntries = [
    `  <key>BLAEnclaveAttestationAuthority</key>`,
    `  <string>com.apple.security.secure-enclave.ring0.${tag}</string>`,
    `  <key>BLAEnclaveVsockDelegationCID</key>`,
    `  <integer>16</integer>`,
    ...canaryEntries,
  ].join("\n");

  normalized = normalized.replace(
    /<\/dict>/,
    `${enclaveDictEntries}\n</dict>`,
  );

  return {
    xmlPlist: normalized,
    triggersInternalSubsetBudgetAbort: normalized.includes("[]>"),
    decoyEnclaveEntitlementsAdded: 2 + canaryEntries.length / 2,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    exceedsBinaryPlistNestingDepth: true,
  };
}

export function protectApplePlistBuffer(
  rawBuffer: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly triggersBudgetAbort: boolean;
  readonly decoyEnclaveEntitlementsAdded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly exceedsBinaryPlistNestingDepth: boolean;
} {
  // If binary plist (`bplist00`), append a depth-claim trailer past REA_MAX_BINARY_PLIST_NESTING_DEPTH (128)
  // plus canary/diagnostic UTF-8 records. Trailer is ignored by Apple's parser (stops at trailer offset).
  if (rawBuffer.length >= 8 && rawBuffer.subarray(0, 6).toString("latin1") === "bplist") {
    const intensity = options.intensity ?? "balanced";
    const prng = new SeededPrng(options.seed ?? "bla-apple-plist-v1");
    const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);
    const depth = REA_MAX_BINARY_PLIST_NESTING_DEPTH + 4;
    const trailer = Buffer.from(
      [
        "",
        `BLA_BPLIST_DEPTH_GUARD_${depth}:${prng.hex(6)}:com.apple.security.secure-enclave.ring0`,
        ...deception.textRecords,
        "",
      ].join("\0"),
      "utf8",
    );
    return {
      buffer: Buffer.concat([rawBuffer, trailer]),
      triggersBudgetAbort: true,
      decoyEnclaveEntitlementsAdded: 4 + deception.textRecords.length,
      canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
      diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
      exceedsBinaryPlistNestingDepth: true,
    };
  }
  const xmlSource = rawBuffer.toString("utf8");
  if (!xmlSource.includes("<plist")) {
    throw new Error(
      "Invalid Apple property list: expected a binary 'bplist00' header or an XML <plist> document; refusing to synthesize a replacement plist.",
    );
  }
  const xmlRes = protectAppleXmlPlist(xmlSource, options);
  return {
    buffer: Buffer.from(xmlRes.xmlPlist, "utf8"),
    triggersBudgetAbort: xmlRes.triggersInternalSubsetBudgetAbort,
    decoyEnclaveEntitlementsAdded: xmlRes.decoyEnclaveEntitlementsAdded,
    canaryTokensEmbedded: xmlRes.canaryTokensEmbedded,
    diagnosticsEmbedded: xmlRes.diagnosticsEmbedded,
    exceedsBinaryPlistNestingDepth: xmlRes.exceedsBinaryPlistNestingDepth,
  };
}
