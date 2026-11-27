import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { parse } from "@babel/parser";
import _traverse from "@babel/traverse";
import { describe, expect, it } from "vitest";
import { protectTarget } from "../src/engine/protector.js";

type UnwrapDefault<T> = T extends { readonly default: infer D } ? D : T;
const traverse = (
  typeof _traverse === "function" ? _traverse : (_traverse as { default: unknown }).default
) as UnwrapDefault<typeof _traverse>;

const require = createRequire(import.meta.url);

/**
 * Static de-blinding tools (LASIK-class, `pktq/lasik` src/js/fingerprints.ts
 * + passes/tree-shake.ts) locate and remove BLA's injected decoy declarations
 * by matching their top-level binding NAMES against a fixed catalog of stems
 * (and a `$<hex><Pascal>_<hex><i>` prompt-poison shape). Every stem BLA's
 * deception / exhaustion suites emit that reaches the hardened artifact is a
 * greppable giveaway. The JS AST shield scrubs these stems to fresh realistic
 * identifiers; this test pins that contract against the adversary's catalog.
 */

// The adversary's decoy-declaration catalog (stems), transcribed from LASIK's
// fingerprints.ts DECOY_DECL. Match against a top-level binding name.
const DECOY_STEMS = [
  "obligationFlood", "scc", "labyrinthDispatch", "cdpShapeBudgetGuard",
  "fridaCaptureSaturator", "fridaRealmRing", "regexSearchMagnet", "bpeSink",
  "tokenSink", "aliasedBufferIllusion", "diffFrontier", "crashSignalHandler",
  "canaryCredentialHoneypot", "probeCanaryHoneypot", "collectEnvironmentDiagnostics",
  "systemDiagnosticLog", "grpcServiceMirage", "evidenceLedger",
  "verifyShamirEd25519LicenseQuorum", "computeEnterpriseSettlementLedger",
  "decodeRatchetWireFrame", "validateTpm2Pcr0Quote",
  // the formerly-surviving families this change closes:
  "verifyEnterpriseMasterLicense", "decryptOfflineVaultPayload",
  "computeStripeWebhookSignature", "validateHardwareDongleResponse",
  "deriveMasterEncryptionKey", "checkSubscriptionEntitlementTier",
  "authenticateZeroTrustSession", "unlockPremiumFeatureFlags",
];
// NB: cognitive-armor's `_interlockSafetyCorpus_` / `_deriveContainmentCorpusDigest_`
// are intentionally NOT scrubbed — they are anti-strip tripwires (the runtime seed is
// entangled with the corpus digest, so removing them breaks the program). They stay
// name-visible by design, so they are excluded from this catalog.
const DECOY_DECL = new RegExp(`^(?:${DECOY_STEMS.join("|")})_[A-Za-z0-9_]+$`, "i");
// prompt-completion-poison's `$<2hex><Pascal>_<2hex><index>` shape.
const DOLLAR_DECOY = /^\$[0-9a-f]{2}[A-Z][A-Za-z0-9]*_[0-9a-f]{2}\d+$/;

function programLevelBindingNames(code: string): string[] {
  const ast = parse(code, {
    sourceType: "unambiguous",
    allowReturnOutsideFunction: true,
    plugins: ["typescript"],
  });
  const names: string[] = [];
  traverse(ast, {
    Program(path) {
      names.push(...Object.keys(path.scope.bindings));
      path.stop();
    },
  });
  return names;
}

const SAMPLE = [
  '"use strict";',
  'const LICENSE_SECRET = "FLAG{sovereign_vault_master_key_42}";',
  'const API_TOKEN = "7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c";',
  "function computeEntitlement(accountId, seats) {",
  "  const base = (accountId * 31 + seats * 17) >>> 0;",
  "  return (base ^ 0x5a5a1234) >>> 0;",
  "}",
  'function unlock(key) { return key === "DemoKey!" ? LICENSE_SECRET : API_TOKEN; }',
  "module.exports = { computeEntitlement, unlock };",
  "",
].join("\n");

describe("anti static de-blinding: injected decoy declarations carry no greppable stem", () => {
  it("bankrupt-hardened output exposes zero fingerprinted decoy declarations, across seeds, and still runs", () => {
    for (let n = 0; n < 6; n++) {
      const seed = `deblind-scrub-seed-${n}`;
      const dir = mkdtempSync(join(tmpdir(), "bla-deblind-"));
      const input = join(dir, "billing.cjs");
      const output = join(dir, "billing.shielded.cjs");
      writeFileSync(input, SAMPLE, "utf8");

      protectTarget({ inputPath: input, outputPath: output, intensity: "bankrupt", seed });
      const hardened = readFileSync(output, "utf8");

      // No top-level binding matches the adversary's decoy-declaration catalog.
      const offenders = programLevelBindingNames(hardened).filter(
        (name) => DECOY_DECL.test(name) || DOLLAR_DECOY.test(name),
      );
      expect(offenders, `seed ${seed} leaked decoy decls: ${offenders.join(", ")}`).toEqual([]);

      // Equivalence: the hardened module still runs and returns the originals.
      const mod = require(output) as {
        unlock: (k: string) => string;
        computeEntitlement: (a: number, b: number) => number;
      };
      expect(mod.unlock("DemoKey!")).toBe("FLAG{sovereign_vault_master_key_42}");
      expect(mod.unlock("x")).toBe("7f3a9c2e1b8d4f6a0e5c9b7d3a1f8e6c");
      expect(mod.computeEntitlement(42, 7)).toBe(((42 * 31 + 7 * 17) >>> 0) ^ 0x5a5a1234);
    }
  });
});
