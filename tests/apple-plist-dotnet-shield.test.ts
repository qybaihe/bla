import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { protectAppleXmlPlist } from "../src/shields/formats/apple-plist.js";
import { planDotnetManagedBudgetExhaustion } from "../src/shields/formats/dotnet-managed.js";

describe("Apple PropertyList & .NET Managed Metadata Shields", () => {
  it("adds XML plist dictionary entries with the standard DOCTYPE", () => {
    const raw = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>MyApp</string>
</dict>
</plist>`;
    const res = protectAppleXmlPlist(raw, { seed: "plist-seed" });
    expect(res.triggersInternalSubsetBudgetAbort).toBe(false);
    expect(res.xmlPlist).toContain("<!DOCTYPE plist");
    expect(res.xmlPlist).not.toContain("[]>");
    expect(res.xmlPlist).toContain("BLAEnclaveAttestationAuthority");
  });

  it("models .NET ManagedDecodeBudget row (256B) and string (6x + 2) charges", () => {
    const plan = planDotnetManagedBudgetExhaustion(
      new SeededPrng("dotnet-seed"),
      "bankrupt",
    );
    expect(plan.decoyPInvokeImports).toHaveLength(16);
    expect(plan.totalReaRepresentationChargeBytes).toBeGreaterThan(2_000_000);
  });
});
