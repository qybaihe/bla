import { describe, expect, it } from "vitest";
import {
  lintPanelDeriveAbiSource,
  rewriteStablePanelDeriveSymbols,
  panelDeriveSeedRoot,
  panelDeriveReplacementName,
  intensityRewritesPanelDerive,
  PANEL_DERIVE_ABI_SCHEMA,
} from "../src/engine/panel-derive-abi-lint.js";

describe("panel-derive ABI lint/rewrite (red-blue round-3)", () => {
  it("flags __vaultPanelDerive_r3 as error and FNV primes as warning", () => {
    const src = `
      const FNV = 0x811c9dc5;
      globalThis.__vaultPanelDerive_r3 = (s) => s;
      export function use(sb) { return sb.__vaultPanelDerive_r3("x"); }
    `;
    const report = lintPanelDeriveAbiSource(src, { path: "panel.html" });
    expect(report.schema).toBe(PANEL_DERIVE_ABI_SCHEMA);
    expect(report.shouldRewriteOrRefuse).toBe(true);
    expect(report.stableSymbols).toContain("__vaultPanelDerive_r3");
    expect(report.findings.some((f) => f.id === "stable-panel-derive-global")).toBe(true);
    expect(report.findings.some((f) => f.id === "classic-fnv-prime-literal")).toBe(true);
    expect(intensityRewritesPanelDerive("bankrupt")).toBe(true);
    expect(intensityRewritesPanelDerive("stealth")).toBe(false);
  });

  it("rewrites JS and HTML-script seeds to the same replacement", () => {
    const original = "__vaultPanelDerive_r3";
    const body = `globalThis.${original} = derive; return sandbox.${original};`;
    const a = rewriteStablePanelDeriveSymbols(body, "proj-seed-1");
    const b = rewriteStablePanelDeriveSymbols(body, "proj-seed-1:html-script-0");
    expect(a.rewrote).toBe(true);
    expect(b.rewrote).toBe(true);
    expect(a.renames[0]!.to).toBe(b.renames[0]!.to);
    expect(a.code).not.toContain(original);
    expect(a.code).toContain(a.renames[0]!.to);
    expect(panelDeriveSeedRoot("proj-seed-1:html-script-0")).toBe("proj-seed-1");
    expect(panelDeriveReplacementName("proj-seed-1", original)).toMatch(/^_blaPd_[0-9a-f]{10}$/);
  });

  it("leaves clean source unchanged", () => {
    const src = `export function derivePanelToken(x) { return x; }\n`;
    const report = lintPanelDeriveAbiSource(src);
    expect(report.looksExposed).toBe(false);
    const rw = rewriteStablePanelDeriveSymbols(src, "seed");
    expect(rw.rewrote).toBe(false);
    expect(rw.code).toBe(src);
  });
});
