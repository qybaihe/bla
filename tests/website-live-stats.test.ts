import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CRACKME_REFRESH_MS,
  FETCH_FRESH_MS,
  STAR_REFRESH_MS,
  decodeBase64Utf8,
  fillTemplate,
  formatExactCount,
  loadCrackmeStatus,
  loadStars,
  parseChallengeReadme,
  readSealCommitment,
  readStarCount,
  readStoredRecord,
  sealPathFor,
  shouldFetch,
  versionTreeUrl,
} from "../website/assets/live-stats.mjs";

const repoRoot = resolve(import.meta.dirname, "..");

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
    json: async () => body,
  };
}

describe("GitHub star figures", () => {
  it("keeps the API integer, including long counts, and rejects non-integers", () => {
    expect(formatExactCount(0)).toBe("0");
    expect(formatExactCount(3312)).toBe("3312");
    expect(formatExactCount(1234567)).toBe("1234567");
    expect(formatExactCount(3.3)).toBeNull();
    expect(formatExactCount(-1)).toBeNull();
    expect(readStarCount({ stargazers_count: 1234567 })).toBe(1234567);
    expect(readStarCount({ stargazers_count: "12" })).toBeNull();
    expect(readStarCount({})).toBeNull();
  });

  it("loads a documented stargazers_count and refuses a failed or rate-limited response", async () => {
    const ok = await loadStars({
      now: 1_700_000_000_000,
      fetchImpl: async () => jsonResponse(200, { stargazers_count: 1234567 }),
    });
    expect(ok).toMatchObject({ ok: true, count: 1234567 });

    const missing = await loadStars({
      now: 1,
      fetchImpl: async () => jsonResponse(200, { stargazers_count: "nope" }),
    });
    expect(missing).toMatchObject({ ok: false, errorKind: "payload" });

    const limited = await loadStars({
      now: 5_000,
      fetchImpl: async () => jsonResponse(403, {}, { "retry-after": "30" }),
    });
    expect(limited.ok).toBe(false);
    if (!limited.ok) expect(limited.retryAt).toBe(35_000);

    const down = await loadStars({
      now: 1,
      fetchImpl: async () => jsonResponse(500, {}),
    });
    expect(down).toMatchObject({ ok: false, errorKind: "http" });

    const timeout = await loadStars({
      now: 1,
      fetchImpl: async () => {
        const error = new Error("aborted");
        error.name = "AbortError";
        throw error;
      },
    });
    expect(timeout).toMatchObject({ ok: false, errorKind: "timeout" });
  });

  it("fetches on open unless the cache is fresh, and pauses while the tab is hidden", () => {
    const now = 1_000_000;
    expect(shouldFetch({
      now,
      fetchedAt: undefined,
      visible: true,
      reason: "open",
      freshMs: FETCH_FRESH_MS,
      intervalMs: STAR_REFRESH_MS,
    })).toBe(true);
    expect(shouldFetch({
      now,
      fetchedAt: now - 30_000,
      visible: true,
      reason: "open",
      freshMs: FETCH_FRESH_MS,
      intervalMs: STAR_REFRESH_MS,
    })).toBe(false);
    expect(shouldFetch({
      now,
      fetchedAt: now - STAR_REFRESH_MS,
      visible: true,
      reason: "timer",
      freshMs: FETCH_FRESH_MS,
      intervalMs: STAR_REFRESH_MS,
    })).toBe(true);
    expect(shouldFetch({
      now,
      fetchedAt: now - CRACKME_REFRESH_MS,
      visible: false,
      reason: "timer",
      freshMs: FETCH_FRESH_MS,
      intervalMs: CRACKME_REFRESH_MS,
    })).toBe(false);
    expect(shouldFetch({
      now,
      fetchedAt: undefined,
      visible: true,
      reason: "open",
      freshMs: FETCH_FRESH_MS,
      intervalMs: STAR_REFRESH_MS,
      retryAt: now + 1,
    })).toBe(false);
  });

  it("rejects a cached record that has no fetch time", () => {
    expect(readStoredRecord(JSON.stringify({ count: 10 }))).toBeNull();
    expect(readStoredRecord(JSON.stringify({ count: 10, fetchedAt: 20 }))).toMatchObject({ fetchedAt: 20 });
    expect(readStoredRecord("not-json")).toBeNull();
  });
});

describe("CrackMe repository status", () => {
  const readme = readFileSync(resolve(repoRoot, "challenge/README.md"), "utf8");
  const seal = JSON.parse(readFileSync(resolve(repoRoot, "challenge/v9/SEAL.json"), "utf8"));

  it("reads exactly one current row from the maintained README", () => {
    const parsed = parseChallengeReadme(readme);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.current.kind).toBe("current");
    expect(parsed.current.path).toBe(`challenge/${parsed.current.id}/`);
    const currentPath = parsed.current.path;
    expect(currentPath).not.toBeNull();
    if (currentPath == null) return;
    expect(sealPathFor(currentPath)).toBe(`challenge/${parsed.current.id}/SEAL.json`);
    expect(parsed.rows.filter((row) => row.kind === "current")).toHaveLength(1);
    expect(parsed.rows.some((row) => row.kind === "snapshot")).toBe(true);
    expect(versionTreeUrl(currentPath)).toBe(
      `https://github.com/qybaihe/bla/tree/main/challenge/${parsed.current.id}/`,
    );
  });

  it("does not invent a current challenge when the table is ambiguous", () => {
    expect(parseChallengeReadme("| v1 | 快照 | `challenge/v1/` |\n| v2 | 归档 | `challenge/archive/v2/` |").ok).toBe(false);
    const two = parseChallengeReadme("| v1 | 当前 | note |\n| v2 | 当前 | note |");
    expect(two.ok).toBe(false);
    expect(sealPathFor("challenge/archive/v6-tiered-protect/")).toBeNull();
    expect(versionTreeUrl("https://evil.example/challenge/v9/")).toBeNull();
  });

  it("reads the public SEAL commitment and drops anything that is not that commitment", () => {
    const commitment = readSealCommitment(seal);
    expect(commitment?.product).toBe("Sovereign");
    expect(commitment?.blaVersion).toMatch(/^\d+\.\d+\.\d+$/);
    expect(commitment?.flagSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(readSealCommitment({ ...seal, flagSha256: "<script>" })).toBeNull();
    expect(readSealCommitment({ product: "Sovereign", blaVersion: "3.1.2", label: "x", flagSha256: "ab" })).toBeNull();
    expect("defenseScore" in (commitment || {})).toBe(false);
  });

  it("loads README plus SEAL through the contents API and fails closed", async () => {
    const readmeB64 = Buffer.from(readme, "utf8").toString("base64");
    const sealB64 = Buffer.from(JSON.stringify(seal), "utf8").toString("base64");
    const ok = await loadCrackmeStatus({
      now: 50,
      fetchImpl: async (url: string) => {
        if (String(url).endsWith("/README.md")) {
          return jsonResponse(200, { encoding: "base64", content: readmeB64, html_url: "https://github.com/qybaihe/bla/blob/main/challenge/README.md" });
        }
        if (String(url).includes("SEAL.json")) {
          return jsonResponse(200, { encoding: "base64", content: sealB64, html_url: "https://github.com/qybaihe/bla/blob/main/challenge/v9/SEAL.json" });
        }
        return jsonResponse(404, {});
      },
    });
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.seal?.flagSha256).toMatch(/^[0-9a-f]{64}$/);
      expect(ok.readmeUrl).toContain("https://github.com/qybaihe/bla/");
    }

    const broken = await loadCrackmeStatus({
      now: 50,
      fetchImpl: async () => jsonResponse(502, {}),
    });
    expect(broken).toMatchObject({ ok: false, errorKind: "http" });
    expect(decodeBase64Utf8(Buffer.from("Sovereign", "utf8").toString("base64"))).toBe("Sovereign");
    expect(fillTemplate("stars {count} at {time}", { count: "1234567", time: "2026-11-08 13:49 UTC" })).toBe(
      "stars 1234567 at 2026-11-08 13:49 UTC",
    );
  });
});
