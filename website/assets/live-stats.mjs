/**
 * Pure helpers for website live figures.
 * Stars: GitHub REST `stargazers_count` for qybaihe/bla.
 * CrackMe: the status table in challenge/README.md plus that version's SEAL.json.
 * No solve tally is derived from issues or CI.
 */

export const STAR_ENDPOINT = "https://api.github.com/repos/qybaihe/bla";
export const STAR_FALLBACK_ENDPOINT = "https://ungh.cc/repos/qybaihe/bla";
export const CONTENT_PREFIX = "https://api.github.com/repos/qybaihe/bla/contents/";
export const RAW_CONTENT_PREFIX = "https://raw.githubusercontent.com/qybaihe/bla/main/";
export const STAR_SOURCE_LABEL = "api.github.com/repos/qybaihe/bla · stargazers_count";
export const README_PATH = "challenge/README.md";
export const README_SOURCE_LABEL = "github.com/qybaihe/bla · challenge/README.md (default branch)";

export const STAR_REFRESH_MS = 5 * 60 * 1000;
export const CRACKME_REFRESH_MS = 10 * 60 * 1000;
export const FETCH_FRESH_MS = 60 * 1000;
export const FETCH_TIMEOUT_MS = 8000;
export const POLL_CHECK_MS = 30 * 1000;
export const MAX_STAR_COUNT = 100_000_000;

// Use only CORS-safelisted Accept header so browsers send a direct GET without preflight OPTIONS.
export const GH_HEADERS = {
  Accept: "application/vnd.github+json",
};

export function formatExactCount(value) {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_STAR_COUNT) {
    return null;
  }
  return String(value);
}

export function readStarCount(payload) {
  if (!payload || typeof payload !== "object") return null;
  const count = payload.stargazers_count;
  if (formatExactCount(count) == null) return null;
  return count;
}

export function formatUtcMinute(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return null;
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function fillTemplate(template, vars) {
  let text = typeof template === "string" ? template : "";
  for (const [key, value] of Object.entries(vars || {})) {
    text = text.replaceAll(`{${key}}`, value == null ? "" : String(value));
  }
  return text;
}

export function shouldFetch({ now, fetchedAt, visible, reason, freshMs, intervalMs, retryAt }) {
  if (!visible) return false;
  if (typeof retryAt === "number" && now < retryAt) return false;
  if (typeof fetchedAt !== "number") return true;
  const age = now - fetchedAt;
  if (reason === "open") return age >= freshMs;
  return age >= intervalMs;
}

export function contentUrl(path) {
  if (typeof path !== "string" || path.includes("..")) return null;
  if (!/^challenge\/[A-Za-z0-9._/-]+$/.test(path)) return null;
  return CONTENT_PREFIX + path.split("/").map((part) => encodeURIComponent(part)).join("/");
}

export function safeGithubUrl(url) {
  if (typeof url !== "string" || url.length > 300) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" || parsed.hostname !== "github.com") return null;
  if (!parsed.pathname.startsWith("/qybaihe/bla/")) return null;
  if (parsed.username || parsed.password) return null;
  return parsed.toString();
}

export function versionTreeUrl(dirPath) {
  if (typeof dirPath !== "string" || !/^challenge\/[A-Za-z0-9._/-]+\/$/.test(dirPath)) return null;
  return safeGithubUrl(`https://github.com/qybaihe/bla/tree/main/${dirPath}`);
}

export function sealPathFor(dirPath) {
  if (typeof dirPath !== "string" || !/^challenge\/v\d+\/$/.test(dirPath)) return null;
  return `${dirPath}SEAL.json`;
}

export function decodeBase64Utf8(content) {
  if (typeof content !== "string") return null;
  const cleaned = content.replace(/\s/g, "");
  if (!cleaned || cleaned.length > 400_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned)) return null;
  try {
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (text.length > 200_000) return null;
    return text;
  } catch {
    return null;
  }
}

function cleanText(value, max) {
  if (typeof value !== "string") return null;
  const text = value.replace(/[\u0000-\u001f\u007f]/g, "").replace(/\s+/g, " ").trim();
  if (!text || text.length > max) return null;
  return text;
}

function stripCell(cell) {
  return cell.replace(/\*\*/g, "").replace(/`/g, "").replace(/\s+/g, " ").trim();
}

export function parseChallengeReadme(markdown) {
  if (typeof markdown !== "string" || markdown.length === 0 || markdown.length > 200_000) {
    return { ok: false, reason: "input", rows: [] };
  }
  const rows = [];
  for (const line of markdown.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("|")) continue;
    const cells = trimmed.split("|").slice(1, -1).map((cell) => cell.trim());
    if (cells.length < 3) continue;
    if (/^:?-+:?$/.test(cells[0].replace(/\s/g, ""))) continue;
    if (cells[0] === "版本" || cells[0].toLowerCase() === "version") continue;
    const name = stripCell(cells[0]).slice(0, 80);
    const id = name.split(/\s+/)[0] || "";
    if (!/^v\d+(?:\.\d+)?(?:-[A-Za-z0-9-]+)?$/.test(id)) continue;
    const status = stripCell(cells[1]).slice(0, 40);
    if (!status) continue;
    const note = cells[2];
    const pathMatch = note.match(/`(challenge\/[A-Za-z0-9._/-]+\/?)`/);
    let path = pathMatch ? pathMatch[1] : null;
    if (path && !path.endsWith("/")) path = `${path}/`;
    if (path && !/^challenge\/[A-Za-z0-9._/-]+\/$/.test(path)) path = null;
    if (!path && /^v\d+$/.test(id)) path = `challenge/${id}/`;
    let kind = "other";
    if (status === "当前" || status.startsWith("当前")) kind = "current";
    else if (status.startsWith("快照")) kind = "snapshot";
    else if (status.startsWith("归档")) kind = "archived";
    rows.push({ id, name, status, kind, path });
  }
  const currentRows = rows.filter((row) => row.kind === "current");
  if (currentRows.length !== 1) {
    return { ok: false, reason: "current-count", rows };
  }
  return { ok: true, current: currentRows[0], rows };
}

export function readSealCommitment(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const product = cleanText(value.product, 40);
  const blaVersion = cleanText(value.blaVersion, 20);
  const label = cleanText(value.label, 80);
  const flagSha256 = value.flagSha256;
  if (!product || !blaVersion || !label) return null;
  if (!/^\d+\.\d+\.\d+$/.test(blaVersion)) return null;
  if (typeof flagSha256 !== "string" || !/^[0-9a-f]{64}$/.test(flagSha256)) return null;
  return { product, blaVersion, label, flagSha256 };
}

function retryAtFromResponse(response, now) {
  const retryAfter = response.headers?.get?.("retry-after");
  if (retryAfter && /^\d+$/.test(retryAfter)) {
    return now + Number(retryAfter) * 1000;
  }
  const reset = response.headers?.get?.("x-ratelimit-reset");
  if (reset && /^\d+$/.test(reset)) {
    const resetMs = Number(reset) * 1000;
    if (resetMs > now) return resetMs;
  }
  return now + STAR_REFRESH_MS;
}

export async function fetchJson(url, { fetchImpl, timeoutMs, now }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { headers: GH_HEADERS, signal: controller.signal });
    if (response.status === 403 || response.status === 429) {
      return { ok: false, errorKind: "rate-limit", retryAt: retryAtFromResponse(response, now) };
    }
    if (!response.ok) return { ok: false, errorKind: "http", status: response.status };
    const payload = await response.json();
    return { ok: true, payload };
  } catch (error) {
    const name = error && error.name;
    return { ok: false, errorKind: name === "AbortError" || name === "TimeoutError" ? "timeout" : "network" };
  } finally {
    clearTimeout(timer);
  }
}

export async function loadStars({ fetchImpl, timeoutMs = FETCH_TIMEOUT_MS, now }) {
  const result = await fetchJson(STAR_ENDPOINT, { fetchImpl, timeoutMs, now });
  if (!result.ok) return result;
  const count = readStarCount(result.payload);
  if (count == null) return { ok: false, errorKind: "payload" };
  return { ok: true, count, fetchedAt: now };
}

export async function loadGithubText(path, { fetchImpl, timeoutMs, now }) {
  const url = contentUrl(path);
  if (!url) return { ok: false, errorKind: "path" };
  const result = await fetchJson(url, { fetchImpl, timeoutMs, now });
  if (!result.ok) return result;
  const payload = result.payload;
  if (!payload || payload.encoding !== "base64") return { ok: false, errorKind: "encoding" };
  const text = decodeBase64Utf8(payload.content);
  if (text == null) return { ok: false, errorKind: "encoding" };
  return { ok: true, text, htmlUrl: safeGithubUrl(payload.html_url) };
}

export async function loadCrackmeStatus({ fetchImpl, timeoutMs = FETCH_TIMEOUT_MS, now }) {
  const readme = await loadGithubText(README_PATH, { fetchImpl, timeoutMs, now });
  if (!readme.ok) return { ok: false, errorKind: readme.errorKind, retryAt: readme.retryAt };
  const parsed = parseChallengeReadme(readme.text);
  if (!parsed.ok) return { ok: false, errorKind: "readme" };
  const sealPath = sealPathFor(parsed.current.path);
  let seal = null;
  let sealError = null;
  if (!sealPath) {
    sealError = "no-seal-path";
  } else {
    const file = await loadGithubText(sealPath, { fetchImpl, timeoutMs, now });
    if (!file.ok) {
      sealError = file.errorKind;
    } else {
      try {
        seal = readSealCommitment(JSON.parse(file.text));
        if (!seal) sealError = "seal-payload";
      } catch {
        sealError = "seal-json";
      }
    }
  }
  return {
    ok: true,
    fetchedAt: now,
    current: parsed.current,
    rows: parsed.rows,
    seal,
    sealError,
    readmeUrl: readme.htmlUrl,
  };
}

export function readStoredRecord(raw) {
  if (typeof raw !== "string" || raw.length > 20_000) return null;
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || typeof value.fetchedAt !== "number") return null;
    return value;
  } catch {
    return null;
  }
}
