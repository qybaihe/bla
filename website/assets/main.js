import {
  CRACKME_REFRESH_MS,
  FETCH_FRESH_MS,
  FETCH_TIMEOUT_MS,
  POLL_CHECK_MS,
  RAW_CONTENT_PREFIX,
  README_PATH,
  README_SOURCE_LABEL,
  STAR_FALLBACK_ENDPOINT,
  STAR_REFRESH_MS,
  STAR_SOURCE_LABEL,
  fillTemplate,
  formatExactCount,
  formatUtcMinute,
  loadCrackmeStatus,
  loadStars,
  parseChallengeReadme,
  readSealCommitment,
  readStoredRecord,
  sealPathFor,
  shouldFetch,
  versionTreeUrl,
} from "./live-stats.mjs";

const STAR_CACHE_KEY = "bla_live_stars_v1";
const CRACKME_CACHE_KEY = "bla_live_crackme_v1";

function detectInitialLang() {
  const params = new URLSearchParams(window.location.search);
  const queryLang = params.get("lang");
  const supported = ["en", "zh-CN", "zh-TW", "ja", "ko", "es", "fr", "de"];
  if (queryLang && supported.includes(queryLang)) {
    return queryLang;
  }
  try {
    const saved = localStorage.getItem("bla_lang");
    if (saved && supported.includes(saved)) return saved;
  } catch {
    // ignore storage access issues
  }
  const nav = (navigator.language || "en").toLowerCase();
  if (nav.startsWith("zh-tw") || nav.startsWith("zh-hk") || nav.startsWith("zh-mo")) return "zh-TW";
  if (nav.startsWith("zh")) return "zh-CN";
  if (nav.startsWith("ja")) return "ja";
  if (nav.startsWith("ko")) return "ko";
  if (nav.startsWith("es")) return "es";
  if (nav.startsWith("fr")) return "fr";
  if (nav.startsWith("de")) return "de";
  return "en";
}

function applyLanguage(lang) {
  const dictRoot = window.BLA_I18N || {};
  const enDict = dictRoot.en || {};
  const langDict = dictRoot[lang] || enDict;

  document.documentElement.lang = lang;
  try {
    localStorage.setItem("bla_lang", lang);
  } catch {
    // ignore
  }

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    const val = langDict[key] || enDict[key];
    if (val) el.textContent = val;
  });

  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    const key = el.getAttribute("data-i18n-html");
    const val = langDict[key] || enDict[key];
    if (val) el.innerHTML = val;
  });

  document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
    const spec = el.getAttribute("data-i18n-attr") || "";
    const splitAt = spec.indexOf(":");
    if (splitAt <= 0) return;
    const attr = spec.slice(0, splitAt);
    const key = spec.slice(splitAt + 1);
    const val = langDict[key] || enDict[key];
    if (attr && val) el.setAttribute(attr, val);
  });

  const select = document.getElementById("bla-lang-select");
  if (select && select.value !== lang) {
    select.value = lang;
  }

  const canonicalEl = document.querySelector('link[rel="canonical"]');
  if (canonicalEl) {
    const baseHref = (canonicalEl.getAttribute("data-base-canonical") || canonicalEl.getAttribute("href") || "").split("?")[0];
    if (baseHref) {
      canonicalEl.setAttribute("data-base-canonical", baseHref);
      const queryLang = new URLSearchParams(window.location.search).get("lang");
      canonicalEl.setAttribute(
        "href",
        queryLang && queryLang !== "en" && lang === queryLang
          ? `${baseHref}?lang=${encodeURIComponent(lang)}`
          : baseHref,
      );
    }
  }

  window.BLA_CURRENT_LANG = lang;
  window.dispatchEvent(new CustomEvent("bla:langchange", { detail: { lang } }));
}

function liveDict() {
  const root = window.BLA_I18N || {};
  const lang = window.BLA_CURRENT_LANG || "en";
  return root[lang] || root.en || {};
}

function readCache(key) {
  try {
    const sessionHit = readStoredRecord(sessionStorage.getItem(key));
    if (sessionHit) return sessionHit;
  } catch {
    // ignore
  }
  try {
    return readStoredRecord(localStorage.getItem(key));
  } catch {
    return null;
  }
}

function writeCache(key, value) {
  const raw = JSON.stringify(value);
  try {
    sessionStorage.setItem(key, raw);
  } catch {
    // ignore
  }
  try {
    localStorage.setItem(key, raw);
  } catch {
    // ignore
  }
}

async function loadFallbackStars(now) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(STAR_FALLBACK_ENDPOINT, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const body = await res.json();
    const stars = body && body.repo && body.repo.stars;
    if (formatExactCount(stars) == null) return null;
    return { ok: true, count: stars, fetchedAt: now };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function loadFallbackCrackme(now) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const readmeRes = await fetch(`${RAW_CONTENT_PREFIX}${README_PATH}`, {
      signal: controller.signal,
    });
    if (!readmeRes.ok) return null;
    const readmeText = await readmeRes.text();
    const parsed = parseChallengeReadme(readmeText);
    if (!parsed.ok) return null;
    const sealPath = sealPathFor(parsed.current.path);
    let seal = null;
    let sealError = null;
    if (sealPath) {
      const sealRes = await fetch(`${RAW_CONTENT_PREFIX}${sealPath}`, {
        signal: controller.signal,
      });
      if (sealRes.ok) {
        try {
          seal = readSealCommitment(await sealRes.json());
        } catch {
          sealError = "seal-json";
        }
      } else {
        sealError = "http";
      }
    }
    return {
      ok: true,
      fetchedAt: now,
      current: parsed.current,
      rows: parsed.rows,
      seal,
      sealError,
      readmeUrl: "https://github.com/qybaihe/bla/blob/main/challenge/README.md",
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

let starState = { state: "loading", count: null, fetchedAt: null, failedAt: null, retryAt: null };
let crackmeState = { state: "loading", record: null, fetchedAt: null, failedAt: null, retryAt: null };
let starFlight = false;
let crackmeFlight = false;

function renderStars() {
  const language = liveDict();
  const countText = formatExactCount(starState.count) || "—";
  const messageKey = {
    live: "live.stars.live",
    stale: "live.stars.stale",
    unavailable: "live.stars.unavailable",
  }[starState.state] || "live.stars.loading";
  const stamp = fillTemplate(language[messageKey] || "", {
    count: countText,
    source: STAR_SOURCE_LABEL,
    time: formatUtcMinute(starState.fetchedAt) || "—",
    failed: formatUtcMinute(starState.failedAt) || "—",
  });
  document.querySelectorAll("[data-gh-stars]").forEach((el) => {
    el.textContent = countText;
    el.setAttribute("data-state", starState.state);
    el.setAttribute("title", stamp);
  });
  document.querySelectorAll('[data-live-stamp="stars"]').forEach((el) => {
    el.textContent = stamp;
    el.setAttribute("data-state", starState.state);
  });
}

function setCrackmeText(root, selector, text) {
  const node = root.querySelector(selector);
  if (node) node.textContent = text;
}

function renderCrackme() {
  const root = document.querySelector("[data-crackme-live]");
  if (!root) return;
  const language = liveDict();
  const record = crackmeState.record;
  const showRecord = record && (crackmeState.state === "live" || crackmeState.state === "stale");
  if (!showRecord) {
    for (const selector of [
      "[data-crackme-version]",
      "[data-crackme-status]",
      "[data-crackme-product]",
      "[data-crackme-engine]",
      "[data-crackme-label]",
      "[data-crackme-flag]",
    ]) {
      setCrackmeText(root, selector, "—");
    }
    const list = root.querySelector("[data-crackme-history]");
    if (list) list.replaceChildren();
    const link = root.querySelector("[data-crackme-link]");
    if (link) link.setAttribute("href", "https://github.com/qybaihe/bla/tree/main/challenge");
  } else {
    const flag = record.seal && /^[0-9a-f]{64}$/.test(record.seal.flagSha256) ? record.seal.flagSha256 : "—";
    setCrackmeText(root, "[data-crackme-version]", String(record.current.name || "—"));
    setCrackmeText(root, "[data-crackme-status]", String(record.current.status || "—"));
    setCrackmeText(root, "[data-crackme-product]", record.seal?.product || "—");
    setCrackmeText(root, "[data-crackme-engine]", record.seal?.blaVersion || "—");
    setCrackmeText(root, "[data-crackme-label]", record.seal?.label || "—");
    setCrackmeText(root, "[data-crackme-flag]", flag);
    const list = root.querySelector("[data-crackme-history]");
    if (list) {
      list.replaceChildren();
      for (const row of record.rows || []) {
        if (!row || row.id === record.current.id) continue;
        const item = document.createElement("li");
        item.textContent = `${row.name} — ${row.status}`;
        list.appendChild(item);
      }
    }
    const link = root.querySelector("[data-crackme-link]");
    if (link) {
      link.setAttribute("href", versionTreeUrl(record.current.path) || "https://github.com/qybaihe/bla/tree/main/challenge");
    }
  }
  const stampKey = {
    live: "live.crackme.source",
    stale: "live.crackme.stale",
    unavailable: "live.crackme.unavailable",
  }[crackmeState.state] || "live.crackme.loading";
  const stamp = fillTemplate(language[stampKey] || "", {
    source: README_SOURCE_LABEL,
    time: formatUtcMinute(crackmeState.fetchedAt) || "—",
    failed: formatUtcMinute(crackmeState.failedAt) || "—",
  });
  const stampEl = root.querySelector('[data-live-stamp="crackme"]');
  if (stampEl) {
    stampEl.textContent = stamp;
    stampEl.setAttribute("data-state", crackmeState.state);
  }
  root.setAttribute("data-state", crackmeState.state);
}

async function refreshStars(reason) {
  if (starFlight) return;
  const now = Date.now();
  if (!shouldFetch({
    now,
    fetchedAt: starState.fetchedAt,
    visible: document.visibilityState !== "hidden",
    reason,
    freshMs: FETCH_FRESH_MS,
    intervalMs: STAR_REFRESH_MS,
    retryAt: starState.retryAt,
  })) {
    return;
  }
  starFlight = true;
  try {
    let result = await loadStars({ fetchImpl: fetch.bind(globalThis), now, timeoutMs: FETCH_TIMEOUT_MS });
    if (!result.ok) {
      const fallback = await loadFallbackStars(now);
      if (fallback) result = fallback;
    }
    if (result.ok) {
      starState = { state: "live", count: result.count, fetchedAt: result.fetchedAt, failedAt: null, retryAt: null };
      writeCache(STAR_CACHE_KEY, { count: result.count, fetchedAt: result.fetchedAt });
    } else if (formatExactCount(starState.count)) {
      starState = { ...starState, state: "stale", failedAt: now, retryAt: result.retryAt || starState.retryAt };
    } else {
      starState = { state: "unavailable", count: null, fetchedAt: null, failedAt: now, retryAt: result.retryAt || null };
    }
    renderStars();
  } finally {
    starFlight = false;
  }
}

async function refreshCrackme(reason) {
  if (!document.querySelector("[data-crackme-live]") || crackmeFlight) return;
  const now = Date.now();
  if (!shouldFetch({
    now,
    fetchedAt: crackmeState.fetchedAt,
    visible: document.visibilityState !== "hidden",
    reason,
    freshMs: FETCH_FRESH_MS,
    intervalMs: CRACKME_REFRESH_MS,
    retryAt: crackmeState.retryAt,
  })) {
    return;
  }
  crackmeFlight = true;
  try {
    let result = await loadCrackmeStatus({ fetchImpl: fetch.bind(globalThis), now, timeoutMs: FETCH_TIMEOUT_MS });
    if (!result.ok) {
      const fallback = await loadFallbackCrackme(now);
      if (fallback) result = fallback;
    }
    if (result.ok) {
      crackmeState = { state: "live", record: result, fetchedAt: result.fetchedAt, failedAt: null, retryAt: null };
      writeCache(CRACKME_CACHE_KEY, {
        fetchedAt: result.fetchedAt,
        current: result.current,
        rows: result.rows,
        seal: result.seal,
        readmeUrl: result.readmeUrl,
      });
    } else if (crackmeState.record) {
      crackmeState = { ...crackmeState, state: "stale", failedAt: now, retryAt: result.retryAt || crackmeState.retryAt };
    } else {
      crackmeState = { state: "unavailable", record: null, fetchedAt: null, failedAt: now, retryAt: result.retryAt || null };
    }
    renderCrackme();
  } finally {
    crackmeFlight = false;
  }
}

function startLiveFigures() {
  const cachedStars = readCache(STAR_CACHE_KEY);
  if (cachedStars && formatExactCount(cachedStars.count)) {
    starState = {
      state: "live",
      count: cachedStars.count,
      fetchedAt: cachedStars.fetchedAt,
      failedAt: null,
      retryAt: null,
    };
  }
  const cachedCrackme = readCache(CRACKME_CACHE_KEY);
  if (
    cachedCrackme &&
    cachedCrackme.current &&
    typeof cachedCrackme.current.name === "string" &&
    typeof cachedCrackme.current.status === "string" &&
    Array.isArray(cachedCrackme.rows)
  ) {
    crackmeState = {
      state: "live",
      record: cachedCrackme,
      fetchedAt: cachedCrackme.fetchedAt,
      failedAt: null,
      retryAt: null,
    };
  }
  renderStars();
  renderCrackme();
  refreshStars("open");
  refreshCrackme("open");
  window.setInterval(() => {
    refreshStars("timer");
    refreshCrackme("timer");
  }, POLL_CHECK_MS);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    refreshStars("timer");
    refreshCrackme("timer");
  });
  window.addEventListener("bla:langchange", () => {
    renderStars();
    renderCrackme();
  });
}

function navLabel(key, fallback) {
  const dictRoot = window.BLA_I18N || {};
  const lang = window.BLA_CURRENT_LANG || "en";
  const dict = dictRoot[lang] || dictRoot.en || {};
  const en = dictRoot.en || {};
  return dict[key] || en[key] || fallback;
}

function syncNavToggleLabel(toggle) {
  if (!toggle) return;
  const open = toggle.getAttribute("aria-expanded") === "true";
  const label = open ? navLabel("nav.menuClose", "Close menu") : navLabel("nav.menu", "Menu");
  toggle.setAttribute("aria-label", label);
  const hidden = toggle.querySelector(".visually-hidden");
  if (hidden) hidden.textContent = label;
}

function initNavMenu() {
  const toggle = document.querySelector(".nav-toggle");
  const header = document.querySelector(".site-header");
  if (!toggle || !header) return;

  const setOpen = (open) => {
    header.classList.toggle("nav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    syncNavToggleLabel(toggle);
  };

  toggle.addEventListener("click", (event) => {
    const next = toggle.getAttribute("aria-expanded") !== "true";
    setOpen(next);
    if (next && event.detail === 0) {
      const first = header.querySelector(".nav-link");
      if (first) first.focus();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && header.classList.contains("nav-open")) {
      setOpen(false);
      toggle.focus();
    }
  });

  header.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => setOpen(false));
  });

  document.addEventListener("click", (event) => {
    if (!header.classList.contains("nav-open")) return;
    if (event.target instanceof Node && header.contains(event.target)) return;
    setOpen(false);
  });

  const desktop = window.matchMedia("(min-width: 1024px)");
  const closeOnDesktop = () => {
    if (desktop.matches) setOpen(false);
  };
  if (typeof desktop.addEventListener === "function") {
    desktop.addEventListener("change", closeOnDesktop);
  } else if (typeof desktop.addListener === "function") {
    desktop.addListener(closeOnDesktop);
  }

  window.addEventListener("bla:langchange", () => syncNavToggleLabel(toggle));
  syncNavToggleLabel(toggle);
}

function initMain() {
  const initialLang = detectInitialLang();
  applyLanguage(initialLang);
  startLiveFigures();
  initNavMenu();

  const select = document.getElementById("bla-lang-select");
  if (select) {
    select.addEventListener("change", (e) => {
      applyLanguage(e.target.value);
    });
  }

  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy") || "";
      const dictRoot = window.BLA_I18N || {};
      const lang = window.BLA_CURRENT_LANG || "en";
      const dict = dictRoot[lang] || dictRoot.en || {};
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = dict["hero.copied"] || "Copied ✓";
        setTimeout(() => {
          btn.textContent = dict["hero.copy"] || "Copy";
        }, 1600);
      } catch {
        // Fallback no-op
      }
    });
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initMain);
} else {
  initMain();
}
