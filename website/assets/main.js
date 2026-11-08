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

  window.BLA_CURRENT_LANG = lang;
  window.dispatchEvent(new CustomEvent("bla:langchange", { detail: { lang } }));
}

function formatStarCount(count) {
  const n = Number(count);
  if (!Number.isFinite(n) || n < 0) return "★";
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

async function loadGitHubStars() {
  const renderStars = (val) => {
    document.querySelectorAll("[data-gh-stars]").forEach((el) => {
      el.textContent = formatStarCount(val);
    });
  };

  try {
    const cached = sessionStorage.getItem("bla_gh_stars");
    if (cached !== null) {
      renderStars(cached);
    }
  } catch {
    // ignore
  }

  try {
    const res = await fetch("https://api.github.com/repos/qybaihe/bla", {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (res.ok) {
      const data = await res.json();
      if (typeof data.stargazers_count === "number") {
        renderStars(data.stargazers_count);
        try {
          sessionStorage.setItem("bla_gh_stars", String(data.stargazers_count));
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore network issues
  }
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

document.addEventListener("DOMContentLoaded", () => {
  const initialLang = detectInitialLang();
  applyLanguage(initialLang);
  loadGitHubStars();
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
});
