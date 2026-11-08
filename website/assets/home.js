const SCENARIOS = {
  electron: {
    redTime: { en: "38s (5 MCP calls)", "zh-CN": "38 秒 (5 次 MCP 调用)" },
    redTokens: { en: "4,800 tokens", "zh-CN": "4,800 tokens" },
    redCost: { en: "$0.20 USD", "zh-CN": "$0.20 USD" },
    redVerdict: {
      en: "Complete (IPC + Preload + SQLite Paired)",
      "zh-CN": "完整解析 (IPC + Preload + SQLite 已配对)"
    },
    redTrace: `$ rea analyze-javascript-application ./notion-app.asar
• examination.status: "complete"
• electron.ipc[0]: "notion:clipboard:write-rich" (paired)
• Electron Fuses: RunAsNode = "honored" (--inspect OPEN)`,
    blueTime: { en: "17+ min (Budget Limited)", "zh-CN": "17+ 分钟 (触发配额限制)" },
    blueTokens: { en: "198,400 tokens (41.3x)", "zh-CN": "198,400 tokens (41.3x)" },
    blueCost: { en: "$14.88 USD", "zh-CN": "$14.88 USD" },
    blueVerdict: {
      en: "Limited (IPC Unpaired + Shadow Logic Selected)",
      "zh-CN": "受限降级 (IPC 去字面量化 + 归因至影子逻辑)"
    },
    blueTrace: `$ npx bla-agents defend ./notion-app.asar --manifest
• examination.status: "limited" (4 JS semantic caps reached)
• Obligation Expansion: 22 families (68 verification cases)
• Static Attribution: Redirected to Shadow Shamir-3-of-5 stub`,
  },
  dxball: {
    redTime: { en: "22s (3 MCP calls)", "zh-CN": "22 秒 (3 次 MCP 调用)" },
    redTokens: { en: "3,100 tokens", "zh-CN": "3,100 tokens" },
    redCost: { en: "$0.13 USD", "zh-CN": "$0.13 USD" },
    redVerdict: {
      en: "Complete (Stereo Pan Formula Recovered)",
      "zh-CN": "完整解析 (声道计算公式直接还原)"
    },
    redTrace: `$ rea analyze-javascript-application ./dxball-audio.js
• examination.status: "complete"
• recovered formula: (ballX / screenW) * 2 - 1`,
    blueTime: { en: "14+ min (SCC Expansion)", "zh-CN": "14+ 分钟 (SCC 状态机扩展)" },
    blueTokens: { en: "152,600 tokens (49.2x)", "zh-CN": "152,600 tokens (49.2x)" },
    blueCost: { en: "$11.45 USD", "zh-CN": "$11.45 USD" },
    blueVerdict: {
      en: "Limited (Candidate Cap Reached)",
      "zh-CN": "受限降级 (触发候选分支配额上限)"
    },
    blueTrace: `$ npx bla-agents defend ./dxball-audio.js --manifest
• primitive-candidates: 512 (> 256 limit -> status: "unknown")
• Call-Graph SCC Mesh: 40 mutually-recursive state nodes
• Runtime Check: calculateSoundPan(160, 640) === -0.5 (100% Exact)`,
  },
  native: {
    redTime: { en: "45s (6 MCP calls)", "zh-CN": "45 秒 (6 次 MCP 调用)" },
    redTokens: { en: "6,400 tokens", "zh-CN": "6,400 tokens" },
    redCost: { en: "$0.27 USD", "zh-CN": "$0.27 USD" },
    redVerdict: {
      en: "Complete (Crates & Control-Flow Extracted)",
      "zh-CN": "完整解析 (提取依赖树与控制流)"
    },
    redTrace: `$ rea inspect-rust-binary ./payment-daemon
• .dep-v0 crates extracted: ring, jsonwebtoken, tokio
• Ghidra decompilation: clean license branch recovered`,
    blueTime: { en: "Parser Limit Reached", "zh-CN": "触发解析器配额上限" },
    blueTokens: { en: "174,000 tokens (27.2x)", "zh-CN": "174,000 tokens (27.2x)" },
    blueCost: { en: "$13.05 USD", "zh-CN": "$13.05 USD" },
    blueVerdict: {
      en: "Limited (>64 Rustc Hashes + >32 Fuse Sentinels)",
      "zh-CN": "受限中止 (超过 64 个 Rustc 哈希与 32 个 Fuse 哨兵)"
    },
    blueTrace: `$ npx bla-agents defend ./payment-daemon --manifest
• RustBinaryProvider: exceeds MAX_RUSTC_HASHES (72 > 64)
• ElectronFuseReader: exceeds maximumSentinelsPerSlice (33 > 32)
• Native Exports: 100% preserved`,
  },
  model: {
    redTime: { en: "19s (2 MCP calls)", "zh-CN": "19 秒 (2 次 MCP 调用)" },
    redTokens: { en: "2,900 tokens", "zh-CN": "2,900 tokens" },
    redCost: { en: "$0.11 USD", "zh-CN": "$0.11 USD" },
    redVerdict: {
      en: "Complete (Tables & Tensor Metadata Parsed)",
      "zh-CN": "完整解析 (读取数据表与张量头部)"
    },
    redTrace: `$ rea inspect-model-artifact ./weights.safetensors
• header parsed: 100% tensor offsets & metadata extracted`,
    blueTime: { en: "Parser Limit Reached", "zh-CN": "触发嵌套深度与虚拟列限制" },
    blueTokens: { en: "112,000 tokens (38.6x)", "zh-CN": "112,000 tokens (38.6x)" },
    blueCost: { en: "$8.40 USD", "zh-CN": "$8.40 USD" },
    blueVerdict: {
      en: "Limited (>32 Nesting Levels & Virtual Column Guard)",
      "zh-CN": "受限中止 (超过 32 层嵌套与只读虚拟列守卫)"
    },
    blueTrace: `$ npx bla-agents defend ./weights.safetensors --manifest
• SafetensorsHeader: ModelFormatFailure("json-nesting" > 32)
• GgufHeader: ModelFormatFailure("metadata-nesting" > 32)
• SQLite: SqliteColumnEvaluationFailure on read-only connection`,
  },
};

let activeScenario = "electron";

function pickLocalized(field) {
  if (typeof field === "string") return field;
  const lang = window.BLA_CURRENT_LANG || "en";
  if (lang.startsWith("zh") && field["zh-CN"]) return field["zh-CN"];
  return field[lang] || field.en;
}

function renderScenario(key) {
  activeScenario = key || activeScenario;
  const s = SCENARIOS[activeScenario];
  if (!s) return;
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = pickLocalized(val);
  };
  set("sim-red-time", s.redTime);
  set("sim-red-tokens", s.redTokens);
  set("sim-red-cost", s.redCost);
  set("sim-red-verdict", s.redVerdict);
  set("sim-red-trace", s.redTrace);
  set("sim-blue-time", s.blueTime);
  set("sim-blue-tokens", s.blueTokens);
  set("sim-blue-cost", s.blueCost);
  set("sim-blue-verdict", s.blueVerdict);
  set("sim-blue-trace", s.blueTrace);
}

/**
 * Interactive Blue Defense Particle & Neural Lattice Canvas for the Hero section.
 * Blue nodes form a protective constellation mesh; outer red probes are deflected
 * at the shield boundary with a luminous cyan ripple.
 */
function initHeroParticles() {
  const canvas = document.getElementById("bla-hero-canvas");
  if (!canvas || typeof canvas.getContext !== "function") return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const hero = canvas.closest(".hero") || canvas.parentElement;
  if (!hero) return;

  const reducedMotion =
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let width = 0;
  let height = 0;
  let dpr = 1;
  let rafId = 0;
  let visible = true;
  const pointer = { x: -9999, y: -9999, active: false };
  const ripples = [];
  const particles = [];

  function createParticles() {
    particles.length = 0;
    const area = Math.max(width * height, 320000);
    const blueCount = Math.min(72, Math.max(38, Math.floor(area / 16500)));
    const redCount = Math.min(12, Math.max(6, Math.floor(blueCount / 6)));

    for (let i = 0; i < blueCount; i += 1) {
      const isSky = i % 3 === 0;
      particles.push({
        kind: "blue",
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.48,
        vy: (Math.random() - 0.5) * 0.48,
        r: isSky ? 2.1 : 1.5 + (i % 3) * 0.4,
        alpha: 0.35 + (i % 5) * 0.1,
        phase: Math.random() * Math.PI * 2,
        color: isSky ? "56, 189, 248" : "96, 165, 250",
      });
    }

    for (let i = 0; i < redCount; i += 1) {
      const side = i % 2 === 0 ? 0.08 + Math.random() * 0.18 : 0.74 + Math.random() * 0.18;
      particles.push({
        kind: "red",
        x: side * width,
        y: (0.12 + Math.random() * 0.76) * height,
        vx: (side < 0.5 ? 1 : -1) * (0.35 + Math.random() * 0.35),
        vy: (Math.random() - 0.5) * 0.45,
        r: 2.0,
        alpha: 0.62,
        phase: Math.random() * Math.PI * 2,
        color: "248, 113, 113",
      });
    }
  }

  function resize() {
    const rect = hero.getBoundingClientRect();
    width = Math.max(320, Math.floor(rect.width));
    height = Math.max(420, Math.floor(rect.height));
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    if (particles.length === 0) createParticles();
  }

  function drawFrame(now) {
    ctx.clearRect(0, 0, width, height);
    const cx = width * 0.5;
    const cy = Math.min(height * 0.38, 250);
    const shieldRadius = Math.min(width * 0.34, 290);

    // Subtle central Blue Shield forcefield aura
    const shieldGrad = ctx.createRadialGradient(cx, cy, shieldRadius * 0.12, cx, cy, shieldRadius);
    shieldGrad.addColorStop(0, "rgba(56, 189, 248, 0.09)");
    shieldGrad.addColorStop(0.65, "rgba(37, 99, 235, 0.04)");
    shieldGrad.addColorStop(1, "rgba(37, 99, 235, 0)");
    ctx.fillStyle = shieldGrad;
    ctx.beginPath();
    ctx.arc(cx, cy, shieldRadius, 0, Math.PI * 2);
    ctx.fill();

    // Update particle positions
    for (let i = 0; i < particles.length; i += 1) {
      const p = particles[i];
      if (!reducedMotion) {
        p.x += p.vx;
        p.y += p.vy;
        p.phase += 0.025;
      }

      // Wrap or bounce at hero bounds
      if (p.x < -20) p.x = width + 20;
      if (p.x > width + 20) p.x = -20;
      if (p.y < -20) p.y = height + 20;
      if (p.y > height + 20) p.y = -20;

      // Deflect red probes off the central Blue Defense perimeter
      if (p.kind === "red") {
        const dx = p.x - cx;
        const dy = p.y - cy;
        const dist = Math.hypot(dx, dy) || 1;
        if (dist < shieldRadius) {
          const nx = dx / dist;
          const ny = dy / dist;
          p.x = cx + nx * (shieldRadius + 4);
          p.y = cy + ny * (shieldRadius + 4);
          const dot = p.vx * nx + p.vy * ny;
          if (dot < 0) {
            p.vx -= 2 * dot * nx;
            p.vy -= 2 * dot * ny;
          }
          if (ripples.length < 8) {
            ripples.push({
              x: cx + nx * shieldRadius,
              y: cy + ny * shieldRadius,
              r: 3,
              maxR: 34,
              alpha: 0.65,
            });
          }
        }
      }

      // Pointer interaction: gentle shield pulse & node attraction/repulsion
      if (pointer.active) {
        const pdx = p.x - pointer.x;
        const pdy = p.y - pointer.y;
        const pdist = Math.hypot(pdx, pdy);
        if (pdist > 1 && pdist < 140) {
          const push = (140 - pdist) / 140;
          const force = p.kind === "red" ? 0.08 : 0.025;
          p.x += (pdx / pdist) * push * force * 14;
          p.y += (pdy / pdist) * push * force * 14;
        }
      }
    }

    // Draw constellation links between Blue Defense nodes
    const linkDist = 132;
    ctx.lineWidth = 1;
    for (let i = 0; i < particles.length; i += 1) {
      const a = particles[i];
      if (a.kind !== "blue") continue;
      for (let j = i + 1; j < particles.length; j += 1) {
        const b = particles[j];
        if (b.kind !== "blue") continue;
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        if (Math.abs(dx) > linkDist || Math.abs(dy) > linkDist) continue;
        const dist = Math.hypot(dx, dy);
        if (dist < linkDist) {
          const alpha = (1 - dist / linkDist) * 0.22;
          ctx.strokeStyle = `rgba(96, 165, 250, ${alpha})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      // Connect nodes near cursor
      if (pointer.active) {
        const cdx = a.x - pointer.x;
        const cdy = a.y - pointer.y;
        const cdist = Math.hypot(cdx, cdy);
        if (cdist < 165) {
          const calpha = (1 - cdist / 165) * 0.36;
          ctx.strokeStyle = `rgba(56, 189, 248, ${calpha})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(pointer.x, pointer.y);
          ctx.stroke();
        }
      }
    }

    // Draw deflection ripples
    for (let i = ripples.length - 1; i >= 0; i -= 1) {
      const rp = ripples[i];
      ctx.strokeStyle = `rgba(56, 189, 248, ${rp.alpha})`;
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(rp.x, rp.y, rp.r, 0, Math.PI * 2);
      ctx.stroke();
      rp.r += 0.9;
      rp.alpha *= 0.93;
      if (rp.r >= rp.maxR || rp.alpha < 0.03) {
        ripples.splice(i, 1);
      }
    }

    // Draw particles
    for (let i = 0; i < particles.length; i += 1) {
      const p = particles[i];
      const pulse = 0.78 + Math.sin(p.phase + now * 0.001) * 0.22;
      const alpha = Math.min(0.95, p.alpha * pulse);

      ctx.fillStyle = `rgba(${p.color}, ${alpha})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();

      // Soft outer halo on larger nodes
      if (p.r >= 2.0) {
        ctx.fillStyle = `rgba(${p.color}, ${alpha * 0.24})`;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r * 2.8, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  function tick(now) {
    if (!visible || document.visibilityState === "hidden") {
      rafId = 0;
      return;
    }
    drawFrame(now || performance.now());
    if (!reducedMotion) {
      rafId = window.requestAnimationFrame(tick);
    }
  }

  function start() {
    if (!rafId && !reducedMotion) {
      rafId = window.requestAnimationFrame(tick);
    }
  }

  resize();
  drawFrame(performance.now());
  start();

  window.addEventListener("resize", () => {
    resize();
    drawFrame(performance.now());
  });

  hero.addEventListener("pointermove", (e) => {
    const rect = hero.getBoundingClientRect();
    pointer.x = e.clientX - rect.left;
    pointer.y = e.clientY - rect.top;
    pointer.active = true;
  });

  hero.addEventListener("pointerleave", () => {
    pointer.active = false;
  });

  if (typeof IntersectionObserver === "function") {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          visible = entry.isIntersecting;
          if (visible) start();
        }
      },
      { threshold: 0.05 },
    );
    observer.observe(hero);
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && visible) start();
  });
}

function initHome() {
  const tabs = document.querySelectorAll("[data-scenario]");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      renderScenario(tab.getAttribute("data-scenario"));
    });
  });

  window.addEventListener("bla:langchange", () => {
    renderScenario(activeScenario);
  });

  renderScenario("electron");
  initHeroParticles();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initHome);
} else {
  initHome();
}
