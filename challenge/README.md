# BLA CrackMe

BLA 对外发布的逆向 / 防护挑战。当前主挑战是 **v9 Sovereign（BLA 3.0）**。

## v9 — Sovereign（当前 · BLA 3.0）

多语言产品 entitlement 门禁（`license.cjs` + `core.wasm` + `panel.html` + `policy.py` + 受保护 `seal.json`），经 **BLA 3.0 四阶段 Agent 主导加固剧本**（`bla_lint` → `bla_weave_plan` → `bla_verify_weave` 100/100 → `bla_harden --weave-decoys --self-seal --sidecar-entangle`，无 `--allow-*`）硬化后发布。
闭合了 v8 遗留的 `seal.json` 数据 sidecar 未覆盖缺口，并强制通过编译前/加固后 `weaveScore: 100` 与 `integrityCoverageSelfVerified: true`。

```bash
npm run crackme:v9 -- '<16-char-key>'
```

设计说明：[`v9/DESIGN.md`](./v9/DESIGN.md) · 承诺摘要：[`v9/SEAL.json`](./v9/SEAL.json)

## 历史

| 版本 | 状态 | 说明 |
|---|---|---|
| v9 Sovereign | **当前** | **3.0 引擎** + 四阶段 Agent 织入（`weaveScore: 100`）+ `sidecar_entangle` + 受保护 `seal.json` |
| v8 Aegis | 快照（2.0） | `challenge/v8/`，2.0 引擎 + R1–R12 配方；unlock-in-WASM |
| v7 Meridian | 快照 | `challenge/v7/`，明文在私有 store，未用 2.0 重 harden |
| v6 Harden-Native | 快照（1.6.1） | `challenge/v6/`，教学用 lane / preserve-exports |
| v6-tiered-protect | 归档 | `challenge/archive/v6-tiered-protect/`（#38） |
| v5.2 | 归档 | `challenge/archive/v5/` |
