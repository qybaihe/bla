# BLA CrackMe

BLA 对外发布的逆向 / 防护挑战。当前主挑战是 **v8 Aegis**。

## v8 — Aegis（当前）

产品 entitlement 门禁，经 `bla harden`（bankrupt + `--self-seal`，无 `--allow-*`）硬化后发布。
吸收红蓝 R1–R12 站住的配方（SHA-256 KDF、commitment 外置、随机 rounds/pad3、arity-2 / export-order / body-index 卫生）。

```bash
npm run crackme:v8 -- '<16-char-key>'
```

设计说明：[`v8/DESIGN.md`](./v8/DESIGN.md) · 承诺摘要：[`v8/SEAL.json`](./v8/SEAL.json)

## 历史

| 版本 | 状态 | 说明 |
|---|---|---|
| v8 Aegis | **当前** | 2.0 引擎 + R1–R12 配方；unlock-in-WASM |
| v7 Meridian | 快照 | `challenge/v7/`，明文在私有 store，未用 2.0 重 harden |
| v6 Harden-Native | 快照（1.6.1） | `challenge/v6/`，教学用 lane / preserve-exports |
| v6-tiered-protect | 归档 | `challenge/archive/v6-tiered-protect/`（#38） |
| v5.2 | 归档 | `challenge/archive/v5/` |
