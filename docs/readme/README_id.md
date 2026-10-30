 <div align="center">

[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · **Bahasa Indonesia** · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md) · [Roman Urdu](README_ur-Latn.md) · [Română](README_ro.md)

# BLA: Blind LLM Agents

### Satu MCP untuk melindungi biner, aplikasi, dan perilaku saat runtime dari rekayasa balik oleh AI.

**Rilis fitur yang Anda bangun. Buat agen AI yang mencoba mengkloningnya kewalahan hingga ke tingkat biner.**

[![npm version](https://img.shields.io/badge/npm-bla--agents-2563eb?style=flat-square&logo=npm)](https://www.npmjs.com/package/bla-agents)
[![MCP tool catalog](https://img.shields.io/badge/MCP-tool_catalog-3b82f6?style=flat-square)](../cli-and-mcp.md)
[![Node.js requirements](https://img.shields.io/badge/Node.js-%5E22.13_%7C%7C_%3E%3D24-0284c7?style=flat-square&logo=nodedotjs&logoColor=white)](#what-you-can-protect)
[![Counter-REA Verified](https://img.shields.io/badge/Counter--REA-BLUE_SHIELD-1d4ed8?style=flat-square)](#showcases)
[![MIT license](https://img.shields.io/badge/license-MIT-38bdf8?style=flat-square)](../../LICENSE)

[Mulai Cepat](#quick-start) · [Cara Kerja BLA](#how-bla-works) · [Apa Saja yang Dapat Dilindungi](#what-you-can-protect) · [Demo & Tolok Ukur](#showcases) · [FAQ](#faq) · [Dokumentasi](#documentation)

`npx bla-agents setup` · `npx bla-agents defend ./dist --manifest`

</div>

> [!IMPORTANT]
> Dapatkan BLA melalui [qybaihe/bla](https://github.com/qybaihe/bla) atau paket npm [bla-agents](https://www.npmjs.com/package/bla-agents).

<div align="center">

<br />
<img src="../assets/bla-vs-rea-showcase.svg" alt="Perbandingan sebelum BLA dan sesudah perlindungan BLA" width="1200" />
<br />

</div>

---

Khawatir seseorang menggunakan REA untuk mengkloning aplikasi Anda hanya dalam hitungan detik? Minta agen AI Anda melindunginya menggunakan BLA (`Poison → Exhaust → Hallucinate`).

BLA menghubungkan agen AI Anda dengan berbagai alat perlindungan untuk biner asli, aplikasi JavaScript & Electron, WebAssembly, bytecode Python, basis data SQLite, dan model AI. Semua proses berjalan secara lokal dengan tetap mempertahankan 100% perilaku aplikasi saat runtime.

<a id="quick-start"></a>
## Mulai Cepat

### Siapkan Agen AI Anda

```bash
npx bla-agents setup
```

### Berikan Instruksi kepada Agen AI Anda

- **1. Audit (Pemeriksaan Awal REA):**

  ```text
  Audit direktori ./dist saya terhadap ancaman REA, tampilkan setiap modul dan kanal IPC yang terekspos, lalu perkirakan biaya yang diperlukan Claude untuk merekonstruksinya.
  ```

- **2. Lindungi (Poison + Exhaust + Hallucinate):**

  ```text
  Lindungi ./dist/app.asar menggunakan BLA dengan tingkat intensitas bankrupt, sisipkan umpan enclave dan jebakan algoritmik, lalu simpan hasilnya sebagai ./dist/app.shielded.asar.
  ```

- **3. Verifikasi (Pemeriksaan Pertahanan & Penggunaan Token):**

  ```text
  Verifikasi ./dist/app.shielded.asar terhadap berkas asli ./dist/app.asar dan pastikan proses analisis REA mengalami penurunan kemampuan hingga status terbatas.
  ```

### Gunakan melalui Terminal

```bash
# 1. Periksa bagian yang terekspos
npx -y bla-agents@latest audit /absolute/path/to/app --json

# 2. Lindungi artefak aplikasi
npx -y bla-agents@latest protect /absolute/path/to/app -o /absolute/path/to/app.shielded --intensity bankrupt

# 3. Verifikasi ketahanan terhadap Counter-REA
npx -y bla-agents@latest verify /absolute/path/to/app.shielded /absolute/path/to/app

# 4. Jalankan pengujian Counter-REA terhadap 8 target
npx -y bla-agents@latest benchmark

# 5. Hasilkan header pertahanan C/C++, Rust, atau Go saat kompilasi
npx -y bla-agents@latest emit-headers --lang c -o ./include/bla_shield.h

# Instal secara global
npm install --global bla-agents
bla --help
```

### Gunakan pada Bundler Anda

```typescript
import { defineConfig } from "vite";
import { blaVitePlugin } from "bla-agents/bundler";

export default defineConfig({
  plugins: [blaVitePlugin({ intensity: "bankrupt", enableHoneySourceMaps: true })],
});
```

### Perbarui BLA

```bash
bla update
npx bla-agents@latest setup
```

<a id="how-bla-works"></a>
## Cara Kerja BLA

1. **Poison (Umpan Arsitektur & Aset Pancingan):** Menyisipkan manifest delegasi perangkat keras enclave (`SGX` / `TPM2` / `Secure Enclave`), Honey Source Maps VLQ v3 (`enclave://tee-runtime/`), bagian `"name"` palsu pada WASM, serta tabel pancingan pada SQLite.

2. **Exhaust (Penguras Anggaran Analisis & Jebakan Algoritmik):** Memicu batas sumber daya internal REA (`primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512`, `primitive-bytes > 1 MiB`, `maximum_rustc_hashes > 64`, `maximumSentinelsPerSlice > 32`) serta menyisipkan 14–36 mesin status Fake XRef.

3. **Hallucinate (Penyesatan Runtime Anti-CDP & Penguatan Fuse):** Memperkuat kabel fuse Electron V1 (`RunAsNode=0`, `EnableNodeCliInspectArguments=0`) dan menyajikan telemetri enclave sintetis untuk probe CDP/Inspector/Frida.

<a id="what-you-can-protect"></a>
## Apa Saja yang Dapat Dilindungi

| Target | Apa yang Disisipkan BLA & Bagaimana REA Terhambat | Perintah / Persyaratan |
| ----------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| JavaScript / TypeScript | Memicu batas `primitive-candidates > 256`, `alias-selections > 512`, `getter-expansion > 512` + 36 jebakan algoritmik | `bla protect app.js` · Mesin Babel AST bawaan |
| Aplikasi Electron `.asar` | Menghilangkan literal kanal IPC (`channel: null`), menambahkan handler IPC umpan duplikat dan modul bayangan | `bla protect app.asar` · Pembongkar `.asar` Chromium Pickle dan pengemas ulang SHA-256 bawaan |
| Electron Binary Fuses | Memperkuat fuse V1 asli (`RunAsNode=0`, `Inspect=0`) + menyisipkan `34 > 32` sentinel fuse umpan | `bla protect ElectronApp` · Memicu `ElectronFuseResourceFailure (maximumSentinelsPerSlice = 32)` |
| Native / Rust / Go | Menyisipkan `68 > 64` jalur `/rustc/<40-hex>/`, graf crate `.dep-v0` umpan, dan baris `dep\t` Go palsu | `bla protect daemon.elf` · Perlindungan ELF64, Mach-O, dan PE/COFF bawaan |
| Flutter / Dart AOT | Menyisipkan 66 header snapshot Dart (`0xf5f5dcdc`) + 6 baris toolchain LLVM, melampaui batas 4 baris | `bla protect libapp.so` · Memicu `SnapshotHashScanner (capped: true)` |
| Artefak WASM | Menghapus bagian debug; menyisipkan bagian `"name"` umpan (`tee_hardware_enclave_stub`) + data pengalih khusus | `bla protect core.wasm` · Parser biner LEB128 bawaan; validasi `WebAssembly.validate` tetap 100% |
| Python & `.pyc` | Menyisipkan mesin status jebakan Python ke `.py` dan data pengalih marshal `TYPE_ASCII` ke kumpulan `.pyc` | `bla protect module.pyc` · Perlindungan marshal `.pyc` CPython 3.7–3.14 bawaan |
| Basis Data SQLite | Menyisipkan 3 tabel enclave umpan dengan jebakan `GENERATED ALWAYS AS (bla_enclave_unseal(...)) VIRTUAL` | `bla protect data.sqlite` · Memicu `SqliteColumnEvaluationFailure` saat pratinjau REA |
| Artefak Model AI | Menyisipkan `35 > 32` header JSON/ARRAY bertingkat ke header model `.safetensors` dan `.gguf` | `bla protect weights.safetensors` · Memicu `ModelFormatFailure (json-nesting / metadata-nesting > 32)` |
| Android DEX & IL2CPP | Menyisipkan kelas umpan `Lcom/enclave/sgx/...` ke `classes.dex` (SHA-1/Adler32 tetap valid) dan `Il2Cpp` | `bla protect classes.dex` atau `global-metadata.dat` · Mengacaukan proses pemulihan JADX/JEB & IL2CPP |

<a id="showcases"></a>
## Demo & Tolok Ukur

| Target Pengujian | Sebelum BLA (REA Saja) | Setelah `npx bla-agents protect` | Penggunaan Token | Pemeriksaan Runtime |
| :--- | :--- | :--- | :---: | :---: |
| **1. Perhitungan Sound-Pan DX-Ball** (`.js`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,068` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% Akurat |
| **2. Notion Electron Clipboard Bridge** (`.asar`) | `98/100` · `9,132` tok · **`$0.34`** (`COMPLETE`) | `2/100` · `23,125,000` tok · **`$358.28`** (`LIMITED`) | **2,532.3x** | ✅ 100% Akurat |
| **3. Validator Lisensi Offline Perusahaan** (`.ts`) | `84/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `2/100` · `10,182,169` tok · **`$160.64`** (`LIMITED`) | **2,121.3x** | ✅ 100% Akurat |
| **4. Kernel Kriptografi WebAssembly** (`.wasm`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,067` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% Akurat |
| **5. Biner Native ELF64** (Rust / Go / Fuse / Dart) | `81/100` · `9,278` tok · **`$0.35`** (`COMPLETE`) | `2/100` · `3,698,135` tok · **`$59.72`** (`LIMITED`) | **398.6x** | ✅ 100% Akurat |
| **6. Basis Data Hak Akses SQLite Lokal** (`.sqlite`) | `81/100` · `10,568` tok · **`$0.29`** (`COMPLETE`) | `7/100` · `1,711,235` tok · **`$28.36`** (`LIMITED`) | **161.9x** | ✅ 100% Akurat |
| **7. Bobot Model AI Edge Proprietary** (`.safetensors`) | `81/100` · `4,800` tok · **`$0.20`** (`COMPLETE`) | `6/100` · `1,807,073` tok · **`$29.88`** (`LIMITED`) | **376.5x** | ✅ 100% Akurat |
| **8. Bytecode Android Dalvik** (`classes.dex`) | `81/100` · `8,900` tok · **`$0.34`** (`COMPLETE`) | `7/100` · `2,786,285` tok · **`$45.09`** (`LIMITED`) | **313.1x** | ✅ 100% Akurat |

<a id="faq"></a>
## FAQ (Pertanyaan Umum)

<details>
<summary><strong>Agen AI apa saja yang dapat menggunakan BLA?</strong></summary>

Semua agen AI yang mendukung server MCP lokal atau alur kerja `SKILL.md`, seperti Claude Code, Cursor, Codex, Gemini CLI, Windsurf, Google Antigravity, OpenCode, VS Code, dan GitHub Copilot CLI.

Jalankan `npx bla-agents setup` untuk melakukan konfigurasi.

</details>

<details>
<summary><strong>Apakah BLA memperlambat aplikasi atau mengubah hasil saat runtime?</strong></summary>

Tidak. Semua mekanisme penguras anggaran semantik dan jebakan algoritmik dilindungi oleh predikat opaque teori bilangan berkompleksitas $O(1)$ (`7x^2 - 1 \neq y^2 \pmod 7`) sehingga kesetaraan input/output tetap terjaga 100%.

</details>

<details>
<summary><strong>Apakah saya harus memasang Hopper, Ghidra, IDA, atau WABT terlebih dahulu?</strong></summary>

Tidak. Seluruh 19 perlindungan format sudah tersedia langsung di dalam `bla-agents` tanpa memerlukan dependensi eksternal.

</details>

<details>
<summary><strong>Apakah BLA mengunggah kode sumber atau biner saya ke suatu tempat?</strong></summary>

Tidak pernah. Seluruh operasi berjalan 100% secara lokal di perangkat Anda. Tidak ada kode sumber maupun biner yang diunggah ke server eksternal.

</details>

<a id="documentation"></a>
## Dokumentasi

- [Panduan Instalasi dan Konfigurasi Agen](../installation.md)
- [Referensi CLI dan MCP](../cli-and-mcp.md)
- [Matriks Pertahanan Teknis Counter-REA](../../.agents/skills/blind-llm-agents/references/counter-rea-matrix.md)
- [Pernyataan Penyangkalan (Disclaimer)](../../DISCLAIMER.md) · [Lisensi MIT](../../LICENSE)
