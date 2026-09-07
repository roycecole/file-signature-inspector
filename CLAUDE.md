# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

File Signature Inspector (檔案簽章鑑識台) — a pure client-side, offline-capable tool that reads a file's leading bytes (magic numbers) to detect its *actual* format and flag mismatches with its extension (e.g. executables disguised as documents/images). No backend, no build step, no package manager. The README.md (in Traditional Chinese) is the canonical, detailed reference for this project — read it for anything not covered here.

## Running / testing — there is no build system

- Open `index.html` directly in a browser (`file://` works fine — no server required). The whole folder (`css/`, `js/`) must stay together since paths are relative.
- **Tests**: open `test.html` in a browser. It synthesizes test fixtures (ZIP, CFB/OLE2, PDF, PNG, etc.) in-browser and runs ~62 assertions against the detection core, showing PASS/FAIL inline. No test runner, no CLI command — just reload the page after editing `js/detectors.js` or `js/signatures.js`. `test.html` only loads `utils.js`, `sha256.js`, `signatures.js`, `detectors.js` (not `app.js`/`preview.js`), so UI changes never affect these logic tests.
- No lint/format/build commands exist in this repo (no `package.json`).
- If Node.js is available, `test.html`'s `buildFixtures()`/`buildTestGroups()` code can in principle run under Node's `vm` module (Node 18+ has built-in `File`/`Blob`/`crypto.subtle`), but there's no committed script for this — `test.html` itself is the maintained test suite.

## Architecture

**No module system.** All JS files are loaded via plain `<script src>` tags in `index.html` (and mirrored, minus UI files, in `test.html`). Every file's top-level functions/vars attach to `window`; later scripts freely use earlier ones. **Load order matters** and must be preserved when adding files:

```
utils.js → i18n.js → sha256.js → signatures.js → detectors.js → preview.js → compare.js → reference-table.js → app.js
```

Rationale: data/utils first, then logic that depends on them, then the UI wiring last. `i18n.js` loads early because `detectors.js` risk-text and `app.js` UI text both call its `t()` function.

`sha256-worker.js` and `detect-worker.js` are **not** in that `<script>` chain — they're loaded by their respective Web Workers via `importScripts()`, a separate load path.

**Coding style: `let`/`const`, never `var`.** All files use ES6 block-scoped declarations (`const` for bindings never reassigned — including top-level singletons, config objects, and DOM references cached once via `$()`/`getElementById` — `let` for anything reassigned). **Critical gotcha specific to this "no module system" architecture**: every file's top-level declarations share *one* global lexical scope (they're separate classic `<script>` tags, not modules), and unlike `var` — which silently allows the same top-level name to be redeclared across files — `let`/`const` throw a hard `SyntaxError` on any duplicate top-level name across the whole page. Before adding a new top-level `const`/`let` name to any file, grep the other files for that exact identifier to make sure it's not already used as a top-level binding elsewhere (function-scoped/block-scoped names inside functions are fine — this only applies to module-scope names sitting at column 0).

### Core files and responsibilities

| File | Responsibility |
|---|---|
| `js/utils.js` | Shared helpers (HTML escaping, formatting, clipboard) |
| `js/i18n.js` | `I18N` dict (zh/zh-Hans/en/ja) and `t()` translation function; `FORMAT_NAME_I18N` maps internal Chinese format names to display names |
| `js/sha256.js` | SHA-256 (WebCrypto first, pure-JS fallback) |
| `js/sha256-worker.js` | Worker-thread wrapper around `sha256.js` |
| `js/signatures.js` | `SIGS` array (signature table), `MEDIA_PREVIEW`, category data, custom-signature storage/validation/import-export |
| `js/detectors.js` | Detection core. `resolveSignature()` is the main entry point (dispatches through `SIGS` + custom sigs). `analyzeFileCore()` is the shared, environment-agnostic analysis function (no `id`/preview-blob fields) used by both the main thread and `detect-worker.js` |
| `js/detect-worker.js` | Worker-thread wrapper that `importScripts()`s the detection logic |
| `js/preview.js` | Thumbnails/lightbox for image/video/audio/PDF previews |
| `js/compare.js` | Byte-level diff/compare mode for two selected files (`COMPARE_CAP_OPTIONS` sets comparable byte range) |
| `js/reference-table.js` | Data + rendering for the "common file signatures" reference table (`REF` array) |
| `js/app.js` | State management, scan pipeline, Worker pool orchestration, table rendering, event/keyboard binding — the main program |

### Detection logic is shared between main thread and Workers

`analyzeFileCore()` in `detectors.js` is pure logic with no environment-specific fields, so both the main thread and `detect-worker.js` call the exact same function — editing detection logic only requires touching `analyzeFileCore()`/`resolveSignature()` once; both paths stay in sync automatically. The orchestration (pool dispatch, timeout, fallback to main thread) lives in `app.js`'s `runAnalysisCore()` and `sha256Async()`.

### Worker pools and fallback

- Detection pool: `DETECT_POOL_SIZE` (`app.js`), sized from `navigator.hardwareConcurrency` (capped at 4), timeout `DETECT_TIMEOUT_MS`.
- Hash pool: `HASH_POOL_SIZE`, timeout `WORKER_TIMEOUT_MS`.
- If Worker creation/communication fails or times out (common under `file://`), the code auto-falls-back to synchronous main-thread computation, and a crashed pool worker is auto-replaced to keep pool size stable. "Compute all SHA-256" uses `runWithConcurrency()` to actually parallelize across the pool rather than serializing.
- Workers have no `localStorage`, so when custom signatures are added/removed, `app.js` calls `broadcastCustomSigsToWorkers()` to push them into every live worker.

### i18n conventions

- All user-facing strings go through `t('module.purpose')` reading from `I18N` in `js/i18n.js` — never hardcode display text, or non-Chinese locales will show a stray Chinese string.
- Internal identifiers used for format matching (e.g. `name` fields in the `SIGS` array) are intentionally kept in Chinese and are **not** translation keys — they're internal IDs. Display conversion happens via `formatName()` looking up `FORMAT_NAME_I18N`. When adding a new format whose internal name isn't English, add a `FORMAT_NAME_I18N` entry too.
- **Known footgun**: the global translator is `t()`. Do not name a local variable or function parameter `t` (e.g. `function foo(t){...}`) — it silently shadows the global and breaks translations in that scope with no error. This has bitten the codebase before.
- Static HTML text in `index.html` uses `data-i18n` (textContent), `data-i18n-html` (innerHTML, for markup like `<b>`/`<code>`), `data-i18n-placeholder`, `data-i18n-aria-label`, or `data-i18n-title` (sets the `title` tooltip) — all applied by `applyStaticI18n()` in `js/i18n.js`, called on load and on every language switch.
- Language preference is stored in `localStorage`; auto-detected from `navigator.language` (zh/zh-Hans/ja) otherwise defaults to English.

### Where to make common changes

| Want to... | Edit |
|---|---|
| Add a format with a fixed magic-number signature | `js/signatures.js` `SIGS` array |
| Add a format needing extra logic (ZIP family, CFB family) | `js/detectors.js` |
| Make a format previewable | `js/signatures.js` `MEDIA_PREVIEW` (non image/video/audio/PDF kinds also need `js/preview.js`) |
| Adjust the reference table | `js/reference-table.js` `REF` array (+ matching i18n keys in `js/i18n.js`) |
| Adjust risk detection text/logic | `js/detectors.js` `filenameRisks()` / `contentRisks()`; text lives in `js/i18n.js` `risk.*` keys |
| Table columns/sort/filter/export | `js/app.js` |
| Styling/theme/responsive/animation | `css/styles.css` (sectioned with header comments) |
| Page copy | `index.html` via `data-i18n` attributes → `js/i18n.js` |
| Compare-mode range/UI | `js/compare.js` |
| Custom signature validation/import-export | `js/signatures.js`: `validateCustomSig()` / `exportCustomSigsJson()` / `importCustomSigsJson()`; wired into detection via `js/detectors.js` `resolveSignature()` → `allSigsSorted()` |
| JSON export fields | `js/app.js` `exportJson()` |
| Worker pool size / timeouts | `js/app.js`: `DETECT_POOL_SIZE` / `HASH_POOL_SIZE` / `*_TIMEOUT_MS` |
| PWA cache manifest | `service-worker.js` `CORE_ASSETS` — must stay in sync with actual files; the dev-only `pwa_regress.js` checks for omissions |

## Privacy/storage model (relevant when touching storage-related code)

The app stores nothing by default. Two opt-in exceptions, both `localStorage`-only, never uploaded:
- `fsi-reviewed` — SHA-256 hashes only (no filenames/paths) of files marked "reviewed", used to persist review checkmarks across sessions when the user enables it.
- `fsi-custom-sigs` — user-defined custom signatures (always persisted once added, since it's user-authored config, not file content).

"Copy view link" only encodes UI state (search/filter/sort/language) in the URL — never filenames or file content, since files never leave the browser.
