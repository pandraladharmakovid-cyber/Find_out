# Find_out — how to run this archive

This archive contains the full source of the Round-2 build: React + TypeScript
frontend, Node/Express + TypeScript backend, and the SQL schema.

**No `node_modules`, no build output, and no secrets are included.** Install
dependencies and add your own key, exactly as below.

---

## 1. Install

```bash
cd backend  && npm install
cd ../frontend && npm install
```

## 2. Add your API key (backend only)

```bash
cp backend/.env.example backend/.env
```

Then open `backend/.env` and set:

```ini
OPENAI_BASE_URL=https://api.aicredits.in/v1
OPENAI_API_KEY=<your key>
OPENAI_MODEL=anthropic/claude-sonnet-4.5
OPENAI_FALLBACK_MODELS=anthropic/claude-sonnet-4.6,openai/gpt-4o-mini,openai/gpt-4.1-mini
```

Every other source key (Gemini, URLhaus, Safe Browsing, YouTube, Bluesky, SMTP)
is **optional**. An unconfigured source is reported as `not_configured` or
`unavailable` — never as "clean" — and the dashboard copilot names it.

## 3. Run the fastest way (no external database)

The demo server runs the real Express app against PGlite (Postgres compiled to
WASM), seeds three brands with candidates and detection records, and serves the
built frontend from the same origin.

```bash
cd frontend && VITE_API_URL=/api npx vite build
cd ../backend && npm run demo                      # http://localhost:5000
```

Open <http://localhost:5000>. (Equivalent to `node scripts/demo-server.cjs`.)

## 4. Run against your own PostgreSQL

```bash
# backend/.env
DATABASE_URL=postgresql://user:pass@host:5432/findout
DATABASE_SSL=false

cd backend  && npm run build && npm run dev    # API on :5000
cd frontend && npm run dev                     # UI on :5173
```

The schema is applied automatically at startup (`src/schema.ts`).

## 5. Continuous integration

`.github/workflows/ci.yml` runs on every push to `main` and proves the archive is
healthy in a clean environment:

| Job | What it runs |
|---|---|
| Backend | `npm ci` → `tsc` → **157 tests** (real PostgreSQL via PGlite) → **28 end-to-end HTTP checks** |
| Frontend | `npm ci` → `tsc --noEmit` → production `vite build` → artifact upload |
| Smoke | builds both bundles, boots the demo server, runs the **20 UI checks** in jsdom against the live API |

Green checks on the commit are therefore evidence the project builds and works,
not just that it compiles.

## 6. Verify it locally (the same checks)

```bash
cd backend
npm run build
npx vitest run --root ..      # 157 tests, 31 files
npm run e2e                   # 28 end-to-end HTTP checks

cd ../frontend
npx tsc --noEmit
node scripts/ui-smoke.cjs     # 20 UI checks (needs the demo server on :5000)
```

---

## What is in the archive

| Path | Contents |
|---|---|
| `frontend/src/agent-chat.tsx` | **Dashboard chat box** (the new AI Agent module) |
| `frontend/src/detections.tsx` | Detection records screen — Rulebook v2 workflow |
| `frontend/src/investigations.tsx` | Overall risk gauge + plain-English evidence |
| `frontend/src/brand-logo.tsx` | Real brand logos with an initials fallback |
| `frontend/src/dashboard.tsx` | Copilot, protected-brand logo strip, metrics |
| `frontend/src/brands.tsx` | Brand registry + "Check logo" resolver panel |
| `frontend/src/recovery.tsx` | Security & Recovery with a tickable checklist |
| `frontend/src/locales/{en,hi,te}.json` | 285 keys each, full parity |
| `backend/src/ai-agent/` | Agent loop, gateway client, tools, diagnostics |
| `backend/src/brand-impersonation.service.ts` | Hostname/brand scoring that works with no feeds |
| `backend/src/risk.ts` | Noisy-OR risk engine + confidence + escalation |
| `backend/src/evidence-narrative.ts` | Evidence → plain-English statements |
| `backend/src/logo-resolver.service.ts` | Domain → real logo discovery |
| `backend/src/safe-https.ts` | SSRF-pinned HTTPS client (binary + redirect support) |
| `backend/src/detection-records.service.ts` | Rulebook v2 lifecycle, audit, alerts, takedown draft |
| `backend/src/routes/` | All HTTP routes, including `detection-records.routes.ts` |
| `backend/src/schema.ts` | Full schema, incl. detection records + alerts |
| `backend/scripts/demo-server.cjs` | One-command demo server |
| `backend/scripts/e2e.cjs` | 28-check end-to-end harness |
| `frontend/scripts/ui-smoke.cjs` | 20-check UI harness (jsdom) |
| `database/`, `docs/` | SQL migrations and project documentation |

## Known limits (stated honestly)

| Area | Status |
|---|---|
| AI agent (chat box) | **Working** — verified live against `anthropic/claude-sonnet-4.5` through the aicredits gateway |
| Brand logos | **Working** — resolved live from paypal.com, github.com, wikipedia.org |
| Risk engine / look-alike / logo similarity | **Working** — no key required |
| Detection records (Rulebook v2) | **Working** — real Postgres tested |
| CISA KEV alert feed | **Working** — no key required |
| Gemini reasoning | Needs `GEMINI_API_KEY` |
| URLhaus | Needs `URLHAUS_AUTH_KEY` (abuse.ch returns 401 anonymously) |
| Google Safe Browsing | Needs `GOOGLE_SAFE_BROWSING_API_KEY` |
| YouTube / Bluesky | Needs `YOUTUBE_API_KEY` / `BLUESKY_*` |
| Complaint email delivery | Needs `SMTP_*` or `COMPLAINT_WEBHOOK_URL`; otherwise HTTP 503 `not_configured` |
| App-store sources | Public endpoints, no key — marked "needs check" until a deep diagnostics run |
