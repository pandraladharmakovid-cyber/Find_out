# Find_out – Digital Risk Protection Platform

Find_out is an AI-assisted cybersecurity platform designed to detect potential social media impersonation, suspicious mobile applications, phishing links, and online threats. It helps users investigate risks, understand evidence, and take appropriate security measures.

## 🚀 Features

- **Brand Profile Management** – Register official brand information, logos, websites, social accounts, and mobile apps.
- **Social Media Monitoring** – Identify potential fake profiles and brand impersonation.
- **App Store Monitoring** – Detect suspicious applications that imitate legitimate brands.
- **Look-alike Detection** – Identify similar names, logos, and branding.
- **Risk Assessment** – Analyze available evidence and explain potential threats.
- **URL Investigation** – Investigate suspicious links, profiles, and account identifiers.
- **Incident Recovery** – Provide security guidance and recovery steps after potential attacks.
- **Complaint Reporting** – Prepare and track reports about suspicious accounts and applications.
- **Cybersecurity Alerts** – Share threat information and prevention guidance.
- **Multilingual Support** – English, Telugu, and Hindi.
- **Investigation Dashboard** – Overall 0–100 risk gauge per investigation, per-factor breakdown, and evidence written as plain-English sentences with a source and status badge for each.
- **AI Agent Copilot** – Chat box at the top of the dashboard that reads every module and reports which ones are not working.
- **Detection Records (Rulebook v2)** – Source, Suspected asset, Evidence, Similarity/Risk score and Status on every detection; analyst confirm/dismiss with a who-and-when audit trail; priority queue; one-time high-risk alerts; evidence-based takedown drafts.

## 🤖 AI Agent (dashboard copilot)

The dashboard opens with a chat box connected to the platform's own AI agent.

| Piece | Where |
|---|---|
| Chat UI (top of dashboard) | `frontend/src/agent-chat.tsx` |
| Endpoint | `POST /api/agent/chat` (also `/api/agent/ask`, `/api/agent/run`, `/api/agent/status`, `/api/agent/diagnostics`) |
| Agent + context builder | `backend/src/ai-agent/agent.ts` |
| Gateway | OpenAI-compatible: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_MODEL` |

The agent reads live platform data (brands, candidates, detection records, module
diagnostics) before answering, keeps the last turns of the conversation, and
**names the modules that are not working** instead of guessing. It reports which
engine answered: the real model, or the deterministic fallback when the gateway
is unset or rejects the request.

```bash
# backend/.env
OPENAI_BASE_URL=https://api.aicredits.in/v1
OPENAI_API_KEY=sk-...                              # supplied by you; never hardcoded
OPENAI_MODEL=anthropic/claude-sonnet-4.5
OPENAI_FALLBACK_MODELS=anthropic/claude-sonnet-4.6,openai/gpt-4o-mini,openai/gpt-4.1-mini
```

If the key produces no answer the API returns the deterministic answer **and**
a `notice` explaining why, so a bad key is visible instead of silently degrading.

## 🧾 Detection records (Rulebook v2)

Every detection is stored as a record with the five required fields — **Source,
Suspected asset, Evidence, Similarity/Risk score, Status** — and a lifecycle:

```
NEW → UNDER_REVIEW → CONFIRMED | FALSE_POSITIVE → CLOSED
```

- `GET  /api/detection-records` — queue ordered by priority then risk, with counts
  and a top-8 priority queue.
- `POST /api/detection-records/:id/decision` — analyst decision. The actor
  (`actor` in the body or `x-analyst-name` header), the previous status, the new
  status, the note and the timestamp are written to `detection_record_events`.
- `GET  /api/detection-records/:id` — record plus its full change history.
- `GET  /api/detection-records/:id/takedown-draft` — evidence-based takedown
  report; every evidence sentence appears verbatim in the draft.
- `GET  /api/detection-records/alerts` — high-risk alerts, raised **once** per
  record (unique dedupe key) and acknowledged by an analyst.

Official assets are excluded by construction: a candidate that matches a verified
official asset is written as `CLOSED`, scores 0, never enters the priority queue,
and a `CONFIRMED` decision on it is rejected by the API.

## 🖼️ Brand logos

`GET /api/intelligence/logo/brand/:brandId/image` streams a real logo, resolved in
this order: uploaded logo asset → verified asset URL → stored `logo_url` → the
brand's primary domain. For a domain the resolver discovers
`apple-touch-icon`, `icon`/`shortcut icon`, `og:image`, `twitter:image` and the web
manifest, follows redirects (HTTPS only, re-validated per hop), and validates the
bytes with `sharp`. Results are cached for 6 hours (10 minutes on failure).
`GET /api/intelligence/logo/domain/:domain/meta` returns where the logo came from
and every candidate it tried.

## 🛠️ Tech Stack

- Frontend: React, TypeScript
- Backend: Node.js, Express
- Database: PostgreSQL
- AI Analysis: Evidence-based AI integration
- APIs: Supported social media, app store, and threat intelligence sources

*The final technology stack depends on the actual implementations and integrations in the project.*

## 🏗️ Project Goal

The goal of Find_out is to help individuals and organizations identify potential digital threats, investigate suspicious activity, protect legitimate brand identities, and respond effectively to cybersecurity incidents.

## 🔐 Security and Reliability

- Evidence-based risk assessment
- Official account and application exclusion
- Secure environment variable management
- Input validation and safe URL handling
- Graceful handling of unavailable data sources
- Clear distinction between confirmed evidence and uncertain findings

## 🎯 Hackathon

**Challenge:** Digital Risk Protection – Social & App Monitoring

Find_out focuses on brand impersonation detection, social media monitoring, mobile application monitoring, and evidence-backed threat investigation.

## Deploy to Vercel

Vercel hosts the Vite frontend from `frontend/dist`; the Express API is hosted separately on Render.

1. Import this GitHub repository into Vercel and leave the project root as `./`. The checked-in `vercel.json` provides the install, build, and output-directory settings.
2. Production frontend builds call `https://find-out-api.onrender.com/api` by default. For a different backend, set `VITE_API_URL` to its `/api` URL in Vercel and redeploy.
3. Keep the PostgreSQL URL and all backend integration keys in Render environment settings, not Vercel. Verify the API at `https://find-out-api.onrender.com/api/health`.

Keep local `.env` files out of Git and never put backend credentials in `VITE_*` variables. The prototype's write APIs do not provide user authentication, so use a database dedicated to this deployment and do not store sensitive personal data.

## Deploy the API to Render

The `render.yaml` Blueprint deploys the Express API as a Node web service from the `backend` directory. It uses the existing PostgreSQL database; it does not create, migrate destructively, or delete a database.

1. Push this repository to GitHub, then in Render choose **New + → Blueprint** and select this repository. Render reads the checked-in `render.yaml` and creates the `find-out-api` web service.
2. During setup, provide `DATABASE_URL` using the hosted PostgreSQL connection string. The Blueprint restricts CORS to `https://findout-henna.vercel.app`; update `FRONTEND_URL` in `render.yaml` if you change the Vercel frontend domain. For more than one allowed frontend, use comma-separated origins. Do not paste secrets into Git or chat.
3. Wait for Render to finish building and deploying. Its health check is `/api/health`; the service initializes the schema during startup. Copy the service URL from Render after deployment.
4. The Vercel production frontend defaults to the Render service URL followed by `/api`. Set `VITE_API_URL` in Vercel only if you use a different backend, then redeploy the frontend.
5. Verify the API by opening `<Render service URL>/api/health`, then use the Vercel frontend and confirm its monitoring and profile requests reach the Render API.

The Render Blueprint defaults `DATABASE_SSL` to `false` for compatibility with database endpoints that do not support TLS; database traffic is then unencrypted in transit. Use a TLS-enabled database endpoint and set `DATABASE_SSL=true` whenever possible. This setting overrides any `sslmode` query parameter in `DATABASE_URL`. The free web-service plan may sleep when idle and take longer to respond on its first request. Rotate any credentials previously exposed in chat before adding them to Render; optional source integrations can be configured later in the Render service's environment settings.

## 🧪 Verification

```bash
cd backend  && npm run build && npx vitest run --root .. && npm run e2e
cd frontend && npx tsc --noEmit && VITE_API_URL=/api npx vite build
```

- Backend unit/integration tests: **157 passing** across 31 files (includes a real
  PostgreSQL engine via PGlite for schema, risk, exclusion and detection-record
  behaviour).
- End-to-end HTTP harness: **28 checks passing** (`npm run e2e`) — brand →
  asset → scan → findings → investigation → logo → agent → complaint → report →
  detection records → chat → threat feed.
- UI smoke test: **20 checks passing** (`node frontend/scripts/ui-smoke.cjs`),
  mounting the real React app in jsdom against a running API and asserting the
  copilot, logos, detection fields, recovery checklist and readable evidence.

### Demo server (no external database needed)

```bash
cd frontend && VITE_API_URL=/api npx vite build
cd ../backend && node scripts/demo-server.cjs      # http://localhost:5000
```

The demo server runs the real Express app against PGlite, seeds three brands
(PayPal, GitHub, Wikipedia) with candidates and detection records, serves the
built frontend from the same origin, and uses the real keys in `backend/.env`.

## 📌 Project Status

Working end to end. Sources that need credentials are reported as
`not_configured` / `unavailable` — never as clean — and are listed in the API
diagnostics (`GET /api/agent/diagnostics?deep=0`).

## 👨‍💻 Developer

**Pandrala Dharma Kovidh**

- GitHub: https://github.com/pandraladharmakovid-cyber

## 📄 License

This project is available for educational and hackathon purposes. Add a formal license before distributing it for other uses.
