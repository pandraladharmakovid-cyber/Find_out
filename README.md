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
- **Investigation Dashboard** – Review findings, evidence, risk levels, and monitoring history.

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

## 📌 Project Status

Under development. Features and integrations should be considered complete only after implementation and testing.

## 👨‍💻 Developer

**Pandrala Dharma Kovidh**

- GitHub: https://github.com/pandraladharmakovid-cyber

## 📄 License

This project is available for educational and hackathon purposes. Add a formal license before distributing it for other uses.
