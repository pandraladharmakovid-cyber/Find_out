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

The repository is configured as a Vercel monorepo: Vercel builds the Vite frontend from `frontend/dist` and serves the Express API through a serverless function under `/api/*`.

1. Create a hosted PostgreSQL database. Use its pooled connection URL for serverless deployments when available.
2. Import this GitHub repository into Vercel and leave the project root as `./`. The checked-in `vercel.json` provides the install, build, and output-directory settings.
3. Add these Vercel environment variables for Production (and Preview if needed):
   - `DATABASE_URL`: the hosted PostgreSQL connection URL.
   - `DATABASE_SSL`: `true` if required by the database provider; otherwise `false`.
   - Optional source credentials: `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_USER_AGENT`, `YOUTUBE_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, and `GEMINI_API_KEY`.
4. Deploy. On the first API request, the backend applies its schema to the configured database. Visit the deployed site and check `/api/health`.

Do not set `VITE_API_URL` for Vercel; the frontend automatically calls the API on the same deployment origin. Keep local `.env` files out of Git and never put backend credentials in `VITE_*` variables. The prototype's write APIs do not provide user authentication, so use a database dedicated to this deployment and do not store sensitive personal data.

## 📌 Project Status

Under development. Features and integrations should be considered complete only after implementation and testing.

## 👨‍💻 Developer

**Pandrala Dharma Kovidh**

- GitHub: https://github.com/pandraladharmakovid-cyber

## 📄 License

This project is available for educational and hackathon purposes. Add a formal license before distributing it for other uses.
