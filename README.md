# CloudSOC — Cloud Security Operations Center (University Demonstration)

**Course:** Cloud Computing (2026)  
**Status:** Functional local Node/React/SQLite demo with automated test coverage.  
**Not claimed:** A production SOC, a public cloud deployment, a live PostgreSQL-backed Node app, AI/ML detection, direct cloud-audit-log ingestion or automated firewall containment.

## Live implementation

- **Frontend:** React, TypeScript, Vite, Chart.js, Tailwind CSS.
- **Backend:** Node.js 22, Express REST API (37 routes).
- **Database:** SQLite (`node:sqlite`) at `./data/cloudsoc.db` by default, with 11 core relational tables plus `sessions` and `schema_migrations`.
- **Authentication:** bcrypt password hashes, hashed server-side session tokens, HttpOnly cookie, CSRF checks, ADMIN/SECURITY_ANALYST RBAC.
- **Detection:** five deterministic sliding-window rules RULE-001 through RULE-005; allowlist and active-alert deduplication.
- **Workflow:** events → alerts → investigation → incident records → audit and CSV/PDF reports.
- **Threat intelligence:** optional VirusTotal and AbuseIPDB API keys; otherwise clearly labeled Local Demonstration Mode.
- **Frontend routes:** 11 main navigation pages across 10 feature groups.

## First-time setup (Node.js 22.16+ and npm)

The ZIP does **not** contain platform-specific `node_modules`. An internet connection is needed to install dependencies on the target device.

### Windows PowerShell

```powershell
cd CloudSOC
Copy-Item .env.example .env
npm ci
npm run dev
```

Or double-click `RUN_CLOUDSOC_WINDOWS.bat` from the `CloudSOC` folder.

### macOS/Linux

```bash
cd CloudSOC
cp .env.example .env
npm ci
npm run dev
```

Open **http://localhost:3000**. Health endpoint: **http://localhost:3000/api/health**. One terminal runs both Express and Vite during development. Do not open `index.html` directly.

### Test and production-style build

```bash
npm run lint
npm test
npm run build
npm start
```

`npm run build` builds the client into `dist` and `npm start` serves the build with Express. First run will automatically initialize the SQLite database, roles, seeded demo users, example events and rules. Use a new database for final presentation to avoid stale prior test data.

## Local-only demo accounts

| Role | Email | Password |
| --- | --- | --- |
| ADMIN | admin@cloudsoc.local | Admin@CloudSOC2026! |
| SECURITY_ANALYST | analyst@cloudsoc.local | Analyst@CloudSOC2026! |

These are known **demonstration credentials**; do not publish them to the internet or reuse them in production. Public deployment requires removing seeded credentials, secure bootstrap/secrets, access restrictions, TLS, durable database storage and a reviewed threat model.

## Database and application facts

`DATABASE_PATH` or a SQLite `DATABASE_URL` selects the live Node SQLite file. Supplying a PostgreSQL URL to Node **does not** establish a PostgreSQL connection; Node uses local SQLite. The separate `CloudSOC/` subdirectory contains a **partial** Flask/SQLAlchemy/PostgreSQL *reference* implementation and PostgreSQL migration. Do not use it for the live demo or claim feature parity with Node.

Source events are manual submissions, application authentication events, simulations and seeded demo records. No live CloudTrail/Azure/GCP connector is included. Incident response actions are **manual records**, not real firewall/IAM actions.

## Change summary — 22 November 2026

- Trusted request IP resolution: untrusted `X-Forwarded-For` and login `simulated_ip` are no longer used. `TRUST_PROXY=1` is allowed only behind one genuinely trusted reverse proxy.
- Brute-force simulation now marks generated events and alerts as demo data.
- RULE-004 does not consume expired threat indicators. RULE-004 and RULE-005 now respect configurable thresholds; RULE-002 uses RULE-001's threshold rather than hardcoded 10.
- Detection event lookback follows configured maximum rule window.
- Dashboard KPI and chart queries apply selected time windows consistently. Auto-refresh interval is read from settings.
- Severity and analyst-activity report filters apply consistently.
- Alert/incident assignees must be active security analysts; protecting the last active administrator is enforced.
- Settings keys and basic values are validated.
- Browser frontend no longer persists the bearer session token in `sessionStorage`; it uses the session cookie.
- Added seven hardening tests, for **24/24 Node tests** passing in local evaluation. `tsc --noEmit` also passed.
- Production server loads Vite only in development, and local Docker setup files have been included.

For evidence and limitations see `TEST_RESULTS_AND_LIMITATIONS.md`. For Egyptian Arabic instructions see `START_HERE_AR.md`.

## Python reference scope

The `CloudSOC/app/` reference is **not fully functional**. RULE-005, complete event/alert/incident workflows, settings/audit endpoints, complete Flask CSRF integration and live cloud deployment remain incomplete or unverified. Four Python logic unit tests are recorded as passing, not a proof of a complete Flask application.

## Optional Docker local demo

`docker compose up --build` starts the Node app bound only to localhost; it persists SQLite data in a Docker named volume. Docker image build was not verified in the offline audit environment. This is **not** public deployment guidance.

## Firebase Email/Password Authentication

New public registrations use Firebase Authentication with email and password only. Firebase verifies the identity; the Express backend verifies the Firebase ID token and creates a CloudSOC HttpOnly session. New Firebase users are provisioned as `SECURITY_ANALYST` in SQLite. Existing seeded demo accounts continue to use the local login fallback.

Follow [`FIREBASE_AUTH_SETUP_AR.md`](./FIREBASE_AUTH_SETUP_AR.md) to configure the Firebase Web App values and the server-only Firebase Admin service account. Do not commit `firebase-service-account.json`.
