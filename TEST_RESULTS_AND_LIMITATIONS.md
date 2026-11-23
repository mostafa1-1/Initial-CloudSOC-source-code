# Verification report — revised Node source, 22 Nov 2026

| Check | Result | How it was evaluated |
|---|---|---|
| Node test suite | **24/24 baseline before Firebase Auth changes** | Re-run `npm test` after installing the added `firebase` and `firebase-admin` packages; the new Firebase integration has not been exercised against live project credentials in this environment. |
| Static TypeScript check | **Partial syntax check PASS** | TypeScript transpilation syntax check passed for 10 modified TS/TSX files; full type-check must be rerun on the target computer after npm install. |
| Production API server smoke | **Previous baseline PASS** | Earlier baseline returned HTTP 200 with schemaVersion 3. Firebase Auth revision adds migration 4; re-run the smoke test after local installation. |
| Firebase Email/Password | **Implemented; live verification pending** | Frontend registration/login/password reset and backend ID-token verification are added. Requires enabling Email/Password, adding Web config to `.env`, and providing a server-only Firebase Admin service account. |
| Fresh `npm ci` | **NOT VERIFIED** | Offline test environment cannot resolve registry.npmjs.org; install on demonstration computer |
| Current Vite production rebuild | **NOT VERIFIED** | Archived node_modules contains Windows-native build tools incompatible with Linux; run `npm ci && npm run build` on target device |
| Docker image build | **NOT VERIFIED** | Docker build depends on downloading Node/npm packages and was not executed here |
| Browser UI after rebuild | **NOT VERIFIED** | UI must be manually checked after `npm run dev`/`npm run build` on your computer |
| Live VirusTotal/AbuseIPDB | **NOT VERIFIED** | No real API key integration test |
| Flask app/PostgreSQL runtime | **INCOMPLETE/NOT VERIFIED** | Flask code is a partial separate academic reference, not live Node app |
| Public cloud deployment | **NOT DONE** | No account/service specified; do not publicly deploy seeded credentials |

The baseline repository recorded 17 Node and 4 Python logic tests passing. Seven additional regression tests were added for security and correctness in `server/hardening.test.ts`.

## Remaining limits

- Firebase Authentication is the identity provider for new public registrations; SQLite remains the CloudSOC operational database. Existing seeded demo accounts retain local login. Firebase credentials must be configured before the new signup/login path can be used.

- No authenticated connector for AWS CloudTrail, Azure security logging, or Google Cloud Audit Logs.
- No live firewall / IAM automated containment.
- Built-in demo users and passwords: safe only in a private local evaluation environment.
- No global distributed rate limiter, advanced session device management, or independently audited security certification; this is an academic demo.
- No production-ready PostgreSQL in Node. Flask is a partial reference and should not be called complete.
- PDF report is limited to 120 displayed records and CSV report to 500 records by design.
- Docker Compose is bound to localhost only; neither a real public cloud deployment nor persistent cloud storage has been verified.

## Quick professor-proof scenario

Login admin → Dashboard → Security Events simulation → RULE-001 Critical alert → Alerts → escalate to Incident → add notes and manual response → Reports CSV/PDF → Audit Logs → explain local/Cloud distinction.
