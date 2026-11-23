import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { createDatabase } from './db';
import { createApp } from './app';

async function startTestServer(dbPath = ':memory:') {
  const db = createDatabase(dbPath);
  const app = createApp(db);
  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  return {
    db,
    server,
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          db.close();
          resolve();
        });
      }),
  };
}

function extractCookie(res: Response): string {
  const setCookie = res.headers.get('set-cookie') || '';
  return setCookie.split(';')[0] || '';
}

test('Security: Security headers, CSRF enforcement, RBAC, and SQLi resilience', async () => {
  const srv = await startTestServer();
  try {
    // 1. Health & security headers check
    const healthRes = await fetch(`${srv.baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    assert.equal(healthRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(healthRes.headers.get('x-frame-options'), 'SAMEORIGIN');

    // 2. Unauthenticated access rejected
    const unauthAlerts = await fetch(`${srv.baseUrl}/api/alerts`);
    assert.equal(unauthAlerts.status, 401);

    // 3. SQL injection attempt on login fails safely
    const sqliLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: "' OR 1=1 --", password: "' OR '1'='1" }),
    });
    assert.equal(sqliLogin.status, 401);

    // 4. Public local registration is disabled; new accounts must use Firebase Email/Password.
    const regRes = await fetch(`${srv.baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'qa_analyst', email: 'qa_analyst@example.com', full_name: 'QA Analyst', password: 'Analyst@2026' }),
    });
    assert.equal(regRes.status, 410);

    const missingFirebaseToken = await fetch(`${srv.baseUrl}/api/auth/firebase/session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    assert.equal(missingFirebaseToken.status, 400);

    // Existing seeded analyst account remains available for local demo/testing.
    const analystLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'analyst@cloudsoc.local', password: 'Analyst@CloudSOC2026!' }),
    });
    assert.equal(analystLogin.status, 200);
    const analystCookie = extractCookie(analystLogin);

    // 5. RBAC: Analyst blocked from admin routes (/api/users, /api/settings)
    const usersBlocked = await fetch(`${srv.baseUrl}/api/users`, {
      headers: { Cookie: analystCookie },
    });
    assert.equal(usersBlocked.status, 403);

    const settingsBlocked = await fetch(`${srv.baseUrl}/api/settings`, {
      headers: { Cookie: analystCookie },
    });
    assert.equal(settingsBlocked.status, 403);

    // 6. CSRF: Mutating request without X-CSRF-Token blocked
    const missingCsrf = await fetch(`${srv.baseUrl}/api/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: analystCookie },
      body: JSON.stringify({ title: 'CSRF Probe', description: 'Should be blocked' }),
    });
    assert.equal(missingCsrf.status, 403);
  } finally {
    await srv.close();
  }
});

test('Functional E2E: Brute-force detection -> Alert -> Incident lifecycle -> CSV/PDF Reports -> Persistence', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsoc-test-'));
  const dbFile = path.join(tmpDir, 'test.db');
  const srv = await startTestServer(dbFile);

  let createdIncidentId = 0;
  try {
    // Sign in as Admin
    const loginRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'admin@cloudsoc.local', password: 'Admin@CloudSOC2026!' }),
    });
    assert.equal(loginRes.status, 200);
    const adminCookie = extractCookie(loginRes);
    const loginJson = (await loginRes.json()) as { csrfToken: string };
    const csrf = loginJson.csrfToken;

    // 1. Create target test user via Admin API
    const createUserRes = await fetch(`${srv.baseUrl}/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: adminCookie, 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        username: 'target_ops',
        email: 'target_ops@cloudsoc.local',
        full_name: 'Target Operations',
        password: 'Target@2026',
        role: 'SECURITY_ANALYST',
      }),
    });
    assert.equal(createUserRes.status, 201);

    // 2. Perform failed logins from actual test connection; forged IP in body must be ignored.
    const attackerIp = '127.0.0.1';
    for (let i = 1; i <= 10; i++) {
      const failRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: 'target_ops',
          password: `WrongPassword${i}!`,
          simulated_ip: '198.51.100.222', // ignored: client-controlled IP spoofing is not permitted
        }),
      });
      assert.equal(failRes.status, 401);
    }

    // 3. Verify security_events recorded and password never leaked
    const eventsRes = await fetch(`${srv.baseUrl}/api/events?search=${attackerIp}`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(eventsRes.status, 200);
    const eventsJson = (await eventsRes.json()) as {
      events: Array<{ event_type: string; description: string }>;
    };
    assert.equal(eventsJson.events.length >= 10, true);
    assert.equal(
      eventsJson.events.some((e) => e.description.includes('WrongPassword')),
      false
    );
    assert.equal(
      eventsJson.events.some((e) => e.event_type === 'Multiple Failed Logins'),
      true
    );

    // 4. Verify RULE-001 Critical alert generated
    const alertsRes = await fetch(`${srv.baseUrl}/api/alerts?search=${attackerIp}`, {
      headers: { Cookie: adminCookie },
    });
    const alertsJson = (await alertsRes.json()) as {
      alerts: Array<{ id: number; severity: string; rule_code: string; status: string }>;
    };
    const bruteAlert = alertsJson.alerts.find((a) => a.rule_code === 'RULE-001');
    assert.ok(bruteAlert);
    assert.equal(bruteAlert.severity, 'Critical');

    // 5. Verify dashboard reflects real data
    const dashRes = await fetch(`${srv.baseUrl}/api/dashboard?days=7`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(dashRes.status, 200);
    const dashJson = (await dashRes.json()) as { kpis: { totalEvents: number; criticalAlerts: number } };
    assert.equal(dashJson.kpis.totalEvents >= 20, true);
    assert.equal(dashJson.kpis.criticalAlerts >= 2, true);

    // 6. Escalate alert to incident
    const escRes = await fetch(`${srv.baseUrl}/api/alerts/${bruteAlert.id}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: adminCookie, 'X-CSRF-Token': csrf },
      body: JSON.stringify({ priority: 'Critical' }),
    });
    assert.equal(escRes.status, 201);
    const escJson = (await escRes.json()) as { incident: { id: number; status: string } };
    createdIncidentId = escJson.incident.id;
    assert.equal(escJson.incident.status, 'NEW');

    // 7. Add note, response action, and transition NEW -> INVESTIGATING -> CONTAINED -> RESOLVED
    const noteRes = await fetch(`${srv.baseUrl}/api/incidents/${createdIncidentId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: adminCookie, 'X-CSRF-Token': csrf },
      body: JSON.stringify({ note: 'Confirmed credential brute-force burst from 198.51.100.222.' }),
    });
    assert.equal(noteRes.status, 201);

    const actionRes = await fetch(`${srv.baseUrl}/api/incidents/${createdIncidentId}/actions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: adminCookie, 'X-CSRF-Token': csrf },
      body: JSON.stringify({
        action_type: 'Credential Reset',
        action_details: 'Forced password rotation for target_ops.',
      }),
    });
    assert.equal(actionRes.status, 201);

    for (const nextStatus of ['INVESTIGATING', 'CONTAINED', 'RESOLVED']) {
      const trRes = await fetch(`${srv.baseUrl}/api/incidents/${createdIncidentId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Cookie: adminCookie, 'X-CSRF-Token': csrf },
        body: JSON.stringify({
          status: nextStatus,
          resolution_summary: nextStatus === 'RESOLVED' ? 'Contained and verified.' : undefined,
        }),
      });
      assert.equal(trRes.status, 200);
    }

    // 8. Export CSV & PDF reports
    const csvRes = await fetch(`${srv.baseUrl}/api/reports/export/csv?type=incidents`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(csvRes.status, 200);
    const csvText = await csvRes.text();
    assert.equal(csvText.includes('INC-2026-'), true);

    const pdfRes = await fetch(`${srv.baseUrl}/api/reports/export/pdf?type=alerts`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(pdfRes.status, 200);
    const pdfBuf = Buffer.from(await pdfRes.arrayBuffer());
    assert.equal(pdfBuf.subarray(0, 4).toString(), '%PDF');
  } finally {
    await srv.close();
  }

  // 9. Restart server on same DB file to verify persistence
  const srv2 = await startTestServer(dbFile);
  try {
    const login2 = await fetch(`${srv2.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'admin@cloudsoc.local', password: 'Admin@CloudSOC2026!' }),
    });
    const cookie2 = extractCookie(login2);
    const incDetail = await fetch(`${srv2.baseUrl}/api/incidents/${createdIncidentId}`, {
      headers: { Cookie: cookie2 },
    });
    assert.equal(incDetail.status, 200);
    const incJson = (await incDetail.json()) as {
      incident: { status: string };
      notes: Array<unknown>;
      actions: Array<unknown>;
    };
    assert.equal(incJson.incident.status, 'RESOLVED');
    assert.equal(incJson.notes.length >= 2, true);
    assert.equal(incJson.actions.length, 1);
  } finally {
    await srv2.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Modules: Demo accounts, Threat Detection Engine API, and Audit Logs search/filter/CSV', async () => {
  const srv = await startTestServer();
  try {
    // 1. Admin demo login & Analyst demo login both work
    const adminLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'admin@cloudsoc.local', password: 'Admin@CloudSOC2026!' }),
    });
    assert.equal(adminLogin.status, 200);
    const adminCookie = extractCookie(adminLogin);

    const analystLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'analyst@cloudsoc.local', password: 'Analyst@CloudSOC2026!' }),
    });
    assert.equal(analystLogin.status, 200);
    const analystCookie = extractCookie(analystLogin);
    const analystData = (await analystLogin.json()) as { user: { role: string }; csrfToken: string };
    assert.equal(analystData.user.role, 'SECURITY_ANALYST');

    // 2. Threat Detection Engine API accessible to Analyst (read-only transparency) and Admin
    const rulesRes = await fetch(`${srv.baseUrl}/api/detection/rules`, {
      headers: { Cookie: analystCookie },
    });
    assert.equal(rulesRes.status, 200);
    const rulesJson = (await rulesRes.json()) as {
      rules: Array<{ rule_code: string; alerts_triggered_count: number }>;
      allowlistedIps: string[];
    };
    assert.equal(rulesJson.rules.length, 5);
    assert.equal(rulesJson.allowlistedIps.includes('10.20.0.10'), true);

    // Analyst cannot mutate detection rule thresholds (403 RBAC)
    const ruleMutateBlocked = await fetch(`${srv.baseUrl}/api/rules/1`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Cookie: analystCookie, 'X-CSRF-Token': analystData.csrfToken },
      body: JSON.stringify({ threshold: 99 }),
    });
    assert.equal(ruleMutateBlocked.status, 403);

    // 3. Audit Logs module: Admin sees all logs, Analyst sees scoped logs, CSV export works
    const adminAuditRes = await fetch(`${srv.baseUrl}/api/audit-logs?search=LOGIN_SUCCESS`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(adminAuditRes.status, 200);
    const adminAuditJson = (await adminAuditRes.json()) as {
      scope: string;
      logs: Array<{ action: string }>;
    };
    assert.equal(adminAuditJson.scope, 'all');
    assert.equal(adminAuditJson.logs.some((l) => l.action === 'LOGIN_SUCCESS'), true);

    const analystAuditRes = await fetch(`${srv.baseUrl}/api/audit-logs`, {
      headers: { Cookie: analystCookie },
    });
    assert.equal(analystAuditRes.status, 200);
    const analystAuditJson = (await analystAuditRes.json()) as { scope: string };
    assert.equal(analystAuditJson.scope, 'operational');

    const auditCsvRes = await fetch(`${srv.baseUrl}/api/audit-logs/export/csv`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(auditCsvRes.status, 200);
    const auditCsv = await auditCsvRes.text();
    assert.equal(auditCsv.startsWith('id,created_at,username,action'), true);

    // 4. Generate Demonstration Data endpoint tags rows with is_demo = 1
    const demoGenRes = await fetch(`${srv.baseUrl}/api/events/generate-demo-data`, {
      method: 'POST',
      headers: { Cookie: analystCookie, 'X-CSRF-Token': analystData.csrfToken },
    });
    assert.equal(demoGenRes.status, 201);
    const demoGenJson = (await demoGenRes.json()) as { eventsCreated: number; labeledAsDemo: boolean };
    assert.equal(demoGenJson.eventsCreated, 5);
    assert.equal(demoGenJson.labeledAsDemo, true);

    // 5. Malformed date parameters on /api/events and /api/reports do not throw 500
    const badDateEvents = await fetch(`${srv.baseUrl}/api/events?startDate=not-a-date&endDate=invalid`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(badDateEvents.status, 200);
    const badDateReport = await fetch(`${srv.baseUrl}/api/reports?type=events&startDate=bad-date`, {
      headers: { Cookie: adminCookie },
    });
    assert.equal(badDateReport.status, 200);

    // 6. Localhost failed login attempts (without simulated_ip) also trigger RULE-001 brute-force alert
    for (let i = 1; i <= 10; i++) {
      const r = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: 'local_brute_probe', password: `WrongPass${i}!` }),
      });
      assert.equal(r.status, 401);
    }
    const localAlertsRes = await fetch(`${srv.baseUrl}/api/alerts?search=local_brute_probe`, {
      headers: { Cookie: adminCookie },
    });
    const localAlertsJson = (await localAlertsRes.json()) as { alerts: Array<{ rule_code: string; severity: string }> };
    assert.equal(localAlertsJson.alerts.some((a) => a.rule_code === 'RULE-001' && a.severity === 'Critical'), true);
  } finally {
    await srv.close();
  }
});

test('Auth: Untrusted HTTPS proxy header ignored; Bearer API sessions + CSRF + RBAC + logout', async () => {
  const srv = await startTestServer();
  try {
    // 1. Untrusted X-Forwarded-Proto must NOT change cookie security flags; Bearer session remains available for API clients
    const adminLoginRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Forwarded-Proto': 'https',
      },
      body: JSON.stringify({ identifier: 'admin@cloudsoc.local', password: 'Admin@CloudSOC2026!' }),
    });
    assert.equal(adminLoginRes.status, 200);
    const setCookieHeader = adminLoginRes.headers.get('set-cookie') || '';
    assert.equal(/SameSite=Lax/i.test(setCookieHeader), true);
    assert.equal(/;\s*Secure/i.test(setCookieHeader), false);
    const adminData = (await adminLoginRes.json()) as {
      user: { role: string };
      csrfToken: string;
      sessionToken: string;
    };
    assert.equal(adminData.user.role, 'ADMIN');
    assert.equal(typeof adminData.sessionToken, 'string');
    assert.equal(adminData.sessionToken.length > 20, true);

    // 2. Simulate browser with third-party iframe cookies completely blocked (no Cookie header, Bearer only)
    const dashRes = await fetch(`${srv.baseUrl}/api/dashboard?days=7`, {
      headers: { Authorization: `Bearer ${adminData.sessionToken}` },
    });
    assert.equal(dashRes.status, 200);

    const sessionRes = await fetch(`${srv.baseUrl}/api/auth/session`, {
      headers: { Authorization: `Bearer ${adminData.sessionToken}` },
    });
    assert.equal(sessionRes.status, 200);
    const sessionJson = (await sessionRes.json()) as { authenticated: boolean; user: { role: string } };
    assert.equal(sessionJson.authenticated, true);
    assert.equal(sessionJson.user.role, 'ADMIN');

    // 3. Mutating request via Bearer still enforces CSRF token
    const noCsrfRes = await fetch(`${srv.baseUrl}/api/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${adminData.sessionToken}`,
      },
      body: JSON.stringify({
        source_ip: '198.51.100.44',
        username: 'bearer_probe',
        event_type: 'Successful Login',
        description: 'Should fail without CSRF',
        severity: 'Low',
      }),
    });
    assert.equal(noCsrfRes.status, 403);

    // 4. Logout invalidates the Bearer session token in SQLite
    const logoutRes = await fetch(`${srv.baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminData.sessionToken}`,
        'X-CSRF-Token': adminData.csrfToken,
      },
    });
    assert.equal(logoutRes.status, 200);

    const afterLogoutDash = await fetch(`${srv.baseUrl}/api/dashboard?days=7`, {
      headers: { Authorization: `Bearer ${adminData.sessionToken}` },
    });
    assert.equal(afterLogoutDash.status, 401);

    // 5. Analyst Demo via Bearer is allowed on dashboard but blocked (403) on admin endpoints
    const analystRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'analyst@cloudsoc.local', password: 'Analyst@CloudSOC2026!' }),
    });
    assert.equal(analystRes.status, 200);
    const analystData = (await analystRes.json()) as { user: { role: string }; sessionToken: string };
    assert.equal(analystData.user.role, 'SECURITY_ANALYST');

    const analystDash = await fetch(`${srv.baseUrl}/api/dashboard?days=7`, {
      headers: { Authorization: `Bearer ${analystData.sessionToken}` },
    });
    assert.equal(analystDash.status, 200);

    const analystUsersBlocked = await fetch(`${srv.baseUrl}/api/users`, {
      headers: { Authorization: `Bearer ${analystData.sessionToken}` },
    });
    assert.equal(analystUsersBlocked.status, 403);
  } finally {
    await srv.close();
  }
});
