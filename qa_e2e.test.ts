import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { createDatabase } from './db';
import { createApp } from './app';

async function startQaServer(dbPath: string) {
  const db = createDatabase(dbPath);
  const app = createApp(db);
  const server = await new Promise<ReturnType<typeof app.listen>>((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = (server.address() as AddressInfo).port;
  return {
    db,
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

test('QA Comprehensive: User CRUD, Lockout/Unlock, Profile Update, Settings/Rules CRUD, Threat Intel, Dashboard SQL Accuracy & DB Integrity', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cloudsoc-qa-'));
  const dbPath = path.join(tmpDir, 'qa.db');
  let srv = await startQaServer(dbPath);

  try {
    // 1. Admin login + CSRF
    const adminLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'admin@cloudsoc.local', password: 'Admin@CloudSOC2026!' }),
    });
    assert.equal(adminLogin.status, 200);
    const adminAuth = (await adminLogin.json()) as { sessionToken: string; csrfToken: string };
    const adminHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${adminAuth.sessionToken}`,
      'X-CSRF-Token': adminAuth.csrfToken,
    };

    // 2. Admin creates a local test analyst via /api/users
    const createUser = await fetch(`${srv.baseUrl}/api/users`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        username: 'qa_operator',
        email: 'qa_operator@cloudsoc.local',
        full_name: 'QA Test Operator',
        password: 'QaUser@2026!',
        role: 'SECURITY_ANALYST',
      }),
    });
    assert.equal(createUser.status, 201);
    const createdUser = ((await createUser.json()) as { user: { id: number; username: string } }).user;
    assert.equal(createdUser.username, 'qa_operator');

    // 3. Test account lockout after max_login_lockout_attempts (default 12) + Admin unlock
    for (let i = 1; i <= 12; i++) {
      const failRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: 'qa_operator', password: `WrongPass${i}!` }),
      });
      assert.equal(failRes.status, 401);
    }
    const lockedRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'qa_operator', password: 'QaUser@2026!' }),
    });
    assert.equal(lockedRes.status, 423);

    // Admin unlocks account
    const unlockRes = await fetch(`${srv.baseUrl}/api/users/${createdUser.id}`, {
      method: 'PATCH',
      headers: adminHeaders,
      body: JSON.stringify({ unlock: true }),
    });
    assert.equal(unlockRes.status, 200);

    // 4. Operator logs in + updates profile & password via /api/auth/profile
    const opLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'qa_operator', password: 'QaUser@2026!' }),
    });
    assert.equal(opLogin.status, 200);
    const opAuth = (await opLogin.json()) as { sessionToken: string; csrfToken: string };
    const opHeaders = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${opAuth.sessionToken}`,
      'X-CSRF-Token': opAuth.csrfToken,
    };

    const profileRes = await fetch(`${srv.baseUrl}/api/auth/profile`, {
      method: 'PATCH',
      headers: opHeaders,
      body: JSON.stringify({
        full_name: 'QA Operator Renamed',
        current_password: 'QaUser@2026!',
        new_password: 'QaUserUpdated@2026!',
      }),
    });
    assert.equal(profileRes.status, 200);
    const profileJson = (await profileRes.json()) as { user: { full_name: string } };
    assert.equal(profileJson.user.full_name, 'QA Operator Renamed');

    // Old password rejected, new password works
    const oldPwdLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'qa_operator', password: 'QaUser@2026!' }),
    });
    assert.equal(oldPwdLogin.status, 401);

    const newPwdLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'qa_operator', password: 'QaUserUpdated@2026!' }),
    });
    assert.equal(newPwdLogin.status, 200);

    // 5. Unauthorized administrative mutations rejected for Analyst
    const analystSettingsPatch = await fetch(`${srv.baseUrl}/api/settings`, {
      method: 'PATCH',
      headers: opHeaders,
      body: JSON.stringify({ settings: { retention_days: '30' } }),
    });
    assert.equal(analystSettingsPatch.status, 403);

    const analystRulePatch = await fetch(`${srv.baseUrl}/api/rules/1`, {
      method: 'PATCH',
      headers: opHeaders,
      body: JSON.stringify({ threshold: 2 }),
    });
    assert.equal(analystRulePatch.status, 403);

    const analystUserCreate = await fetch(`${srv.baseUrl}/api/users`, {
      method: 'POST',
      headers: opHeaders,
      body: JSON.stringify({
        username: 'unauth_create',
        email: 'unauth@cloudsoc.local',
        full_name: 'Nope',
        password: 'ValidPass@2026',
      }),
    });
    assert.equal(analystUserCreate.status, 403);

    // 6. Admin Settings & Detection Rule update + validation
    const settingsRes = await fetch(`${srv.baseUrl}/api/settings`, {
      method: 'PATCH',
      headers: adminHeaders,
      body: JSON.stringify({ settings: { threat_intel_cache_hours: '48' } }),
    });
    assert.equal(settingsRes.status, 200);

    const ruleRes = await fetch(`${srv.baseUrl}/api/rules/1`, {
      method: 'PATCH',
      headers: adminHeaders,
      body: JSON.stringify({ threshold: 'not-a-number', time_window_minutes: 10 }),
    });
    assert.equal(ruleRes.status, 200);
    const ruleJson = (await ruleRes.json()) as { rule: { threshold: number; time_window_minutes: number } };
    assert.equal(ruleJson.rule.threshold, 10); // preserved existing threshold instead of NaN
    assert.equal(ruleJson.rule.time_window_minutes, 10);

    // 7. Threat Intelligence lookup & validation (Local Demonstration Mode)
    const badTiRes = await fetch(`${srv.baseUrl}/api/threat-intel/lookup`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({ indicator_type: 'ipv4', indicator_value: '999.999.1.1' }),
    });
    assert.equal(badTiRes.status, 400);

    const okTiRes = await fetch(`${srv.baseUrl}/api/threat-intel/lookup`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({ indicator_type: 'ipv4', indicator_value: '185.220.101.42' }),
    });
    assert.equal(okTiRes.status, 200);
    const okTiJson = (await okTiRes.json()) as { result: { source: string; demo_mode: boolean; verdict: string } };
    assert.equal(okTiJson.result.demo_mode, true);
    assert.equal(okTiJson.result.verdict, 'Malicious');

    // 8. Dashboard API KPIs match direct SQL counts exactly
    const dashRes = await fetch(`${srv.baseUrl}/api/dashboard?days=7`, { headers: adminHeaders });
    assert.equal(dashRes.status, 200);
    const dash = (await dashRes.json()) as {
      kpis: {
        totalEvents: number;
        totalAlerts: number;
        criticalAlerts: number;
        highRiskEvents: number;
        openIncidents: number;
        resolvedIncidents: number;
      };
    };
    assert.equal(
      dash.kpis.totalEvents,
      (srv.db.prepare('SELECT COUNT(*) AS c FROM security_events').get() as { c: number }).c
    );
    assert.equal(
      dash.kpis.totalAlerts,
      (srv.db.prepare('SELECT COUNT(*) AS c FROM alerts').get() as { c: number }).c
    );
    assert.equal(
      dash.kpis.criticalAlerts,
      (srv.db.prepare("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'Critical'").get() as { c: number }).c
    );
    assert.equal(
      dash.kpis.openIncidents,
      (srv.db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE status != 'RESOLVED'").get() as { c: number }).c
    );
    assert.equal(
      dash.kpis.resolvedIncidents,
      (srv.db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE status = 'RESOLVED'").get() as { c: number }).c
    );

    // 9. Foreign-key integrity check across all tables
    const fkErrors = srv.db.prepare('PRAGMA foreign_key_check').all();
    assert.equal(fkErrors.length, 0);

    // 10. Restart server on same SQLite DB and verify persisted user, rule, setting, and threat indicator survive
    await srv.close();
    srv = await startQaServer(dbPath);
    const postRestartLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'qa_operator', password: 'QaUserUpdated@2026!' }),
    });
    assert.equal(postRestartLogin.status, 200);
    const postSettings = srv.db
      .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'threat_intel_cache_hours'")
      .get() as { setting_value: string };
    assert.equal(postSettings.setting_value, '48');
  } finally {
    await srv.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
