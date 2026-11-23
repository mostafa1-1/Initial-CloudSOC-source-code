import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import bcrypt from 'bcryptjs';

export interface ResolvedDatabaseConfig {
  mode: 'sqlite';
  sqlitePath: string;
  externalDatabaseUrlDetected: boolean;
  notice?: string;
}

export function resolveDatabaseConfig(dbPath?: string): ResolvedDatabaseConfig {
  if (dbPath && dbPath.trim()) {
    return {
      mode: 'sqlite',
      sqlitePath: dbPath.trim(),
      externalDatabaseUrlDetected: false,
    };
  }

  const rawUrl = (process.env.DATABASE_URL || '').trim();
  const rawPath = (process.env.DATABASE_PATH || '').trim();
  const defaultPath = path.resolve(process.cwd(), 'data', 'cloudsoc.db');

  if (rawUrl) {
    const lower = rawUrl.toLowerCase();
    if (lower === 'sqlite:///:memory:' || lower === ':memory:') {
      return {
        mode: 'sqlite',
        sqlitePath: ':memory:',
        externalDatabaseUrlDetected: false,
      };
    }
    if (lower.startsWith('sqlite:///')) {
      const parsed = rawUrl.slice('sqlite:///'.length);
      return {
        mode: 'sqlite',
        sqlitePath: path.isAbsolute(parsed) ? parsed : path.resolve(process.cwd(), parsed),
        externalDatabaseUrlDetected: false,
      };
    }
    if (lower.startsWith('sqlite://')) {
      const parsed = rawUrl.slice('sqlite://'.length);
      return {
        mode: 'sqlite',
        sqlitePath: parsed === ':memory:' ? ':memory:' : path.resolve(process.cwd(), parsed),
        externalDatabaseUrlDetected: false,
      };
    }
    if (lower.startsWith('file:')) {
      const parsed = rawUrl.slice('file:'.length).split('?')[0];
      return {
        mode: 'sqlite',
        sqlitePath:
          parsed === ':memory:'
            ? ':memory:'
            : path.isAbsolute(parsed)
              ? parsed
              : path.resolve(process.cwd(), parsed),
        externalDatabaseUrlDetected: false,
      };
    }
    if (lower.startsWith('postgres://') || lower.startsWith('postgresql://')) {
      const fallbackPath = rawPath ? path.resolve(process.cwd(), rawPath) : defaultPath;
      return {
        mode: 'sqlite',
        sqlitePath: fallbackPath,
        externalDatabaseUrlDetected: true,
        notice:
          'PostgreSQL DATABASE_URL detected; using local SQLite runtime database (see CloudSOC/migrations/001_initial_postgresql.sql for cloud PostgreSQL deployment).',
      };
    }
  }

  return {
    mode: 'sqlite',
    sqlitePath: rawPath ? (rawPath === ':memory:' ? ':memory:' : path.resolve(process.cwd(), rawPath)) : defaultPath,
    externalDatabaseUrlDetected: false,
  };
}

interface MigrationDefinition {
  version: number;
  name: string;
  sql: string;
}

const MIGRATIONS: MigrationDefinition[] = [
  {
    version: 1,
    name: '001_initial_schema',
    sql: `
      CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role_id INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        failed_login_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until TEXT,
        last_login_at TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (role_id) REFERENCES roles(id)
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_hash TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL,
        csrf_token TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_uid TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        username TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        user_agent TEXT NOT NULL DEFAULT '',
        detection_status TEXT NOT NULL DEFAULT 'Processed',
        rule_triggered TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS detection_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        event_type_target TEXT NOT NULL,
        threshold INTEGER NOT NULL DEFAULT 1,
        time_window_minutes INTEGER NOT NULL DEFAULT 5,
        severity TEXT NOT NULL,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        explanation_template TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
      );

      CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_uid TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        rule_id INTEGER NOT NULL,
        trigger_event_id INTEGER,
        source_ip TEXT NOT NULL,
        target_username TEXT NOT NULL,
        assigned_to INTEGER,
        investigation_notes TEXT NOT NULL DEFAULT '',
        explanation TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 1,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (rule_id) REFERENCES detection_rules(id),
        FOREIGN KEY (trigger_event_id) REFERENCES security_events(id) ON DELETE SET NULL,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_uid TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        priority TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'NEW',
        alert_id INTEGER,
        assigned_to INTEGER,
        created_by INTEGER NOT NULL,
        resolution_summary TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        closed_at TEXT,
        FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE SET NULL,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (created_by) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS incident_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        note TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS response_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        performed_by INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        action_details TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Completed',
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
        FOREIGN KEY (performed_by) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS threat_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        reputation_score INTEGER NOT NULL DEFAULT 0,
        verdict TEXT NOT NULL,
        source TEXT NOT NULL,
        raw_summary TEXT NOT NULL,
        queried_by INTEGER,
        cached_until TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (queried_by) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT NOT NULL UNIQUE,
        setting_value TEXT NOT NULL,
        description TEXT NOT NULL,
        updated_by INTEGER,
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
        FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
      );
    `,
  },
  {
    version: 2,
    name: '002_indexes_and_audit_filters',
    sql: `
      CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
      CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);
      CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
      CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
      CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
      CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
      CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
      CREATE INDEX IF NOT EXISTS idx_threat_lookup ON threat_indicators(indicator_type, indicator_value);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_logs(resource_type);
    `,
  },
  {
    version: 3,
    name: '003_demo_data_labeling_and_allowlist',
    sql: `
      ALTER TABLE security_events ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE alerts ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE incidents ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0;

      UPDATE security_events SET is_demo = 1 WHERE event_uid <= 'EVT-2026-0014';
      UPDATE alerts SET is_demo = 1 WHERE alert_uid <= 'ALT-2026-0004';
      UPDATE incidents SET is_demo = 1 WHERE incident_uid <= 'INC-2026-0002';

      UPDATE system_settings
      SET setting_value = '10.20.0.10, 10.20.0.11'
      WHERE setting_key = 'allowlisted_ips' AND setting_value = '127.0.0.1, ::1';
    `,
  },
  {
    version: 4,
    name: '004_firebase_auth_identity_link',
    sql: `
      ALTER TABLE users ADD COLUMN firebase_uid TEXT;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_users_firebase_uid
        ON users(firebase_uid) WHERE firebase_uid IS NOT NULL;
    `,
  },
];

export function runMigrations(db: DatabaseSync): number[] {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
  `);

  const appliedRows = db.prepare('SELECT version FROM schema_migrations').all() as Array<{ version: number }>;
  const applied = new Set(appliedRows.map((r) => r.version));
  const newlyApplied: number[] = [];

  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    db.exec('BEGIN;');
    try {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_migrations (version, name) VALUES (?, ?)').run(
        migration.version,
        migration.name
      );
      db.exec('COMMIT;');
      newlyApplied.push(migration.version);
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }

  return newlyApplied;
}

export function createDatabase(dbPath?: string): DatabaseSync {
  const config = resolveDatabaseConfig(dbPath);
  if (config.notice) {
    console.info(`[CloudSOC DB] ${config.notice}`);
  }
  if (config.sqlitePath !== ':memory:') {
    fs.mkdirSync(path.dirname(config.sqlitePath), { recursive: true });
  }
  const db = new DatabaseSync(config.sqlitePath);
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA journal_mode = WAL;');
  initSchema(db);
  seedInitialData(db);
  return db;
}

export function initSchema(db: DatabaseSync): void {
  runMigrations(db);
}

function ensureDemoAccounts(db: DatabaseSync): void {
  db.prepare('INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)').run(
    'ADMIN',
    'Full platform administration, user management, detection rules, and security operations.'
  );
  db.prepare('INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)').run(
    'SECURITY_ANALYST',
    'Security event monitoring, threat intelligence, alert triage, incident response, and reporting.'
  );

  const adminRole = db.prepare("SELECT id FROM roles WHERE name = 'ADMIN'").get() as { id: number };
  const analystRole = db.prepare("SELECT id FROM roles WHERE name = 'SECURITY_ANALYST'").get() as {
    id: number;
  };

  const existingAdmin = db
    .prepare("SELECT id FROM users WHERE LOWER(email) = 'admin@cloudsoc.local' OR LOWER(username) = 'soc_admin'")
    .get();
  if (!existingAdmin) {
    const adminHash = bcrypt.hashSync('Admin@CloudSOC2026!', 10);
    db.prepare(
      'INSERT INTO users (username, email, full_name, password_hash, role_id) VALUES (?, ?, ?, ?, ?)'
    ).run('soc_admin', 'admin@cloudsoc.local', 'Lead SOC Administrator', adminHash, adminRole.id);
  }

  const existingAnalyst = db
    .prepare("SELECT id FROM users WHERE LOWER(email) = 'analyst@cloudsoc.local' OR LOWER(username) = 'sec_analyst'")
    .get();
  if (!existingAnalyst) {
    const analystHash = bcrypt.hashSync('Analyst@CloudSOC2026!', 10);
    db.prepare(
      'INSERT INTO users (username, email, full_name, password_hash, role_id) VALUES (?, ?, ?, ?, ?)'
    ).run('sec_analyst', 'analyst@cloudsoc.local', 'Senior Security Analyst', analystHash, analystRole.id);
  }
}

function seedInitialData(db: DatabaseSync): void {
  const roleCount = (db.prepare('SELECT COUNT(*) as count FROM roles').get() as { count: number }).count;
  if (roleCount > 0) {
    ensureDemoAccounts(db);
    return;
  }

  db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)').run(
    'ADMIN',
    'Full platform administration, user management, detection rules, and security operations.'
  );
  db.prepare('INSERT INTO roles (name, description) VALUES (?, ?)').run(
    'SECURITY_ANALYST',
    'Security event monitoring, threat intelligence, alert triage, incident response, and reporting.'
  );

  const adminRole = db.prepare("SELECT id FROM roles WHERE name = 'ADMIN'").get() as { id: number };
  const analystRole = db.prepare("SELECT id FROM roles WHERE name = 'SECURITY_ANALYST'").get() as {
    id: number;
  };

  const adminHash = bcrypt.hashSync('Admin@CloudSOC2026!', 10);
  const analystHash = bcrypt.hashSync('Analyst@CloudSOC2026!', 10);

  const adminRes = db
    .prepare(
      'INSERT INTO users (username, email, full_name, password_hash, role_id) VALUES (?, ?, ?, ?, ?)'
    )
    .run('soc_admin', 'admin@cloudsoc.local', 'Lead SOC Administrator', adminHash, adminRole.id);
  const analystRes = db
    .prepare(
      'INSERT INTO users (username, email, full_name, password_hash, role_id) VALUES (?, ?, ?, ?, ?)'
    )
    .run(
      'sec_analyst',
      'analyst@cloudsoc.local',
      'Senior Security Analyst',
      analystHash,
      analystRole.id
    );

  const adminId = Number(adminRes.lastInsertRowid);
  const analystId = Number(analystRes.lastInsertRowid);

  // 5 Configurable Detection Rules
  const insertRule = db.prepare(`
    INSERT INTO detection_rules (rule_code, name, description, event_type_target, threshold, time_window_minutes, severity, is_enabled, explanation_template)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertRule.run(
    'RULE-001',
    'Brute-Force Authentication Attempt',
    'Detects 10 or more failed login events from a single source IP or targeting the same user within a 5-minute sliding window.',
    'Failed Login',
    10,
    5,
    'Critical',
    1,
    'High-velocity failed login burst exceeding configured threshold.'
  );
  insertRule.run(
    'RULE-002',
    'Repeated Authentication Failures',
    'Flags 4 or more repeated failed login attempts inside 10 minutes before reaching full brute-force volume.',
    'Failed Login',
    4,
    10,
    'High',
    1,
    'Repeated authentication failures indicating credential guessing.'
  );
  insertRule.run(
    'RULE-003',
    'Unauthorized Access Probe',
    'Triggers when 2 or more unauthorized endpoint or privilege escalation attempts occur from one IP within 15 minutes.',
    'Unauthorized Access',
    2,
    15,
    'High',
    1,
    'Repeated HTTP 403/unauthorized resource probes detected.'
  );
  insertRule.run(
    'RULE-004',
    'Suspicious IP Reputation Activity',
    'Correlates incoming event source IPs against cached malicious or suspicious threat intelligence indicators.',
    '*',
    1,
    60,
    'High',
    1,
    'Activity originated from an IP flagged in threat intelligence.'
  );
  insertRule.run(
    'RULE-005',
    'Unusual Login Activity',
    'Detects Suspicious Access alerts or successful logins from previously unseen IP addresses for an account.',
    'Suspicious Access',
    1,
    30,
    'Medium',
    1,
    'Login or access from unfamiliar source network.'
  );

  // System Settings
  const insertSetting = db.prepare(
    'INSERT INTO system_settings (setting_key, setting_value, description, updated_by) VALUES (?, ?, ?, ?)'
  );
  insertSetting.run(
    'allowlisted_ips',
    '10.20.0.10, 10.20.0.11',
    'Comma-separated IPv4/IPv6 addresses excluded from automated alert generation to prevent false positives.',
    adminId
  );
  insertSetting.run(
    'max_login_lockout_attempts',
    '12',
    'Number of consecutive failed authentication attempts before temporary account lockout.',
    adminId
  );
  insertSetting.run(
    'threat_intel_cache_hours',
    '24',
    'Duration in hours to cache external or demonstration threat intelligence lookups.',
    adminId
  );
  insertSetting.run(
    'auto_refresh_seconds',
    '30',
    'SOC dashboard polling interval in seconds for near-real-time telemetry updates.',
    adminId
  );

  // Threat Intelligence Indicators (Local Demonstration Baseline)
  const tomorrow = new Date(Date.now() + 7 * 24 * 3600_000).toISOString();
  const insertIntel = db.prepare(`
    INSERT INTO threat_indicators (indicator_type, indicator_value, reputation_score, verdict, source, raw_summary, queried_by, cached_until)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertIntel.run(
    'ipv4',
    '185.220.101.42',
    92,
    'Malicious',
    'Local Demonstration',
    JSON.stringify({
      abuseConfidenceScore: 92,
      category: 'Credential Stuffing / Tor Exit Node',
      countryCode: 'DE',
      reports: 148,
      note: 'Simulated local threat feed record (no live external key configured).',
    }),
    analystId,
    tomorrow
  );
  insertIntel.run(
    'ipv4',
    '45.155.205.91',
    84,
    'Malicious',
    'Local Demonstration',
    JSON.stringify({
      abuseConfidenceScore: 84,
      category: 'SSH & Web Auth Brute-Force Scanner',
      countryCode: 'NL',
      reports: 93,
      note: 'Simulated local threat feed record.',
    }),
    analystId,
    tomorrow
  );
  insertIntel.run(
    'domain',
    'auth-verify-cloud-login.example.net',
    78,
    'Suspicious',
    'Local Demonstration',
    JSON.stringify({
      maliciousEngines: 6,
      category: 'Credential Phishing Lookalike Domain',
      registrar: 'Simulated Registry',
    }),
    analystId,
    tomorrow
  );

  // Historical Security Events across last 6 days for real analytics
  const now = Date.now();
  const hoursAgo = (h: number) => new Date(now - h * 3600_000).toISOString();
  const seedEvents: Array<{
    uid: string;
    ts: string;
    ip: string;
    user: string;
    type: string;
    desc: string;
    sev: string;
    ua: string;
    status: string;
    rule: string | null;
  }> = [
    {
      uid: 'EVT-2026-0001',
      ts: hoursAgo(118),
      ip: '10.20.4.15',
      user: 'soc_admin',
      type: 'Successful Login',
      desc: 'Administrator authenticated cleanly from corporate VPN subnet.',
      sev: 'Low',
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      status: 'Cleared',
      rule: null,
    },
    {
      uid: 'EVT-2026-0002',
      ts: hoursAgo(96),
      ip: '10.20.4.22',
      user: 'sec_analyst',
      type: 'Administrative Activity',
      desc: 'Updated detection rule retention window and exported weekly audit baseline.',
      sev: 'Low',
      ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      status: 'Cleared',
      rule: null,
    },
    {
      uid: 'EVT-2026-0003',
      ts: hoursAgo(78),
      ip: '198.51.100.44',
      user: 'm.chen',
      type: 'Failed Login',
      desc: 'Invalid password supplied during portal login.',
      sev: 'Medium',
      ua: 'Mozilla/5.0 (X11; Linux x86_64)',
      status: 'Processed',
      rule: null,
    },
    {
      uid: 'EVT-2026-0004',
      ts: hoursAgo(72),
      ip: '198.51.100.44',
      user: 'm.chen',
      type: 'Successful Login',
      desc: 'User completed MFA verification after prior failed attempt.',
      sev: 'Low',
      ua: 'Mozilla/5.0 (X11; Linux x86_64)',
      status: 'Cleared',
      rule: null,
    },
    {
      uid: 'EVT-2026-0005',
      ts: hoursAgo(54),
      ip: '45.155.205.91',
      user: 'root',
      type: 'Unauthorized Access',
      desc: 'Blocked attempt to access /api/users without administrative privileges.',
      sev: 'High',
      ua: 'python-requests/2.31.0',
      status: 'Alert Triggered',
      rule: 'RULE-004',
    },
    {
      uid: 'EVT-2026-0006',
      ts: hoursAgo(53),
      ip: '45.155.205.91',
      user: 'root',
      type: 'Unauthorized Access',
      desc: 'Repeated unauthorized access probe against /api/settings endpoint.',
      sev: 'High',
      ua: 'python-requests/2.31.0',
      status: 'Alert Triggered',
      rule: 'RULE-003',
    },
    {
      uid: 'EVT-2026-0007',
      ts: hoursAgo(32),
      ip: '185.220.101.42',
      user: 'ops_deploy',
      type: 'Suspicious Access',
      desc: 'Session token anomaly observed from known exit-node IP range.',
      sev: 'High',
      ua: 'curl/8.4.0',
      status: 'Alert Triggered',
      rule: 'RULE-005',
    },
    {
      uid: 'EVT-2026-0008',
      ts: hoursAgo(26),
      ip: '10.20.8.11',
      user: 'sec_analyst',
      type: 'Successful Login',
      desc: 'Morning shift SOC analyst sign-in verified.',
      sev: 'Low',
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      status: 'Cleared',
      rule: null,
    },
    {
      uid: 'EVT-2026-0009',
      ts: hoursAgo(14),
      ip: '203.0.113.77',
      user: 'finance_bot',
      type: 'Failed Login',
      desc: 'Repeated authentication failure on service account.',
      sev: 'Medium',
      ua: 'Go-http-client/1.1',
      status: 'Processed',
      rule: null,
    },
    {
      uid: 'EVT-2026-0010',
      ts: hoursAgo(13.9),
      ip: '203.0.113.77',
      user: 'finance_bot',
      type: 'Failed Login',
      desc: 'Repeated authentication failure on service account.',
      sev: 'Medium',
      ua: 'Go-http-client/1.1',
      status: 'Processed',
      rule: null,
    },
    {
      uid: 'EVT-2026-0011',
      ts: hoursAgo(13.85),
      ip: '203.0.113.77',
      user: 'finance_bot',
      type: 'Failed Login',
      desc: 'Repeated authentication failure on service account.',
      sev: 'Medium',
      ua: 'Go-http-client/1.1',
      status: 'Processed',
      rule: null,
    },
    {
      uid: 'EVT-2026-0012',
      ts: hoursAgo(13.8),
      ip: '203.0.113.77',
      user: 'finance_bot',
      type: 'Failed Login',
      desc: 'Repeated authentication failure on service account.',
      sev: 'High',
      ua: 'Go-http-client/1.1',
      status: 'Alert Triggered',
      rule: 'RULE-002',
    },
    {
      uid: 'EVT-2026-0013',
      ts: hoursAgo(6),
      ip: '10.20.4.15',
      user: 'soc_admin',
      type: 'Administrative Activity',
      desc: 'Reviewed system security settings and rotated threat feed cache.',
      sev: 'Low',
      ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      status: 'Cleared',
      rule: null,
    },
    {
      uid: 'EVT-2026-0014',
      ts: hoursAgo(2),
      ip: '185.220.101.42',
      user: 'svc_backup',
      type: 'Multiple Failed Logins',
      desc: 'Automated credential spray burst recorded across backup service account.',
      sev: 'Critical',
      ua: 'Hydra/9.5',
      status: 'Alert Triggered',
      rule: 'RULE-001',
    },
  ];

  const insertEvent = db.prepare(`
    INSERT INTO security_events (event_uid, timestamp, source_ip, username, event_type, description, severity, user_agent, detection_status, rule_triggered, is_demo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);
  const eventIds: number[] = [];
  for (const e of seedEvents) {
    const res = insertEvent.run(
      e.uid,
      e.ts,
      e.ip,
      e.user,
      e.type,
      e.desc,
      e.sev,
      e.ua,
      e.status,
      e.rule
    );
    eventIds.push(Number(res.lastInsertRowid));
  }

  const rule1 = db.prepare("SELECT id FROM detection_rules WHERE rule_code = 'RULE-001'").get() as {
    id: number;
  };
  const rule2 = db.prepare("SELECT id FROM detection_rules WHERE rule_code = 'RULE-002'").get() as {
    id: number;
  };
  const rule3 = db.prepare("SELECT id FROM detection_rules WHERE rule_code = 'RULE-003'").get() as {
    id: number;
  };
  const rule5 = db.prepare("SELECT id FROM detection_rules WHERE rule_code = 'RULE-005'").get() as {
    id: number;
  };

  // Seed 4 realistic alerts across severities and statuses (labeled is_demo = 1)
  const insertAlert = db.prepare(`
    INSERT INTO alerts (alert_uid, title, description, severity, status, rule_id, trigger_event_id, source_ip, target_username, assigned_to, investigation_notes, explanation, event_count, window_start, window_end, created_at, updated_at, is_demo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);

  const alert1Id = Number(
    insertAlert.run(
      'ALT-2026-0001',
      'Brute-Force Attempt Detected from 185.220.101.42',
      '12 rapid failed login attempts observed targeting backup service account svc_backup.',
      'Critical',
      'Investigating',
      rule1.id,
      eventIds[13],
      '185.220.101.42',
      'svc_backup',
      analystId,
      'Correlated with Threat Intel: 185.220.101.42 has reputation score 92/100.',
      'Rule RULE-001 triggered because 12 failed authentication events exceeded the threshold of 10 within 5 minutes.',
      12,
      hoursAgo(2.1),
      hoursAgo(2),
      hoursAgo(2),
      hoursAgo(2)
    ).lastInsertRowid
  );

  const alert2Id = Number(
    insertAlert.run(
      'ALT-2026-0002',
      'Unauthorized Access Attempts from 45.155.205.91',
      'Repeated HTTP 403 unauthorized endpoint probes targeting admin configuration routes.',
      'High',
      'Resolved',
      rule3.id,
      eventIds[5],
      '45.155.205.91',
      'root',
      analystId,
      'Verified WAF rate limiting blocked follow-up requests; escalated and contained.',
      'Rule RULE-003 matched 2 Unauthorized Access events within 15 minutes.',
      2,
      hoursAgo(53.2),
      hoursAgo(53),
      hoursAgo(53),
      hoursAgo(48)
    ).lastInsertRowid
  );

  insertAlert.run(
    'ALT-2026-0003',
    'Repeated Authentication Failures (203.0.113.77)',
    '4 repeated login failures detected for user finance_bot within 10 minutes.',
    'High',
    'Acknowledged',
    rule2.id,
    eventIds[11],
    '203.0.113.77',
    'finance_bot',
    adminId,
    'Checking if scheduled CI job used an expired service token.',
    'Rule RULE-002 detected 4 failed login attempts (threshold: 4 in 10 min).',
    4,
    hoursAgo(14),
    hoursAgo(13.8),
    hoursAgo(13.8),
    hoursAgo(13.8)
  );

  insertAlert.run(
    'ALT-2026-0004',
    'Unusual Login Activity for ops_deploy',
    'Suspicious access pattern from Tor exit node 185.220.101.42.',
    'Medium',
    'New',
    rule5.id,
    eventIds[6],
    '185.220.101.42',
    'ops_deploy',
    null,
    '',
    'Rule RULE-005 flagged anomalous user-agent and external exit-node origin.',
    1,
    hoursAgo(32.5),
    hoursAgo(32),
    hoursAgo(32),
    hoursAgo(32)
  );

  // Seed 2 realistic incidents (1 active INVESTIGATING, 1 RESOLVED, labeled is_demo = 1)
  const insertIncident = db.prepare(`
    INSERT INTO incidents (incident_uid, title, description, priority, status, alert_id, assigned_to, created_by, resolution_summary, closed_at, is_demo)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
  `);

  const inc1Id = Number(
    insertIncident.run(
      'INC-2026-0001',
      'Credential Brute-Force Attack Against svc_backup',
      'Investigating high-velocity credential spray originating from Tor exit IP 185.220.101.42.',
      'Critical',
      'INVESTIGATING',
      alert1Id,
      analystId,
      adminId,
      '',
      null
    ).lastInsertRowid
  );

  const inc2Id = Number(
    insertIncident.run(
      'INC-2026-0002',
      'Automated Admin Route Reconnaissance (45.155.205.91)',
      'External scanner probed privileged administrative API routes and received HTTP 403 denials.',
      'High',
      'RESOLVED',
      alert2Id,
      analystId,
      analystId,
      'Confirmed RBAC middleware denied all probes; source IP documented for perimeter ACL review.',
      hoursAgo(48)
    ).lastInsertRowid
  );

  db.prepare('INSERT INTO incident_notes (incident_id, author_id, note) VALUES (?, ?, ?)').run(
    inc1Id,
    analystId,
    'Initial triage complete. Verified svc_backup account remains locked and no successful auth occurred.'
  );
  db.prepare('INSERT INTO incident_notes (incident_id, author_id, note) VALUES (?, ?, ?)').run(
    inc2Id,
    analystId,
    'Reviewed server access logs; zero data exfiltration or token compromise observed.'
  );

  db.prepare(
    'INSERT INTO response_actions (incident_id, performed_by, action_type, action_details, status) VALUES (?, ?, ?, ?, ?)'
  ).run(
    inc1Id,
    analystId,
    'Account Lock Verification',
    'Verified svc_backup authentication lockout policy active and rotated temporary credentials.',
    'Completed'
  );
  db.prepare(
    'INSERT INTO response_actions (incident_id, performed_by, action_type, action_details, status) VALUES (?, ?, ?, ?, ?)'
  ).run(
    inc2Id,
    analystId,
    'Perimeter ACL Recommendation',
    'Documented 45.155.205.91 in threat indicator watch-list for firewall team approval (no automatic network blocking executed).',
    'Completed'
  );

  db.prepare(
    'INSERT INTO audit_logs (user_id, username, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(
    adminId,
    'soc_admin',
    'SYSTEM_INITIALIZED',
    'system',
    '0',
    'CloudSOC relational database initialized with baseline rules, roles, and demonstration telemetry.',
    '127.0.0.1'
  );
}
