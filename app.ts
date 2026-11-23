import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import {
  evaluateDetectionRules,
  parseAllowlistedIps,
  type ActiveAlertRecord,
  type DetectionRuleConfig,
  type SecurityEventRecord,
  type ThreatIndicatorMatch,
} from './detection';
import {
  ALERT_STATUSES,
  EVENT_TYPES,
  INCIDENT_STATUSES,
  SEVERITY_LEVELS,
  escapeCsvCell,
  isValidEmail,
  isValidIPv4,
  isValidIncidentTransition,
  isValidUsername,
  redactSensitiveFields,
  sanitizeText,
  validatePasswordStrength,
  validateThreatIndicator,
  type AlertStatus,
  type EventType,
  type IncidentStatus,
  type IndicatorType,
  type RoleName,
  type SeverityLevel,
} from './validation';
import { lookupThreatIndicator } from './threatIntel';
import { buildReportData, renderReportCsv, renderReportPdf, type ReportType } from './reports';
import { getFirebaseAdminAuth } from './firebaseAdmin';

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  full_name: string;
  role: RoleName;
  is_active: number;
  auth_provider?: 'local' | 'firebase';
}

interface AuthenticatedRequest extends Request {
  user?: AuthUser;
  csrfToken?: string;
  sessionId?: number;
}

function hashToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function nextUid(db: DatabaseSync, table: string, prefix: string): string {
  const row = db.prepare(`SELECT COALESCE(MAX(id), 0) + 1 AS next_id FROM ${table}`).get() as {
    next_id: number;
  };
  return `${prefix}-2026-${String(row.next_id).padStart(4, '0')}`;
}

function getClientIp(req: Request): string {
  // Express resolves proxy headers only if an explicitly trusted reverse proxy is configured.
  // Never read untrusted X-Forwarded-For directly from the request.
  const raw = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const cleaned = String(raw).replace(/^::ffff:/, '').trim();
  return cleaned || '127.0.0.1';
}

function isAssignableAnalyst(db: DatabaseSync, userId: number | null): boolean {
  if (userId === null) return true;
  if (!Number.isSafeInteger(userId) || userId <= 0) return false;
  const match = db.prepare(`SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.id = ? AND u.is_active = 1 AND r.name = 'SECURITY_ANALYST'`).get(userId);
  return Boolean(match);
}

function recordAudit(
  db: DatabaseSync,
  userId: number | null,
  username: string,
  action: string,
  resourceType: string,
  resourceId: string,
  details: string,
  ipAddress: string
): void {
  db.prepare(
    `INSERT INTO audit_logs (user_id, username, action, resource_type, resource_id, details, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(userId, username, action, resourceType, resourceId, redactSensitiveFields(details), ipAddress);
}

export function ingestSecurityEventAndEvaluate(
  db: DatabaseSync,
  input: {
    source_ip: string;
    username: string;
    event_type: EventType;
    description: string;
    severity: SeverityLevel;
    user_agent?: string;
    timestamp?: string;
    is_demo?: boolean;
  }
): { event: SecurityEventRecord; triggeredAlerts: Array<{ id: number; alert_uid: string; title: string; severity: string }> } {
  const timestamp = input.timestamp || new Date().toISOString();
  const eventUid = nextUid(db, 'security_events', 'EVT');
  const safeDescription = redactSensitiveFields(sanitizeText(input.description, 400));
  const safeUa = sanitizeText(input.user_agent || '', 240);
  const safeUser = sanitizeText(input.username || 'unknown', 64);
  const safeIp = sanitizeText(input.source_ip || '127.0.0.1', 64);
  const isDemoInt = input.is_demo ? 1 : 0;

  const allowSetting = db
    .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'allowlisted_ips'")
    .get() as { setting_value: string } | undefined;
  const allowlistedIps = parseAllowlistedIps(allowSetting?.setting_value || '');

  const initialStatus = allowlistedIps.has(safeIp) ? 'Allowlisted' : 'Processed';

  const insertResult = db
    .prepare(
      `INSERT INTO security_events (event_uid, timestamp, source_ip, username, event_type, description, severity, user_agent, detection_status, is_demo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      eventUid,
      timestamp,
      safeIp,
      safeUser,
      input.event_type,
      safeDescription,
      input.severity,
      safeUa,
      initialStatus,
      isDemoInt
    );

  const eventId = Number(insertResult.lastInsertRowid);
  const incomingEvent = db
    .prepare('SELECT * FROM security_events WHERE id = ?')
    .get(eventId) as unknown as SecurityEventRecord;

  const rules = db.prepare('SELECT * FROM detection_rules ORDER BY id ASC').all() as unknown as DetectionRuleConfig[];
  const maxLookbackMinutes = Math.max(60, ...rules.filter(r => r.is_enabled).map(r => r.time_window_minutes));
  const lookbackStart = new Date(new Date(timestamp).getTime() - maxLookbackMinutes * 60_000).toISOString();
  const recentEvents = db
    .prepare('SELECT * FROM security_events WHERE timestamp >= ? ORDER BY timestamp ASC')
    .all(lookbackStart) as unknown as SecurityEventRecord[];
  const activeAlerts = db
    .prepare(
      "SELECT id, rule_id, source_ip, target_username, status, window_end FROM alerts WHERE status IN ('New', 'Acknowledged', 'Investigating')"
    )
    .all() as unknown as ActiveAlertRecord[];

  const threatRows = db
    .prepare(
      "SELECT indicator_value, verdict, reputation_score, source FROM threat_indicators WHERE indicator_type = 'ipv4' AND verdict IN ('Malicious', 'Suspicious') AND cached_until > ?"
    )
    .all(timestamp) as unknown as ThreatIndicatorMatch[];
  const knownMaliciousIps = new Map<string, ThreatIndicatorMatch>();
  for (const row of threatRows) {
    knownMaliciousIps.set(row.indicator_value, row);
  }

  // Known historical login IPs per user (before current event)
  const historyRows = db
    .prepare(
      "SELECT username, source_ip FROM security_events WHERE event_type = 'Successful Login' AND id < ?"
    )
    .all(eventId) as Array<{ username: string; source_ip: string }>;
  const knownUserIps = new Map<string, Set<string>>();
  for (const r of historyRows) {
    if (!knownUserIps.has(r.username)) knownUserIps.set(r.username, new Set());
    knownUserIps.get(r.username)!.add(r.source_ip);
  }

  const matches = evaluateDetectionRules({
    incomingEvent,
    recentEvents,
    rules,
    activeAlerts,
    allowlistedIps,
    knownMaliciousIps,
    knownUserIps,
  });

  const triggeredAlerts: Array<{ id: number; alert_uid: string; title: string; severity: string }> = [];

  for (const match of matches) {
    const alertUid = nextUid(db, 'alerts', 'ALT');
    const alertRes = db
      .prepare(
        `INSERT INTO alerts (alert_uid, title, description, severity, status, rule_id, trigger_event_id, source_ip, target_username, explanation, event_count, window_start, window_end, is_demo)
         VALUES (?, ?, ?, ?, 'New', ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        alertUid,
        match.title,
        match.description,
        match.severity,
        match.rule.id,
        eventId,
        match.source_ip,
        match.target_username,
        match.explanation,
        match.event_count,
        match.window_start,
        match.window_end,
        isDemoInt
      );

    const alertId = Number(alertRes.lastInsertRowid);
    triggeredAlerts.push({
      id: alertId,
      alert_uid: alertUid,
      title: match.title,
      severity: match.severity,
    });

    db.prepare(
      "UPDATE security_events SET detection_status = 'Alert Triggered', rule_triggered = ? WHERE id = ?"
    ).run(match.rule.rule_code, eventId);

    if (match.emit_summary_event) {
      const summaryUid = nextUid(db, 'security_events', 'EVT');
      db.prepare(
        `INSERT INTO security_events (event_uid, timestamp, source_ip, username, event_type, description, severity, user_agent, detection_status, rule_triggered, is_demo)
         VALUES (?, ?, ?, ?, 'Multiple Failed Logins', ?, ?, ?, 'Alert Triggered', ?, ?)`
      ).run(
        summaryUid,
        timestamp,
        match.source_ip,
        match.target_username,
        `Rule ${match.rule.rule_code} detected ${match.event_count} failed logins within ${match.rule.time_window_minutes} minutes.`,
        match.severity,
        safeUa,
        match.rule.rule_code,
        isDemoInt
      );
    }
  }

  const refreshedEvent = db
    .prepare('SELECT * FROM security_events WHERE id = ?')
    .get(eventId) as unknown as SecurityEventRecord;

  return { event: refreshedEvent, triggeredAlerts };
}

export function createApp(db: DatabaseSync) {
  const app = express();

  // Set TRUST_PROXY=1 only when exactly one trusted reverse proxy is in front of the app.
  if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '512kb' }));
  app.use(cookieParser());

  // Security Headers Middleware (OWASP hardening)
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    const firebaseConnect = 'https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://www.googleapis.com';
    const connectSrc = process.env.NODE_ENV === 'production'
      ? `connect-src 'self' ${firebaseConnect};`
      : `connect-src 'self' ws: wss: ${firebaseConnect};`;
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; ${connectSrc}`
    );
    if (req.secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  const attachSession = (req: AuthenticatedRequest, _res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const bearerToken =
      typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7).trim()
        : '';
    const cookieToken =
      typeof req.cookies?.cloudsoc_session === 'string' ? req.cookies.cloudsoc_session : '';
    const rawToken = cookieToken || bearerToken;
    if (!rawToken) return next();

    const tokenHash = hashToken(rawToken);
    const nowIso = new Date().toISOString();
    const row = db
      .prepare(
        `SELECT s.id AS session_id, s.csrf_token, u.id, u.username, u.email, u.full_name, u.is_active, u.firebase_uid, r.name AS role
         FROM sessions s
         JOIN users u ON s.user_id = u.id
         JOIN roles r ON u.role_id = r.id
         WHERE s.token_hash = ? AND s.expires_at > ?`
      )
      .get(tokenHash, nowIso) as unknown as
      | (AuthUser & { session_id: number; csrf_token: string; firebase_uid: string | null })
      | undefined;

    if (row && row.is_active === 1) {
      req.user = {
        id: row.id,
        username: row.username,
        email: row.email,
        full_name: row.full_name,
        role: row.role,
        is_active: row.is_active,
        auth_provider: row.firebase_uid ? 'firebase' : 'local',
      };
      req.csrfToken = row.csrf_token;
      req.sessionId = row.session_id;
    }
    next();
  };

  app.use(attachSession);

  const requireAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const sentCsrf = req.headers['x-csrf-token'];
      if (!sentCsrf || sentCsrf !== req.csrfToken) {
        return res.status(403).json({ error: 'Invalid or missing CSRF security token.' });
      }
    }
    next();
  };

  const requireAdmin = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }
    if (req.user.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Administrator privileges required for this action.' });
    }
    next();
  };

  function issueSessionCookie(res: Response, userId: number, req: Request): { csrfToken: string; sessionToken: string } {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(24).toString('hex');
    const tokenHash = hashToken(rawToken);
    const expiresAt = new Date(Date.now() + 12 * 3600_000).toISOString();
    db.prepare(
      `INSERT INTO sessions (token_hash, user_id, csrf_token, ip_address, user_agent, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(
      tokenHash,
      userId,
      csrfToken,
      getClientIp(req),
      sanitizeText(req.headers['user-agent'] || '', 200),
      expiresAt
    );

    const isHttps = req.secure;
    res.cookie('cloudsoc_session', rawToken, {
      httpOnly: true,
      sameSite: isHttps ? 'none' : 'lax',
      secure: isHttps,
      path: '/',
      maxAge: 12 * 3600_000,
    });
    return { csrfToken, sessionToken: rawToken };
  }

  // Health Endpoint
  app.get('/api/health', (_req, res) => {
    const check = db.prepare('SELECT 1 AS ok').get() as { ok: number };
    const mig = db.prepare('SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations').get() as {
      version: number;
    };
    res.json({
      status: check.ok === 1 ? 'healthy' : 'degraded',
      service: 'CloudSOC API',
      database: {
        engine: 'sqlite',
        schemaVersion: mig.version,
      },
      timestamp: new Date().toISOString(),
    });
  });

  // Firebase Authentication exchange: Firebase proves the email/password identity;
  // CloudSOC then issues its own HttpOnly session and keeps roles/data in SQLite.
  app.post('/api/auth/firebase/session', async (req: Request, res: Response) => {
    const idToken = String(req.body?.idToken || '').trim();
    if (!idToken || idToken.length > 12_000) {
      return res.status(400).json({ error: 'A valid Firebase ID token is required.' });
    }

    let firebaseAuth;
    try {
      firebaseAuth = getFirebaseAdminAuth();
    } catch {
      return res.status(503).json({ error: 'Firebase server credentials are invalid. Check the Firebase Admin service-account setup.' });
    }
    if (!firebaseAuth) {
      return res.status(503).json({ error: 'Firebase Admin is not configured. Add FIREBASE_SERVICE_ACCOUNT_PATH to the server .env file.' });
    }

    let decoded;
    try {
      decoded = await firebaseAuth.verifyIdToken(idToken, true);
    } catch {
      return res.status(401).json({ error: 'Firebase sign-in could not be verified. Please sign in again.' });
    }

    const email = String(decoded.email || '').trim().toLowerCase();
    const firebaseUid = String(decoded.uid || '').trim();
    if (!email || !firebaseUid || !isValidEmail(email)) {
      return res.status(401).json({ error: 'The Firebase account must have a valid email address.' });
    }

    let userRow = db.prepare(
      `SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.firebase_uid, u.locked_until,
              r.name AS role_name
       FROM users u JOIN roles r ON u.role_id = r.id
       WHERE u.firebase_uid = ?`
    ).get(firebaseUid) as {
      id: number; username: string; email: string; full_name: string; is_active: number;
      firebase_uid: string | null; locked_until: string | null; role_name: RoleName;
    } | undefined;

    if (!userRow) {
      const emailOwner = db.prepare(
        `SELECT u.id, u.username, u.email, u.firebase_uid, r.name AS role_name
         FROM users u JOIN roles r ON u.role_id = r.id WHERE LOWER(u.email) = ?`
      ).get(email) as { id: number; username: string; email: string; firebase_uid: string | null; role_name: RoleName } | undefined;

      // Never let a new Firebase registration claim a pre-existing local/admin account.
      if (emailOwner) {
        return res.status(409).json({ error: 'This email is already assigned to an existing CloudSOC account. Use its existing sign-in method or ask an administrator to link it.' });
      }

      const localPart = email.split('@')[0].toLowerCase();
      const safeBase = localPart.replace(/[^a-z0-9._-]/g, '').slice(0, 24);
      let username = safeBase.length >= 3 ? safeBase : `user_${crypto.randomBytes(3).toString('hex')}`;
      let suffix = 1;
      while (db.prepare('SELECT id FROM users WHERE LOWER(username) = ?').get(username.toLowerCase())) {
        const tail = `_${suffix++}`;
        username = `${safeBase.slice(0, 32 - tail.length) || 'user'}${tail}`;
      }
      const fullName = sanitizeText(localPart.replace(/[._-]+/g, ' ').trim(), 100) || 'CloudSOC User';
      const analystRole = db.prepare("SELECT id FROM roles WHERE name = 'SECURITY_ANALYST'").get() as { id: number } | undefined;
      if (!analystRole) return res.status(500).json({ error: 'Security Analyst role is missing from the local database.' });

      // Firebase owns this user's password. A random, unusable local hash satisfies
      // the legacy NOT NULL schema and is never used to authenticate Firebase users.
      const unusableLocalHash = bcrypt.hashSync(crypto.randomBytes(48).toString('hex'), 10);
      try {
        const inserted = db.prepare(
          `INSERT INTO users (username, email, full_name, password_hash, role_id, firebase_uid)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).run(username, email, fullName, unusableLocalHash, analystRole.id, firebaseUid);
        const newUserId = Number(inserted.lastInsertRowid);
        recordAudit(db, newUserId, username, 'USER_REGISTERED', 'user', String(newUserId), 'Firebase email/password account registered with SECURITY_ANALYST permissions.', getClientIp(req));
      } catch {
        return res.status(409).json({ error: 'An account with this email already exists. Contact an administrator if you need account linking.' });
      }

      userRow = db.prepare(
        `SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.firebase_uid, u.locked_until,
                r.name AS role_name
         FROM users u JOIN roles r ON u.role_id = r.id WHERE u.firebase_uid = ?`
      ).get(firebaseUid) as typeof userRow;
    }

    if (!userRow || userRow.is_active !== 1) {
      return res.status(403).json({ error: 'This CloudSOC account is disabled. Contact an administrator.' });
    }
    if (userRow.locked_until && new Date(userRow.locked_until).getTime() > Date.now()) {
      return res.status(423).json({ error: 'This CloudSOC account is temporarily locked. Contact an administrator.' });
    }

    db.prepare(
      "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
    ).run(userRow.id);
    const clientIp = getClientIp(req);
    ingestSecurityEventAndEvaluate(db, {
      source_ip: clientIp,
      username: userRow.username,
      event_type: 'Successful Login',
      description: `Firebase-authenticated user "${userRow.username}" (${userRow.role_name}) signed in successfully.`,
      severity: 'Low',
      user_agent: String(req.headers['user-agent'] || ''),
    });
    recordAudit(db, userRow.id, userRow.username, 'LOGIN_SUCCESS', 'auth', String(userRow.id), 'Firebase ID token verified; CloudSOC session issued.', clientIp);

    const { csrfToken } = issueSessionCookie(res, userRow.id, req);
    return res.json({
      user: {
        id: userRow.id,
        username: userRow.username,
        email: userRow.email,
        full_name: userRow.full_name,
        role: userRow.role_name,
        is_active: userRow.is_active,
        auth_provider: 'firebase',
      },
      csrfToken,
    });
  });

  app.post('/api/auth/register', (_req: Request, res: Response) => {
    return res.status(410).json({
      error: 'Direct local registration is disabled. Create an account using Firebase Email/Password from the CloudSOC sign-up page.',
    });
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const identifier = sanitizeText(req.body?.identifier || req.body?.email || req.body?.username, 120).toLowerCase();
    const password = String(req.body?.password || '');
    const clientIp = getClientIp(req); // source IP must never come from an untrusted login payload
    const ua = String(req.headers['user-agent'] || '');

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/email and password are required.' });
    }

    const userRow = db
      .prepare(
        `SELECT u.*, r.name AS role_name
         FROM users u JOIN roles r ON u.role_id = r.id
         WHERE LOWER(u.email) = ? OR LOWER(u.username) = ?`
      )
      .get(identifier, identifier) as
      | {
          id: number;
          username: string;
          email: string;
          full_name: string;
          password_hash: string;
          role_name: RoleName;
          is_active: number;
          failed_login_attempts: number;
          locked_until: string | null;
        }
      | undefined;

    if (!userRow) {
      ingestSecurityEventAndEvaluate(db, {
        source_ip: clientIp,
        username: identifier,
        event_type: 'Failed Login',
        description: `Authentication failed for unknown identifier "${identifier}".`,
        severity: 'Medium',
        user_agent: ua,
      });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    if (userRow.is_active !== 1) {
      ingestSecurityEventAndEvaluate(db, {
        source_ip: clientIp,
        username: userRow.username,
        event_type: 'Unauthorized Access',
        description: `Disabled account "${userRow.username}" attempted sign-in.`,
        severity: 'High',
        user_agent: ua,
      });
      return res.status(403).json({ error: 'Account is disabled. Contact a SOC administrator.' });
    }

    if (userRow.locked_until && new Date(userRow.locked_until).getTime() > Date.now()) {
      ingestSecurityEventAndEvaluate(db, {
        source_ip: clientIp,
        username: userRow.username,
        event_type: 'Failed Login',
        description: `Sign-in attempt against temporarily locked account "${userRow.username}".`,
        severity: 'High',
        user_agent: ua,
      });
      return res.status(423).json({
        error: 'Account temporarily locked due to repeated failed login attempts.',
      });
    }

    const passwordMatches = bcrypt.compareSync(password, userRow.password_hash);
    if (!passwordMatches) {
      const nextFails = userRow.failed_login_attempts + 1;
      const lockoutSetting = db
        .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'max_login_lockout_attempts'")
        .get() as { setting_value: string } | undefined;
      const maxLockout = Math.max(5, Number(lockoutSetting?.setting_value ?? 12) || 12);
      const lockedUntil = nextFails >= maxLockout ? new Date(Date.now() + 15 * 60_000).toISOString() : null;

      db.prepare(
        "UPDATE users SET failed_login_attempts = ?, locked_until = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
      ).run(nextFails, lockedUntil, userRow.id);

      const detectionResult = ingestSecurityEventAndEvaluate(db, {
        source_ip: clientIp,
        username: userRow.username,
        event_type: 'Failed Login',
        description: `Invalid password provided for "${userRow.username}" (attempt #${nextFails}).`,
        severity: nextFails >= 4 ? 'High' : 'Medium',
        user_agent: ua,
      });

      recordAudit(
        db,
        userRow.id,
        userRow.username,
        'LOGIN_FAILED',
        'auth',
        String(userRow.id),
        `Failed login attempt #${nextFails} from ${clientIp}`,
        clientIp
      );

      return res.status(401).json({
        error: 'Invalid credentials.',
        alertsTriggered: detectionResult.triggeredAlerts.length,
      });
    }

    // Successful authentication
    db.prepare(
      "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
    ).run(userRow.id);

    ingestSecurityEventAndEvaluate(db, {
      source_ip: clientIp,
      username: userRow.username,
      event_type: 'Successful Login',
      description: `User "${userRow.username}" (${userRow.role_name}) signed in successfully.`,
      severity: 'Low',
      user_agent: ua,
    });

    recordAudit(
      db,
      userRow.id,
      userRow.username,
      'LOGIN_SUCCESS',
      'auth',
      String(userRow.id),
      `Authenticated session issued from ${clientIp}`,
      clientIp
    );

    const { csrfToken, sessionToken } = issueSessionCookie(res, userRow.id, req);
    return res.json({
      user: {
        id: userRow.id,
        username: userRow.username,
        email: userRow.email,
        full_name: userRow.full_name,
        role: userRow.role_name,
        is_active: userRow.is_active,
      },
      csrfToken,
      sessionToken,
    });
  });

  app.post('/api/auth/logout', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    if (req.sessionId) {
      db.prepare('DELETE FROM sessions WHERE id = ?').run(req.sessionId);
    }
    if (req.user) {
      recordAudit(db, req.user.id, req.user.username, 'LOGOUT', 'auth', String(req.user.id), 'User signed out', getClientIp(req));
    }
    const isHttps = req.secure;
    res.clearCookie('cloudsoc_session', {
      path: '/',
      sameSite: isHttps ? 'none' : 'lax',
      secure: isHttps,
    });
    res.json({ ok: true });
  });

  app.get('/api/auth/session', (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
      return res.json({ authenticated: false, user: null });
    }
    return res.json({
      authenticated: true,
      user: req.user,
      csrfToken: req.csrfToken,
    });
  });

  app.get('/api/auth/me', (req: AuthenticatedRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    const profileDetails = db
      .prepare("SELECT id, username, email, full_name, is_active, last_login_at, created_at, CASE WHEN firebase_uid IS NULL THEN 'local' ELSE 'firebase' END AS auth_provider FROM users WHERE id = ?")
      .get(req.user.id) as Record<string, unknown>;
    const myAudit = db
      .prepare('SELECT id, action, resource_type, details, ip_address, created_at FROM audit_logs WHERE user_id = ? ORDER BY id DESC LIMIT 12')
      .all(req.user.id);
    return res.json({
      user: { ...profileDetails, role: req.user.role },
      csrfToken: req.csrfToken,
      recentAudit: myAudit,
    });
  });

  app.patch('/api/auth/profile', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;
    const fullName = sanitizeText(req.body?.full_name, 100);
    const email = sanitizeText(req.body?.email, 120).toLowerCase();
    const currentPassword = String(req.body?.current_password || '');
    const newPassword = String(req.body?.new_password || '');
    const authRow = db.prepare('SELECT firebase_uid FROM users WHERE id = ?').get(userId) as { firebase_uid: string | null } | undefined;
    const isFirebaseAccount = Boolean(authRow?.firebase_uid);
    if (isFirebaseAccount && (newPassword || (email && email !== req.user!.email))) {
      return res.status(400).json({ error: 'This account password and email are managed by Firebase Authentication. Use the password reset option on the sign-in page to change your password.' });
    }

    if (fullName && fullName.length < 2) {
      return res.status(400).json({ error: 'Full name must be at least 2 characters.' });
    }
    if (email && !isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format.' });
    }
    if (email) {
      const clash = db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').get(email, userId);
      if (clash) {
        return res.status(409).json({ error: 'Email is already in use by another account.' });
      }
    }

    if (newPassword) {
      const userRow = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(userId) as {
        password_hash: string;
      };
      if (!currentPassword || !bcrypt.compareSync(currentPassword, userRow.password_hash)) {
        return res.status(400).json({ error: 'Current password is incorrect.' });
      }
      const pwdCheck = validatePasswordStrength(newPassword);
      if (!pwdCheck.valid) {
        return res.status(400).json({ error: pwdCheck.reason });
      }
      const nextHash = bcrypt.hashSync(newPassword, 10);
      db.prepare("UPDATE users SET password_hash = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").run(
        nextHash,
        userId
      );
    }

    if (fullName || email) {
      db.prepare(
        "UPDATE users SET full_name = COALESCE(NULLIF(?, ''), full_name), email = COALESCE(NULLIF(?, ''), email), updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
      ).run(fullName, email, userId);
    }

    recordAudit(db, userId, req.user!.username, 'PROFILE_UPDATED', 'user', String(userId), 'Updated profile/credentials', getClientIp(req));
    const updated = db
      .prepare(
        'SELECT u.id, u.username, u.email, u.full_name, u.is_active, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?'
      )
      .get(userId);
    res.json({ user: updated });
  });

  // Dashboard Analytics Route
  app.get('/api/dashboard', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const days = Math.min(90, Math.max(1, Number(req.query.days ?? 7) || 7));
    const cutoffIso = new Date(Date.now() - days * 86_400_000).toISOString();

    const kpis = {
      totalEvents: (
        db.prepare('SELECT COUNT(*) AS c FROM security_events WHERE timestamp >= ?').get(cutoffIso) as { c: number }
      ).c,
      totalAlerts: (
        db.prepare('SELECT COUNT(*) AS c FROM alerts WHERE created_at >= ?').get(cutoffIso) as { c: number }
      ).c,
      criticalAlerts: (
        db.prepare("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'Critical' AND status != 'False Positive' AND created_at >= ?").get(cutoffIso) as {
          c: number;
        }
      ).c,
      highRiskEvents: (
        db
          .prepare("SELECT COUNT(*) AS c FROM security_events WHERE severity IN ('Critical', 'High') AND timestamp >= ?")
          .get(cutoffIso) as { c: number }
      ).c,
      openIncidents: (
        db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE status != 'RESOLVED' AND created_at >= ?").get(cutoffIso) as { c: number }
      ).c,
      resolvedIncidents: (
        db.prepare("SELECT COUNT(*) AS c FROM incidents WHERE status = 'RESOLVED' AND created_at >= ?").get(cutoffIso) as { c: number }
      ).c,
    };

    const eventsOverTime = db
      .prepare(
        `SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS count
         FROM security_events
         WHERE timestamp >= ?
         GROUP BY day
         ORDER BY day ASC`
      )
      .all(cutoffIso) as Array<{ day: string; count: number }>;

    const alertsBySeverity = db
      .prepare(
        `SELECT severity, COUNT(*) AS count
         FROM alerts
         WHERE created_at >= ?
         GROUP BY severity
         ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
      )
      .all(cutoffIso) as Array<{ severity: string; count: number }>;

    const incidentsByStatus = db
      .prepare('SELECT status, COUNT(*) AS count FROM incidents WHERE created_at >= ? GROUP BY status')
      .all(cutoffIso) as Array<{ status: string; count: number }>;

    const eventCategories = db
      .prepare(
        `SELECT event_type, COUNT(*) AS count
         FROM security_events
         WHERE timestamp >= ?
         GROUP BY event_type
         ORDER BY count DESC`
      )
      .all(cutoffIso) as Array<{ event_type: string; count: number }>;

    const detectionTrends = db
      .prepare(
        `SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS count
         FROM alerts
         WHERE created_at >= ?
         GROUP BY day
         ORDER BY day ASC`
      )
      .all(cutoffIso) as Array<{ day: string; count: number }>;

    const recentActivity = db
      .prepare(
        `SELECT id, event_uid, timestamp, source_ip, username, event_type, severity, detection_status, description, is_demo
         FROM security_events
         ORDER BY timestamp DESC LIMIT 8`
      )
      .all();

    const activeAlertsPreview = db
      .prepare(
        `SELECT a.id, a.alert_uid, a.title, a.severity, a.status, a.source_ip, a.created_at, a.is_demo, dr.rule_code
         FROM alerts a JOIN detection_rules dr ON a.rule_id = dr.id
         WHERE a.status IN ('New', 'Acknowledged', 'Investigating')
         ORDER BY a.created_at DESC LIMIT 5`
      )
      .all();

    const demoCounts = {
      events: (db.prepare('SELECT COUNT(*) AS c FROM security_events WHERE is_demo = 1').get() as { c: number }).c,
      alerts: (db.prepare('SELECT COUNT(*) AS c FROM alerts WHERE is_demo = 1').get() as { c: number }).c,
      incidents: (db.prepare('SELECT COUNT(*) AS c FROM incidents WHERE is_demo = 1').get() as { c: number }).c,
    };

    res.json({
      days,
      refreshIntervalSeconds: Math.max(5, Math.min(300, Number((db.prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'auto_refresh_seconds'").get() as { setting_value: string } | undefined)?.setting_value || 30) || 30)),
      kpis,
      demoCounts,
      charts: {
        eventsOverTime,
        alertsBySeverity,
        incidentsByStatus,
        eventCategories,
        detectionTrends,
      },
      recentActivity,
      activeAlertsPreview,
    });
  });

  // Security Events Routes
  app.get('/api/events', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const search = sanitizeText(req.query.search, 100).toLowerCase();
    const severity = sanitizeText(req.query.severity, 20);
    const eventType = sanitizeText(req.query.event_type, 40);
    const startDate = sanitizeText(req.query.startDate, 40);
    const endDate = sanitizeText(req.query.endDate, 40);

    const conditions: string[] = ['1=1'];
    const params: Array<string | number> = [];

    if (search) {
      conditions.push(
        '(LOWER(event_uid) LIKE ? OR LOWER(source_ip) LIKE ? OR LOWER(username) LIKE ? OR LOWER(description) LIKE ?)'
      );
      const q = `%${search}%`;
      params.push(q, q, q, q);
    }
    if (severity && SEVERITY_LEVELS.includes(severity as SeverityLevel)) {
      conditions.push('severity = ?');
      params.push(severity);
    }
    if (eventType && EVENT_TYPES.includes(eventType as EventType)) {
      conditions.push('event_type = ?');
      params.push(eventType);
    }
    if (startDate) {
      const startMs = Date.parse(startDate);
      if (!Number.isNaN(startMs)) {
        conditions.push('timestamp >= ?');
        params.push(new Date(startMs).toISOString());
      }
    }
    if (endDate) {
      const endMs = Date.parse(endDate);
      if (!Number.isNaN(endMs)) {
        conditions.push('timestamp <= ?');
        params.push(new Date(endMs + 86_399_999).toISOString());
      }
    }

    const events = db
      .prepare(`SELECT * FROM security_events WHERE ${conditions.join(' AND ')} ORDER BY timestamp DESC LIMIT 250`)
      .all(...params);

    res.json({ events });
  });

  app.get('/api/events/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid event ID' });
    const event = db.prepare('SELECT * FROM security_events WHERE id = ?').get(id);
    if (!event) return res.status(404).json({ error: 'Security event not found' });
    const linkedAlerts = db.prepare('SELECT * FROM alerts WHERE trigger_event_id = ?').all(id);
    res.json({ event, linkedAlerts });
  });

  app.post('/api/events', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const sourceIp = sanitizeText(req.body?.source_ip, 64);
    const username = sanitizeText(req.body?.username, 64);
    const eventType = sanitizeText(req.body?.event_type, 40) as EventType;
    const description = sanitizeText(req.body?.description, 400);
    const severity = sanitizeText(req.body?.severity, 20) as SeverityLevel;
    const userAgent = sanitizeText(req.body?.user_agent || 'CloudSOC-Agent/1.0', 200);

    if (!isValidIPv4(sourceIp) && sourceIp !== '::1') {
      return res.status(400).json({ error: 'A valid IPv4 source address is required.' });
    }
    if (!username) {
      return res.status(400).json({ error: 'Target username is required.' });
    }
    if (!EVENT_TYPES.includes(eventType)) {
      return res.status(400).json({ error: 'Unsupported security event type.' });
    }
    if (!SEVERITY_LEVELS.includes(severity)) {
      return res.status(400).json({ error: 'Invalid severity level.' });
    }
    if (!description) {
      return res.status(400).json({ error: 'Event description is required.' });
    }

    const result = ingestSecurityEventAndEvaluate(db, {
      source_ip: sourceIp,
      username,
      event_type: eventType,
      description,
      severity,
      user_agent: userAgent,
    });

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'EVENT_INGESTED',
      'security_event',
      String(result.event.id),
      `Ingested ${eventType} from ${sourceIp} for ${username}; triggered ${result.triggeredAlerts.length} alert(s)`,
      getClientIp(req)
    );

    res.status(201).json(result);
  });

  // Authorized Brute-Force Simulation Helper (strictly controlled demo testing inside SOC)
  app.post('/api/events/simulate-bruteforce', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const sourceIp = sanitizeText(req.body?.source_ip || '198.51.100.99', 64);
    const targetUsername = sanitizeText(req.body?.username || 'demo_target', 64);
    const attempts = Math.min(20, Math.max(1, Number(req.body?.attempts ?? 10) || 10));

    if (!isValidIPv4(sourceIp)) {
      return res.status(400).json({ error: 'Valid IPv4 address required for simulation.' });
    }
    if (!targetUsername) {
      return res.status(400).json({ error: 'Target username required for simulation.' });
    }

    const createdEvents: SecurityEventRecord[] = [];
    const allAlerts: Array<{ id: number; alert_uid: string; title: string; severity: string }> = [];

    for (let i = 1; i <= attempts; i++) {
      const outcome = ingestSecurityEventAndEvaluate(db, {
        source_ip: sourceIp,
        username: targetUsername,
        event_type: 'Failed Login',
        description: `Authorized brute-force simulation attempt #${i} against account "${targetUsername}".`,
        severity: i >= 4 ? 'High' : 'Medium',
        user_agent: 'CloudSOC-Authorized-Simulator/1.0',
        is_demo: true,
      });
      createdEvents.push(outcome.event);
      allAlerts.push(...outcome.triggeredAlerts);
    }

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'SIMULATION_EXECUTED',
      'detection_engine',
      sourceIp,
      `Ran authorized brute-force simulation (${attempts} failed logins from ${sourceIp} targeting ${targetUsername}); alerts generated: ${allAlerts.length}`,
      getClientIp(req)
    );

    res.status(201).json({
      attemptsExecuted: attempts,
      eventsCreated: createdEvents.length,
      alertsTriggered: allAlerts,
    });
  });

  // Realistic Demonstration Telemetry Generator (Explicitly Labeled is_demo = 1)
  app.post('/api/events/generate-demo-data', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const samples: Array<{
      source_ip: string;
      username: string;
      event_type: EventType;
      description: string;
      severity: SeverityLevel;
      user_agent: string;
    }> = [
      {
        source_ip: '10.20.12.40',
        username: 'd.patel',
        event_type: 'Successful Login',
        description: '[Demonstration Data] Authenticated cleanly from corporate SSO gateway.',
        severity: 'Low',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
      {
        source_ip: '194.26.135.88',
        username: 'deploy_ci',
        event_type: 'Suspicious Access',
        description: '[Demonstration Data] API token replay probe from external cloud hosting block.',
        severity: 'High',
        user_agent: 'curl/8.5.0',
      },
      {
        source_ip: '45.155.205.91',
        username: 'admin_probe',
        event_type: 'Unauthorized Access',
        description: '[Demonstration Data] Blocked request to privileged /api/settings from known scanner IP.',
        severity: 'High',
        user_agent: 'python-requests/2.31.0',
      },
      {
        source_ip: '203.0.113.180',
        username: 'j.smith',
        event_type: 'Failed Login',
        description: '[Demonstration Data] Invalid MFA challenge during portal authentication.',
        severity: 'Medium',
        user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      },
      {
        source_ip: '10.20.4.15',
        username: req.user!.username,
        event_type: 'Administrative Activity',
        description: '[Demonstration Data] Generated synthetic SOC baseline telemetry for evaluation.',
        severity: 'Low',
        user_agent: 'CloudSOC-Demo-Seeder/1.0',
      },
    ];

    const created: SecurityEventRecord[] = [];
    const alerts: Array<{ id: number; alert_uid: string; title: string; severity: string }> = [];
    for (const sample of samples) {
      const outcome = ingestSecurityEventAndEvaluate(db, { ...sample, is_demo: true });
      created.push(outcome.event);
      alerts.push(...outcome.triggeredAlerts);
    }

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'DEMO_DATA_GENERATED',
      'security_event',
      String(created.length),
      `Generated ${created.length} labeled demonstration telemetry events (${alerts.length} alert(s) triggered)`,
      getClientIp(req)
    );

    res.status(201).json({
      eventsCreated: created.length,
      alertsTriggered: alerts,
      labeledAsDemo: true,
    });
  });

  // Threat Intelligence Routes
  app.get('/api/threat-intel', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    const indicators = db
      .prepare(
        `SELECT t.*, COALESCE(u.username, 'system') AS queried_by_username
         FROM threat_indicators t LEFT JOIN users u ON t.queried_by = u.id
         ORDER BY t.id DESC LIMIT 100`
      )
      .all();
    const liveApisConfigured = Boolean(
      process.env.VIRUSTOTAL_API_KEY?.trim() || process.env.ABUSEIPDB_API_KEY?.trim()
    );
    res.json({ indicators, liveApisConfigured });
  });

  app.post('/api/threat-intel/lookup', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const indicatorType = sanitizeText(req.body?.indicator_type, 20) as IndicatorType;
    const rawValue = sanitizeText(req.body?.indicator_value, 255);
    const check = validateThreatIndicator(indicatorType, rawValue);
    if (!check.valid) {
      return res.status(400).json({ error: check.error });
    }

    try {
      const result = await lookupThreatIndicator(db, indicatorType, check.normalized, req.user!.id);
      recordAudit(
        db,
        req.user!.id,
        req.user!.username,
        'THREAT_INTEL_LOOKUP',
        'threat_indicator',
        check.normalized,
        `Looked up ${indicatorType} ${check.normalized} via ${result.source} (${result.verdict})`,
        getClientIp(req)
      );
      res.json({ result });
    } catch {
      res.status(502).json({ error: 'Threat intelligence lookup failed due to upstream timeout.' });
    }
  });

  // Alerts Routes
  app.get('/api/alerts', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const search = sanitizeText(req.query.search, 100).toLowerCase();
    const severity = sanitizeText(req.query.severity, 20);
    const status = sanitizeText(req.query.status, 30);
    const sort = sanitizeText(req.query.sort, 20);

    const conditions: string[] = ['1=1'];
    const params: string[] = [];

    if (search) {
      conditions.push(
        '(LOWER(a.alert_uid) LIKE ? OR LOWER(a.title) LIKE ? OR LOWER(a.source_ip) LIKE ? OR LOWER(a.target_username) LIKE ?)'
      );
      const q = `%${search}%`;
      params.push(q, q, q, q);
    }
    if (severity && SEVERITY_LEVELS.includes(severity as SeverityLevel)) {
      conditions.push('a.severity = ?');
      params.push(severity);
    }
    if (status && ALERT_STATUSES.includes(status as AlertStatus)) {
      conditions.push('a.status = ?');
      params.push(status);
    }

    let orderBy = 'a.created_at DESC';
    if (sort === 'oldest') orderBy = 'a.created_at ASC';
    else if (sort === 'severity') {
      orderBy =
        "CASE a.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, a.created_at DESC";
    }

    const alerts = db
      .prepare(
        `SELECT a.*, dr.rule_code, dr.name AS rule_name,
                COALESCE(u.username, 'Unassigned') AS assigned_username
         FROM alerts a
         JOIN detection_rules dr ON a.rule_id = dr.id
         LEFT JOIN users u ON a.assigned_to = u.id
         WHERE ${conditions.join(' AND ')}
         ORDER BY ${orderBy} LIMIT 250`
      )
      .all(...params);

    const analysts = db
      .prepare('SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username ASC')
      .all();

    res.json({ alerts, analysts });
  });

  app.get('/api/alerts/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid alert ID' });

    const alert = db
      .prepare(
        `SELECT a.*, dr.rule_code, dr.name AS rule_name, dr.threshold, dr.time_window_minutes,
                COALESCE(u.username, 'Unassigned') AS assigned_username
         FROM alerts a
         JOIN detection_rules dr ON a.rule_id = dr.id
         LEFT JOIN users u ON a.assigned_to = u.id
         WHERE a.id = ?`
      )
      .get(id) as Record<string, unknown> | undefined;

    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const relatedEvents = db
      .prepare(
        `SELECT * FROM security_events
         WHERE (source_ip = ? OR username = ?) AND timestamp >= ? AND timestamp <= ?
         ORDER BY timestamp DESC LIMIT 50`
      )
      .all(
        String(alert.source_ip),
        String(alert.target_username),
        String(alert.window_start),
        String(alert.window_end)
      );

    const linkedIncidents = db
      .prepare('SELECT id, incident_uid, title, status, priority FROM incidents WHERE alert_id = ?')
      .all(id);

    res.json({ alert, relatedEvents, linkedIncidents });
  });

  app.patch('/api/alerts/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid alert ID' });

    const existing = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id) as
      | Record<string, unknown>
      | undefined;
    if (!existing) return res.status(404).json({ error: 'Alert not found' });

    const nextStatus = req.body?.status !== undefined ? sanitizeText(req.body.status, 30) : undefined;
    if (nextStatus !== undefined && !ALERT_STATUSES.includes(nextStatus as AlertStatus)) {
      return res.status(400).json({ error: 'Invalid alert status.' });
    }

    const assignedTo =
      req.body?.assigned_to === null || req.body?.assigned_to === ''
        ? null
        : req.body?.assigned_to !== undefined
          ? Number(req.body.assigned_to)
          : undefined;
    if (assignedTo !== undefined && assignedTo !== null) {
      if (!isAssignableAnalyst(db, assignedTo)) return res.status(400).json({ error: 'Assignee must be an active security analyst.' });
    }

    const notes =
      req.body?.investigation_notes !== undefined
        ? redactSensitiveFields(sanitizeText(req.body.investigation_notes, 1000))
        : undefined;

    db.prepare(
      `UPDATE alerts
       SET status = COALESCE(?, status),
           assigned_to = CASE WHEN ? = 1 THEN ? ELSE assigned_to END,
           investigation_notes = COALESCE(?, investigation_notes),
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE id = ?`
    ).run(
      nextStatus ?? null,
      assignedTo !== undefined ? 1 : 0,
      assignedTo ?? null,
      notes ?? null,
      id
    );

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'ALERT_UPDATED',
      'alert',
      String(existing.alert_uid),
      `Status: ${nextStatus ?? existing.status}; Notes updated: ${notes !== undefined}`,
      getClientIp(req)
    );

    const updated = db
      .prepare(
        `SELECT a.*, dr.rule_code, dr.name AS rule_name, COALESCE(u.username, 'Unassigned') AS assigned_username
         FROM alerts a JOIN detection_rules dr ON a.rule_id = dr.id LEFT JOIN users u ON a.assigned_to = u.id
         WHERE a.id = ?`
      )
      .get(id);
    res.json({ alert: updated });
  });

  app.post('/api/alerts/:id/escalate', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid alert ID' });

    const alert = db.prepare('SELECT * FROM alerts WHERE id = ?').get(id) as
      | {
          id: number;
          alert_uid: string;
          title: string;
          description: string;
          severity: SeverityLevel;
          status: AlertStatus;
          assigned_to: number | null;
        }
      | undefined;
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const title = sanitizeText(req.body?.title || `Incident: ${alert.title}`, 180);
    const description = sanitizeText(req.body?.description || alert.description, 800);
    const priority = (SEVERITY_LEVELS.includes(req.body?.priority) ? req.body.priority : alert.severity) as SeverityLevel;
    const incidentUid = nextUid(db, 'incidents', 'INC');

    const incRes = db
      .prepare(
        `INSERT INTO incidents (incident_uid, title, description, priority, status, alert_id, assigned_to, created_by)
         VALUES (?, ?, ?, ?, 'NEW', ?, ?, ?)`
      )
      .run(
        incidentUid,
        title,
        description,
        priority,
        alert.id,
        isAssignableAnalyst(db, alert.assigned_to) ? alert.assigned_to : null,
        req.user!.id
      );
    const incidentId = Number(incRes.lastInsertRowid);

    if (alert.status === 'New' || alert.status === 'Acknowledged') {
      db.prepare(
        "UPDATE alerts SET status = 'Investigating', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?"
      ).run(alert.id);
    }

    db.prepare('INSERT INTO incident_notes (incident_id, author_id, note) VALUES (?, ?, ?)').run(
      incidentId,
      req.user!.id,
      `Escalated from alert ${alert.alert_uid}.`
    );

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'ALERT_ESCALATED',
      'incident',
      incidentUid,
      `Created incident ${incidentUid} from alert ${alert.alert_uid}`,
      getClientIp(req)
    );

    const createdIncident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(incidentId);
    res.status(201).json({ incident: createdIncident });
  });

  // Incident Management Routes
  app.get('/api/incidents', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const search = sanitizeText(req.query.search, 100).toLowerCase();
    const status = sanitizeText(req.query.status, 30);
    const priority = sanitizeText(req.query.priority, 20);

    const conditions: string[] = ['1=1'];
    const params: string[] = [];

    if (search) {
      conditions.push('(LOWER(i.incident_uid) LIKE ? OR LOWER(i.title) LIKE ? OR LOWER(i.description) LIKE ?)');
      const q = `%${search}%`;
      params.push(q, q, q);
    }
    if (status && INCIDENT_STATUSES.includes(status as IncidentStatus)) {
      conditions.push('i.status = ?');
      params.push(status);
    }
    if (priority && SEVERITY_LEVELS.includes(priority as SeverityLevel)) {
      conditions.push('i.priority = ?');
      params.push(priority);
    }

    const incidents = db
      .prepare(
        `SELECT i.*, COALESCE(u.username, 'Unassigned') AS assigned_username, c.username AS created_by_username,
                a.alert_uid
         FROM incidents i
         LEFT JOIN users u ON i.assigned_to = u.id
         JOIN users c ON i.created_by = c.id
         LEFT JOIN alerts a ON i.alert_id = a.id
         WHERE ${conditions.join(' AND ')}
         ORDER BY i.updated_at DESC LIMIT 200`
      )
      .all(...params);

    const analysts = db
      .prepare('SELECT id, username, full_name FROM users WHERE is_active = 1 ORDER BY username ASC')
      .all();

    res.json({ incidents, analysts });
  });

  app.get('/api/incidents/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid incident ID' });

    const incident = db
      .prepare(
        `SELECT i.*, COALESCE(u.username, 'Unassigned') AS assigned_username, c.username AS created_by_username,
                a.alert_uid, a.title AS alert_title
         FROM incidents i
         LEFT JOIN users u ON i.assigned_to = u.id
         JOIN users c ON i.created_by = c.id
         LEFT JOIN alerts a ON i.alert_id = a.id
         WHERE i.id = ?`
      )
      .get(id) as Record<string, unknown> | undefined;

    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const notes = db
      .prepare(
        `SELECT n.*, u.username AS author_username
         FROM incident_notes n JOIN users u ON n.author_id = u.id
         WHERE n.incident_id = ? ORDER BY n.created_at ASC`
      )
      .all(id);

    const actions = db
      .prepare(
        `SELECT ra.*, u.username AS performed_by_username
         FROM response_actions ra JOIN users u ON ra.performed_by = u.id
         WHERE ra.incident_id = ? ORDER BY ra.created_at ASC`
      )
      .all(id);

    const auditTrail = db
      .prepare('SELECT * FROM audit_logs WHERE resource_id = ? ORDER BY created_at DESC LIMIT 30')
      .all(String(incident.incident_uid));

    res.json({ incident, notes, actions, auditTrail });
  });

  app.post('/api/incidents', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const title = sanitizeText(req.body?.title, 180);
    const description = sanitizeText(req.body?.description, 800);
    const priority = sanitizeText(req.body?.priority || 'High', 20) as SeverityLevel;
    const assignedTo = req.body?.assigned_to ? Number(req.body.assigned_to) : null;
    if (!isAssignableAnalyst(db, assignedTo)) return res.status(400).json({ error: 'Assignee must be an active security analyst.' });

    if (!title || title.length < 4) {
      return res.status(400).json({ error: 'Incident title must be at least 4 characters.' });
    }
    if (!description) {
      return res.status(400).json({ error: 'Incident description is required.' });
    }
    if (!SEVERITY_LEVELS.includes(priority)) {
      return res.status(400).json({ error: 'Invalid incident priority.' });
    }

    const incidentUid = nextUid(db, 'incidents', 'INC');
    const insertRes = db
      .prepare(
        `INSERT INTO incidents (incident_uid, title, description, priority, status, assigned_to, created_by)
         VALUES (?, ?, ?, ?, 'NEW', ?, ?)`
      )
      .run(incidentUid, title, description, priority, assignedTo, req.user!.id);

    const id = Number(insertRes.lastInsertRowid);
    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'INCIDENT_CREATED',
      'incident',
      incidentUid,
      `Created manual incident "${title}" (${priority})`,
      getClientIp(req)
    );

    const created = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
    res.status(201).json({ incident: created });
  });

  app.patch('/api/incidents/:id', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid incident ID' });

    const existing = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id) as
      | { id: number; incident_uid: string; status: IncidentStatus; priority: SeverityLevel }
      | undefined;
    if (!existing) return res.status(404).json({ error: 'Incident not found' });

    const nextStatus = req.body?.status !== undefined ? (sanitizeText(req.body.status, 30) as IncidentStatus) : undefined;
    if (nextStatus !== undefined) {
      if (!INCIDENT_STATUSES.includes(nextStatus)) {
        return res.status(400).json({ error: 'Invalid incident lifecycle status.' });
      }
      if (!isValidIncidentTransition(existing.status, nextStatus)) {
        return res.status(400).json({
          error: `Invalid lifecycle transition from ${existing.status} to ${nextStatus}.`,
        });
      }
    }

    const nextPriority =
      req.body?.priority !== undefined ? (sanitizeText(req.body.priority, 20) as SeverityLevel) : undefined;
    if (nextPriority !== undefined && !SEVERITY_LEVELS.includes(nextPriority)) {
      return res.status(400).json({ error: 'Invalid priority level.' });
    }

    const assignedTo =
      req.body?.assigned_to === null || req.body?.assigned_to === ''
        ? null
        : req.body?.assigned_to !== undefined
          ? Number(req.body.assigned_to)
          : undefined;
    if (assignedTo !== undefined && !isAssignableAnalyst(db, assignedTo)) {
      return res.status(400).json({ error: 'Assignee must be an active security analyst.' });
    }
    const resolutionSummary =
      req.body?.resolution_summary !== undefined
        ? sanitizeText(req.body.resolution_summary, 800)
        : undefined;

    const closedAt =
      nextStatus === 'RESOLVED' ? new Date().toISOString() : nextStatus ? null : undefined;

    db.prepare(
      `UPDATE incidents
       SET status = COALESCE(?, status),
           priority = COALESCE(?, priority),
           assigned_to = CASE WHEN ? = 1 THEN ? ELSE assigned_to END,
           resolution_summary = COALESCE(?, resolution_summary),
           closed_at = CASE WHEN ? = 1 THEN ? ELSE closed_at END,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE id = ?`
    ).run(
      nextStatus ?? null,
      nextPriority ?? null,
      assignedTo !== undefined ? 1 : 0,
      assignedTo ?? null,
      resolutionSummary ?? null,
      closedAt !== undefined ? 1 : 0,
      closedAt ?? null,
      id
    );

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'INCIDENT_UPDATED',
      'incident',
      existing.incident_uid,
      `Transitioned status ${existing.status} -> ${nextStatus ?? existing.status}`,
      getClientIp(req)
    );

    const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
    res.json({ incident: updated });
  });

  app.post('/api/incidents/:id/notes', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid incident ID' });
    const incident = db.prepare('SELECT incident_uid FROM incidents WHERE id = ?').get(id) as
      | { incident_uid: string }
      | undefined;
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const note = redactSensitiveFields(sanitizeText(req.body?.note, 1000));
    if (!note) return res.status(400).json({ error: 'Note text is required.' });

    const noteRes = db
      .prepare('INSERT INTO incident_notes (incident_id, author_id, note) VALUES (?, ?, ?)')
      .run(id, req.user!.id, note);
    db.prepare("UPDATE incidents SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").run(id);

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'INCIDENT_NOTE_ADDED',
      'incident',
      incident.incident_uid,
      `Added investigation note (${note.slice(0, 80)})`,
      getClientIp(req)
    );

    const created = db
      .prepare('SELECT n.*, u.username AS author_username FROM incident_notes n JOIN users u ON n.author_id = u.id WHERE n.id = ?')
      .get(Number(noteRes.lastInsertRowid));
    res.status(201).json({ note: created });
  });

  app.post('/api/incidents/:id/actions', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid incident ID' });
    const incident = db.prepare('SELECT incident_uid FROM incidents WHERE id = ?').get(id) as
      | { incident_uid: string }
      | undefined;
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    const actionType = sanitizeText(req.body?.action_type, 100);
    const actionDetails = sanitizeText(req.body?.action_details, 500);
    if (!actionType || !actionDetails) {
      return res.status(400).json({ error: 'Action type and details are required.' });
    }

    const actionRes = db
      .prepare(
        `INSERT INTO response_actions (incident_id, performed_by, action_type, action_details, status)
         VALUES (?, ?, ?, ?, 'Completed')`
      )
      .run(id, req.user!.id, actionType, actionDetails);

    db.prepare("UPDATE incidents SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?").run(id);
    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'RESPONSE_ACTION_RECORDED',
      'incident',
      incident.incident_uid,
      `${actionType}: ${actionDetails.slice(0, 100)}`,
      getClientIp(req)
    );

    const created = db
      .prepare(
        'SELECT ra.*, u.username AS performed_by_username FROM response_actions ra JOIN users u ON ra.performed_by = u.id WHERE ra.id = ?'
      )
      .get(Number(actionRes.lastInsertRowid));
    res.status(201).json({ action: created });
  });

  // Reports Routes
  app.get('/api/reports', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const type = (sanitizeText(req.query.type || 'events', 30) as ReportType) || 'events';
    const allowed: ReportType[] = ['events', 'alerts', 'incidents', 'severity', 'analyst_activity'];
    if (!allowed.includes(type)) {
      return res.status(400).json({ error: 'Unsupported report type.' });
    }
    const report = buildReportData(db, {
      type,
      startDate: sanitizeText(req.query.startDate, 40) || undefined,
      endDate: sanitizeText(req.query.endDate, 40) || undefined,
      severity: sanitizeText(req.query.severity, 20) || undefined,
    });
    res.json({ report });
  });

  app.get('/api/reports/export/csv', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const type = (sanitizeText(req.query.type || 'events', 30) as ReportType) || 'events';
    const report = buildReportData(db, {
      type,
      startDate: sanitizeText(req.query.startDate, 40) || undefined,
      endDate: sanitizeText(req.query.endDate, 40) || undefined,
      severity: sanitizeText(req.query.severity, 20) || undefined,
    });
    const csv = renderReportCsv(report);
    recordAudit(db, req.user!.id, req.user!.username, 'REPORT_EXPORTED_CSV', 'report', type, `Exported ${report.rows.length} rows`, getClientIp(req));
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="cloudsoc_${type}_report.csv"`);
    res.send(csv);
  });

  app.get('/api/reports/export/pdf', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const type = (sanitizeText(req.query.type || 'events', 30) as ReportType) || 'events';
    const report = buildReportData(db, {
      type,
      startDate: sanitizeText(req.query.startDate, 40) || undefined,
      endDate: sanitizeText(req.query.endDate, 40) || undefined,
      severity: sanitizeText(req.query.severity, 20) || undefined,
    });
    const pdfBuf = await renderReportPdf(report);
    recordAudit(db, req.user!.id, req.user!.username, 'REPORT_EXPORTED_PDF', 'report', type, `Exported PDF (${report.rows.length} rows)`, getClientIp(req));
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="cloudsoc_${type}_report.pdf"`);
    res.send(pdfBuf);
  });

  // Admin-Only User Management
  app.get('/api/users', requireAuth, requireAdmin, (_req: AuthenticatedRequest, res: Response) => {
    const users = db
      .prepare(
        `SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.failed_login_attempts,
                u.locked_until, u.last_login_at, u.created_at, r.name AS role
         FROM users u JOIN roles r ON u.role_id = r.id
         ORDER BY u.id ASC`
      )
      .all();
    res.json({ users });
  });

  app.post('/api/users', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
    const username = sanitizeText(req.body?.username, 32).toLowerCase();
    const email = sanitizeText(req.body?.email, 120).toLowerCase();
    const fullName = sanitizeText(req.body?.full_name, 100);
    const password = String(req.body?.password || '');
    const roleName = sanitizeText(req.body?.role || 'SECURITY_ANALYST', 30) as RoleName;

    if (!isValidUsername(username) || !isValidEmail(email) || !fullName) {
      return res.status(400).json({ error: 'Valid username, email, and full name are required.' });
    }
    const pwdCheck = validatePasswordStrength(password);
    if (!pwdCheck.valid) return res.status(400).json({ error: pwdCheck.reason });

    const roleRow = db.prepare('SELECT id FROM roles WHERE name = ?').get(roleName) as { id: number } | undefined;
    if (!roleRow) return res.status(400).json({ error: 'Invalid role specified.' });

    const clash = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (clash) return res.status(409).json({ error: 'Username or email already exists.' });

    const hash = bcrypt.hashSync(password, 10);
    const insertRes = db
      .prepare(
        'INSERT INTO users (username, email, full_name, password_hash, role_id) VALUES (?, ?, ?, ?, ?)'
      )
      .run(username, email, fullName, hash, roleRow.id);
    const newId = Number(insertRes.lastInsertRowid);

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'USER_CREATED',
      'user',
      String(newId),
      `Admin created user ${username} (${roleName})`,
      getClientIp(req)
    );
    ingestSecurityEventAndEvaluate(db, {
      source_ip: getClientIp(req),
      username: req.user!.username,
      event_type: 'Administrative Activity',
      description: `Administrator created user account "${username}" with role ${roleName}.`,
      severity: 'Low',
      user_agent: String(req.headers['user-agent'] || ''),
    });

    const created = db
      .prepare(
        'SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.created_at, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?'
      )
      .get(newId);
    res.status(201).json({ user: created });
  });

  app.patch('/api/users/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid user ID' });

    const existing = db.prepare(`SELECT u.id, u.username, u.is_active, r.name AS role
      FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?`).get(id) as
      | { id: number; username: string; is_active: number; role: string }
      | undefined;
    if (!existing) return res.status(404).json({ error: 'User not found' });

    const proposedRole = req.body?.role !== undefined ? sanitizeText(req.body.role, 30) : existing.role;
    const proposedActive = req.body?.is_active !== undefined ? (req.body.is_active ? 1 : 0) : existing.is_active;
    if (id === req.user!.id && (proposedActive === 0 || proposedRole !== 'ADMIN')) {
      return res.status(400).json({ error: 'You cannot disable or demote your own administrator account.' });
    }
    if (existing.role === 'ADMIN' && existing.is_active === 1 && (proposedRole !== 'ADMIN' || proposedActive === 0)) {
      const admins = db.prepare(`SELECT COUNT(*) AS total FROM users u JOIN roles r ON r.id = u.role_id
        WHERE r.name = 'ADMIN' AND u.is_active = 1`).get() as { total: number };
      if (admins.total <= 1) return res.status(400).json({ error: 'The last active administrator cannot be removed.' });
    }
    if (req.body?.role !== undefined) {
      const roleName = sanitizeText(req.body.role, 30);
      const roleRow = db.prepare('SELECT id FROM roles WHERE name = ?').get(roleName) as { id: number } | undefined;
      if (!roleRow) return res.status(400).json({ error: 'Invalid role.' });
      db.prepare('UPDATE users SET role_id = ? WHERE id = ?').run(roleRow.id, id);
    }

    if (req.body?.is_active !== undefined) {
      const nextActive = req.body.is_active ? 1 : 0;
      if (id === req.user!.id && nextActive === 0) {
        return res.status(400).json({ error: 'You cannot disable your own administrator account.' });
      }
      db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(nextActive, id);
    }

    if (req.body?.unlock === true) {
      db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(id);
    }

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'USER_UPDATED',
      'user',
      String(id),
      `Updated user ${existing.username}`,
      getClientIp(req)
    );

    const updated = db
      .prepare(
        'SELECT u.id, u.username, u.email, u.full_name, u.is_active, u.failed_login_attempts, u.locked_until, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?'
      )
      .get(id);
    res.json({ user: updated });
  });

  // Admin-Only Settings & Detection Rules
  app.get('/api/settings', requireAuth, requireAdmin, (_req: AuthenticatedRequest, res: Response) => {
    const settings = db.prepare('SELECT * FROM system_settings ORDER BY id ASC').all();
    const rules = db.prepare('SELECT * FROM detection_rules ORDER BY id ASC').all();
    const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 40').all();
    res.json({ settings, rules, auditLogs });
  });

  app.patch('/api/settings', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
    const updates = req.body?.settings;
    if (!updates || typeof updates !== 'object') {
      return res.status(400).json({ error: 'Settings payload object is required.' });
    }

    const knownSettings = new Set((db.prepare('SELECT setting_key FROM system_settings').all() as Array<{ setting_key: string }>).map(r => r.setting_key));
    for (const [key, val] of Object.entries(updates)) {
      if (!knownSettings.has(key)) return res.status(400).json({ error: `Unknown setting: ${key}` });
      if (typeof val !== 'string' && typeof val !== 'number') return res.status(400).json({ error: `Invalid value for ${key}` });
      const text = String(val);
      if (text.length > 400) return res.status(400).json({ error: `Setting value too long: ${key}` });
      if (key === 'allowlisted_ips' && text.trim() && !text.split(',').every(ip => isValidIPv4(ip.trim()))) {
        return res.status(400).json({ error: 'Allowlist must contain valid comma-separated IPv4 addresses.' });
      }
      if (key === 'auto_refresh_seconds' && (!/^\d+$/.test(text) || Number(text) < 5 || Number(text) > 300)) {
        return res.status(400).json({ error: 'Refresh interval must be 5-300 seconds.' });
      }
      if (key === 'max_login_lockout_attempts' && (!/^\d+$/.test(text) || Number(text) < 5 || Number(text) > 100)) {
        return res.status(400).json({ error: 'Lockout threshold must be 5-100 attempts.' });
      }
    }
    const stmt = db.prepare(
      "UPDATE system_settings SET setting_value = ?, updated_by = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE setting_key = ?"
    );
    for (const [key, val] of Object.entries(updates)) {
      stmt.run(sanitizeText(String(val), 400), req.user!.id, key);
    }

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'SETTINGS_UPDATED',
      'system_settings',
      'global',
      `Updated keys: ${Object.keys(updates).join(', ')}`,
      getClientIp(req)
    );

    const settings = db.prepare('SELECT * FROM system_settings ORDER BY id ASC').all();
    res.json({ settings });
  });

  app.patch('/api/rules/:id', requireAuth, requireAdmin, (req: AuthenticatedRequest, res: Response) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid rule ID' });

    const rule = db.prepare('SELECT * FROM detection_rules WHERE id = ?').get(id) as unknown as
      | DetectionRuleConfig
      | undefined;
    if (!rule) return res.status(404).json({ error: 'Detection rule not found' });

    const rawThreshold = Number(req.body?.threshold);
    const threshold =
      req.body?.threshold !== undefined && Number.isFinite(rawThreshold)
        ? Math.max(1, Math.min(500, Math.round(rawThreshold)))
        : rule.threshold;
    const rawWindow = Number(req.body?.time_window_minutes);
    const windowMin =
      req.body?.time_window_minutes !== undefined && Number.isFinite(rawWindow)
        ? Math.max(1, Math.min(1440, Math.round(rawWindow)))
        : rule.time_window_minutes;
    const severity =
      req.body?.severity !== undefined && SEVERITY_LEVELS.includes(req.body.severity)
        ? req.body.severity
        : rule.severity;
    const isEnabled = req.body?.is_enabled !== undefined ? (req.body.is_enabled ? 1 : 0) : rule.is_enabled;

    db.prepare(
      `UPDATE detection_rules
       SET threshold = ?, time_window_minutes = ?, severity = ?, is_enabled = ?,
           updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE id = ?`
    ).run(threshold, windowMin, severity, isEnabled, id);

    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'DETECTION_RULE_UPDATED',
      'detection_rule',
      rule.rule_code,
      `Threshold=${threshold}, Window=${windowMin}m, Severity=${severity}, Enabled=${isEnabled}`,
      getClientIp(req)
    );

    const updated = db.prepare('SELECT * FROM detection_rules WHERE id = ?').get(id);
    res.json({ rule: updated });
  });

  // Dedicated Threat Detection Engine View Endpoint (All Authenticated SOC Operators)
  app.get('/api/detection/rules', requireAuth, (_req: AuthenticatedRequest, res: Response) => {
    const rules = db
      .prepare(
        `SELECT dr.*,
                COUNT(a.id) AS alerts_triggered_count,
                MAX(a.created_at) AS last_triggered_at
         FROM detection_rules dr
         LEFT JOIN alerts a ON a.rule_id = dr.id
         GROUP BY dr.id
         ORDER BY dr.id ASC`
      )
      .all();
    const allowSetting = db
      .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'allowlisted_ips'")
      .get() as { setting_value: string } | undefined;
    res.json({
      rules,
      allowlistedIps: Array.from(parseAllowlistedIps(allowSetting?.setting_value || '')),
    });
  });

  // Dedicated Audit Logs Module Endpoints
  const queryAuditLogs = (req: AuthenticatedRequest, limit = 200) => {
    const search = sanitizeText(req.query.search, 100).toLowerCase();
    const action = sanitizeText(req.query.action, 60);
    const resourceType = sanitizeText(req.query.resource_type, 60);
    const startDate = sanitizeText(req.query.startDate, 40);
    const endDate = sanitizeText(req.query.endDate, 40);

    const conditions: string[] = ['1=1'];
    const params: Array<string | number> = [];

    if (req.user!.role !== 'ADMIN') {
      conditions.push(
        "(user_id = ? OR resource_type IN ('alert', 'incident', 'security_event', 'threat_indicator', 'detection_engine', 'report'))"
      );
      params.push(req.user!.id);
    }

    if (search) {
      conditions.push(
        '(LOWER(username) LIKE ? OR LOWER(action) LIKE ? OR LOWER(resource_type) LIKE ? OR LOWER(resource_id) LIKE ? OR LOWER(details) LIKE ? OR LOWER(ip_address) LIKE ?)'
      );
      const q = `%${search}%`;
      params.push(q, q, q, q, q, q);
    }
    if (action && action !== 'ALL') {
      conditions.push('action = ?');
      params.push(action);
    }
    if (resourceType && resourceType !== 'ALL') {
      conditions.push('resource_type = ?');
      params.push(resourceType);
    }
    if (startDate) {
      const startMs = Date.parse(startDate);
      if (!Number.isNaN(startMs)) {
        conditions.push('created_at >= ?');
        params.push(new Date(startMs).toISOString());
      }
    }
    if (endDate) {
      const endMs = Date.parse(endDate);
      if (!Number.isNaN(endMs)) {
        conditions.push('created_at <= ?');
        params.push(new Date(endMs + 86_399_999).toISOString());
      }
    }

    const safeLimit = Math.min(500, Math.max(10, Number(req.query.limit ?? limit) || limit));
    return db
      .prepare(
        `SELECT id, user_id, username, action, resource_type, resource_id, details, ip_address, created_at
         FROM audit_logs
         WHERE ${conditions.join(' AND ')}
         ORDER BY id DESC LIMIT ?`
      )
      .all(...params, safeLimit) as Array<{
      id: number;
      user_id: number | null;
      username: string;
      action: string;
      resource_type: string;
      resource_id: string;
      details: string;
      ip_address: string;
      created_at: string;
    }>;
  };

  app.get('/api/audit-logs', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const logs = queryAuditLogs(req, 250);
    const scopeClause =
      req.user!.role === 'ADMIN'
        ? '1=1'
        : `(user_id = ${Number(req.user!.id)} OR resource_type IN ('alert', 'incident', 'security_event', 'threat_indicator', 'detection_engine', 'report'))`;
    const actions = (
      db.prepare(`SELECT DISTINCT action FROM audit_logs WHERE ${scopeClause} ORDER BY action ASC`).all() as Array<{
        action: string;
      }>
    ).map((r) => r.action);
    const resourceTypes = (
      db
        .prepare(`SELECT DISTINCT resource_type FROM audit_logs WHERE ${scopeClause} ORDER BY resource_type ASC`)
        .all() as Array<{ resource_type: string }>
    ).map((r) => r.resource_type);

    res.json({
      logs,
      actions,
      resourceTypes,
      scope: req.user!.role === 'ADMIN' ? 'all' : 'operational',
    });
  });

  app.get('/api/audit-logs/export/csv', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const logs = queryAuditLogs(req, 500);
    const columns = ['id', 'created_at', 'username', 'action', 'resource_type', 'resource_id', 'ip_address', 'details'];
    const header = columns.map(escapeCsvCell).join(',');
    const lines = logs.map((row) =>
      columns.map((col) => escapeCsvCell((row as Record<string, unknown>)[col])).join(',')
    );
    const csv = [header, ...lines].join('\r\n');
    recordAudit(
      db,
      req.user!.id,
      req.user!.username,
      'AUDIT_LOG_EXPORTED_CSV',
      'audit_log',
      'csv',
      `Exported ${logs.length} audit log records`,
      getClientIp(req)
    );
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="cloudsoc_audit_logs.csv"');
    res.send(csv);
  });

  return app;
}
