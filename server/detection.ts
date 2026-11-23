import type { AlertStatus, EventType, SeverityLevel } from './validation';

export interface DetectionRuleConfig {
  id: number;
  rule_code: string;
  name: string;
  description: string;
  event_type_target: string;
  threshold: number;
  time_window_minutes: number;
  severity: SeverityLevel;
  is_enabled: number;
  explanation_template: string;
}

export interface SecurityEventRecord {
  id: number;
  event_uid: string;
  timestamp: string;
  source_ip: string;
  username: string;
  event_type: EventType;
  description: string;
  severity: SeverityLevel;
  user_agent: string;
  detection_status: string;
}

export interface ActiveAlertRecord {
  id: number;
  rule_id: number;
  source_ip: string;
  target_username: string;
  status: AlertStatus;
  window_end: string;
}

export interface ThreatIndicatorMatch {
  indicator_value: string;
  verdict: string;
  reputation_score: number;
  source: string;
}

export interface RuleMatchCandidate {
  rule: DetectionRuleConfig;
  title: string;
  description: string;
  explanation: string;
  severity: SeverityLevel;
  source_ip: string;
  target_username: string;
  event_count: number;
  window_start: string;
  window_end: string;
  emit_summary_event: boolean;
}

export function parseAllowlistedIps(rawSetting: string): Set<string> {
  return new Set(
    String(rawSetting || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

export function hasActiveAlertInWindow(
  activeAlerts: ActiveAlertRecord[],
  ruleId: number,
  sourceIp: string,
  targetUsername: string,
  eventTimeIso: string,
  windowMinutes: number
): boolean {
  const eventMs = new Date(eventTimeIso).getTime();
  const windowMs = windowMinutes * 60 * 1000;
  return activeAlerts.some((alert) => {
    if (alert.rule_id !== ruleId) return false;
    if (alert.status === 'Resolved' || alert.status === 'False Positive') return false;
    const sameIp = sourceIp && alert.source_ip === sourceIp;
    const sameUser = targetUsername && alert.target_username === targetUsername;
    if (!sameIp && !sameUser) return false;
    const alertEndMs = new Date(alert.window_end).getTime();
    return Math.abs(eventMs - alertEndMs) <= windowMs;
  });
}

export function evaluateDetectionRules(params: {
  incomingEvent: SecurityEventRecord;
  recentEvents: SecurityEventRecord[];
  rules: DetectionRuleConfig[];
  activeAlerts: ActiveAlertRecord[];
  allowlistedIps: Set<string>;
  knownMaliciousIps: Map<string, ThreatIndicatorMatch>;
  knownUserIps?: Map<string, Set<string>>;
}): RuleMatchCandidate[] {
  const {
    incomingEvent,
    recentEvents,
    rules,
    activeAlerts,
    allowlistedIps,
    knownMaliciousIps,
    knownUserIps,
  } = params;

  if (allowlistedIps.has(incomingEvent.source_ip)) {
    return [];
  }

  const eventMs = new Date(incomingEvent.timestamp).getTime();
  const matches: RuleMatchCandidate[] = [];

  for (const rule of rules) {
    if (!rule.is_enabled) continue;

    const windowMs = Math.max(1, rule.time_window_minutes) * 60 * 1000;
    const windowStartIso = new Date(eventMs - windowMs).toISOString();

    const inWindow = recentEvents.filter((ev) => {
      const t = new Date(ev.timestamp).getTime();
      return t >= eventMs - windowMs && t <= eventMs;
    });

    if (rule.rule_code === 'RULE-001' && incomingEvent.event_type === 'Failed Login') {
      const sameIpFails = inWindow.filter(
        (ev) => ev.event_type === 'Failed Login' && ev.source_ip === incomingEvent.source_ip
      );
      const sameUserFails = inWindow.filter(
        (ev) =>
          ev.event_type === 'Failed Login' &&
          incomingEvent.username &&
          incomingEvent.username !== 'unknown' &&
          ev.username === incomingEvent.username
      );
      const peakCount = Math.max(sameIpFails.length, sameUserFails.length);
      if (peakCount >= rule.threshold) {
        if (
          !hasActiveAlertInWindow(
            activeAlerts,
            rule.id,
            incomingEvent.source_ip,
            incomingEvent.username,
            incomingEvent.timestamp,
            rule.time_window_minutes
          )
        ) {
          matches.push({
            rule,
            title: `Brute-Force Attempt Detected from ${incomingEvent.source_ip}`,
            description: `${peakCount} failed login attempts observed within ${rule.time_window_minutes} minutes targeting account "${incomingEvent.username}".`,
            explanation: `Rule ${rule.rule_code} triggered because ${peakCount} failed authentication events met or exceeded the configured threshold of ${rule.threshold} inside a ${rule.time_window_minutes}-minute sliding window.`,
            severity: rule.severity,
            source_ip: incomingEvent.source_ip,
            target_username: incomingEvent.username,
            event_count: peakCount,
            window_start: windowStartIso,
            window_end: incomingEvent.timestamp,
            emit_summary_event: true,
          });
        }
      }
    } else if (rule.rule_code === 'RULE-002' && incomingEvent.event_type === 'Failed Login') {
      const sameIpFails = inWindow.filter(
        (ev) => ev.event_type === 'Failed Login' && ev.source_ip === incomingEvent.source_ip
      );
      const bruteForceRule = rules.find(r => r.rule_code === 'RULE-001' && r.is_enabled);
      const bruteForceThreshold = bruteForceRule?.threshold ?? Number.POSITIVE_INFINITY;
      if (sameIpFails.length >= rule.threshold && sameIpFails.length < bruteForceThreshold) {
        if (
          !hasActiveAlertInWindow(
            activeAlerts,
            rule.id,
            incomingEvent.source_ip,
            incomingEvent.username,
            incomingEvent.timestamp,
            rule.time_window_minutes
          )
        ) {
          matches.push({
            rule,
            title: `Repeated Authentication Failures (${incomingEvent.source_ip})`,
            description: `${sameIpFails.length} repeated login failures detected for user "${incomingEvent.username}" within ${rule.time_window_minutes} minutes.`,
            explanation: `Rule ${rule.rule_code} detected ${sameIpFails.length} failed login attempts (threshold: ${rule.threshold} in ${rule.time_window_minutes} min), indicating password guessing or credential stuffing.`,
            severity: rule.severity,
            source_ip: incomingEvent.source_ip,
            target_username: incomingEvent.username,
            event_count: sameIpFails.length,
            window_start: windowStartIso,
            window_end: incomingEvent.timestamp,
            emit_summary_event: false,
          });
        }
      }
    } else if (
      rule.rule_code === 'RULE-003' &&
      incomingEvent.event_type === 'Unauthorized Access'
    ) {
      const unauthEvents = inWindow.filter(
        (ev) =>
          ev.event_type === 'Unauthorized Access' && ev.source_ip === incomingEvent.source_ip
      );
      if (unauthEvents.length >= rule.threshold) {
        if (
          !hasActiveAlertInWindow(
            activeAlerts,
            rule.id,
            incomingEvent.source_ip,
            incomingEvent.username,
            incomingEvent.timestamp,
            rule.time_window_minutes
          )
        ) {
          matches.push({
            rule,
            title: `Unauthorized Access Attempts from ${incomingEvent.source_ip}`,
            description: `${unauthEvents.length} unauthorized endpoint or privilege access attempts blocked for "${incomingEvent.username}".`,
            explanation: `Rule ${rule.rule_code} matched ${unauthEvents.length} Unauthorized Access events (threshold: ${rule.threshold}) within ${rule.time_window_minutes} minutes.`,
            severity: rule.severity,
            source_ip: incomingEvent.source_ip,
            target_username: incomingEvent.username,
            event_count: unauthEvents.length,
            window_start: windowStartIso,
            window_end: incomingEvent.timestamp,
            emit_summary_event: false,
          });
        }
      }
    } else if (rule.rule_code === 'RULE-004') {
      const threat = knownMaliciousIps.get(incomingEvent.source_ip);
      const flaggedEvents = inWindow.filter(ev => ev.source_ip === incomingEvent.source_ip);
      if (threat && (threat.verdict === 'Malicious' || threat.verdict === 'Suspicious') && flaggedEvents.length >= rule.threshold) {
        if (
          !hasActiveAlertInWindow(
            activeAlerts,
            rule.id,
            incomingEvent.source_ip,
            incomingEvent.username,
            incomingEvent.timestamp,
            rule.time_window_minutes
          )
        ) {
          matches.push({
            rule,
            title: `Suspicious IP Reputation Activity (${incomingEvent.source_ip})`,
            description: `Event "${incomingEvent.event_type}" originated from flagged IP ${incomingEvent.source_ip} (Reputation Score: ${threat.reputation_score}/100, Verdict: ${threat.verdict}).`,
            explanation: `Rule ${rule.rule_code} correlated source IP ${incomingEvent.source_ip} against threat intelligence records (${threat.source}) with verdict ${threat.verdict}.`,
            severity: threat.verdict === 'Malicious' ? 'Critical' : rule.severity,
            source_ip: incomingEvent.source_ip,
            target_username: incomingEvent.username,
            event_count: flaggedEvents.length,
            window_start: windowStartIso,
            window_end: incomingEvent.timestamp,
            emit_summary_event: false,
          });
        }
      }
    } else if (
      rule.rule_code === 'RULE-005' &&
      (incomingEvent.event_type === 'Suspicious Access' ||
        (incomingEvent.event_type === 'Successful Login' &&
          knownUserIps &&
          incomingEvent.username &&
          knownUserIps.has(incomingEvent.username) &&
          !knownUserIps.get(incomingEvent.username)!.has(incomingEvent.source_ip)))
    ) {
      const unusualEventCount = inWindow.filter(ev =>
        ev.username === incomingEvent.username &&
        (ev.event_type === 'Suspicious Access' ||
          (ev.event_type === 'Successful Login' && knownUserIps?.has(ev.username) &&
            !knownUserIps.get(ev.username)!.has(ev.source_ip)))
      ).length;
      if (
        unusualEventCount >= rule.threshold &&
        !hasActiveAlertInWindow(
          activeAlerts,
          rule.id,
          incomingEvent.source_ip,
          incomingEvent.username,
          incomingEvent.timestamp,
          rule.time_window_minutes
        )
      ) {
        matches.push({
          rule,
          title: `Unusual Login Activity for ${incomingEvent.username}`,
          description: `Unfamiliar source IP ${incomingEvent.source_ip} or suspicious access pattern detected for "${incomingEvent.username}".`,
          explanation: `Rule ${rule.rule_code} detected either a Suspicious Access event or a login from a previously unseen IP (${incomingEvent.source_ip}) for user "${incomingEvent.username}".`,
          severity: rule.severity,
          source_ip: incomingEvent.source_ip,
          target_username: incomingEvent.username,
          event_count: unusualEventCount,
          window_start: windowStartIso,
          window_end: incomingEvent.timestamp,
          emit_summary_event: false,
        });
      }
    }
  }

  return matches;
}
