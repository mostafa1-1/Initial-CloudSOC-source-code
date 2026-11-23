import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateDetectionRules,
  parseAllowlistedIps,
  type DetectionRuleConfig,
  type SecurityEventRecord,
} from './detection';

const baseRules: DetectionRuleConfig[] = [
  {
    id: 1,
    rule_code: 'RULE-001',
    name: 'Brute-Force Authentication Attempt',
    description: '10 failed logins in 5 minutes',
    event_type_target: 'Failed Login',
    threshold: 10,
    time_window_minutes: 5,
    severity: 'Critical',
    is_enabled: 1,
    explanation_template: '',
  },
  {
    id: 2,
    rule_code: 'RULE-002',
    name: 'Repeated Authentication Failures',
    description: '4 failed logins in 10 minutes',
    event_type_target: 'Failed Login',
    threshold: 4,
    time_window_minutes: 10,
    severity: 'High',
    is_enabled: 1,
    explanation_template: '',
  },
  {
    id: 4,
    rule_code: 'RULE-004',
    name: 'Suspicious IP Reputation',
    description: 'Known malicious IP activity',
    event_type_target: '*',
    threshold: 1,
    time_window_minutes: 60,
    severity: 'High',
    is_enabled: 1,
    explanation_template: '',
  },
];

function makeEvent(id: number, minutesAgo: number, overrides: Partial<SecurityEventRecord> = {}): SecurityEventRecord {
  const ts = new Date(Date.UTC(2026, 10, 19, 12, 0, 0) - minutesAgo * 60_000).toISOString();
  return {
    id,
    event_uid: `EVT-${id}`,
    timestamp: ts,
    source_ip: '203.0.113.50',
    username: 'jdoe',
    event_type: 'Failed Login',
    description: 'Invalid credentials',
    severity: 'Medium',
    user_agent: 'Mozilla/5.0',
    detection_status: 'Processed',
    ...overrides,
  };
}

test('RULE-001 triggers Critical brute-force alert at threshold 10 within 5 minutes', () => {
  const events: SecurityEventRecord[] = [];
  for (let i = 1; i <= 10; i++) {
    events.push(makeEvent(i, (10 - i) * 0.3));
  }
  const incoming = events[events.length - 1];
  const alerts = evaluateDetectionRules({
    incomingEvent: incoming,
    recentEvents: events,
    rules: baseRules,
    activeAlerts: [],
    allowlistedIps: new Set(),
    knownMaliciousIps: new Map(),
  });

  assert.equal(alerts.some((a) => a.rule.rule_code === 'RULE-001' && a.severity === 'Critical'), true);
});

test('Deduplication suppresses duplicate RULE-001 alerts within active window', () => {
  const events: SecurityEventRecord[] = [];
  for (let i = 1; i <= 11; i++) {
    events.push(makeEvent(i, (11 - i) * 0.2));
  }
  const incoming = events[events.length - 1];
  const alerts = evaluateDetectionRules({
    incomingEvent: incoming,
    recentEvents: events,
    rules: baseRules,
    activeAlerts: [
      {
        id: 99,
        rule_id: 1,
        source_ip: '203.0.113.50',
        target_username: 'jdoe',
        status: 'New',
        window_end: incoming.timestamp,
      },
    ],
    allowlistedIps: new Set(),
    knownMaliciousIps: new Map(),
  });

  assert.equal(alerts.some((a) => a.rule.rule_code === 'RULE-001'), false);
});

test('Allowlisted IP skips false-positive rule triggers', () => {
  const events = [makeEvent(1, 0), makeEvent(2, 0.5), makeEvent(3, 1), makeEvent(4, 1.5)];
  const alerts = evaluateDetectionRules({
    incomingEvent: events[0],
    recentEvents: events,
    rules: baseRules,
    activeAlerts: [],
    allowlistedIps: parseAllowlistedIps('203.0.113.50, 10.0.0.1'),
    knownMaliciousIps: new Map(),
  });

  assert.equal(alerts.length, 0);
});

test('RULE-004 triggers when source IP matches malicious threat indicator', () => {
  const ev = makeEvent(50, 0, { source_ip: '185.220.101.42', event_type: 'Successful Login' });
  const alerts = evaluateDetectionRules({
    incomingEvent: ev,
    recentEvents: [ev],
    rules: baseRules,
    activeAlerts: [],
    allowlistedIps: new Set(),
    knownMaliciousIps: new Map([
      [
        '185.220.101.42',
        {
          indicator_value: '185.220.101.42',
          verdict: 'Malicious',
          reputation_score: 94,
          source: 'Local Demonstration',
        },
      ],
    ]),
  });

  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].rule.rule_code, 'RULE-004');
  assert.equal(alerts[0].severity, 'Critical');
});
