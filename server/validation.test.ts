import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidIPv4,
  isValidDomain,
  isValidUrl,
  isValidHash,
  validatePasswordStrength,
  validateThreatIndicator,
  isValidIncidentTransition,
  escapeCsvCell,
  redactSensitiveFields,
} from './validation';

test('IPv4 validation accepts valid addresses and rejects invalid ones', () => {
  assert.equal(isValidIPv4('192.168.1.10'), true);
  assert.equal(isValidIPv4('185.220.101.42'), true);
  assert.equal(isValidIPv4('999.1.1.1'), false);
  assert.equal(isValidIPv4('10.0.0'), false);
  assert.equal(isValidIPv4("1.1.1.1' OR 1=1--"), false);
});

test('Threat indicator validator checks domain, URL, and SHA-256 hash', () => {
  assert.equal(isValidDomain('malicious-c2.example.org'), true);
  assert.equal(isValidDomain('not a domain'), false);
  assert.equal(isValidUrl('https://phishing.example.com/login'), true);
  assert.equal(isValidUrl('javascript:alert(1)'), false);
  assert.equal(
    isValidHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    true
  );
  assert.equal(validateThreatIndicator('ipv4', '8.8.8.8').valid, true);
  assert.equal(validateThreatIndicator('hash', 'short').valid, false);
});

test('Password strength rejects weak passwords and accepts strong ones', () => {
  assert.equal(validatePasswordStrength('12345').valid, false);
  assert.equal(validatePasswordStrength('lowercase1').valid, false);
  assert.equal(validatePasswordStrength('Analyst@2026').valid, true);
});

test('Incident status transitions allow valid lifecycle steps and reject invalid', () => {
  assert.equal(isValidIncidentTransition('NEW', 'INVESTIGATING'), true);
  assert.equal(isValidIncidentTransition('INVESTIGATING', 'CONTAINED'), true);
  assert.equal(isValidIncidentTransition('CONTAINED', 'RESOLVED'), true);
  assert.equal(isValidIncidentTransition('RESOLVED', 'NEW'), false);
});

test('CSV escaping prevents formula injection and quotes commas', () => {
  assert.equal(escapeCsvCell('=CMD()'), "'=CMD()");
  assert.equal(escapeCsvCell('hello, world'), '"hello, world"');
});

test('Sensitive field redaction masks passwords in log descriptions', () => {
  const cleaned = redactSensitiveFields('Failed login with password=SuperSecret123 from 10.0.0.2');
  assert.equal(cleaned.includes('SuperSecret123'), false);
  assert.equal(cleaned.includes('[REDACTED]'), true);
});
