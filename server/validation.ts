export type RoleName = 'ADMIN' | 'SECURITY_ANALYST';
export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type EventType =
  | 'Successful Login'
  | 'Failed Login'
  | 'Multiple Failed Logins'
  | 'Suspicious Access'
  | 'Unauthorized Access'
  | 'Administrative Activity';

export type AlertStatus = 'New' | 'Acknowledged' | 'Investigating' | 'Resolved' | 'False Positive';
export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
export type IndicatorType = 'ipv4' | 'domain' | 'url' | 'hash';

export const SEVERITY_LEVELS: readonly SeverityLevel[] = ['Critical', 'High', 'Medium', 'Low'];
export const EVENT_TYPES: readonly EventType[] = [
  'Successful Login',
  'Failed Login',
  'Multiple Failed Logins',
  'Suspicious Access',
  'Unauthorized Access',
  'Administrative Activity',
];
export const ALERT_STATUSES: readonly AlertStatus[] = [
  'New',
  'Acknowledged',
  'Investigating',
  'Resolved',
  'False Positive',
];
export const INCIDENT_STATUSES: readonly IncidentStatus[] = [
  'NEW',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
];

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const DOMAIN_REGEX =
  /^(?=.{3,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
const HASH_REGEX = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,32}$/;

export function isValidIPv4(value: string): boolean {
  return IPV4_REGEX.test(value.trim());
}

export function isValidDomain(value: string): boolean {
  return DOMAIN_REGEX.test(value.trim());
}

export function isValidUrl(value: string): boolean {
  try {
    const parsed = new URL(value.trim());
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function isValidHash(value: string): boolean {
  return HASH_REGEX.test(value.trim());
}

export function isValidEmail(value: string): boolean {
  return value.length <= 120 && EMAIL_REGEX.test(value.trim());
}

export function isValidUsername(value: string): boolean {
  return USERNAME_REGEX.test(value.trim());
}

export function validatePasswordStrength(password: string): { valid: boolean; reason?: string } {
  if (typeof password !== 'string' || password.length < 8) {
    return { valid: false, reason: 'Password must be at least 8 characters long.' };
  }
  if (password.length > 128) {
    return { valid: false, reason: 'Password must not exceed 128 characters.' };
  }
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    return {
      valid: false,
      reason: 'Password must include uppercase, lowercase, and numeric characters.',
    };
  }
  return { valid: true };
}

export function validateThreatIndicator(
  indicatorType: string,
  indicatorValue: string
): { valid: boolean; normalized: string; error?: string } {
  const trimmed = String(indicatorValue || '').trim();
  if (!trimmed) {
    return { valid: false, normalized: '', error: 'Indicator value is required.' };
  }
  switch (indicatorType) {
    case 'ipv4':
      return isValidIPv4(trimmed)
        ? { valid: true, normalized: trimmed }
        : { valid: false, normalized: trimmed, error: 'Invalid IPv4 address format.' };
    case 'domain':
      return isValidDomain(trimmed)
        ? { valid: true, normalized: trimmed.toLowerCase() }
        : { valid: false, normalized: trimmed, error: 'Invalid domain name format.' };
    case 'url':
      return isValidUrl(trimmed)
        ? { valid: true, normalized: trimmed }
        : { valid: false, normalized: trimmed, error: 'URL must begin with http:// or https://.' };
    case 'hash':
      return isValidHash(trimmed)
        ? { valid: true, normalized: trimmed.toLowerCase() }
        : {
            valid: false,
            normalized: trimmed,
            error: 'Hash must be a valid MD5 (32), SHA-1 (40), or SHA-256 (64) hex digest.',
          };
    default:
      return { valid: false, normalized: trimmed, error: 'Unsupported indicator type.' };
  }
}

export function isValidIncidentTransition(current: IncidentStatus, next: IncidentStatus): boolean {
  const allowed: Record<IncidentStatus, IncidentStatus[]> = {
    NEW: ['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'],
    INVESTIGATING: ['INVESTIGATING', 'CONTAINED', 'RESOLVED'],
    CONTAINED: ['CONTAINED', 'INVESTIGATING', 'RESOLVED'],
    RESOLVED: ['RESOLVED', 'INVESTIGATING'],
  };
  return allowed[current]?.includes(next) ?? false;
}

export function sanitizeText(value: unknown, maxLength = 500): string {
  if (typeof value !== 'string') return '';
  return value.replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, maxLength);
}

export function redactSensitiveFields(text: string): string {
  return text.replace(/(password|passwd|pwd|secret|token)\s*[:=]\s*\S+/gi, '$1=[REDACTED]');
}

export function escapeCsvCell(value: unknown): string {
  const str = String(value ?? '');
  const formulaSafe = /^[=+\-@]/.test(str) ? `'${str}` : str;
  if (/[",\n\r]/.test(formulaSafe)) {
    return `"${formulaSafe.replace(/"/g, '""')}"`;
  }
  return formulaSafe;
}
