import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import type { IndicatorType } from './validation';

export interface ThreatLookupResult {
  indicator_type: IndicatorType;
  indicator_value: string;
  reputation_score: number;
  verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  source: 'VirusTotal' | 'AbuseIPDB' | 'Local Demonstration';
  demo_mode: boolean;
  cached: boolean;
  raw_summary: Record<string, unknown>;
  checked_at: string;
}

const DEMO_MALICIOUS_IPS: Record<string, { score: number; category: string; country: string; reports: number }> = {
  '185.220.101.42': { score: 92, category: 'Tor Exit Node / Credential Stuffing', country: 'DE', reports: 148 },
  '45.155.205.91': { score: 84, category: 'SSH & HTTP Auth Brute-Force Scanner', country: 'NL', reports: 93 },
  '194.26.135.88': { score: 79, category: 'Botnet Command & Control Relay', country: 'RU', reports: 67 },
  '203.0.113.77': { score: 61, category: 'Repeated Failed Authentication Source', country: 'US', reports: 19 },
};

const DEMO_CLEAN_IPS = new Set(['8.8.8.8', '1.1.1.1', '9.9.9.9', '127.0.0.1']);

async function fetchWithTimeout(url: string, headers: Record<string, string>, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    return res;
  } finally {
    clearTimeout(timer);
  }
}

function deterministicDemoResult(
  indicatorType: IndicatorType,
  indicatorValue: string
): Omit<ThreatLookupResult, 'cached' | 'checked_at'> {
  if (indicatorType === 'ipv4') {
    const known = DEMO_MALICIOUS_IPS[indicatorValue];
    if (known) {
      return {
        indicator_type: indicatorType,
        indicator_value: indicatorValue,
        reputation_score: known.score,
        verdict: known.score >= 75 ? 'Malicious' : 'Suspicious',
        source: 'Local Demonstration',
        demo_mode: true,
        raw_summary: {
          mode: 'Local Demonstration (no live API credentials configured)',
          abuseConfidenceScore: known.score,
          category: known.category,
          countryCode: known.country,
          totalReports: known.reports,
        },
      };
    }
    if (DEMO_CLEAN_IPS.has(indicatorValue) || indicatorValue.startsWith('10.') || indicatorValue.startsWith('192.168.')) {
      return {
        indicator_type: indicatorType,
        indicator_value: indicatorValue,
        reputation_score: 0,
        verdict: 'Clean',
        source: 'Local Demonstration',
        demo_mode: true,
        raw_summary: {
          mode: 'Local Demonstration (no live API credentials configured)',
          abuseConfidenceScore: 0,
          category: 'Well-Known DNS / Private RFC1918 Range',
          totalReports: 0,
        },
      };
    }
  }

  // Deterministic pseudo-classification strictly labeled as Local Demonstration
  const digest = crypto.createHash('sha256').update(`${indicatorType}:${indicatorValue}`).digest()[0];
  const isFlagged =
    indicatorValue.includes('malicious') ||
    indicatorValue.includes('phish') ||
    indicatorValue.includes('c2') ||
    digest >= 215;
  const isSuspicious = !isFlagged && (indicatorValue.includes('verify') || digest >= 165);
  const score = isFlagged ? 82 : isSuspicious ? 48 : 4;
  const verdict = isFlagged ? 'Malicious' : isSuspicious ? 'Suspicious' : 'Clean';

  return {
    indicator_type: indicatorType,
    indicator_value: indicatorValue,
    reputation_score: score,
    verdict,
    source: 'Local Demonstration',
    demo_mode: true,
    raw_summary: {
      mode: 'Local Demonstration (deterministic offline evaluation — configure VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY for live intelligence)',
      simulatedRiskScore: score,
      indicatorType,
      classification: verdict,
    },
  };
}

export async function lookupThreatIndicator(
  db: DatabaseSync,
  indicatorType: IndicatorType,
  indicatorValue: string,
  userId: number
): Promise<ThreatLookupResult> {
  const nowIso = new Date().toISOString();
  const cachedRow = db
    .prepare(
      `SELECT * FROM threat_indicators
       WHERE indicator_type = ? AND indicator_value = ? AND cached_until > ?
       ORDER BY id DESC LIMIT 1`
    )
    .get(indicatorType, indicatorValue, nowIso) as
    | {
        indicator_type: IndicatorType;
        indicator_value: string;
        reputation_score: number;
        verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
        source: 'VirusTotal' | 'AbuseIPDB' | 'Local Demonstration';
        raw_summary: string;
        created_at: string;
      }
    | undefined;

  if (cachedRow) {
    let parsed: Record<string, unknown> = {};
    try {
      parsed = JSON.parse(cachedRow.raw_summary);
    } catch {
      parsed = { note: cachedRow.raw_summary };
    }
    return {
      indicator_type: cachedRow.indicator_type,
      indicator_value: cachedRow.indicator_value,
      reputation_score: cachedRow.reputation_score,
      verdict: cachedRow.verdict,
      source: cachedRow.source,
      demo_mode: cachedRow.source === 'Local Demonstration',
      cached: true,
      raw_summary: parsed,
      checked_at: cachedRow.created_at,
    };
  }

  const vtKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  const abuseKey = process.env.ABUSEIPDB_API_KEY?.trim();
  let result: Omit<ThreatLookupResult, 'cached' | 'checked_at'> | null = null;

  if (indicatorType === 'ipv4' && abuseKey) {
    try {
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicatorValue)}&maxAgeInDays=90`;
      const resp = await fetchWithTimeout(url, { Key: abuseKey, Accept: 'application/json' });
      if (resp.status === 429) {
        throw new Error('AbuseIPDB rate limit exceeded');
      }
      if (resp.ok) {
        const json = (await resp.json()) as {
          data?: {
            abuseConfidenceScore?: number;
            countryCode?: string;
            isp?: string;
            totalReports?: number;
          };
        };
        const score = Number(json.data?.abuseConfidenceScore ?? 0);
        result = {
          indicator_type: indicatorType,
          indicator_value: indicatorValue,
          reputation_score: score,
          verdict: score >= 75 ? 'Malicious' : score >= 25 ? 'Suspicious' : 'Clean',
          source: 'AbuseIPDB',
          demo_mode: false,
          raw_summary: {
            abuseConfidenceScore: score,
            countryCode: json.data?.countryCode || 'Unknown',
            isp: json.data?.isp || 'Unknown',
            totalReports: json.data?.totalReports ?? 0,
          },
        };
      }
    } catch {
      result = null;
    }
  } else if (vtKey) {
    try {
      let vtPath = '';
      if (indicatorType === 'ipv4') vtPath = `ip_addresses/${encodeURIComponent(indicatorValue)}`;
      else if (indicatorType === 'domain') vtPath = `domains/${encodeURIComponent(indicatorValue)}`;
      else if (indicatorType === 'hash') vtPath = `files/${encodeURIComponent(indicatorValue)}`;
      else if (indicatorType === 'url') {
        const encodedUrl = Buffer.from(indicatorValue).toString('base64url');
        vtPath = `urls/${encodedUrl}`;
      }
      if (vtPath) {
        const resp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/${vtPath}`, {
          'x-apikey': vtKey,
          Accept: 'application/json',
        });
        if (resp.status === 429) {
          throw new Error('VirusTotal rate limit exceeded');
        }
        if (resp.ok) {
          const json = (await resp.json()) as {
            data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
          };
          const stats = json.data?.attributes?.last_analysis_stats ?? {};
          const malicious = Number(stats.malicious ?? 0);
          const suspicious = Number(stats.suspicious ?? 0);
          const total = Math.max(1, malicious + suspicious + Number(stats.harmless ?? 0) + Number(stats.undetected ?? 0));
          const score = Math.min(100, Math.round(((malicious * 1.0 + suspicious * 0.5) / total) * 100));
          result = {
            indicator_type: indicatorType,
            indicator_value: indicatorValue,
            reputation_score: score,
            verdict: malicious >= 3 ? 'Malicious' : malicious > 0 || suspicious > 0 ? 'Suspicious' : 'Clean',
            source: 'VirusTotal',
            demo_mode: false,
            raw_summary: { last_analysis_stats: stats },
          };
        }
      }
    } catch {
      result = null;
    }
  }

  if (!result) {
    result = deterministicDemoResult(indicatorType, indicatorValue);
  }

  const cacheSetting = db
    .prepare("SELECT setting_value FROM system_settings WHERE setting_key = 'threat_intel_cache_hours'")
    .get() as { setting_value: string } | undefined;
  const cacheHours = Math.max(1, Number(cacheSetting?.setting_value ?? 24) || 24);
  const cachedUntil = new Date(Date.now() + cacheHours * 3600_000).toISOString();

  db.prepare(
    `INSERT INTO threat_indicators (indicator_type, indicator_value, reputation_score, verdict, source, raw_summary, queried_by, cached_until)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    result.indicator_type,
    result.indicator_value,
    result.reputation_score,
    result.verdict,
    result.source,
    JSON.stringify(result.raw_summary),
    userId,
    cachedUntil
  );

  return {
    ...result,
    cached: false,
    checked_at: nowIso,
  };
}
