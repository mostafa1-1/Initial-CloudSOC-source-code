import React, { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { IndicatorType, ThreatIndicator } from '../types';

interface LookupResponse {
  result: {
    indicator_type: IndicatorType;
    indicator_value: string;
    reputation_score: number;
    verdict: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
    source: string;
    demo_mode: boolean;
    cached: boolean;
    raw_summary: Record<string, unknown>;
    checked_at: string;
  };
}

export const ThreatIntelPage: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [liveApisConfigured, setLiveApisConfigured] = useState(false);
  const [indicatorType, setIndicatorType] = useState<IndicatorType>('ipv4');
  const [indicatorValue, setIndicatorValue] = useState('');
  const [latestResult, setLatestResult] = useState<LookupResponse['result'] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const loadIndicators = async () => {
    try {
      const data = await apiRequest<{ indicators: ThreatIndicator[]; liveApisConfigured: boolean }>(
        '/api/threat-intel'
      );
      setIndicators(data.indicators);
      setLiveApisConfigured(data.liveApisConfigured);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threat intelligence records.');
    }
  };

  useEffect(() => {
    loadIndicators();
  }, []);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await apiRequest<LookupResponse>('/api/threat-intel/lookup', {
        method: 'POST',
        body: JSON.stringify({ indicator_type: indicatorType, indicator_value: indicatorValue.trim() }),
      });
      setLatestResult(data.result);
      await loadIndicators();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Indicator lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">Threat Intelligence Lookup</h2>
        <p className="text-sm text-slate-400">
          Inspect IPv4 addresses, domains, URLs, and file hashes through backend-isolated threat feeds.
        </p>
      </div>

      {!liveApisConfigured && (
        <div className="p-4 rounded-lg bg-amber-950/40 border border-amber-500/40 text-xs text-amber-200">
          <strong>Local Demonstration Mode Active:</strong> Live VirusTotal / AbuseIPDB API keys are not
          configured in environment variables. Indicators are evaluated deterministically using local
          demonstration threat records and clearly attributed as &ldquo;Local Demonstration&rdquo;.
        </div>
      )}

      {/* Lookup Form */}
      <form
        onSubmit={handleLookup}
        className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div>
            <label htmlFor="ti-type" className="block text-xs font-medium text-slate-300 mb-1.5">
              Indicator Type
            </label>
            <select
              id="ti-type"
              value={indicatorType}
              onChange={(e) => setIndicatorType(e.target.value as IndicatorType)}
              className="w-full px-3 py-2.5 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
            >
              <option value="ipv4">IPv4 Address</option>
              <option value="domain">Domain Name</option>
              <option value="url">URL</option>
              <option value="hash">File Hash (MD5 / SHA-1 / SHA-256)</option>
            </select>
          </div>

          <div className="md:col-span-2">
            <label htmlFor="ti-value" className="block text-xs font-medium text-slate-300 mb-1.5">
              Indicator Value
            </label>
            <input
              id="ti-value"
              type="text"
              value={indicatorValue}
              onChange={(e) => setIndicatorValue(e.target.value)}
              placeholder={
                indicatorType === 'ipv4'
                  ? '185.220.101.42'
                  : indicatorType === 'domain'
                    ? 'auth-verify-cloud-login.example.net'
                    : indicatorType === 'url'
                      ? 'https://example.com/login'
                      : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
              }
              className="w-full px-3.5 py-2.5 rounded-md bg-[#080d1a] border border-slate-700 text-xs font-mono text-white placeholder:text-slate-500"
              required
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-xs font-semibold text-white transition-colors"
            >
              <Search className="h-3.5 w-3.5" />
              <span>{loading ? 'Querying...' : 'Analyze Indicator'}</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <span>Quick Test Samples:</span>
          <button
            type="button"
            onClick={() => {
              setIndicatorType('ipv4');
              setIndicatorValue('185.220.101.42');
            }}
            className="text-cyan-400 hover:underline font-mono"
          >
            185.220.101.42
          </button>
          <span>·</span>
          <button
            type="button"
            onClick={() => {
              setIndicatorType('ipv4');
              setIndicatorValue('8.8.8.8');
            }}
            className="text-cyan-400 hover:underline font-mono"
          >
            8.8.8.8
          </button>
          <span>·</span>
          <button
            type="button"
            onClick={() => {
              setIndicatorType('domain');
              setIndicatorValue('phishing-portal.example.org');
            }}
            className="text-cyan-400 hover:underline font-mono"
          >
            phishing-portal.example.org
          </button>
        </div>

        {error && (
          <div role="alert" className="p-3 rounded bg-rose-950/60 border border-rose-500/40 text-xs text-rose-200">
            {error}
          </div>
        )}
      </form>

      {/* Latest Lookup Result */}
      {latestResult && (
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <p className="text-xs text-slate-400">
                {latestResult.indicator_type.toUpperCase()} · Source: {latestResult.source}
                {latestResult.cached ? ' · Cached Result' : ' · Fresh Lookup'}
              </p>
              <h3 className="text-base font-mono font-semibold text-white mt-0.5">
                {latestResult.indicator_value}
              </h3>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className="text-xl font-bold font-mono text-white tabular-nums">
                  {latestResult.reputation_score} / 100
                </p>
              </div>
              <StatusTag label={latestResult.verdict} variant={severityVariant(latestResult.verdict)} />
            </div>
          </div>
          <pre className="p-3 rounded bg-[#080d1a] border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
            {JSON.stringify(latestResult.raw_summary, null, 2)}
          </pre>
        </div>
      )}

      {/* Cached Indicator History */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800/80">
          <h3 className="text-sm font-semibold text-white">Threat Indicator Cache &amp; Query History</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Indicator</th>
                <th className="px-4 py-3 font-medium">Score</th>
                <th className="px-4 py-3 font-medium">Verdict</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Queried By</th>
                <th className="px-4 py-3 font-medium">Checked At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {indicators.map((ind) => (
                <tr key={ind.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3 font-mono text-slate-300">{ind.indicator_type}</td>
                  <td className="px-4 py-3 font-mono text-cyan-300 break-all">{ind.indicator_value}</td>
                  <td className="px-4 py-3 font-mono text-white tabular-nums">{ind.reputation_score}</td>
                  <td className="px-4 py-3">
                    <StatusTag label={ind.verdict} variant={severityVariant(ind.verdict)} />
                  </td>
                  <td className="px-4 py-3 text-slate-300">{ind.source}</td>
                  <td className="px-4 py-3 text-slate-300">{ind.queried_by_username || 'system'}</td>
                  <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                    {formatTimestamp(ind.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
