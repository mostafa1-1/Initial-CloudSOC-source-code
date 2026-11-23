import React, { useCallback, useEffect, useState } from 'react';
import { Play, ShieldCheck, X } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { DetectionRule, RoleName, SeverityLevel } from '../types';
import type { NavRoute } from '../components/Layout';

interface DetectionEnginePageProps {
  userRole: RoleName;
  onNavigate: (route: NavRoute) => void;
}

export const DetectionEnginePage: React.FC<DetectionEnginePageProps> = ({ userRole, onNavigate }) => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [allowlistedIps, setAllowlistedIps] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [testingRule, setTestingRule] = useState(false);
  const [simIp, setSimIp] = useState('198.51.100.245');
  const [simUser, setSimUser] = useState('rule_verify_target');
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const isAdmin = userRole === 'ADMIN';

  const loadRules = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiRequest<{ rules: DetectionRule[]; allowlistedIps: string[] }>('/api/detection/rules');
      setRules(data.rules);
      setAllowlistedIps(data.allowlistedIps);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Unable to load detection engine rules.',
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleRuleUpdate = async (
    rule: DetectionRule,
    updates: Partial<{ threshold: number; time_window_minutes: number; severity: SeverityLevel; is_enabled: boolean }>
  ) => {
    setBanner(null);
    try {
      await apiRequest(`/api/rules/${rule.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      });
      setBanner({ type: 'success', text: `Updated detection rule ${rule.rule_code}.` });
      await loadRules();
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to update detection rule.',
      });
    }
  };

  const handleRunVerificationBurst = async (e: React.FormEvent) => {
    e.preventDefault();
    setTestingRule(true);
    setBanner(null);
    try {
      const res = await apiRequest<{
        attemptsExecuted: number;
        alertsTriggered: Array<{ alert_uid: string; title: string; severity: string }>;
      }>('/api/events/simulate-bruteforce', {
        method: 'POST',
        body: JSON.stringify({
          source_ip: simIp.trim(),
          username: simUser.trim(),
          attempts: 10,
        }),
      });
      setBanner({
        type: 'success',
        text:
          res.alertsTriggered.length > 0
            ? `Verification passed: ${res.attemptsExecuted} events triggered ${res.alertsTriggered
                .map((a) => `${a.alert_uid} (${a.severity})`)
                .join(', ')}.`
            : `Executed ${res.attemptsExecuted} failed login events from ${simIp}. Active window deduplication prevented duplicate alerts.`,
      });
      await loadRules();
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Detection engine test failed.',
      });
    } finally {
      setTestingRule(false);
    }
  };

  const enabledCount = rules.filter((r) => r.is_enabled === 1).length;
  const totalTriggers = rules.reduce((acc, r) => acc + Number(r.alerts_triggered_count ?? 0), 0);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Threat Detection Engine</h2>
          <p className="text-sm text-slate-400">
            Real-time correlation rules, sliding-window thresholds, allowlist exclusions, and rule verification.
          </p>
        </div>

        <button
          type="button"
          onClick={() => onNavigate('alerts')}
          className="px-3.5 py-2 rounded-md border border-slate-700 bg-[#0f172a] hover:bg-slate-800 text-xs font-medium text-white whitespace-nowrap"
        >
          Inspect Generated Alerts
        </button>
      </div>

      {banner && (
        <div
          role="status"
          className={`p-3.5 rounded-md border text-sm flex items-center justify-between gap-4 ${
            banner.type === 'success'
              ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/50 border-rose-500/40 text-rose-200'
          }`}
        >
          <span>{banner.text}</span>
          <button type="button" onClick={() => setBanner(null)} aria-label="Dismiss notification">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Engine Summary Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4">
          <p className="text-xs text-slate-400">Active Detection Rules</p>
          <p className="text-2xl font-bold font-mono text-cyan-300 tabular-nums mt-1">
            {enabledCount} / {rules.length}
          </p>
        </div>
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4">
          <p className="text-xs text-slate-400">Total Alerts Generated</p>
          <p className="text-2xl font-bold font-mono text-white tabular-nums mt-1">{totalTriggers}</p>
        </div>
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4">
          <p className="text-xs text-slate-400">Allowlisted Source IPs</p>
          <p className="text-sm font-mono text-slate-200 mt-2 truncate" title={allowlistedIps.join(', ')}>
            {allowlistedIps.length > 0 ? allowlistedIps.join(', ') : 'None configured'}
          </p>
        </div>
      </div>

      {/* Rules Table / Configuration Cards */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Correlation Rules &amp; Thresholds</h3>
          </div>
          {!isAdmin && (
            <span className="text-xs text-slate-400">
              Read-only transparency mode (Administrators manage thresholds)
            </span>
          )}
        </div>

        <div className="divide-y divide-slate-800/70">
          {loading ? (
            <div className="p-8 text-center text-xs text-slate-400">Loading detection rules...</div>
          ) : (
            rules.map((rule) => (
              <div key={rule.id} className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-1.5 max-w-2xl">
                  <div className="flex flex-wrap items-center gap-2.5">
                    <span className="font-mono text-xs text-cyan-300">{rule.rule_code}</span>
                    <span className="text-sm font-semibold text-white">{rule.name}</span>
                    <StatusTag label={rule.severity} variant={severityVariant(rule.severity)} />
                    <StatusTag label={rule.is_enabled ? 'Active' : 'Paused'} variant={rule.is_enabled ? 'low' : 'neutral'} />
                  </div>
                  <p className="text-xs text-slate-400">{rule.description}</p>
                  <p className="text-xs font-mono text-slate-400">
                    Target Event: <span className="text-slate-200">{rule.event_type_target}</span> · Alerts Fired:{' '}
                    <span className="text-cyan-300 tabular-nums">{rule.alerts_triggered_count ?? 0}</span> · Last Fired:{' '}
                    <span className="text-slate-300">{formatTimestamp(rule.last_triggered_at)}</span>
                  </p>
                </div>

                {isAdmin ? (
                  <div className="flex flex-wrap items-center gap-3 text-xs shrink-0">
                    <label className="flex items-center gap-1.5 text-slate-300">
                      <span>Threshold:</span>
                      <input
                        type="number"
                        min={1}
                        max={200}
                        aria-label={`${rule.rule_code} threshold`}
                        defaultValue={rule.threshold}
                        onBlur={(e) => {
                          const val = Number(e.target.value);
                          if (val > 0 && val !== rule.threshold) {
                            handleRuleUpdate(rule, { threshold: val });
                          }
                        }}
                        className="w-16 px-2 py-1.5 rounded bg-[#080d1a] border border-slate-700 font-mono text-white"
                      />
                    </label>

                    <label className="flex items-center gap-1.5 text-slate-300">
                      <span>Window (m):</span>
                      <input
                        type="number"
                        min={1}
                        max={1440}
                        aria-label={`${rule.rule_code} window minutes`}
                        defaultValue={rule.time_window_minutes}
                        onBlur={(e) => {
                          const val = Number(e.target.value);
                          if (val > 0 && val !== rule.time_window_minutes) {
                            handleRuleUpdate(rule, { time_window_minutes: val });
                          }
                        }}
                        className="w-16 px-2 py-1.5 rounded bg-[#080d1a] border border-slate-700 font-mono text-white"
                      />
                    </label>

                    <select
                      aria-label={`${rule.rule_code} severity`}
                      value={rule.severity}
                      onChange={(e) => handleRuleUpdate(rule, { severity: e.target.value as SeverityLevel })}
                      className="px-2.5 py-1.5 rounded bg-[#080d1a] border border-slate-700 text-white"
                    >
                      <option value="Critical">Critical</option>
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>

                    <button
                      type="button"
                      onClick={() => handleRuleUpdate(rule, { is_enabled: !rule.is_enabled })}
                      className={`px-3 py-1.5 rounded border font-medium ${
                        rule.is_enabled
                          ? 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300'
                          : 'border-slate-700 bg-slate-900 text-slate-400'
                      }`}
                    >
                      {rule.is_enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-4 text-xs font-mono text-slate-300 shrink-0">
                    <span>Threshold: {rule.threshold}</span>
                    <span>Window: {rule.time_window_minutes}m</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Authorized Rule Verification Workflow */}
      <form
        onSubmit={handleRunVerificationBurst}
        className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-4"
      >
        <div>
          <h3 className="text-sm font-semibold text-white">Controlled Rule Trigger Verification (RULE-001)</h3>
          <p className="text-xs text-slate-400 mt-1">
            Ingest 10 controlled Failed Login events inside the sandbox to verify real-time correlation and automatic
            Critical alert creation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label htmlFor="sim-engine-ip" className="block text-xs text-slate-300 mb-1">
              Test Source IPv4
            </label>
            <input
              id="sim-engine-ip"
              type="text"
              value={simIp}
              onChange={(e) => setSimIp(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs font-mono text-white"
              required
            />
          </div>
          <div>
            <label htmlFor="sim-engine-user" className="block text-xs text-slate-300 mb-1">
              Test Target Username
            </label>
            <input
              id="sim-engine-user"
              type="text"
              value={simUser}
              onChange={(e) => setSimUser(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
              required
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={testingRule}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-xs font-semibold text-white"
            >
              <Play className="h-3.5 w-3.5" />
              <span>{testingRule ? 'Executing 10 Events...' : 'Trigger 10-Event Burst Test'}</span>
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
