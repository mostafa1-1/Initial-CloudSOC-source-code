import React, { useEffect, useState } from 'react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { DetectionRule, SeverityLevel } from '../types';

interface SystemSettingRow {
  id: number;
  setting_key: string;
  setting_value: string;
  description: string;
  updated_at: string;
}

interface AuditLogRow {
  id: number;
  username: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: string;
  created_at: string;
}

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [settingMeta, setSettingMeta] = useState<SystemSettingRow[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogRow[]>([]);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadSettings = async () => {
    try {
      const data = await apiRequest<{
        settings: SystemSettingRow[];
        rules: DetectionRule[];
        auditLogs: AuditLogRow[];
      }>('/api/settings');
      setSettingMeta(data.settings);
      const map: Record<string, string> = {};
      data.settings.forEach((s) => {
        map[s.setting_key] = s.setting_value;
      });
      setSettings(map);
      setRules(data.rules);
      setAuditLogs(data.auditLogs);
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Unable to load system settings.',
      });
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiRequest('/api/settings', {
        method: 'PATCH',
        body: JSON.stringify({ settings }),
      });
      setBanner({ type: 'success', text: 'System security settings saved.' });
      await loadSettings();
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to save system settings.',
      });
    }
  };

  const handleRuleUpdate = async (
    rule: DetectionRule,
    updates: Partial<{ threshold: number; time_window_minutes: number; severity: SeverityLevel; is_enabled: boolean }>
  ) => {
    try {
      await apiRequest(`/api/rules/${rule.id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      });
      setBanner({ type: 'success', text: `Updated detection rule ${rule.rule_code}.` });
      await loadSettings();
    } catch (err) {
      setBanner({
        type: 'error',
        text: err instanceof Error ? err.message : 'Failed to update detection rule.',
      });
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">Detection Rules &amp; System Settings</h2>
        <p className="text-sm text-slate-400">
          Configure rule thresholds, sliding time windows, allowlisted IPs, and lockout policies.
        </p>
      </div>

      {banner && (
        <div
          role="status"
          className={`p-3.5 rounded-md border text-sm ${
            banner.type === 'success'
              ? 'bg-emerald-950/50 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/50 border-rose-500/40 text-rose-200'
          }`}
        >
          {banner.text}
        </div>
      )}

      {/* Detection Rules Configuration */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800">
          <h3 className="text-sm font-semibold text-white">Rule-Based Threat Detection Engine</h3>
        </div>
        <div className="divide-y divide-slate-800/70">
          {rules.map((rule) => (
            <div key={rule.id} className="p-4 flex flex-wrap items-center justify-between gap-4">
              <div className="max-w-xl space-y-1">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs text-cyan-300">{rule.rule_code}</span>
                  <span className="text-sm font-medium text-white">{rule.name}</span>
                  <StatusTag label={rule.severity} variant={severityVariant(rule.severity)} />
                </div>
                <p className="text-xs text-slate-400">{rule.description}</p>
              </div>

              <div className="flex flex-wrap items-center gap-3 text-xs">
                <label className="flex items-center gap-1.5 text-slate-300">
                  <span>Threshold:</span>
                  <input
                    type="number"
                    min={1}
                    max={200}
                    defaultValue={rule.threshold}
                    onBlur={(e) => {
                      const val = Number(e.target.value);
                      if (val > 0 && val !== rule.threshold) {
                        handleRuleUpdate(rule, { threshold: val });
                      }
                    }}
                    className="w-16 px-2 py-1 rounded bg-[#080d1a] border border-slate-700 font-mono text-white"
                  />
                </label>

                <label className="flex items-center gap-1.5 text-slate-300">
                  <span>Window (m):</span>
                  <input
                    type="number"
                    min={1}
                    max={1440}
                    defaultValue={rule.time_window_minutes}
                    onBlur={(e) => {
                      const val = Number(e.target.value);
                      if (val > 0 && val !== rule.time_window_minutes) {
                        handleRuleUpdate(rule, { time_window_minutes: val });
                      }
                    }}
                    className="w-16 px-2 py-1 rounded bg-[#080d1a] border border-slate-700 font-mono text-white"
                  />
                </label>

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
            </div>
          ))}
        </div>
      </div>

      {/* Global Settings Form */}
      <form onSubmit={handleSaveSettings} className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-4">
        <h3 className="text-sm font-semibold text-white">False-Positive Allowlist &amp; Security Parameters</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {settingMeta.map((meta) => (
            <div key={meta.setting_key}>
              <label className="block text-xs font-medium text-slate-300 mb-1 font-mono">
                {meta.setting_key}
              </label>
              <input
                type="text"
                value={settings[meta.setting_key] ?? ''}
                onChange={(e) =>
                  setSettings((prev) => ({ ...prev, [meta.setting_key]: e.target.value }))
                }
                className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs font-mono text-white"
              />
              <p className="text-xs text-slate-500 mt-1">{meta.description}</p>
            </div>
          ))}
        </div>
        <div className="flex justify-end">
          <button
            type="submit"
            className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
          >
            Save System Settings
          </button>
        </div>
      </form>

      {/* Audit Logs */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-800">
          <h3 className="text-sm font-semibold text-white">System Audit Log</h3>
        </div>
        <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/70">
          {auditLogs.map((log) => (
            <div key={log.id} className="px-4 py-2.5 text-xs flex flex-wrap justify-between gap-2">
              <div>
                <span className="font-mono text-cyan-300">{log.action}</span>
                <span className="text-slate-400"> · {log.username} · </span>
                <span className="text-slate-200">{log.details}</span>
              </div>
              <span className="font-mono text-slate-500">{formatTimestamp(log.created_at)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
