import React, { useCallback, useEffect, useState } from 'react';
import { Download, Search } from 'lucide-react';
import { apiFetchRaw, apiRequest, formatTimestamp } from '../api';
import type { AuditLogEntry } from '../types';

export const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [actions, setActions] = useState<string[]>([]);
  const [resourceTypes, setResourceTypes] = useState<string[]>([]);
  const [scope, setScope] = useState<'all' | 'operational'>('all');
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');
  const [resourceFilter, setResourceFilter] = useState('ALL');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const buildQs = useCallback(() => {
    const qs = new URLSearchParams();
    if (search.trim()) qs.set('search', search.trim());
    if (actionFilter !== 'ALL') qs.set('action', actionFilter);
    if (resourceFilter !== 'ALL') qs.set('resource_type', resourceFilter);
    if (startDate) qs.set('startDate', startDate);
    if (endDate) qs.set('endDate', endDate);
    return qs.toString();
  }, [search, actionFilter, resourceFilter, startDate, endDate]);

  const loadLogs = useCallback(async () => {
    setLoading(true);
    try {
      const qs = buildQs();
      const data = await apiRequest<{
        logs: AuditLogEntry[];
        actions: string[];
        resourceTypes: string[];
        scope: 'all' | 'operational';
      }>(`/api/audit-logs${qs ? `?${qs}` : ''}`);
      setLogs(data.logs);
      setActions(data.actions);
      setResourceTypes(data.resourceTypes);
      setScope(data.scope);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load audit logs.');
    } finally {
      setLoading(false);
    }
  }, [buildQs]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  const handleExportCsv = async () => {
    setError('');
    try {
      const qs = buildQs();
      const res = await apiFetchRaw(`/api/audit-logs/export/csv${qs ? `?${qs}` : ''}`);
      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cloudsoc_audit_logs.csv';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to export audit logs CSV.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Audit Logs</h2>
          <p className="text-sm text-slate-400">
            Immutable chronological trail of authentication, rule adjustments, alert triage, and incident actions.
            {scope === 'operational' ? ' (Scoped to operational SOC and personal records)' : ''}
          </p>
        </div>

        <button
          type="button"
          onClick={handleExportCsv}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md border border-slate-700 bg-[#0f172a] hover:bg-slate-800 text-xs font-medium text-white whitespace-nowrap"
        >
          <Download className="h-3.5 w-3.5" />
          <span>Export Audit CSV</span>
        </button>
      </div>

      {error && (
        <div role="alert" className="p-3.5 rounded-md bg-rose-950/50 border border-rose-500/40 text-sm text-rose-200">
          {error}
        </div>
      )}

      {/* Search & Filters */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="relative">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search user, action, details..."
            aria-label="Search audit logs"
            className="w-full pl-9 pr-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white placeholder:text-slate-500"
          />
        </div>

        <select
          aria-label="Filter by action"
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        >
          <option value="ALL">All Actions</option>
          {actions.map((act) => (
            <option key={act} value={act}>
              {act}
            </option>
          ))}
        </select>

        <select
          aria-label="Filter by resource type"
          value={resourceFilter}
          onChange={(e) => setResourceFilter(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        >
          <option value="ALL">All Resources</option>
          {resourceTypes.map((rt) => (
            <option key={rt} value={rt}>
              {rt}
            </option>
          ))}
        </select>

        <input
          type="date"
          aria-label="Audit log start date"
          value={startDate}
          onChange={(e) => setStartDate(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        />

        <input
          type="date"
          aria-label="Audit log end date"
          value={endDate}
          onChange={(e) => setEndDate(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        />
      </div>

      {/* Audit Table */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Operator</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Resource</th>
                <th className="px-4 py-3 font-medium">Source IP</th>
                <th className="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-400">
                    Loading audit logs...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-slate-400">
                    No audit records matched the active filters.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimestamp(log.created_at)}
                    </td>
                    <td className="px-4 py-3 font-mono text-white whitespace-nowrap">{log.username}</td>
                    <td className="px-4 py-3 font-mono text-cyan-300 whitespace-nowrap">{log.action}</td>
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      {log.resource_type}
                      {log.resource_id ? `:${log.resource_id}` : ''}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                      {log.ip_address || '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-200">{log.details}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
