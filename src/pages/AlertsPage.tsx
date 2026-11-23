import React, { useCallback, useEffect, useState } from 'react';
import { ArrowUpRight, Search, X } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { AlertRecord, AlertStatus, SecurityEvent } from '../types';

interface AlertsPageProps {
  onEscalateSuccess: () => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({ onEscalateSuccess }) => {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [analysts, setAnalysts] = useState<Array<{ id: number; username: string; full_name: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sort, setSort] = useState('newest');
  const [selected, setSelected] = useState<{
    alert: AlertRecord;
    relatedEvents: SecurityEvent[];
    linkedIncidents: Array<{ id: number; incident_uid: string; status: string }>;
  } | null>(null);
  const [editStatus, setEditStatus] = useState<AlertStatus>('New');
  const [editAssignee, setEditAssignee] = useState<string>('');
  const [editNotes, setEditNotes] = useState('');
  const [saving, setSaving] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams({ sort });
      if (search.trim()) qs.set('search', search.trim());
      if (severity !== 'ALL') qs.set('severity', severity);
      if (statusFilter !== 'ALL') qs.set('status', statusFilter);
      const data = await apiRequest<{
        alerts: AlertRecord[];
        analysts: Array<{ id: number; username: string; full_name: string }>;
      }>(`/api/alerts?${qs.toString()}`);
      setAlerts(data.alerts);
      setAnalysts(data.analysts);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unable to load alerts.' });
    } finally {
      setLoading(false);
    }
  }, [search, severity, statusFilter, sort]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const openAlertDetail = async (id: number) => {
    try {
      const data = await apiRequest<{
        alert: AlertRecord;
        relatedEvents: SecurityEvent[];
        linkedIncidents: Array<{ id: number; incident_uid: string; status: string }>;
      }>(`/api/alerts/${id}`);
      setSelected(data);
      setEditStatus(data.alert.status);
      setEditAssignee(data.alert.assigned_to ? String(data.alert.assigned_to) : '');
      setEditNotes(data.alert.investigation_notes || '');
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unable to inspect alert.' });
    }
  };

  const handleSaveAlert = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    setSaving(true);
    try {
      await apiRequest(`/api/alerts/${selected.alert.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: editStatus,
          assigned_to: editAssignee ? Number(editAssignee) : null,
          investigation_notes: editNotes,
        }),
      });
      setBanner({ type: 'success', text: `Updated alert ${selected.alert.alert_uid}.` });
      await loadAlerts();
      await openAlertDetail(selected.alert.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to save alert.' });
    } finally {
      setSaving(false);
    }
  };

  const handleEscalate = async () => {
    if (!selected) return;
    setSaving(true);
    try {
      const res = await apiRequest<{ incident: { incident_uid: string } }>(
        `/api/alerts/${selected.alert.id}/escalate`,
        { method: 'POST', body: JSON.stringify({ priority: selected.alert.severity }) }
      );
      setBanner({
        type: 'success',
        text: `Escalated ${selected.alert.alert_uid} to incident ${res.incident.incident_uid}.`,
      });
      setSelected(null);
      await loadAlerts();
      onEscalateSuccess();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to escalate alert.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-white">Security Alerts</h2>
        <p className="text-sm text-slate-400">
          Investigate rule-triggered alerts, record triage notes, and escalate confirmed threats to incidents.
        </p>
      </div>

      {banner && (
        <div
          role="status"
          className={`p-3.5 rounded-md border text-sm flex items-center justify-between ${
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

      {/* Filters */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="relative">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search alert ID, title, IP..."
            aria-label="Search alerts"
            className="w-full pl-9 pr-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          />
        </div>

        <select
          aria-label="Filter alerts by severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        >
          <option value="ALL">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          aria-label="Filter alerts by status"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        >
          <option value="ALL">All Statuses</option>
          <option value="New">New</option>
          <option value="Acknowledged">Acknowledged</option>
          <option value="Investigating">Investigating</option>
          <option value="Resolved">Resolved</option>
          <option value="False Positive">False Positive</option>
        </select>

        <select
          aria-label="Sort alerts"
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
        >
          <option value="newest">Sort: Newest First</option>
          <option value="oldest">Sort: Oldest First</option>
          <option value="severity">Sort: Highest Severity</option>
        </select>
      </div>

      {/* Alerts Table */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Alert ID</th>
                <th className="px-4 py-3 font-medium">Title &amp; Rule</th>
                <th className="px-4 py-3 font-medium">Source IP</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Assigned</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-400">
                    Loading alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                    No alerts match the current filter.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      <span>{alert.alert_uid}</span>
                      {alert.is_demo === 1 && (
                        <span className="ml-2">
                          <StatusTag label="Demo Data" variant="neutral" />
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-white font-medium">{alert.title}</p>
                      <p className="text-slate-400 font-mono mt-0.5">
                        {alert.rule_code} · {alert.event_count} event(s)
                      </p>
                    </td>
                    <td className="px-4 py-3 font-mono text-cyan-300 whitespace-nowrap">{alert.source_ip}</td>
                    <td className="px-4 py-3">
                      <StatusTag label={alert.severity} variant={severityVariant(alert.severity)} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusTag label={alert.status} variant={severityVariant(alert.status)} />
                    </td>
                    <td className="px-4 py-3 text-slate-300">{alert.assigned_username}</td>
                    <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimestamp(alert.created_at)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => openAlertDetail(alert.id)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Investigation Modal */}
      {selected && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-2xl w-full p-6 space-y-5 my-8">
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
              <div>
                <p className="font-mono text-xs text-cyan-400">
                  {selected.alert.alert_uid} · {selected.alert.rule_code} ({selected.alert.rule_name})
                </p>
                <h3 className="text-base font-semibold text-white mt-0.5">{selected.alert.title}</h3>
              </div>
              <button type="button" onClick={() => setSelected(null)} aria-label="Close modal">
                <X className="h-5 w-5 text-slate-400 hover:text-white" />
              </button>
            </div>

            <div className="p-3.5 rounded bg-[#080d1a] border border-slate-800 text-xs space-y-1.5">
              <p className="font-medium text-slate-200">Detection Explanation</p>
              <p className="text-slate-400">{selected.alert.explanation}</p>
              <p className="font-mono text-slate-400 pt-1">
                Target: {selected.alert.target_username} · Source IP: {selected.alert.source_ip}
              </p>
            </div>

            <form onSubmit={handleSaveAlert} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Alert Status</label>
                  <select
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value as AlertStatus)}
                    className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  >
                    <option value="New">New</option>
                    <option value="Acknowledged">Acknowledged</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Resolved">Resolved</option>
                    <option value="False Positive">False Positive</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Assign Analyst</label>
                  <select
                    value={editAssignee}
                    onChange={(e) => setEditAssignee(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  >
                    <option value="">Unassigned</option>
                    {analysts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.username} ({a.full_name})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs text-slate-300 mb-1">Investigation Notes</label>
                <textarea
                  rows={3}
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Document findings, verification steps, or false-positive justification..."
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                />
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={handleEscalate}
                  disabled={saving}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md border border-amber-500/50 bg-amber-950/50 hover:bg-amber-900/60 text-xs font-semibold text-amber-200"
                >
                  <ArrowUpRight className="h-3.5 w-3.5" />
                  <span>Escalate to Incident</span>
                </button>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setSelected(null)}
                    className="px-4 py-2 rounded-md border border-slate-700 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    Close
                  </button>
                  <button
                    type="submit"
                    disabled={saving}
                    className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
                  >
                    {saving ? 'Saving...' : 'Save Triage'}
                  </button>
                </div>
              </div>
            </form>

            {/* Related Events */}
            <div className="border-t border-slate-800 pt-3">
              <p className="text-xs font-semibold text-slate-300 mb-2">
                Related Security Events ({selected.relatedEvents.length})
              </p>
              <div className="max-h-40 overflow-y-auto divide-y divide-slate-800/70 border border-slate-800 rounded">
                {selected.relatedEvents.map((ev) => (
                  <div key={ev.id} className="px-3 py-2 text-xs flex items-center justify-between gap-3">
                    <span className="font-mono text-slate-300">
                      {ev.event_uid} · {ev.event_type}
                    </span>
                    <span className="font-mono text-slate-400">{formatTimestamp(ev.timestamp)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
