import React, { useCallback, useEffect, useState } from 'react';
import { Plus, Search, X } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { IncidentRecord, IncidentStatus, SeverityLevel } from '../types';

interface IncidentDetailPayload {
  incident: IncidentRecord;
  notes: Array<{ id: number; author_username: string; note: string; created_at: string }>;
  actions: Array<{
    id: number;
    performed_by_username: string;
    action_type: string;
    action_details: string;
    status: string;
    created_at: string;
  }>;
  auditTrail: Array<{ id: number; username: string; action: string; details: string; created_at: string }>;
}

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [analysts, setAnalysts] = useState<Array<{ id: number; username: string; full_name: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedDetail, setSelectedDetail] = useState<IncidentDetailPayload | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  // Create Manual Incident
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newPriority, setNewPriority] = useState<SeverityLevel>('High');

  // Detail Updates
  const [noteInput, setNoteInput] = useState('');
  const [actionType, setActionType] = useState('Credential Rotation');
  const [actionDetails, setActionDetails] = useState('');
  const [resolutionSummary, setResolutionSummary] = useState('');
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (search.trim()) qs.set('search', search.trim());
      if (statusFilter !== 'ALL') qs.set('status', statusFilter);
      const data = await apiRequest<{
        incidents: IncidentRecord[];
        analysts: Array<{ id: number; username: string; full_name: string }>;
      }>(`/api/incidents?${qs.toString()}`);
      setIncidents(data.incidents);
      setAnalysts(data.analysts);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unable to load incidents.' });
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter]);

  useEffect(() => {
    loadIncidents();
  }, [loadIncidents]);

  const openDetail = async (id: number) => {
    try {
      const data = await apiRequest<IncidentDetailPayload>(`/api/incidents/${id}`);
      setSelectedDetail(data);
      setResolutionSummary(data.incident.resolution_summary || '');
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Unable to open incident case.' });
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiRequest<{ incident: IncidentRecord }>('/api/incidents', {
        method: 'POST',
        body: JSON.stringify({ title: newTitle, description: newDesc, priority: newPriority }),
      });
      setShowCreate(false);
      setNewTitle('');
      setNewDesc('');
      setBanner({ type: 'success', text: `Created incident ${res.incident.incident_uid}.` });
      await loadIncidents();
      await openDetail(res.incident.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to create incident.' });
    }
  };

  const handleTransition = async (nextStatus: IncidentStatus) => {
    if (!selectedDetail) return;
    try {
      await apiRequest(`/api/incidents/${selectedDetail.incident.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          status: nextStatus,
          resolution_summary: resolutionSummary,
        }),
      });
      setBanner({ type: 'success', text: `Incident ${selectedDetail.incident.incident_uid} updated to ${nextStatus}.` });
      await loadIncidents();
      await openDetail(selectedDetail.incident.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Lifecycle transition failed.' });
    }
  };

  const handleAssign = async (assigneeId: string) => {
    if (!selectedDetail) return;
    try {
      await apiRequest(`/api/incidents/${selectedDetail.incident.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ assigned_to: assigneeId ? Number(assigneeId) : null }),
      });
      await loadIncidents();
      await openDetail(selectedDetail.incident.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to assign analyst.' });
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDetail || !noteInput.trim()) return;
    try {
      await apiRequest(`/api/incidents/${selectedDetail.incident.id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ note: noteInput.trim() }),
      });
      setNoteInput('');
      await openDetail(selectedDetail.incident.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to record note.' });
    }
  };

  const handleAddAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDetail || !actionDetails.trim()) return;
    try {
      await apiRequest(`/api/incidents/${selectedDetail.incident.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({ action_type: actionType, action_details: actionDetails.trim() }),
      });
      setActionDetails('');
      await openDetail(selectedDetail.incident.id);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to record response action.' });
    }
  };

  const LIFECYCLE: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'];
  const ALLOWED_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
    NEW: ['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'],
    INVESTIGATING: ['INVESTIGATING', 'CONTAINED', 'RESOLVED'],
    CONTAINED: ['CONTAINED', 'INVESTIGATING', 'RESOLVED'],
    RESOLVED: ['RESOLVED', 'INVESTIGATING'],
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Incident Response Management</h2>
          <p className="text-sm text-slate-400">
            Manage incident lifecycles (NEW → INVESTIGATING → CONTAINED → RESOLVED) with full audit trails.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setShowCreate(true)}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white whitespace-nowrap"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>Create Incident</span>
        </button>
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

      {/* Search & Status Filter */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search incident ID or title..."
            aria-label="Search incidents"
            className="w-full pl-9 pr-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          />
        </div>
        <div className="flex items-center gap-1 p-1 bg-[#080d1a] border border-slate-800 rounded-md">
          {['ALL', ...LIFECYCLE].map((st) => (
            <button
              key={st}
              type="button"
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1.5 text-xs font-medium rounded whitespace-nowrap ${
                statusFilter === st ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Incident ID</th>
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Priority</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Assigned Analyst</th>
                <th className="px-4 py-3 font-medium">Updated</th>
                <th className="px-4 py-3 font-medium text-right">Manage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-400">
                    Loading incidents...
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-slate-400">
                    No incidents found.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      <span>{inc.incident_uid}</span>
                      {inc.is_demo === 1 && (
                        <span className="ml-2">
                          <StatusTag label="Demo Data" variant="neutral" />
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-white font-medium">{inc.title}</p>
                      {inc.alert_uid && (
                        <p className="text-slate-400 font-mono mt-0.5">Linked Alert: {inc.alert_uid}</p>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <StatusTag label={inc.priority} variant={severityVariant(inc.priority)} />
                    </td>
                    <td className="px-4 py-3">
                      <StatusTag label={inc.status} variant={severityVariant(inc.status)} />
                    </td>
                    <td className="px-4 py-3 text-slate-300">{inc.assigned_username || 'Unassigned'}</td>
                    <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimestamp(inc.updated_at)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => openDetail(inc.id)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                      >
                        Open Case
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Incident Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-md w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">Create Manual Incident</h3>
              <button type="button" onClick={() => setShowCreate(false)} aria-label="Close modal">
                <X className="h-5 w-5 text-slate-400" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-300 mb-1">Incident Title</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Suspicious API Credential Misuse"
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Priority</label>
                <select
                  value={newPriority}
                  onChange={(e) => setNewPriority(e.target.value as SeverityLevel)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                >
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Describe scope, impacted accounts, and initial indicators..."
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-4 py-2 rounded-md border border-slate-700 text-xs text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
              >
                Create Incident
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Incident Case Workspace Modal */}
      {selectedDetail && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-3xl w-full p-6 space-y-5 my-8 max-h-[90vh] overflow-y-auto">
            <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
              <div>
                <p className="font-mono text-xs text-cyan-400">
                  {selectedDetail.incident.incident_uid} · Priority: {selectedDetail.incident.priority}
                </p>
                <h3 className="text-base font-semibold text-white mt-0.5">{selectedDetail.incident.title}</h3>
              </div>
              <button type="button" onClick={() => setSelectedDetail(null)} aria-label="Close case">
                <X className="h-5 w-5 text-slate-400 hover:text-white" />
              </button>
            </div>

            <p className="text-xs text-slate-300">{selectedDetail.incident.description}</p>

            {/* Lifecycle & Assignment */}
            <div className="p-4 rounded-md bg-[#080d1a] border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span className="text-xs font-medium text-slate-300">Lifecycle Stage</span>
                <div className="flex flex-wrap items-center gap-1.5">
                  {LIFECYCLE.map((step) => {
                    const allowed = ALLOWED_TRANSITIONS[selectedDetail.incident.status]?.includes(step);
                    return (
                      <button
                        key={step}
                        type="button"
                        disabled={!allowed}
                        onClick={() => handleTransition(step)}
                        className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                          selectedDetail.incident.status === step
                            ? 'bg-blue-600 border-blue-500 text-white'
                            : allowed
                              ? 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
                              : 'bg-slate-950 border-slate-800 text-slate-600 cursor-not-allowed'
                        }`}
                      >
                        {step}
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800/80">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Assigned Analyst</label>
                  <select
                    value={selectedDetail.incident.assigned_to ? String(selectedDetail.incident.assigned_to) : ''}
                    onChange={(e) => handleAssign(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-[#0f172a] border border-slate-700 text-xs text-white"
                  >
                    <option value="">Unassigned</option>
                    {analysts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.username} ({a.full_name})
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Resolution Summary</label>
                  <input
                    type="text"
                    value={resolutionSummary}
                    onChange={(e) => setResolutionSummary(e.target.value)}
                    placeholder="Summary recorded when resolving incident"
                    className="w-full px-3 py-2 rounded bg-[#0f172a] border border-slate-700 text-xs text-white"
                  />
                </div>
              </div>
            </div>

            {/* Notes & Response Actions Split */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Investigation Notes */}
              <div className="border border-slate-800 rounded-md p-4 space-y-3">
                <h4 className="text-xs font-semibold text-white">Investigation Notes</h4>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {selectedDetail.notes.map((n) => (
                    <div key={n.id} className="p-2.5 rounded bg-[#080d1a] text-xs space-y-1">
                      <p className="text-slate-200">{n.note}</p>
                      <p className="text-slate-500 font-mono">
                        {n.author_username} · {formatTimestamp(n.created_at)}
                      </p>
                    </div>
                  ))}
                </div>
                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    placeholder="Add investigation note..."
                    className="flex-1 px-2.5 py-1.5 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-xs font-medium text-white"
                  >
                    Add
                  </button>
                </form>
              </div>

              {/* Response Actions */}
              <div className="border border-slate-800 rounded-md p-4 space-y-3">
                <h4 className="text-xs font-semibold text-white">Response Actions (Manual Audit)</h4>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {selectedDetail.actions.length === 0 ? (
                    <p className="text-xs text-slate-500">No response actions recorded yet.</p>
                  ) : (
                    selectedDetail.actions.map((act) => (
                      <div key={act.id} className="p-2.5 rounded bg-[#080d1a] text-xs space-y-1">
                        <p className="font-medium text-cyan-300">{act.action_type}</p>
                        <p className="text-slate-300">{act.action_details}</p>
                        <p className="text-slate-500 font-mono">
                          {act.performed_by_username} · {formatTimestamp(act.created_at)}
                        </p>
                      </div>
                    ))
                  )}
                </div>
                <form onSubmit={handleAddAction} className="space-y-2">
                  <select
                    value={actionType}
                    onChange={(e) => setActionType(e.target.value)}
                    className="w-full px-2.5 py-1.5 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  >
                    <option value="Credential Rotation">Credential Rotation</option>
                    <option value="Session Revocation">Session Revocation</option>
                    <option value="Firewall Advisory Logged">Firewall Advisory Logged</option>
                    <option value="Account Lockout Verified">Account Lockout Verified</option>
                  </select>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={actionDetails}
                      onChange={(e) => setActionDetails(e.target.value)}
                      placeholder="Record containment step..."
                      className="flex-1 px-2.5 py-1.5 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-xs font-medium text-white"
                    >
                      Record
                    </button>
                  </div>
                </form>
              </div>
            </div>

            {/* Audit Trail */}
            <div className="border-t border-slate-800 pt-3">
              <h4 className="text-xs font-semibold text-slate-300 mb-2">Case Audit Trail</h4>
              <div className="space-y-1 max-h-32 overflow-y-auto text-xs font-mono text-slate-400">
                {selectedDetail.auditTrail.map((log) => (
                  <div key={log.id} className="flex justify-between gap-2">
                    <span>
                      [{log.username}] {log.action}: {log.details}
                    </span>
                    <span className="shrink-0">{formatTimestamp(log.created_at)}</span>
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
