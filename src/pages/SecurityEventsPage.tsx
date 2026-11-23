import React, { useCallback, useEffect, useState } from 'react';
import { Database, Play, Plus, Search, X } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { SecurityEvent, SeverityLevel } from '../types';

export const SecurityEventsPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [eventType, setEventType] = useState('ALL');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [showIngest, setShowIngest] = useState(false);
  const [showSim, setShowSim] = useState(false);
  const [banner, setBanner] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Ingest Form State
  const [formIp, setFormIp] = useState('203.0.113.55');
  const [formUser, setFormUser] = useState('j.miller');
  const [formType, setFormType] = useState('Failed Login');
  const [formSeverity, setFormSeverity] = useState<SeverityLevel>('Medium');
  const [formDesc, setFormDesc] = useState('Invalid password entered during SSH/Web portal login.');

  // Brute-Force Simulation State
  const [simIp, setSimIp] = useState('198.51.100.240');
  const [simUser, setSimUser] = useState('target_analyst');
  const [simAttempts, setSimAttempts] = useState(10);
  const [submitting, setSubmitting] = useState(false);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (search.trim()) qs.set('search', search.trim());
      if (severity !== 'ALL') qs.set('severity', severity);
      if (eventType !== 'ALL') qs.set('event_type', eventType);
      if (startDate) qs.set('startDate', startDate);
      if (endDate) qs.set('endDate', endDate);
      const data = await apiRequest<{ events: SecurityEvent[] }>(`/api/events?${qs.toString()}`);
      setEvents(data.events);
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to load events.' });
    } finally {
      setLoading(false);
    }
  }, [search, severity, eventType, startDate, endDate]);

  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setBanner(null);
    try {
      const res = await apiRequest<{
        event: SecurityEvent;
        triggeredAlerts: Array<{ alert_uid: string; title: string }>;
      }>('/api/events', {
        method: 'POST',
        body: JSON.stringify({
          source_ip: formIp,
          username: formUser,
          event_type: formType,
          severity: formSeverity,
          description: formDesc,
        }),
      });
      setShowIngest(false);
      setBanner({
        type: 'success',
        text:
          res.triggeredAlerts.length > 0
            ? `Recorded ${res.event.event_uid} and triggered alert ${res.triggeredAlerts[0].alert_uid}.`
            : `Security event ${res.event.event_uid} recorded and evaluated.`,
      });
      await loadEvents();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to ingest event.' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleSimulateBruteforce = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setBanner(null);
    try {
      const res = await apiRequest<{
        attemptsExecuted: number;
        alertsTriggered: Array<{ alert_uid: string; title: string; severity: string }>;
      }>('/api/events/simulate-bruteforce', {
        method: 'POST',
        body: JSON.stringify({
          source_ip: simIp,
          username: simUser,
          attempts: simAttempts,
        }),
      });
      setShowSim(false);
      setBanner({
        type: 'success',
        text: `Executed ${res.attemptsExecuted} controlled failed login events from ${simIp}. Triggered ${res.alertsTriggered.length} alert(s): ${res.alertsTriggered.map((a) => a.alert_uid).join(', ') || 'Deduplicated within active window'}.`,
      });
      await loadEvents();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Simulation failed.' });
    } finally {
      setSubmitting(false);
    }
  };

  const handleGenerateDemoData = async () => {
    setSubmitting(true);
    setBanner(null);
    try {
      const res = await apiRequest<{ eventsCreated: number; alertsTriggered: Array<{ alert_uid: string }> }>(
        '/api/events/generate-demo-data',
        { method: 'POST' }
      );
      setBanner({
        type: 'success',
        text: `Generated ${res.eventsCreated} realistic demonstration events (labeled Demo Data). Triggered ${res.alertsTriggered.length} alert(s).`,
      });
      await loadEvents();
    } catch (err) {
      setBanner({ type: 'error', text: err instanceof Error ? err.message : 'Failed to generate demo data.' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Event Stream</h2>
          <p className="text-sm text-slate-400">
            Search, filter, and inspect normalized authentication and access telemetry.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={submitting}
            onClick={handleGenerateDemoData}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md border border-slate-700 bg-[#0f172a] hover:bg-slate-800 disabled:opacity-60 text-xs font-medium text-slate-200 transition-colors whitespace-nowrap"
          >
            <Database className="h-3.5 w-3.5" />
            <span>Generate Demo Data</span>
          </button>
          <button
            type="button"
            onClick={() => setShowSim(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md border border-cyan-500/40 bg-cyan-950/40 hover:bg-cyan-900/50 text-xs font-medium text-cyan-200 transition-colors whitespace-nowrap"
          >
            <Play className="h-3.5 w-3.5" />
            <span>Run Brute-Force Test</span>
          </button>
          <button
            type="button"
            onClick={() => setShowIngest(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white transition-colors whitespace-nowrap"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>Log Security Event</span>
          </button>
        </div>
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

      {/* Search & Filters */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="relative">
          <Search className="h-4 w-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, user, ID..."
            aria-label="Search security events"
            className="w-full pl-9 pr-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="ALL">All Severities</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          aria-label="Filter by event type"
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="ALL">All Event Types</option>
          <option value="Successful Login">Successful Login</option>
          <option value="Failed Login">Failed Login</option>
          <option value="Multiple Failed Logins">Multiple Failed Logins</option>
          <option value="Suspicious Access">Suspicious Access</option>
          <option value="Unauthorized Access">Unauthorized Access</option>
          <option value="Administrative Activity">Administrative Activity</option>
        </select>

        <input
          type="date"
          aria-label="Start date"
          value={startDate}
          onChange={(e) => setStartDate(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        />

        <input
          type="date"
          aria-label="End date"
          value={endDate}
          onChange={(e) => setEndDate(e.target.value)}
          className="px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white focus:outline-none focus:border-cyan-500"
        />
      </div>

      {/* Events Table */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
              <tr>
                <th className="px-4 py-3 font-medium">Event ID</th>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Source IP</th>
                <th className="px-4 py-3 font-medium">Username</th>
                <th className="px-4 py-3 font-medium">Event Type</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Detection Status</th>
                <th className="px-4 py-3 font-medium text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-slate-400">
                    Loading security telemetry...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-10 text-center text-slate-400">
                    No security events matched the active search criteria.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-3 font-mono text-slate-300 whitespace-nowrap">
                      <span>{ev.event_uid}</span>
                      {ev.is_demo === 1 && (
                        <span className="ml-2">
                          <StatusTag label="Demo Data" variant="neutral" />
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </td>
                    <td className="px-4 py-3 font-mono text-cyan-300 whitespace-nowrap">{ev.source_ip}</td>
                    <td className="px-4 py-3 text-slate-200">{ev.username}</td>
                    <td className="px-4 py-3 text-slate-200 whitespace-nowrap">{ev.event_type}</td>
                    <td className="px-4 py-3">
                      <StatusTag label={ev.severity} variant={severityVariant(ev.severity)} />
                    </td>
                    <td className="px-4 py-3 text-slate-300 whitespace-nowrap">
                      {ev.detection_status}
                      {ev.rule_triggered ? ` (${ev.rule_triggered})` : ''}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => setSelectedEvent(ev)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">
                Security Event Details · {selectedEvent.event_uid}
              </h3>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
                aria-label="Close event details"
                className="text-slate-400 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <dl className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <dt className="text-slate-400">Timestamp</dt>
                <dd className="font-mono text-white mt-0.5">{formatTimestamp(selectedEvent.timestamp)}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Source IP</dt>
                <dd className="font-mono text-cyan-300 mt-0.5">{selectedEvent.source_ip}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Username</dt>
                <dd className="text-white mt-0.5">{selectedEvent.username}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Event Type</dt>
                <dd className="text-white mt-0.5">{selectedEvent.event_type}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Severity</dt>
                <dd className="mt-1">
                  <StatusTag label={selectedEvent.severity} variant={severityVariant(selectedEvent.severity)} />
                </dd>
              </div>
              <div>
                <dt className="text-slate-400">Detection Status</dt>
                <dd className="text-white mt-0.5">
                  {selectedEvent.detection_status}
                  {selectedEvent.rule_triggered ? ` (${selectedEvent.rule_triggered})` : ''}
                </dd>
              </div>
              <div className="col-span-2">
                <dt className="text-slate-400">User Agent</dt>
                <dd className="font-mono text-slate-300 mt-0.5 break-all">
                  {selectedEvent.user_agent || 'Not captured'}
                </dd>
              </div>
              <div className="col-span-2">
                <dt className="text-slate-400">Description</dt>
                <dd className="text-slate-200 mt-1 p-3 rounded bg-[#080d1a] border border-slate-800">
                  {selectedEvent.description}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      )}

      {/* Ingest Event Modal */}
      {showIngest && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleIngest}
            className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-md w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">Log Security Event</h3>
              <button type="button" onClick={() => setShowIngest(false)} aria-label="Close modal">
                <X className="h-5 w-5 text-slate-400" />
              </button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-300 mb-1">Source IPv4</label>
                <input
                  type="text"
                  value={formIp}
                  onChange={(e) => setFormIp(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Username</label>
                <input
                  type="text"
                  value={formUser}
                  onChange={(e) => setFormUser(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Event Type</label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value)}
                    className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  >
                    <option value="Successful Login">Successful Login</option>
                    <option value="Failed Login">Failed Login</option>
                    <option value="Suspicious Access">Suspicious Access</option>
                    <option value="Unauthorized Access">Unauthorized Access</option>
                    <option value="Administrative Activity">Administrative Activity</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-slate-300 mb-1">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Description</label>
                <textarea
                  rows={3}
                  value={formDesc}
                  onChange={(e) => setFormDesc(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowIngest(false)}
                className="px-4 py-2 rounded-md border border-slate-700 text-xs text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
              >
                {submitting ? 'Saving...' : 'Submit Event'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Controlled Brute-Force Detection Demo Modal */}
      {showSim && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleSimulateBruteforce}
            className="bg-[#0f172a] border border-slate-700 rounded-lg max-w-md w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-semibold text-white">Authorized Brute-Force Simulation</h3>
              <button type="button" onClick={() => setShowSim(false)} aria-label="Close modal">
                <X className="h-5 w-5 text-slate-400" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Generates controlled Failed Login events inside this isolated SOC sandbox to test RULE-001
              threshold detection and automatic alert generation.
            </p>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-slate-300 mb-1">Simulated Attacker IPv4</label>
                <input
                  type="text"
                  value={simIp}
                  onChange={(e) => setSimIp(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Target Username</label>
                <input
                  type="text"
                  value={simUser}
                  onChange={(e) => setSimUser(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-slate-300 mb-1">Failed Attempts Count (1–20)</label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={simAttempts}
                  onChange={(e) => setSimAttempts(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded bg-[#080d1a] border border-slate-700 text-xs text-white font-mono"
                  required
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowSim(false)}
                className="px-4 py-2 rounded-md border border-slate-700 text-xs text-slate-300 hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white"
              >
                {submitting ? 'Running...' : 'Execute Simulation'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
