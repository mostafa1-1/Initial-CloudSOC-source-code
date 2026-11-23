import React, { useCallback, useEffect, useState } from 'react';
import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LinearScale,
  LineElement,
  PointElement,
  Title,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import { RefreshCw } from 'lucide-react';
import { apiRequest, formatTimestamp } from '../api';
import { StatusTag, severityVariant } from '../components/StatusBadge';
import type { DashboardPayload } from '../types';
import type { NavRoute } from '../components/Layout';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface DashboardPageProps {
  onNavigate: (route: NavRoute) => void;
}

const CHART_TEXT = '#94a3b8';
const CHART_GRID = 'rgba(148, 163, 184, 0.1)';

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [days, setDays] = useState(7);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [data, setData] = useState<DashboardPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadDashboard = useCallback(async () => {
    try {
      const payload = await apiRequest<DashboardPayload>(`/api/dashboard?days=${days}`);
      setData(payload);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard telemetry.');
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    setLoading(true);
    loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(() => {
      loadDashboard();
    }, (data?.refreshIntervalSeconds ?? 30) * 1000);
    return () => clearInterval(timer);
  }, [autoRefresh, loadDashboard, data?.refreshIntervalSeconds]);

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div key={idx} className="h-24 rounded-lg bg-[#0f172a] border border-slate-800 animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-72 rounded-lg bg-[#0f172a] border border-slate-800 animate-pulse" />
          <div className="h-72 rounded-lg bg-[#0f172a] border border-slate-800 animate-pulse" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div role="alert" className="p-6 rounded-lg bg-rose-950/50 border border-rose-500/40 text-rose-200">
        {error}
      </div>
    );
  }

  if (!data) return null;

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: CHART_TEXT, font: { family: 'Plus Jakarta Sans', size: 11 } },
      },
    },
    scales: {
      x: { ticks: { color: CHART_TEXT, font: { size: 11 } }, grid: { color: CHART_GRID } },
      y: {
        beginAtZero: true,
        ticks: { color: CHART_TEXT, precision: 0, font: { size: 11 } },
        grid: { color: CHART_GRID },
      },
    },
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: { color: CHART_TEXT, font: { family: 'Plus Jakarta Sans', size: 11 } },
      },
    },
  };

  const eventsLineData = {
    labels: data.charts.eventsOverTime.map((d) => d.day),
    datasets: [
      {
        label: 'Security Events',
        data: data.charts.eventsOverTime.map((d) => d.count),
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.14)',
        fill: true,
        tension: 0.3,
      },
    ],
  };

  const severityMap: Record<string, string> = {
    Critical: '#f43f5e',
    High: '#f59e0b',
    Medium: '#38bdf8',
    Low: '#10b981',
  };

  const alertsSeverityData = {
    labels: data.charts.alertsBySeverity.map((d) => d.severity),
    datasets: [
      {
        data: data.charts.alertsBySeverity.map((d) => d.count),
        backgroundColor: data.charts.alertsBySeverity.map((d) => severityMap[d.severity] || '#64748b'),
        borderColor: '#0f172a',
        borderWidth: 2,
      },
    ],
  };

  const incidentStatusColors: Record<string, string> = {
    NEW: '#f43f5e',
    INVESTIGATING: '#f59e0b',
    CONTAINED: '#38bdf8',
    RESOLVED: '#10b981',
  };

  const incidentsStatusData = {
    labels: data.charts.incidentsByStatus.map((d) => d.status),
    datasets: [
      {
        label: 'Incidents',
        data: data.charts.incidentsByStatus.map((d) => d.count),
        backgroundColor: data.charts.incidentsByStatus.map((d) => incidentStatusColors[d.status] || '#64748b'),
        borderRadius: 4,
      },
    ],
  };

  const eventCategoriesData = {
    labels: data.charts.eventCategories.map((d) => d.event_type),
    datasets: [
      {
        label: 'Events',
        data: data.charts.eventCategories.map((d) => d.count),
        backgroundColor: '#3b82f6',
        borderRadius: 4,
      },
    ],
  };

  const detectionTrendsData = {
    labels: data.charts.detectionTrends.map((d) => d.day),
    datasets: [
      {
        label: 'Generated Alerts',
        data: data.charts.detectionTrends.map((d) => d.count),
        borderColor: '#f59e0b',
        backgroundColor: 'rgba(245, 158, 11, 0.15)',
        fill: true,
        tension: 0.3,
      },
    ],
  };

  const kpiCards = [
    { label: 'Total Events', value: data.kpis.totalEvents, accent: 'text-white' },
    { label: 'Total Alerts', value: data.kpis.totalAlerts, accent: 'text-cyan-300' },
    { label: 'Critical Alerts', value: data.kpis.criticalAlerts, accent: 'text-rose-400' },
    { label: 'High-Risk Events', value: data.kpis.highRiskEvents, accent: 'text-amber-400' },
    { label: 'Open Incidents', value: data.kpis.openIncidents, accent: 'text-sky-300' },
    { label: 'Resolved Incidents', value: data.kpis.resolvedIncidents, accent: 'text-emerald-400' },
  ];

  return (
    <div className="space-y-6">
      {/* Filter & Refresh Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Operations Overview</h2>
          <p className="text-sm text-slate-400">
            Live database metrics across ingested events, rule detections, and incident workflows.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-1 p-1 bg-[#0f172a] border border-slate-800 rounded-md">
            {[7, 14, 30].map((d) => (
              <button
                key={d}
                type="button"
                onClick={() => setDays(d)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  days === d ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Last {d} Days
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-3 py-2 text-xs font-medium rounded-md border transition-colors whitespace-nowrap ${
              autoRefresh
                ? 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300'
                : 'border-slate-700 bg-[#0f172a] text-slate-400 hover:text-white'
            }`}
          >
            {autoRefresh ? 'Auto-Refresh: On (30s)' : 'Auto-Refresh: Off'}
          </button>

          <button
            type="button"
            onClick={loadDashboard}
            className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-700 bg-[#0f172a] text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {data.demoCounts && data.demoCounts.events > 0 && (
        <div className="px-4 py-2.5 rounded-md bg-slate-900/80 border border-slate-800 text-xs text-slate-300 flex flex-wrap items-center justify-between gap-2">
          <span>
            Database telemetry includes{' '}
            <strong className="text-cyan-300 font-mono">{data.demoCounts.events}</strong> labeled demonstration events,{' '}
            <strong className="text-cyan-300 font-mono">{data.demoCounts.alerts}</strong> demonstration alerts, and{' '}
            <strong className="text-cyan-300 font-mono">{data.demoCounts.incidents}</strong> demonstration incidents alongside live activity.
          </span>
          <span className="font-mono text-slate-400">Source: Live SQLite Database</span>
        </div>
      )}

      {/* 6 KPI Cards */}
      <section aria-label="Key Security Metrics" className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpiCards.map((kpi) => (
          <div
            key={kpi.label}
            className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 flex flex-col justify-between"
          >
            <span className="text-xs font-medium text-slate-400">{kpi.label}</span>
            <span className={`mt-2 text-2xl font-bold font-mono tabular-nums ${kpi.accent}`}>
              {kpi.value}
            </span>
          </div>
        ))}
      </section>

      {/* Primary Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Security Events Over Time</h3>
          <div className="h-64">
            <Line data={eventsLineData} options={baseOptions} />
          </div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Detection Trends (Alerts Generated)</h3>
          <div className="h-64">
            <Line data={detectionTrendsData} options={baseOptions} />
          </div>
        </div>
      </div>

      {/* Secondary Charts Row (3 charts) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Alerts by Severity</h3>
          <div className="h-56">
            <Doughnut data={alertsSeverityData} options={doughnutOptions} />
          </div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Incidents by Status</h3>
          <div className="h-56">
            <Bar data={incidentsStatusData} options={baseOptions} />
          </div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Event Categories</h3>
          <div className="h-56">
            <Bar
              data={eventCategoriesData}
              options={{ ...baseOptions, indexAxis: 'y' as const }}
            />
          </div>
        </div>
      </div>

      {/* Recent Activity & Active Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Recent Security Activity</h3>
            <button
              type="button"
              onClick={() => onNavigate('events')}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              View All Events
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800/80">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Event ID</th>
                  <th className="px-4 py-2.5 font-medium">Type</th>
                  <th className="px-4 py-2.5 font-medium">Source IP</th>
                  <th className="px-4 py-2.5 font-medium">User</th>
                  <th className="px-4 py-2.5 font-medium">Severity</th>
                  <th className="px-4 py-2.5 font-medium">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {data.recentActivity.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30">
                    <td className="px-4 py-2.5 font-mono text-slate-300 whitespace-nowrap">
                      <span>{ev.event_uid}</span>
                      {ev.is_demo === 1 && <span className="ml-2"><StatusTag label="Demo Data" variant="neutral" /></span>}
                    </td>
                    <td className="px-4 py-2.5 text-slate-200">{ev.event_type}</td>
                    <td className="px-4 py-2.5 font-mono text-cyan-300">{ev.source_ip}</td>
                    <td className="px-4 py-2.5 text-slate-300">{ev.username}</td>
                    <td className="px-4 py-2.5">
                      <StatusTag label={ev.severity} variant={severityVariant(ev.severity)} />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Active Alerts Queue</h3>
            <button
              type="button"
              onClick={() => onNavigate('alerts')}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300"
            >
              Triage Alerts
            </button>
          </div>
          <div className="divide-y divide-slate-800/70">
            {data.activeAlertsPreview.length === 0 ? (
              <p className="p-5 text-sm text-slate-400">No open alerts in the active queue.</p>
            ) : (
              data.activeAlertsPreview.map((alert) => (
                <div key={alert.id} className="p-4 hover:bg-slate-800/30 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-slate-400">
                      {alert.alert_uid} · {alert.rule_code}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {alert.is_demo === 1 && <StatusTag label="Demo Data" variant="neutral" />}
                      <StatusTag label={alert.severity} variant={severityVariant(alert.severity)} />
                    </div>
                  </div>
                  <p className="text-sm font-medium text-white line-clamp-1">{alert.title}</p>
                  <p className="text-xs text-slate-400 font-mono">
                    {alert.source_ip} · {alert.status}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
