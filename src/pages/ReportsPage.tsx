import React, { useCallback, useEffect, useState } from 'react';
import { Download } from 'lucide-react';
import { apiFetchRaw, apiRequest } from '../api';

interface ReportData {
  type: string;
  title: string;
  generatedAt: string;
  summary: Record<string, number | string>;
  columns: string[];
  rows: Array<Record<string, string | number>>;
}

export const ReportsPage: React.FC = () => {
  const [reportType, setReportType] = useState<'events' | 'alerts' | 'incidents' | 'severity' | 'analyst_activity'>('events');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [report, setReport] = useState<ReportData | null>(null);
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState<'csv' | 'pdf' | null>(null);
  const [error, setError] = useState('');

  const buildQs = useCallback(() => {
    const qs = new URLSearchParams({ type: reportType });
    if (startDate) qs.set('startDate', startDate);
    if (endDate) qs.set('endDate', endDate);
    if (severity !== 'ALL') qs.set('severity', severity);
    return qs.toString();
  }, [reportType, startDate, endDate, severity]);

  const loadReport = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiRequest<{ report: ReportData }>(`/api/reports?${buildQs()}`);
      setReport(data.report);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to generate report.');
    } finally {
      setLoading(false);
    }
  }, [buildQs]);

  useEffect(() => {
    loadReport();
  }, [loadReport]);

  const handleDownload = async (format: 'csv' | 'pdf') => {
    setDownloading(format);
    setError('');
    try {
      const res = await apiFetchRaw(`/api/reports/export/${format}?${buildQs()}`);
      if (!res.ok) {
        throw new Error(`Export failed (${res.status})`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cloudsoc_${reportType}_report.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to download ${format.toUpperCase()} report.`);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Reports &amp; Exports</h2>
          <p className="text-sm text-slate-400">
            Generate database-verified audit reports and export as CSV or formatted PDF documents.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={downloading !== null}
            onClick={() => handleDownload('csv')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md border border-slate-700 bg-[#0f172a] hover:bg-slate-800 disabled:opacity-60 text-xs font-medium text-white whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" />
            <span>{downloading === 'csv' ? 'Exporting...' : 'Export CSV'}</span>
          </button>
          <button
            type="button"
            disabled={downloading !== null}
            onClick={() => handleDownload('pdf')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-600 hover:bg-blue-500 disabled:opacity-60 text-xs font-semibold text-white whitespace-nowrap"
          >
            <Download className="h-3.5 w-3.5" />
            <span>{downloading === 'pdf' ? 'Exporting...' : 'Export PDF'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="p-3.5 rounded-md bg-rose-950/50 border border-rose-500/40 text-sm text-rose-200">
          {error}
        </div>
      )}

      {/* Report Controls */}
      <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Report Category</label>
          <select
            aria-label="Report category"
            value={reportType}
            onChange={(e) => setReportType(e.target.value as typeof reportType)}
            className="w-full px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          >
            <option value="events">Security Events Report</option>
            <option value="alerts">Alert Summary Report</option>
            <option value="incidents">Incident Lifecycle Report</option>
            <option value="severity">Severity Distribution Report</option>
            <option value="analyst_activity">Analyst Activity Report</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">Severity Filter</label>
          <select
            aria-label="Report severity filter"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="w-full px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">Start Date</label>
          <input
            type="date"
            aria-label="Report start date"
            value={startDate}
            onChange={(e) => setStartDate(e.target.value)}
            className="w-full px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          />
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">End Date</label>
          <input
            type="date"
            aria-label="Report end date"
            value={endDate}
            onChange={(e) => setEndDate(e.target.value)}
            className="w-full px-3 py-2 rounded-md bg-[#080d1a] border border-slate-700 text-xs text-white"
          />
        </div>
      </div>

      {/* Report Summary Metrics */}
      {report && (
        <div className="bg-[#0f172a] border border-slate-800/90 rounded-lg p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-white">{report.title}</h3>
            <span className="font-mono text-xs text-slate-400">Generated: {report.generatedAt}</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-800 border-y border-slate-800 py-3">
            {Object.entries(report.summary).map(([key, val]) => (
              <div key={key} className="px-4 py-1 first:pl-0">
                <p className="text-xs text-slate-400 capitalize">{key.replace(/([A-Z])/g, ' $1')}</p>
                <p className="text-lg font-bold font-mono text-cyan-300 tabular-nums mt-0.5">{val}</p>
              </div>
            ))}
          </div>

          <div className="overflow-x-auto border border-slate-800 rounded">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b1120] text-slate-400 border-b border-slate-800">
                <tr>
                  {report.columns.map((col) => (
                    <th key={col} className="px-4 py-2.5 font-medium uppercase">
                      {col.replace(/_/g, ' ')}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {loading ? (
                  <tr>
                    <td colSpan={report.columns.length} className="px-4 py-8 text-center text-slate-400">
                      Computing report...
                    </td>
                  </tr>
                ) : report.rows.length === 0 ? (
                  <tr>
                    <td colSpan={report.columns.length} className="px-4 py-8 text-center text-slate-400">
                      No records matched this report window.
                    </td>
                  </tr>
                ) : (
                  report.rows.map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      {report.columns.map((col) => (
                        <td key={col} className="px-4 py-2.5 font-mono text-slate-200 whitespace-nowrap">
                          {String(row[col] ?? '—')}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
