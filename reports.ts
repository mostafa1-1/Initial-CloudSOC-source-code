import PDFDocument from 'pdfkit';
import type { DatabaseSync } from 'node:sqlite';
import { escapeCsvCell } from './validation';

export type ReportType = 'events' | 'alerts' | 'incidents' | 'severity' | 'analyst_activity';

export interface ReportFilter {
  type: ReportType;
  startDate?: string;
  endDate?: string;
  severity?: string;
}

export interface GeneratedReport {
  type: ReportType;
  title: string;
  generatedAt: string;
  summary: Record<string, number | string>;
  columns: string[];
  rows: Array<Record<string, string | number>>;
}

function safeDateBoundary(raw: string | undefined, endOfDay: boolean, fallback: string): string {
  if (!raw) return fallback;
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) return fallback;
  return new Date(endOfDay ? parsed + 86_399_999 : parsed).toISOString();
}

export function buildReportData(db: DatabaseSync, filter: ReportFilter): GeneratedReport {
  const generatedAt = new Date().toISOString();
  const start = safeDateBoundary(filter.startDate, false, '1970-01-01T00:00:00.000Z');
  const end = safeDateBoundary(filter.endDate, true, '2999-12-31T23:59:59.999Z');

  if (filter.type === 'events') {
    const params: string[] = [start, end];
    let sql = `SELECT event_uid, timestamp, source_ip, username, event_type, severity, detection_status, description
               FROM security_events WHERE timestamp >= ? AND timestamp <= ?`;
    if (filter.severity && filter.severity !== 'ALL') {
      sql += ' AND severity = ?';
      params.push(filter.severity);
    }
    sql += ' ORDER BY timestamp DESC LIMIT 500';
    const rows = db.prepare(sql).all(...params) as Array<Record<string, string | number>>;
    return {
      type: 'events',
      title: 'Security Events Audit Report',
      generatedAt,
      summary: {
        totalRecords: rows.length,
        criticalCount: rows.filter((r) => r.severity === 'Critical').length,
        highCount: rows.filter((r) => r.severity === 'High').length,
        alertsTriggered: rows.filter((r) => r.detection_status === 'Alert Triggered').length,
      },
      columns: ['event_uid', 'timestamp', 'source_ip', 'username', 'event_type', 'severity', 'detection_status'],
      rows,
    };
  }

  if (filter.type === 'alerts') {
    const params: string[] = [start, end];
    let sql = `SELECT a.alert_uid, a.title, a.severity, a.status, a.source_ip, a.target_username,
                      a.event_count, COALESCE(u.username, 'Unassigned') AS assigned_analyst, a.created_at
               FROM alerts a LEFT JOIN users u ON a.assigned_to = u.id
               WHERE a.created_at >= ? AND a.created_at <= ?`;
    if (filter.severity && filter.severity !== 'ALL') {
      sql += ' AND a.severity = ?';
      params.push(filter.severity);
    }
    sql += ' ORDER BY a.created_at DESC LIMIT 500';
    const rows = db.prepare(sql).all(...params) as Array<Record<string, string | number>>;
    return {
      type: 'alerts',
      title: 'Security Alerts Summary Report',
      generatedAt,
      summary: {
        totalAlerts: rows.length,
        newAlerts: rows.filter((r) => r.status === 'New').length,
        investigatingAlerts: rows.filter((r) => r.status === 'Investigating').length,
        resolvedAlerts: rows.filter((r) => r.status === 'Resolved').length,
      },
      columns: ['alert_uid', 'title', 'severity', 'status', 'source_ip', 'target_username', 'event_count', 'assigned_analyst', 'created_at'],
      rows,
    };
  }

  if (filter.type === 'incidents') {
    const params: string[] = [start, end];
    let sql = `SELECT i.incident_uid, i.title, i.priority, i.status,
                      COALESCE(u.username, 'Unassigned') AS assigned_analyst,
                      c.username AS created_by, i.created_at, COALESCE(i.closed_at, 'Open') AS closed_at
               FROM incidents i
               LEFT JOIN users u ON i.assigned_to = u.id
               JOIN users c ON i.created_by = c.id
               WHERE i.created_at >= ? AND i.created_at <= ?`;
    if (filter.severity && filter.severity !== 'ALL') {
      sql += ' AND i.priority = ?';
      params.push(filter.severity);
    }
    sql += ' ORDER BY i.created_at DESC LIMIT 500';
    const rows = db.prepare(sql).all(...params) as Array<Record<string, string | number>>;
    return {
      type: 'incidents',
      title: 'Incident Response & Lifecycle Report',
      generatedAt,
      summary: {
        totalIncidents: rows.length,
        openIncidents: rows.filter((r) => r.status !== 'RESOLVED').length,
        resolvedIncidents: rows.filter((r) => r.status === 'RESOLVED').length,
        criticalPriority: rows.filter((r) => r.priority === 'Critical').length,
      },
      columns: ['incident_uid', 'title', 'priority', 'status', 'assigned_analyst', 'created_by', 'created_at', 'closed_at'],
      rows,
    };
  }

  if (filter.type === 'severity') {
    const severityOnly = filter.severity && filter.severity !== 'ALL' ? ' AND severity = ?' : '';
    const rows = db
      .prepare(
        `SELECT severity,
                COUNT(*) AS event_count,
                SUM(CASE WHEN detection_status = 'Alert Triggered' THEN 1 ELSE 0 END) AS alerts_triggered
         FROM security_events
         WHERE timestamp >= ? AND timestamp <= ?${severityOnly}
         GROUP BY severity
         ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
      )
      .all(...(severityOnly ? [start, end, filter.severity!] : [start, end])) as Array<Record<string, string | number>>;
    const totalEvents = rows.reduce((acc, r) => acc + Number(r.event_count), 0);
    return {
      type: 'severity',
      title: 'Severity Distribution & Detection Impact Report',
      generatedAt,
      summary: {
        totalEventsAnalyzed: totalEvents,
        severityTiers: rows.length,
      },
      columns: ['severity', 'event_count', 'alerts_triggered'],
      rows,
    };
  }

  // analyst_activity
  const rows = db
    .prepare(
      `SELECT u.username, r.name AS role,
              (SELECT COUNT(*) FROM alerts a WHERE a.assigned_to = u.id AND a.created_at BETWEEN ? AND ?) AS assigned_alerts,
              (SELECT COUNT(*) FROM incidents i WHERE i.assigned_to = u.id AND i.created_at BETWEEN ? AND ?) AS assigned_incidents,
              (SELECT COUNT(*) FROM incident_notes n WHERE n.author_id = u.id AND n.created_at BETWEEN ? AND ?) AS notes_authored,
              (SELECT COUNT(*) FROM response_actions ra WHERE ra.performed_by = u.id AND ra.created_at BETWEEN ? AND ?) AS response_actions,
              (SELECT COUNT(*) FROM audit_logs al WHERE al.user_id = u.id AND al.created_at >= ? AND al.created_at <= ?) AS audit_actions
       FROM users u
       JOIN roles r ON u.role_id = r.id
       WHERE u.is_active = 1
       ORDER BY audit_actions DESC`
    )
    .all(start, end, start, end, start, end, start, end, start, end) as Array<Record<string, string | number>>;

  return {
    type: 'analyst_activity',
    title: 'SOC Analyst Activity & Workload Report',
    generatedAt,
    summary: {
      activeUsers: rows.length,
      totalAuditActions: rows.reduce((acc, r) => acc + Number(r.audit_actions), 0),
      totalResponseActions: rows.reduce((acc, r) => acc + Number(r.response_actions), 0),
    },
    columns: [
      'username',
      'role',
      'assigned_alerts',
      'assigned_incidents',
      'notes_authored',
      'response_actions',
      'audit_actions',
    ],
    rows,
  };
}

export function renderReportCsv(report: GeneratedReport): string {
  const header = report.columns.map(escapeCsvCell).join(',');
  const lines = report.rows.map((row) =>
    report.columns.map((col) => escapeCsvCell(row[col])).join(',')
  );
  return [header, ...lines].join('\r\n');
}

export function renderReportPdf(report: GeneratedReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 40, size: 'A4' });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.rect(0, 0, doc.page.width, 72).fill('#0f172a');
    doc.fillColor('#38bdf8').fontSize(10).text('CLOUDSOC SECURITY OPERATIONS CENTER', 40, 20);
    doc.fillColor('#ffffff').fontSize(17).text(report.title, 40, 36);

    doc.moveDown(2.2);
    doc.fillColor('#334155').fontSize(9.5).text(`Generated At (UTC): ${report.generatedAt}`, 40, 88);
    doc.text(`Report Category: ${report.type.toUpperCase()}`, 40, 102);

    // Summary KPIs box
    doc.rect(40, 122, doc.page.width - 80, 48).fill('#f1f5f9');
    doc.fillColor('#0f172a').fontSize(10).text('Executive Summary Metrics', 50, 130);
    const summaryText = Object.entries(report.summary)
      .map(([k, v]) => `${k}: ${v}`)
      .join('   |   ');
    doc.fillColor('#475569').fontSize(9).text(summaryText, 50, 148, { width: doc.page.width - 100 });

    let y = 188;
    const usableWidth = doc.page.width - 80;
    const colWidth = Math.max(55, Math.floor(usableWidth / report.columns.length));

    const drawHeader = () => {
      doc.rect(40, y, usableWidth, 20).fill('#1e293b');
      doc.fillColor('#f8fafc').fontSize(7.5);
      report.columns.forEach((col, idx) => {
        doc.text(col.toUpperCase(), 44 + idx * colWidth, y + 6, {
          width: colWidth - 6,
          ellipsis: true,
          lineBreak: false,
        });
      });
      y += 22;
    };

    drawHeader();

    if (report.rows.length === 0) {
      doc.fillColor('#64748b').fontSize(10).text('No matching records found for the selected filter criteria.', 44, y + 8);
    } else {
      report.rows.slice(0, 120).forEach((row, rIdx) => {
        if (y > doc.page.height - 60) {
          doc.addPage();
          y = 44;
          drawHeader();
        }
        if (rIdx % 2 === 1) {
          doc.rect(40, y - 2, usableWidth, 18).fill('#f8fafc');
        }
        doc.fillColor('#0f172a').fontSize(7.5);
        report.columns.forEach((col, idx) => {
          doc.text(String(row[col] ?? ''), 44 + idx * colWidth, y + 2, {
            width: colWidth - 6,
            ellipsis: true,
            lineBreak: false,
          });
        });
        y += 18;
      });
    }

    doc.end();
  });
}
