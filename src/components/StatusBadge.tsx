import React from 'react';

interface TagProps {
  label: string;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'neutral' | 'info' | 'success';
}

const VARIANT_CLASSES: Record<NonNullable<TagProps['variant']>, string> = {
  critical: 'border-rose-500/40 bg-rose-950/50 text-rose-300',
  high: 'border-amber-500/40 bg-amber-950/50 text-amber-300',
  medium: 'border-sky-500/40 bg-sky-950/50 text-sky-300',
  low: 'border-emerald-500/40 bg-emerald-950/50 text-emerald-300',
  info: 'border-cyan-500/40 bg-cyan-950/50 text-cyan-300',
  success: 'border-emerald-500/40 bg-emerald-950/50 text-emerald-300',
  neutral: 'border-slate-700 bg-slate-800/60 text-slate-300',
};

export function severityVariant(severity: string): NonNullable<TagProps['variant']> {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'malicious':
      return 'critical';
    case 'high':
    case 'suspicious':
    case 'new':
      return 'high';
    case 'medium':
    case 'investigating':
    case 'acknowledged':
      return 'medium';
    case 'low':
    case 'resolved':
    case 'clean':
    case 'contained':
      return 'low';
    default:
      return 'neutral';
  }
}

export const StatusTag: React.FC<TagProps> = ({ label, variant = 'neutral' }) => {
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium whitespace-nowrap shrink-0 ${VARIANT_CLASSES[variant]}`}
    >
      {label}
    </span>
  );
};
