import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Cpu,
  FileBarChart2,
  Globe,
  LayoutDashboard,
  LogOut,
  Menu,
  ScrollText,
  Settings,
  Shield,
  ShieldAlert,
  User as UserIcon,
  Users,
  X,
} from 'lucide-react';
import type { User } from '../types';

export type NavRoute =
  | 'dashboard'
  | 'events'
  | 'threat-intel'
  | 'detection-engine'
  | 'alerts'
  | 'incidents'
  | 'reports'
  | 'audit-logs'
  | 'users'
  | 'settings'
  | 'profile';

interface LayoutProps {
  user: User;
  activeRoute: NavRoute;
  pageTitle: string;
  onNavigate: (route: NavRoute) => void;
  onLogout: () => void;
  headerAction?: React.ReactNode;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  user,
  activeRoute,
  pageTitle,
  onNavigate,
  onLogout,
  headerAction,
  children,
}) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems: Array<{ id: NavRoute; label: string; icon: React.ReactNode; adminOnly?: boolean }> = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="h-4 w-4" /> },
    { id: 'events', label: 'Security Events', icon: <Activity className="h-4 w-4" /> },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: <Globe className="h-4 w-4" /> },
    { id: 'detection-engine', label: 'Detection Engine', icon: <Cpu className="h-4 w-4" /> },
    { id: 'alerts', label: 'Alerts', icon: <AlertTriangle className="h-4 w-4" /> },
    { id: 'incidents', label: 'Incidents', icon: <ShieldAlert className="h-4 w-4" /> },
    { id: 'reports', label: 'Reports', icon: <FileBarChart2 className="h-4 w-4" /> },
    { id: 'audit-logs', label: 'Audit Logs', icon: <ScrollText className="h-4 w-4" /> },
    { id: 'users', label: 'User Management', icon: <Users className="h-4 w-4" />, adminOnly: true },
    { id: 'settings', label: 'System Settings', icon: <Settings className="h-4 w-4" />, adminOnly: true },
    { id: 'profile', label: 'User Profile', icon: <UserIcon className="h-4 w-4" /> },
  ];

  const visibleNav = navItems.filter((item) => !item.adminOnly || user.role === 'ADMIN');

  const handleNavClick = (id: NavRoute) => {
    onNavigate(id);
    setMobileOpen(false);
  };

  const initials = user.full_name
    .split(' ')
    .map((p) => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex">
      {/* Mobile Sidebar Overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-[#0c1427] border-r border-slate-800/80 flex flex-col transition-transform duration-200 lg:sticky lg:top-0 lg:h-screen lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="h-16 px-5 flex items-center justify-between border-b border-slate-800/80 shrink-0">
          <a
            href="#dashboard"
            onClick={(e) => {
              e.preventDefault();
              handleNavClick('dashboard');
            }}
            className="flex items-center gap-2.5 text-base font-semibold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            <Shield className="h-5 w-5 text-cyan-400" />
            <span>CloudSOC</span>
          </a>
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            className="lg:hidden p-1.5 text-slate-400 hover:text-white rounded"
            aria-label="Close navigation menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="Primary Navigation">
          {visibleNav.map((item) => {
            const active = activeRoute === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNavClick(item.id)}
                aria-current={active ? 'page' : undefined}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-blue-600/15 text-cyan-300 border border-blue-500/30'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <span className={active ? 'text-cyan-400' : 'text-slate-400'}>{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div className="p-4 border-t border-slate-800/80 shrink-0">
          <div className="flex items-center gap-3 mb-3">
            <div className="h-9 w-9 rounded-md bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-xs font-semibold text-cyan-300 shrink-0">
              {initials || 'SO'}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-white truncate">{user.full_name}</p>
              <p className="text-xs text-slate-400 truncate">
                {user.username} · {user.role === 'ADMIN' ? 'Admin' : 'Analyst'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-md text-xs font-medium text-slate-300 hover:text-white bg-slate-800/70 hover:bg-slate-800 border border-slate-700/80 transition-colors whitespace-nowrap"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 px-4 sm:px-6 bg-[#0c1427]/90 border-b border-slate-800/80 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 -ml-2 text-slate-300 hover:text-white rounded-md"
              aria-label="Open navigation menu"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2 text-sm min-w-0">
              <span className="text-slate-400 hidden sm:inline whitespace-nowrap">CloudSOC</span>
              <span className="text-slate-600 hidden sm:inline" aria-hidden="true">
                /
              </span>
              <h1 className="text-base font-semibold text-white truncate">{pageTitle}</h1>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">{headerAction}</div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-x-hidden">
          <div className="max-w-7xl mx-auto">{children}</div>
        </main>
      </div>
    </div>
  );
};
