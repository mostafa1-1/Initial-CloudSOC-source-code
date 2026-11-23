import { useEffect, useState } from 'react';
import { apiRequest, clearAuthSession, setCsrfToken } from './api';
import { Layout, type NavRoute } from './components/Layout';
import { AlertsPage } from './pages/AlertsPage';
import { AuditLogsPage } from './pages/AuditLogsPage';
import { DashboardPage } from './pages/DashboardPage';
import { DetectionEnginePage } from './pages/DetectionEnginePage';
import { ErrorPage } from './pages/ErrorPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { LoginPage } from './pages/LoginPage';
import { ProfilePage } from './pages/ProfilePage';
import { RegisterPage } from './pages/RegisterPage';
import { ReportsPage } from './pages/ReportsPage';
import { SecurityEventsPage } from './pages/SecurityEventsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ThreatIntelPage } from './pages/ThreatIntelPage';
import { UsersPage } from './pages/UsersPage';
import type { User } from './types';

const ROUTE_TITLES: Record<NavRoute, string> = {
  dashboard: 'Dashboard',
  events: 'Security Events',
  'threat-intel': 'Threat Intelligence',
  'detection-engine': 'Threat Detection Engine',
  alerts: 'Alerts',
  incidents: 'Incident Management',
  reports: 'Reports',
  'audit-logs': 'Audit Logs',
  users: 'User Management',
  settings: 'System Settings',
  profile: 'User Profile',
};

function parseRouteFromPath(): NavRoute | 'not-found' {
  const path = window.location.pathname.replace(/\/+$/, '') || '/';
  if (path === '/' || path === '/dashboard') return 'dashboard';
  if (path === '/events') return 'events';
  if (path === '/threat-intel') return 'threat-intel';
  if (path === '/detection-engine') return 'detection-engine';
  if (path === '/alerts') return 'alerts';
  if (path === '/incidents') return 'incidents';
  if (path === '/reports') return 'reports';
  if (path === '/audit-logs') return 'audit-logs';
  if (path === '/users') return 'users';
  if (path === '/settings') return 'settings';
  if (path === '/profile') return 'profile';
  if (path === '/login' || path === '/register') return 'dashboard';
  return 'not-found';
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authView, setAuthView] = useState<'login' | 'register'>(
    window.location.pathname === '/register' ? 'register' : 'login'
  );
  const [route, setRoute] = useState<NavRoute | 'not-found'>(parseRouteFromPath);

  useEffect(() => {
    apiRequest<{ authenticated: boolean; user: User | null; csrfToken?: string }>('/api/auth/session')
      .then((data) => {
        if (data.authenticated && data.user) {
          setUser(data.user);
          if (data.csrfToken) setCsrfToken(data.csrfToken);
        } else {
          clearAuthSession();
          setUser(null);
        }
      })
      .catch(() => {
        clearAuthSession();
        setUser(null);
      })
      .finally(() => setAuthChecked(true));

    const handlePop = () => {
      setRoute(parseRouteFromPath());
    };
    window.addEventListener('popstate', handlePop);
    return () => window.removeEventListener('popstate', handlePop);
  }, []);

  const navigate = (next: NavRoute) => {
    setRoute(next);
    const url = next === 'dashboard' ? '/' : `/${next}`;
    window.history.pushState({}, '', url);
  };

  const handleLogout = async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {
      // ignore network error on logout
    } finally {
      clearAuthSession();
      setUser(null);
      setAuthView('login');
      window.history.pushState({}, '', '/login');
    }
  };

  if (!authChecked) {
    return (
      <div className="min-h-screen bg-[#080d1a] flex items-center justify-center text-sm text-slate-400">
        Initializing CloudSOC session...
      </div>
    );
  }

  if (!user) {
    if (authView === 'register') {
      return (
        <RegisterPage
          onSuccess={(u) => {
            setUser(u);
            navigate('dashboard');
          }}
          onSwitchToLogin={() => {
            setAuthView('login');
            window.history.pushState({}, '', '/login');
          }}
        />
      );
    }
    return (
      <LoginPage
        onSuccess={(u) => {
          setUser(u);
          navigate('dashboard');
        }}
        onSwitchToRegister={() => {
          setAuthView('register');
          window.history.pushState({}, '', '/register');
        }}
      />
    );
  }

  const activeNav: NavRoute = route === 'not-found' ? 'dashboard' : route;
  const pageTitle = route === 'not-found' ? 'Page Not Found' : ROUTE_TITLES[route];

  const renderPage = () => {
    if (route === 'not-found') {
      return (
        <ErrorPage
          code={404}
          title="Security Console Route Not Found"
          message="The requested CloudSOC view does not exist or has been relocated."
          onReturn={() => navigate('dashboard')}
        />
      );
    }

    if ((route === 'users' || route === 'settings') && user.role !== 'ADMIN') {
      return (
        <ErrorPage
          code={403}
          title="Administrator Access Required"
          message="Your account holds Security Analyst permissions. Only Administrators can access user management or rule configuration."
          onReturn={() => navigate('dashboard')}
        />
      );
    }

    switch (route) {
      case 'dashboard':
        return <DashboardPage onNavigate={navigate} />;
      case 'events':
        return <SecurityEventsPage />;
      case 'threat-intel':
        return <ThreatIntelPage />;
      case 'detection-engine':
        return <DetectionEnginePage userRole={user.role} onNavigate={navigate} />;
      case 'alerts':
        return <AlertsPage onEscalateSuccess={() => navigate('incidents')} />;
      case 'incidents':
        return <IncidentsPage />;
      case 'reports':
        return <ReportsPage />;
      case 'audit-logs':
        return <AuditLogsPage />;
      case 'users':
        return <UsersPage />;
      case 'settings':
        return <SettingsPage />;
      case 'profile':
        return <ProfilePage user={user} onUserUpdated={setUser} />;
    }
  };

  return (
    <Layout
      user={user}
      activeRoute={activeNav}
      pageTitle={pageTitle}
      onNavigate={navigate}
      onLogout={handleLogout}
      headerAction={
        <button
          type="button"
          onClick={() => navigate('events')}
          className="px-3.5 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white whitespace-nowrap shrink-0 transition-colors"
        >
          Inspect Telemetry
        </button>
      }
    >
      {renderPage()}
    </Layout>
  );
}
