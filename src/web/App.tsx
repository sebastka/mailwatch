import { useCallback, useEffect, useRef, useState } from 'react';
import type { Alert, CheckKind, DomainOverview, Level, Status } from '../shared/types.ts';
import { api } from './api.ts';
import { StatusIcon } from './components/ui.tsx';
import { ago, setTimezone } from './format.ts';
import { useAsync } from './hooks.ts';
import logo from './logo.svg';
import { AlertsView } from './views/Alerts.tsx';
import { CheckView } from './views/CheckView.tsx';
import { DeliveryView } from './views/Delivery.tsx';
import { DmarcReportsView } from './views/DmarcReports.tsx';
import { OverviewView } from './views/Overview.tsx';
import { StatusView } from './views/Status.tsx';
import { TlsRptView } from './views/TlsRpt.tsx';

interface Tab {
  path: string;
  label: string;
  check?: CheckKind;
}

const TABS: Tab[] = [
  { path: '/', label: 'Overview' },
  { path: '/mx', label: 'MX & SMTP', check: 'mx' },
  { path: '/spf', label: 'SPF', check: 'spf' },
  { path: '/dkim', label: 'DKIM', check: 'dkim' },
  { path: '/dmarc', label: 'DMARC', check: 'dmarc' },
  { path: '/dmarc-reports', label: 'DMARC reports' },
  { path: '/mta-sts', label: 'MTA-STS', check: 'mta-sts' },
  { path: '/tls-rpt', label: 'TLS-RPT', check: 'tls-rpt' },
  { path: '/dane', label: 'DANE', check: 'dane' },
  { path: '/bimi', label: 'BIMI', check: 'bimi' },
  { path: '/dnsbl', label: 'Blocklists', check: 'dnsbl' },
  { path: '/delivery', label: 'Delivery' },
  { path: '/alerts', label: 'Alerts' },
  { path: '/status', label: 'Status' },
];

const currentPath = () => {
  const p = location.pathname.replace(/\/+$/, '') || '/';
  return TABS.some((t) => t.path === p) ? p : '/';
};
const currentDomain = () => new URLSearchParams(location.search).get('domain') ?? '';

/** Polls the job status: quickly while something runs, slowly otherwise; refreshes data when a job ends. */
function useStatus(onFinished: () => void) {
  const [status, setStatus] = useState<Status | null>(null);
  const wasRunning = useRef(false);
  const running = Boolean(status && (status.checks.running || status.reports.running || status.delivery.running));
  useEffect(() => {
    let active = true;
    const poll = () =>
      api.status().then(
        (s) => {
          if (!active) return;
          setTimezone(s.timezone);
          setStatus(s);
          const now = s.checks.running || s.reports.running || s.delivery.running;
          if (wasRunning.current && !now) onFinished();
          wasRunning.current = now;
        },
        () => {}, // keep the last known status
      );
    void poll();
    const t = setInterval(poll, running ? 2500 : 15_000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [onFinished, running]);
  const started = () => {
    wasRunning.current = true;
    setStatus((s) => (s ? { ...s, checks: { ...s.checks, running: true } } : s));
  };
  return { status, started };
}

function UserMenu() {
  const { data } = useAsync(() => api.me(), []);
  if (!data) return null;
  const u = data.user;
  return (
    <form method="post" action="/auth/logout" className="user-menu">
      <span className="user-name" title={`${u.email ?? u.sub}${u.canEdit ? ' (editor)' : ' (read-only)'}`}>
        {u.name ?? u.email ?? u.sub}
      </span>
      <button type="submit" className="btn">
        Log out
      </button>
    </form>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<string>(() => document.documentElement.getAttribute('data-theme') ?? 'auto');
  const set = (t: string) => {
    setTheme(t);
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    try {
      localStorage.setItem('theme', t);
    } catch {
      // storage unavailable
    }
  };
  return (
    <div className="segmented" role="group" aria-label="Theme">
      {['auto', 'light', 'dark'].map((t) => (
        <button key={t} type="button" aria-pressed={theme === t} onClick={() => set(t)}>
          {t[0]!.toUpperCase() + t.slice(1)}
        </button>
      ))}
    </div>
  );
}

/** Domains with a warning or error in a check, and the worst of them. */
function tabProblems(overview: DomainOverview[] | null, check: CheckKind, domain: string): { n: number; level: Level } {
  let n = 0;
  let level: Level = 'ok';
  for (const d of overview ?? []) {
    if (domain && d.name !== domain) continue;
    const c = d.checks.find((x) => x.check === check);
    if (c && (c.level === 'warning' || c.level === 'error')) {
      n++;
      if (c.level === 'error') level = 'error';
      else if (level !== 'error') level = 'warning';
    }
  }
  return { n, level };
}

export function App() {
  const [path, setPath] = useState(currentPath);
  const [domain, setDomainState] = useState(currentDomain);
  const [version, setVersion] = useState(0);
  const bump = useCallback(() => setVersion((v) => v + 1), []);
  const { status, started } = useStatus(bump);
  const me = useAsync(() => api.me(), []);
  const overview = useAsync(() => api.overview(), [version]);
  const active = useAsync(() => api.alerts({ active: true }), [version]);
  const canEdit = me.data?.user.canEdit ?? false;

  useEffect(() => {
    const t = setInterval(bump, 60_000);
    return () => clearInterval(t);
  }, [bump]);
  useEffect(() => {
    const onPop = () => {
      setPath(currentPath());
      setDomainState(currentDomain());
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const url = (p: string, d: string) => `${p}${d ? `?${new URLSearchParams({ domain: d })}` : ''}`;
  const go = (p: string, d = domain) => {
    history.pushState(null, '', url(p, d));
    setPath(p);
    setDomainState(d);
    window.scrollTo({ top: 0 });
  };
  const setDomain = (d: string) => {
    history.replaceState(null, '', url(path, d));
    setDomainState(d);
  };

  const runChecks = async () => {
    await api.runChecks(domain || undefined);
    started();
  };

  const domains = status?.domains ?? [];
  const alerts: Alert[] = active.data ?? [];
  const busy = status?.checks.running ?? false;

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <a
            href="/"
            className="brand-logo"
            aria-label="MailWatch: back to the overview"
            onClick={(e) => {
              if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
              e.preventDefault();
              go('/', '');
            }}
          >
            <img src={logo} alt="" width="32" height="32" />
          </a>
          <div>
            <h1>MailWatch</h1>
            <div className="sub">
              E-mail setup of {domains.length} domain{domains.length === 1 ? '' : 's'}
              {status?.demo && <> · demo data</>}
            </div>
          </div>
        </div>
        <div className="header-actions">
          {status?.demo ? (
            <span className="sync-state">Demo data: nothing is checked, synced or sent</span>
          ) : (
            <>
              <span className="sync-state" aria-live="polite">
                {busy ? (
                  <>
                    <span className="spin" /> Checking…
                  </>
                ) : status?.checks.lastError ? (
                  <>
                    <StatusIcon level="error" size={12} /> Last check failed
                  </>
                ) : (
                  <>Checked {ago(status?.checks.lastSuccessAt ?? null)}</>
                )}
              </span>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void runChecks()}
                disabled={!status || busy || !domains.length}
              >
                {domain ? `Check ${domain} now` : 'Check now'}
              </button>
            </>
          )}
          <ThemeToggle />
          <UserMenu />
        </div>
      </header>

      <nav className="tabs" aria-label="Views">
        {TABS.map((t) => {
          let badge: { n: number; cls: string; title: string } | null = null;
          if (t.check) {
            const p = tabProblems(overview.data, t.check, domain);
            if (p.n)
              badge = {
                n: p.n,
                cls: p.level === 'error' ? '' : 'warn',
                title: `${p.n} domain${p.n === 1 ? '' : 's'} with ${p.level === 'error' ? 'errors' : 'warnings'}`,
              };
          } else if (t.path === '/alerts' && alerts.length) {
            badge = {
              n: alerts.length,
              cls: '',
              title: `${alerts.length} active alert${alerts.length === 1 ? '' : 's'}`,
            };
          }
          return (
            <a
              key={t.path}
              href={url(t.path, domain)}
              aria-current={path === t.path ? 'page' : undefined}
              onClick={(e) => {
                if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
                e.preventDefault();
                go(t.path);
              }}
            >
              {t.label}
              {badge && (
                <span className={`count ${badge.cls}`} title={badge.title}>
                  {badge.n}
                </span>
              )}
            </a>
          );
        })}
      </nav>

      {path !== '/status' && path !== '/alerts' && (
        <div className="filters" role="search">
          <label className="field">
            Domain
            <select value={domain} onChange={(e) => setDomain(e.target.value)}>
              <option value="">All domains</option>
              {domains.map((d) => (
                <option key={d.name} value={d.name}>
                  {d.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      )}

      {path === '/' && (
        <OverviewView overview={overview.data} alerts={alerts} domain={domain} version={version} onOpen={go} />
      )}
      {TABS.filter((t) => t.check && t.path === path).map((t) =>
        t.check === 'tls-rpt' ? (
          <TlsRptView key={t.path} domain={domain} version={version} onDomain={setDomain} />
        ) : (
          <CheckView key={t.path} check={t.check!} domain={domain} version={version} />
        ),
      )}
      {path === '/dmarc-reports' && <DmarcReportsView domain={domain} version={version} onDomain={setDomain} />}
      {path === '/delivery' && (
        <DeliveryView domain={domain} version={version} status={status} canEdit={canEdit} onChanged={bump} />
      )}
      {path === '/alerts' && <AlertsView version={version} onChanged={bump} onOpen={go} />}
      {path === '/status' && <StatusView status={status} canEdit={canEdit} onChanged={bump} />}
    </div>
  );
}
