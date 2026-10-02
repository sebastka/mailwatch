import type {
  Alert,
  CheckKind,
  CheckResult,
  DeliveryOverview,
  DeliveryProbe,
  DmarcOverview,
  DmarcReportDetail,
  DmarcReportSummary,
  DomainOverview,
  FailureReport,
  FailureReportDetail,
  Filters,
  Me,
  RecordChange,
  ReportFilterOptions,
  Settings,
  Snooze,
  Status,
  TlsOverview,
  TlsReportDetail,
  TlsReportSummary,
} from '../shared/types.ts';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (res.status === 401) {
    // Session expired or missing: go through the OIDC login and come back here.
    location.href = `/auth/login?returnTo=${encodeURIComponent(location.pathname + location.search)}`;
    throw new Error('authentication required');
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) msg = body.error;
    } catch {
      // not JSON
    }
    throw new Error(msg);
  }
  return (await res.json()) as T;
}

const json = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: { 'content-type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export function query(f: object): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}

export const api = {
  me: () => request<Me>('/api/me'),
  status: () => request<Status>('/api/status'),
  overview: () => request<DomainOverview[]>('/api/overview'),
  checks: <T = unknown>(check: CheckKind, domain?: string) =>
    request<CheckResult<T>[]>(`/api/checks/${check}${query({ domain })}`),
  runChecks: (domain?: string) => request<{ ok: true }>('/api/checks/run', json('POST', { domain })),
  changes: (q: { domain?: string; check?: CheckKind; limit?: number } = {}) =>
    request<RecordChange[]>(`/api/changes${query(q)}`),
  syncReports: () => request<{ ok: true }>('/api/reports/sync', json('POST')),
  tlsFilters: () => request<ReportFilterOptions>('/api/tls/filters'),
  tlsOverview: (f: Filters) => request<TlsOverview>(`/api/tls/overview${query(f)}`),
  tlsReports: (f: Filters) => request<TlsReportSummary[]>(`/api/tls/reports${query(f)}`),
  tlsReport: (id: number) => request<TlsReportDetail>(`/api/tls/reports/${id}`),
  dmarcFilters: () => request<ReportFilterOptions>('/api/dmarc/filters'),
  dmarcOverview: (f: Filters) => request<DmarcOverview>(`/api/dmarc/overview${query(f)}`),
  dmarcReports: (f: Filters) => request<DmarcReportSummary[]>(`/api/dmarc/reports${query(f)}`),
  dmarcReport: (id: number) => request<DmarcReportDetail>(`/api/dmarc/reports/${id}`),
  failures: (f: Filters) => request<FailureReport[]>(`/api/dmarc/failures${query(f)}`),
  failure: (id: number) => request<FailureReportDetail>(`/api/dmarc/failures/${id}`),
  delivery: (days: number) => request<DeliveryOverview>(`/api/delivery${query({ days })}`),
  probe: (id: number) => request<DeliveryProbe>(`/api/delivery/probes/${id}`),
  runDelivery: () => request<{ ok: true }>('/api/delivery/run', json('POST')),
  alerts: (q: { active?: boolean; days?: number; domain?: string }) =>
    request<Alert[]>(
      `/api/alerts${query({ active: q.active ? '1' : undefined, days: q.days ?? 30, domain: q.domain })}`,
    ),
  ack: (id: number) => request<Alert>(`/api/alerts/${id}/ack`, json('POST')),
  snooze: (id: number, minutes: number) => request<Alert>(`/api/alerts/${id}/snooze`, json('POST', { minutes })),
  snoozes: () => request<Snooze[]>('/api/snoozes'),
  unsnooze: (key: string) => request<{ ok: true }>(`/api/snoozes/${encodeURIComponent(key)}`, json('DELETE')),
  settings: () => request<Settings>('/api/settings'),
  saveSettings: (s: Settings) => request<Settings>('/api/settings', json('PUT', s)),
  testTelegram: () => request<{ ok: true }>('/api/telegram/test', json('POST')),
};
