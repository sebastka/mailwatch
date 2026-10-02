import { useEffect, useState, type ReactNode } from 'react';
import type { Finding, InsightSubject, Level, RfcRef } from '../../shared/types.ts';
import { refLabel, refUrl, SPECS } from '../../shared/rfcs.ts';
import { LEVEL_ORDER } from '../levels.ts';

const STATUS: Record<Level, { color: string; label: string }> = {
  ok: { color: 'var(--status-good)', label: 'OK' },
  info: { color: 'var(--status-info)', label: 'Info' },
  warning: { color: 'var(--status-warning)', label: 'Warning' },
  error: { color: 'var(--status-critical)', label: 'Error' },
};

export function StatusIcon({ level, size = 16 }: { level: Level; size?: number }) {
  const c = STATUS[level].color;
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
      {level === 'ok' && (
        <>
          <circle cx="8" cy="8" r="7" fill={c} />
          <path
            d="M4.8 8.2l2.1 2.1 4.3-4.5"
            fill="none"
            stroke="#fff"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </>
      )}
      {level === 'info' && (
        <>
          <circle cx="8" cy="8" r="7" fill={c} />
          <path d="M8 7.2v4.2" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
          <circle cx="8" cy="4.7" r="1.1" fill="#fff" />
        </>
      )}
      {level === 'warning' && (
        <>
          <path d="M8 1.3l7 12.6H1z" fill={c} strokeLinejoin="round" />
          <path d="M8 6v3.6" stroke="#0b0b0b" strokeWidth="1.7" strokeLinecap="round" />
          <circle cx="8" cy="11.8" r="1" fill="#0b0b0b" />
        </>
      )}
      {level === 'error' && (
        <>
          <circle cx="8" cy="8" r="7" fill={c} />
          <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" />
        </>
      )}
    </svg>
  );
}

export function StatusLabel({ level }: { level: Level }) {
  return <span className="badge">{STATUS[level].label}</span>;
}

/** Icon and word together: status is never conveyed by colour alone. */
export function StatusPill({ level, text }: { level: Level; text?: string }) {
  return (
    <span className="status-pill">
      <StatusIcon level={level} size={14} />
      {text ?? STATUS[level].label}
    </span>
  );
}

export function Card({
  title,
  desc,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  desc?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className ?? ''}`}>
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          {desc && <p className="desc">{desc}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

/** A chart card with a chart/table toggle, so no value is only reachable by hovering. */
export function ChartCard({
  title,
  desc,
  chart,
  table,
}: {
  title: string;
  desc?: ReactNode;
  chart: ReactNode;
  table: ReactNode;
}) {
  const [view, setView] = useState<'chart' | 'table'>('chart');
  return (
    <Card
      title={title}
      desc={desc}
      actions={
        <div className="segmented" role="group" aria-label="View">
          <button type="button" aria-pressed={view === 'chart'} onClick={() => setView('chart')}>
            Chart
          </button>
          <button type="button" aria-pressed={view === 'table'} onClick={() => setView('table')}>
            Table
          </button>
        </div>
      }
    >
      {view === 'chart' ? chart : <div className="table-wrap">{table}</div>}
    </Card>
  );
}

/** A side panel over the page; Escape or a click on the backdrop closes it. */
export function Drawer({ title, onClose, children }: { title: ReactNode; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : undefined}
      >
        <div className="drawer-head">
          <h2>{title}</h2>
          <button type="button" className="btn" onClick={onClose} autoFocus>
            Close
          </button>
        </div>
        {children}
      </aside>
    </>
  );
}

export function FailCount({ n }: { n: number }) {
  if (n === 0) return <span className="muted">0</span>;
  return (
    <span className="fail-count">
      <StatusIcon level="error" size={12} />
      {n.toLocaleString('en')}
    </span>
  );
}

export function ErrorBanner({ children }: { children: ReactNode }) {
  return (
    <div className="error-banner" role="alert">
      <StatusIcon level="error" />
      <div>{children}</div>
    </div>
  );
}

/** Links to the cited sections, e.g. "RFC 7208 §4.6.4". */
export function Refs({ refs }: { refs?: RfcRef[] }) {
  if (!refs?.length) return null;
  return (
    <span className="refs">
      {refs.map((r, i) => (
        <a key={i} className="ref" href={refUrl(r)} target="_blank" rel="noreferrer" title={SPECS[r.doc]?.title}>
          {refLabel(r)}
        </a>
      ))}
    </span>
  );
}

/** Findings, worst first; "ok" findings can be hidden. */
export function FindingList({ findings, showOk = true }: { findings: Finding[]; showOk?: boolean }) {
  const list = [...findings]
    .filter((f) => showOk || f.level !== 'ok')
    .sort((a, b) => LEVEL_ORDER[b.level] - LEVEL_ORDER[a.level]);
  if (!list.length) return <div className="muted">Nothing to report.</div>;
  return (
    <ul className="findings">
      {list.map((f, i) => (
        <li key={`${f.code}-${f.subject ?? ''}-${i}`} className={`finding level-${f.level}`}>
          <StatusIcon level={f.level} />
          <div>
            <div className="t">
              {f.title}
              {f.level !== 'ok' && <StatusLabel level={f.level} />}
              <Refs refs={f.refs} />
            </div>
            {f.detail && <div className="d">{f.detail}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}

/**
 * The specifications relevant to a tab. Those that current warnings or errors cite are marked
 * with the worst level and the number of findings citing them.
 */
export function SpecPanel({ docs, findings }: { docs: string[]; findings: Finding[] }) {
  const issues = new Map<string, { level: Level; count: number }>();
  for (const f of findings) {
    if (f.level !== 'warning' && f.level !== 'error') continue;
    for (const d of new Set((f.refs ?? []).map((r) => r.doc))) {
      const cur = issues.get(d) ?? { level: f.level, count: 0 };
      cur.count++;
      if (LEVEL_ORDER[f.level] > LEVEL_ORDER[cur.level]) cur.level = f.level;
      issues.set(d, cur);
    }
  }
  // Documents cited by findings but not listed for the tab are added at the end.
  const all = [...docs, ...[...issues.keys()].filter((d) => !docs.includes(d) && SPECS[d])];
  const broken = all.filter((d) => issues.has(d)).length;
  return (
    <details className="card collapsible section-top" open={broken > 0}>
      <summary>
        <b>Relevant specifications</b>{' '}
        <span className="muted small">
          {all.length} document{all.length === 1 ? '' : 's'} ·{' '}
          {broken ? `${broken} with warnings or errors` : 'no warnings or errors'}
        </span>
      </summary>
      <ul className="spec-list" style={{ marginTop: 10 }}>
        {all.map((d) => {
          const s = SPECS[d]!;
          const i = issues.get(d);
          return (
            <li key={d} className={`spec${i ? ` broken-${i.level}` : ''}`}>
              <StatusIcon level={i?.level ?? 'ok'} size={14} />
              <div>
                <a href={s.url} target="_blank" rel="noreferrer">
                  {s.label}
                </a>
                {s.status && <span className="note"> · {s.status}</span>}
                <div className="title">{s.title}</div>
                <div className="issues">
                  {i ? (
                    <>
                      {i.count} {i.level === 'error' ? 'error' : 'warning'}
                      {i.count === 1 ? '' : 's'} cite this
                    </>
                  ) : (
                    <span className="muted">No warnings or errors</span>
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </details>
  );
}

const CHIPS_COLLAPSED = 12;

/** Compact, wrapping list of the domains/reporters/sources a finding covers; a click filters the view. */
export function SubjectChips({
  subjects,
  onPick,
}: {
  subjects: InsightSubject[];
  onPick?: (s: InsightSubject) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? subjects : subjects.slice(0, CHIPS_COLLAPSED);
  const hidden = subjects.length - shown.length;
  return (
    <ul className="chips">
      {shown.map((s) => (
        <li key={`${s.kind}:${s.value}`}>
          <button
            type="button"
            className={`chip${s.level ? ` chip-${s.level === 'error' ? 'critical' : s.level}` : ''}`}
            onClick={() => onPick?.(s)}
            disabled={!onPick}
          >
            {s.level && <StatusIcon level={s.level} size={12} />}
            {s.value}
            {s.note && <span className="chip-note">{s.note}</span>}
          </button>
        </li>
      ))}
      {(hidden > 0 || expanded) && subjects.length > CHIPS_COLLAPSED && (
        <li>
          <button type="button" className="chip chip-more" onClick={() => setExpanded(!expanded)}>
            {expanded ? 'Show fewer' : `+${hidden} more`}
          </button>
        </li>
      )}
    </ul>
  );
}

/** Insight rows (report analysis), as in tlsrpt. */
export function Insights({
  items,
  onPick,
}: {
  items: { level: Level; title: string; detail: string; subjects?: InsightSubject[]; refs?: RfcRef[] }[];
  onPick?: (s: InsightSubject) => void;
}) {
  return (
    <div className="insights" aria-label="Findings">
      {items.map((i, n) => (
        <div className="insight" key={n}>
          <StatusIcon level={i.level} />
          <div>
            <div className="t">
              {i.title}
              <StatusLabel level={i.level} />
              <Refs refs={i.refs} />
            </div>
            <div className="d">{i.detail}</div>
            {i.subjects && <SubjectChips subjects={i.subjects} {...(onPick ? { onPick } : {})} />}
          </div>
        </div>
      ))}
    </div>
  );
}
