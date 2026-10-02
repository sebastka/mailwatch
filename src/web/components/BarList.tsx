import { useState } from 'react';
import { num } from '../format.ts';

export interface BarItem {
  key: string;
  label: string;
  value: number;
  note?: string;
}

/** Horizontal single-series bars with the value at the tip and a hover/focus tooltip. */
export function BarList({ items, unit }: { items: BarItem[]; unit: string }) {
  const [active, setActive] = useState<string | null>(null);
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="bars" role="list">
      {items.map((it) => (
        <div
          key={it.key}
          className="row"
          role="listitem"
          tabIndex={0}
          style={{ position: 'relative' }}
          onPointerEnter={() => setActive(it.key)}
          onPointerLeave={() => setActive(null)}
          onFocus={() => setActive(it.key)}
          onBlur={() => setActive(null)}
          aria-label={`${it.label}: ${num(it.value)} ${unit}`}
        >
          <span className="name" title={it.label}>
            {it.label}
          </span>
          <span className="track">
            <span className="bar" style={{ width: `${(it.value / max) * 85}%` }} />
            <span className="val">{num(it.value)}</span>
          </span>
          {active === it.key && it.note && (
            <div className="tooltip" style={{ top: '100%', left: 0, marginTop: 4 }}>
              <div className="tt-row">
                <span className="tt-key">
                  <i style={{ background: 'var(--series-1)' }} />
                  {it.label}
                </span>
                <b>
                  {num(it.value)} {unit}
                </b>
              </div>
              <div className="tt-note">{it.note}</div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
