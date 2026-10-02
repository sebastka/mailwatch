import { useState } from 'react';
import { compact, num, percent, shortDay } from '../format.ts';
import { useWidth } from '../hooks.ts';

const HEIGHT = 220;
const AXIS_BAND = 24;
const PAD_LEFT = 44;
const PAD_TOP = 8;
const GAP = 2;
const RADIUS = 4;

export interface Series<K extends string> {
  key: K;
  label: string;
  color: string;
}

function niceMax(v: number): { max: number; step: number } {
  if (v <= 0) return { max: 4, step: 1 };
  const rough = v / 4;
  const mag = 10 ** Math.floor(Math.log10(rough));
  const norm = rough / mag;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
  const s = Math.max(1, step);
  return { max: Math.ceil(v / s) * s, step: s };
}

/** Rect with rounded top corners, square at the bottom. */
function topRounded(x: number, y: number, w: number, h: number, r: number): string {
  const rr = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + rr}Q${x},${y} ${x + rr},${y}H${x + w - rr}Q${x + w},${y} ${x + w},${y + rr}V${y + h}Z`;
}

/**
 * Two stacked series per day or week (e.g. successful / failed), with a crosshair tooltip,
 * keyboard reading (arrow keys) and the share of the first series ("rate").
 */
export function StackedChart<K extends string, T extends { start: string; reports: number } & Record<K, number>>({
  data,
  bucket,
  series,
  rateLabel,
  what,
}: {
  data: T[];
  bucket: 'day' | 'week';
  series: [Series<K>, Series<K>];
  rateLabel: string;
  what: string;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [active, setActive] = useState<number | null>(null);
  const [lo, hi] = series;

  const plotW = Math.max(0, width - PAD_LEFT);
  const plotH = HEIGHT - PAD_TOP - AXIS_BAND;
  const peak = Math.max(0, ...data.map((d) => d[lo.key] + d[hi.key]));
  const { max, step } = niceMax(peak);
  const band = data.length ? plotW / data.length : 0;
  const barW = Math.max(2, Math.min(24, band * 0.7));
  const y = (v: number) => PAD_TOP + plotH - (v / max) * plotH;
  const ticks: number[] = [];
  for (let t = 0; t <= max + 1e-9; t += step) ticks.push(t);
  const labelEvery = Math.max(1, Math.ceil(56 / Math.max(band, 1)));

  const onKey = (e: React.KeyboardEvent) => {
    if (!data.length) return;
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const d = e.key === 'ArrowRight' ? 1 : -1;
      setActive((a) => Math.min(data.length - 1, Math.max(0, (a ?? (d > 0 ? -1 : data.length)) + d)));
    } else if (e.key === 'Escape') setActive(null);
  };

  const cur = active !== null ? data[active] : undefined;
  const curX = active !== null ? PAD_LEFT + band * active + band / 2 : 0;

  return (
    <div>
      <div className="legend" aria-hidden="true">
        {series.map((s) => (
          <span key={s.key}>
            <i className="swatch" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
      </div>
      <div className="chart" ref={ref} style={{ height: HEIGHT }}>
        {width > 0 && (
          <svg
            width={width}
            height={HEIGHT}
            role="img"
            aria-label={`${what} per ${bucket}. Use the arrow keys to read values; the table view lists them all.`}
            tabIndex={0}
            onKeyDown={onKey}
            onBlur={() => setActive(null)}
            onPointerLeave={() => setActive(null)}
            onPointerMove={(e) => {
              const box = e.currentTarget.getBoundingClientRect();
              const i = Math.floor((e.clientX - box.left - PAD_LEFT) / band);
              setActive(i >= 0 && i < data.length ? i : null);
            }}
          >
            <g className="axis">
              {ticks.map((t) => (
                <g key={t}>
                  {t > 0 && <line className="gridline" x1={PAD_LEFT} x2={width} y1={y(t)} y2={y(t)} />}
                  <text x={PAD_LEFT - 8} y={y(t)} dy="0.32em" textAnchor="end">
                    {compact(t)}
                  </text>
                </g>
              ))}
            </g>
            {cur && <rect className="crosshair" x={curX - band / 2} y={PAD_TOP} width={band} height={plotH} />}
            {data.map((d, i) => {
              const x = PAD_LEFT + band * i + (band - barW) / 2;
              const loH = d[lo.key] ? Math.max(1, y(0) - y(d[lo.key])) : 0;
              const hiH = d[hi.key] ? Math.max(1, y(0) - y(d[hi.key])) : 0;
              const loTop = y(0) - loH;
              return (
                <g key={d.start} opacity={active === null || active === i ? 1 : 0.55}>
                  {loH > 0 && (
                    <path
                      d={hiH > 0 ? `M${x},${loTop}h${barW}v${loH}h${-barW}Z` : topRounded(x, loTop, barW, loH, RADIUS)}
                      fill={lo.color}
                    />
                  )}
                  {hiH > 0 && (
                    <path d={topRounded(x, loTop - hiH - (loH > 0 ? GAP : 0), barW, hiH, RADIUS)} fill={hi.color} />
                  )}
                </g>
              );
            })}
            <line className="baseline" x1={PAD_LEFT} x2={width} y1={y(0)} y2={y(0)} />
            <g className="axis">
              {data.map((d, i) =>
                i % labelEvery === 0 ? (
                  <text key={d.start} x={PAD_LEFT + band * i + band / 2} y={HEIGHT - 6} textAnchor="middle">
                    {shortDay(d.start)}
                  </text>
                ) : null,
              )}
            </g>
          </svg>
        )}
        {cur && (
          <div
            className="tooltip"
            style={{
              top: PAD_TOP,
              left: curX > width / 2 ? undefined : curX + band / 2 + 8,
              right: curX > width / 2 ? width - curX + band / 2 + 8 : undefined,
            }}
          >
            <div className="tt-title">
              {bucket === 'week' ? `Week of ${shortDay(cur.start)}` : shortDay(cur.start)} · {cur.reports} report
              {cur.reports === 1 ? '' : 's'}
            </div>
            {series.map((s) => (
              <div className="tt-row" key={s.key}>
                <span className="tt-key">
                  <i style={{ background: s.color }} />
                  {s.label}
                </span>
                <b>{num(cur[s.key])}</b>
              </div>
            ))}
            <div className="tt-row">
              <span className="tt-key">{rateLabel}</span>
              <b>{percent(cur[lo.key] + cur[hi.key] ? cur[lo.key] / (cur[lo.key] + cur[hi.key]) : null)}</b>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
