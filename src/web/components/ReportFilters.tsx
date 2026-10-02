import type { ReportFilterOptions } from '../../shared/types.ts';
import { PRESETS, type RangeState } from '../report-filters.ts';

export function ReportFilterBar({
  state,
  update,
  options,
}: {
  state: RangeState;
  update: (patch: Partial<RangeState>) => void;
  options: ReportFilterOptions | null;
}) {
  return (
    <div className="filters" role="search">
      <div className="segmented" role="group" aria-label="Date range">
        {PRESETS.map((p) => (
          <button
            key={p.key}
            type="button"
            aria-pressed={state.preset === p.key}
            onClick={() => update({ preset: p.key })}
          >
            {p.label}
          </button>
        ))}
        <button type="button" aria-pressed={state.preset === 'custom'} onClick={() => update({ preset: 'custom' })}>
          Custom
        </button>
      </div>
      {state.preset === 'custom' && (
        <>
          <label className="field">
            From
            <input
              type="date"
              value={state.from}
              max={state.to}
              onChange={(e) => e.target.value && update({ from: e.target.value })}
            />
          </label>
          <label className="field">
            To
            <input
              type="date"
              value={state.to}
              min={state.from}
              onChange={(e) => e.target.value && update({ to: e.target.value })}
            />
          </label>
        </>
      )}
      <label className="field">
        Reporter
        <select value={state.org} onChange={(e) => update({ org: e.target.value })}>
          <option value="">All reporters</option>
          {options?.orgs.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </label>
      {options?.firstDay && (
        <span className="muted small">
          Reports from {options.firstDay} to {options.lastDay}
        </span>
      )}
    </div>
  );
}
