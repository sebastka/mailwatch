// Date range and reporter of the report tabs.
import { useMemo, useState } from 'react';
import type { Filters } from '../shared/types.ts';
import { todayUtc } from './format.ts';

export const PRESETS = [
  { key: '7d', label: '7 days', days: 7 },
  { key: '30d', label: '30 days', days: 30 },
  { key: '90d', label: '90 days', days: 90 },
  { key: '1y', label: '1 year', days: 365 },
  { key: 'all', label: 'All', days: 0 },
] as const;
export type PresetKey = (typeof PRESETS)[number]['key'] | 'custom';

export interface RangeState {
  preset: PresetKey;
  from: string;
  to: string;
  org: string;
}

/** Date range and reporter of a report tab; the domain comes from the global filter. */
export function useReportFilters(domain: string, defaultPreset: PresetKey = '30d') {
  const [s, setS] = useState<RangeState>({ preset: defaultPreset, from: todayUtc(-29), to: todayUtc(), org: '' });
  const filters = useMemo<Filters>(() => {
    const f: Filters = {};
    if (s.preset === 'custom') {
      f.from = s.from;
      f.to = s.to;
    } else {
      const p = PRESETS.find((x) => x.key === s.preset)!;
      if (p.days) {
        f.from = todayUtc(-(p.days - 1));
        f.to = todayUtc();
      }
    }
    if (domain) f.domain = domain;
    if (s.org) f.org = s.org;
    return f;
  }, [s, domain]);
  return { state: s, update: (patch: Partial<RangeState>) => setS((x) => ({ ...x, ...patch })), filters };
}
