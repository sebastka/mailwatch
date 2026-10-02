// What counts as "the published record" of each check, to log and announce changes.
import type {
  BimiData,
  CheckKind,
  CheckResult,
  DaneData,
  DkimData,
  DmarcData,
  MtaStsData,
  MxData,
  SpfData,
  TlsRptData,
} from '../../shared/types.ts';

/**
 * A stable text form of the records a check read, or undefined when the check could not
 * read them (a failed lookup must not look like a change). null means "no record".
 */
export function recordSignature(r: CheckResult): string | null | undefined {
  if (r.findings.some((f) => f.code.endsWith('lookup-failed') || f.code === 'internal-error')) return undefined;
  const d = r.data;
  if (d === null || d === undefined) return undefined;
  const lines = (xs: string[]) => (xs.length ? [...xs].sort().join('\n') : null);
  switch (r.check as CheckKind) {
    case 'mx': {
      const m = d as MxData;
      if (m.nullMx) return '0 .';
      return lines(m.records.map((x) => `${x.preference} ${x.exchange}`));
    }
    case 'spf':
      return lines((d as SpfData).records);
    case 'dkim':
      return lines((d as DkimData).selectors.filter((s) => s.found).map((s) => `${s.selector}: ${s.record}`));
    case 'dmarc': {
      const x = d as DmarcData;
      return x.record && !x.inherited ? x.record : lines(x.records.map((rec) => `${x.name}: ${rec}`));
    }
    case 'mta-sts': {
      const x = d as MtaStsData;
      if (!x.record) return null;
      // The policy could not be fetched: unknown, not removed.
      if (x.raw === null) return undefined;
      return `${x.record}${x.raw !== null ? `\n${x.raw.replace(/\r/g, '').trim()}` : ''}`;
    }
    case 'tls-rpt':
      return lines((d as TlsRptData).records);
    case 'dane':
      return lines(
        (d as DaneData).hosts.flatMap((h) =>
          h.tlsa.map((t) => `_25._tcp.${h.mx} ${t.usage} ${t.selector} ${t.matchingType} ${t.data}`),
        ),
      );
    case 'bimi':
      return lines((d as BimiData).records);
    default:
      return undefined;
  }
}
