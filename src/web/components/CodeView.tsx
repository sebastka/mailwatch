import { useMemo } from 'react';
import { jsonTokens, yamlTokens } from '../highlight.ts';

/** Read-only, syntax-coloured view of a report; rendered as text nodes (no HTML injection). */
export function CodeView({ value, format, label }: { value: unknown; format: 'json' | 'yaml'; label: string }) {
  const tokens = useMemo(() => (format === 'json' ? jsonTokens(value) : yamlTokens(value)), [value, format]);
  return (
    <pre className="code" aria-label={label} tabIndex={0}>
      {tokens.map((t, i) =>
        t.kind ? (
          <span key={i} className={`tok-${t.kind}`}>
            {t.text}
          </span>
        ) : (
          t.text
        ),
      )}
    </pre>
  );
}
