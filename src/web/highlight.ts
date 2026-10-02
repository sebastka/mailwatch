// Syntax-coloured renderings of a parsed report, computed in the browser for display only.
// Both functions return tokens whose texts, joined, are the complete document.

export type TokenKind = 'key' | 'string' | 'number' | 'literal' | 'punct';
export interface Token {
  text: string;
  kind?: TokenKind;
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const scalar = (v: null | boolean | number): Token => ({
  text: String(v),
  kind: v === null || typeof v === 'boolean' ? 'literal' : 'number',
});

/** Same text as JSON.stringify(value, null, 2), split into coloured tokens. */
export function jsonTokens(value: unknown): Token[] {
  const out: Token[] = [];
  const walk = (v: Json, indent: string): void => {
    if (v === null || typeof v === 'boolean' || typeof v === 'number') {
      out.push(scalar(v));
    } else if (typeof v === 'string') {
      out.push({ text: JSON.stringify(v), kind: 'string' });
    } else if (Array.isArray(v)) {
      if (!v.length) return void out.push({ text: '[]', kind: 'punct' });
      out.push({ text: '[', kind: 'punct' });
      v.forEach((item, i) => {
        out.push({ text: `\n${indent}  ` });
        walk(item, `${indent}  `);
        if (i < v.length - 1) out.push({ text: ',', kind: 'punct' });
      });
      out.push({ text: `\n${indent}` }, { text: ']', kind: 'punct' });
    } else {
      const entries = Object.entries(v);
      if (!entries.length) return void out.push({ text: '{}', kind: 'punct' });
      out.push({ text: '{', kind: 'punct' });
      entries.forEach(([k, item], i) => {
        out.push({ text: `\n${indent}  ` }, { text: JSON.stringify(k), kind: 'key' }, { text: ': ', kind: 'punct' });
        walk(item, `${indent}  `);
        if (i < entries.length - 1) out.push({ text: ',', kind: 'punct' });
      });
      out.push({ text: `\n${indent}` }, { text: '}', kind: 'punct' });
    }
  };
  // Round-trip first so the input is exactly what JSON can represent (drops undefined, etc.).
  walk(JSON.parse(JSON.stringify(value ?? null)) as Json, '');
  return out;
}

// Words that YAML 1.1 or 1.2 parsers read as booleans or null when left unquoted.
const RESERVED = /^(?:true|false|yes|no|y|n|on|off|null|~)$/i;
// A conservative "safe plain scalar": starts with a letter, no characters with YAML meaning,
// and nothing that could be read as a number, date or other typed value.
const PLAIN = /^[A-Za-z][\w.@/+-]*(?: [\w.@/+-]+)*$/;

/** Strings stay unquoted only when every YAML parser reads them back as the same string. */
function yamlString(s: string): string {
  return PLAIN.test(s) && !RESERVED.test(s) ? s : JSON.stringify(s); // JSON strings are valid YAML
}

/** A readable YAML rendering of the same data, with block style and two-space indentation. */
export function yamlTokens(value: unknown): Token[] {
  const out: Token[] = [];
  const inline = (v: Json): Token | null => {
    if (v === null || typeof v === 'boolean' || typeof v === 'number') return scalar(v);
    if (typeof v === 'string') return { text: yamlString(v), kind: 'string' };
    if (Array.isArray(v) && !v.length) return { text: '[]', kind: 'punct' };
    if (!Array.isArray(v) && !Object.keys(v).length) return { text: '{}', kind: 'punct' };
    return null; // non-empty collection: written as a block
  };
  const block = (v: Json, indent: string): void => {
    if (Array.isArray(v)) {
      for (const item of v) {
        out.push({ text: indent }, { text: '- ', kind: 'punct' });
        const one = inline(item);
        if (one) {
          out.push(one, { text: '\n' });
        } else if (Array.isArray(item)) {
          out.push({ text: '\n' });
          block(item, `${indent}  `);
        } else {
          mapping(item as Record<string, Json>, `${indent}  `, true);
        }
      }
    } else {
      mapping(v as Record<string, Json>, indent, false);
    }
  };
  // In a list item the first key continues the "- " line; later keys are indented under it.
  const mapping = (m: Record<string, Json>, indent: string, continuesDash: boolean): void => {
    Object.entries(m).forEach(([k, item], i) => {
      if (!(continuesDash && i === 0)) out.push({ text: indent });
      out.push({ text: yamlString(k), kind: 'key' }, { text: ':', kind: 'punct' });
      const one = inline(item);
      if (one) {
        out.push({ text: ' ' }, one, { text: '\n' });
      } else {
        out.push({ text: '\n' });
        block(item, `${indent}  `);
      }
    });
  };
  const root = JSON.parse(JSON.stringify(value ?? null)) as Json;
  const one = inline(root);
  if (one) out.push(one, { text: '\n' });
  else block(root, '');
  return out;
}
