import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parse } from 'yaml';
import { jsonTokens, yamlTokens, type Token } from '../src/web/highlight.ts';
import { fixture } from './helpers.ts';

const text = (tokens: Token[]) => tokens.map((t) => t.text).join('');

const TRICKY_STRINGS = [
  'yes',
  'No',
  'on',
  'OFF',
  'y',
  'n',
  'true',
  'False',
  'null',
  'Null',
  '~',
  '',
  '123',
  '1.5',
  '-1',
  '0x1F',
  '0o17',
  '1e3',
  '.inf',
  '.NaN',
  '1_000',
  '12:30',
  '2026-08-27',
  '2026-08-27T00:00:00Z',
  'version: STSv1',
  'mode: testing',
  'a #b',
  '#comment',
  '- x',
  '-',
  '? q',
  ': c',
  '@at',
  '`tick',
  '*alias',
  '&anchor',
  '!tag',
  '%dir',
  '|',
  '>',
  '[a]',
  '{a}',
  'a, b',
  ' lead',
  'trail ',
  'two  spaces',
  'multi\nline',
  'tab\there',
  'quote"s',
  "'single'",
  'back\\slash',
  'ünicode ✓',
  '3 1 1 7FF8B87BB2',
  'mx.domeneshop.no',
  '["3 1 1 ABC"]',
  'https://example.com/x?y=1#z',
  'Infinity',
  'NaN',
];

const EDGE_CASES: unknown[] = [
  null,
  true,
  false,
  0,
  -1.5,
  'plain',
  'yes',
  [],
  {},
  [[]],
  [{}],
  [[1, [2, []]], { a: [] }],
  { a: { b: { c: [1, 'two', null, { d: [] }] } } },
  [{ a: 1, b: [{ c: 2 }, [3, 4]], e: {} }, 'x'],
  Object.fromEntries(TRICKY_STRINGS.map((s, i) => [s, s || i])),
  TRICKY_STRINGS,
];

const FIXTURES = ['google-sts.json', 'microsoft-tlsa-sts.json', 'synthetic-failures.json'].map(fixture);

test('JSON tokens reproduce JSON.stringify(value, null, 2) exactly', () => {
  for (const v of [...FIXTURES, ...EDGE_CASES]) {
    assert.equal(text(jsonTokens(v)), JSON.stringify(v, null, 2));
  }
});

test('YAML parses back to identical data, under YAML 1.2 and 1.1', () => {
  for (const v of [...FIXTURES, ...EDGE_CASES]) {
    const yaml = text(yamlTokens(v));
    for (const version of ['1.2', '1.1'] as const) {
      assert.deepEqual(parse(yaml, { version, uniqueKeys: true }), v, `YAML ${version}:\n${yaml}`);
    }
  }
});

test('YAML leaves simple words unquoted and quotes anything a parser could reinterpret', () => {
  const yaml = text(
    yamlTokens({ 'policy-type': 'sts', mode: 'yes', count: '123', when: '2026-08-27', ok: 'mx.example.com', n: 1 }),
  );
  // "n" is quoted as a key too: YAML 1.1 reads a bare n as the boolean false.
  assert.equal(yaml, 'policy-type: sts\nmode: "yes"\ncount: "123"\nwhen: "2026-08-27"\nok: mx.example.com\n"n": 1\n');
});

test('a real report renders as readable block YAML', () => {
  const yaml = text(yamlTokens(fixture('google-sts.json')));
  assert.ok(yaml.startsWith('organization-name: Google Inc.\n'), yaml);
  const expected = [
    'policies:',
    '  - policy:',
    '      policy-type: sts',
    '      policy-string:',
    '        - "version: STSv1"',
  ].join('\n');
  assert.ok(yaml.includes(expected), yaml);
  assert.ok(yaml.includes('\n    summary:\n      total-successful-session-count: 2\n'), yaml);
});

test('tokens are classified for colouring', () => {
  const tokens = jsonTokens({ k: 'v', n: 1, b: true, z: null });
  const kinds = Object.fromEntries(tokens.filter((t) => t.kind && t.kind !== 'punct').map((t) => [t.text, t.kind]));
  assert.deepEqual(kinds, {
    '"k"': 'key',
    '"v"': 'string',
    '"n"': 'key',
    '1': 'number',
    '"b"': 'key',
    true: 'literal',
    '"z"': 'key',
    null: 'literal',
  });
});
