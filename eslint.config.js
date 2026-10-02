import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Flat config. Formatting is delegated to Prettier (eslint-config-prettier, last,
// turns off any stylistic rules that would fight it), so ESLint only enforces
// correctness — type-aware bug rules are left to `tsc` (npm run typecheck).
export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'data', 'build'] },

  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },

  // Web UI: browser globals, React hooks + Fast Refresh checks.
  {
    files: ['src/web/**/*.{ts,tsx}'],
    languageOptions: { globals: globals.browser },
    plugins: { 'react-hooks': reactHooks, 'react-refresh': reactRefresh },
    rules: {
      ...reactHooks.configs['recommended-latest'].rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
    },
  },

  // Server, scripts, tests and tool config run on Node.
  {
    files: ['src/server/**/*.ts', 'scripts/**/*.ts', 'test/**/*.ts', '*.config.{ts,js}'],
    languageOptions: { globals: globals.node },
  },

  prettier,
);
