import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiPort = process.env.PORT ?? '3000';

export default defineConfig({
  root: 'src/web',
  plugins: [react()],
  build: { outDir: '../../dist/web', emptyOutDir: true },
  server: {
    port: 5173,
    // /auth too, so the OIDC flow works through the dev server (PUBLIC_URL=http://localhost:5173).
    // With trailing slashes: a bare '/api' prefix would also capture the UI module /api.ts.
    proxy: { '/api/': `http://127.0.0.1:${apiPort}`, '/auth/': `http://127.0.0.1:${apiPort}` },
  },
});
