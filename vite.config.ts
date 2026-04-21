import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Base path for asset URLs. Defaults to "/" for local dev.
// GitHub Pages at a project subpath sets this via VITE_BASE in the workflow
// (e.g. VITE_BASE=/SuperSecretSecrets/).
const base = process.env.VITE_BASE ?? '/';

export default defineConfig({
  base,
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
