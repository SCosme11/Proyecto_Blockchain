import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The C++ node serves /api; in dev, Vite proxies to it. Override with LEDGER_API=http://host:port
const target = process.env.LEDGER_API ?? 'http://127.0.0.1:8080';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': { target, changeOrigin: true } },
  },
});
