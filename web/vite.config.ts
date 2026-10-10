import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// In development the UI runs on Vite (5173) and proxies the API and terminal WebSocket
// to the backend, so set ANYSSH_ORIGIN=http://localhost:5173 on the server.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', ws: true },
    },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 1000 },
});
