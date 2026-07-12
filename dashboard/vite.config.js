import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// HTTP API is proxied through Vite for convenience; the WebSocket is NOT
// proxied — it connects directly via VITE_WS_URL to avoid ws:// vs http://
// protocol confusion that Vite proxies are prone to.
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
            },
        },
    },
});
