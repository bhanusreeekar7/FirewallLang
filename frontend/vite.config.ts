import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0', // Listen on all network addresses including 127.0.0.1 and localhost
    port: 5173,
    strictPort: true,
  },
})
