import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: [],
    // tests/*.test.mjs are node:test source-assertion suites run by
    // `npm run test:source`; vitest cannot bundle node:test.
    include: ['src/**/*.{test,spec}.{js,jsx,ts,tsx}'],
  },
})
