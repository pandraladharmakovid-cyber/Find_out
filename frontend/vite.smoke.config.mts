import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  define: { 'import.meta.env.VITE_API_URL': JSON.stringify('/api') },
  plugins: [react()],
  build: {
    outDir: 'dist-smoke',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        format: 'iife',
        entryFileNames: 'assets/app.js',
        inlineDynamicImports: true,
      },
    },
  },
});
