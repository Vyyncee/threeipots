import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://147.135.213.152:5000' // toutes les requêtes /api passent par Flask
    }
  }
});