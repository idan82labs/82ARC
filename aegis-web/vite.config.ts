import { defineConfig, Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// Security headers plugin for development server
const securityHeadersPlugin = (): Plugin => ({
  name: 'security-headers',
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      // Content Security Policy - strict but allows necessary resources
      res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Required for Vite HMR in dev
        "style-src 'self' 'unsafe-inline' https://api.fontshare.com",
        "font-src 'self' https://api.fontshare.com data:",
        "img-src 'self' data: https:",
        "connect-src 'self' ws: wss:", // WebSocket for HMR
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join('; '));

      // Prevent clickjacking
      res.setHeader('X-Frame-Options', 'DENY');

      // Prevent MIME type sniffing
      res.setHeader('X-Content-Type-Options', 'nosniff');

      // XSS Protection (legacy browsers)
      res.setHeader('X-XSS-Protection', '1; mode=block');

      // Referrer Policy
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

      // Permissions Policy - disable unnecessary features
      res.setHeader('Permissions-Policy', [
        'camera=()',
        'microphone=()',
        'geolocation=()',
        'payment=()',
        'usb=()',
        'magnetometer=()',
        'gyroscope=()',
        'accelerometer=()'
      ].join(', '));

      // Cross-Origin policies
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

      next();
    });
  }
});

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), securityHeadersPlugin()],
  build: {
    // Generate source maps only in development
    sourcemap: process.env.NODE_ENV !== 'production',
    // Minify for production
    minify: 'terser',
    terserOptions: {
      compress: {
        // Remove console logs in production
        drop_console: process.env.NODE_ENV === 'production',
        drop_debugger: true
      }
    },
    // Content hash for cache busting
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'framer-motion'],
          security: ['dompurify', 'validator']
        }
      }
    }
  },
  // Security-related server options
  server: {
    // Only allow localhost connections
    host: 'localhost',
    // Strict port
    strictPort: true
  }
})
