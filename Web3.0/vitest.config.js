import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
  include: ['frontend/assets/__tests__/**/*.test.js'],
    coverage: {
      enabled: false,
    },
  },
});
