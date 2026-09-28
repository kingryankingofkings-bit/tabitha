import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { __TB_VERSION__: JSON.stringify('0.1.0') },
  test: {
    include: ['test/unit/**/*.test.ts', 'test/integration/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20_000,
  },
});
