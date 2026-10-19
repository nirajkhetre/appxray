import { defineConfig } from 'vitest/config';

// Real-binary tests scan actual Electron/Qt builds. They are opt-in because the
// binaries are large; point APPXRAY_REAL_FIXTURES at a directory that contains them.
export default defineConfig({
  test: {
    include: ['test/real/**/*.test.ts'],
    environment: 'node',
    testTimeout: 300_000,
  },
});
