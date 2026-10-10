import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Argon2id at production cost (64 MiB) makes user-heavy setup slow on small CI runners.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
