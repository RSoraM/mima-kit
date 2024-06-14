import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    browser: {
      enabled: false,
      name: 'chrome', // browser name is required
    },
  },
})
