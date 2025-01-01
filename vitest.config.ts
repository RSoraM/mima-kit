import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  test: {
    browser: {
      enabled: false,
      name: 'chrome',
      provider: 'preview',
    },
  },
})
