import { defineBuildConfig } from 'unbuild'

export default defineBuildConfig([
  {
    name: 'default',
    entries: ['src/index'],
    outDir: 'dist',
    clean: true,
    failOnWarn: false,
    sourcemap: true,
    rollup: {
      emitCJS: true,
    },
    declaration: true,
  },
  {
    name: 'minified',
    entries: ['src/index'],
    outDir: 'dist/min',
    clean: true,
    failOnWarn: false,
    sourcemap: true,
    rollup: {
      emitCJS: true,
      esbuild: {
        minify: true,
      },
    },
  },
])
