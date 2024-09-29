// @ts-check
import antfu from '@antfu/eslint-config'

export default antfu(
  {
    ignores: [
      // eslint ignore globs here
    ],
  },
  {
    rules: {
      // overrides
      'style/indent': 'off',
      'style/max-statements-per-line': 'off',
    },
  },
)
