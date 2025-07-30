// @ts-check
import antfu from '@antfu/eslint-config'

export default antfu(
  {
    type: 'lib',
    typescript: true,
    ignores: [
      // eslint ignore globs here
    ],
  },
  {
    rules: {
      // overrides
      'ts/explicit-function-return-type': 'off',
      'style/indent': 'off',
      'style/max-statements-per-line': 'off',
      'style/indent-binary-ops': 'off',
    },
  },
)
