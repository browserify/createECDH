import ljharb from '@ljharb/eslint-config/flat';

export default [
	...ljharb,
	{
		rules: {
			'func-style': 'off',
			'no-magic-numbers': 'off',
			'no-use-before-define': 'off',
			strict: 'off',
		},
	},
	{
		files: ['**/*.js'],
		rules: {
			indent: ['error', 2],
			semi: ['error', 'never'],
			'space-before-function-paren': ['error', 'always'],
		},
	},
	{
		files: ['browser.js'],
		rules: {
			'no-buffer-constructor': 'off',
			'no-else-return': 'off',
			'no-multi-assign': 'off',
			'no-negated-condition': 'off',
			'no-param-reassign': 'off',
			'no-underscore-dangle': 'off',
			'sort-keys': 'off',
		},
	},
	{
		files: ['index.js'],
		rules: {
			'global-require': 'off',
		},
	},
	{
		files: ['test/**'],
		rules: {
			'no-plusplus': 'off',
			'no-shadow': 'off',
		},
	},
];
