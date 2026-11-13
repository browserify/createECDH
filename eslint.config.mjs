import ljharb from '@ljharb/eslint-config/flat';

export default [
	...ljharb,
	{
		rules: {
			'func-style': ['error', 'declaration'],
			'no-magic-numbers': 'off',
		},
	},
	{
		files: ['browser.js'],
		rules: {
			'no-buffer-constructor': 'off',
			'no-underscore-dangle': 'off',
		},
	},
	{
		files: ['index.js'],
		rules: {
			'global-require': 'off',
		},
	},
];
