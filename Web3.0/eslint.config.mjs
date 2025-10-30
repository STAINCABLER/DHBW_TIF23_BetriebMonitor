import js from '@eslint/js';
import pluginImport from 'eslint-plugin-import';
import globals from 'globals';

export default [
  {
  ignores: ['frontend/assets/vendor/**', 'node_modules/**'],
  },
  js.configs.recommended,
  {
  files: ['frontend/assets/**/*.js'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        sessionStorage: 'readonly',
        AlteBankCrypto: 'readonly',
        AlteBankArgon2: 'readonly',
        AlteBankArgon2Load: 'readonly',
        ALTEBANK_DEBUG: 'readonly',
      },
    },
    plugins: {
      import: pluginImport,
    },
    settings: {
      'import/resolver': {
        node: {
          extensions: ['.js'],
        },
      },
    },
    rules: {
      'no-console': [
        'warn',
        {
          allow: ['debug', 'info', 'warn', 'error'],
        },
      ],
      'import/no-unresolved': 'off',
    },
  },
];
