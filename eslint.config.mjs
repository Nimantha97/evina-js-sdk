// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

/**
 * Flat ESLint config, type-checked (ADR-001, ADR-003).
 *
 * Security-relevant lint rules (THREAT_MODEL §5A): no eval / implied eval /
 * Function constructor anywhere in the codebase.
 */
export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/coverage/**",
      "**/*.config.*",
      "eslint.config.mjs",
      // Example apps are standalone demos with their own toolchains and deps
      // (express, tsx). They are not part of the shippable SDK and are linted
      // within their own projects, so exclude them from the root type-checked
      // lint (their deps aren't installed in the root node_modules).
      "examples/**",
      // Standalone dev probe scripts (real network calls, run manually).
      "packages/*/scripts/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
    },
  },
  prettier,
);
