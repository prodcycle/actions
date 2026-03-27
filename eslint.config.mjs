import tseslint from "typescript-eslint";

export default tseslint.config({
  files: ["src/**/*.ts", "__tests__/**/*.ts"],
  extends: [tseslint.configs.recommended],
  rules: {
    "@typescript-eslint/no-unused-vars": [
      "warn",
      { argsIgnorePattern: "^_" },
    ],
  },
});
