# Contributing

Thanks for your interest in contributing to the ProdCycle Compliance Verification Action!

## Development

```bash
# Install dependencies
pnpm install

# Type check
pnpm run type-check

# Run tests
pnpm run test

# Build (bundles into dist/ with ncc)
pnpm run build

# Run all checks
pnpm run all
```

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run `pnpm run all` to ensure everything passes
5. Commit your changes **including the updated `dist/` folder** (GitHub Actions require `dist/` to be committed)
6. Open a pull request

## Important: Commit `dist/`

GitHub Actions run directly from the repository, so the bundled `dist/index.js` must be committed. Always run `pnpm run build` before committing and include the `dist/` changes.

## Testing

Tests use [Vitest](https://vitest.dev). Add tests for any new functionality in the `__tests__/` directory.

## Code Style

- TypeScript strict mode
- Prettier for formatting (`pnpm run format`)
- ESLint for linting (`pnpm run lint`)

## Issues

- Bug reports and feature requests are welcome via GitHub Issues
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)
