# Contributing to BLA (`bla-shield`)

Thank you for helping software developers fight back against automated AI reverse engineering!

## Development Workflow

```bash
# Install dependencies
npm install

# Build TypeScript to dist/
npm run build

# Run the Vitest test suite
npm test

# Run the local showcase (token and cost figures are estimates, not metered usage)
node dist/cli.js benchmark
```

## Architecture Guidelines

1. **Zero Runtime Side Effects**: Every AST transformation, opaque predicate, and binary section extension must be 100% side-effect free at runtime. Every shield must be verified by executing both the original and protected artifacts and asserting identical return values.
2. **Deterministic Builds**: Always thread `SeededPrng` (`--seed`) through new shield passes so builds are reproducible in CI/CD pipelines.
3. **Target Real Analyzer Limits**: When adding a new countermeasure, document the exact static/semantic analyzer heuristic or resource limit it defeats.
