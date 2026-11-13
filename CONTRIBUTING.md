# Contributing to NoxaPlus EnvSentinel

Thanks for taking the time to improve a tool whose whole job is to keep people out of trouble. Small, well-tested changes are welcome — especially new rules, better placeholder detection, and fewer false positives.

## Before you start

- For a new rule, open an issue with the provider documentation and a synthetic example. Do not paste a real credential.
- For a behavior change, describe the false positive or false negative you hit and what you expected instead.
- For a large refactor, open an issue first so we can agree on the shape before you spend time on it.

## Development setup

```bash
npm ci
npm run typecheck
npm test
npm run build
npm run scan
```

`npm run scan` runs EnvSentinel against the repository itself. It should stay clean. If you add a fixture that looks like a secret, construct it at runtime in the test instead of committing a literal value.

## Adding a rule

1. Add the rule to `RULES` in `src/rules.ts` with a unique kebab-case `id`, a severity, a one-sentence `description`, and an anchored-enough regex. Use a capture group when the secret is part of a larger match and set `secretGroup`; set `hideMatch` when the whole match is the sensitive value.
2. Add cases to `test/rules.test.ts`: a positive sample, a near-miss that must not match, and a masking expectation.
3. Run `envsentinel rules` and confirm the summary counts.
4. Add the rule to `CHANGELOG.md` under the next unreleased version.

Prefer specific provider rules over broad generic ones. Specific rules produce better messages and outrank `generic-assignment` during deduplication.

## Pull requests

- Keep one concern per pull request.
- Include tests for behavior changes. The suite must pass with `npm test`.
- Update `README.md` or `CHANGELOG.md` when the CLI, config, output, or rule list changes.
- Do not commit real secrets, private keys, customer data, or anything that looks like a live credential. Tests must build fake values at runtime.
- Match the existing style: TypeScript with strict settings, no runtime dependencies, Node built-ins only.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be specific, be kind, and critique the work rather than the person.

## License

By contributing, you agree that your contribution is licensed under the MIT License.
