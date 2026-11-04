# Contributing

Thanks for helping keep this verifier correct. A few rules keep it trustworthy.

## Ground rules

1. **Never weaken a check to make a test pass.** If a fixture no longer
   verifies, the fixture or the verifier has a bug; find out which.
2. **Offline only.** No `fetch`, no analytics, no CDN assets in `src/`,
   `cli/` or `web/`. The only network call in the repository is the fixture
   generator's one request to a public timestamp authority.
3. **Runtime-neutral library.** `src/` must not import `node:*`; ESLint
   enforces it. Node-only code lives in `cli/`.
4. **No issuer branding in code.** `scripts/check-no-brand.mjs` fails the
   build if `src/`, `cli/`, `web/src/` or `test/` mention the issuer. The
   brand belongs in README, LICENSE, `package.json`, docs and the footer of
   `web/index.html` only.
5. **Spec changes bump the schema.** A change to the proof format is a new
   `schemaVersion`; the verifier must keep accepting the old one.

## Development

```bash
npm ci
npm run lint        # eslint + prettier --check
npm run typecheck   # tsc --noEmit
npm test            # vitest with coverage (≥ 90 % lines enforced)
npm run check:brand # issuer name must not appear in code
npm run check:roots # src/tsa-roots.generated.ts matches tsa-roots/*.pem
npm run build       # dist/ (ESM + CJS + types + CLI) and web/dist/
npm run check:pack  # publint + arethetypeswrong on the built package
npm run check       # everything above in CI order, then the dist smoke test
```

`npm run check` is what CI runs and what `prepublishOnly` runs; make it green
before opening a pull request. The published package runs on Node 20; the
development tooling (vitest 5, vite 8) needs Node 22.12+, which `.nvmrc`
selects. CI runs the gate on Node 22 and 24 and exercises the built `dist/`
on Node 20.

### Browser page

`npm run dev:web` serves `web/` with Vite. The page has no framework and no
external assets by design; keep it that way. Every state the page can be in
(empty, file chosen, checking, genuine, altered, incomplete, failure) has a
designed appearance in `web/src/style.css`; check both colour schemes and a
phone-width viewport before sending a change.

### Fixtures

`npm run fixtures` regenerates everything under `test/fixtures/` with a fresh
ephemeral key, a synthetic timestamp authority (including malformed token
variants the verifier must reject) and two real tokens, from FreeTSA and
DigiCert (only a 32-byte hash is sent to each). Commit the regenerated files
together. Never commit a real customer document.

### Trusted roots

Roots live in `tsa-roots/*.pem` and are mirrored into
`src/tsa-roots.generated.ts` by `npm run sync:roots`. Add a root only from the
CA's own site and say where it came from in the pull request.

## Pull requests

- Keep changes small and focused; include tests for every new branch.
- Add a line to `CHANGELOG.md` under "Unreleased".
- CI runs lint, typecheck, tests, the brand check, both builds and the
  package lint on Node 20 and 22; all must be green.
- Be kind; the [Code of Conduct](CODE_OF_CONDUCT.md) applies everywhere in
  this project.
