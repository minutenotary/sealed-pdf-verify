## What

<!-- One paragraph: the change and why. Link the issue. -->

## Checklist

- [ ] `npm run check` passes locally (lint, typecheck, tests ≥ 90 % lines, brand check, build, package lint)
- [ ] No check was weakened to make a test pass; new branches have tests
- [ ] No network call added anywhere (library, CLI, web page)
- [ ] No issuer branding in `src/`, `cli/`, `web/src/` or `test/`
- [ ] `CHANGELOG.md` has a line under **Unreleased**
- [ ] Proof-format change (if any) bumps `schemaVersion` and keeps accepting version 1
