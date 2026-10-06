## What this changes

## If this adds or changes a check

- [ ] Fires on a broken handler, with a test
- [ ] Stays silent on a correct handler, with a test
- [ ] Carries a `method` sentence saying how it was reached
- [ ] Confidence is the weaker of the two you considered
- [ ] `limitations` says what the finding does not establish
- [ ] Catalogue entry with CWE and references
- [ ] Read-only, or marked `mutating` and gated behind the `writes` profile

## Checks

- [ ] `python -m pytest` passes
- [ ] `node --check namazu/static/app.js` passes
- [ ] No em dashes (the test suite enforces this)
