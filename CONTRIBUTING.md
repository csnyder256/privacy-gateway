# Contributing

Privacy and security changes need evidence, not only happy-path tests.

1. Create a focused branch.
2. Add or update shared fixtures in `conformance/` when wire behavior changes.
3. Run Python and TypeScript checks from `README.md`.
4. Include a regression test for every security or privacy bug.
5. Update the threat model when a trust boundary changes.
6. Keep examples synthetic; never commit real personal data or secrets.

Pull requests should state what was changed, what was verified, and what remains outside the
tested boundary.
