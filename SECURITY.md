# Security policy

This verifier is a reference implementation. A bug in it can make a tampered
document look genuine, or a genuine document look tampered. Both matter.

## Reporting a bug in the verifier

Please use GitHub's private vulnerability reporting on this repository
("Security" tab → "Report a vulnerability"). Include:

- the inputs that reproduce the problem (a PDF, proof JSON or evidence ZIP
  that you are allowed to share, or a synthetic one made with
  `scripts/make-fixtures.mjs`),
- the verdict you got and the verdict you expected,
- the package version (`npx sealed-pdf-verify --version`).

Reports are acknowledged within a few working days. There is no bug bounty.
Fixes ship as a patch release with a CHANGELOG entry; coordinated disclosure
is welcome but not required for verifier bugs, because this tool only reads
files the user already holds.

## What is and is not in scope

In scope:

- a check that passes when it should fail (hash, signature, key pinning,
  timestamp imprint or trust, ledger),
- a check that can be bypassed by crafted input (malformed DER, ZIP tricks,
  oversized inputs that crash instead of failing closed),
- any network request made by the library, CLI or browser page.

Out of scope:

- the sealing service itself (how seals are issued, its web site, its keys);
  report those to the issuer named in the README,
- the legal meaning of a document: the verifier proves bytes and time, not
  who signed the underlying document.

## Design rules that this project keeps

- Offline by design: no network calls anywhere.
- Fail closed: any parse or crypto error makes that check fail.
- Constant-time comparison of digests.
- Strict DER parsing of signatures (no non-minimal lengths or integers).
- Trusted roots ship in the repository and are downloaded from the CAs' own
  sites, never hand-typed.
