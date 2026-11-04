# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- PEM parsing runs in linear time. A file with many `BEGIN` lines and no
  `END` used to take quadratic time.

## [0.1.0] - 2026-11-04

First release. Two independent review rounds ran before it and their findings
are part of this version; nothing was published earlier, so there is no
previous behaviour to list as fixed.

### Added

- `verifySealedPdf()`: the five checks (hash, signature, key, timestamp,
  ledger) with a `genuine` / `altered` / `incomplete` verdict, proof-only mode
  and key pinning by fingerprint or PEM. Document input never throws; invalid
  options (a malformed fingerprint, an unparsable trusted key or root, a root
  string with no CERTIFICATE block) throw `TypeError` and are never reported as
  "altered". `prepareOptions()` exposes the same validation.
- `verifyEvidenceZip()`: verifies every PDF in an evidence archive against the
  matching seal, pairs each with its ledger entry by digest and `sealedAt`,
  checks the segment, notes seals without a document and documents the segment
  does not mention.
- Helpers: `sha256Hex`, `parseProof`, `verifySignature`,
  `verifyTimestampImprint`, `verifyTimestampTrust`, `computeLedgerEntryHash`,
  `keyFingerprint`, `verifyLedgerSegment`, the accepted CMS algorithm sets and
  the archive inflation limits.
- Command-line tool `sealed-pdf-verify` (exit 0 genuine, 1 altered,
  2 incomplete or usage error, `--json`, `--version`). Archives are recognised
  by their bytes. Usage errors: an empty `--trust` file, `--no-builtin-roots`
  without `--tsa-roots` (unless `--no-tsa-trust`), a `--tsa-roots` file with no
  CERTIFICATE block, `--proof` together with an archive.
- Browser verifier: one HTML file that works offline and makes no request;
  file slots with explicit states, drag-and-drop anywhere, a verdict panel
  that names the five checks in plain words, copy controls, local-time
  rendering, dark scheme and reduced-motion support.
- Built-in RFC 3161 roots: DigiCert Trusted Root G4 and the FreeTSA root,
  their SHA-256 pinned in the test suite.
- Specification of the proof format (schema version 1) in the README and docs.
- ESM and CommonJS builds with type declarations for both (`publint` and
  `@arethetypeswrong/cli` clean); the CommonJS and CLI bundles are minified
  without source maps, the ESM build keeps its map.
- `npm run check` (the full CI gate), `check:pack`, `check:web` (the built page
  contains no network code). CI on Node 22 and 24 with a Node 20 runtime job,
  every Action pinned to a commit SHA; CodeQL; Dependabot for npm, Actions and
  Docker; a distroless container image pinned by digest that carries only the
  bundled CLI; issue and pull request templates, a Code of Conduct, `.nvmrc`.
- Fixtures: a real FreeTSA and a real DigiCert token, a synthetic TSA with
  malformed, weak and unusual variants (missing or wrong content-type
  attribute, constructed content, plain id-data CMS, embedded self-signed
  root, non-critical or multi-purpose EKU, SHA-1 CMS signature, two
  SignerInfos, a self-signed timestamp unit, a cross-signed intermediate), a
  P1363 proof whose `r` starts with 0x30, and tests for every one of them.

### Security

- Signatures: strict DER `Ecdsa-Sig-Value` parsing; a 64-byte value is P1363
  and anything else must be DER (the length decides, never the first byte).
- Timestamps: the imprint must be SHA-256; the token must carry exactly one
  `SignerInfo` whose digest algorithm is SHA-2 and whose signature algorithm
  is RSA or ECDSA (SHA-1 is refused before any signature is checked); the
  signer's extended key usage must be critical and contain only
  id-kp-timeStamping; the chain must end at a supplied root, and a dead-end
  candidate in the token (a cross-signed copy of a CA) never hides a valid
  path. A self-signed timestamp unit supplied as a root is accepted. No
  revocation data is consulted (documented in the threat model).
- Ledger: a zero link is accepted at seq 0 and 1 only; seq 0 must carry the
  zero link; `seq` must be a safe integer.
- Evidence archives: only `README.txt`, `seals/`, `ledger/segment.json` and
  `documents/` are inflated, 256 MiB per entry, 1 GiB and 1 000 entries in
  total; a refused entry makes the archive `incomplete`; each document is
  assembled under its own try/catch; paths, seal files and side files match
  case-insensitively.
- CLI: proof-derived text is stripped of control, bidirectional and
  zero-width characters; `--json` escapes them as `\uXXXX`.
- Browser page: `verifyUrl` becomes a link only when it is https; a
  verification run that finishes after a newer one started (or after Clear)
  never paints the panel.
