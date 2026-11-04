# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- A 64-byte P1363 signature whose `r` begins with `0x30` (about one in 256)
  was handed to the DER parser and rejected, turning a genuine document into
  "altered". The length now decides the encoding.
- A real DigiCert timestamp token failed trust evaluation ("no valid
  certificate paths") because the token embeds a cross-signed copy of the
  DigiCert Trusted Root G4 that shadowed the shipped self-signed root. Copies
  of a trusted root (same subject, same key) are now dropped from the token's
  certificate pool before path building.
- `verifyEvidenceZip` could throw on a key file that is not UTF-8; that
  document is now reported `incomplete` and the rest of the archive is still
  checked.
- Seal files were matched case-sensitively while PDFs were not; both are now
  case-insensitive.

### Security

- The CLI strips control characters from proof-derived text (seal id, key id,
  URLs, archive paths) so a crafted proof cannot move the cursor and overwrite
  the verdict line. `--json` is untouched.
- The browser page turns `verifyUrl` into a link only when it is an https URL;
  `javascript:`, `data:` and plain-http values are shown as text.
- Evidence archives: only `README.txt`, `seals/`, `ledger/segment.json` and
  `documents/` are inflated, each capped at 256 MiB; an oversized entry makes
  the archive `incomplete` instead of exhausting memory.
- The timestamp signer's extended key usage must now be critical and contain
  only id-kp-timeStamping (RFC 3161 §2.3). Both public TSAs the package ships
  roots for comply.
- A ledger entry from seq 2 on that links to the genesis value (64 zeros) is
  reported inconsistent; `seq` must be a safe integer.
- The two shipped roots' SHA-256 fingerprints are pinned in the test suite.

### Changed

- Invalid `options` (a malformed fingerprint, an unparsable trusted key or
  root certificate) throw `TypeError` instead of being ignored or reported as
  `key: rejected` / `timestamp: invalid`; `prepareOptions()` exposes the same
  validation. `timestamp: invalid` is reserved for a chain that was evaluated
  and failed; with no usable root the check is `imprint_only` and says why.
- CLI usage errors (exit 2): an empty `--trust` file, `--no-builtin-roots`
  without `--tsa-roots` (unless `--no-tsa-trust`), a `--tsa-roots` file with no
  CERTIFICATE block, `--proof` together with an evidence archive. Archives are
  recognised by their bytes, not their extension.
- `sealed-pdf-verify --version`.
- `verifyEvidenceZip` notes seals that match no document in the archive.
- CI pins every GitHub Action to a commit SHA, runs the gate on Node 22 and
  24 and exercises the built package on Node 20; the container image carries
  only the bundled CLI.

- Browser page redesigned: file slots with explicit empty / chosen / checking
  states, drag-and-drop anywhere on the page, a verdict panel that names the
  five checks in plain words, copy controls for the digest and the key
  fingerprint, local-time rendering next to every timestamp, dark colour
  scheme, reduced-motion support.
- `require('sealed-pdf-verify')` now resolves CommonJS type declarations
  (`dist/index.d.cts`); the package passes `publint` and
  `@arethetypeswrong/cli`.
- The self-contained CommonJS and CLI bundles no longer ship source maps
  (8 MB less in the tarball); the ESM build keeps its map.

### Added

- `npm run check` (the full CI gate), `npm run check:pack` (publint +
  arethetypeswrong) and `npm run check:web` (the built page contains no
  network code; Vite's modulepreload polyfill is disabled).
- Fixtures: a real DigiCert token, a P1363 proof whose `r` starts with 0x30,
  malformed token variants (missing or wrong content-type attribute,
  constructed content, plain id-data CMS) and a token that embeds its own
  self-signed root; tests for every one of them, a table-driven test of the
  verdict rule over all 216 check combinations, and jsdom tests for the page's
  renderers.
- CodeQL and Dependabot configuration, issue and pull request templates,
  a Code of Conduct and `.nvmrc`.

## [0.1.0] - 2026-11-04

### Added

- `verifySealedPdf()`: the five checks (hash, signature, key, timestamp, ledger)
  with a `genuine` / `altered` / `incomplete` verdict, proof-only mode and
  key pinning by fingerprint or PEM.
- `verifyEvidenceZip()`: verifies every PDF in an evidence archive against the
  matching seal and checks the ledger segment.
- Helpers: `sha256Hex`, `parseProof`, `verifySignature`,
  `verifyTimestampImprint`, `verifyTimestampTrust`, `computeLedgerEntryHash`,
  `keyFingerprint`, `verifyLedgerSegment`.
- Command-line tool `sealed-pdf-verify` (exit 0 genuine, 1 altered,
  2 incomplete/error, `--json` output).
- Browser verifier (single HTML file, works offline, no network requests).
- Built-in RFC 3161 roots: DigiCert Trusted Root G4 and the FreeTSA root.
- Specification of the proof format (schema version 1) in the README and docs.
