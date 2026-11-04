# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
