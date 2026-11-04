# sealed-pdf-verify

[![CI](https://github.com/minutenotary/sealed-pdf-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/minutenotary/sealed-pdf-verify/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/sealed-pdf-verify)](https://www.npmjs.com/package/sealed-pdf-verify)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node ≥ 20](https://img.shields.io/badge/node-%E2%89%A5%2020-brightgreen)](package.json)

Offline, independent verifier for PDF documents sealed by
[minutenotary.ca](https://minutenotary.ca). It checks, without any network
access, that the PDF you hold is byte-for-byte the one that was sealed, that
the seal was made with the issuer's key, when it was made (RFC 3161
timestamp), and that the seal sits in the issuer's public append-only ledger.

- **Library** (`import { verifySealedPdf } from 'sealed-pdf-verify'`): ESM +
  CommonJS + TypeScript types, runs in Node 20+ (development needs 22.12+)
  and in browsers (WebCrypto
  for SHA-256, [@noble/curves](https://github.com/paulmillr/noble-curves)
  for ECDSA, [PKI.js](https://pkijs.org) for the timestamp chain).
- **CLI** (`npx sealed-pdf-verify`): one command, exit status 0/1/2.
- **Browser page** (`web/`): drop a PDF and its proof, read the verdict; one
  HTML file that works from `file://` and offline. Hosted copy:
  <https://minutenotary.github.io/sealed-pdf-verify/>.

Documentation: <https://sealed-pdf-verify.readthedocs.io/>.

Online check by the issuer: `https://minutenotary.ca/verify/<sealId>` (the
seal id is printed on the document as `Code: <sealId>` and encoded in its
QR). This tool is the offline, independent second opinion.

## 60-second quick start

You received two files next to each other: `document.pdf` (the sealed PDF)
and `document.proof.json` (the proof sidecar).

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json
```

```
Verdict: GENUINE

  hash       match         SHA-256 of the PDF equals the digest recorded in the proof
  signature  valid         ECDSA P-256 over the digest verifies with the proof's public key (der encoding)
  key        unpinned      no trust list supplied: the signature math was checked, the key itself was not (compare the fingerprint out of band)
  timestamp  trusted       the token covers this digest at 2026-11-04T17:16:41.000Z and its signer chains to a trusted root
  ledger     consistent    ledger entry #1 recomputes from the proof and matches

  Seal id        ...
  Sealed digest  ...
  Key            <sha256 fingerprint of the signing key>
  Sealed at      2026-11-04T12:00:00.000Z
  Timestamp      2026-11-04T17:16:41.000Z  (https://freetsa.org/tsr)
  Online check   https://minutenotary.ca/verify/...
  Algorithm      OCI_ECDSA_P256_SHA256
```

Exit status: `0` genuine, `1` altered, `2` incomplete or error. Add `--json`
for the verdict as JSON, `--version` for the version. Proof-derived text is
stripped of control, bidirectional and zero-width characters before it
reaches the terminal; `--json` writes them as `\uXXXX` escapes instead (the
same JSON value to any parser).

Proof-only mode (`--proof` without a PDF) checks the proof against its own
recorded digest. It can prove that the proof is internally consistent, not
that any PDF matches it; the verdict line, the `mode` field and a note all
say so, and the exit status is the same `0` as a full check. Scripts that
need the PDF checked must pass it.

To also prove that the key is the issuer's key, pin it with a trust list you
have filled in yourself (the CLI refuses an empty one):

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json --trust issuers.json
```

`trust/issuers.json` in this repository is the empty template for that file;
see [Confirming the key fingerprint](#confirming-the-key-fingerprint) for the
fingerprint to put in it.

An evidence ZIP (delivered by the issuer on request) verifies in one go:

```bash
npx sealed-pdf-verify evidence.zip
```

## The five checks, in plain words

| Check         | Result                                          | Meaning                                                                                                                                                                                                                                                                    |
| ------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **hash**      | `match` / `mismatch` / `not_checked`            | SHA-256 of the exact PDF bytes equals the digest in the proof. `mismatch` means the file changed after sealing (even one byte). `not_checked` only in proof-only mode (no PDF given).                                                                                      |
| **signature** | `valid` / `invalid`                             | The ECDSA P-256 signature in the proof verifies over that digest with the public key in the proof. Proves the proof and the digest belong together and were produced by whoever holds the private key.                                                                     |
| **key**       | `pinned` / `unpinned` / `rejected`              | Whether that public key is one you trust. `pinned`: it matches your trust list. `unpinned`: no trust list was given, so only the math was checked. `rejected`: a trust list was given and the key is not on it, which makes the verdict `altered` even if the math passes. |
| **timestamp** | `trusted` / `imprint_only` / `none` / `invalid` | The RFC 3161 token covers the same digest (`imprint`) and, when roots are available, its signer chains to a trusted timestamp authority (`trusted`). `invalid` means the token does not match the digest or its chain failed; it makes the verdict `altered`.              |
| **ledger**    | `consistent` / `inconsistent` / `not_checked`   | The ledger entry hash recomputes from the proof's own fields (sequence number, digest, previous entry hash, sealing time). `inconsistent` makes the verdict `altered`.                                                                                                     |

**Verdict:** `genuine` when hash is not a mismatch, signature is valid, key is
not rejected, timestamp is not invalid and ledger is not inconsistent.
Anything else is `altered`. `incomplete` means the input could not be read
(for example a proof with an unknown schema version, or a PDF in an evidence
archive with no matching seal).

In proof-only mode (no PDF supplied) the verdict says explicitly that the PDF
bytes were not checked.

## Getting the proof JSON and the evidence ZIP

- The **proof sidecar** (`<name>.proof.json`) is delivered next to the sealed
  PDF by the issuer. Keep both files together; the proof is useless without
  the PDF and vice versa.
- The **evidence ZIP** is produced by the issuer on request. It contains the
  sealed PDF(s), one seal file per document, the public key, the timestamp
  token and a segment of the ledger. `sealed-pdf-verify evidence.zip`
  verifies every PDF inside against the seal whose digest matches it.

## Confirming the key fingerprint

A valid signature only proves that _some_ key signed the digest. To know it
is the issuer's key, compare the fingerprint the verifier prints (`Key` line,
or `facts.fingerprint` in JSON) with the fingerprint published out of band:

- on the issuer's web site, [minutenotary.ca](https://minutenotary.ca)
  (verification page), or
- printed in the `README.txt` of an evidence archive from the issuer.

Then put it in a trust file and pass `--trust`:

```json
{ "fingerprints": ["<64 hex characters>"] }
```

The fingerprint is the SHA-256 of the key's SubjectPublicKeyInfo DER. You can
compute it yourself from a PEM public key:

```bash
openssl ec -pubin -in key.pem -outform DER | openssl dgst -sha256
```

With `--trust` (or `trustedKeyFingerprints` / `trustedPublicKeys` in the API)
the key check becomes `pinned` or `rejected`; a rejected key makes the whole
verdict `altered`, because a valid signature from an unauthorised key proves
nothing.

## Timestamp roots

The package ships two public roots under `tsa-roots/`, downloaded from the
CAs' own sites and mirrored into the library:

- `digicert-trusted-root-g4.pem` (DigiCert Trusted Root G4; the issuer's
  primary TSA is `http://timestamp.digicert.com`)
- `freetsa-root.pem` (FreeTSA, `https://freetsa.org/tsr`)

Add roots with `--tsa-roots extra.pem` (CLI) or `tsaRootsPem` (API).
`--no-builtin-roots` drops the shipped ones and must come with `--tsa-roots`
(or `--no-tsa-trust`): with no root at all the CLI exits 2 rather than quietly
reporting `imprint_only`. `--no-tsa-trust` skips the chain check, in which
case the best timestamp result is `imprint_only`.

## Library

```ts
import { readFile } from 'node:fs/promises';
import { verifySealedPdf, verifyEvidenceZip } from 'sealed-pdf-verify';

const verdict = await verifySealedPdf({
  pdf: new Uint8Array(await readFile('document.pdf')),
  proof: await readFile('document.proof.json', 'utf8'), // object, JSON text or bytes
  options: {
    trustedKeyFingerprints: ['<sha256 hex>'], // optional: key pinning
    tsaRootsPem: [], // optional: extra TSA roots (PEM)
    useBuiltInTsaRoots: true, // default
    checkTimestampTrust: true, // default
  },
});
verdict.overall; // 'genuine' | 'altered' | 'incomplete'
verdict.checks; // { hash, signature, key, timestamp, ledger }
verdict.facts; // sealId, documentHash, computedHash, fingerprint, sealedAt, timestampTime, tsaUrl, verifyUrl, algorithm, keyId, keyVersion
verdict.reasons; // one sentence per check
verdict.notes; // e.g. the proof-only warning

const archive = await verifyEvidenceZip(new Uint8Array(await readFile('evidence.zip')));
archive.overall;
archive.documents;
archive.ledgerSegment;
```

Lower-level helpers are exported too: `sha256Hex`, `parseProof`,
`verifySignature`, `keyFingerprint`, `verifyTimestampImprint`,
`verifyTimestampTrust`, `computeLedgerEntryHash`, `verifyLedgerEntry`,
`verifyLedgerSegment`, `BUILT_IN_TSA_ROOTS`.

`verifySealedPdf` and `verifyEvidenceZip` never throw on bad **document**
input; an unreadable proof yields `overall: 'incomplete'` with `error` set and
a broken file inside an archive marks that document `incomplete`. Bad
**options** (a malformed fingerprint, an unparsable trusted key or root
certificate) throw `TypeError` up front: those are caller mistakes, not
evidence about the document. The lower-level helpers throw on malformed input
where the documentation says so.

Browsers: the library uses only WebCrypto, `atob`/`btoa` and `TextEncoder`;
no `node:` imports. The `web/` page is a ready-made static verifier.

## Threat model

What a `genuine` verdict proves:

- The PDF bytes are exactly the bytes that were sealed (SHA-256).
- The seal was produced by the holder of the private key whose public key is
  in the proof, and, with pinning, that this is the issuer's key.
- The digest existed no later than the timestamp authority's `genTime`
  (if `timestamp: trusted`), and the issuer recorded it in its ledger at
  the stated sequence position (`ledger: consistent`, recomputed locally).

What it does **not** prove:

- Who signed the underlying document, that they were who they claimed, or
  that they had authority: the seal is the issuer's statement about bytes
  and time, not about the people in the document.
- The legal effect of the document in any jurisdiction.
- That the issuer's key was not compromised: a stolen key produces valid
  seals. Key compromise is handled by the issuer rotating keys and
  publishing the fingerprints; keep your trust list current.
- That the ledger is globally consistent: the local check recomputes one
  entry (or one segment). Comparing against the issuer's published chain is
  what the online check adds.
- Anything about a PDF without its proof: with the proof missing the tool
  cannot run; with the PDF missing it runs in proof-only mode and says so.

The verifier makes no network requests, so nothing about your document is
disclosed by running it.

## FAQ

**The verdict is `altered` but I did not change anything.** Any re-save,
"print to PDF", mail-client conversion, or annotation changes the bytes. Ask
for the original file from the issuer's delivery (or the evidence ZIP).

**`key: unpinned`: is that a failure?** No. It means you did not supply a
trust list, so the verifier could only check the math. Pin the key to turn it
into `pinned`.

**`timestamp: invalid` with "signer not trusted".** The token's signer does
not chain to the shipped roots. If the issuer used another TSA, add its root
with `--tsa-roots`. If the issuer did use DigiCert or FreeTSA, treat the
document as altered.

**`timestamp: imprint_only`.** The token matches the digest but the signer
chain was not evaluated (no roots, or `--no-tsa-trust`).

**Can I verify without the PDF?** Yes, `sealed-pdf-verify --proof x.json`
checks the proof's internal consistency (signature, timestamp, ledger over the
recorded digest) and states that the PDF bytes were not checked.

**Does it work offline?** Yes, everywhere: CLI, library and the browser page.

**Why does the proof carry its own public key?** So the signature can be
checked without a lookup. Trust in the key comes from pinning, not from the
proof.

## Specification (schema version 1)

Third parties can write their own verifier from this section alone.

### Document hash

`documentHash` = SHA-256 of the exact PDF bytes, lowercase hex, 64 characters.
Compare case-insensitively, in constant time.

### Proof sidecar JSON

```json
{
  "schemaVersion": 1,
  "sealId": "opaque id, also the verify code printed on the document",
  "documentHash": "64 hex",
  "algorithm": "OCI_ECDSA_P256_SHA256",
  "signature": "base64",
  "keyId": "opaque string",
  "keyVersion": "opaque string",
  "publicKeyPem": "-----BEGIN PUBLIC KEY----- (SPKI, EC P-256) -----END PUBLIC KEY-----",
  "tsaToken": "base64 DER RFC 3161 TimeStampToken (CMS ContentInfo) or null",
  "tsaUrl": "string or null",
  "timestampedAt": "ISO-8601 or null",
  "ledger": { "seq": 123, "previousEntryHash": "64 hex", "entryHash": "64 hex" },
  "verifyUrl": "https://minutenotary.ca/verify/<sealId>",
  "sealedAt": "ISO-8601 (Date#toISOString() form, e.g. 2026-11-04T15:04:05.000Z)"
}
```

`keyId`, `keyVersion`, `tsaUrl`, `timestampedAt` and `verifyUrl` are opaque
display strings (this verifier tolerates their absence). Unknown extra fields
are ignored. `schemaVersion` other than `1` is rejected with a clear error.

### Signature

- ECDSA on P-256 (secp256r1) over the raw 32-byte SHA-256 digest. The digest
  is the message; it is **not** hashed again (prehashed / digest-signing
  mode).
- Encoding: base64 of a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s
INTEGER }` (RFC 3279). A 64-byte IEEE P1363 `r || s` is also accepted.
  Nothing else.
- Low-S is **not** enforced: a high-S signature is valid. `r` and `s` must be
  in `[1, n-1]`.
- `algorithm` must be exactly `OCI_ECDSA_P256_SHA256` (current) or
  `ECDSA_P256_SHA256` (legacy); both mean the scheme above. Any other label
  fails the signature check.
- `publicKeyPem` is a PEM SubjectPublicKeyInfo (`PUBLIC KEY`), key type EC,
  named curve P-256. Other key types or curves are rejected. The API also
  accepts raw SPKI DER.

### Key fingerprint and pinning

`fingerprint` = SHA-256, lowercase hex, of the SPKI DER bytes. With a trust
list (fingerprints and/or PEM keys) the proof's key must match one →
`pinned`; otherwise `rejected` and the verdict is `altered`. With no trust
list → `unpinned`.

### RFC 3161 timestamp

`tsaToken` = base64 DER TimeStampToken: CMS `ContentInfo` with
`contentType` = id-signedData, whose `SignedData.encapContentInfo` has
`eContentType` = id-ct-TSTInfo (`1.2.840.113549.1.9.16.1.4`) and `eContent` =
DER `TSTInfo`.

- Required ("imprint"): `TSTInfo.messageImprint.hashAlgorithm` =
  `2.16.840.1.101.3.4.2.1` (SHA-256) and `hashedMessage` = the document
  digest (constant-time). `genTime` is the trusted time. No token →
  `timestamp: none`.
- Optional ("trust", on by default when roots exist): the token carries
  exactly one `SignerInfo`, whose digest algorithm is SHA-256/384/512 and
  whose signature algorithm is RSA or ECDSA (SHA-1 is refused outright); its
  signature over the signed attributes verifies (the `messageDigest`
  attribute equals the digest of `eContent` with that digest algorithm, and
  the `content-type` attribute names id-ct-TSTInfo); the signer certificate
  is found in `SignedData.certificates` by `sid`; it carries the extended key
  usage extension, critical, with id-kp-timeStamping (`1.3.6.1.5.5.7.3.8`) as
  its only purpose; it was valid at `genTime`; and it chains to a trusted
  root (a cross-signed copy of a CA inside the token never blocks the path).
  No revocation data is consulted.
- Results: `none` | `imprint_only` | `trusted` | `invalid`. `invalid` →
  verdict `altered`.

### Ledger (append-only hash chain)

```
entryHash = sha256_hex( "<seq>\n<documentHash>\n<previousEntryHash>\n<sealedAt>" )
```

UTF-8, `\n` = LF, `seq` as a decimal integer, hashes lowercase hex,
`sealedAt` exactly the ISO string of the proof. The genesis entry has
`previousEntryHash` = 64 zeros.

- Required: recompute from `ledger.seq`, `documentHash`,
  `ledger.previousEntryHash`, `sealedAt` and compare with `ledger.entryHash`
  → `consistent` | `inconsistent`. No ledger block → `not_checked`.
- Optional: an evidence archive's `ledger/segment.json` (array of
  `{ seq, documentHash, previousEntryHash, entryHash, sealedAt }`) is checked
  entry by entry, each `previousEntryHash` must equal the prior `entryHash`,
  and `seq` must increase by one.

### Evidence ZIP

```
README.txt
documents/<name>.pdf            one or more
seals/<sealId>.json             proof fields minus schemaVersion/ledger, plus disposition, roundSequence, supersededAt, supersededReason
seals/<sealId>.public-key.pem
seals/<sealId>.tsr              raw TimeStampToken DER (only when a timestamp exists)
ledger/segment.json
audit/booking-audit-log.json    ignored by the verifier
```

For each PDF under `documents/`, the seal whose `documentHash` equals the
PDF's SHA-256 is verified as above; the ledger block comes from the segment
entry with the same digest and the same `sealedAt` (a document sealed twice
has two entries), and a `ledger` block inside the seal file is ignored. A
document the segment does not mention keeps its own checks but makes the
archive `incomplete`. Only `README.txt`, `seals/`, `ledger/segment.json` and
`documents/` are inflated: 256 MiB per entry, 1 GiB and 1 000 entries in
total. Missing optional files are tolerated. A top-level folder inside the
archive is tolerated.

### Verdict object

```ts
overall: 'genuine' | 'altered' | 'incomplete'
checks: {
  hash:      'match' | 'mismatch' | 'not_checked',
  signature: 'valid' | 'invalid',
  key:       'pinned' | 'unpinned' | 'rejected',
  timestamp: 'trusted' | 'imprint_only' | 'none' | 'invalid',
  ledger:    'consistent' | 'inconsistent' | 'not_checked',
}
facts: { sealId, documentHash, computedHash, fingerprint, sealedAt, timestampTime, tsaUrl, verifyUrl, algorithm, keyId, keyVersion }
```

`genuine` = hash ≠ mismatch AND signature = valid AND key ≠ rejected AND
timestamp ≠ invalid AND ledger ≠ inconsistent. Any failing check → `altered`.
Unreadable proof → `incomplete`.

## Development

```bash
npm ci
npm run lint && npm run typecheck && npm test   # tests enforce ≥ 90 % line coverage
npm run check:brand                              # issuer name must not appear in code
npm run build                                    # dist/ and web/dist/
npm run fixtures                                 # regenerate test/fixtures/ (one request each to freetsa.org and timestamp.digicert.com)
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CHANGELOG.md](CHANGELOG.md).

## License

MIT © 2026 minutenotary.ca
