# Specification (schema version 1)

This page is normative for the proof format; a third party can write an
independent verifier from it.

## Document hash

`documentHash` = SHA-256 of the exact PDF bytes, lowercase hex, 64 characters.
Compare case-insensitively and in constant time.

## Proof sidecar JSON

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
  "sealedAt": "ISO-8601, Date#toISOString() form (2026-11-04T15:04:05.000Z)"
}
```

`keyId`, `keyVersion`, `tsaUrl`, `timestampedAt`, `verifyUrl` are opaque
display strings. Unknown extra fields are ignored. Any `schemaVersion` other
than `1` must be rejected with a clear error.

## Signature

- ECDSA, curve P-256 (secp256r1), over the raw 32-byte SHA-256 digest. The
  digest is the message for ECDSA directly; it is **not** hashed again.
- Encoding: base64 of a DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s
INTEGER }` (RFC 3279). A 64-byte IEEE P1363 `r || s` must also be accepted.
  Reject anything else. Parse DER strictly (minimal lengths and integers, no
  trailing bytes).
- Do **not** enforce low-S. Reject `r` or `s` outside `[1, n-1]`.
- `algorithm` must be one of exactly two labels meaning the scheme above:
  `OCI_ECDSA_P256_SHA256` (current) and `ECDSA_P256_SHA256` (legacy). Any
  other label fails the signature check.
- `publicKeyPem` is a PEM SubjectPublicKeyInfo (`PUBLIC KEY`), algorithm
  id-ecPublicKey (`1.2.840.10045.2.1`), named curve secp256r1
  (`1.2.840.10045.3.1.7`). Reject other key types or curves. Raw SPKI DER may
  also be accepted by an API.

## Key fingerprint and pinning

`fingerprint` = SHA-256 (lowercase hex) of the SPKI DER bytes.

Given a trust list (fingerprints and/or PEM keys), the proof's key must match
one → `key: pinned`; otherwise `key: rejected`, and the overall verdict is
`altered` even when the signature math passes. With no trust list →
`key: unpinned`; the verifier must say that only the math was checked.

## RFC 3161 timestamp

`tsaToken` = base64 of the DER TimeStampToken = CMS `ContentInfo` with
`contentType` = id-signedData (`1.2.840.113549.1.7.2`), whose
`SignedData.encapContentInfo.eContentType` = id-ct-TSTInfo
(`1.2.840.113549.1.9.16.1.4`) and `eContent` = DER `TSTInfo` (a primitive
OCTET STRING).

Required check ("imprint"): `TSTInfo.messageImprint.hashAlgorithm.algorithm`
= `2.16.840.1.101.3.4.2.1` (SHA-256) and `hashedMessage` = the document digest
(constant-time). Extract `genTime` (GeneralizedTime) as the trusted time. No
token → `timestamp: none`.

Optional check ("trust", on by default when roots are available): verify the
CMS `SignerInfo` signature over the signed attributes (the `messageDigest`
attribute must equal the digest of `eContent` under the signer's
`digestAlgorithm`; the `content-type` attribute must name id-ct-TSTInfo);
locate the signer certificate in `SignedData.certificates` by `sid`
(issuerAndSerialNumber or subjectKeyIdentifier); require the timeStamping
EKU (`1.3.6.1.5.5.7.3.8`); require validity at `genTime`; build a chain to a
trusted root. Shipped roots: DigiCert Trusted Root G4 and the FreeTSA root;
callers may add roots.

Result levels: `none` | `imprint_only` (imprint ok, trust not evaluated or no
roots) | `trusted` | `invalid` (imprint mismatch, or trust evaluation
attempted and failed). `invalid` → overall `altered`.

## Ledger (append-only hash chain)

Each seal has one chain entry:

```
entryHash = sha256_hex( "<seq>" + "\n" + "<documentHash>" + "\n" + "<previousEntryHash>" + "\n" + "<sealedAt>" )
```

UTF-8, `\n` = LF (0x0A), `seq` as a decimal integer, hashes lowercase hex,
`sealedAt` exactly the ISO-8601 string carried by the proof. The genesis
entry has `previousEntryHash` = 64 zeros.

Required check: recompute from `ledger.seq`, `documentHash`,
`ledger.previousEntryHash`, `sealedAt` and compare with `ledger.entryHash` →
`ledger: consistent` | `inconsistent`. No ledger block → `not_checked`.
`inconsistent` → overall `altered`.

Optional: an evidence `ledger/segment.json` (array of `{ seq, documentHash,
previousEntryHash, entryHash, sealedAt }`) is verified entry by entry; each
`previousEntryHash` must equal the prior entry's `entryHash` and `seq` must
increase by one; report the range checked.

## Evidence ZIP

```
README.txt
documents/<name>.pdf
seals/<sealId>.json             proof fields minus schemaVersion/ledger, plus disposition, roundSequence, supersededAt, supersededReason
seals/<sealId>.public-key.pem
seals/<sealId>.tsr              raw TimeStampToken DER, present only when a timestamp exists
ledger/segment.json
audit/booking-audit-log.json    ignore
```

For each PDF under `documents/`, find the seal whose `documentHash` equals the
PDF's SHA-256 and verify it. Tolerate missing optional files.

## Verdict

```
overall: "genuine" | "altered" | "incomplete"
checks: {
  hash:      "match" | "mismatch" | "not_checked",   // not_checked when no PDF supplied (proof-only mode)
  signature: "valid" | "invalid",                     // over the PDF digest if a PDF is given, else over documentHash
  key:       "pinned" | "unpinned" | "rejected",
  timestamp: "trusted" | "imprint_only" | "none" | "invalid",
  ledger:    "consistent" | "inconsistent" | "not_checked"
}
facts: { sealId, documentHash, fingerprint, sealedAt, timestampTime (genTime) | null, tsaUrl | null, verifyUrl, algorithm }
```

`genuine` = hash is `match` (or `not_checked` in proof-only mode) AND
signature `valid` AND key ≠ `rejected` AND timestamp ≠ `invalid` AND ledger
≠ `inconsistent`. Any failing check → `altered`. Missing or unreadable input →
`incomplete`. In proof-only mode the verdict must say explicitly that the PDF
bytes were not checked.
