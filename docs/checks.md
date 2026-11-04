# The five checks

Every verdict is built from five independent checks. Each has a small set of
possible results and one sentence of explanation (`reasons`).

## hash: `match` | `mismatch` | `not_checked`

SHA-256 of the exact PDF bytes is compared (constant-time, case-insensitive)
with the digest recorded in the proof. `mismatch` means the bytes changed
after sealing: a re-save, a "print to PDF", an annotation, a mail client
conversion, anything. `not_checked` appears only in proof-only mode.

## signature: `valid` | `invalid`

The ECDSA P-256 signature in the proof is verified over the digest (the PDF's
digest when a PDF was supplied, the proof's recorded digest otherwise) with
the public key carried by the proof. The signature is DER (RFC 3279) or
64-byte P1363; high-S is accepted; `r` and `s` must be in `[1, n-1]`; the
`algorithm` label must be `OCI_ECDSA_P256_SHA256` or `ECDSA_P256_SHA256`.
A tampered PDF therefore fails both `hash` and `signature`.

## key: `pinned` | `unpinned` | `rejected`

A valid signature proves that _some_ key signed the digest. The key check
tells you whether it is a key you trust:

- `unpinned`: you gave no trust list; only the math was checked.
- `pinned`: the key's fingerprint matches your trust list.
- `rejected`: you gave a trust list and the key is not on it. The verdict
  becomes `altered` even if the signature math passes.

## timestamp: `trusted` | `imprint_only` | `none` | `invalid`

The RFC 3161 token is parsed; its `messageImprint` must be SHA-256 over the
same digest (`imprint`). `genTime` becomes the trusted time. When roots are
available (the shipped DigiCert and FreeTSA roots, plus any you add), the CMS
signature, the signer certificate's timeStamping EKU, its validity at
`genTime` and its chain to a root are checked (`trusted`). `imprint_only`
means the chain was not evaluated. `invalid` means the imprint does not match
or the chain failed; the verdict becomes `altered`.

## ledger: `consistent` | `inconsistent` | `not_checked`

The ledger entry hash is recomputed as
`sha256("<seq>\n<documentHash>\n<previousEntryHash>\n<sealedAt>")` from the
proof's own fields and compared with `ledger.entryHash`. An evidence archive
also lets the verifier walk a whole segment of the chain.

## The verdict

`genuine` = hash is not `mismatch` AND signature is `valid` AND key is not
`rejected` AND timestamp is not `invalid` AND ledger is not `inconsistent`.
Any failing check makes it `altered`. An unreadable proof, or a PDF in an
archive with no matching seal, is `incomplete`.
