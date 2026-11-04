# Library API

```bash
npm install sealed-pdf-verify
```

ESM and CommonJS builds with TypeScript types. Runs in Node 20+ and in
browsers (WebCrypto for SHA-256, `@noble/curves` for ECDSA, PKI.js for the
timestamp chain). No `node:` imports.

## `verifySealedPdf(input)`

```ts
import { verifySealedPdf } from 'sealed-pdf-verify';

const verdict = await verifySealedPdf({
  pdf,            // Uint8Array, optional (omit for proof-only mode)
  proof,          // ProofV1 object, JSON text, or JSON bytes
  options: {
    trustedKeyFingerprints?: string[], // sha256 hex of SPKI DER
    trustedPublicKeys?: string[],      // PEM PUBLIC KEY blocks
    tsaRootsPem?: string[],            // extra roots, PEM (several blocks per string allowed)
    useBuiltInTsaRoots?: boolean,      // default true
    checkTimestampTrust?: boolean,     // default true
  },
});
```

Returns a `Verdict`:

```ts
interface Verdict {
  overall: 'genuine' | 'altered' | 'incomplete';
  mode: 'pdf' | 'proof-only';
  checks: {
    hash: 'match' | 'mismatch' | 'not_checked';
    signature: 'valid' | 'invalid';
    key: 'pinned' | 'unpinned' | 'rejected';
    timestamp: 'trusted' | 'imprint_only' | 'none' | 'invalid';
    ledger: 'consistent' | 'inconsistent' | 'not_checked';
  };
  facts: {
    sealId: string;
    documentHash: string;
    computedHash: string | null;
    fingerprint: string | null;
    sealedAt: string;
    timestampTime: string | null;
    tsaUrl: string | null;
    verifyUrl: string | null;
    algorithm: string;
    keyId: string | null;
    keyVersion: string | null;
  } | null;
  reasons: Record<'hash' | 'signature' | 'key' | 'timestamp' | 'ledger', string>;
  notes: string[];
  error?: string;
}
```

It never throws for document input: an unreadable proof gives `overall:
'incomplete'` with `error` set and `facts: null`. Invalid `options` throw
`TypeError` before any check runs: a fingerprint that is not 64 hex
characters, a `trustedPublicKeys` entry that does not parse, or a
`tsaRootsPem` certificate that does not parse. `prepareOptions(options)` runs
the same validation on its own.

Timestamp semantics: `invalid` means a chain was evaluated and failed (or the
imprint does not match). When no trust evaluation is possible (`
checkTimestampTrust: false`, or no usable root once `useBuiltInTsaRoots:
false` is set) the check is `imprint_only` and the reason says why.

## `verifyEvidenceZip(zip, options?)`

Takes the archive bytes, returns `{ overall, documents, sealCount,
ledgerSegment, readme, notes }` where each document has `{ path,
computedHash, sealId, verdict, overall, disposition, reason? }`.

## Helpers

| Function                                                                                  | Purpose                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sha256Hex(bytes)`                                                                        | SHA-256 as lowercase hex (WebCrypto).                                                                                                                                                                     |
| `parseProof(input)`                                                                       | Validates schema version 1; throws `ProofFormatError`.                                                                                                                                                    |
| `verifySignature({ digest, signature, publicKey, algorithm })`                            | ECDSA P-256 over the raw digest; DER or P1363; returns `{ ok, encoding, reason? }`.                                                                                                                       |
| `keyFingerprint(pemOrDer)`                                                                | SHA-256 hex of the SPKI DER.                                                                                                                                                                              |
| `verifyTimestampImprint({ token, digest })`                                               | SHA-256 imprint equals the digest; returns `genTime`.                                                                                                                                                     |
| `verifyTimestampTrust({ token, roots })`                                                  | CMS signature + EKU (critical, sole purpose) + validity at `genTime` + chain to `roots`. Does **not** bind the token to a digest: pair it with `verifyTimestampImprint`. No revocation data is consulted. |
| `computeLedgerEntryHash({ seq, documentHash, previousEntryHash, sealedAt })`              | The chain hash.                                                                                                                                                                                           |
| `verifyLedgerEntry(block, documentHash, sealedAt)`                                        | Recompute and compare one entry.                                                                                                                                                                          |
| `verifyLedgerSegment(entries)`                                                            | Walk a segment, check links and sequence.                                                                                                                                                                 |
| `BUILT_IN_TSA_ROOTS` / `builtInTsaRootsPem()`                                             | The shipped roots.                                                                                                                                                                                        |
| `parseDerSignature`, `decodeSignature`, `pemBlocks`, `pemToDer`, `derToPem`, byte helpers | Building blocks.                                                                                                                                                                                          |

Synchronous forms exist where no I/O is involved: `verifySignatureSync`,
`verifyTimestampImprintSync`.
