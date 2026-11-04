/** Proof sidecar JSON, schema version 1. Unknown extra fields are ignored. */
export interface ProofV1 {
  schemaVersion: 1;
  /** Opaque id; also the verify code printed on the document. */
  sealId: string;
  /** SHA-256 of the exact sealed PDF bytes, 64 hex characters. */
  documentHash: string;
  /** `OCI_ECDSA_P256_SHA256` (current) or `ECDSA_P256_SHA256` (legacy). */
  algorithm: string;
  /** Base64: DER `Ecdsa-Sig-Value` (RFC 3279) or 64-byte IEEE P1363 `r || s`. */
  signature: string;
  keyId: string | null;
  keyVersion: string | null;
  /** PEM SubjectPublicKeyInfo, EC P-256. */
  publicKeyPem: string;
  /** Base64 DER RFC 3161 TimeStampToken (CMS ContentInfo), or null. */
  tsaToken: string | null;
  tsaUrl: string | null;
  timestampedAt: string | null;
  ledger?: LedgerBlock;
  verifyUrl: string | null;
  /** ISO-8601 (`Date#toISOString()` form). Part of the ledger entry hash. */
  sealedAt: string;
}

export interface LedgerBlock {
  seq: number;
  previousEntryHash: string;
  entryHash: string;
}

/** One row of an evidence ZIP `ledger/segment.json`. */
export interface LedgerEntry extends LedgerBlock {
  documentHash: string;
  sealedAt: string;
}

export type HashCheck = 'match' | 'mismatch' | 'not_checked';
export type SignatureCheck = 'valid' | 'invalid';
export type KeyCheck = 'pinned' | 'unpinned' | 'rejected';
export type TimestampCheck = 'trusted' | 'imprint_only' | 'none' | 'invalid';
export type LedgerCheck = 'consistent' | 'inconsistent' | 'not_checked';
export type Overall = 'genuine' | 'altered' | 'incomplete';

export interface Checks {
  hash: HashCheck;
  signature: SignatureCheck;
  key: KeyCheck;
  timestamp: TimestampCheck;
  ledger: LedgerCheck;
}

export interface Facts {
  sealId: string;
  /** The digest recorded in the proof. */
  documentHash: string;
  /** SHA-256 actually computed from the supplied PDF, or null in proof-only mode. */
  computedHash: string | null;
  /** SHA-256 hex of the SPKI DER of the proof's public key, or null if the key did not parse. */
  fingerprint: string | null;
  sealedAt: string;
  /** `genTime` of the RFC 3161 token (ISO-8601) or null. */
  timestampTime: string | null;
  tsaUrl: string | null;
  verifyUrl: string | null;
  algorithm: string;
  keyId: string | null;
  keyVersion: string | null;
}

export interface Verdict {
  overall: Overall;
  /** `pdf` when the PDF bytes were hashed; `proof-only` when only the proof was supplied. */
  mode: 'pdf' | 'proof-only';
  checks: Checks;
  /** Null only when the proof could not be parsed (overall `incomplete`). */
  facts: Facts | null;
  /** One short human sentence per check. */
  reasons: Record<keyof Checks, string>;
  /** Extra lines the caller should show (for example the proof-only warning). */
  notes: string[];
  /** Set when the proof could not be parsed. */
  error?: string;
}

export interface VerifyOptions {
  /** Lowercase/uppercase SHA-256 hex fingerprints of trusted SPKI DER keys. */
  trustedKeyFingerprints?: string[];
  /** Trusted public keys as PEM SubjectPublicKeyInfo. */
  trustedPublicKeys?: string[];
  /** Extra TSA root certificates (PEM, several blocks per string allowed). */
  tsaRootsPem?: string[];
  /** Default true: the DigiCert / FreeTSA roots shipped with the package are trusted. */
  useBuiltInTsaRoots?: boolean;
  /** Default true: evaluate the timestamp signer chain when any root is available. */
  checkTimestampTrust?: boolean;
}

export interface VerifyInput {
  /** The exact PDF bytes. Omit for proof-only mode. */
  pdf?: Uint8Array;
  /** Parsed proof, JSON text, or JSON bytes. */
  proof: ProofV1 | string | Uint8Array;
  options?: VerifyOptions;
}
