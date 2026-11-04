import { constantTimeEqualHex, isHex } from './bytes.js';
import { sha256Hex } from './hash.js';
import { keyFingerprint } from './key.js';
import { verifyLedgerEntry } from './ledger.js';
import { parseProof } from './proof.js';
import { messageOf, verifySignature } from './signature.js';
import {
  parseRootCertificates,
  verifyTimestampImprint,
  verifyTimestampTrust,
} from './timestamp.js';
import { builtInTsaRootsPem } from './tsa-roots.js';
import type {
  Checks,
  Facts,
  HashCheck,
  KeyCheck,
  LedgerCheck,
  Overall,
  ProofV1,
  TimestampCheck,
  Verdict,
  VerifyInput,
  VerifyOptions,
} from './types.js';

export const PROOF_ONLY_NOTE =
  'PDF bytes were NOT checked: no PDF was supplied, so the signature, timestamp and ledger were evaluated against the digest recorded in the proof only.';

function incomplete(error: unknown): Verdict {
  const message = messageOf(error);
  return {
    overall: 'incomplete',
    mode: 'proof-only',
    checks: {
      hash: 'not_checked',
      signature: 'invalid',
      key: 'rejected',
      timestamp: 'none',
      ledger: 'not_checked',
    },
    facts: null,
    reasons: {
      hash: 'not checked: the proof could not be read',
      signature: 'not verifiable: the proof could not be read',
      key: 'not verifiable: the proof could not be read',
      timestamp: 'not verifiable: the proof could not be read',
      ledger: 'not verifiable: the proof could not be read',
    },
    notes: [],
    error: message,
  };
}

/**
 * Caller configuration, validated once up front. Document inputs never throw
 * (they yield a verdict); options do, because a mistyped fingerprint or an
 * unreadable root file is a mistake by the operator, not evidence about the
 * document, and must not be reported as "altered" or silently ignored.
 */
export interface PreparedOptions {
  /** Trusted key fingerprints, lowercase hex; null when no trust list was supplied. */
  trustedFingerprints: Set<string> | null;
  /** PEM text of every trust anchor to use (built-in and supplied). */
  tsaRootsPem: string[];
  /** Number of usable certificates among those roots. */
  tsaRootCount: number;
  checkTimestampTrust: boolean;
}

/**
 * Validates {@link VerifyOptions}. Throws `TypeError` on a malformed
 * fingerprint, an unparsable trusted public key or an unparsable root
 * certificate. Exported so callers that run many verifications (evidence
 * archives) can fail fast before touching any document.
 */
export async function prepareOptions(options: VerifyOptions = {}): Promise<PreparedOptions> {
  let trustedFingerprints: Set<string> | null = null;
  if (options.trustedKeyFingerprints !== undefined || options.trustedPublicKeys !== undefined) {
    trustedFingerprints = new Set<string>();
    const fingerprints = options.trustedKeyFingerprints ?? [];
    for (const [index, raw] of fingerprints.entries()) {
      // Allow the colon / space separated form fingerprint tools print.
      const compact = raw.replace(/[\s:]/g, '').toLowerCase();
      if (!isHex(compact, 32)) {
        throw new TypeError(
          `trustedKeyFingerprints[${index}] is not a SHA-256 fingerprint (64 hex characters)`,
        );
      }
      trustedFingerprints.add(compact);
    }
    const keys = options.trustedPublicKeys ?? [];
    for (const [index, pem] of keys.entries()) {
      try {
        trustedFingerprints.add(await keyFingerprint(pem));
      } catch (error) {
        throw new TypeError(`trustedPublicKeys[${index}] does not parse: ${messageOf(error)}`, {
          cause: error,
        });
      }
    }
  }

  const tsaRootsPem: string[] = [];
  if (options.useBuiltInTsaRoots !== false) tsaRootsPem.push(...builtInTsaRootsPem());
  const supplied = options.tsaRootsPem ?? [];
  let suppliedCount: number;
  try {
    suppliedCount = parseRootCertificates(supplied).length;
  } catch (error) {
    throw new TypeError(`tsaRootsPem: ${messageOf(error)}`, { cause: error });
  }
  tsaRootsPem.push(...supplied);
  const builtInCount = options.useBuiltInTsaRoots !== false ? builtInTsaRootsPem().length : 0;

  return {
    trustedFingerprints,
    tsaRootsPem,
    tsaRootCount: builtInCount + suppliedCount,
    checkTimestampTrust: options.checkTimestampTrust !== false,
  };
}

interface KeyEvaluation {
  check: KeyCheck;
  reason: string;
}

function evaluateKey(fingerprint: string | null, prepared: PreparedOptions): KeyEvaluation {
  const trusted = prepared.trustedFingerprints;
  if (trusted === null) {
    return {
      check: 'unpinned',
      reason:
        'no trust list supplied: the signature math was checked, the key itself was not (compare the fingerprint out of band)',
    };
  }
  // An empty list is honoured as written: trusting nobody rejects every key.
  if (trusted.size === 0) {
    return {
      check: 'rejected',
      reason: 'a trust list was supplied but it is empty, so no key can be trusted',
    };
  }
  if (fingerprint !== null && trusted.has(fingerprint)) {
    return { check: 'pinned', reason: 'the signing key matches a fingerprint in the trust list' };
  }
  return {
    check: 'rejected',
    reason:
      'the signing key is not in the trust list (a valid signature from an unknown key proves nothing)',
  };
}

interface TimestampEvaluation {
  check: TimestampCheck;
  reason: string;
  genTime: string | null;
}

async function evaluateTimestamp(
  proof: ProofV1,
  digestHex: string,
  prepared: PreparedOptions,
): Promise<TimestampEvaluation> {
  if (proof.tsaToken === null) {
    return {
      check: 'none',
      reason: 'the proof carries no RFC 3161 timestamp token',
      genTime: null,
    };
  }
  const imprint = await verifyTimestampImprint({ token: proof.tsaToken, digest: digestHex });
  const genTime = imprint.genTime ? imprint.genTime.toISOString() : null;
  if (!imprint.ok) {
    return { check: 'invalid', reason: imprint.reason ?? 'imprint check failed', genTime };
  }
  // `invalid` is reserved for a chain that was evaluated and failed. With no
  // usable root the chain cannot be evaluated at all; say so instead.
  if (!prepared.checkTimestampTrust) {
    return {
      check: 'imprint_only',
      reason: `the token covers this digest at ${genTime ?? '?'}; the signer chain was not evaluated (trust check disabled)`,
      genTime,
    };
  }
  if (prepared.tsaRootCount === 0) {
    return {
      check: 'imprint_only',
      reason: `the token covers this digest at ${genTime ?? '?'}; the signer chain was not evaluated (no trusted roots configured)`,
      genTime,
    };
  }
  const trust = await verifyTimestampTrust({ token: proof.tsaToken, roots: prepared.tsaRootsPem });
  if (!trust.ok) {
    return { check: 'invalid', reason: trust.reason ?? 'trust evaluation failed', genTime };
  }
  return {
    check: 'trusted',
    reason: `the token covers this digest at ${genTime ?? '?'} and its signer chains to a trusted root`,
    genTime,
  };
}

/**
 * The verdict rule, identical to the README: `genuine` needs hash ≠ mismatch,
 * signature valid, key ≠ rejected, timestamp ≠ invalid and ledger ≠
 * inconsistent; anything else is `altered`. (`incomplete` is produced only
 * when the proof itself cannot be read.) Exported for the table-driven test.
 */
export function decideOverall(checks: Checks): Overall {
  const ok =
    checks.hash !== 'mismatch' &&
    checks.signature === 'valid' &&
    checks.key !== 'rejected' &&
    checks.timestamp !== 'invalid' &&
    checks.ledger !== 'inconsistent';
  return ok ? 'genuine' : 'altered';
}

/**
 * Runs the five checks (hash, signature, key, timestamp, ledger) and returns
 * a verdict. Never throws for document input: an unreadable proof yields
 * `overall: "incomplete"` with `error` set. Invalid `options` throw
 * `TypeError` (see {@link prepareOptions}).
 */
export async function verifySealedPdf(input: VerifyInput): Promise<Verdict> {
  const prepared = await prepareOptions(input.options);
  let proof: ProofV1;
  try {
    proof = parseProof(input.proof);
  } catch (error) {
    return incomplete(error);
  }
  const notes: string[] = [];

  // 1. hash
  let hash: HashCheck;
  let hashReason: string;
  let computedHash: string | null = null;
  let digestHex: string;
  if (input.pdf) {
    computedHash = await sha256Hex(input.pdf);
    digestHex = computedHash;
    if (constantTimeEqualHex(computedHash, proof.documentHash)) {
      hash = 'match';
      hashReason = 'SHA-256 of the PDF equals the digest recorded in the proof';
    } else {
      hash = 'mismatch';
      hashReason =
        'SHA-256 of the PDF differs from the digest recorded in the proof: the bytes changed since sealing';
    }
  } else {
    hash = 'not_checked';
    hashReason = 'no PDF supplied; the digest recorded in the proof was used as-is';
    digestHex = proof.documentHash;
    notes.push(PROOF_ONLY_NOTE);
  }

  // 2. signature
  const signature = await verifySignature({
    digest: digestHex,
    signature: proof.signature,
    publicKey: proof.publicKeyPem,
    algorithm: proof.algorithm,
  });
  const signatureReason = signature.ok
    ? `ECDSA P-256 over the digest verifies with the proof's public key (${signature.encoding ?? '?'} encoding)`
    : (signature.reason ?? 'signature check failed');

  // 3. key
  const fingerprint = await keyFingerprint(proof.publicKeyPem).catch(() => null);
  const key = evaluateKey(fingerprint, prepared);

  // 4. timestamp
  const timestamp = await evaluateTimestamp(proof, digestHex, prepared);

  // 5. ledger
  // Recomputed from the digest RECORDED in the proof, not the one computed
  // from the PDF: the entry proves that this seal exists in the issuer's chain
  // as written. Whether the PDF matches that digest is the hash check's job,
  // so a tampered PDF shows `hash: mismatch` next to `ledger: consistent`,
  // which is the truthful reading (the seal is real, the bytes are not the
  // sealed bytes).
  let ledger: LedgerCheck;
  let ledgerReason: string;
  if (!proof.ledger) {
    ledger = 'not_checked';
    ledgerReason = 'the proof carries no ledger block';
  } else {
    const entry = await verifyLedgerEntry(proof.ledger, proof.documentHash, proof.sealedAt);
    if (entry.ok) {
      ledger = 'consistent';
      ledgerReason = `ledger entry #${proof.ledger.seq} recomputes from the proof and matches`;
    } else {
      ledger = 'inconsistent';
      ledgerReason = entry.reason ?? 'ledger entry does not recompute';
    }
  }

  const checks: Checks = {
    hash,
    signature: signature.ok ? 'valid' : 'invalid',
    key: key.check,
    timestamp: timestamp.check,
    ledger,
  };
  const facts: Facts = {
    sealId: proof.sealId,
    documentHash: proof.documentHash,
    computedHash,
    fingerprint,
    sealedAt: proof.sealedAt,
    timestampTime: timestamp.genTime,
    tsaUrl: proof.tsaUrl,
    verifyUrl: proof.verifyUrl,
    algorithm: proof.algorithm,
    keyId: proof.keyId,
    keyVersion: proof.keyVersion,
  };
  return {
    overall: decideOverall(checks),
    mode: input.pdf ? 'pdf' : 'proof-only',
    checks,
    facts,
    reasons: {
      hash: hashReason,
      signature: signatureReason,
      key: key.reason,
      timestamp: timestamp.reason,
      ledger: ledgerReason,
    },
    notes,
  };
}
