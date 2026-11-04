import { constantTimeEqualHex } from './bytes.js';
import { sha256Hex } from './hash.js';
import { keyFingerprint } from './key.js';
import { verifyLedgerEntry } from './ledger.js';
import { parseProof } from './proof.js';
import { messageOf, verifySignature } from './signature.js';
import { verifyTimestampImprint, verifyTimestampTrust } from './timestamp.js';
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

interface KeyEvaluation {
  check: KeyCheck;
  reason: string;
}

async function evaluateKey(
  fingerprint: string | null,
  options: VerifyOptions,
  notes: string[],
): Promise<KeyEvaluation> {
  const suppliedFingerprints = options.trustedKeyFingerprints;
  const suppliedKeys = options.trustedPublicKeys;
  if (suppliedFingerprints === undefined && suppliedKeys === undefined) {
    return {
      check: 'unpinned',
      reason:
        'no trust list supplied: the signature math was checked, the key itself was not (compare the fingerprint out of band)',
    };
  }
  const trusted = new Set<string>();
  for (const fp of suppliedFingerprints ?? [])
    trusted.add(fp.replace(/[^0-9a-fA-F]/g, '').toLowerCase());
  for (const pem of suppliedKeys ?? []) {
    try {
      trusted.add(await keyFingerprint(pem));
    } catch (error) {
      notes.push(`a trusted public key could not be parsed and was ignored: ${messageOf(error)}`);
    }
  }
  if (trusted.size === 0) {
    return {
      check: 'rejected',
      reason: 'a trust list was supplied but it contains no usable fingerprint',
    };
  }
  if (fingerprint && trusted.has(fingerprint)) {
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
  options: VerifyOptions,
): Promise<TimestampEvaluation> {
  if (!proof.tsaToken) {
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
  const roots: string[] = [];
  if (options.useBuiltInTsaRoots !== false) roots.push(...builtInTsaRootsPem());
  roots.push(...(options.tsaRootsPem ?? []));
  if (options.checkTimestampTrust === false || roots.length === 0) {
    return {
      check: 'imprint_only',
      reason: `the token covers this digest at ${genTime ?? '?'}; the signer chain was not evaluated`,
      genTime,
    };
  }
  const trust = await verifyTimestampTrust({ token: proof.tsaToken, roots });
  if (!trust.ok) {
    return { check: 'invalid', reason: trust.reason ?? 'trust evaluation failed', genTime };
  }
  return {
    check: 'trusted',
    reason: `the token covers this digest at ${genTime ?? '?'} and its signer chains to a trusted root`,
    genTime,
  };
}

function decide(checks: Checks): Overall {
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
 * a verdict. Never throws for bad input: an unreadable proof yields
 * `overall: "incomplete"` with `error` set.
 */
export async function verifySealedPdf(input: VerifyInput): Promise<Verdict> {
  let proof: ProofV1;
  try {
    proof = parseProof(input.proof);
  } catch (error) {
    return incomplete(error);
  }
  const options = input.options ?? {};
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
  const key = await evaluateKey(fingerprint, options, notes);

  // 4. timestamp
  const timestamp = await evaluateTimestamp(proof, digestHex, options);

  // 5. ledger
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
    overall: decide(checks),
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
