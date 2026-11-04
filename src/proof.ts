import { z } from 'zod';
import { bytesToUtf8 } from './bytes.js';
import { ProofFormatError } from './errors.js';
import type { LedgerBlock, ProofV1 } from './types.js';

const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/, 'expected 64 hex characters');

const ledgerSchema = z.object({
  seq: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  previousEntryHash: hex64,
  entryHash: hex64,
});

const optionalText = z.string().nullable().optional();

const proofSchema = z.object({
  schemaVersion: z.literal(1),
  sealId: z.string().min(1),
  documentHash: hex64,
  algorithm: z.string().min(1),
  signature: z.string().min(1),
  keyId: optionalText,
  keyVersion: optionalText,
  publicKeyPem: z.string().min(1),
  tsaToken: optionalText,
  tsaUrl: optionalText,
  timestampedAt: optionalText,
  ledger: ledgerSchema.optional(),
  verifyUrl: optionalText,
  sealedAt: z.iso.datetime({ message: 'sealedAt must be an ISO-8601 UTC timestamp' }),
});

function toObject(input: ProofV1 | string | Uint8Array): unknown {
  let text: string;
  if (input instanceof Uint8Array) {
    try {
      text = bytesToUtf8(input);
    } catch {
      throw new ProofFormatError('proof is not valid UTF-8 text');
    }
  } else if (typeof input === 'string') {
    text = input;
  } else {
    return input;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ProofFormatError('proof is not valid JSON');
  }
}

/**
 * Validates the proof sidecar shape (schema version 1) and normalises the
 * optional display fields to `null`. Throws {@link ProofFormatError}.
 */
export function parseProof(input: ProofV1 | string | Uint8Array): ProofV1 {
  const raw = toObject(input);
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ProofFormatError('proof must be a JSON object');
  }
  const version: unknown = (raw as { schemaVersion?: unknown }).schemaVersion;
  if (version !== 1) {
    throw new ProofFormatError(
      `unsupported proof schemaVersion ${JSON.stringify(version)}; this verifier supports schemaVersion 1`,
    );
  }
  const result = proofSchema.safeParse(raw);
  if (!result.success) {
    const first = result.error.issues[0];
    const where = first?.path.join('.') ?? '';
    const what = first?.message ?? 'invalid';
    throw new ProofFormatError(`proof field "${where}": ${what}`);
  }
  const p = result.data;
  const ledger: LedgerBlock | undefined = p.ledger
    ? {
        seq: p.ledger.seq,
        previousEntryHash: p.ledger.previousEntryHash.toLowerCase(),
        entryHash: p.ledger.entryHash.toLowerCase(),
      }
    : undefined;
  const proof: ProofV1 = {
    schemaVersion: 1,
    sealId: p.sealId,
    documentHash: p.documentHash.toLowerCase(),
    algorithm: p.algorithm,
    signature: p.signature,
    keyId: p.keyId ?? null,
    keyVersion: p.keyVersion ?? null,
    publicKeyPem: p.publicKeyPem,
    tsaToken: p.tsaToken ?? null,
    tsaUrl: p.tsaUrl ?? null,
    timestampedAt: p.timestampedAt ?? null,
    verifyUrl: p.verifyUrl ?? null,
    sealedAt: p.sealedAt,
  };
  if (ledger) proof.ledger = ledger;
  return proof;
}
