import { constantTimeEqualHex, isHex, utf8ToBytes } from './bytes.js';
import { sha256Hex } from './hash.js';
import type { LedgerBlock, LedgerEntry } from './types.js';

export const GENESIS_PREVIOUS_HASH = '0'.repeat(64);

export interface LedgerEntryInput {
  seq: number;
  documentHash: string;
  previousEntryHash: string;
  /** Exactly the ISO-8601 string carried by the proof. */
  sealedAt: string;
}

/**
 * `entryHash = sha256_hex("<seq>\n<documentHash>\n<previousEntryHash>\n<sealedAt>")`,
 * UTF-8, LF separators, seq as a decimal integer, hashes lowercase hex.
 */
export async function computeLedgerEntryHash(entry: LedgerEntryInput): Promise<string> {
  // Number.isSafeInteger: above 2^53 String(seq) would print exponent form
  // ("1e+21"), which is not the decimal integer the chain is defined over.
  if (!Number.isSafeInteger(entry.seq) || entry.seq < 0)
    throw new Error('seq must be a non-negative safe integer');
  if (!isHex(entry.documentHash, 32)) throw new Error('documentHash must be 64 hex characters');
  if (!isHex(entry.previousEntryHash, 32))
    throw new Error('previousEntryHash must be 64 hex characters');
  const line = [
    String(entry.seq),
    entry.documentHash.toLowerCase(),
    entry.previousEntryHash.toLowerCase(),
    entry.sealedAt,
  ].join('\n');
  return sha256Hex(utf8ToBytes(line));
}

export interface LedgerEntryResult {
  ok: boolean;
  expectedEntryHash: string | null;
  reason?: string;
}

/**
 * The first entry of a chain links to {@link GENESIS_PREVIOUS_HASH}. Whether
 * an issuer numbers that entry 0 or 1 is not fixed by the format (the fixtures
 * start at 1), so a zero link is accepted at seq 0 and 1 and rejected from
 * seq 2 on, where it can only mean a forged "fresh start".
 */
export function claimsGenesis(seq: number, previousEntryHash: string): boolean {
  return previousEntryHash.toLowerCase() === GENESIS_PREVIOUS_HASH && seq <= 1;
}

/** Recomputes a proof's ledger block from the proof's own fields and compares. */
export async function verifyLedgerEntry(
  block: LedgerBlock,
  documentHash: string,
  sealedAt: string,
): Promise<LedgerEntryResult> {
  const previous = block.previousEntryHash.toLowerCase();
  if (previous === GENESIS_PREVIOUS_HASH && !claimsGenesis(block.seq, previous)) {
    return {
      ok: false,
      expectedEntryHash: null,
      reason: `entry #${block.seq} links to the genesis value; only the first entry may`,
    };
  }
  // The converse: seq 0 can only ever be the first entry, so it must link to
  // the genesis value. (seq 1 may be either: see claimsGenesis.)
  if (block.seq === 0 && previous !== GENESIS_PREVIOUS_HASH) {
    return {
      ok: false,
      expectedEntryHash: null,
      reason: 'entry #0 is the genesis entry and must link to 64 zeros',
    };
  }
  let expected: string;
  try {
    expected = await computeLedgerEntryHash({
      seq: block.seq,
      documentHash,
      previousEntryHash: block.previousEntryHash,
      sealedAt,
    });
  } catch (error) {
    return {
      ok: false,
      expectedEntryHash: null,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
  if (!constantTimeEqualHex(expected, block.entryHash)) {
    return {
      ok: false,
      expectedEntryHash: expected,
      reason: `entry #${block.seq} hash does not match its recomputation`,
    };
  }
  return { ok: true, expectedEntryHash: expected };
}

export interface LedgerSegmentResult {
  ok: boolean;
  /** Number of entries checked. */
  count: number;
  /** First and last seq covered, or null when the segment is empty. */
  from: number | null;
  to: number | null;
  reason?: string;
}

/**
 * Checks an evidence ZIP `ledger/segment.json`: every entry's hash recomputes,
 * seq increases by one, and each `previousEntryHash` equals the prior `entryHash`.
 * A segment may start anywhere in the chain; only its first entry's link is
 * taken on trust (the issuer's online check covers the rest of the chain).
 */
export async function verifyLedgerSegment(entries: LedgerEntry[]): Promise<LedgerSegmentResult> {
  if (entries.length === 0)
    return { ok: false, count: 0, from: null, to: null, reason: 'segment is empty' };
  const first = entries[0];
  const last = entries[entries.length - 1];
  const range = { from: first?.seq ?? null, to: last?.seq ?? null };
  let previous: LedgerEntry | undefined;
  for (const entry of entries) {
    const own = await verifyLedgerEntry(entry, entry.documentHash, entry.sealedAt);
    if (!own.ok) {
      const failed: LedgerSegmentResult = { ok: false, count: entries.length, ...range };
      if (own.reason !== undefined) failed.reason = own.reason;
      return failed;
    }
    if (previous) {
      if (entry.seq !== previous.seq + 1) {
        return {
          ok: false,
          count: entries.length,
          ...range,
          reason: `seq jumps from ${previous.seq} to ${entry.seq}`,
        };
      }
      if (!constantTimeEqualHex(entry.previousEntryHash, previous.entryHash)) {
        return {
          ok: false,
          count: entries.length,
          ...range,
          reason: `entry #${entry.seq} does not link to entry #${previous.seq}`,
        };
      }
    }
    // The genesis rules (a zero link only at seq 0 or 1, seq 0 only with a
    // zero link) are enforced by verifyLedgerEntry above for every entry.
    previous = entry;
  }
  return { ok: true, count: entries.length, ...range };
}
