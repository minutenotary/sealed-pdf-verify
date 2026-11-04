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
  if (!Number.isInteger(entry.seq) || entry.seq < 0)
    throw new Error('seq must be a non-negative integer');
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

/** Recomputes a proof's ledger block from the proof's own fields and compares. */
export async function verifyLedgerEntry(
  block: LedgerBlock,
  documentHash: string,
  sealedAt: string,
): Promise<LedgerEntryResult> {
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
    if (!own.ok) return { ok: false, count: entries.length, ...range, reason: own.reason };
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
    } else if (entry.seq === 0 && entry.previousEntryHash.toLowerCase() !== GENESIS_PREVIOUS_HASH) {
      return {
        ok: false,
        count: entries.length,
        ...range,
        reason: 'genesis entry must link to 64 zeros',
      };
    }
    previous = entry;
  }
  return { ok: true, count: entries.length, ...range };
}
