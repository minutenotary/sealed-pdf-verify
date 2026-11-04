import { describe, expect, it } from 'vitest';
import {
  GENESIS_PREVIOUS_HASH,
  computeLedgerEntryHash,
  verifyLedgerEntry,
  verifyLedgerSegment,
} from '../src/index.js';
import type { LedgerEntry } from '../src/index.js';
import { claimsGenesis } from '../src/ledger.js';
import { readJson } from './helpers.js';

const segment = readJson('ledger-segment.json') as LedgerEntry[];
const [entry1, entry2] = segment as [LedgerEntry, LedgerEntry];

describe('computeLedgerEntryHash', () => {
  it('matches the fixture chain (genesis and non-genesis)', async () => {
    expect(entry1.previousEntryHash).toBe(GENESIS_PREVIOUS_HASH);
    expect(await computeLedgerEntryHash(entry1)).toBe(entry1.entryHash);
    expect(await computeLedgerEntryHash(entry2)).toBe(entry2.entryHash);
    expect(
      await computeLedgerEntryHash({ ...entry2, documentHash: entry2.documentHash.toUpperCase() }),
    ).toBe(entry2.entryHash);
  });
  it('validates its inputs', async () => {
    await expect(computeLedgerEntryHash({ ...entry1, seq: 1.5 })).rejects.toThrow('seq');
    await expect(computeLedgerEntryHash({ ...entry1, documentHash: 'nope' })).rejects.toThrow(
      'documentHash',
    );
    await expect(computeLedgerEntryHash({ ...entry1, previousEntryHash: 'nope' })).rejects.toThrow(
      'previousEntryHash',
    );
  });
});

describe('verifyLedgerEntry', () => {
  it('recomputes and compares', async () => {
    expect(await verifyLedgerEntry(entry1, entry1.documentHash, entry1.sealedAt)).toEqual({
      ok: true,
      expectedEntryHash: entry1.entryHash,
    });
    const wrongTime = await verifyLedgerEntry(
      entry1,
      entry1.documentHash,
      '2026-11-04T12:00:01.000Z',
    );
    expect(wrongTime.ok).toBe(false);
    expect(wrongTime.reason).toContain('entry #1');
    const broken = await verifyLedgerEntry(
      { ...entry1, previousEntryHash: 'zz' },
      entry1.documentHash,
      entry1.sealedAt,
    );
    expect(broken).toEqual({
      ok: false,
      expectedEntryHash: null,
      reason: 'previousEntryHash must be 64 hex characters',
    });
  });
});

describe('verifyLedgerSegment', () => {
  it('accepts the fixture segment', async () => {
    expect(await verifyLedgerSegment(segment)).toEqual({ ok: true, count: 2, from: 1, to: 2 });
  });
  it('rejects empty, jumping, unlinked and corrupted segments', async () => {
    expect((await verifyLedgerSegment([])).reason).toBe('segment is empty');
    const jump = await verifyLedgerSegment([
      entry1,
      { ...entry2, seq: 3, entryHash: await computeLedgerEntryHash({ ...entry2, seq: 3 }) },
    ]);
    expect(jump.reason).toBe('seq jumps from 1 to 3');
    const unlinked = { ...entry2, previousEntryHash: 'a'.repeat(64) };
    unlinked.entryHash = await computeLedgerEntryHash(unlinked);
    expect((await verifyLedgerSegment([entry1, unlinked])).reason).toBe(
      'entry #2 does not link to entry #1',
    );
    const corrupted = await verifyLedgerSegment([entry1, { ...entry2, entryHash: 'b'.repeat(64) }]);
    expect(corrupted.ok).toBe(false);
    expect(corrupted.reason).toContain('entry #2');
  });
  it('requires a seq-0 genesis to link to zeros', async () => {
    const genesis0 = { ...entry1, seq: 0, previousEntryHash: 'c'.repeat(64) };
    genesis0.entryHash = await computeLedgerEntryHash(genesis0);
    expect((await verifyLedgerSegment([genesis0])).reason).toBe(
      'genesis entry must link to 64 zeros',
    );
    const proper = { ...entry1, seq: 0 };
    proper.entryHash = await computeLedgerEntryHash(proper);
    expect((await verifyLedgerSegment([proper])).ok).toBe(true);
  });
});

describe('genesis rule', () => {
  it('accepts a zero link at seq 0 and 1 only', () => {
    expect(claimsGenesis(0, GENESIS_PREVIOUS_HASH)).toBe(true);
    expect(claimsGenesis(1, GENESIS_PREVIOUS_HASH.toUpperCase())).toBe(true);
    expect(claimsGenesis(2, GENESIS_PREVIOUS_HASH)).toBe(false);
    expect(claimsGenesis(1, 'a'.repeat(64))).toBe(false);
  });
  it('rejects a later entry that claims to be a genesis entry', async () => {
    const forged = { seq: 7, previousEntryHash: GENESIS_PREVIOUS_HASH, entryHash: '' };
    forged.entryHash = await computeLedgerEntryHash({
      seq: 7,
      documentHash: entry1.documentHash,
      previousEntryHash: GENESIS_PREVIOUS_HASH,
      sealedAt: entry1.sealedAt,
    });
    const single = await verifyLedgerEntry(forged, entry1.documentHash, entry1.sealedAt);
    expect(single.ok).toBe(false);
    expect(single.reason).toContain('genesis');
    const segment = await verifyLedgerSegment([{ ...entry1, ...forged }]);
    expect(segment.ok).toBe(false);
    expect(segment.reason).toContain('genesis');
  });
  it('refuses a seq that would not print as a decimal integer', async () => {
    await expect(computeLedgerEntryHash({ ...entry1, seq: 1e21 })).rejects.toThrow('safe integer');
  });
});
