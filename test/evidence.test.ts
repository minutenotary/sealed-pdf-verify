import { unzipSync, zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';
import { verifyEvidenceZip } from '../src/index.js';
import { readBytes, readText } from './helpers.js';

const evidence = readBytes('evidence.zip');
const base = unzipSync(evidence);
const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

function rezip(overrides: Record<string, Uint8Array | null>, prefix = ''): Uint8Array {
  const files: Record<string, Uint8Array> = {};
  for (const [path, data] of Object.entries(base)) files[prefix + path] = data;
  for (const [path, data] of Object.entries(overrides)) {
    if (data === null) Reflect.deleteProperty(files, prefix + path);
    else files[prefix + path] = data;
  }
  return zipSync(files);
}

const SEAL1 = 'seals/SPV-TEST-000001.json';
const SEAL2 = 'seals/SPV-TEST-000002.json';

describe('verifyEvidenceZip', () => {
  it('verifies the fixture archive end to end', async () => {
    const r = await verifyEvidenceZip(evidence);
    expect(r.overall).toBe('genuine');
    expect(r.documents.map((d) => [d.path, d.sealId, d.overall])).toEqual([
      ['documents/sample.pdf', 'SPV-TEST-000001', 'genuine'],
      ['documents/second.pdf', 'SPV-TEST-000002', 'genuine'],
    ]);
    expect(r.documents[0]?.verdict?.checks.timestamp).toBe('trusted');
    expect(r.documents[0]?.verdict?.checks.ledger).toBe('consistent');
    expect(r.documents[1]?.verdict?.checks.ledger).toBe('consistent');
    expect(r.documents[1]?.disposition).toBe('superseded');
    expect(r.sealCount).toBe(2);
    expect(r.ledgerSegment).toEqual({ ok: true, count: 2, from: 1, to: 2 });
    expect(r.readme).toContain('Evidence archive');
    expect(r.notes.some((n) => n.includes('superseded') && n.includes('reissued'))).toBe(true);
  });
  it('tolerates a top-level folder inside the archive', async () => {
    const r = await verifyEvidenceZip(rezip({}, 'bundle-123/'));
    expect(r.overall).toBe('genuine');
    expect(r.documents).toHaveLength(2);
  });
  it('falls back to the .public-key.pem and .tsr files when the seal JSON omits them', async () => {
    const seal = JSON.parse(new TextDecoder().decode(base[SEAL1])) as Record<string, unknown>;
    Reflect.deleteProperty(seal, 'publicKeyPem');
    Reflect.deleteProperty(seal, 'tsaToken');
    const r = await verifyEvidenceZip(rezip({ [SEAL1]: enc(JSON.stringify(seal)) }));
    expect(r.documents[0]?.overall).toBe('genuine');
    expect(r.documents[0]?.verdict?.checks.timestamp).toBe('trusted');
  });
  it('passes verify options through (key pinning)', async () => {
    const r = await verifyEvidenceZip(evidence, { trustedKeyFingerprints: ['00'.repeat(32)] });
    expect(r.overall).toBe('altered');
    expect(r.documents[0]?.verdict?.checks.key).toBe('rejected');
  });
  it('reports incomplete for a PDF without a matching seal', async () => {
    const r = await verifyEvidenceZip(rezip({ 'documents/extra.pdf': readBytes('tampered.pdf') }));
    expect(r.overall).toBe('incomplete');
    const extra = r.documents.find((d) => d.path === 'documents/extra.pdf');
    expect(extra?.overall).toBe('incomplete');
    expect(extra?.sealId).toBeNull();
    expect(extra?.reason).toContain('no seal');
  });
  it('reports altered when any document fails', async () => {
    const r = await verifyEvidenceZip(
      rezip({
        'documents/sample.pdf': readBytes('tampered.pdf'),
        [SEAL2]: null,
        'ledger/segment.json': null,
      }),
    );
    // tampered sample has no matching seal → incomplete; second has no seal → incomplete
    expect(r.overall).toBe('incomplete');
    const wrongKey = enc(readText('sample.wrong-key.proof.json'));
    const r2 = await verifyEvidenceZip(rezip({ [SEAL1]: wrongKey }));
    expect(r2.overall).toBe('altered');
    expect(r2.documents[0]?.verdict?.checks.signature).toBe('invalid');
  });
  it('flags a broken ledger segment even when the documents pass', async () => {
    const entries = JSON.parse(new TextDecoder().decode(base['ledger/segment.json'])) as {
      entryHash: string;
    }[];
    const broken = entries.map((e, i) => (i === 1 ? { ...e, entryHash: 'd'.repeat(64) } : e));
    const r = await verifyEvidenceZip(
      rezip({ 'ledger/segment.json': enc(JSON.stringify(broken)) }),
    );
    expect(r.overall).toBe('altered');
    expect(r.ledgerSegment?.ok).toBe(false);
    // the second document's ledger block now comes from the broken segment
    expect(r.documents[1]?.verdict?.checks.ledger).toBe('inconsistent');
  });
  it('reports malformed and unreadable segment files', async () => {
    const malformed = await verifyEvidenceZip(
      rezip({ 'ledger/segment.json': enc('{"not":"an array"}') }),
    );
    expect(malformed.ledgerSegment?.ok).toBe(false);
    expect(malformed.ledgerSegment?.reason).toContain('malformed');
    const unreadable = await verifyEvidenceZip(rezip({ 'ledger/segment.json': enc('{{{') }));
    expect(unreadable.ledgerSegment?.reason).toContain('unreadable');
    const none = await verifyEvidenceZip(rezip({ 'ledger/segment.json': null }));
    expect(none.ledgerSegment).toBeNull();
    expect(none.documents[0]?.verdict?.checks.ledger).toBe('not_checked');
  });
  it('notes unreadable or non-seal files under seals/', async () => {
    const r = await verifyEvidenceZip(
      rezip({ 'seals/junk.json': enc('{{{'), 'seals/other.json': enc('{"hello":1}') }),
    );
    expect(r.notes.some((n) => n.includes('seals/junk.json') && n.includes('unreadable'))).toBe(
      true,
    );
    expect(
      r.notes.some((n) => n.includes('seals/other.json') && n.includes('not a seal file')),
    ).toBe(true);
    expect(r.overall).toBe('genuine');
  });
  it('notes when several seals match one document', async () => {
    const r = await verifyEvidenceZip(
      rezip({ 'seals/SPV-TEST-000001-copy.json': base[SEAL1] ?? new Uint8Array() }),
    );
    expect(r.notes.some((n) => n.includes('2 seals match'))).toBe(true);
  });
  it('notes a README that is not UTF-8', async () => {
    const r = await verifyEvidenceZip(rezip({ 'README.txt': new Uint8Array([0xff, 0xfe, 0x00]) }));
    expect(r.readme).toBeNull();
    expect(r.notes).toContain('README.txt is not UTF-8 text');
  });
  it('handles empty and non-ZIP input', async () => {
    const empty = await verifyEvidenceZip(zipSync({ 'README.txt': enc('empty') }));
    expect(empty.overall).toBe('incomplete');
    expect(empty.notes).toContain('the archive contains no documents/*.pdf');
    const junk = await verifyEvidenceZip(new Uint8Array([1, 2, 3, 4]));
    expect(junk.overall).toBe('incomplete');
    expect(junk.notes[0]).toContain('not a readable ZIP');
  });
  it('surfaces a seal that fails to parse as a proof', async () => {
    const seal = JSON.parse(new TextDecoder().decode(base[SEAL1])) as Record<string, unknown>;
    seal.sealedAt = 'yesterday';
    const r = await verifyEvidenceZip(rezip({ [SEAL1]: enc(JSON.stringify(seal)) }));
    expect(r.documents[0]?.overall).toBe('incomplete');
    expect(r.documents[0]?.reason).toContain('sealedAt');
  });
});
