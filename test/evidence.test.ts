import { unzipSync, zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';
import { verifyEvidenceZip } from '../src/index.js';
import { MAX_ENTRY_BYTES, classifyEntry } from '../src/evidence.js';
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

/**
 * A minimal ZIP writer (stored entries) whose central directory can lie about
 * an entry's uncompressed size: the only way to exercise the inflation cap
 * without actually allocating hundreds of megabytes.
 */
function storedZip(
  entries: { name: string; data: Uint8Array; claimedSize?: number }[],
): Uint8Array {
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const u16 = (n: number): number[] => [n & 0xff, (n >> 8) & 0xff];
  const u32 = (n: number): number[] => [
    n & 0xff,
    (n >> 8) & 0xff,
    (n >> 16) & 0xff,
    (n >>> 24) & 0xff,
  ];
  for (const { name, data, claimedSize } of entries) {
    const nameBytes = new TextEncoder().encode(name);
    const size = claimedSize ?? data.length;
    const local = new Uint8Array([
      0x50,
      0x4b,
      0x03,
      0x04,
      ...u16(20),
      ...u16(0),
      ...u16(0),
      ...u16(0),
      ...u16(0),
      ...u32(0),
      ...u32(data.length),
      ...u32(size),
      ...u16(nameBytes.length),
      ...u16(0),
      ...nameBytes,
    ]);
    chunks.push(local, data);
    central.push(
      new Uint8Array([
        0x50,
        0x4b,
        0x01,
        0x02,
        ...u16(20),
        ...u16(20),
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u32(0),
        ...u32(data.length),
        ...u32(size),
        ...u16(nameBytes.length),
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u16(0),
        ...u32(0),
        ...u32(offset),
        ...nameBytes,
      ]),
    );
    offset += local.length + data.length;
  }
  const centralSize = central.reduce((n, c) => n + c.length, 0);
  const end = new Uint8Array([
    0x50,
    0x4b,
    0x05,
    0x06,
    ...u16(0),
    ...u16(0),
    ...u16(entries.length),
    ...u16(entries.length),
    ...u32(centralSize),
    ...u32(offset),
    ...u16(0),
  ]);
  const all = [...chunks, ...central, end];
  const out = new Uint8Array(all.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of all) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

describe('verifyEvidenceZip — fail-closed edges', () => {
  it('classifies entries: only the paths it reads are inflated, each within the cap', () => {
    expect(classifyEntry('documents/a.pdf', 10)).toBe('inflate');
    expect(classifyEntry('bundle/seals/x.json', 10)).toBe('inflate');
    expect(classifyEntry('SEALS/X.JSON', 10)).toBe('inflate');
    expect(classifyEntry('ledger/segment.json', 10)).toBe('inflate');
    expect(classifyEntry('README.txt', 10)).toBe('inflate');
    expect(classifyEntry('audit/booking-audit-log.json', 10)).toBe('skip');
    expect(classifyEntry('__MACOSX/._x', 10)).toBe('skip');
    expect(classifyEntry('documents/a.pdf', MAX_ENTRY_BYTES)).toBe('inflate');
    expect(classifyEntry('documents/a.pdf', MAX_ENTRY_BYTES + 1)).toBe('too-large');
  });
  it('does not inflate an entry that claims to be larger than the cap', async () => {
    const zip = storedZip([
      { name: 'documents/bomb.pdf', data: enc('%PDF-tiny'), claimedSize: MAX_ENTRY_BYTES + 1 },
      { name: 'README.txt', data: enc('hello') },
    ]);
    const res = await verifyEvidenceZip(zip);
    expect(res.overall).toBe('incomplete');
    expect(res.documents).toHaveLength(0);
    expect(res.readme).toBe('hello');
    expect(res.notes.some((n) => n.includes('bomb.pdf') && n.includes('not inflated'))).toBe(true);
  });
  it('reads seal files whatever their case', async () => {
    const res = await verifyEvidenceZip(
      rezip({ [SEAL1]: null, 'seals/SPV-TEST-000001.JSON': base[SEAL1] ?? new Uint8Array() }),
    );
    expect(res.sealCount).toBe(2);
    expect(res.documents.find((d) => d.path.endsWith('sample.pdf'))?.overall).toBe('genuine');
  });
  it('reports a document as incomplete, not a crash, when its key file is not UTF-8', async () => {
    const seal = JSON.parse(new TextDecoder().decode(base[SEAL1])) as Record<string, unknown>;
    delete seal.publicKeyPem;
    const res = await verifyEvidenceZip(
      rezip({
        [SEAL1]: enc(JSON.stringify(seal)),
        'seals/SPV-TEST-000001.public-key.pem': new Uint8Array([0xff, 0xfe, 0xc0]),
      }),
    );
    const doc = res.documents.find((d) => d.path.endsWith('sample.pdf'));
    expect(doc?.overall).toBe('incomplete');
    expect(doc?.verdict).toBeNull();
    expect(doc?.reason).toContain('could not be assembled');
    expect(res.overall).toBe('incomplete');
  });
  it('notes a seal that matches no document', async () => {
    const res = await verifyEvidenceZip(rezip({ 'documents/second.pdf': null }));
    expect(res.documents).toHaveLength(1);
    expect(res.overall).toBe('genuine');
    expect(res.notes.some((n) => n.includes(SEAL2) && n.includes('matches no document'))).toBe(
      true,
    );
  });
  it('throws on invalid options before touching any document', async () => {
    await expect(verifyEvidenceZip(evidence, { trustedKeyFingerprints: ['nope'] })).rejects.toThrow(
      TypeError,
    );
  });
});
