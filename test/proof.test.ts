import { describe, expect, it } from 'vitest';
import { ProofFormatError, parseProof } from '../src/index.js';
import type { ProofV1 } from '../src/index.js';
import { readBytes, readProof, readText } from './helpers.js';

describe('parseProof', () => {
  it('accepts text, bytes and objects', () => {
    const fromText = parseProof(readText('sample.proof.json'));
    const fromBytes = parseProof(readBytes('sample.proof.json'));
    const fromObject = parseProof(readProof('sample.proof.json'));
    expect(fromText).toEqual(fromBytes);
    expect(fromText).toEqual(fromObject);
    expect(fromText.sealId).toBe('SPV-TEST-000001');
    expect(fromText.ledger?.seq).toBe(1);
  });
  it('normalises optional display fields to null and hashes to lowercase', () => {
    const raw = readProof('sample.no-ledger.proof.json');
    const loose = {
      ...raw,
      documentHash: raw.documentHash.toUpperCase(),
      keyId: undefined,
      keyVersion: undefined,
      verifyUrl: undefined,
      tsaUrl: undefined,
      timestampedAt: undefined,
      tsaToken: undefined,
      extra: 'ignored',
    };
    const p = parseProof(loose as unknown as string);
    expect(p.documentHash).toBe(raw.documentHash.toLowerCase());
    expect(p.keyId).toBeNull();
    expect(p.keyVersion).toBeNull();
    expect(p.verifyUrl).toBeNull();
    expect(p.tsaUrl).toBeNull();
    expect(p.tsaToken).toBeNull();
    expect(p.timestampedAt).toBeNull();
    expect(p.ledger).toBeUndefined();
    expect('extra' in p).toBe(false);
  });
  it('rejects unsupported schema versions with a clear message', () => {
    const raw = readProof('sample.proof.json');
    expect(() => parseProof({ ...raw, schemaVersion: 2 } as unknown as string)).toThrow(
      'unsupported proof schemaVersion 2',
    );
    const noVersion: Partial<ProofV1> = { ...raw };
    delete noVersion.schemaVersion;
    expect(() => parseProof(noVersion as unknown as string)).toThrow('schemaVersion undefined');
  });
  it('rejects non-objects and malformed input', () => {
    expect(() => parseProof('not json')).toThrow(ProofFormatError);
    expect(() => parseProof('not json')).toThrow('not valid JSON');
    expect(() => parseProof('[1,2]')).toThrow('must be a JSON object');
    expect(() => parseProof('null')).toThrow('must be a JSON object');
    expect(() => parseProof(new Uint8Array([0xff, 0xfe]))).toThrow('not valid UTF-8');
  });
  it('reports the failing field', () => {
    const raw = readProof('sample.proof.json');
    expect(() => parseProof({ ...raw, documentHash: 'abc' })).toThrow('proof field "documentHash"');
    expect(() => parseProof({ ...raw, sealedAt: '2026-11-04 12:00' })).toThrow(
      'proof field "sealedAt"',
    );
    expect(() =>
      parseProof({ ...raw, ledger: { seq: -1, previousEntryHash: 'x', entryHash: 'y' } }),
    ).toThrow('proof field "ledger.');
  });
});
