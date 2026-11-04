import { describe, expect, it } from 'vitest';
import {
  ACCEPTED_ALGORITHMS,
  base64ToBytes,
  bytesToBase64,
  decodeSignature,
  hexToBytes,
  parseDerSignature,
  verifySignature,
} from '../src/index.js';
import { facts, readProof, readText } from './helpers.js';

const signerPem = readText('signer.pub.pem');
const sample = readProof('sample.proof.json');

describe('verifySignature', () => {
  it('accepts DER, high-S DER and P1363 encodings', async () => {
    const der = await verifySignature({
      digest: facts.sampleHash,
      signature: sample.signature,
      publicKey: signerPem,
      algorithm: sample.algorithm,
    });
    expect(der).toEqual({ ok: true, encoding: 'der' });
    const highS = readProof('sample.high-s.proof.json');
    expect(
      await verifySignature({
        digest: facts.sampleHash,
        signature: highS.signature,
        publicKey: signerPem,
        algorithm: highS.algorithm,
      }),
    ).toEqual({ ok: true, encoding: 'der' });
    const p1363 = readProof('sample.p1363.proof.json');
    expect(base64ToBytes(p1363.signature).length).toBe(64);
    expect(
      await verifySignature({
        digest: hexToBytes(facts.sampleHash),
        signature: base64ToBytes(p1363.signature),
        publicKey: signerPem,
        algorithm: p1363.algorithm,
      }),
    ).toEqual({ ok: true, encoding: 'p1363' });
  });
  it('accepts both algorithm labels and nothing else', async () => {
    expect(ACCEPTED_ALGORITHMS).toEqual(['OCI_ECDSA_P256_SHA256', 'ECDSA_P256_SHA256']);
    const legacy = await verifySignature({
      digest: facts.sampleHash,
      signature: sample.signature,
      publicKey: signerPem,
      algorithm: 'ECDSA_P256_SHA256',
    });
    expect(legacy.ok).toBe(true);
    const bad = await verifySignature({
      digest: facts.sampleHash,
      signature: sample.signature,
      publicKey: signerPem,
      algorithm: 'RSA_PSS_SHA256',
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toContain('algorithm "RSA_PSS_SHA256"');
  });
  it('fails for a different digest or key', async () => {
    const wrongDigest = await verifySignature({
      digest: facts.secondHash,
      signature: sample.signature,
      publicKey: signerPem,
      algorithm: sample.algorithm,
    });
    expect(wrongDigest).toEqual({
      ok: false,
      encoding: 'der',
      reason: 'signature does not verify with this key',
    });
    const wrongKey = await verifySignature({
      digest: facts.sampleHash,
      signature: sample.signature,
      publicKey: readText('other.pub.pem'),
      algorithm: sample.algorithm,
    });
    expect(wrongKey.ok).toBe(false);
  });
  it('rejects bad digests, keys and signature encodings', async () => {
    const base = { signature: sample.signature, publicKey: signerPem, algorithm: sample.algorithm };
    expect((await verifySignature({ ...base, digest: 'abc' })).reason).toContain('64 hex');
    expect((await verifySignature({ ...base, digest: new Uint8Array(31) })).reason).toContain(
      '32 bytes',
    );
    expect(
      (await verifySignature({ ...base, digest: facts.sampleHash, publicKey: 'garbage' })).reason,
    ).toContain('public key:');
    expect(
      (await verifySignature({ ...base, digest: facts.sampleHash, signature: '***' })).reason,
    ).toContain('signature: invalid base64');
    expect(
      (await verifySignature({ ...base, digest: facts.sampleHash, signature: new Uint8Array(10) }))
        .reason,
    ).toContain('neither DER nor 64-byte');
  });
  it('rejects r or s outside [1, n-1]', async () => {
    const zeroR = new Uint8Array(64);
    zeroR[63] = 1;
    const r0 = await verifySignature({
      digest: facts.sampleHash,
      signature: zeroR,
      publicKey: signerPem,
      algorithm: sample.algorithm,
    });
    expect(r0.reason).toContain('outside [1, n-1]');
    const n = hexToBytes('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
    const sN = new Uint8Array(64);
    sN[31] = 1;
    sN.set(n, 32);
    const sTooBig = await verifySignature({
      digest: facts.sampleHash,
      signature: sN,
      publicKey: signerPem,
      algorithm: sample.algorithm,
    });
    expect(sTooBig.reason).toContain('outside [1, n-1]');
  });
  it('rejects a signature that noble refuses (point not on curve)', async () => {
    const der = base64ToBytes(sample.signature);
    const { r, s } = parseDerSignature(der);
    expect(r > 0n && s > 0n).toBe(true);
    // A public key whose x/y are not on the curve: valid SPKI shape, bad point.
    const pem = signerPem;
    const der2 = base64ToBytes(pem.replace(/-----[A-Z ]+-----/g, ''));
    der2[der2.length - 1] = (der2[der2.length - 1] ?? 0) ^ 0xff;
    const res = await verifySignature({
      digest: facts.sampleHash,
      signature: sample.signature,
      publicKey: der2,
      algorithm: sample.algorithm,
    });
    expect(res.ok).toBe(false);
  });
});

describe('parseDerSignature strictness', () => {
  const good = base64ToBytes(sample.signature);
  it('round-trips through decodeSignature', () => {
    const d = decodeSignature(good);
    expect(d.encoding).toBe('der');
    expect(d.r).toBe(parseDerSignature(good).r);
  });
  it('rejects trailing bytes, truncation and length mismatches', () => {
    const trailing = new Uint8Array(good.length + 1);
    trailing.set(good);
    expect(() => parseDerSignature(trailing)).toThrow('length mismatch');
    expect(() => parseDerSignature(good.subarray(0, good.length - 1))).toThrow();
    expect(() => parseDerSignature(new Uint8Array([0x02, 0x01, 0x01]))).toThrow(
      'expected DER SEQUENCE',
    );
    expect(() => parseDerSignature(new Uint8Array([0x30]))).toThrow('truncated');
  });
  it('rejects non-minimal lengths and integers', () => {
    const nonMinimalLen = new Uint8Array([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    expect(() => parseDerSignature(nonMinimalLen)).toThrow('non-minimal DER length');
    const negative = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]);
    expect(() => parseDerSignature(negative)).toThrow('negative');
    const padded = new Uint8Array([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01]);
    expect(() => parseDerSignature(padded)).toThrow('non-minimal DER INTEGER');
    const notInt = new Uint8Array([0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01]);
    expect(() => parseDerSignature(notInt)).toThrow('expected DER INTEGER');
    const emptyInt = new Uint8Array([0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01]);
    expect(() => parseDerSignature(emptyInt)).toThrow('bad DER INTEGER length');
    const unsupportedLen = new Uint8Array([0x30, 0x83, 0x00, 0x00, 0x06]);
    expect(() => parseDerSignature(unsupportedLen)).toThrow('unsupported DER length');
    const truncatedLong = new Uint8Array([0x30, 0x82, 0x01]);
    expect(() => parseDerSignature(truncatedLong)).toThrow('truncated');
  });
  it('accepts long-form lengths when they are minimal', () => {
    const content = new Uint8Array(0x82);
    content.fill(0);
    // r INTEGER of 0x7f bytes, s INTEGER of 1 byte → total 0x7f+2 + 3 = 0x84 > 0x7f → long form required.
    const r = new Uint8Array(0x7f).fill(0x01);
    const body = new Uint8Array([0x02, 0x7f, ...r, 0x02, 0x01, 0x01]);
    const der = new Uint8Array([0x30, 0x81, body.length, ...body]);
    expect(parseDerSignature(der).s).toBe(1n);
    expect(bytesToBase64(der).length).toBeGreaterThan(0);
  });
});
