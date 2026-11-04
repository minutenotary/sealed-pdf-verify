import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_TSA_ROOTS,
  bytesToBase64,
  parseTimestampToken,
  verifyTimestampImprint,
  verifyTimestampTrust,
} from '../src/index.js';
import { facts, readBytes, readText } from './helpers.js';

const synthetic = readBytes('synthetic.tsr');
const real = readBytes('real-freetsa.tsr');
const testRoot = readText('tsa-test-root.pem');
const builtIn = BUILT_IN_TSA_ROOTS.map((r) => r.pem);

describe('parseTimestampToken', () => {
  it('extracts genTime from a synthetic token (bytes and base64)', () => {
    expect(parseTimestampToken(synthetic).genTime.toISOString()).toBe(facts.genTime);
    expect(parseTimestampToken(bytesToBase64(synthetic)).genTime.toISOString()).toBe(facts.genTime);
  });
  it('rejects non-token input', () => {
    expect(() => parseTimestampToken(new Uint8Array([1, 2, 3]))).toThrow();
    // A certificate is a valid DER SEQUENCE but not a CMS ContentInfo.
    expect(() => parseTimestampToken(readBytes('tsa-test-root.pem'))).toThrow();
  });
});

describe('verifyTimestampImprint', () => {
  it('passes for the sealed digest and fails for another digest', async () => {
    const ok = await verifyTimestampImprint({ token: synthetic, digest: facts.sampleHash });
    expect(ok.ok).toBe(true);
    expect(ok.genTime?.toISOString()).toBe(facts.genTime);
    const bad = await verifyTimestampImprint({
      token: bytesToBase64(synthetic),
      digest: facts.secondHash,
    });
    expect(bad.ok).toBe(false);
    expect(bad.reason).toContain('does not match');
    expect(bad.genTime?.toISOString()).toBe(facts.genTime);
  });
  it('requires a SHA-256 imprint', async () => {
    const sha1 = await verifyTimestampImprint({
      token: readBytes('synthetic-sha1.tsr'),
      digest: facts.sampleHash,
    });
    expect(sha1.ok).toBe(false);
    expect(sha1.reason).toContain('is not SHA-256');
  });
  it('fails closed on bad digests and unparseable tokens', async () => {
    expect((await verifyTimestampImprint({ token: synthetic, digest: 'xyz' })).reason).toContain(
      '64 hex',
    );
    const broken = await verifyTimestampImprint({
      token: new Uint8Array([0x30, 0x00]),
      digest: facts.sampleHash,
    });
    expect(broken.ok).toBe(false);
    expect(broken.reason).toContain('token:');
  });
  it('works with a real FreeTSA token', async () => {
    const res = await verifyTimestampImprint({ token: real, digest: facts.sampleHash });
    expect(res.ok).toBe(true);
    expect(res.genTime).toBeInstanceOf(Date);
  });
});

describe('verifyTimestampTrust', () => {
  it('trusts the synthetic token with the test root only', async () => {
    const ok = await verifyTimestampTrust({ token: synthetic, roots: [testRoot] });
    expect(ok.ok).toBe(true);
    expect(ok.signer).toContain('Test Timestamp Unit');
    expect(ok.pathLength).toBe(2);
    const notOk = await verifyTimestampTrust({ token: synthetic, roots: builtIn });
    expect(notOk.ok).toBe(false);
    expect(notOk.reason).toContain('not trusted');
  });
  it('trusts the real FreeTSA token with the shipped FreeTSA root', async () => {
    const res = await verifyTimestampTrust({ token: real, roots: builtIn });
    expect(res.ok).toBe(true);
    expect(res.signer).toContain('www.freetsa.org');
    const digicertOnly = BUILT_IN_TSA_ROOTS.filter((r) => r.name.startsWith('digicert')).map(
      (r) => r.pem,
    );
    expect((await verifyTimestampTrust({ token: real, roots: digicertOnly })).ok).toBe(false);
  });
  it('requires the timeStamping EKU', async () => {
    const res = await verifyTimestampTrust({
      token: readBytes('synthetic-noeku.tsr'),
      roots: [testRoot],
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toContain('timeStamping');
  });
  it('rejects a chain to an unknown root', async () => {
    const res = await verifyTimestampTrust({
      token: readBytes('synthetic-untrusted.tsr'),
      roots: [testRoot],
    });
    expect(res.ok).toBe(false);
    expect(res.signer ?? '').toContain('Unrelated Timestamp Unit');
    const withItsRoot = await verifyTimestampTrust({
      token: readBytes('synthetic-untrusted.tsr'),
      roots: [readText('tsa-unrelated-root.pem')],
    });
    expect(withItsRoot.ok).toBe(true);
  });
  it('fails closed on missing or bad roots and bad tokens', async () => {
    expect((await verifyTimestampTrust({ token: synthetic, roots: [] })).reason).toBe(
      'no trusted root certificates supplied',
    );
    expect((await verifyTimestampTrust({ token: synthetic, roots: ['no pem here'] })).reason).toBe(
      'no trusted root certificates supplied',
    );
    const badRoot = await verifyTimestampTrust({
      token: synthetic,
      roots: [new Uint8Array([1, 2, 3])],
    });
    expect(badRoot.reason).toContain('roots:');
    const badToken = await verifyTimestampTrust({ token: new Uint8Array([1]), roots: [testRoot] });
    expect(badToken.reason).toContain('token:');
  });
  it('rejects a token whose signature bytes were altered', async () => {
    const tampered = new Uint8Array(synthetic);
    tampered[tampered.length - 1] = (tampered[tampered.length - 1] ?? 0) ^ 0x01;
    const res = await verifyTimestampTrust({ token: tampered, roots: [testRoot] });
    expect(res.ok).toBe(false);
  });
  it('rejects a token whose signed content was altered', async () => {
    // Flip one byte inside the encapsulated TSTInfo (after the header, before the signature).
    const tampered = new Uint8Array(synthetic);
    const idx = Math.floor(tampered.length / 3);
    tampered[idx] = (tampered[idx] ?? 0) ^ 0x01;
    const res = await verifyTimestampTrust({ token: tampered, roots: [testRoot] });
    expect(res.ok).toBe(false);
  });
});
