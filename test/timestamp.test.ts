import { describe, expect, it } from 'vitest';
import {
  BUILT_IN_TSA_ROOTS,
  bytesToBase64,
  hexToBytes,
  parseTimestampToken,
  verifyTimestampImprint,
  verifyTimestampTrust,
} from '../src/index.js';
import { ContentInfo, SignedData } from '@peculiar/asn1-cms';
import { AsnConvert } from '@peculiar/asn1-schema';
import { facts, readBytes, readText } from './helpers.js';

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = 0; i + needle.length <= haystack.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

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
  it('requires the timeStamping EKU, critical, as the only purpose (RFC 3161 §2.3)', async () => {
    const absent = await verifyTimestampTrust({
      token: readBytes('synthetic-noeku.tsr'),
      roots: [testRoot],
    });
    expect(absent.ok).toBe(false);
    expect(absent.reason).toBe(
      'timestamp signer certificate lacks the timeStamping extended key usage extension',
    );
    const noncritical = await verifyTimestampTrust({
      token: readBytes('synthetic-eku-noncritical.tsr'),
      roots: [testRoot],
    });
    expect(noncritical.ok).toBe(false);
    expect(noncritical.reason).toBe(
      'timestamp signer certificate does not mark its extended key usage critical (RFC 3161 §2.3)',
    );
    const multi = await verifyTimestampTrust({
      token: readBytes('synthetic-eku-multi.tsr'),
      roots: [testRoot],
    });
    expect(multi.ok).toBe(false);
    expect(multi.reason).toBe(
      'timestamp signer certificate lists purposes other than timeStamping (RFC 3161 §2.3)',
    );
  });
  it('refuses a CMS signature made with SHA-1 before checking it', async () => {
    const token = readBytes('synthetic-sha1-cms.tsr');
    // The imprint itself is SHA-256 and matches: only the CMS layer is weak.
    expect((await verifyTimestampImprint({ token, digest: facts.sampleHash })).ok).toBe(true);
    expect(parseTimestampToken(token).digestAlgorithm).toBe('1.3.14.3.2.26');
    const res = await verifyTimestampTrust({ token, roots: [testRoot] });
    expect(res.ok).toBe(false);
    expect(res.reason).toBe(
      'timestamp CMS uses digest algorithm 1.3.14.3.2.26, not an accepted SHA-2 digest',
    );
  });
  it('accepts the CMS algorithms the real and synthetic tokens use', () => {
    expect(parseTimestampToken(synthetic).signatureAlgorithm).toBe('1.2.840.10045.4.3.2');
    expect(parseTimestampToken(real).digestAlgorithm).toBe('2.16.840.1.101.3.4.2.3');
    expect(parseTimestampToken(readBytes('real-digicert.tsr')).signatureAlgorithm).toBe(
      '1.2.840.113549.1.1.1',
    );
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
  it('rejects a token whose signed content (TSTInfo) was altered', async () => {
    // Locate the encapsulated TSTInfo inside the token and flip one byte in
    // the middle of it, so the failure is the messageDigest attribute, not
    // a broken certificate.
    const signedData = AsnConvert.parse(
      AsnConvert.parse(synthetic, ContentInfo).content,
      SignedData,
    );
    const tstDer = new Uint8Array(signedData.encapContentInfo.eContent?.single?.buffer ?? []);
    expect(tstDer.length).toBeGreaterThan(0);
    const start = indexOfBytes(synthetic, tstDer);
    expect(start).toBeGreaterThan(0);
    // Flip inside the imprint value: the structure stays valid, so the
    // failure must come from the signed messageDigest attribute.
    const imprintAt = indexOfBytes(tstDer, hexToBytes(facts.sampleHash));
    expect(imprintAt).toBeGreaterThan(0);
    const tampered = new Uint8Array(synthetic);
    const idx = start + imprintAt + 5;
    tampered[idx] = (tampered[idx] ?? 0) ^ 0x01;
    expect(() => parseTimestampToken(tampered)).not.toThrow();
    const res = await verifyTimestampTrust({ token: tampered, roots: [testRoot] });
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/digest/i);
  });
});

describe('parseTimestampToken — malformed variants fail closed', () => {
  it('rejects a token whose signed attributes lack content-type', () => {
    expect(() => parseTimestampToken(readBytes('synthetic-no-content-type.tsr'))).toThrow(
      'lack content-type',
    );
  });
  it('rejects a token whose content-type attribute names id-data', () => {
    expect(() => parseTimestampToken(readBytes('synthetic-wrong-content-type.tsr'))).toThrow(
      'does not name id-ct-TSTInfo',
    );
  });
  it('rejects a constructed (BER) encapsulated content', () => {
    expect(() => parseTimestampToken(readBytes('synthetic-constructed.tsr'))).toThrow(
      'no encapsulated TSTInfo content',
    );
  });
  it('rejects a plain id-data CMS that merely carries TSTInfo bytes', () => {
    expect(() => parseTimestampToken(readBytes('synthetic-id-data.tsr'))).toThrow(
      'is not id-ct-TSTInfo',
    );
  });
  it('rejects a token with two SignerInfos (RFC 3161 §2.4.2)', () => {
    expect(() => parseTimestampToken(readBytes('synthetic-two-signers.tsr'))).toThrow(
      'token has 2 SignerInfos; RFC 3161 allows exactly one',
    );
  });
  it('reports each of them as an invalid imprint and an untrusted token', async () => {
    for (const name of [
      'synthetic-no-content-type.tsr',
      'synthetic-wrong-content-type.tsr',
      'synthetic-constructed.tsr',
      'synthetic-id-data.tsr',
      'synthetic-two-signers.tsr',
    ]) {
      const token = readBytes(name);
      expect((await verifyTimestampImprint({ token, digest: facts.sampleHash })).ok, name).toBe(
        false,
      );
      expect((await verifyTimestampTrust({ token, roots: [testRoot] })).ok, name).toBe(false);
    }
  });
});

describe('verifyTimestampTrust — chain anchoring', () => {
  it('ignores a self-signed root embedded in the token', async () => {
    // The unrelated TSA ships its own root inside the token; only roots the
    // caller supplies may anchor a chain.
    const token = readBytes('synthetic-untrusted-with-root.tsr');
    expect((await verifyTimestampTrust({ token, roots: [testRoot] })).ok).toBe(false);
    expect((await verifyTimestampTrust({ token, roots: builtIn })).ok).toBe(false);
    const anchored = await verifyTimestampTrust({
      token,
      roots: [readText('tsa-unrelated-root.pem')],
    });
    expect(anchored.ok).toBe(true);
    expect(anchored.pathLength).toBe(2);
  });
  it('accepts a TSA whose self-signed certificate is both signer and trust anchor', async () => {
    // A private TSA (openssl ts) has one self-signed certificate; the chain
    // is that certificate alone and it must be accepted when it is a root.
    const token = readBytes('synthetic-selfsigned-tsu.tsr');
    const anchored = await verifyTimestampTrust({
      token,
      roots: [readText('tsa-selfsigned-tsu.pem')],
    });
    expect(anchored.ok, anchored.reason).toBe(true);
    expect(anchored.signer).toContain('Test Self-Signed Timestamp Unit');
    expect(anchored.pathLength).toBeGreaterThanOrEqual(1);
    expect((await verifyTimestampTrust({ token, roots: [testRoot] })).ok).toBe(false);
  });
  it('chains through a cross-signed intermediate to whichever root is trusted', async () => {
    // The pool holds the intermediate twice (certified by the test root and
    // by the unrelated root). Either root must anchor; the dead-end copy
    // must not abort the search.
    const token = readBytes('synthetic-cross-signed.tsr');
    const viaTest = await verifyTimestampTrust({ token, roots: [testRoot] });
    expect(viaTest.ok, viaTest.reason).toBe(true);
    expect(viaTest.pathLength).toBe(3);
    const viaUnrelated = await verifyTimestampTrust({
      token,
      roots: [readText('tsa-unrelated-root.pem')],
    });
    expect(viaUnrelated.ok, viaUnrelated.reason).toBe(true);
    expect(viaUnrelated.pathLength).toBe(3);
    expect((await verifyTimestampTrust({ token, roots: builtIn })).ok).toBe(false);
  });
  it('validates a real DigiCert token (RSA-4096 signer, three-certificate chain) against the shipped root', async () => {
    // The token embeds a cross-signed copy of "DigiCert Trusted Root G4"
    // (same key, issued by another DigiCert root); the chain must still end
    // at the self-signed copy shipped with the package.
    const token = readBytes('real-digicert.tsr');
    const imprint = await verifyTimestampImprint({ token, digest: facts.sampleHash });
    expect(imprint.ok).toBe(true);
    const trust = await verifyTimestampTrust({ token, roots: builtIn });
    expect(trust.ok, trust.reason).toBe(true);
    expect(trust.signer).toContain('DigiCert');
    expect(trust.pathLength).toBe(3);
    const onlyFreeTsa = await verifyTimestampTrust({
      token,
      roots: [BUILT_IN_TSA_ROOTS.find((r) => r.name === 'freetsa-root')?.pem ?? ''],
    });
    expect(onlyFreeTsa.ok).toBe(false);
  });
});
