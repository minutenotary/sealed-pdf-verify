import { describe, expect, it } from 'vitest';
import { PROOF_ONLY_NOTE, verifySealedPdf } from '../src/index.js';
import type { Verdict } from '../src/index.js';
import { facts, readBytes, readProof, readText } from './helpers.js';

const pdf = readBytes('sample.pdf');
const proof = readText('sample.proof.json');
const testRoot = readText('tsa-test-root.pem');

function expectChecks(v: Verdict, checks: Partial<Verdict['checks']>): void {
  for (const [k, val] of Object.entries(checks)) {
    expect(
      v.checks[k as keyof Verdict['checks']],
      `check ${k}: ${v.reasons[k as keyof Verdict['checks']]}`,
    ).toBe(val);
  }
}

describe('verifySealedPdf — genuine documents', () => {
  it('passes all five checks for the sample (real FreeTSA token, built-in root)', async () => {
    const v = await verifySealedPdf({ pdf, proof });
    expect(v.overall).toBe('genuine');
    expect(v.mode).toBe('pdf');
    expectChecks(v, {
      hash: 'match',
      signature: 'valid',
      key: 'unpinned',
      timestamp: 'trusted',
      ledger: 'consistent',
    });
    expect(v.facts?.sealId).toBe('SPV-TEST-000001');
    expect(v.facts?.documentHash).toBe(facts.sampleHash);
    expect(v.facts?.computedHash).toBe(facts.sampleHash);
    expect(v.facts?.fingerprint).toBe(facts.signer);
    expect(v.facts?.timestampTime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(v.facts?.tsaUrl).toBe('https://freetsa.org/tsr');
    expect(v.facts?.verifyUrl).toBe('https://example.com/verify/SPV-TEST-000001');
    expect(v.facts?.algorithm).toBe('OCI_ECDSA_P256_SHA256');
    expect(v.facts?.keyId).toBe('test-key');
    expect(v.notes).toEqual([]);
    expect(v.reasons.signature).toContain('der encoding');
  });
  it('accepts high-S, P1363 and the legacy label', async () => {
    for (const name of [
      'sample.high-s.proof.json',
      'sample.p1363.proof.json',
      'sample.legacy.proof.json',
    ]) {
      const v = await verifySealedPdf({ pdf, proof: readText(name) });
      expect(v.overall, name).toBe('genuine');
      expectChecks(v, { signature: 'valid' });
    }
    const p1363 = await verifySealedPdf({ pdf, proof: readText('sample.p1363.proof.json') });
    expect(p1363.reasons.signature).toContain('p1363 encoding');
  });
  it('reports timestamp none and ledger not_checked when the proof lacks them', async () => {
    const noTs = await verifySealedPdf({ pdf, proof: readText('sample.no-timestamp.proof.json') });
    expect(noTs.overall).toBe('genuine');
    expectChecks(noTs, { timestamp: 'none', ledger: 'consistent' });
    expect(noTs.facts?.timestampTime).toBeNull();
    const noLedger = await verifySealedPdf({ pdf, proof: readText('sample.no-ledger.proof.json') });
    expect(noLedger.overall).toBe('genuine');
    expectChecks(noLedger, { ledger: 'not_checked', timestamp: 'none' });
  });
  it('verifies the second chained document', async () => {
    const v = await verifySealedPdf({
      pdf: readBytes('second.pdf'),
      proof: readText('second.proof.json'),
    });
    expect(v.overall).toBe('genuine');
    expectChecks(v, { ledger: 'consistent', timestamp: 'none' });
  });
});

describe('verifySealedPdf — altered documents', () => {
  it('flags a tampered PDF: hash mismatch, signature and imprint fail', async () => {
    const v = await verifySealedPdf({ pdf: readBytes('tampered.pdf'), proof });
    expect(v.overall).toBe('altered');
    expectChecks(v, {
      hash: 'mismatch',
      signature: 'invalid',
      timestamp: 'invalid',
      ledger: 'consistent',
    });
    expect(v.facts?.computedHash).not.toBe(facts.sampleHash);
    expect(v.reasons.hash).toContain('bytes changed');
  });
  it('flags a wrong-key proof: hash matches but the signature is invalid', async () => {
    const v = await verifySealedPdf({ pdf, proof: readText('sample.wrong-key.proof.json') });
    expect(v.overall).toBe('altered');
    expectChecks(v, {
      hash: 'match',
      signature: 'invalid',
      timestamp: 'none',
      ledger: 'consistent',
    });
  });
  it('flags an unknown algorithm label', async () => {
    const v = await verifySealedPdf({ pdf, proof: readText('sample.bad-algorithm.proof.json') });
    expect(v.overall).toBe('altered');
    expectChecks(v, { signature: 'invalid' });
  });
  it('flags an inconsistent ledger block', async () => {
    const v = await verifySealedPdf({ pdf, proof: readText('sample.bad-ledger.proof.json') });
    expect(v.overall).toBe('altered');
    expectChecks(v, { hash: 'match', signature: 'valid', ledger: 'inconsistent' });
  });
});

describe('verifySealedPdf — timestamp trust options', () => {
  const synthetic = readText('sample.synthetic-tsa.proof.json');
  it('rejects a timestamp from an unknown TSA by default', async () => {
    const v = await verifySealedPdf({ pdf, proof: synthetic });
    expect(v.overall).toBe('altered');
    expectChecks(v, { timestamp: 'invalid' });
    expect(v.facts?.timestampTime).toBe(facts.genTime);
  });
  it('trusts it when its root is supplied', async () => {
    const v = await verifySealedPdf({
      pdf,
      proof: synthetic,
      options: { tsaRootsPem: [testRoot] },
    });
    expect(v.overall).toBe('genuine');
    expectChecks(v, { timestamp: 'trusted' });
    const onlyExtra = await verifySealedPdf({
      pdf,
      proof: synthetic,
      options: { tsaRootsPem: [testRoot], useBuiltInTsaRoots: false },
    });
    expectChecks(onlyExtra, { timestamp: 'trusted' });
  });
  it('reports imprint_only when trust is disabled or no roots are available', async () => {
    const disabled = await verifySealedPdf({
      pdf,
      proof: synthetic,
      options: { checkTimestampTrust: false },
    });
    expect(disabled.overall).toBe('genuine');
    expectChecks(disabled, { timestamp: 'imprint_only' });
    const noRoots = await verifySealedPdf({
      pdf,
      proof: synthetic,
      options: { useBuiltInTsaRoots: false },
    });
    expectChecks(noRoots, { timestamp: 'imprint_only' });
    expect(noRoots.reasons.timestamp).toContain('not evaluated');
  });
});

describe('verifySealedPdf — key pinning', () => {
  it('pins by fingerprint (any case, with or without separators)', async () => {
    const pinned = await verifySealedPdf({
      pdf,
      proof,
      options: { trustedKeyFingerprints: [facts.signer] },
    });
    expectChecks(pinned, { key: 'pinned' });
    const colons = facts.signer.toUpperCase().match(/.{2}/g)?.join(':') ?? '';
    const pinned2 = await verifySealedPdf({
      pdf,
      proof,
      options: { trustedKeyFingerprints: [colons] },
    });
    expectChecks(pinned2, { key: 'pinned' });
  });
  it('pins by public key PEM', async () => {
    const v = await verifySealedPdf({
      pdf,
      proof,
      options: { trustedPublicKeys: [readText('signer.pub.pem')] },
    });
    expectChecks(v, { key: 'pinned' });
    expect(v.overall).toBe('genuine');
  });
  it('rejects an unlisted key even though the signature is valid', async () => {
    const v = await verifySealedPdf({
      pdf,
      proof,
      options: { trustedKeyFingerprints: [facts.other] },
    });
    expect(v.overall).toBe('altered');
    expectChecks(v, { signature: 'valid', key: 'rejected' });
  });
  it('rejects when the supplied trust list is empty or unusable', async () => {
    const empty = await verifySealedPdf({ pdf, proof, options: { trustedKeyFingerprints: [] } });
    expectChecks(empty, { key: 'rejected' });
    expect(empty.reasons.key).toContain('no usable fingerprint');
    const garbage = await verifySealedPdf({
      pdf,
      proof,
      options: { trustedPublicKeys: ['not a key'] },
    });
    expectChecks(garbage, { key: 'rejected' });
    expect(garbage.notes.some((n) => n.includes('could not be parsed'))).toBe(true);
  });
});

describe('verifySealedPdf — proof-only mode and bad input', () => {
  it('skips the hash check and says so', async () => {
    const v = await verifySealedPdf({ proof });
    expect(v.mode).toBe('proof-only');
    expect(v.overall).toBe('genuine');
    expectChecks(v, {
      hash: 'not_checked',
      signature: 'valid',
      timestamp: 'trusted',
      ledger: 'consistent',
    });
    expect(v.notes).toContain(PROOF_ONLY_NOTE);
    expect(v.facts?.computedHash).toBeNull();
  });
  it('accepts a parsed proof object and bytes', async () => {
    const obj = await verifySealedPdf({ pdf, proof: readProof('sample.proof.json') });
    const bytes = await verifySealedPdf({ pdf, proof: readBytes('sample.proof.json') });
    expect(obj.overall).toBe('genuine');
    expect(bytes.overall).toBe('genuine');
  });
  it('returns incomplete for an unreadable proof', async () => {
    const v = await verifySealedPdf({ pdf, proof: '{"schemaVersion": 3}' });
    expect(v.overall).toBe('incomplete');
    expect(v.facts).toBeNull();
    expect(v.error).toContain('schemaVersion 3');
    expectChecks(v, { hash: 'not_checked', signature: 'invalid', key: 'rejected' });
  });
  it('reports a null fingerprint when the key does not parse', async () => {
    const raw = readProof('sample.no-timestamp.proof.json');
    const v = await verifySealedPdf({
      pdf,
      proof: { ...raw, publicKeyPem: '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----' },
    });
    expect(v.overall).toBe('altered');
    expect(v.facts?.fingerprint).toBeNull();
    expectChecks(v, { signature: 'invalid', key: 'unpinned' });
  });
});
