import { generateKeyPairSync } from 'node:crypto';
import * as asn1js from 'asn1js';
import { describe, expect, it } from 'vitest';
import { keyFingerprint, parseP256PublicKey, pemToDer } from '../src/index.js';
import { facts, readText } from './helpers.js';

function spkiWith(algorithmChildren: asn1js.AsnType[], pointLength: number): Uint8Array {
  const seq = new asn1js.Sequence({
    value: [
      new asn1js.Sequence({ value: algorithmChildren }),
      new asn1js.BitString({ valueHex: new Uint8Array(pointLength).fill(4).buffer }),
    ],
  });
  return new Uint8Array(seq.toBER(false));
}

describe('parseP256PublicKey / keyFingerprint', () => {
  it('fingerprints the SPKI DER (PEM and DER inputs agree with openssl-style hashing)', async () => {
    const pem = readText('signer.pub.pem');
    expect(await keyFingerprint(pem)).toBe(facts.signer);
    expect(await keyFingerprint(pemToDer(pem, 'PUBLIC KEY'))).toBe(facts.signer);
    expect(await keyFingerprint(readText('other.pub.pem'))).toBe(facts.other);
    expect(parseP256PublicKey(pem).point.length).toBe(65);
  });
  it('rejects non-EC keys', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({
      type: 'spki',
      format: 'pem',
    });
    expect(() => parseP256PublicKey(rsa)).toThrow('is not id-ecPublicKey');
    const ed = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    expect(() => parseP256PublicKey(ed)).toThrow('is not id-ecPublicKey');
  });
  it('rejects other curves', () => {
    const p384 = generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({
      type: 'spki',
      format: 'pem',
    });
    expect(() => parseP256PublicKey(p384)).toThrow('is not P-256');
  });
  it('rejects malformed structures', () => {
    expect(() => parseP256PublicKey(new Uint8Array([1, 2, 3]))).toThrow(
      'not a SubjectPublicKeyInfo',
    );
    expect(() =>
      parseP256PublicKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'),
    ).toThrow('expected exactly one "PUBLIC KEY"');
    const noParams = spkiWith([new asn1js.ObjectIdentifier({ value: '1.2.840.10045.2.1' })], 65);
    expect(() => parseP256PublicKey(noParams)).toThrow('no EC parameters');
    const badParams = spkiWith(
      [
        new asn1js.ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
        new asn1js.OctetString({ valueHex: new Uint8Array([1]).buffer }),
      ],
      65,
    );
    expect(() => parseP256PublicKey(badParams)).toThrow('malformed');
    const shortPoint = spkiWith(
      [
        new asn1js.ObjectIdentifier({ value: '1.2.840.10045.2.1' }),
        new asn1js.ObjectIdentifier({ value: '1.2.840.10045.3.1.7' }),
      ],
      10,
    );
    expect(() => parseP256PublicKey(shortPoint)).toThrow('unexpected EC point length 10');
  });
});
