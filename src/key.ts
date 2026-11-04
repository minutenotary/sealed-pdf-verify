import { AsnConvert } from '@peculiar/asn1-schema';
import { SubjectPublicKeyInfo } from '@peculiar/asn1-x509';
import { ECParameters, id_ecPublicKey, id_secp256r1 } from '@peculiar/asn1-ecc';
import { bytesToHex } from './bytes.js';
import { sha256 } from './hash.js';
import { pemToDer } from './pem.js';

export interface ParsedP256Key {
  /** The SubjectPublicKeyInfo DER exactly as supplied (what the fingerprint covers). */
  spkiDer: Uint8Array;
  /** The EC point bytes (SEC 1 uncompressed `04 || x || y`, or compressed). */
  point: Uint8Array;
}

/** Accepts a PEM `PUBLIC KEY` block or raw SPKI DER. Only EC P-256 keys are accepted. */
export function parseP256PublicKey(input: string | Uint8Array): ParsedP256Key {
  const spkiDer = typeof input === 'string' ? pemToDer(input, 'PUBLIC KEY') : input;
  let spki: SubjectPublicKeyInfo;
  try {
    spki = AsnConvert.parse(spkiDer, SubjectPublicKeyInfo);
  } catch {
    throw new Error('public key is not a SubjectPublicKeyInfo structure');
  }
  if (spki.algorithm.algorithm !== id_ecPublicKey) {
    throw new Error(`public key algorithm ${spki.algorithm.algorithm} is not id-ecPublicKey`);
  }
  const params = spki.algorithm.parameters;
  if (!params) throw new Error('public key has no EC parameters');
  let curve: ECParameters;
  try {
    curve = AsnConvert.parse(params, ECParameters);
  } catch {
    throw new Error('public key EC parameters are malformed');
  }
  if (curve.namedCurve !== id_secp256r1) {
    throw new Error(`public key curve ${curve.namedCurve ?? '(unnamed)'} is not P-256`);
  }
  const point = new Uint8Array(spki.subjectPublicKey);
  if (point.length !== 65 && point.length !== 33) {
    throw new Error(`unexpected EC point length ${point.length}`);
  }
  return { spkiDer, point };
}

/** SHA-256 (lowercase hex) of the SPKI DER bytes of a public key (PEM or DER). */
export async function keyFingerprint(input: string | Uint8Array): Promise<string> {
  const { spkiDer } = parseP256PublicKey(input);
  return bytesToHex(await sha256(spkiDer));
}
