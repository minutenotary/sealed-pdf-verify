import { p256 } from '@noble/curves/nist.js';
import { base64ToBytes, concatBytes, hexToBytes, isHex } from './bytes.js';
import { parseP256PublicKey } from './key.js';

/** The two accepted algorithm labels; both mean ECDSA P-256 over a raw SHA-256 digest. */
export const ALGORITHM_CURRENT = 'OCI_ECDSA_P256_SHA256';
export const ALGORITHM_LEGACY = 'ECDSA_P256_SHA256';
export const ACCEPTED_ALGORITHMS: readonly string[] = [ALGORITHM_CURRENT, ALGORITHM_LEGACY];

/** Order of the P-256 base point. */
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

export type SignatureEncoding = 'der' | 'p1363';

export interface SignatureInput {
  /** The 32-byte SHA-256 digest the signature is over (bytes or 64 hex chars). */
  digest: Uint8Array | string;
  /** Base64 text or raw bytes: DER `Ecdsa-Sig-Value` or 64-byte `r || s`. */
  signature: string | Uint8Array;
  /** PEM `PUBLIC KEY` or SPKI DER, EC P-256. */
  publicKey: string | Uint8Array;
  /** Must be one of {@link ACCEPTED_ALGORITHMS}. */
  algorithm: string;
}

export interface SignatureResult {
  ok: boolean;
  /** Which encoding the signature used, when it could be decoded. */
  encoding: SignatureEncoding | null;
  /** Why the check failed; absent on success. */
  reason?: string;
}

interface ScalarPair {
  r: bigint;
  s: bigint;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bigIntTo32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/** Reads one DER length at `offset`; returns the length and the offset after it. */
function readDerLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
  const first = bytes[offset];
  if (first === undefined) throw new Error('truncated DER length');
  if (first < 0x80) return { length: first, next: offset + 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 2) throw new Error('unsupported DER length');
  let length = 0;
  for (let i = 0; i < count; i += 1) {
    const b = bytes[offset + 1 + i];
    if (b === undefined) throw new Error('truncated DER length');
    length = (length << 8) | b;
  }
  // DER: long form only when the value does not fit the short form; no leading zero bytes.
  if (length < 0x80 || (count === 2 && length < 0x100)) throw new Error('non-minimal DER length');
  return { length, next: offset + 1 + count };
}

/** Reads one DER INTEGER at `offset` as a non-negative bigint. */
function readDerInteger(bytes: Uint8Array, offset: number): { value: bigint; next: number } {
  if (bytes[offset] !== 0x02) throw new Error('expected DER INTEGER');
  const { length, next } = readDerLength(bytes, offset + 1);
  if (length === 0 || next + length > bytes.length) throw new Error('bad DER INTEGER length');
  const content = bytes.subarray(next, next + length);
  const first = content[0] ?? 0;
  if (first & 0x80) throw new Error('negative DER INTEGER');
  if (length > 1 && first === 0x00 && ((content[1] ?? 0) & 0x80) === 0) {
    throw new Error('non-minimal DER INTEGER');
  }
  return { value: bytesToBigInt(content), next: next + length };
}

/** Strict DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279). */
export function parseDerSignature(bytes: Uint8Array): ScalarPair {
  if (bytes[0] !== 0x30) throw new Error('expected DER SEQUENCE');
  const seq = readDerLength(bytes, 1);
  if (seq.next + seq.length !== bytes.length) throw new Error('DER SEQUENCE length mismatch');
  const r = readDerInteger(bytes, seq.next);
  const s = readDerInteger(bytes, r.next);
  if (s.next !== bytes.length) throw new Error('trailing bytes after DER signature');
  return { r: r.value, s: s.value };
}

/** Decodes DER or 64-byte P1363 into (r, s) and reports which encoding was used. */
export function decodeSignature(bytes: Uint8Array): ScalarPair & { encoding: SignatureEncoding } {
  if (bytes[0] === 0x30) {
    return { ...parseDerSignature(bytes), encoding: 'der' };
  }
  if (bytes.length === 64) {
    return {
      r: bytesToBigInt(bytes.subarray(0, 32)),
      s: bytesToBigInt(bytes.subarray(32, 64)),
      encoding: 'p1363',
    };
  }
  throw new Error(`signature is neither DER nor 64-byte P1363 (${bytes.length} bytes)`);
}

/**
 * ECDSA P-256 over the raw 32-byte digest (prehashed mode: the digest is the
 * message; it is not hashed again). High-S signatures are accepted on purpose;
 * r and s must both be in [1, n-1].
 */
export function verifySignature(input: SignatureInput): Promise<SignatureResult> {
  return Promise.resolve(verifySignatureSync(input));
}

/** Synchronous form of {@link verifySignature} (the ECDSA check needs no I/O). */
export function verifySignatureSync(input: SignatureInput): SignatureResult {
  if (!ACCEPTED_ALGORITHMS.includes(input.algorithm)) {
    return {
      ok: false,
      encoding: null,
      reason: `algorithm "${input.algorithm}" is not one of ${ACCEPTED_ALGORITHMS.join(', ')}`,
    };
  }
  let digest: Uint8Array;
  if (typeof input.digest === 'string') {
    if (!isHex(input.digest, 32))
      return { ok: false, encoding: null, reason: 'digest must be 64 hex characters' };
    digest = hexToBytes(input.digest);
  } else {
    digest = input.digest;
  }
  if (digest.length !== 32) return { ok: false, encoding: null, reason: 'digest must be 32 bytes' };

  let point: Uint8Array;
  try {
    point = parseP256PublicKey(input.publicKey).point;
  } catch (error) {
    return { ok: false, encoding: null, reason: `public key: ${messageOf(error)}` };
  }

  let scalars: ScalarPair & { encoding: SignatureEncoding };
  try {
    const raw =
      typeof input.signature === 'string' ? base64ToBytes(input.signature) : input.signature;
    scalars = decodeSignature(raw);
  } catch (error) {
    return { ok: false, encoding: null, reason: `signature: ${messageOf(error)}` };
  }
  const { r, s, encoding } = scalars;
  if (r < 1n || r >= P256_N || s < 1n || s >= P256_N) {
    return { ok: false, encoding, reason: 'signature: r or s is outside [1, n-1]' };
  }

  const compact = concatBytes(bigIntTo32(r), bigIntTo32(s));
  let ok: boolean;
  try {
    ok = p256.verify(compact, digest, point, { prehash: false, lowS: false, format: 'compact' });
  } catch (error) {
    return { ok: false, encoding, reason: `signature: ${messageOf(error)}` };
  }
  return ok
    ? { ok: true, encoding }
    : { ok: false, encoding, reason: 'signature does not verify with this key' };
}

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
