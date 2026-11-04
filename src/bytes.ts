/**
 * Small byte helpers shared by every check. Runtime-neutral: only `atob`,
 * `btoa`, `TextEncoder` and `TextDecoder`, which exist in Node 20+ and every
 * modern browser.
 */

const HEX_RE = /^[0-9a-fA-F]*$/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

export function isHex(value: string, byteLength?: number): boolean {
  if (!HEX_RE.test(value) || value.length % 2 !== 0) return false;
  return byteLength === undefined || value.length === byteLength * 2;
}

export function hexToBytes(hex: string): Uint8Array {
  if (!isHex(hex)) throw new Error('invalid hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Strict standard base64 (RFC 4648 §4). Whitespace is tolerated, nothing else. */
export function base64ToBytes(text: string): Uint8Array {
  const compact = text.replace(/\s+/g, '');
  if (!BASE64_RE.test(compact)) throw new Error('invalid base64');
  const padded = compact + '='.repeat((4 - (compact.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('invalid base64');
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/**
 * Constant-time byte comparison. The length is not secret; the content is
 * compared in full regardless of where the first difference sits.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Case-insensitive, constant-time comparison of two hex strings. */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (!isHex(a) || !isHex(b)) return false;
  return constantTimeEqual(hexToBytes(a), hexToBytes(b));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Copies a view into a standalone ArrayBuffer (what the ASN.1 parsers expect). */
export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
