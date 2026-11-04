import { bytesToHex, toArrayBuffer } from './bytes.js';

/** SHA-256 through WebCrypto (`crypto.subtle`), available in Node 20+ and browsers. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return new Uint8Array(digest);
}

/** SHA-256 of the bytes as lowercase hex (64 characters). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return bytesToHex(await sha256(bytes));
}
