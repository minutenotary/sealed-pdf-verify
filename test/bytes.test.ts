import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  constantTimeEqual,
  constantTimeEqualHex,
  hexToBytes,
  isHex,
  toArrayBuffer,
  utf8ToBytes,
} from '../src/bytes.js';

describe('hex', () => {
  it('round-trips', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
    expect(bytesToHex(new Uint8Array([]))).toBe('');
  });
  it('validates', () => {
    expect(isHex('abcd')).toBe(true);
    expect(isHex('abc')).toBe(false);
    expect(isHex('zz')).toBe(false);
    expect(isHex('ab', 1)).toBe(true);
    expect(isHex('ab', 2)).toBe(false);
    expect(() => hexToBytes('xyz')).toThrow('invalid hex');
  });
});

describe('base64', () => {
  it('round-trips and tolerates whitespace / missing padding', () => {
    const bytes = new Uint8Array([1, 2, 3, 250, 251]);
    const text = bytesToBase64(bytes);
    expect(base64ToBytes(text)).toEqual(bytes);
    expect(base64ToBytes(text.replace(/=+$/, ''))).toEqual(bytes);
    expect(base64ToBytes(`  ${text.slice(0, 2)}\n${text.slice(2)} `)).toEqual(bytes);
  });
  it('rejects invalid input', () => {
    expect(() => base64ToBytes('not*base64')).toThrow('invalid base64');
    expect(() => base64ToBytes('==')).toThrow('invalid base64');
  });
});

describe('utf8', () => {
  it('round-trips and fails closed on invalid bytes', () => {
    expect(bytesToUtf8(utf8ToBytes('héllo'))).toBe('héllo');
    expect(() => bytesToUtf8(new Uint8Array([0xff, 0xfe]))).toThrow();
  });
});

describe('constant-time compare', () => {
  it('compares bytes', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });
  it('compares hex case-insensitively and rejects non-hex', () => {
    expect(constantTimeEqualHex('ABcd', 'abCD')).toBe(true);
    expect(constantTimeEqualHex('abcd', 'abce')).toBe(false);
    expect(constantTimeEqualHex('abcd', 'xx')).toBe(false);
  });
});

describe('concat / buffers', () => {
  it('concatenates and copies', () => {
    const joined = concatBytes(new Uint8Array([1]), new Uint8Array([2, 3]));
    expect(Array.from(joined)).toEqual([1, 2, 3]);
    const view = new Uint8Array(new Uint8Array([9, 8, 7, 6]).buffer, 1, 2);
    expect(Array.from(new Uint8Array(toArrayBuffer(view)))).toEqual([8, 7]);
  });
});
