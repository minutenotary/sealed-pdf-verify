import { describe, expect, it } from 'vitest';
import { derToPem, pemBlocks, pemToDer } from '../src/pem.js';
import { readText } from './helpers.js';

describe('pem', () => {
  it('parses blocks and labels', () => {
    const text = readText('signer.pub.pem') + readText('tsa-test-root.pem');
    const blocks = pemBlocks(text);
    expect(blocks.map((b) => b.label)).toEqual(['PUBLIC KEY', 'CERTIFICATE']);
    expect(blocks[0]?.der.length).toBe(91);
  });
  it('pemToDer requires exactly one block of the label', () => {
    expect(() => pemToDer('nothing here', 'PUBLIC KEY')).toThrow('found 0');
    const twice = readText('signer.pub.pem').repeat(2);
    expect(() => pemToDer(twice, 'PUBLIC KEY')).toThrow('found 2');
    expect(pemToDer(readText('signer.pub.pem'), 'PUBLIC KEY').length).toBe(91);
  });
  it('rejects bad base64 inside a block', () => {
    expect(() => pemBlocks('-----BEGIN X-----\n@@@@\n-----END X-----')).toThrow('invalid base64');
  });
  it('derToPem round-trips', () => {
    const der = pemToDer(readText('signer.pub.pem'), 'PUBLIC KEY');
    const pem = derToPem(der, 'PUBLIC KEY');
    expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true);
    expect(pemToDer(pem, 'PUBLIC KEY')).toEqual(der);
  });
});
