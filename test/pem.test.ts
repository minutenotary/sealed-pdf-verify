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
  it('skips a BEGIN line that never ends and still finds the blocks around it', () => {
    const pub = readText('signer.pub.pem');
    const text = `-----BEGIN PUBLIC KEY-----\nAAAA\n${pub}-----BEGIN CERTIFICATE-----\nAAAA\n`;
    // The unterminated PUBLIC KEY line runs to the first PUBLIC KEY END, so it
    // swallows the real block's BEGIN line: same result as the old regex.
    expect(() => pemBlocks(text)).toThrow('invalid base64');
    const blocks = pemBlocks(`-----BEGIN CERTIFICATE-----\nAAAA\n${pub}`);
    expect(blocks.map((b) => b.label)).toEqual(['PUBLIC KEY']);
    expect(blocks[0]?.der.length).toBe(91);
  });
  it('matches END markers that share dashes with the one before', () => {
    // END B starts on the dashes that close END A; finding it puts "AAAA-----END A"
    // in the body (not base64), where missing it would return no block at all.
    expect(() => pemBlocks('-----BEGIN B-----AAAA-----END A-----END B-----')).toThrow(
      'invalid base64',
    );
  });
  it('finds a BEGIN line that shares dashes with an unterminated one', () => {
    const blocks = pemBlocks('-----BEGIN X-----BEGIN Y-----AAAA-----END Y-----');
    expect(blocks.map((b) => b.label)).toEqual(['Y']);
  });
  it('stays fast on many BEGIN lines with no END', () => {
    const text = '-----BEGIN A-----\n'.repeat(50_000) + '-----BEGIN B-----\n'.repeat(50_000);
    const started = performance.now();
    expect(pemBlocks(text)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(1000);
  });
  it('derToPem round-trips', () => {
    const der = pemToDer(readText('signer.pub.pem'), 'PUBLIC KEY');
    const pem = derToPem(der, 'PUBLIC KEY');
    expect(pem.startsWith('-----BEGIN PUBLIC KEY-----\n')).toBe(true);
    expect(pemToDer(pem, 'PUBLIC KEY')).toEqual(der);
  });
});
