import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  EXIT_ALTERED,
  EXIT_GENUINE,
  EXIT_INCOMPLETE,
  formatEvidence,
  formatVerdict,
  runCli,
  sanitizeForTerminal,
} from '../cli/main.js';
import type { EvidenceResult, ProofV1, Verdict } from '../src/index.js';
import { fx, readProof } from './helpers.js';

interface Run {
  code: number;
  out: string;
  err: string;
}

async function run(...argv: string[]): Promise<Run> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runCli(argv, { out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

const pdf = fx('sample.pdf');
const proof = fx('sample.proof.json');

describe('cli', () => {
  it('strips bidi overrides and zero-width characters, and escapes them in --json', async () => {
    expect(sanitizeForTerminal('A\u202eLTERED\u200b\u00ad\u2066x\u2069')).toBe('ALTEREDx');
    const dir = mkdtempSync(join(tmpdir(), 'spv-bidi-'));
    const crafted = {
      ...readProof('sample.proof.json'),
      sealId: 'SEAL\u202e\u0085\u2028\u009b[2J-END',
    };
    const proofPath = join(dir, 'crafted.proof.json');
    writeFileSync(proofPath, JSON.stringify(crafted));
    const human = await run(pdf, '--proof', proofPath);
    expect(human.out).not.toMatch(/[\u202e\u0085\u2028\u009b]/);
    expect(human.out).toContain('SEAL[2J-END');
    const json = await run(pdf, '--proof', proofPath, '--json');
    expect(json.out).not.toMatch(/[\u202e\u0085\u2028\u009b]/);
    expect(json.out).toContain('\\u202e');
    expect(json.out).toContain('\\u009b');
    const parsed = JSON.parse(json.out) as { facts: { sealId: string } };
    expect(parsed.facts.sealId).toBe(crafted.sealId);
  });
  it('prints usage with --help', async () => {
    const r = await run('--help');
    expect(r.code).toBe(EXIT_GENUINE);
    expect(r.out).toContain('Usage:');
  });
  it('prints GENUINE for the sample', async () => {
    const r = await run(pdf, '--proof', proof);
    expect(r.code).toBe(EXIT_GENUINE);
    expect(r.out).toContain('Verdict: GENUINE');
    expect(r.out).toMatch(/hash\s+match/);
    expect(r.out).toMatch(/timestamp\s+trusted/);
    expect(r.out).toContain('Online check   https://example.com/verify/SPV-TEST-000001');
    expect(r.out).toContain('(id test-key, version 1)');
  });
  it('prints ALTERED with hash mismatch for the tampered PDF', async () => {
    const r = await run(fx('tampered.pdf'), '--proof', proof);
    expect(r.code).toBe(EXIT_ALTERED);
    expect(r.out).toContain('Verdict: ALTERED');
    expect(r.out).toMatch(/hash\s+mismatch/);
    expect(r.out).toContain('PDF digest');
  });
  it('prints ALTERED with signature invalid for the wrong-key proof', async () => {
    const r = await run(pdf, '--proof', fx('sample.wrong-key.proof.json'));
    expect(r.code).toBe(EXIT_ALTERED);
    expect(r.out).toMatch(/signature\s+invalid/);
  });
  it('pins and rejects keys through --trust', async () => {
    const pinned = await run(pdf, '--proof', proof, '--trust', fx('trust-pinned.json'));
    expect(pinned.code).toBe(EXIT_GENUINE);
    expect(pinned.out).toMatch(/key\s+pinned/);
    const rejected = await run(pdf, '--proof', proof, '--trust', fx('trust-other.json'));
    expect(rejected.code).toBe(EXIT_ALTERED);
    expect(rejected.out).toMatch(/key\s+rejected/);
    // An empty trust file is an unfilled template, not a document problem.
    const empty = await run(pdf, '--proof', proof, '--trust', fx('trust-empty.json'));
    expect(empty.code).toBe(EXIT_INCOMPLETE);
    expect(empty.err).toContain('empty');
    const bad = await run(pdf, '--proof', proof, '--trust', fx('trust-bad.json'));
    expect(bad.code).toBe(EXIT_INCOMPLETE);
    expect(bad.err).toContain('fingerprints');
  });
  it('emits JSON with --json', async () => {
    const r = await run(pdf, '--proof', proof, '--json');
    expect(r.code).toBe(EXIT_GENUINE);
    const v = JSON.parse(r.out) as Verdict;
    expect(v.overall).toBe('genuine');
    expect(v.checks.ledger).toBe('consistent');
  });
  it('supports proof-only mode', async () => {
    const r = await run('--proof', proof);
    expect(r.code).toBe(EXIT_GENUINE);
    expect(r.out).toContain('proof-only: PDF bytes not checked');
    expect(r.out).toMatch(/hash\s+not_checked/);
    expect(r.out).toContain('note: PDF bytes were NOT checked');
  });
  it('handles timestamp root options', async () => {
    const synthetic = fx('sample.synthetic-tsa.proof.json');
    const untrusted = await run(pdf, '--proof', synthetic);
    expect(untrusted.code).toBe(EXIT_ALTERED);
    expect(untrusted.out).toMatch(/timestamp\s+invalid/);
    const trusted = await run(pdf, '--proof', synthetic, '--tsa-roots', fx('tsa-test-root.pem'));
    expect(trusted.code).toBe(EXIT_GENUINE);
    expect(trusted.out).toMatch(/timestamp\s+trusted/);
    const imprintOnly = await run(pdf, '--proof', synthetic, '--no-tsa-trust');
    expect(imprintOnly.code).toBe(EXIT_GENUINE);
    expect(imprintOnly.out).toMatch(/timestamp\s+imprint_only/);
    // No root left to trust is a usage error, not an "imprint only" verdict.
    const noBuiltin = await run(pdf, '--proof', proof, '--no-builtin-roots');
    expect(noBuiltin.code).toBe(EXIT_INCOMPLETE);
    expect(noBuiltin.err).toContain('--no-builtin-roots');
    const explicit = await run(pdf, '--proof', proof, '--no-builtin-roots', '--no-tsa-trust');
    expect(explicit.code).toBe(EXIT_GENUINE);
    expect(explicit.out).toMatch(/timestamp\s+imprint_only/);
    const notPem = await run(pdf, '--proof', synthetic, '--tsa-roots', fx('trust-bad.json'));
    expect(notPem.code).toBe(EXIT_INCOMPLETE);
    expect(notPem.err).toContain('CERTIFICATE');
    const missing = await run(pdf, '--proof', synthetic, '--tsa-roots', fx('missing.pem'));
    expect(missing.code).toBe(EXIT_INCOMPLETE);
  });
  it('prints its version', async () => {
    const r = await run('--version');
    expect(r.code).toBe(EXIT_GENUINE);
    expect(r.out).toMatch(/^sealed-pdf-verify \S+$/);
  });
  it('strips terminal control characters from proof-derived text', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'spv-'));
    const crafted: ProofV1 = {
      ...readProof('sample.proof.json'),
      sealId: 'X\u001b[3A\u001b[2KVerdict: GENUINE\n\u001b[3B',
      keyId: 'k\r\u0007',
    };
    const path = join(dir, 'crafted.proof.json');
    writeFileSync(path, JSON.stringify(crafted));
    const r = await run(fx('tampered.pdf'), '--proof', path);
    expect(r.code).toBe(EXIT_ALTERED);
    // eslint-disable-next-line no-control-regex -- the test is about control characters
    expect(r.out).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(r.out.split('\n').filter((l) => l.startsWith('Verdict:'))).toEqual(['Verdict: ALTERED']);
    // JSON output keeps the raw value, escaped by JSON itself.
    const j = await run(fx('tampered.pdf'), '--proof', path, '--json');
    expect((JSON.parse(j.out) as Verdict).facts?.sealId).toBe(crafted.sealId);
    expect(sanitizeForTerminal('a\tb\u001bc')).toBe('a\tbc');
  });
  it('verifies an evidence archive', async () => {
    const r = await run(fx('evidence.zip'));
    expect(r.code).toBe(EXIT_GENUINE);
    expect(r.out).toContain('Evidence archive: GENUINE');
    expect(r.out).toContain('== documents/second.pdf  seal SPV-TEST-000002  [superseded]');
    expect(r.out).toContain('Ledger segment consistent');
    const json = await run(fx('evidence.zip'), '--json');
    const parsed = JSON.parse(json.out) as EvidenceResult;
    expect(parsed.documents).toHaveLength(2);
    // Key pinning applies to every document in the archive.
    const pinned = await run(fx('evidence.zip'), '--trust', fx('trust-pinned.json'));
    expect(pinned.code).toBe(EXIT_GENUINE);
    const rejected = await run(fx('evidence.zip'), '--trust', fx('trust-other.json'));
    expect(rejected.code).toBe(EXIT_ALTERED);
    // An archive is recognised by its bytes and never takes --proof.
    const withProof = await run(fx('evidence.zip'), '--proof', proof);
    expect(withProof.code).toBe(EXIT_INCOMPLETE);
    expect(withProof.err).toContain('does not take --proof');
    const dir = mkdtempSync(join(tmpdir(), 'spv-'));
    const fake = join(dir, 'fake.zip');
    writeFileSync(fake, 'not an archive');
    expect((await run(fake)).err).toContain('not a ZIP archive');
  });
  it('returns 2 for usage errors and missing files', async () => {
    expect((await run(pdf)).code).toBe(EXIT_INCOMPLETE);
    expect((await run(pdf)).err).toContain('--proof');
    expect((await run(pdf, proof, '--proof', proof)).err).toContain('at most one file');
    expect((await run('--bogus')).err).toContain('Usage:');
    expect((await run(fx('missing.pdf'), '--proof', proof)).code).toBe(EXIT_INCOMPLETE);
    expect((await run(pdf, '--proof', fx('missing.json'))).err).toContain('error:');
  });
  it('returns 2 for an unreadable proof', async () => {
    const r = await run(pdf, '--proof', fx('trust-bad.json'));
    expect(r.code).toBe(EXIT_INCOMPLETE);
    expect(r.out).toContain('Verdict: INCOMPLETE');
    expect(r.out).toContain('error:');
    const j = await run(pdf, '--proof', fx('trust-bad.json'), '--json');
    expect(j.code).toBe(EXIT_INCOMPLETE);
    const v = JSON.parse(j.out) as Verdict;
    expect(v.overall).toBe('incomplete');
    expect(v.facts).toBeNull();
    expect(v.error).toBeDefined();
  });
});

describe('formatters', () => {
  it('render documents without a seal and archives without a segment', () => {
    const result: EvidenceResult = {
      overall: 'incomplete',
      documents: [
        {
          path: 'documents/x.pdf',
          computedHash: 'ab'.repeat(32),
          sealId: null,
          verdict: null,
          overall: 'incomplete',
          disposition: null,
          reason: 'no seal',
        },
      ],
      sealCount: 0,
      ledgerSegment: { ok: false, count: 0, from: null, to: null, reason: 'segment is empty' },
      readme: null,
      notes: ['a note'],
    };
    const text = formatEvidence(result).join('\n');
    expect(text).toContain('Verdict: INCOMPLETE');
    expect(text).toContain('no seal');
    expect(text).toContain(
      'Ledger segment INCONSISTENT  (no entries, 0 checked)  segment is empty',
    );
    expect(text).toContain('note: a note');
    const noSegment = formatEvidence({ ...result, ledgerSegment: null }).join('\n');
    expect(noSegment).toContain('Ledger segment not present');
  });
  it('renders a verdict without facts', () => {
    const verdict: Verdict = {
      overall: 'incomplete',
      mode: 'proof-only',
      checks: {
        hash: 'not_checked',
        signature: 'invalid',
        key: 'rejected',
        timestamp: 'none',
        ledger: 'not_checked',
      },
      facts: null,
      reasons: { hash: 'h', signature: 's', key: 'k', timestamp: 't', ledger: 'l' },
      notes: [],
      error: 'boom',
    };
    const text = formatVerdict(verdict).join('\n');
    expect(text).toContain('error: boom');
    expect(text).not.toContain('Seal id');
  });
});
