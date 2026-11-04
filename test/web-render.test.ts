// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import type { EvidenceResult, Verdict } from '../src/index.js';
import {
  formatBytes,
  renderEvidence,
  renderFailure,
  renderSkeleton,
  renderVerdict,
  safeHttpsUrl,
  toneOf,
} from '../web/src/render.js';

function verdict(overrides: Partial<Verdict> = {}): Verdict {
  return {
    overall: 'genuine',
    mode: 'pdf',
    checks: {
      hash: 'match',
      signature: 'valid',
      key: 'unpinned',
      timestamp: 'trusted',
      ledger: 'consistent',
    },
    facts: {
      sealId: 'SEAL-1',
      documentHash: 'ab'.repeat(32),
      computedHash: 'ab'.repeat(32),
      fingerprint: 'cd'.repeat(32),
      sealedAt: '2026-11-04T12:00:00.000Z',
      timestampTime: '2026-11-04T12:00:05.000Z',
      tsaUrl: 'https://tsa.example/tsr',
      verifyUrl: 'https://example.com/verify/SEAL-1',
      algorithm: 'ECDSA_P256_SHA256',
      keyId: 'k',
      keyVersion: '2',
    },
    reasons: { hash: 'h', signature: 's', key: 'k', timestamp: 't', ledger: 'l' },
    notes: [],
    ...overrides,
  };
}

describe('render helpers', () => {
  it('maps status words to tones, unknown words to neutral', () => {
    expect(toneOf('match')).toBe('ok');
    expect(toneOf('mismatch')).toBe('bad');
    expect(toneOf('unpinned')).toBe('warn');
    expect(toneOf('none')).toBe('neutral');
    expect(toneOf('whatever')).toBe('neutral');
  });
  it('formats sizes', () => {
    expect(formatBytes(602)).toBe('602 B');
    expect(formatBytes(7 * 1024)).toBe('7.0 KB');
    expect(formatBytes(3 * 1024 * 1024)).toBe('3.0 MB');
  });
  it('links only https URLs', () => {
    expect(safeHttpsUrl('https://example.com/verify/X')).toBe('https://example.com/verify/X');
    expect(safeHttpsUrl('http://example.com/verify/X')).toBeNull();
    expect(safeHttpsUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpsUrl('data:text/html,hi')).toBeNull();
    expect(safeHttpsUrl('not a url')).toBeNull();
  });
});

describe('renderVerdict', () => {
  it('renders the word, the five rows, the facts and a safe online-check link', () => {
    const node = renderVerdict(verdict());
    expect(node.className).toBe('verdict verdict-ok');
    expect(node.querySelector('.verdict-word')?.textContent).toBe('Genuine');
    expect(node.querySelectorAll('.check')).toHaveLength(5);
    expect(node.querySelector('.check.tone-warn .chip')?.textContent).toBe('unpinned');
    const link = node.querySelector<HTMLAnchorElement>('.facts a');
    expect(link?.href).toBe('https://example.com/verify/SEAL-1');
    expect(link?.rel).toContain('noopener');
    expect(node.textContent).toContain('k (version 2)');
    expect(node.querySelectorAll('time')).toHaveLength(2);
  });
  it('never turns a non-https verifyUrl into a link', () => {
    const facts = verdict().facts;
    const node = renderVerdict(
      verdict({
        facts: facts ? { ...facts, verifyUrl: 'javascript:alert(document.title)' } : null,
      }),
    );
    expect(node.querySelector('.facts a')).toBeNull();
    expect(node.textContent).toContain('javascript:alert(document.title)');
    expect(node.textContent).toContain('not an https link');
  });
  it('shows the computed hash only when it differs, and the proof-only notice', () => {
    const facts = verdict().facts;
    const altered = renderVerdict(
      verdict({
        overall: 'altered',
        checks: { ...verdict().checks, hash: 'mismatch' },
        facts: facts ? { ...facts, computedHash: 'ef'.repeat(32) } : null,
      }),
    );
    expect(altered.className).toContain('verdict-bad');
    expect(altered.textContent).toContain('This PDF hashes to');
    const proofOnly = renderVerdict(verdict({ mode: 'proof-only' }));
    expect(proofOnly.textContent).toContain('Only the proof file was checked');
    expect(proofOnly.textContent).not.toContain('This PDF hashes to');
  });
  it('renders an incomplete verdict without facts, with its error', () => {
    const node = renderVerdict(
      verdict({
        overall: 'incomplete',
        facts: null,
        error: 'proof is not valid JSON',
        notes: ['n1'],
      }),
    );
    expect(node.className).toContain('verdict-warn');
    expect(node.querySelector('.facts')).toBeNull();
    expect(node.textContent).toContain('proof is not valid JSON');
    expect(node.querySelectorAll('.notes li')).toHaveLength(1);
  });
  it('drops the meaning line in compact mode', () => {
    const node = renderVerdict(verdict(), { compact: true });
    expect(node.classList.contains('verdict-compact')).toBe(true);
    expect(node.querySelector('.verdict-meaning')).toBeNull();
    expect(node.querySelector('.verdict-label')?.textContent).toBe('Document');
  });
});

describe('renderEvidence, renderSkeleton, renderFailure', () => {
  it('renders an archive with a sealed document, an unmatched one and a segment', () => {
    const result: EvidenceResult = {
      overall: 'incomplete',
      documents: [
        {
          path: 'documents/a.pdf',
          computedHash: 'ab'.repeat(32),
          sealId: 'SEAL-1',
          verdict: verdict(),
          overall: 'genuine',
          disposition: 'superseded',
        },
        {
          path: 'documents/b.pdf',
          computedHash: 'ef'.repeat(32),
          sealId: null,
          verdict: null,
          overall: 'incomplete',
          disposition: null,
          reason: 'no seal in the archive matches this PDF',
        },
      ],
      sealCount: 1,
      ledgerSegment: { ok: true, count: 2, from: 1, to: 2 },
      readme: null,
      notes: ['a note'],
    };
    const node = renderEvidence(result);
    expect(node.querySelector('.verdict-word')?.textContent).toBe('Incomplete');
    expect(node.querySelector('.archive-summary')?.textContent).toContain('2 documents');
    expect(node.querySelector('.archive-summary')?.textContent).toContain('1 seal');
    expect(node.querySelectorAll('.doc')).toHaveLength(2);
    expect(node.querySelector('.doc-head .chip')?.textContent).toBe('superseded');
    expect(node.textContent).toContain('no seal in the archive matches this PDF');
    expect(node.querySelector('.segment')?.textContent).toContain('entries #1 to #2, 2 checked.');
    expect(node.querySelector('.segment')?.classList.contains('tone-ok')).toBe(true);
    const none = renderEvidence({ ...result, ledgerSegment: null, documents: [], notes: [] });
    expect(none.querySelector('.segment')?.textContent).toContain('no ledger segment');
    expect(none.querySelector('.archive-summary')?.textContent).toContain('0 documents');
    const broken = renderEvidence({
      ...result,
      ledgerSegment: { ok: false, count: 0, from: null, to: null, reason: 'empty' },
    });
    expect(broken.querySelector('.segment')?.textContent).toContain('no entries, 0 checked. empty');
  });
  it('renders a skeleton and a failure', () => {
    expect(renderSkeleton().querySelectorAll('.skeleton-bar')).toHaveLength(6);
    const failure = renderFailure('boom');
    expect(failure.className).toContain('verdict-warn');
    expect(failure.textContent).toContain('Could not verify');
    expect(failure.textContent).toContain('boom');
  });
});
