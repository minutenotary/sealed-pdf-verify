// @vitest-environment jsdom
/**
 * The page wiring (web/src/main.ts) against the real markup, with the
 * library mocked so each verification run can be resolved by hand. The
 * ordering test is the point: a run that finishes after a newer one started
 * must never paint the panel.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EvidenceResult, Verdict, VerifyInput, VerifyOptions } from '../src/index.js';

interface PendingSealed {
  input: VerifyInput;
  resolve: (verdict: Verdict) => void;
  reject: (error: Error) => void;
}
interface PendingZip {
  options: VerifyOptions;
  resolve: (result: EvidenceResult) => void;
}

const pending = vi.hoisted(() => ({
  sealed: [] as { input: unknown; resolve: (v: unknown) => void; reject: (e: Error) => void }[],
  zip: [] as { options: unknown; resolve: (v: unknown) => void }[],
}));

vi.mock('../src/index.js', () => ({
  verifySealedPdf: (input: unknown) =>
    new Promise((resolve, reject) => {
      pending.sealed.push({ input, resolve, reject });
    }),
  verifyEvidenceZip: (_zip: unknown, options: unknown) =>
    new Promise((resolve) => {
      pending.zip.push({ options, resolve });
    }),
}));

const sealed = pending.sealed as unknown as PendingSealed[];
const zips = pending.zip as unknown as PendingZip[];

function verdict(sealId: string): Verdict {
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
      sealId,
      documentHash: 'ab'.repeat(32),
      computedHash: 'ab'.repeat(32),
      fingerprint: 'cd'.repeat(32),
      sealedAt: '2026-11-04T12:00:00.000Z',
      timestampTime: null,
      tsaUrl: null,
      verifyUrl: null,
      algorithm: 'ECDSA_P256_SHA256',
      keyId: null,
      keyVersion: null,
    },
    reasons: { hash: 'h', signature: 's', key: 'k', timestamp: 't', ledger: 'l' },
    notes: [],
  };
}

const file = (name: string, content = 'x'): File => new File([content], name);

function drop(...files: File[]): void {
  const event = new Event('drop', { cancelable: true });
  Object.defineProperty(event, 'dataTransfer', { value: { files, types: ['Files'] } });
  document.dispatchEvent(event);
}

/** Lets the awaited `arrayBuffer()` reads inside verify() run before the mock is reached. */
async function settle(): Promise<void> {
  for (let i = 0; i < 10; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

function el<T extends Element>(selector: string, type: new () => T): T {
  const node = document.querySelector(selector);
  if (!(node instanceof type)) throw new Error(`missing ${selector}`);
  return node;
}
const result = (): HTMLElement => el('#result', HTMLElement);
const message = (): HTMLElement => el('#intake-message', HTMLElement);
const verifyButton = (): HTMLButtonElement => el('#verify-button', HTMLButtonElement);
const slotName = (kind: string): string =>
  el(`[data-slot="${kind}"] .slot-name`, HTMLElement).textContent;

beforeAll(async () => {
  const html = readFileSync(join(import.meta.dirname, '..', 'web', 'index.html'), 'utf8');
  const body = html.slice(html.indexOf('<body'), html.indexOf('</body>'));
  document.body.innerHTML = body
    .replace(/^<body[^>]*>/, '')
    .replace(/<script[\s\S]*?<\/script>/g, '');
  window.matchMedia = () => ({ matches: false }) as MediaQueryList;
  Element.prototype.scrollIntoView = () => undefined;
  await import('../web/src/main.js');
});

beforeEach(() => {
  el('#clear-button', HTMLButtonElement).click();
  sealed.length = 0;
  zips.length = 0;
});

afterEach(() => {
  // Leave no run hanging into the next test.
  for (const run of sealed) run.resolve(verdict('LATE'));
  for (const run of zips)
    run.resolve({
      overall: 'incomplete',
      documents: [],
      sealCount: 0,
      ledgerSegment: null,
      readme: null,
      notes: [],
    });
});

describe('intake', () => {
  it('starts empty: Verify disabled, prompts in the slots, the default hint', () => {
    expect(verifyButton().disabled).toBe(true);
    expect(slotName('pdf')).toBe('Choose a file');
    expect(slotName('zip')).toBe('Or choose a .zip instead');
    expect(message().textContent).toContain('Drop files anywhere');
    expect(result().hidden).toBe(true);
  });
  it('files land in the slot their extension names; anything else is named and ignored', () => {
    drop(file('notes.txt'), file('scan.PDF'));
    expect(slotName('pdf')).toBe('scan.PDF');
    expect(message().textContent).toContain('Ignored notes.txt');
    expect(message().classList.contains('is-error')).toBe(true);
    expect(verifyButton().disabled).toBe(true);
  });
  it('guides to the proof after a PDF, and offers proof-only after a proof', () => {
    drop(file('a.pdf'));
    expect(message().textContent).toContain('Now add the proof file');
    el('#clear-button', HTMLButtonElement).click();
    drop(file('a.proof.json'));
    expect(message().textContent).toContain('press Verify to check the proof alone');
    expect(verifyButton().disabled).toBe(false);
  });
  it('an archive replaces a PDF + proof pair and dims the other slots', () => {
    drop(file('a.pdf'), file('a.proof.json'));
    drop(file('bundle.zip'));
    expect(slotName('zip')).toBe('bundle.zip');
    expect(slotName('pdf')).toBe('Choose a file');
    expect(el('[data-slot="pdf"]', HTMLElement).classList.contains('is-dimmed')).toBe(true);
  });
  it('the remove control empties one slot and the hint follows', () => {
    drop(file('a.pdf'), file('a.proof.json'));
    el('[data-slot="proof"] .slot-remove', HTMLButtonElement).click();
    expect(slotName('proof')).toBe('Choose a file');
    expect(message().textContent).toContain('Now add the proof file');
  });
});

describe('verification runs', () => {
  it('runs as soon as the pair is complete and paints the verdict', async () => {
    drop(file('a.pdf', 'pdf-bytes'), file('a.proof.json', '{}'));
    expect(result().hidden).toBe(false);
    expect(result().getAttribute('aria-busy')).toBe('true');
    await settle();
    expect(sealed).toHaveLength(1);
    expect(sealed[0]?.input.pdf).toBeInstanceOf(Uint8Array);
    sealed[0]?.resolve(verdict('SEAL-A'));
    await settle();
    expect(result().getAttribute('aria-busy')).toBe('false');
    expect(result().textContent).toContain('Genuine');
    expect(result().textContent).toContain('SEAL-A');
    expect(document.activeElement?.classList.contains('verdict-word')).toBe(true);
  });
  it('never paints a run that finished after a newer one started', async () => {
    drop(file('first.pdf'), file('a.proof.json'));
    await settle();
    drop(file('second.pdf'));
    await settle();
    expect(sealed).toHaveLength(2);
    sealed[1]?.resolve(verdict('SEAL-OF-SECOND'));
    await settle();
    sealed[0]?.resolve(verdict('SEAL-OF-FIRST'));
    await settle();
    expect(slotName('pdf')).toBe('second.pdf');
    expect(result().textContent).toContain('SEAL-OF-SECOND');
    expect(result().textContent).not.toContain('SEAL-OF-FIRST');
  });
  it('a result that arrives after Clear stays gone', async () => {
    drop(file('a.pdf'), file('a.proof.json'));
    await settle();
    el('#clear-button', HTMLButtonElement).click();
    expect(result().hidden).toBe(true);
    sealed[0]?.resolve(verdict('LATE'));
    await settle();
    expect(result().hidden).toBe(true);
    expect(result().textContent).not.toContain('LATE');
  });
  it('Verify with a proof alone runs proof-only and passes the pinned fingerprints', async () => {
    drop(file('a.proof.json'));
    el('#fingerprints', HTMLTextAreaElement).value = ` ${'ab'.repeat(32)} \n\n${'cd'.repeat(32)}`;
    verifyButton().click();
    await settle();
    expect(sealed[0]?.input.pdf).toBeUndefined();
    expect(sealed[0]?.input.options?.trustedKeyFingerprints).toEqual([
      'ab'.repeat(32),
      'cd'.repeat(32),
    ]);
  });
  it('an archive goes to verifyEvidenceZip and the panel shows the archive verdict', async () => {
    drop(file('bundle.zip'));
    await settle();
    expect(zips).toHaveLength(1);
    zips[0]?.resolve({
      overall: 'incomplete',
      documents: [],
      sealCount: 0,
      ledgerSegment: null,
      readme: null,
      notes: ['the archive contains no documents/*.pdf'],
    });
    await settle();
    expect(result().textContent).toContain('Incomplete');
    expect(result().textContent).toContain('no documents');
  });
  it('a thrown error becomes a failure panel', async () => {
    drop(file('a.pdf'), file('a.proof.json'));
    await settle();
    sealed[0]?.reject(new Error('boom'));
    await settle();
    expect(result().textContent).toContain('Could not verify');
    expect(result().textContent).toContain('boom');
  });
});
