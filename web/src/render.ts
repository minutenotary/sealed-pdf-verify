/**
 * Pure DOM rendering for the verifier page: a verdict in, elements out. No
 * state, no event wiring (that lives in main.ts), so each renderer can be
 * tested in isolation and nothing here can start a request.
 */
import type {
  Checks,
  EvidenceDocumentResult,
  EvidenceResult,
  Overall,
  Verdict,
} from '../../src/index.js';

// ---------- Vocabulary ----------

type CheckName = keyof Checks;
export type Tone = 'ok' | 'bad' | 'warn' | 'neutral';

const CHECK_ORDER: readonly CheckName[] = ['hash', 'signature', 'key', 'timestamp', 'ledger'];

const CHECK_LABEL: Readonly<Record<CheckName, string>> = {
  hash: 'Document hash',
  signature: 'Signature',
  key: 'Signing key',
  timestamp: 'Timestamp',
  ledger: 'Ledger entry',
};

/** Status words come from the library; the page only maps them to a tone. */
const STATUS_TONE: ReadonlyMap<string, Tone> = new Map<string, Tone>([
  ['match', 'ok'],
  ['valid', 'ok'],
  ['pinned', 'ok'],
  ['trusted', 'ok'],
  ['consistent', 'ok'],
  ['mismatch', 'bad'],
  ['invalid', 'bad'],
  ['rejected', 'bad'],
  ['inconsistent', 'bad'],
  ['unpinned', 'warn'],
  ['imprint_only', 'warn'],
]);

export const OVERALL_TONE: Readonly<Record<Overall, Tone>> = {
  genuine: 'ok',
  altered: 'bad',
  incomplete: 'warn',
};

const OVERALL_WORD: Readonly<Record<Overall, string>> = {
  genuine: 'Genuine',
  altered: 'Altered',
  incomplete: 'Incomplete',
};

const OVERALL_MEANING: Readonly<Record<Overall, string>> = {
  genuine: 'This PDF is the document that was sealed, and every check passed.',
  altered: 'Do not rely on this PDF. At least one check failed; the rows below say which.',
  incomplete: 'Not enough to decide. Something could not be checked; the rows below say what.',
};

const ARCHIVE_MEANING: Readonly<Record<Overall, string>> = {
  genuine: 'Every document in the archive is the one that was sealed, and every check passed.',
  altered: 'Do not rely on this archive. At least one document failed a check; see below.',
  incomplete: 'Not enough to decide. Something in the archive could not be checked; see below.',
};

const GLYPH: Readonly<Record<Tone, string>> = {
  ok: '✓',
  bad: '✕',
  warn: '!',
  neutral: '–',
};

// ---------- Helpers ----------

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function toneOf(status: string): Tone {
  return STATUS_TONE.get(status) ?? 'neutral';
}

function chip(status: string): HTMLSpanElement {
  return el('span', `chip tone-${toneOf(status)}`, status);
}

export function formatBytes(size: number): string {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * A proof's `verifyUrl` is attacker-controlled text. It becomes a link only
 * when it is an https URL; anything else (javascript:, data:, http:, junk)
 * is shown as plain text so the page never offers a click it cannot vouch for.
 */
export function safeHttpsUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}

/** The ISO timestamp as given, plus a local rendering so a reader need not convert. */
function timeNode(iso: string): HTMLElement[] {
  const time = el('time', 'mono', iso);
  time.dateTime = iso;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return [time];
  // timeStyle 'long' includes the zone abbreviation, which a reader comparing
  // against a paper record needs.
  const local = date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'long' });
  return [time, el('span', 'local-time', local)];
}

/** A small Copy control, only where the Clipboard API exists (secure contexts). */
function copyButton(value: string, what: string): HTMLButtonElement | null {
  if (!('clipboard' in navigator)) return null;
  const button = el('button', 'button button-quiet', 'Copy');
  button.type = 'button';
  button.setAttribute('aria-label', `Copy the ${what}`);
  button.addEventListener('click', () => {
    navigator.clipboard.writeText(value).then(
      () => {
        button.textContent = 'Copied';
        window.setTimeout(() => {
          button.textContent = 'Copy';
        }, 1500);
      },
      () => {
        button.textContent = 'Copy failed';
      },
    );
  });
  return button;
}

// ---------- Renderers ----------

function renderHead(
  overall: Overall,
  label: string,
  meaning: string | null,
  extra: string[] = [],
): HTMLElement {
  const head = el('header', 'verdict-head');
  head.append(el('p', 'verdict-label', label));
  // The word is the page's answer; it receives focus after a check so screen
  // readers announce it and keyboard users land on it.
  const word = el('h2', 'verdict-word', OVERALL_WORD[overall]);
  word.tabIndex = -1;
  head.append(word);
  if (meaning !== null) head.append(el('p', 'verdict-meaning', meaning));
  for (const line of extra) head.append(el('p', 'verdict-sub', line));
  return head;
}

function renderChecks(verdict: Verdict): HTMLOListElement {
  const list = el('ol', 'checks');
  for (const name of CHECK_ORDER) {
    const status = verdict.checks[name];
    const tone = toneOf(status);
    const row = el('li', `check tone-${tone}`);
    const glyph = el('span', 'check-glyph', GLYPH[tone]);
    glyph.setAttribute('aria-hidden', 'true');
    const line = el('div', 'check-line');
    line.append(el('span', 'check-name', CHECK_LABEL[name]), chip(status));
    row.append(glyph, line, el('p', 'check-reason', verdict.reasons[name]));
    list.append(row);
  }
  return list;
}

function renderFacts(verdict: Verdict): HTMLDListElement | null {
  const facts = verdict.facts;
  if (!facts) return null;
  const dl = el('dl', 'facts');
  const add = (term: string, ...nodes: (HTMLElement | string | null)[]): void => {
    const present = nodes.filter((n): n is HTMLElement | string => n !== null && n !== '');
    if (present.length === 0) return;
    dl.append(el('dt', undefined, term));
    const dd = el('dd');
    for (const node of present) {
      // A control gets its own line under the value, whatever the width.
      if (node instanceof HTMLButtonElement) {
        const row = el('div', 'facts-action');
        row.append(node);
        dd.append(row);
      } else {
        dd.append(node);
      }
    }
    dl.append(dd);
  };
  const mono = (value: string | null): HTMLElement | null =>
    value === null ? null : el('span', 'mono', value);

  add('Seal id', mono(facts.sealId));
  add('Document hash', mono(facts.documentHash), copyButton(facts.documentHash, 'document hash'));
  if (facts.computedHash !== null && facts.computedHash !== facts.documentHash)
    add('This PDF hashes to', mono(facts.computedHash));
  if (facts.fingerprint !== null)
    add(
      'Key fingerprint',
      mono(facts.fingerprint),
      copyButton(facts.fingerprint, 'key fingerprint'),
    );
  if (facts.keyId !== null)
    add(
      'Key id',
      facts.keyVersion === null ? facts.keyId : `${facts.keyId} (version ${facts.keyVersion})`,
    );
  add('Sealed at', ...timeNode(facts.sealedAt));
  if (facts.timestampTime !== null)
    add(
      'Timestamped at',
      ...timeNode(facts.timestampTime),
      facts.tsaUrl === null ? null : el('span', 'local-time', `via ${facts.tsaUrl}`),
    );
  add('Algorithm', mono(facts.algorithm));
  if (facts.verifyUrl !== null) {
    const href = safeHttpsUrl(facts.verifyUrl);
    if (href === null) {
      add('Online check', mono(facts.verifyUrl), el('span', 'local-time', '(not an https link)'));
    } else {
      const link = el('a', undefined, href);
      link.href = href;
      link.rel = 'noopener noreferrer';
      link.target = '_blank';
      add('Online check', link);
    }
  }
  return dl;
}

function renderNotes(notes: readonly string[]): HTMLUListElement | null {
  if (notes.length === 0) return null;
  const list = el('ul', 'notes');
  for (const note of notes) list.append(el('li', undefined, note));
  return list;
}

/** A full verdict block; `compact` drops the meaning line when the block sits inside an archive. */
export function renderVerdict(verdict: Verdict, { compact = false } = {}): HTMLElement {
  const article = el('article', `verdict verdict-${OVERALL_TONE[verdict.overall]}`);
  if (compact) article.classList.add('verdict-compact');
  const extra: string[] = [];
  if (verdict.mode === 'proof-only')
    extra.push('Only the proof file was checked. Add the PDF to check the document itself.');
  if (verdict.error !== undefined) extra.push(verdict.error);
  const head = renderHead(
    verdict.overall,
    compact ? 'Document' : 'Verdict',
    compact ? null : OVERALL_MEANING[verdict.overall],
    extra,
  );
  article.append(head, renderChecks(verdict));
  const facts = renderFacts(verdict);
  if (facts) article.append(facts);
  const notes = renderNotes(verdict.notes);
  if (notes) article.append(notes);
  return article;
}

function renderDocument(doc: EvidenceDocumentResult): HTMLElement {
  const section = el('section', 'doc');
  const head = el('div', 'doc-head');
  head.append(el('span', 'doc-path mono', doc.path));
  if (doc.sealId !== null) head.append(el('span', 'doc-seal', `seal ${doc.sealId}`));
  if (doc.disposition !== null && doc.disposition !== 'active') head.append(chip(doc.disposition));
  section.append(head);
  if (doc.verdict) {
    section.append(renderVerdict(doc.verdict, { compact: true }));
    return section;
  }
  const plain = el('div', 'doc-plain');
  const line = el('p');
  line.append(chip(doc.overall), ' ', doc.reason ?? '');
  plain.append(line);
  const hash = el('p', 'local-time');
  hash.append('This PDF hashes to ', el('span', 'mono', doc.computedHash));
  plain.append(hash);
  section.append(plain);
  return section;
}

export function renderEvidence(result: EvidenceResult): HTMLElement {
  const article = el('article', `verdict verdict-${OVERALL_TONE[result.overall]}`);
  article.append(renderHead(result.overall, 'Evidence archive', ARCHIVE_MEANING[result.overall]));
  const summary = el('div', 'archive-summary');
  const docs = result.documents.length;
  summary.append(
    el('span', undefined, `${docs} ${docs === 1 ? 'document' : 'documents'}`),
    el('span', undefined, `${result.sealCount} ${result.sealCount === 1 ? 'seal' : 'seals'}`),
  );
  article.append(summary);
  for (const doc of result.documents) article.append(renderDocument(doc));

  const segment = el('div', 'segment');
  const seg = result.ledgerSegment;
  const tone: Tone = seg === null ? 'neutral' : seg.ok ? 'ok' : 'bad';
  const glyph = el('span', 'check-glyph', GLYPH[tone]);
  glyph.setAttribute('aria-hidden', 'true');
  segment.classList.add(`tone-${tone}`);
  const line = el('div', 'check-line');
  line.append(el('span', 'check-name', 'Ledger segment'));
  let reason: string;
  if (seg === null) {
    reason = 'The archive carries no ledger segment.';
  } else {
    line.append(chip(seg.ok ? 'consistent' : 'inconsistent'));
    const range =
      seg.from !== null && seg.to !== null ? `entries #${seg.from} to #${seg.to}` : 'no entries';
    reason = `${range}, ${seg.count} checked.${seg.reason === undefined ? '' : ` ${seg.reason}`}`;
  }
  segment.append(glyph, line, el('p', 'check-reason', reason));
  article.append(segment);

  const notes = renderNotes(result.notes);
  if (notes) article.append(notes);
  return article;
}

/** Loading state, shaped like the verdict it is about to become. */
export function renderSkeleton(): HTMLElement {
  const box = el('div', 'skeleton');
  const bars = el('div');
  bars.setAttribute('aria-hidden', 'true');
  for (const width of ['w-30', 'w-70', 'w-50', 'w-60', 'w-50', 'w-70'])
    bars.append(el('div', `skeleton-bar ${width}`));
  box.append(bars, el('p', 'skeleton-text', 'Checking…'));
  return box;
}

/** The page could not run the checks at all (unreadable file, bad option). */
export function renderFailure(message: string): HTMLElement {
  const article = el('article', 'verdict verdict-warn');
  const head = el('header', 'verdict-head');
  head.append(el('p', 'verdict-label', 'Verdict'));
  const word = el('h2', 'verdict-word', 'Could not verify');
  word.tabIndex = -1;
  head.append(word, el('p', 'verdict-meaning', message));
  article.append(head);
  return article;
}
