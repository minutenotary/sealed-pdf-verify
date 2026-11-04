import { verifyEvidenceZip, verifySealedPdf } from '../../src/index.js';
import type { Checks, EvidenceResult, Verdict, VerifyOptions } from '../../src/index.js';

type CheckName = keyof Checks;
const CHECK_ORDER: CheckName[] = ['hash', 'signature', 'key', 'timestamp', 'ledger'];

const GOOD = new Set(['match', 'valid', 'pinned', 'trusted', 'consistent']);
const BAD = new Set(['mismatch', 'invalid', 'rejected', 'inconsistent']);
const WARN = new Set(['unpinned', 'imprint_only']);

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el;
}

const dropzone = byId('dropzone');
const pdfInput = byId('pdf-input') as HTMLInputElement;
const proofInput = byId('proof-input') as HTMLInputElement;
const zipInput = byId('zip-input') as HTMLInputElement;
const fingerprints = byId('fingerprints') as HTMLTextAreaElement;
const verifyButton = byId('verify-button') as HTMLButtonElement;
const clearButton = byId('clear-button') as HTMLButtonElement;
const result = byId('result');

interface Selected {
  pdf: File | null;
  proof: File | null;
  zip: File | null;
}
const selected: Selected = { pdf: null, proof: null, zip: null };

function el(tag: string, className?: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badgeClass(value: string): string {
  if (GOOD.has(value)) return 'badge badge-ok';
  if (BAD.has(value)) return 'badge badge-bad';
  if (WARN.has(value)) return 'badge badge-warn';
  return 'badge badge-neutral';
}

function renderVerdict(verdict: Verdict): HTMLElement {
  const box = el('div');
  const banner = el('p', `verdict verdict-${verdict.overall}`, verdict.overall.toUpperCase());
  if (verdict.mode === 'proof-only')
    banner.append(el('small', undefined, 'Proof-only: the PDF bytes were not checked.'));
  if (verdict.error) banner.append(el('small', undefined, verdict.error));
  box.append(banner);

  const table = el('table', 'checks');
  for (const name of CHECK_ORDER) {
    const row = el('tr');
    row.append(el('th', undefined, name));
    const cell = el('td');
    cell.append(el('span', badgeClass(verdict.checks[name]), verdict.checks[name]));
    cell.append(document.createTextNode(verdict.reasons[name]));
    row.append(cell);
    table.append(row);
  }
  box.append(table);

  const f = verdict.facts;
  if (f) {
    const dl = el('dl', 'facts');
    const add = (k: string, v: string | null, mono = false): void => {
      if (v === null || v === '') return;
      dl.append(el('dt', undefined, k));
      dl.append(el('dd', mono ? 'mono' : undefined, v));
    };
    add('Seal id', f.sealId, true);
    add('Sealed digest', f.documentHash, true);
    if (f.computedHash !== null && f.computedHash !== f.documentHash)
      add('PDF digest', f.computedHash, true);
    add('Key fingerprint', f.fingerprint, true);
    add('Key id', f.keyId ? `${f.keyId}${f.keyVersion ? ` (version ${f.keyVersion})` : ''}` : null);
    add('Sealed at', f.sealedAt);
    add(
      'Timestamp',
      f.timestampTime ? `${f.timestampTime}${f.tsaUrl ? ` via ${f.tsaUrl}` : ''}` : null,
    );
    add('Algorithm', f.algorithm, true);
    if (f.verifyUrl) {
      dl.append(el('dt', undefined, 'Online check'));
      const dd = el('dd');
      const a = el('a', undefined, f.verifyUrl) as HTMLAnchorElement;
      a.href = f.verifyUrl;
      a.rel = 'noopener';
      a.target = '_blank';
      dd.append(a);
      dl.append(dd);
    }
    box.append(dl);
  }
  if (verdict.notes.length > 0) {
    const ul = el('ul', 'notes');
    for (const note of verdict.notes) ul.append(el('li', undefined, note));
    box.append(ul);
  }
  return box;
}

function renderEvidence(res: EvidenceResult): HTMLElement {
  const box = el('div');
  const banner = el(
    'p',
    `verdict verdict-${res.overall}`,
    `Evidence archive: ${res.overall.toUpperCase()}`,
  );
  banner.append(
    el('small', undefined, `${res.documents.length} document(s), ${res.sealCount} seal(s)`),
  );
  box.append(banner);
  for (const doc of res.documents) {
    const section = el('div', 'doc');
    const title = `${doc.path}${doc.sealId ? ` — seal ${doc.sealId}` : ''}${doc.disposition && doc.disposition !== 'active' ? ` [${doc.disposition}]` : ''}`;
    section.append(el('h3', undefined, title));
    if (doc.verdict) {
      section.append(renderVerdict(doc.verdict));
    } else {
      section.append(el('p', `verdict verdict-${doc.overall}`, doc.overall.toUpperCase()));
      section.append(el('p', 'notes', doc.reason ?? ''));
      section.append(el('p', 'mono', `PDF digest ${doc.computedHash}`));
    }
    box.append(section);
  }
  const seg = res.ledgerSegment;
  const segLine = seg
    ? `Ledger segment ${seg.ok ? 'consistent' : 'INCONSISTENT'} (${seg.from !== null && seg.to !== null ? `entries #${seg.from}..#${seg.to}` : 'no entries'}, ${seg.count} checked)${seg.reason ? ` — ${seg.reason}` : ''}`
    : 'Ledger segment not present in the archive';
  box.append(el('p', 'doc', segLine));
  if (res.notes.length > 0) {
    const ul = el('ul', 'notes');
    for (const note of res.notes) ul.append(el('li', undefined, note));
    box.append(ul);
  }
  return box;
}

function options(): VerifyOptions {
  const lines = fingerprints.value
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const opts: VerifyOptions = {};
  if (lines.length > 0) opts.trustedKeyFingerprints = lines;
  return opts;
}

function showResult(node: HTMLElement): void {
  result.replaceChildren(node);
  result.hidden = false;
  result.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function verify(): Promise<void> {
  verifyButton.disabled = true;
  showResult(el('p', 'notes', 'Verifying…'));
  try {
    if (selected.zip) {
      const bytes = new Uint8Array(await selected.zip.arrayBuffer());
      showResult(renderEvidence(await verifyEvidenceZip(bytes, options())));
    } else if (selected.proof) {
      const proof = new Uint8Array(await selected.proof.arrayBuffer());
      const input: Parameters<typeof verifySealedPdf>[0] = { proof, options: options() };
      if (selected.pdf) input.pdf = new Uint8Array(await selected.pdf.arrayBuffer());
      showResult(renderVerdict(await verifySealedPdf(input)));
    } else {
      showResult(el('p', 'notes', 'Choose a proof JSON (with its PDF) or an evidence ZIP first.'));
    }
  } catch (error) {
    showResult(
      el(
        'p',
        'verdict verdict-incomplete',
        `Could not verify: ${error instanceof Error ? error.message : String(error)}`,
      ),
    );
  } finally {
    updateButtons();
  }
}

function updateButtons(): void {
  verifyButton.disabled = !(selected.zip ?? selected.proof);
}

function assign(file: File): void {
  const name = file.name.toLowerCase();
  if (name.endsWith('.zip')) selected.zip = file;
  else if (name.endsWith('.json')) selected.proof = file;
  else if (name.endsWith('.pdf')) selected.pdf = file;
}

function handleFiles(files: FileList | File[]): void {
  for (const file of Array.from(files)) assign(file);
  updateButtons();
  if (selected.zip ?? (selected.proof && selected.pdf)) void verify();
}

pdfInput.addEventListener('change', () => {
  selected.pdf = pdfInput.files?.[0] ?? null;
  handleFiles([]);
});
proofInput.addEventListener('change', () => {
  selected.proof = proofInput.files?.[0] ?? null;
  handleFiles([]);
});
zipInput.addEventListener('change', () => {
  selected.zip = zipInput.files?.[0] ?? null;
  handleFiles([]);
});

for (const type of ['dragenter', 'dragover']) {
  dropzone.addEventListener(type, (e) => {
    e.preventDefault();
    dropzone.classList.add('active');
  });
}
for (const type of ['dragleave', 'drop']) {
  dropzone.addEventListener(type, (e) => {
    e.preventDefault();
    dropzone.classList.remove('active');
  });
}
dropzone.addEventListener('drop', (e) => {
  const files = e.dataTransfer?.files;
  if (files) handleFiles(files);
});
dropzone.addEventListener('click', () => {
  pdfInput.click();
});
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    pdfInput.click();
  }
});
verifyButton.addEventListener('click', () => {
  void verify();
});
clearButton.addEventListener('click', () => {
  selected.pdf = null;
  selected.proof = null;
  selected.zip = null;
  pdfInput.value = '';
  proofInput.value = '';
  zipInput.value = '';
  result.hidden = true;
  result.replaceChildren();
  updateButtons();
});

updateButtons();
