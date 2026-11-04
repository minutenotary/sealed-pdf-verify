/**
 * Browser verifier page: state and event wiring.
 *
 * Everything runs in the tab: the library is bundled into the page, files are
 * read with the File API and no request ever leaves the browser. This module
 * only connects the DOM to `verifySealedPdf` / `verifyEvidenceZip`; rendering
 * lives in render.ts and every verdict rule lives in the library.
 */
import { verifyEvidenceZip, verifySealedPdf } from '../../src/index.js';
import type { VerifyInput, VerifyOptions } from '../../src/index.js';
import {
  formatBytes,
  renderEvidence,
  renderFailure,
  renderSkeleton,
  renderVerdict,
} from './render.js';

type SlotKind = 'pdf' | 'proof' | 'zip';

const SLOT_PROMPT: Readonly<Record<SlotKind, string>> = {
  pdf: 'Choose a file',
  proof: 'Choose a file',
  zip: 'Or choose a .zip instead',
};

const SLOT_EXTENSION: Readonly<Record<SlotKind, string>> = {
  pdf: '.pdf',
  proof: '.json',
  zip: '.zip',
};

const DEFAULT_MESSAGE = 'Drop files anywhere on this page, or click a box to choose one.';

/** Finds a required element and checks its type at runtime, so a markup slip fails loudly. */
function query<T extends Element>(root: ParentNode, selector: string, type: new () => T): T {
  const node = root.querySelector(selector);
  if (!(node instanceof type)) throw new Error(`missing element ${selector}`);
  return node;
}

function prefersReducedMotion(): boolean {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

// ---------- State ----------

const files: Record<SlotKind, File | null> = { pdf: null, proof: null, zip: null };

interface SlotView {
  root: HTMLElement;
  pick: HTMLButtonElement;
  name: HTMLElement;
  meta: HTMLElement;
  remove: HTMLButtonElement;
  input: HTMLInputElement;
}

const slots = {} as Record<SlotKind, SlotView>;
for (const kind of ['pdf', 'proof', 'zip'] as const) {
  const root = query(document, `[data-slot="${kind}"]`, HTMLElement);
  slots[kind] = {
    root,
    pick: query(root, '.slot-pick', HTMLButtonElement),
    name: query(root, '.slot-name', HTMLElement),
    meta: query(root, '.slot-meta', HTMLElement),
    remove: query(root, '.slot-remove', HTMLButtonElement),
    input: query(root, 'input[type="file"]', HTMLInputElement),
  };
}

const fingerprints = query(document, '#fingerprints', HTMLTextAreaElement);
const verifyButton = query(document, '#verify-button', HTMLButtonElement);
const clearButton = query(document, '#clear-button', HTMLButtonElement);
const message = query(document, '#intake-message', HTMLElement);
const result = query(document, '#result', HTMLElement);

function setMessage(text: string, isError = false): void {
  message.textContent = text;
  message.classList.toggle('is-error', isError);
}

/** Reflects `files` into the three slots and the Verify button. */
function renderSlots(): void {
  const archiveMode = files.zip !== null;
  for (const kind of ['pdf', 'proof', 'zip'] as const) {
    const view = slots[kind];
    const file = files[kind];
    view.root.classList.toggle('is-filled', file !== null);
    view.root.classList.toggle('is-dimmed', kind !== 'zip' && archiveMode);
    view.name.textContent = file === null ? SLOT_PROMPT[kind] : file.name;
    view.meta.textContent = file === null ? SLOT_EXTENSION[kind] : formatBytes(file.size);
    view.remove.hidden = file === null;
  }
  verifyButton.disabled = files.zip === null && files.proof === null;
}

/** Assigns a file to its slot by extension. Returns false for anything else. */
function accept(file: File): boolean {
  const name = file.name.toLowerCase();
  let kind: SlotKind;
  if (name.endsWith('.zip')) kind = 'zip';
  else if (name.endsWith('.json')) kind = 'proof';
  else if (name.endsWith('.pdf')) kind = 'pdf';
  else return false;
  // A PDF + proof pair and an archive are two different inputs; keep one mode.
  if (kind === 'zip') {
    files.pdf = null;
    files.proof = null;
  } else {
    files.zip = null;
  }
  files[kind] = file;
  return true;
}

function clearResult(): void {
  result.hidden = true;
  result.replaceChildren();
  result.setAttribute('aria-busy', 'false');
}

function showResult(node: HTMLElement, { busy = false } = {}): void {
  // Unhide first, then fill: a live region announces content that changes
  // while it is visible, not content that appears together with it.
  result.hidden = false;
  result.setAttribute('aria-busy', busy ? 'true' : 'false');
  result.replaceChildren(node);
  if (!busy) {
    result.classList.remove('result-enter');
    // Restarting the animation needs a layout flush between remove and add.
    result.getBoundingClientRect();
    result.classList.add('result-enter');
    const word = result.querySelector('.verdict-word');
    if (word instanceof HTMLElement) word.focus({ preventScroll: true });
  }
  result.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
}

function options(): VerifyOptions {
  const lines = fingerprints.value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.length > 0 ? { trustedKeyFingerprints: lines } : {};
}

async function verify(): Promise<void> {
  verifyButton.disabled = true;
  showResult(renderSkeleton(), { busy: true });
  try {
    if (files.zip !== null) {
      const bytes = new Uint8Array(await files.zip.arrayBuffer());
      showResult(renderEvidence(await verifyEvidenceZip(bytes, options())));
    } else if (files.proof !== null) {
      const input: VerifyInput = {
        proof: new Uint8Array(await files.proof.arrayBuffer()),
        options: options(),
      };
      if (files.pdf !== null) input.pdf = new Uint8Array(await files.pdf.arrayBuffer());
      showResult(renderVerdict(await verifySealedPdf(input)));
    } else {
      showResult(renderFailure('Choose a proof file (with its PDF) or an evidence archive first.'));
    }
  } catch (error) {
    showResult(renderFailure(error instanceof Error ? error.message : String(error)));
  } finally {
    renderSlots();
  }
}

/** After any change to `files`: update the slots, guide the next step, auto-run when complete. */
function filesChanged(): void {
  renderSlots();
  const complete = files.zip !== null || (files.pdf !== null && files.proof !== null);
  if (complete) {
    setMessage(DEFAULT_MESSAGE);
    void verify();
    return;
  }
  clearResult();
  if (files.pdf !== null) setMessage('Now add the proof file (.json) that came with the PDF.');
  else if (files.proof !== null)
    setMessage(
      'Add the PDF to check the document itself, or press Verify to check the proof alone.',
    );
  else setMessage(DEFAULT_MESSAGE);
}

function acceptFiles(list: ArrayLike<File>): void {
  const rejected: string[] = [];
  for (const file of Array.from(list)) if (!accept(file)) rejected.push(file.name);
  filesChanged();
  if (rejected.length > 0)
    setMessage(`Ignored ${rejected.join(', ')}: only .pdf, .json and .zip files are used.`, true);
}

// ---------- Events ----------

for (const kind of ['pdf', 'proof', 'zip'] as const) {
  const view = slots[kind];
  view.pick.addEventListener('click', () => {
    view.input.click();
  });
  view.input.addEventListener('change', () => {
    const file = view.input.files?.[0];
    if (file) acceptFiles([file]);
    // Let the same file be chosen again after Clear.
    view.input.value = '';
  });
  view.remove.addEventListener('click', () => {
    files[kind] = null;
    filesChanged();
    view.pick.focus();
  });
}

verifyButton.addEventListener('click', () => {
  void verify();
});

clearButton.addEventListener('click', () => {
  files.pdf = null;
  files.proof = null;
  files.zip = null;
  fingerprints.value = '';
  clearResult();
  filesChanged();
});

// The whole page is a drop target. dragenter/dragleave fire for every nested
// element the pointer crosses, so a depth counter tells a real leave apart.
let dragDepth = 0;

function hasFiles(event: DragEvent): boolean {
  return event.dataTransfer?.types.includes('Files') ?? false;
}

document.addEventListener('dragenter', (event) => {
  if (!hasFiles(event)) return;
  event.preventDefault();
  dragDepth += 1;
  document.body.classList.add('is-dragging');
});
document.addEventListener('dragover', (event) => {
  if (!hasFiles(event)) return;
  event.preventDefault();
});
document.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) document.body.classList.remove('is-dragging');
});
document.addEventListener('drop', (event) => {
  event.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('is-dragging');
  const dropped = event.dataTransfer?.files;
  if (dropped && dropped.length > 0) acceptFiles(dropped);
});

renderSlots();
