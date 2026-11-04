import { base64ToBytes, bytesToBase64 } from './bytes.js';

export interface PemBlock {
  label: string;
  der: Uint8Array;
}

const PEM_RE = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

/** Every PEM block in the text, in order. Invalid base64 inside a block throws. */
export function pemBlocks(text: string): PemBlock[] {
  const blocks: PemBlock[] = [];
  for (const match of text.matchAll(PEM_RE)) {
    const label = match[1] ?? '';
    const body = match[2] ?? '';
    blocks.push({ label, der: base64ToBytes(body) });
  }
  return blocks;
}

/** The DER of the single block with the given label; throws when absent or ambiguous. */
export function pemToDer(text: string, label: string): Uint8Array {
  const blocks = pemBlocks(text).filter((b) => b.label === label);
  const first = blocks[0];
  if (!first || blocks.length !== 1) {
    throw new Error(`expected exactly one "${label}" PEM block, found ${blocks.length}`);
  }
  return first.der;
}

export function derToPem(der: Uint8Array, label: string): string {
  const b64 = bytesToBase64(der);
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}
