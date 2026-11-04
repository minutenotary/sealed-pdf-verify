import { base64ToBytes, bytesToBase64 } from './bytes.js';

export interface PemBlock {
  label: string;
  der: Uint8Array;
}

const BEGIN_RE = /-----BEGIN ([A-Z0-9 ]+)-----/g;
const END_RE = /-----END ([A-Z0-9 ]+)-----/g;

/** Where each END marker starts, by label, in text order (overlapping markers included). */
function endMarkers(text: string): Map<string, number[]> {
  const ends = new Map<string, number[]>();
  const re = new RegExp(END_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const label = m[1] ?? '';
    const list = ends.get(label) ?? [];
    list.push(m.index);
    ends.set(label, list);
    re.lastIndex = m.index + 1;
  }
  return ends;
}

/**
 * Every PEM block in the text, in order. Invalid base64 inside a block throws.
 *
 * A block runs from a BEGIN line to the first END line of the same label. The
 * END markers are indexed once up front, so text with many BEGIN lines and no
 * END stays linear (a single lazy regex is quadratic on it).
 */
export function pemBlocks(text: string): PemBlock[] {
  const ends = endMarkers(text);
  const cursor = new Map<string, number>();
  const blocks: PemBlock[] = [];
  const begin = new RegExp(BEGIN_RE.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = begin.exec(text)) !== null) {
    const label = m[1] ?? '';
    const bodyStart = m.index + m[0].length;
    const list = ends.get(label) ?? [];
    // BEGIN lines are visited left to right, so each label's cursor only moves forward.
    let i = cursor.get(label) ?? 0;
    let end = list[i];
    while (end !== undefined && end < bodyStart) {
      i += 1;
      end = list[i];
    }
    cursor.set(label, i);
    if (end === undefined) {
      begin.lastIndex = m.index + 1;
      continue;
    }
    blocks.push({ label, der: base64ToBytes(text.slice(bodyStart, end)) });
    begin.lastIndex = end + `-----END ${label}-----`.length;
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
