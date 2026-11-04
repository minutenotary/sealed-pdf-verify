import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ProofV1 } from '../src/index.js';

export const FIXTURES = join(import.meta.dirname, 'fixtures');

export function fx(name: string): string {
  return join(FIXTURES, name);
}

export function readBytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(fx(name)));
}

export function readText(name: string): string {
  return readFileSync(fx(name), 'utf8');
}

export function readJson(name: string): unknown {
  return JSON.parse(readText(name));
}

export function readProof(name: string): ProofV1 {
  return readJson(name) as ProofV1;
}

export interface FixtureFacts {
  signer: string;
  other: string;
  sampleHash: string;
  secondHash: string;
  genTime: string;
}

export const facts = readJson('fingerprints.json') as FixtureFacts;
