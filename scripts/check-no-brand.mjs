#!/usr/bin/env node
// Fails when src/, cli/, web/src/ or test/ mention the issuer's brand. The
// brand may appear only in README, LICENSE, package.json, docs and the
// footer of web/index.html.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const scanned = ['src', 'cli', 'web/src', 'test'];
const patterns = [/minute/i, /notary/i];

function listDir(dir) {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

function walk(dir, out) {
  for (const name of listDir(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

const hits = [];
for (const dir of scanned) {
  for (const file of walk(join(root, dir), [])) {
    const text = readFileSync(file, 'latin1');
    for (const re of patterns) {
      const m = re.exec(text);
      if (m) {
        const line = text.slice(0, m.index).split('\n').length;
        hits.push(`${relative(root, file)}:${line}: matches ${re}`);
      }
    }
  }
}

if (hits.length > 0) {
  console.error('brand check FAILED:');
  for (const h of hits) console.error('  ' + h);
  process.exit(1);
}
console.log(`brand check passed (${scanned.join(', ')})`);
