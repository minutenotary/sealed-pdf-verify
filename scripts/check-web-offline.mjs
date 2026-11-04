#!/usr/bin/env node
// Fails when the built browser page contains anything that could reach the
// network: a fetch/XHR/WebSocket/beacon call, a dynamic import, or an external
// script, stylesheet or font. The page promises "no network requests"; this
// keeps a dependency bump from quietly breaking that promise.
import { readFileSync } from 'node:fs';

const path = new URL('../web/dist/index.html', import.meta.url);
let html;
try {
  html = readFileSync(path, 'utf8');
} catch {
  console.error('web check: web/dist/index.html not found; run `npm run build:web` first');
  process.exit(1);
}

const patterns = [
  [/\bfetch\s*\(/, 'fetch('],
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bnew\s+WebSocket\s*\(/, 'WebSocket'],
  [/\bsendBeacon\s*\(/, 'sendBeacon'],
  [/\bnew\s+EventSource\s*\(/, 'EventSource'],
  [/\bimport\s*\(\s*["'`]https?:/, 'dynamic import of a URL'],
  [/<script[^>]+src\s*=\s*["']https?:/i, 'external <script src>'],
  [/<link[^>]+href\s*=\s*["']https?:/i, 'external <link href>'],
  [/url\(\s*["']?https?:/i, 'external url() in CSS'],
];
const problems = patterns.filter(([re]) => re.test(html)).map(([, label]) => label);
if (problems.length > 0) {
  console.error(`web check FAILED: web/dist/index.html contains ${problems.join(', ')}`);
  process.exit(1);
}
console.log(`web check passed (${(html.length / 1024).toFixed(0)} KB, no network code)`);
