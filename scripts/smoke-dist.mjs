#!/usr/bin/env node
// After `npm run build:lib`: the ESM build, the CJS build and the bundled CLI
// must all verify the sample fixture. Run by CI.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pdf = new Uint8Array(readFileSync(join(root, 'test/fixtures/sample.pdf')));
const proof = readFileSync(join(root, 'test/fixtures/sample.proof.json'), 'utf8');

const esm = await import(join(root, 'dist/index.js'));
const esmVerdict = await esm.verifySealedPdf({ pdf, proof });
if (esmVerdict.overall !== 'genuine') throw new Error(`ESM build: ${esmVerdict.overall}`);

const require = createRequire(import.meta.url);
const cjs = require(join(root, 'dist/index.cjs'));
const cjsVerdict = await cjs.verifySealedPdf({ pdf, proof });
if (cjsVerdict.overall !== 'genuine') throw new Error(`CJS build: ${cjsVerdict.overall}`);

const cli = spawnSync(
  process.execPath,
  [
    join(root, 'dist/cli.js'),
    join(root, 'test/fixtures/sample.pdf'),
    '--proof',
    join(root, 'test/fixtures/sample.proof.json'),
  ],
  { encoding: 'utf8' },
);
if (cli.status !== 0 || !cli.stdout.includes('GENUINE'))
  throw new Error(`CLI: exit ${cli.status}\n${cli.stdout}${cli.stderr}`);
const tampered = spawnSync(
  process.execPath,
  [
    join(root, 'dist/cli.js'),
    join(root, 'test/fixtures/tampered.pdf'),
    '--proof',
    join(root, 'test/fixtures/sample.proof.json'),
  ],
  { encoding: 'utf8' },
);
if (tampered.status !== 1) throw new Error(`CLI tampered: exit ${tampered.status}`);

console.log('smoke: ESM, CJS and CLI builds verify the sample fixture');
