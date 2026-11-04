import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  verifyEvidenceZip,
  verifySealedPdf,
  type EvidenceResult,
  type Verdict,
  type VerifyOptions,
} from '../src/index.js';

export interface CliIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

export const EXIT_GENUINE = 0;
export const EXIT_ALTERED = 1;
export const EXIT_INCOMPLETE = 2;

const USAGE = `Usage:
  sealed-pdf-verify <file.pdf> --proof <proof.json> [options]
  sealed-pdf-verify --proof <proof.json> [options]        (proof-only: PDF bytes are not checked)
  sealed-pdf-verify <evidence.zip> [options]

Options:
  --proof <file>       proof sidecar JSON delivered next to the sealed PDF
  --trust <file>       JSON { "fingerprints": [...] } of trusted signing keys (key: pinned/rejected)
  --tsa-roots <file>   extra PEM root certificate(s) for the timestamp authority (repeatable)
  --no-builtin-roots   do not trust the DigiCert / FreeTSA roots shipped with the package
  --no-tsa-trust       skip the timestamp signer-chain check (timestamp: imprint_only at best)
  --json               print the verdict object as JSON
  -h, --help           show this help

Exit status: 0 genuine, 1 altered, 2 incomplete or error.`;

interface ParsedArgs {
  positionals: string[];
  proof?: string;
  trust?: string;
  tsaRoots: string[];
  builtinRoots: boolean;
  tsaTrust: boolean;
  json: boolean;
  help: boolean;
}

function parse(argv: string[]): ParsedArgs {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      proof: { type: 'string' },
      trust: { type: 'string' },
      'tsa-roots': { type: 'string', multiple: true },
      'no-builtin-roots': { type: 'boolean', default: false },
      'no-tsa-trust': { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  const parsed: ParsedArgs = {
    positionals,
    tsaRoots: values['tsa-roots'] ?? [],
    builtinRoots: !values['no-builtin-roots'],
    tsaTrust: !values['no-tsa-trust'],
    json: values.json,
    help: values.help,
  };
  if (values.proof !== undefined) parsed.proof = values.proof;
  if (values.trust !== undefined) parsed.trust = values.trust;
  return parsed;
}

function loadTrust(path: string): string[] {
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
  const list: unknown =
    typeof raw === 'object' && raw !== null
      ? (raw as { fingerprints?: unknown }).fingerprints
      : undefined;
  if (!Array.isArray(list) || !list.every((x): x is string => typeof x === 'string')) {
    throw new Error(`${path}: expected { "fingerprints": [ "<sha256 hex>", ... ] }`);
  }
  return list;
}

function buildOptions(args: ParsedArgs): VerifyOptions {
  const options: VerifyOptions = {
    useBuiltInTsaRoots: args.builtinRoots,
    checkTimestampTrust: args.tsaTrust,
  };
  if (args.trust !== undefined) options.trustedKeyFingerprints = loadTrust(args.trust);
  if (args.tsaRoots.length > 0)
    options.tsaRootsPem = args.tsaRoots.map((p) => readFileSync(p, 'utf8'));
  return options;
}

const CHECK_LABELS: Record<keyof Verdict['checks'], string> = {
  hash: 'hash',
  signature: 'signature',
  key: 'key',
  timestamp: 'timestamp',
  ledger: 'ledger',
};

export function formatVerdict(verdict: Verdict): string[] {
  const lines: string[] = [];
  lines.push(
    `Verdict: ${verdict.overall.toUpperCase()}${verdict.mode === 'proof-only' ? ' (proof-only: PDF bytes not checked)' : ''}`,
  );
  if (verdict.error) lines.push(`  error: ${verdict.error}`);
  lines.push('');
  for (const name of Object.keys(CHECK_LABELS) as (keyof Verdict['checks'])[]) {
    lines.push(
      `  ${CHECK_LABELS[name].padEnd(10)} ${verdict.checks[name].padEnd(13)} ${verdict.reasons[name]}`,
    );
  }
  const f = verdict.facts;
  if (f) {
    lines.push('');
    lines.push(`  Seal id        ${f.sealId}`);
    lines.push(`  Sealed digest  ${f.documentHash}`);
    if (f.computedHash !== null && f.computedHash !== f.documentHash)
      lines.push(`  PDF digest     ${f.computedHash}`);
    lines.push(
      `  Key            ${f.fingerprint ?? '(unparseable)'}${f.keyId ? `  (id ${f.keyId}${f.keyVersion ? `, version ${f.keyVersion}` : ''})` : ''}`,
    );
    lines.push(`  Sealed at      ${f.sealedAt}`);
    lines.push(`  Timestamp      ${f.timestampTime ?? '-'}${f.tsaUrl ? `  (${f.tsaUrl})` : ''}`);
    if (f.verifyUrl) lines.push(`  Online check   ${f.verifyUrl}`);
    lines.push(`  Algorithm      ${f.algorithm}`);
  }
  for (const note of verdict.notes) lines.push(`  note: ${note}`);
  return lines;
}

export function formatEvidence(result: EvidenceResult): string[] {
  const lines: string[] = [];
  lines.push(
    `Evidence archive: ${result.overall.toUpperCase()}  (${result.documents.length} document(s), ${result.sealCount} seal(s))`,
  );
  for (const doc of result.documents) {
    lines.push('');
    lines.push(
      `== ${doc.path}${doc.sealId ? `  seal ${doc.sealId}` : ''}${doc.disposition && doc.disposition !== 'active' ? `  [${doc.disposition}]` : ''}`,
    );
    if (doc.verdict) {
      for (const line of formatVerdict(doc.verdict)) lines.push(line);
    } else {
      lines.push(`Verdict: ${doc.overall.toUpperCase()}`);
      lines.push(`  ${doc.reason ?? ''}`);
      lines.push(`  PDF digest     ${doc.computedHash}`);
    }
  }
  lines.push('');
  if (result.ledgerSegment) {
    const seg = result.ledgerSegment;
    const range =
      seg.from !== null && seg.to !== null ? `entries #${seg.from}..#${seg.to}` : 'no entries';
    lines.push(
      `  Ledger segment ${seg.ok ? 'consistent' : 'INCONSISTENT'}  (${range}, ${seg.count} checked)${seg.reason ? `  ${seg.reason}` : ''}`,
    );
  } else {
    lines.push('  Ledger segment not present in the archive');
  }
  for (const note of result.notes) lines.push(`  note: ${note}`);
  return lines;
}

function exitCode(overall: Verdict['overall']): number {
  if (overall === 'genuine') return EXIT_GENUINE;
  if (overall === 'altered') return EXIT_ALTERED;
  return EXIT_INCOMPLETE;
}

/** Runs the CLI; returns the exit status instead of exiting so it can be tested. */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  let args: ParsedArgs;
  try {
    args = parse(argv);
  } catch (error) {
    io.err(error instanceof Error ? error.message : String(error));
    io.err(USAGE);
    return EXIT_INCOMPLETE;
  }
  if (args.help) {
    io.out(USAGE);
    return EXIT_GENUINE;
  }
  try {
    const options = buildOptions(args);
    const [target, extra] = args.positionals;
    if (extra !== undefined) throw new Error('expected at most one file argument');

    if (target !== undefined && /\.zip$/i.test(target) && args.proof === undefined) {
      const result = await verifyEvidenceZip(new Uint8Array(readFileSync(target)), options);
      if (args.json) io.out(JSON.stringify(result, null, 2));
      else for (const line of formatEvidence(result)) io.out(line);
      return exitCode(result.overall);
    }

    if (args.proof === undefined)
      throw new Error('--proof <proof.json> is required (or pass an evidence .zip)');
    const proof = readFileSync(args.proof, 'utf8');
    const input: Parameters<typeof verifySealedPdf>[0] = { proof, options };
    if (target !== undefined) input.pdf = new Uint8Array(readFileSync(target));
    const verdict = await verifySealedPdf(input);
    if (args.json) io.out(JSON.stringify(verdict, null, 2));
    else for (const line of formatVerdict(verdict)) io.out(line);
    return exitCode(verdict.overall);
  } catch (error) {
    io.err(`error: ${error instanceof Error ? error.message : String(error)}`);
    return EXIT_INCOMPLETE;
  }
}
