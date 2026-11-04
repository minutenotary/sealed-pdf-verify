import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import {
  pemBlocks,
  verifyEvidenceZip,
  verifySealedPdf,
  type EvidenceResult,
  type Verdict,
  type VerifyInput,
  type VerifyOptions,
} from '../src/index.js';

// Injected by the build (tsup `define`); absent when the source runs directly.
declare const __SPV_VERSION__: string | undefined;
const VERSION = typeof __SPV_VERSION__ === 'string' ? __SPV_VERSION__ : 'dev';

export interface CliIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

export const EXIT_GENUINE = 0;
export const EXIT_ALTERED = 1;
export const EXIT_INCOMPLETE = 2;

/**
 * Characters that can move the cursor, hide text or reorder it on a terminal:
 * C0 and C1 controls (except TAB), DEL, the Unicode line separators, the
 * soft hyphen, zero-width characters and the bidirectional embedding /
 * override / isolate controls (a right-to-left override turns "ALTERED" into
 * "DERETLA" on screen).
 */
const TERMINAL_UNSAFE =
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  /[\u0000-\u0008\u000a-\u001f\u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/**
 * Removes {@link TERMINAL_UNSAFE} characters from a line before it reaches a
 * terminal. Proof fields (seal id, key id, URLs) and archive paths are
 * attacker-controlled text; an escape sequence or a bare newline in one of
 * them could move the cursor and overwrite the verdict line a person reads.
 */
export function sanitizeForTerminal(line: string): string {
  return line.replace(TERMINAL_UNSAFE, '');
}

/**
 * The part of {@link TERMINAL_UNSAFE} that `JSON.stringify` leaves raw: it
 * escapes U+0000–U+001F itself, but C1 controls, the soft hyphen, zero-width
 * and bidi characters and U+2028/9 are legal inside a JSON string.
 */
const JSON_UNSAFE = /[\u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/**
 * JSON for `--json`: the pretty-printed value with {@link JSON_UNSAFE}
 * characters written as `\\uXXXX`, which is the same JSON value to any parser
 * (the line feeds of the pretty-printing are structure, not string content,
 * and stay).
 */
export function jsonForTerminal(value: unknown): string {
  return JSON.stringify(value, null, 2).replace(
    JSON_UNSAFE,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
}

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
  -v, --version        print the version
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
  version: boolean;
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
      version: { type: 'boolean', short: 'v', default: false },
    },
  });
  const parsed: ParsedArgs = {
    positionals,
    tsaRoots: values['tsa-roots'] ?? [],
    builtinRoots: !values['no-builtin-roots'],
    tsaTrust: !values['no-tsa-trust'],
    json: values.json,
    help: values.help,
    version: values.version,
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
  // The library honours an empty list as "trust nobody" and rejects every
  // key; from the command line that can only be an unfilled trust file, so
  // refuse it as a usage error instead of reporting the document as altered.
  if (list.length === 0) {
    throw new Error(
      `${path}: the trust list is empty; add the issuer's key fingerprint(s) before using --trust`,
    );
  }
  return list;
}

function loadRoots(path: string): string {
  const text = readFileSync(path, 'utf8');
  if (!pemBlocks(text).some((block) => block.label === 'CERTIFICATE')) {
    throw new Error(`${path}: no CERTIFICATE block found (expected a PEM root certificate)`);
  }
  return text;
}

function buildOptions(args: ParsedArgs): VerifyOptions {
  if (!args.builtinRoots && args.tsaRoots.length === 0 && args.tsaTrust) {
    throw new Error(
      '--no-builtin-roots leaves no root to trust: add --tsa-roots <file> or --no-tsa-trust',
    );
  }
  const options: VerifyOptions = {
    useBuiltInTsaRoots: args.builtinRoots,
    checkTimestampTrust: args.tsaTrust,
  };
  if (args.trust !== undefined) options.trustedKeyFingerprints = loadTrust(args.trust);
  if (args.tsaRoots.length > 0) options.tsaRootsPem = args.tsaRoots.map(loadRoots);
  return options;
}

/** ZIP local-file-header or empty-archive signature ("PK\x03\x04" / "PK\x05\x06"). */
function looksLikeZip(bytes: Uint8Array): boolean {
  return (
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    (bytes[2] === 0x03 || bytes[2] === 0x05) &&
    bytes[3] === bytes[2] + 1
  );
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
  return lines.map(sanitizeForTerminal);
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
  return lines.map(sanitizeForTerminal);
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
  if (args.version) {
    io.out(`sealed-pdf-verify ${VERSION}`);
    return EXIT_GENUINE;
  }
  try {
    const options = buildOptions(args);
    const [target, extra] = args.positionals;
    if (extra !== undefined) throw new Error('expected at most one file argument');
    const targetBytes = target === undefined ? null : new Uint8Array(readFileSync(target));

    // The file's own bytes decide what it is; an extension is only a hint.
    if (targetBytes !== null && looksLikeZip(targetBytes)) {
      if (args.proof !== undefined)
        throw new Error('an evidence archive carries its own seals and does not take --proof');
      const result = await verifyEvidenceZip(targetBytes, options);
      if (args.json) io.out(jsonForTerminal(result));
      else for (const line of formatEvidence(result)) io.out(line);
      return exitCode(result.overall);
    }
    if (target !== undefined && /\.zip$/i.test(target))
      throw new Error(`${target}: not a ZIP archive`);

    if (args.proof === undefined)
      throw new Error('--proof <proof.json> is required (or pass an evidence .zip)');
    const proof = readFileSync(args.proof, 'utf8');
    const input: VerifyInput = { proof, options };
    if (targetBytes !== null) input.pdf = targetBytes;
    const verdict = await verifySealedPdf(input);
    if (args.json) io.out(jsonForTerminal(verdict));
    else for (const line of formatVerdict(verdict)) io.out(line);
    return exitCode(verdict.overall);
  } catch (error) {
    io.err(`error: ${error instanceof Error ? error.message : String(error)}`);
    return EXIT_INCOMPLETE;
  }
}
