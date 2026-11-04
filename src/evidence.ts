import { unzipSync, type UnzipFileInfo } from 'fflate';
import { z } from 'zod';
import { bytesToBase64, bytesToUtf8, constantTimeEqualHex } from './bytes.js';
import { sha256Hex } from './hash.js';
import { verifyLedgerSegment, type LedgerSegmentResult } from './ledger.js';
import { messageOf } from './signature.js';
import { prepareOptions, verifySealedPdf } from './verify.js';
import type { LedgerEntry, Overall, Verdict, VerifyOptions } from './types.js';

/**
 * Largest single ZIP entry that is inflated (256 MiB). An archive is a few
 * PDFs and some JSON; anything larger is either a mistake or a decompression
 * bomb, and inflating it would exhaust the tab or process before any check
 * could fail closed.
 */
export const MAX_ENTRY_BYTES = 256 * 1024 * 1024;

export type EntryDisposition = 'inflate' | 'skip' | 'too-large';

/**
 * Which ZIP entries are inflated at all: only the paths the verifier reads
 * (README, seals, ledger segment, documents), each within
 * {@link MAX_ENTRY_BYTES}. Everything else (audit logs, OS metadata) is left
 * compressed and never touches memory. Matching is case-insensitive because
 * archives pass through tools that change case.
 */
export function classifyEntry(name: string, originalSize: number): EntryDisposition {
  const wanted = /(^|\/)(README\.txt|seals\/[^/]+|ledger\/segment\.json|documents\/[^/]+)$/i.test(
    name,
  );
  if (!wanted) return 'skip';
  return originalSize > MAX_ENTRY_BYTES ? 'too-large' : 'inflate';
}

const hex64 = z.string().regex(/^[0-9a-fA-F]{64}$/);

const sealFileSchema = z.looseObject({
  sealId: z.string().min(1),
  documentHash: hex64,
  publicKeyPem: z.string().optional(),
  tsaToken: z.string().nullable().optional(),
  disposition: z.string().nullable().optional(),
  roundSequence: z.number().nullable().optional(),
  supersededAt: z.string().nullable().optional(),
  supersededReason: z.string().nullable().optional(),
});

const segmentSchema = z.array(
  z.object({
    seq: z.number().int().nonnegative(),
    documentHash: hex64,
    previousEntryHash: hex64,
    entryHash: hex64,
    sealedAt: z.string().min(1),
  }),
);

export interface EvidenceDocumentResult {
  /** Path inside the ZIP. */
  path: string;
  /** SHA-256 of the PDF bytes found in the ZIP. */
  computedHash: string;
  sealId: string | null;
  /** The full verdict, or null when no seal matched this PDF. */
  verdict: Verdict | null;
  overall: Overall;
  /** Disposition from the seal file, when present (for example `superseded`). */
  disposition: string | null;
  reason?: string;
}

export interface EvidenceResult {
  overall: Overall;
  documents: EvidenceDocumentResult[];
  /** Number of seal files found under `seals/`. */
  sealCount: number;
  /** Result of the ledger segment check, or null when the ZIP has no segment. */
  ledgerSegment: LedgerSegmentResult | null;
  readme: string | null;
  notes: string[];
}

interface SealFile {
  path: string;
  data: z.infer<typeof sealFileSchema>;
}

function entriesMatching(files: Record<string, Uint8Array>, re: RegExp): [string, Uint8Array][] {
  return Object.entries(files)
    .filter(([path]) => re.test(path))
    .sort(([a], [b]) => a.localeCompare(b));
}

function readJson(bytes: Uint8Array): unknown {
  return JSON.parse(bytesToUtf8(bytes)) as unknown;
}

function overallOf(documents: EvidenceDocumentResult[]): Overall {
  if (documents.length === 0) return 'incomplete';
  if (documents.some((d) => d.overall === 'altered')) return 'altered';
  if (documents.some((d) => d.overall === 'incomplete')) return 'incomplete';
  return 'genuine';
}

/**
 * Verifies every PDF under `documents/` of an evidence ZIP against the seal
 * under `seals/` whose documentHash matches its SHA-256, and checks the
 * ledger segment when one is present. Missing optional files are tolerated.
 */
export async function verifyEvidenceZip(
  zip: Uint8Array,
  options: VerifyOptions = {},
): Promise<EvidenceResult> {
  // Fail fast on caller mistakes before any document is touched; the
  // per-document try/catch below must only ever see document problems.
  await prepareOptions(options);
  const notes: string[] = [];
  const tooLarge: string[] = [];
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(zip, {
      filter: (info: UnzipFileInfo) => {
        const disposition = classifyEntry(info.name, info.originalSize);
        if (disposition === 'too-large') tooLarge.push(info.name);
        return disposition === 'inflate';
      },
    });
  } catch (error) {
    return {
      overall: 'incomplete',
      documents: [],
      sealCount: 0,
      ledgerSegment: null,
      readme: null,
      notes: [`not a readable ZIP archive: ${messageOf(error)}`],
    };
  }

  for (const name of tooLarge)
    notes.push(`${name}: entry larger than ${MAX_ENTRY_BYTES} bytes was not inflated`);

  const readmeEntry = entriesMatching(files, /(^|\/)README\.txt$/i)[0];
  let readme: string | null = null;
  if (readmeEntry) {
    try {
      readme = bytesToUtf8(readmeEntry[1]);
    } catch {
      notes.push('README.txt is not UTF-8 text');
    }
  }

  // Seals
  const seals: SealFile[] = [];
  for (const [path, bytes] of entriesMatching(files, /(^|\/)seals\/[^/]+\.json$/i)) {
    try {
      const parsed = sealFileSchema.safeParse(readJson(bytes));
      if (!parsed.success) {
        notes.push(`${path}: not a seal file (${parsed.error.issues[0]?.message ?? 'invalid'})`);
        continue;
      }
      seals.push({ path, data: parsed.data });
    } catch (error) {
      notes.push(`${path}: unreadable (${messageOf(error)})`);
    }
  }

  // Ledger segment
  let segment: LedgerEntry[] | null = null;
  let ledgerSegment: LedgerSegmentResult | null = null;
  const segmentEntry = entriesMatching(files, /(^|\/)ledger\/segment\.json$/i)[0];
  if (segmentEntry) {
    try {
      const parsed = segmentSchema.safeParse(readJson(segmentEntry[1]));
      if (parsed.success) {
        segment = parsed.data.map((e) => ({
          ...e,
          documentHash: e.documentHash.toLowerCase(),
          previousEntryHash: e.previousEntryHash.toLowerCase(),
          entryHash: e.entryHash.toLowerCase(),
        }));
        ledgerSegment = await verifyLedgerSegment(segment);
      } else {
        ledgerSegment = {
          ok: false,
          count: 0,
          from: null,
          to: null,
          reason: `segment.json is malformed: ${parsed.error.issues[0]?.message ?? 'invalid'}`,
        };
      }
    } catch (error) {
      ledgerSegment = {
        ok: false,
        count: 0,
        from: null,
        to: null,
        reason: `segment.json is unreadable: ${messageOf(error)}`,
      };
    }
  }

  // Documents
  const documents: EvidenceDocumentResult[] = [];
  const usedSeals = new Set<string>();
  for (const [path, bytes] of entriesMatching(files, /(^|\/)documents\/[^/]+\.pdf$/i)) {
    const computedHash = await sha256Hex(bytes);
    const matches = seals.filter((s) => constantTimeEqualHex(s.data.documentHash, computedHash));
    const seal = matches[0];
    if (!seal) {
      documents.push({
        path,
        computedHash,
        sealId: null,
        verdict: null,
        overall: 'incomplete',
        disposition: null,
        reason: 'no seal in the archive matches this PDF',
      });
      continue;
    }
    usedSeals.add(seal.path);
    if (matches.length > 1)
      notes.push(
        `${path}: ${matches.length} seals match this PDF; the first (${seal.path}) was used`,
      );
    // Anything that goes wrong while assembling this document's proof (a
    // key file that is not UTF-8, for instance) is this document's problem:
    // report it as incomplete and carry on with the rest of the archive.
    let verdict: Verdict;
    try {
      verdict = await verifySealedPdf({
        pdf: bytes,
        proof: JSON.stringify(assembleProof(seal, files, segment, computedHash)),
        options,
      });
    } catch (error) {
      documents.push({
        path,
        computedHash,
        sealId: seal.data.sealId,
        verdict: null,
        overall: 'incomplete',
        disposition: seal.data.disposition ?? null,
        reason: `seal ${seal.path} could not be assembled: ${messageOf(error)}`,
      });
      continue;
    }
    const disposition = seal.data.disposition ?? null;
    const result: EvidenceDocumentResult = {
      path,
      computedHash,
      sealId: seal.data.sealId,
      verdict,
      overall: verdict.overall,
      disposition,
    };
    if (verdict.error !== undefined) result.reason = verdict.error;
    if (disposition !== null && disposition !== 'active') {
      const when = seal.data.supersededAt ? ` at ${seal.data.supersededAt}` : '';
      const why = seal.data.supersededReason ? ` (${seal.data.supersededReason})` : '';
      notes.push(`${path}: seal ${seal.data.sealId} is marked ${disposition}${when}${why}`);
    }
    documents.push(result);
  }
  // A seal with no document is not a failure (the archive may be partial),
  // but a reader must be able to see that something the issuer sealed is
  // not in front of them.
  for (const seal of seals)
    if (!usedSeals.has(seal.path))
      notes.push(`${seal.path}: seal ${seal.data.sealId} matches no document in the archive`);

  let overall = overallOf(documents);
  if (overall === 'genuine' && ledgerSegment && !ledgerSegment.ok) overall = 'altered';
  if (overall === 'genuine' && tooLarge.length > 0) overall = 'incomplete';
  if (documents.length === 0) notes.push('the archive contains no documents/*.pdf');
  return { overall, documents, sealCount: seals.length, ledgerSegment, readme, notes };
}

/**
 * Builds the proof object for one document from its seal file. Older
 * archives kept the public key and the raw token next to the seal JSON
 * (`<seal>.public-key.pem`, `<seal>.tsr`) instead of inside it; both forms
 * are read so an archive produced by either generation verifies. The ledger
 * block comes from the segment, which is the authoritative copy in an
 * archive. Throws on an unreadable side file; the caller reports it.
 */
function assembleProof(
  seal: SealFile,
  files: Record<string, Uint8Array>,
  segment: LedgerEntry[] | null,
  computedHash: string,
): Record<string, unknown> {
  const base = seal.path.replace(/\.json$/i, '');
  const pemFile = files[`${base}.public-key.pem`];
  const tsrFile = files[`${base}.tsr`];
  const proof: Record<string, unknown> = { ...seal.data, schemaVersion: 1 };
  if (!proof.publicKeyPem && pemFile) proof.publicKeyPem = bytesToUtf8(pemFile);
  if (!proof.tsaToken && tsrFile) proof.tsaToken = bytesToBase64(tsrFile);
  delete proof.ledger;
  const entry = segment?.find((e) => constantTimeEqualHex(e.documentHash, computedHash));
  if (entry)
    proof.ledger = {
      seq: entry.seq,
      previousEntryHash: entry.previousEntryHash,
      entryHash: entry.entryHash,
    };
  return proof;
}
