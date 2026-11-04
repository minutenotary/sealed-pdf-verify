import { unzipSync } from 'fflate';
import { z } from 'zod';
import { bytesToBase64, bytesToUtf8, constantTimeEqualHex } from './bytes.js';
import { sha256Hex } from './hash.js';
import { verifyLedgerSegment, type LedgerSegmentResult } from './ledger.js';
import { messageOf } from './signature.js';
import { verifySealedPdf } from './verify.js';
import type { LedgerEntry, Overall, Verdict, VerifyOptions } from './types.js';

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
  const notes: string[] = [];
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(zip);
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

  const readmeEntry = entriesMatching(files, /(^|\/)README\.txt$/)[0];
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
  for (const [path, bytes] of entriesMatching(files, /(^|\/)seals\/[^/]+\.json$/)) {
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
  const segmentEntry = entriesMatching(files, /(^|\/)ledger\/segment\.json$/)[0];
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
    if (matches.length > 1)
      notes.push(
        `${path}: ${matches.length} seals match this PDF; the first (${seal.path}) was used`,
      );
    const base = seal.path.replace(/\.json$/, '');
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
    const verdict = await verifySealedPdf({ pdf: bytes, proof: JSON.stringify(proof), options });
    const disposition = seal.data.disposition ?? null;
    const result: EvidenceDocumentResult = {
      path,
      computedHash,
      sealId: seal.data.sealId,
      verdict,
      overall: verdict.overall,
      disposition,
    };
    if (verdict.error) result.reason = verdict.error;
    if (disposition && disposition !== 'active') {
      const when = seal.data.supersededAt ? ` at ${seal.data.supersededAt}` : '';
      const why = seal.data.supersededReason ? ` (${seal.data.supersededReason})` : '';
      notes.push(`${path}: seal ${seal.data.sealId} is marked ${disposition}${when}${why}`);
    }
    documents.push(result);
  }

  let overall = overallOf(documents);
  if (overall === 'genuine' && ledgerSegment && !ledgerSegment.ok) overall = 'altered';
  if (documents.length === 0) notes.push('the archive contains no documents/*.pdf');
  return { overall, documents, sealCount: seals.length, ledgerSegment, readme, notes };
}
