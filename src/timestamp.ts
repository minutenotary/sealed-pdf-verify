import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { AsnConvert } from '@peculiar/asn1-schema';
import {
  ContentInfo,
  SignedData,
  id_contentType,
  id_data,
  id_signedData,
} from '@peculiar/asn1-cms';
import { TSTInfo, id_ct_tstInfo } from '@peculiar/asn1-tsp';
import { base64ToBytes, constantTimeEqual, hexToBytes, isHex, toArrayBuffer } from './bytes.js';
import { pemBlocks } from './pem.js';
import { messageOf } from './signature.js';

/** id-sha256 (NIST), the only imprint algorithm accepted. */
export const SHA256_OID = '2.16.840.1.101.3.4.2.1';
/** id-kp-timeStamping (RFC 3161 §2.3). */
export const TIMESTAMPING_EKU_OID = '1.3.6.1.5.5.7.3.8';
const EXT_KEY_USAGE_OID = '2.5.29.37';

export interface ParsedTimestampToken {
  der: Uint8Array;
  tstInfo: TSTInfo;
  /** `TSTInfo.genTime`. */
  genTime: Date;
}

function tokenBytes(token: string | Uint8Array): Uint8Array {
  return typeof token === 'string' ? base64ToBytes(token) : token;
}

/**
 * Parses a DER RFC 3161 TimeStampToken: CMS ContentInfo(id-signedData) whose
 * encapsulated content is id-ct-TSTInfo with a DER TSTInfo. Throws on any
 * structural problem.
 */
export function parseTimestampToken(token: string | Uint8Array): ParsedTimestampToken {
  const der = tokenBytes(token);
  const contentInfo = AsnConvert.parse(der, ContentInfo);
  if (contentInfo.contentType !== id_signedData) {
    throw new Error(`token contentType ${contentInfo.contentType} is not id-signedData`);
  }
  const signedData = AsnConvert.parse(contentInfo.content, SignedData);
  const encap = signedData.encapContentInfo;
  if (encap.eContentType !== id_ct_tstInfo) {
    throw new Error(`token eContentType ${encap.eContentType} is not id-ct-TSTInfo`);
  }
  const single = encap.eContent?.single;
  if (!single) throw new Error('token has no encapsulated TSTInfo content');
  const tstInfo = AsnConvert.parse(single.buffer, TSTInfo);
  const genTime = tstInfo.genTime;
  if (!(genTime instanceof Date) || Number.isNaN(genTime.getTime())) {
    throw new Error('TSTInfo genTime is not a valid time');
  }
  // RFC 5652 §11.1: the signed content-type attribute must name the eContentType.
  const signer = signedData.signerInfos[0];
  if (!signer) throw new Error('token has no SignerInfo');
  const contentTypeAttr = signer.signedAttrs?.find((a) => a.attrType === id_contentType);
  const attrValue = contentTypeAttr?.attrValues[0];
  if (!attrValue) throw new Error('token signed attributes lack content-type');
  const parsed = asn1js.fromBER(attrValue);
  if (parsed.offset === -1 || !(parsed.result instanceof asn1js.ObjectIdentifier)) {
    throw new Error('token content-type attribute is malformed');
  }
  if (parsed.result.valueBlock.toString() !== id_ct_tstInfo) {
    throw new Error('token content-type attribute does not name id-ct-TSTInfo');
  }
  return { der, tstInfo, genTime };
}

export interface ImprintInput {
  token: string | Uint8Array;
  /** The document digest, 32 bytes or 64 hex characters. */
  digest: Uint8Array | string;
}

export interface ImprintResult {
  ok: boolean;
  genTime: Date | null;
  reason?: string;
}

/**
 * Required check: `messageImprint.hashAlgorithm` is SHA-256 and
 * `hashedMessage` equals the document digest (constant-time).
 */
export function verifyTimestampImprint(input: ImprintInput): Promise<ImprintResult> {
  return Promise.resolve(verifyTimestampImprintSync(input));
}

/** Synchronous form of {@link verifyTimestampImprint}. */
export function verifyTimestampImprintSync(input: ImprintInput): ImprintResult {
  let digest: Uint8Array;
  if (typeof input.digest === 'string') {
    if (!isHex(input.digest, 32))
      return { ok: false, genTime: null, reason: 'digest must be 64 hex characters' };
    digest = hexToBytes(input.digest);
  } else {
    digest = input.digest;
  }
  let parsed: ParsedTimestampToken;
  try {
    parsed = parseTimestampToken(input.token);
  } catch (error) {
    return { ok: false, genTime: null, reason: `token: ${messageOf(error)}` };
  }
  const imprint = parsed.tstInfo.messageImprint;
  if (imprint.hashAlgorithm.algorithm !== SHA256_OID) {
    return {
      ok: false,
      genTime: parsed.genTime,
      reason: `token imprint algorithm ${imprint.hashAlgorithm.algorithm} is not SHA-256`,
    };
  }
  const hashed = new Uint8Array(imprint.hashedMessage.buffer);
  if (!constantTimeEqual(hashed, digest)) {
    return {
      ok: false,
      genTime: parsed.genTime,
      reason: 'token imprint does not match the document digest',
    };
  }
  return { ok: true, genTime: parsed.genTime };
}

export interface TrustInput {
  token: string | Uint8Array;
  /** Trusted roots: PEM text (several CERTIFICATE blocks per string allowed) or DER. */
  roots: (string | Uint8Array)[];
}

export interface TrustResult {
  ok: boolean;
  /** Subject of the signing certificate, when it was located. */
  signer: string | null;
  /** Number of certificates in the validated path (signer first). */
  pathLength: number;
  reason?: string;
}

function rootsToCertificates(roots: (string | Uint8Array)[]): pkijs.Certificate[] {
  const certs: pkijs.Certificate[] = [];
  for (const root of roots) {
    if (typeof root === 'string') {
      for (const block of pemBlocks(root)) {
        if (block.label !== 'CERTIFICATE') continue;
        certs.push(pkijs.Certificate.fromBER(toArrayBuffer(block.der)));
      }
    } else {
      certs.push(pkijs.Certificate.fromBER(toArrayBuffer(root)));
    }
  }
  return certs;
}

function subjectString(cert: pkijs.Certificate): string {
  return cert.subject.typesAndValues
    .map((tv) => `${tv.type}=${tv.value.valueBlock.value}`)
    .join(', ');
}

function hasTimeStampingEku(cert: pkijs.Certificate): boolean {
  const ext = cert.extensions?.find((e) => e.extnID === EXT_KEY_USAGE_OID);
  const parsed: unknown = ext?.parsedValue;
  if (!(parsed instanceof pkijs.ExtKeyUsage)) return false;
  return parsed.keyPurposes.includes(TIMESTAMPING_EKU_OID);
}

/**
 * Optional check: the CMS signature over the signed attributes verifies with
 * the signer certificate found by `sid`, that certificate carries the
 * timeStamping EKU, was valid at `genTime`, and chains to one of `roots`.
 */
export async function verifyTimestampTrust(input: TrustInput): Promise<TrustResult> {
  let parsed: ParsedTimestampToken;
  try {
    parsed = parseTimestampToken(input.token);
  } catch (error) {
    return { ok: false, signer: null, pathLength: 0, reason: `token: ${messageOf(error)}` };
  }
  let trustedCerts: pkijs.Certificate[];
  try {
    trustedCerts = rootsToCertificates(input.roots);
  } catch (error) {
    return { ok: false, signer: null, pathLength: 0, reason: `roots: ${messageOf(error)}` };
  }
  if (trustedCerts.length === 0) {
    return {
      ok: false,
      signer: null,
      pathLength: 0,
      reason: 'no trusted root certificates supplied',
    };
  }

  let signedData: pkijs.SignedData;
  try {
    const contentInfo = pkijs.ContentInfo.fromBER(toArrayBuffer(parsed.der));
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
  } catch (error) {
    return { ok: false, signer: null, pathLength: 0, reason: `token: ${messageOf(error)}` };
  }

  // The TSTInfo imprint is checked separately against the digest we hold
  // (verifyTimestampImprint); the content type is already enforced by
  // parseTimestampToken. Presenting the content as id-data here lets the CMS
  // engine verify messageDigest + signature + chain without needing the
  // original document bytes, which a digest-only caller does not have.
  signedData.encapContentInfo.eContentType = id_data;

  let result: pkijs.SignedDataVerifyResult;
  try {
    result = await signedData.verify({
      signer: 0,
      trustedCerts,
      checkDate: parsed.genTime,
      checkChain: true,
      extendedMode: true,
    });
  } catch (error) {
    const detail = error instanceof pkijs.SignedDataVerifyError ? error.message : messageOf(error);
    const signer =
      error instanceof pkijs.SignedDataVerifyError && error.signerCertificate
        ? subjectString(error.signerCertificate)
        : null;
    return { ok: false, signer, pathLength: 0, reason: `timestamp signer not trusted: ${detail}` };
  }
  const signerCert = result.signerCertificate ?? null;
  const signer = signerCert ? subjectString(signerCert) : null;
  const pathLength = result.certificatePath.length;
  if (result.signatureVerified !== true) {
    return { ok: false, signer, pathLength, reason: 'timestamp CMS signature does not verify' };
  }
  if (!signerCert) {
    return { ok: false, signer, pathLength, reason: 'timestamp signer certificate not found' };
  }
  if (!hasTimeStampingEku(signerCert)) {
    return {
      ok: false,
      signer,
      pathLength,
      reason: 'timestamp signer certificate lacks the timeStamping extended key usage',
    };
  }
  const notBefore = signerCert.notBefore.value;
  const notAfter = signerCert.notAfter.value;
  if (parsed.genTime < notBefore || parsed.genTime > notAfter) {
    return {
      ok: false,
      signer,
      pathLength,
      reason: 'timestamp signer certificate was not valid at genTime',
    };
  }
  return { ok: true, signer, pathLength };
}
