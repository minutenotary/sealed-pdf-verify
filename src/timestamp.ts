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

/**
 * CMS digest algorithms accepted for the token's own signature: the SHA-2
 * family. The imprint is SHA-256 by the spec; this is the hash the TSA signs
 * the signed attributes with. A TSA still signing with SHA-1 is refused
 * outright: the attacker controls the nonce inside TSTInfo, so a
 * chosen-prefix SHA-1 collision could let one TSA signature cover a second
 * TSTInfo with another imprint or genTime. (Both shipped roots' TSAs use
 * SHA-2: FreeTSA SHA-512, DigiCert SHA-256.)
 */
export const ACCEPTED_CMS_DIGEST_OIDS: ReadonlySet<string> = new Set([
  '2.16.840.1.101.3.4.2.1', // id-sha256
  '2.16.840.1.101.3.4.2.2', // id-sha384
  '2.16.840.1.101.3.4.2.3', // id-sha512
]);

/**
 * CMS signature algorithms accepted: RSA (PKCS#1 v1.5 with the hash named
 * either by `digestAlgorithm` or in the OID itself, or RSASSA-PSS) and ECDSA
 * with SHA-2 (or the bare ecPublicKey form). Anything else, SHA-1 variants
 * included, is refused before any signature is checked.
 */
export const ACCEPTED_CMS_SIGNATURE_OIDS: ReadonlySet<string> = new Set([
  '1.2.840.113549.1.1.1', // rsaEncryption (hash from digestAlgorithm; DigiCert)
  '1.2.840.113549.1.1.10', // id-RSASSA-PSS
  '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
  '1.2.840.10045.2.1', // id-ecPublicKey (hash from digestAlgorithm)
  '1.2.840.10045.4.3.2', // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3', // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4', // ecdsa-with-SHA512 (FreeTSA)
]);

export interface ParsedTimestampToken {
  der: Uint8Array;
  tstInfo: TSTInfo;
  /** `TSTInfo.genTime`. */
  genTime: Date;
  /** `SignerInfo.digestAlgorithm` OID. */
  digestAlgorithm: string;
  /** `SignerInfo.signatureAlgorithm` OID. */
  signatureAlgorithm: string;
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
  // RFC 3161 §2.4.2: a TimeStampToken carries exactly one SignerInfo. Every
  // later step reads index 0, so a second signer could never be checked.
  if (signedData.signerInfos.length !== 1) {
    throw new Error(
      `token has ${signedData.signerInfos.length} SignerInfos; RFC 3161 allows exactly one`,
    );
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
  return {
    der,
    tstInfo,
    genTime,
    digestAlgorithm: signer.digestAlgorithm.algorithm,
    signatureAlgorithm: signer.signatureAlgorithm.algorithm,
  };
}

/** The reason a token's CMS algorithms are refused, or null when both are accepted. */
export function cmsAlgorithmProblem(parsed: ParsedTimestampToken): string | null {
  if (!ACCEPTED_CMS_DIGEST_OIDS.has(parsed.digestAlgorithm)) {
    return `timestamp CMS uses digest algorithm ${parsed.digestAlgorithm}, not an accepted SHA-2 digest`;
  }
  if (!ACCEPTED_CMS_SIGNATURE_OIDS.has(parsed.signatureAlgorithm)) {
    return `timestamp CMS uses signature algorithm ${parsed.signatureAlgorithm}, not an accepted RSA or ECDSA algorithm`;
  }
  return null;
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

/**
 * Parses trust anchors: PEM text (every CERTIFICATE block in it) or one DER
 * certificate per Uint8Array. Throws on the first certificate that does not
 * parse, so a mistyped root file is a loud caller error rather than a silently
 * smaller trust set.
 */
export function parseRootCertificates(
  roots: readonly (string | Uint8Array)[],
): pkijs.Certificate[] {
  const certs: pkijs.Certificate[] = [];
  roots.forEach((root, index) => {
    try {
      if (typeof root === 'string') {
        for (const block of pemBlocks(root)) {
          if (block.label !== 'CERTIFICATE') continue;
          certs.push(pkijs.Certificate.fromBER(toArrayBuffer(block.der)));
        }
      } else {
        certs.push(pkijs.Certificate.fromBER(toArrayBuffer(root)));
      }
    } catch (error) {
      throw new Error(`root certificate ${index} does not parse: ${messageOf(error)}`, {
        cause: error,
      });
    }
  });
  return certs;
}

/** The certificate's TBS bytes, the identity pkijs compares anchors by. */
function tbsOf(cert: pkijs.Certificate): Uint8Array {
  return cert.tbsView.byteLength > 0 ? cert.tbsView : new Uint8Array(cert.encodeTBS().toBER());
}

function isAnchor(cert: pkijs.Certificate, trusted: readonly pkijs.Certificate[]): boolean {
  const tbs = tbsOf(cert);
  return trusted.some((root) => constantTimeEqual(tbsOf(root), tbs));
}

/**
 * Issuer finder for pkijs's chain engine that leaves dead ends unexplored.
 *
 * `defaultFindIssuer` returns every certificate in the pool or the anchors
 * whose name (or authority key identifier) matches and whose key verifies
 * the child. `buildPath` then throws "No valid certificate paths found" the
 * moment ANY candidate has no issuer of its own, and that throw unwinds the
 * whole search, so one dead-end branch hides a valid path next to it. Real
 * tokens have such branches: DigiCert embeds a cross-signed "DigiCert Trusted
 * Root G4" (issued by DigiCert Assured ID Root CA, same key as the shipped
 * self-signed root, a different serial); a CA in transition ships one
 * intermediate certified by two roots.
 *
 * This finder keeps a candidate only if it is a trust anchor itself, is
 * self-signed (pkijs ends the path there and rejects it as untrusted, which
 * is harmless), or has an issuer path of its own. It adds nothing to the pool
 * or the anchors and verifies nothing itself: a certificate that was not
 * trusted before is not trusted now; a dead end is simply not walked into.
 * Cross-signing cycles (A certifies B, B certifies A) are cut by the
 * `visited` list.
 */
function pruningFindIssuer(): pkijs.FindIssuerCallback {
  const find = async (
    certificate: pkijs.Certificate,
    engine: pkijs.CertificateChainValidationEngine,
    crypto: pkijs.ICryptoEngine | undefined,
    visited: readonly Uint8Array[],
  ): Promise<pkijs.Certificate[]> => {
    const candidates = await engine.defaultFindIssuer(certificate, engine, crypto);
    const kept: pkijs.Certificate[] = [];
    for (const candidate of candidates) {
      if (isAnchor(candidate, engine.trustedCerts) || candidate.subject.isEqual(candidate.issuer)) {
        kept.push(candidate);
        continue;
      }
      const tbs = tbsOf(candidate);
      if (visited.some((seen) => constantTimeEqual(seen, tbs))) continue;
      const own = await find(candidate, engine, crypto, [...visited, tbs]);
      if (own.length > 0) kept.push(candidate);
    }
    return kept;
  };
  return (certificate, engine, crypto) => find(certificate, engine, crypto, [tbsOf(certificate)]);
}

function subjectString(cert: pkijs.Certificate): string {
  return cert.subject.typesAndValues
    .map((tv) => `${tv.type}=${tv.value.valueBlock.value}`)
    .join(', ');
}

/**
 * RFC 3161 §2.3: the signer certificate MUST carry the extended key usage
 * extension, marked critical, with id-kp-timeStamping as its only purpose.
 * Both public TSAs this package ships roots for (DigiCert, FreeTSA) comply.
 */
function hasStrictTimeStampingEku(cert: pkijs.Certificate): string | null {
  const ext = cert.extensions?.find((e) => e.extnID === EXT_KEY_USAGE_OID);
  const parsed: unknown = ext?.parsedValue;
  if (!ext || !(parsed instanceof pkijs.ExtKeyUsage)) {
    return 'timestamp signer certificate lacks the timeStamping extended key usage extension';
  }
  if (!parsed.keyPurposes.includes(TIMESTAMPING_EKU_OID)) {
    return 'timestamp signer certificate lacks the timeStamping extended key usage';
  }
  if (parsed.keyPurposes.length !== 1) {
    return 'timestamp signer certificate lists purposes other than timeStamping (RFC 3161 §2.3)';
  }
  if (!ext.critical) {
    return 'timestamp signer certificate does not mark its extended key usage critical (RFC 3161 §2.3)';
  }
  return null;
}

/**
 * Optional check: the token's CMS digest and signature algorithms are in the
 * accepted sets, the CMS signature over the signed attributes verifies with
 * the signer certificate found by `sid`, that certificate carries the
 * timeStamping EKU (critical, sole purpose), was valid at `genTime`, and
 * chains to one of `roots`. No revocation data is consulted: offline
 * verification has no CRL or OCSP, so a signer revoked after `genTime` still
 * verifies (see docs/threat-model.md).
 *
 * This check alone does not tie the token to any document: pair it with
 * {@link verifyTimestampImprint}, as {@link verifySealedPdf} does.
 */
export async function verifyTimestampTrust(input: TrustInput): Promise<TrustResult> {
  let parsed: ParsedTimestampToken;
  try {
    parsed = parseTimestampToken(input.token);
  } catch (error) {
    return { ok: false, signer: null, pathLength: 0, reason: `token: ${messageOf(error)}` };
  }
  const algorithmProblem = cmsAlgorithmProblem(parsed);
  if (algorithmProblem !== null) {
    return { ok: false, signer: null, pathLength: 0, reason: algorithmProblem };
  }
  let trustedCerts: pkijs.Certificate[];
  try {
    trustedCerts = parseRootCertificates(input.roots);
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
  // Relabel the encapsulated content as id-data before calling pkijs.
  //
  // pkijs's TSTInfo branch (SignedData.verify, eContentType === id-ct-TSTInfo)
  // insists on receiving the original `data` so it can hash it and compare it
  // with the imprint, and would also set checkDate from genTime and extract the
  // serial. A digest-only verifier does not hold the document bytes, so that
  // branch is skipped on purpose and each of its duties is covered elsewhere:
  //   - imprint vs digest: verifyTimestampImprint, which every caller of this
  //     function in this package runs first (this function alone does NOT bind
  //     the token to any digest; a valid token for another digest passes);
  //   - checkDate = genTime: passed explicitly below;
  //   - content-type signed attribute naming id-ct-TSTInfo: enforced in
  //     parseTimestampToken. pkijs never compares that attribute with
  //     eContentType in either branch, so that local check is load-bearing.
  // What pkijs still verifies after the relabel: signer located by sid, chain
  // anchored only on trustedCerts (an embedded self-signed root does not
  // anchor), validity of every path certificate at checkDate, cA / keyUsage on
  // intermediates, each hop's signature, messageDigest attribute vs the
  // encapsulated bytes, and the signature over the re-encoded signed
  // attributes (so BER / non-canonical signed attributes fail closed).
  signedData.encapContentInfo.eContentType = id_data;

  let result: pkijs.SignedDataVerifyResult;
  try {
    result = await signedData.verify({
      signer: 0,
      trustedCerts,
      checkDate: parsed.genTime,
      checkChain: true,
      extendedMode: true,
      findIssuer: pruningFindIssuer(),
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
  const ekuProblem = hasStrictTimeStampingEku(signerCert);
  if (ekuProblem !== null) {
    return { ok: false, signer, pathLength, reason: ekuProblem };
  }
  // Defence in depth: pkijs already rejected any path certificate that was not
  // valid at checkDate (genTime) above, so this branch is normally unreachable.
  // It stays so the validity rule does not silently depend on pkijs internals.
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
