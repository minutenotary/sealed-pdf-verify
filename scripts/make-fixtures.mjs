#!/usr/bin/env node
// Generates every test fixture under test/fixtures/ from scratch:
//   - an ephemeral P-256 signing key (only the PUBLIC key is written)
//   - two tiny hand-built PDFs plus a tampered copy
//   - proofs: DER, high-S, P1363, legacy label, wrong key, no timestamp,
//     no ledger, bad ledger, synthetic TSA, real FreeTSA
//   - a synthetic RFC 3161 TSA (root + leaf with timeStamping EKU) and tokens
//   - ONE real token from https://freetsa.org/tsr (only a 32-byte hash is sent)
//   - trust lists, a ledger segment and an evidence ZIP
// Signatures are produced with node:crypto so the verifier's own ECDSA code
// is not used to make what it later checks.
import {
  createHash,
  generateKeyPairSync,
  sign as nodeSign,
  webcrypto,
  randomBytes,
} from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import { AlgorithmIdentifier } from '@peculiar/asn1-x509';
import { MessageImprint, TimeStampReq, TimeStampResp } from '@peculiar/asn1-tsp';
import { zipSync } from 'fflate';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'test', 'fixtures');
mkdirSync(out, { recursive: true });

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const SHA1_OID = '1.3.14.3.2.26';
const ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const EKU_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const P256_N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

const write = (name, data) => {
  writeFileSync(join(out, name), data);
  console.log(`  ${name}`);
};
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const hex = (buf) => Buffer.from(buf).toString('hex');
const b64 = (buf) => Buffer.from(buf).toString('base64');

// ---------------------------------------------------------------- PDFs
function minimalPdf(text) {
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 120] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    null, // content stream, built below
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  const content = `BT /F1 16 Tf 20 50 Td (${text}) Tj ET`;
  objects[3] = `<< /Length ${content.length} >>\nstream\n${content}\nendstream`;
  let body = '%PDF-1.4\n%âãÏÓ\n';
  const offsets = [];
  objects.forEach((obj, i) => {
    offsets.push(Buffer.byteLength(body, 'latin1'));
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });
  const xref = Buffer.byteLength(body, 'latin1');
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const o of offsets) body += `${String(o).padStart(10, '0')} 00000 n \n`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(body, 'latin1');
}

const samplePdf = minimalPdf('Sample sealed document');
const secondPdf = minimalPdf('Second sealed document');
const tamperedPdf = Buffer.from(samplePdf);
{
  const idx = tamperedPdf.indexOf('Sample sealed');
  tamperedPdf.write('Sample tealed', idx, 'latin1');
}
const sampleHash = hex(sha256(samplePdf));
const secondHash = hex(sha256(secondPdf));

// ---------------------------------------------------------------- keys + signatures
const signer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const signerPubPem = signer.publicKey.export({ type: 'spki', format: 'pem' });
const otherPubPem = other.publicKey.export({ type: 'spki', format: 'pem' });
const fingerprintOf = (pem) =>
  hex(sha256(Buffer.from(pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, ''), 'base64')));

// ECDSA with SHA-256 over the PDF bytes == ECDSA over the raw SHA-256 digest.
const signDer = (key, bytes) => nodeSign('sha256', bytes, { key, dsaEncoding: 'der' });
const signP1363 = (key, bytes) => nodeSign('sha256', bytes, { key, dsaEncoding: 'ieee-p1363' });

function derToRs(der) {
  // DER SEQUENCE { INTEGER r, INTEGER s } (short-form lengths only; fine for P-256)
  let i = 2;
  const readInt = () => {
    if (der[i] !== 0x02) throw new Error('bad DER');
    const len = der[i + 1];
    const v = BigInt('0x' + hex(der.subarray(i + 2, i + 2 + len)));
    i += 2 + len;
    return v;
  };
  return { r: readInt(), s: readInt() };
}
function rsToDer(r, s) {
  const int = (v) => {
    let h = v.toString(16);
    if (h.length % 2) h = '0' + h;
    let b = Buffer.from(h, 'hex');
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return Buffer.concat([Buffer.from([0x02, b.length]), b]);
  };
  const body = Buffer.concat([int(r), int(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
function withS(der, high) {
  const { r, s } = derToRs(der);
  const isHigh = s > P256_N / 2n;
  return isHigh === high ? der : rsToDer(r, P256_N - s);
}

const sampleSigDer = signDer(signer.privateKey, samplePdf);
const sampleSigLow = withS(sampleSigDer, false);
const sampleSigHigh = withS(sampleSigDer, true);
const sampleSigP1363 = signP1363(signer.privateKey, samplePdf);
const secondSigDer = signDer(signer.privateKey, secondPdf);
const wrongKeySig = signDer(other.privateKey, samplePdf);

// ---------------------------------------------------------------- ledger
const ZERO = '0'.repeat(64);
const SEALED_1 = '2026-11-04T12:00:00.000Z';
const SEALED_2 = '2026-11-04T12:30:00.000Z';
const entryHash = (seq, docHash, prev, sealedAt) =>
  hex(sha256(Buffer.from(`${seq}\n${docHash}\n${prev}\n${sealedAt}`, 'utf8')));
const entry1 = { seq: 1, documentHash: sampleHash, previousEntryHash: ZERO, sealedAt: SEALED_1 };
entry1.entryHash = entryHash(1, sampleHash, ZERO, SEALED_1);
const entry2 = {
  seq: 2,
  documentHash: secondHash,
  previousEntryHash: entry1.entryHash,
  sealedAt: SEALED_2,
};
entry2.entryHash = entryHash(2, secondHash, entry1.entryHash, SEALED_2);
const ledgerBlock = (e) => ({
  seq: e.seq,
  previousEntryHash: e.previousEntryHash,
  entryHash: e.entryHash,
});

// ---------------------------------------------------------------- synthetic TSA (pkijs)
const subtle = webcrypto.subtle;
pkijs.setEngine('node', new pkijs.CryptoEngine({ name: 'node', crypto: webcrypto }));

async function makeCert({
  serial,
  subjectCn,
  issuer,
  issuerKey,
  keys,
  ca,
  eku,
  notBefore,
  notAfter,
}) {
  const cert = new pkijs.Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1js.Integer({ value: serial });
  const cn = (v) =>
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.PrintableString({ value: v }),
    });
  cert.subject.typesAndValues.push(cn(subjectCn));
  cert.issuer = issuer ? issuer.subject : cert.subject;
  cert.notBefore.value = notBefore;
  cert.notAfter.value = notAfter;
  cert.extensions = [];
  cert.extensions.push(
    new pkijs.Extension({
      extnID: '2.5.29.19',
      critical: true,
      extnValue: new pkijs.BasicConstraints({ cA: ca }).toSchema().toBER(false),
    }),
  );
  // keyUsage: CA → keyCertSign|cRLSign (0x06, 1 unused bit); leaf → digitalSignature (0x80, 7 unused)
  cert.extensions.push(
    new pkijs.Extension({
      extnID: '2.5.29.15',
      critical: true,
      extnValue: new asn1js.BitString({
        valueHex: new Uint8Array([ca ? 0x06 : 0x80]).buffer,
        unusedBits: ca ? 1 : 7,
      }).toBER(false),
    }),
  );
  if (eku) {
    cert.extensions.push(
      new pkijs.Extension({
        extnID: '2.5.29.37',
        critical: true,
        extnValue: new pkijs.ExtKeyUsage({ keyPurposes: eku }).toSchema().toBER(false),
      }),
    );
  }
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey);
  await cert.sign(issuerKey ?? keys.privateKey, 'SHA-256');
  return cert;
}

const ecKeys = () =>
  subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const pem = (der, label) =>
  `-----BEGIN ${label}-----\n${b64(der)
    .match(/.{1,64}/g)
    .join('\n')}\n-----END ${label}-----\n`;
const certDer = (c) => Buffer.from(c.toSchema(true).toBER(false));

const T0 = new Date('2026-01-01T00:00:00Z');
const T1 = new Date('2036-01-01T00:00:00Z');
const GEN_TIME = new Date('2026-11-04T12:00:05Z');

const rootKeys = await ecKeys();
const rootCert = await makeCert({
  serial: 1,
  subjectCn: 'Test Timestamp Root',
  keys: rootKeys,
  ca: true,
  notBefore: T0,
  notAfter: T1,
});
const leafKeys = await ecKeys();
const leafCert = await makeCert({
  serial: 2,
  subjectCn: 'Test Timestamp Unit',
  issuer: rootCert,
  issuerKey: rootKeys.privateKey,
  keys: leafKeys,
  ca: false,
  eku: [EKU_TIMESTAMPING],
  notBefore: T0,
  notAfter: T1,
});
const noEkuKeys = await ecKeys();
const noEkuCert = await makeCert({
  serial: 3,
  subjectCn: 'Test Unit Without EKU',
  issuer: rootCert,
  issuerKey: rootKeys.privateKey,
  keys: noEkuKeys,
  ca: false,
  notBefore: T0,
  notAfter: T1,
});
const strangerRootKeys = await ecKeys();
const strangerRoot = await makeCert({
  serial: 1,
  subjectCn: 'Unrelated Root',
  keys: strangerRootKeys,
  ca: true,
  notBefore: T0,
  notAfter: T1,
});
const strangerKeys = await ecKeys();
const strangerCert = await makeCert({
  serial: 2,
  subjectCn: 'Unrelated Timestamp Unit',
  issuer: strangerRoot,
  issuerKey: strangerRootKeys.privateKey,
  keys: strangerKeys,
  ca: false,
  eku: [EKU_TIMESTAMPING],
  notBefore: T0,
  notAfter: T1,
});

async function makeToken({
  digest,
  hashOid = SHA256_OID,
  cert,
  keys,
  genTime = GEN_TIME,
  serial = 1001,
}) {
  const tst = new pkijs.TSTInfo({
    version: 1,
    policy: '1.2.3.4.5.6.7',
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({
        algorithmId: hashOid,
        algorithmParams: new asn1js.Null(),
      }),
      hashedMessage: new asn1js.OctetString({ valueHex: new Uint8Array(digest).buffer }),
    }),
    serialNumber: new asn1js.Integer({ value: serial }),
    genTime,
    accuracy: new pkijs.Accuracy({ seconds: 1 }),
    ordering: false,
    tsa: new pkijs.GeneralName({ type: 4, value: cert.subject }),
  });
  const tstDer = tst.toSchema().toBER(false);
  const signed = new pkijs.SignedData({
    version: 3,
    encapContentInfo: new pkijs.EncapsulatedContentInfo({ eContentType: ID_CT_TSTINFO }),
    signerInfos: [
      new pkijs.SignerInfo({
        version: 1,
        sid: new pkijs.IssuerAndSerialNumber({
          issuer: cert.issuer,
          serialNumber: cert.serialNumber,
        }),
      }),
    ],
    certificates: [cert],
  });
  // Assign directly: the pkijs constructor would re-wrap the OCTET STRING as a
  // constructed (BER) string, while real TSAs emit a primitive DER OCTET STRING.
  signed.encapContentInfo.eContent = new asn1js.OctetString({ valueHex: tstDer });
  signed.signerInfos[0].signedAttrs = new pkijs.SignedAndUnsignedAttributes({
    type: 0,
    attributes: [
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.3',
        values: [new asn1js.ObjectIdentifier({ value: ID_CT_TSTINFO })],
      }),
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.5',
        values: [new asn1js.UTCTime({ valueDate: genTime })],
      }),
      new pkijs.Attribute({
        type: '1.2.840.113549.1.9.4',
        values: [
          new asn1js.OctetString({ valueHex: new Uint8Array(sha256(Buffer.from(tstDer))).buffer }),
        ],
      }),
    ],
  });
  await signed.sign(keys.privateKey, 0, 'SHA-256');
  const ci = new pkijs.ContentInfo({ contentType: ID_SIGNED_DATA, content: signed.toSchema(true) });
  return Buffer.from(ci.toSchema().toBER(false));
}

const sampleDigest = sha256(samplePdf);
const syntheticTsr = await makeToken({ digest: sampleDigest, cert: leafCert, keys: leafKeys });
const syntheticNoEkuTsr = await makeToken({
  digest: sampleDigest,
  cert: noEkuCert,
  keys: noEkuKeys,
  serial: 1002,
});
const syntheticUntrustedTsr = await makeToken({
  digest: sampleDigest,
  cert: strangerCert,
  keys: strangerKeys,
  serial: 1003,
});
const syntheticSha1Tsr = await makeToken({
  digest: createHash('sha1').update(samplePdf).digest(),
  hashOid: SHA1_OID,
  cert: leafCert,
  keys: leafKeys,
  serial: 1004,
});

// ---------------------------------------------------------------- real FreeTSA token
async function fetchFreeTsa(digest) {
  const nonce = randomBytes(8);
  nonce[0] &= 0x7f;
  const req = new TimeStampReq({
    version: 1,
    messageImprint: new MessageImprint({
      hashAlgorithm: new AlgorithmIdentifier({ algorithm: SHA256_OID, parameters: null }),
      hashedMessage: new OctetString(new Uint8Array(digest).buffer),
    }),
    nonce: new Uint8Array(nonce).buffer,
    certReq: true,
  });
  const body = AsnConvert.serialize(req);
  const res = await fetch('https://freetsa.org/tsr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body,
  });
  if (!res.ok) throw new Error(`freetsa.org answered ${res.status}`);
  const resp = AsnConvert.parse(await res.arrayBuffer(), TimeStampResp);
  if (resp.status.status > 1 || !resp.timeStampToken)
    throw new Error(`freetsa.org status ${resp.status.status}`);
  return Buffer.from(AsnConvert.serialize(resp.timeStampToken));
}
let realTsr = null;
try {
  realTsr = await fetchFreeTsa(sampleDigest);
  console.log(`fetched real FreeTSA token (${realTsr.length} bytes)`);
} catch (error) {
  console.error(`WARNING: could not fetch a FreeTSA token: ${error.message}`);
}

// ---------------------------------------------------------------- proofs
const SEAL_1 = 'SPV-TEST-000001';
const SEAL_2 = 'SPV-TEST-000002';
function proof({
  sealId,
  hash,
  signature,
  algorithm = 'OCI_ECDSA_P256_SHA256',
  publicKeyPem = signerPubPem,
  tsaToken = null,
  tsaUrl = null,
  ledger,
  sealedAt = SEALED_1,
  timestampedAt = null,
}) {
  const p = {
    schemaVersion: 1,
    sealId,
    documentHash: hash,
    algorithm,
    signature: b64(signature),
    keyId: 'test-key',
    keyVersion: '1',
    publicKeyPem,
    tsaToken: tsaToken ? b64(tsaToken) : null,
    tsaUrl,
    timestampedAt,
    verifyUrl: `https://example.com/verify/${sealId}`,
    sealedAt,
  };
  if (ledger) p.ledger = ledger;
  return p;
}
const json = (o) => JSON.stringify(o, null, 2) + '\n';

console.log('writing fixtures:');
write('sample.pdf', samplePdf);
write('second.pdf', secondPdf);
write('tampered.pdf', tamperedPdf);
write('signer.pub.pem', signerPubPem);
write('other.pub.pem', otherPubPem);
write('tsa-test-root.pem', pem(certDer(rootCert), 'CERTIFICATE'));
write('tsa-unrelated-root.pem', pem(certDer(strangerRoot), 'CERTIFICATE'));
write('synthetic.tsr', syntheticTsr);
write('synthetic-noeku.tsr', syntheticNoEkuTsr);
write('synthetic-untrusted.tsr', syntheticUntrustedTsr);
write('synthetic-sha1.tsr', syntheticSha1Tsr);
if (realTsr) write('real-freetsa.tsr', realTsr);

const primaryTsr = realTsr ?? syntheticTsr;
const primaryTsaUrl = realTsr ? 'https://freetsa.org/tsr' : 'https://tsa.example.test/tsr';
const base = { sealId: SEAL_1, hash: sampleHash, ledger: ledgerBlock(entry1) };
write(
  'sample.proof.json',
  json(proof({ ...base, signature: sampleSigLow, tsaToken: primaryTsr, tsaUrl: primaryTsaUrl })),
);
write(
  'sample.high-s.proof.json',
  json(proof({ ...base, signature: sampleSigHigh, tsaToken: primaryTsr, tsaUrl: primaryTsaUrl })),
);
write(
  'sample.p1363.proof.json',
  json(proof({ ...base, signature: sampleSigP1363, tsaToken: primaryTsr, tsaUrl: primaryTsaUrl })),
);
write(
  'sample.legacy.proof.json',
  json(
    proof({
      ...base,
      signature: sampleSigLow,
      algorithm: 'ECDSA_P256_SHA256',
      tsaToken: primaryTsr,
      tsaUrl: primaryTsaUrl,
    }),
  ),
);
write(
  'sample.synthetic-tsa.proof.json',
  json(
    proof({
      ...base,
      signature: sampleSigLow,
      tsaToken: syntheticTsr,
      tsaUrl: 'https://tsa.example.test/tsr',
      timestampedAt: GEN_TIME.toISOString(),
    }),
  ),
);
write('sample.no-timestamp.proof.json', json(proof({ ...base, signature: sampleSigLow })));
write(
  'sample.no-ledger.proof.json',
  json(proof({ sealId: SEAL_1, hash: sampleHash, signature: sampleSigLow })),
);
write(
  'sample.bad-ledger.proof.json',
  json(
    proof({
      ...base,
      signature: sampleSigLow,
      ledger: { ...ledgerBlock(entry1), entryHash: 'f'.repeat(64) },
    }),
  ),
);
write('sample.wrong-key.proof.json', json(proof({ ...base, signature: wrongKeySig })));
write(
  'sample.bad-algorithm.proof.json',
  json(proof({ ...base, signature: sampleSigLow, algorithm: 'RSA_PSS_SHA256' })),
);
write(
  'second.proof.json',
  json(
    proof({
      sealId: SEAL_2,
      hash: secondHash,
      signature: secondSigDer,
      ledger: ledgerBlock(entry2),
      sealedAt: SEALED_2,
    }),
  ),
);
write('ledger-segment.json', json([entry1, entry2]));
write('trust-pinned.json', json({ fingerprints: [fingerprintOf(signerPubPem)] }));
write('trust-other.json', json({ fingerprints: [fingerprintOf(otherPubPem)] }));
write('trust-empty.json', json({ fingerprints: [] }));
write('trust-bad.json', json({ fingerprints: 'nope' }));
write(
  'fingerprints.json',
  json({
    signer: fingerprintOf(signerPubPem),
    other: fingerprintOf(otherPubPem),
    sampleHash,
    secondHash,
    genTime: GEN_TIME.toISOString(),
  }),
);

// ---------------------------------------------------------------- evidence ZIP
const sealFile = (p, extra) => {
  const rest = { ...p, ...extra };
  delete rest.schemaVersion;
  delete rest.ledger;
  return json(rest);
};
const seal1 = proof({
  ...base,
  signature: sampleSigLow,
  tsaToken: primaryTsr,
  tsaUrl: primaryTsaUrl,
});
const seal2 = proof({
  sealId: SEAL_2,
  hash: secondHash,
  signature: secondSigDer,
  sealedAt: SEALED_2,
});
const enc = (s) => new TextEncoder().encode(s);
const zip = zipSync(
  {
    'README.txt': enc('Evidence archive for two sealed documents (test fixture).\n'),
    'documents/sample.pdf': new Uint8Array(samplePdf),
    'documents/second.pdf': new Uint8Array(secondPdf),
    [`seals/${SEAL_1}.json`]: enc(
      sealFile(seal1, {
        disposition: 'active',
        roundSequence: 1,
        supersededAt: null,
        supersededReason: null,
      }),
    ),
    [`seals/${SEAL_1}.public-key.pem`]: enc(signerPubPem),
    [`seals/${SEAL_1}.tsr`]: new Uint8Array(primaryTsr),
    [`seals/${SEAL_2}.json`]: enc(
      sealFile(seal2, {
        disposition: 'superseded',
        roundSequence: 1,
        supersededAt: '2026-11-05T09:00:00.000Z',
        supersededReason: 'reissued after a correction',
      }),
    ),
    [`seals/${SEAL_2}.public-key.pem`]: enc(signerPubPem),
    'ledger/segment.json': enc(json([entry1, entry2])),
    'audit/booking-audit-log.json': enc(json([{ event: 'ignored-by-verifier' }])),
  },
  { level: 6 },
);
write('evidence.zip', zip);
console.log('done');
