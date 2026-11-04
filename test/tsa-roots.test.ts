import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as pkijs from 'pkijs';
import { describe, expect, it } from 'vitest';
import { BUILT_IN_TSA_ROOTS, builtInTsaRootsPem, pemBlocks } from '../src/index.js';

const dir = join(import.meta.dirname, '..', 'tsa-roots');

describe('built-in TSA roots', () => {
  it('ship DigiCert Trusted Root G4 and the FreeTSA root', () => {
    const names = BUILT_IN_TSA_ROOTS.map((r) => r.name);
    expect(names).toEqual(['digicert-trusted-root-g4', 'freetsa-root']);
    expect(builtInTsaRootsPem()).toHaveLength(2);
  });
  it('match tsa-roots/*.pem on disk (run `npm run sync:roots` when they drift)', () => {
    const files = readdirSync(dir)
      .filter((f) => f.endsWith('.pem'))
      .sort();
    expect(files.map((f) => f.replace(/\.pem$/, ''))).toEqual(
      BUILT_IN_TSA_ROOTS.map((r) => r.name),
    );
    for (const root of BUILT_IN_TSA_ROOTS) {
      const onDisk =
        readFileSync(join(dir, `${root.name}.pem`), 'utf8')
          .replace(/\r\n/g, '\n')
          .trim() + '\n';
      expect(root.pem).toBe(onDisk);
    }
  });
  it('are exactly the certificates the CAs publish (SHA-256 of the DER)', () => {
    // DigiCert publishes this thumbprint on its root page; FreeTSA's matches
    // https://freetsa.org/files/cacert.pem. A root that drifts from these
    // values is a different trust anchor and must not ship unnoticed.
    const pinned: Record<string, string> = {
      'digicert-trusted-root-g4':
        '552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988',
      'freetsa-root': 'a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc',
    };
    for (const root of BUILT_IN_TSA_ROOTS) {
      const der = pemBlocks(root.pem)[0]?.der ?? new Uint8Array();
      expect(createHash('sha256').update(der).digest('hex'), root.name).toBe(pinned[root.name]);
    }
  });
  it('are self-signed CA certificates', () => {
    const expected: Record<string, string> = {
      'digicert-trusted-root-g4': 'DigiCert Trusted Root G4',
      'freetsa-root': 'www.freetsa.org',
    };
    for (const root of BUILT_IN_TSA_ROOTS) {
      const blocks = pemBlocks(root.pem);
      expect(blocks).toHaveLength(1);
      const cert = pkijs.Certificate.fromBER((blocks[0]?.der ?? new Uint8Array()).slice().buffer);
      const cn = cert.subject.typesAndValues.find((tv) => tv.type === '2.5.4.3');
      expect(String(cn?.value.valueBlock.value)).toBe(expected[root.name]);
      expect(cert.issuer.isEqual(cert.subject)).toBe(true);
    }
  });
});
