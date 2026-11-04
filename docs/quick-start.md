# Quick start

You hold two files delivered together: the sealed PDF and its proof JSON.

## Command line

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json
```

The output is a short table of the five checks and the facts of the seal.
Exit status `0` means genuine, `1` altered, `2` incomplete or error.

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json --json   # machine-readable
npx sealed-pdf-verify evidence.zip                                       # an evidence archive
npx sealed-pdf-verify --proof document.proof.json                        # proof-only mode
```

To prove the signing key is the issuer's key, pin it with a trust list you
filled in yourself (see [Confirming the key](fingerprint.md); the CLI refuses
an empty list):

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json --trust issuers.json
```

## Browser

Open the verifier page, drop the PDF and the proof JSON (or an evidence ZIP)
on it. The page is one HTML file; it works from `file://`, works offline once
loaded and makes no requests.

## Library

```ts
import { verifySealedPdf } from 'sealed-pdf-verify';

const verdict = await verifySealedPdf({ pdf, proof });
console.log(verdict.overall, verdict.checks);
```

See the [library API](api.md).
