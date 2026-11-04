# Command line

```
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

Exit status: 0 genuine, 1 altered, 2 incomplete or error.
```

Run it without installing: `npx sealed-pdf-verify ...`. Install globally with
`npm install -g sealed-pdf-verify`. A container image is published to GHCR on
every release:

```bash
docker run --rm -v "$PWD:/data" ghcr.io/OWNER/sealed-pdf-verify document.pdf --proof document.proof.json
```

The human output is a table of the five checks followed by the facts of the
seal (seal id, digests, key fingerprint, times, online check URL). `--json`
prints the full verdict object described in the [API](api.md).
