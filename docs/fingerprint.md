# Confirming the key out of band

The proof carries its own public key, so the signature can be checked
without any lookup. Trust in that key must come from somewhere else: compare
its **fingerprint** with the one the issuer publishes.

The verifier prints the fingerprint on the `Key` line (CLI) or in
`facts.fingerprint` (JSON / API). It is the SHA-256 of the key's
SubjectPublicKeyInfo DER, 64 lowercase hex characters.

Where to find the official fingerprint:

- the issuer's verification page on [minutenotary.ca](https://minutenotary.ca),
- the `README.txt` inside an evidence archive from the issuer.

Compute it yourself from a PEM public key:

```bash
openssl ec -pubin -in key.pem -outform DER | openssl dgst -sha256
```

Then pin it:

```json
{ "fingerprints": ["<64 hex>"] }
```

```bash
npx sealed-pdf-verify document.pdf --proof document.proof.json --trust issuers.json
```

With a trust list the key check is `pinned` or `rejected`; `rejected` makes
the verdict `altered`. In the library an empty `trustedKeyFingerprints` list
rejects every key on purpose (you asked for pinning and nothing is trusted);
the CLI refuses an empty `--trust` file with exit status 2 instead, because
from the command line it can only be an unfilled template. A fingerprint that
is not 64 hex characters is a caller error: the library throws `TypeError`,
the CLI exits 2.
