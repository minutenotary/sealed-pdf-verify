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
the verdict `altered`. An empty trust list rejects every key on purpose: you
asked for pinning and nothing is trusted.
