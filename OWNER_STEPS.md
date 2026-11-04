# Owner steps

Everything below needs an account, a secret or a decision that only the owner
has. The code side is done; these are the buttons to press, in order.

## 1. GitHub repository

1. Create the public repository `sealed-pdf-verify` (under your user or an
   organisation; the name must stay generic).
2. Replace every `OWNER` placeholder with the actual GitHub owner. They sit in
   `package.json`, `README.md`, `Dockerfile`, `docs/cli.md`, `mkdocs.yml` and
   `.github/ISSUE_TEMPLATE/config.yml`; `grep -rl OWNER --exclude-dir=node_modules --exclude-dir=dist .`
   lists them. Commit, push `main`.
3. Settings → Security → enable **Private vulnerability reporting**
   (SECURITY.md points people there).
4. Settings → Pages → Source: **GitHub Actions** (the `pages.yml` workflow
   publishes `web/dist/`). After the first run, copy the Pages URL into the
   README "Browser page" bullet.
5. Settings → Actions → General → Workflow permissions: keep "Read repository
   contents" (the workflows request what they need).

## 2. npm (trusted publishing, no token on GitHub)

npm can only attach a trusted publisher to a package that already exists, so
the first version goes up by hand once; every later release is published by
`release.yml` through OIDC with provenance, and no `NPM_TOKEN` secret exists.

1. First publish, from this folder, logged in as the npm account that should
   own the package (2FA prompts in the browser):

   ```bash
   npm login
   npm publish --access public --provenance=false
   ```

   `prepublishOnly` runs the full `npm run check` first. `--provenance=false`
   is needed only here: provenance can only be generated inside CI.

2. npmjs.com → the package → Settings → **Trusted publishing** → GitHub
   Actions: organization `minutenotary`, repository `sealed-pdf-verify`,
   workflow `release.yml`, no environment, allow `npm publish`. The connection
   must see its first successful publish within 2 days or it expires.
3. Same settings page → Publishing access: **Require two-factor
   authentication and disallow tokens** (trusted publishing still works).
4. `npm logout` on the laptop.

## 3. Read the Docs

1. Sign in at readthedocs.org with GitHub, **Import a project**, pick the
   repository. `.readthedocs.yaml` + `mkdocs.yml` are already in place.
2. After the first build, copy the docs URL into the README.

## 4. First release

```bash
git tag v0.1.0
git push --tags
```

Tag the commit you published by hand in step 2.1. This runs `release.yml`
(which sees 0.1.0 already on npm and skips the publish) and `docker.yml`
(image to `ghcr.io/<owner>/sealed-pdf-verify:0.1.0`). After the first image,
make the GHCR package public: GitHub profile → Packages → sealed-pdf-verify
→ Package settings → Change visibility.

Later releases: bump `version` in `package.json`, move the CHANGELOG
"Unreleased" notes under the new version, commit, tag `vX.Y.Z`, push tags.

## 5. Official key fingerprint

`trust/issuers.json` ships empty on purpose, and the CLI refuses an empty
trust list (`--trust` exits 2 until the file is filled). Read the official
public key from the sealing service's verification page and compute:

```bash
openssl ec -pubin -in official-key.pem -outform DER | openssl dgst -sha256
```

Paste the 64 hex characters into `trust/issuers.json`:

```json
{ "fingerprints": ["<64 hex>"] }
```

Commit it. Also publish the same fingerprint on the issuer's verification
page and in every evidence `README.txt`, so users can confirm it out of band
(the README tells them to).

## 6. Later: announcements (drafts)

### Show HN

Title (≤ 80 chars):

> Show HN: Offline verifier for sealed PDFs (ECDSA + RFC 3161 + hash chain)

Text:

> We seal PDFs with a detached ECDSA P-256 signature over the SHA-256, an RFC 3161 timestamp and an append-only hash chain, and hand the holder a small proof JSON next to the file. This is the open-source, offline verifier for those proofs: a library (Node + browser), a CLI and a single-file web page that never uploads anything.
> The spec is in the README so anyone can write their own checker; the test suite includes a real FreeTSA token and a synthetic TSA so the chain validation runs offline.
> Happy to hear what a cryptographer or a PDF person would poke at first.

### Awesome-list one-liners

- awesome-pdf: `- [sealed-pdf-verify](https://github.com/<owner>/sealed-pdf-verify) - Offline verifier for PDFs sealed with a detached ECDSA signature, RFC 3161 timestamp and hash-chain ledger; CLI, library and browser page.`
- awesome-legal-tech: `- [sealed-pdf-verify](https://github.com/<owner>/sealed-pdf-verify) - Open-source, offline verification of sealed PDF documents (integrity, signing key, trusted timestamp, append-only ledger) with a published spec.`
- awesome-nextjs (weak fit; the tool is framework-agnostic — consider awesome-cryptography or awesome-digital-signatures instead): `- [sealed-pdf-verify](https://github.com/<owner>/sealed-pdf-verify) - Browser-ready library to verify sealed PDFs client-side (WebCrypto + ECDSA + RFC 3161), drop-in for a Next.js verification page.`

Replace `<owner>` before posting.
