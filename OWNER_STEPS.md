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

## 2. npm (trusted publishing, no token)

The package is published from `release.yml` over OIDC. There is no npm token
on GitHub.

1. The npm package `sealed-pdf-verify` is owned by the `minutenotary` npm
   account. 0.1.0 was published on 2026-11-05 by `release.yml` with a
   short-lived token, because npm only lets you add a trusted publisher to a
   package that already exists. That token and the `NPM_TOKEN` secret are
   deleted.
2. npmjs.com → sealed-pdf-verify → Settings → Trusted publisher → GitHub
   Actions: organization `minutenotary`, repository `sealed-pdf-verify`,
   workflow `release.yml`, no environment, allow `npm publish`.
3. Publishing access: "Require two-factor authentication and disallow bypass
   2fa tokens". Trusted publishing keeps working with this setting.
4. `release.yml` needs `id-token: write` and npm >= 11.5.1 (Node 24).
   Provenance is attached automatically; the repository must stay public.
5. If the workflow file is renamed, update the trusted publisher on npmjs.com
   first, or the publish fails.

## 3. Read the Docs

1. Sign in at readthedocs.org with GitHub, **Import a project**, pick the
   repository. `.readthedocs.yaml` + `mkdocs.yml` are already in place.
2. After the first build, copy the docs URL into the README.

## 4. Releasing a version

Bump `version` in `package.json`, move the CHANGELOG "Unreleased" notes under
the new version, merge that through a PR, then tag the merge commit (repo
admins only, ruleset `protect-release-tags`):

```bash
git pull --ff-only
git tag vX.Y.Z
git push origin vX.Y.Z
```

This runs `release.yml` (npm publish over OIDC, with provenance) and
`docker.yml` (image to `ghcr.io/minutenotary/sealed-pdf-verify:X.Y.Z`).
`release.yml` fails if the tag does not match `package.json`.

The GHCR package must be public once (after the first image): GitHub
profile → Packages → sealed-pdf-verify → Package settings → Change
visibility.

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
