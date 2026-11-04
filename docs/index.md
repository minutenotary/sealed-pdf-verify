# sealed-pdf-verify

Offline, independent verifier for PDF documents sealed by
[minutenotary.ca](https://minutenotary.ca).

A sealed PDF comes with a small **proof sidecar** (`<name>.proof.json`). The
proof carries a detached ECDSA P-256 signature over the PDF's SHA-256, the
public key, an RFC 3161 timestamp token and the document's entry in the
issuer's append-only ledger. This tool recomputes and checks all of that on
your own machine, with no network access.

| Form         | Where                                           | Use it when                               |
| ------------ | ----------------------------------------------- | ----------------------------------------- |
| CLI          | `npx sealed-pdf-verify`                         | you have a terminal                       |
| Library      | `npm install sealed-pdf-verify`                 | you build software (Node 20+ or browsers) |
| Browser page | the GitHub Pages site, or `web/dist/index.html` | you want drag-and-drop, nothing installed |

The issuer also offers an online check at
`https://minutenotary.ca/verify/<sealId>` (the id printed on the document as
`Code: <sealId>`). This project is the offline second opinion, and its
[specification](specification.md) lets anyone write a third one.

Start with the [quick start](quick-start.md), then read
[the five checks](checks.md) and [how to confirm the key](fingerprint.md).
