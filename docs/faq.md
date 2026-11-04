# FAQ

**The verdict is `altered` but I did not change anything.**
Any re-save, "print to PDF", mail-client conversion or annotation changes the
bytes. Ask for the original file from the issuer's delivery (or the evidence
archive).

**`key: unpinned`: is that a failure?**
No. You did not supply a trust list, so only the signature math was checked.
Pin the key to turn it into `pinned` (see [Confirming the key](fingerprint.md)).

**`timestamp: invalid` with "signer not trusted".**
The token's signer does not chain to the shipped roots. If the issuer used
another TSA, add its root with `--tsa-roots`. If the issuer used DigiCert or
FreeTSA, treat the document as altered.

**`timestamp: imprint_only`.**
The token matches the digest but the signer chain was not evaluated (no
roots, or `--no-tsa-trust`).

**Can I verify without the PDF?**
Yes: `sealed-pdf-verify --proof x.json` checks the proof's internal
consistency and states that the PDF bytes were not checked.

**Does it work offline?**
Yes, everywhere: CLI, library and the browser page.

**Why does the proof carry its own public key?**
So the signature can be checked without a lookup. Trust in the key comes from
pinning, not from the proof.

**What is the difference from a PAdES / Adobe signature?**
The seal is detached: the PDF is not modified, the proof lives beside it. A
PDF reader will not show a signature panel; this tool (or the online check)
is how the seal is verified.
