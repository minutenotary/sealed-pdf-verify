# Threat model

## What a `genuine` verdict proves

- **Integrity**: the PDF bytes are exactly the bytes that were sealed.
- **Origin of the seal**: the seal was made by the holder of the private key
  whose public key is in the proof; with pinning, that this is the issuer's
  key.
- **Time**: the digest existed no later than the timestamp authority's
  `genTime` (`timestamp: trusted`), and the issuer recorded it at the stated
  position in its ledger (`ledger: consistent`, recomputed locally).

## What it does not prove

- Who signed the underlying document, that they were who they claimed, or
  that they had authority. The seal is the issuer's statement about bytes and
  time, not about the people in the document.
- The legal effect of the document in any jurisdiction.
- That the issuer's private key was never compromised: a stolen key makes
  valid seals. The issuer rotates keys and publishes fingerprints; keep the
  trust list current.
- Global consistency of the ledger: the local check recomputes one entry (or
  one segment). The online check compares against the issuer's published
  chain.

## Attacks considered

| Attack                                 | Defence                                                                           |
| -------------------------------------- | --------------------------------------------------------------------------------- |
| Modified PDF with the original proof   | hash mismatch, signature invalid, timestamp invalid                               |
| Forged proof with a new key            | key rejected when pinned; `unpinned` is reported honestly when not                |
| Replayed proof on a different PDF      | hash mismatch                                                                     |
| Back-dated timestamp                   | the token is signed by a TSA; forging it needs the TSA's key                      |
| Timestamp from a rogue TSA             | chain must reach a shipped or user-supplied root; otherwise `invalid`             |
| Malformed DER to confuse the parser    | strict DER (minimal lengths/integers, no trailing bytes), fail closed             |
| Timing side channels on digest compare | constant-time comparison                                                          |
| Tool phoning home                      | no network code; browser page is one file with no external requests               |
| Supply chain of roots                  | roots downloaded from the CAs' own sites, committed, mirrored by a checked script |
