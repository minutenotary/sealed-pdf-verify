# Evidence archives

On request the issuer produces an evidence ZIP for a case. Its layout:

```
README.txt
documents/<name>.pdf            one or more sealed PDFs
seals/<sealId>.json             the proof fields (minus schemaVersion/ledger) plus
                                disposition, roundSequence, supersededAt, supersededReason
seals/<sealId>.public-key.pem   the signing public key
seals/<sealId>.tsr              the raw RFC 3161 token (only when a timestamp exists)
ledger/segment.json             the ledger entries around these seals
audit/booking-audit-log.json    issuer-side log, ignored by the verifier
```

`sealed-pdf-verify evidence.zip` (or `verifyEvidenceZip(bytes)`):

1. hashes every PDF under `documents/`,
2. finds the seal under `seals/` whose `documentHash` matches (falling back to
   the `.public-key.pem` and `.tsr` files when the JSON omits those fields),
3. takes the ledger block from the matching `segment.json` entry,
4. runs the five checks on each document,
5. walks the whole segment: every entry recomputes, each `previousEntryHash`
   equals the prior `entryHash`, `seq` increases by one.

The archive verdict is `altered` if any document is altered or the segment is
broken, `incomplete` if a PDF has no matching seal, otherwise `genuine`.
Seals marked `superseded` are verified like any other and flagged in the
notes with the stated reason. A top-level folder inside the ZIP is tolerated.
