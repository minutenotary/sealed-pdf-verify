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
2. finds the seal under `seals/` whose `documentHash` matches. Current
   archives carry the public key and the token inside the seal JSON; older
   ones kept them next to it as `.public-key.pem` and `.tsr`, which are read
   only when the JSON omits those fields,
3. takes the ledger block from the `segment.json` entry with the same digest
   and the same `sealedAt` (a document sealed twice has two entries); a
   `ledger` block inside the seal JSON is ignored,
4. runs the five checks on each document,
5. walks the whole segment: every entry recomputes, each `previousEntryHash`
   equals the prior `entryHash`, `seq` increases by one.

The archive verdict is `altered` if any document is altered or the segment is
broken, `incomplete` if a PDF has no matching seal, is not mentioned by the
segment, could not be assembled (for example a key file that is not UTF-8)
or an entry was refused by the inflation limits, otherwise `genuine`. A seal
that matches no document is noted.

Only `README.txt`, `seals/`, `ledger/segment.json` and `documents/` are
inflated, 256 MiB per entry, 1 GiB and 1 000 entries in total; everything
else in the archive stays compressed and is never read. Paths, seal files
and their side files are matched case-insensitively.
Seals marked `superseded` are verified like any other and flagged in the
notes with the stated reason. A top-level folder inside the ZIP is tolerated.
