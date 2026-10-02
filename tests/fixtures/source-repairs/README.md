# Reviewed Kelee source compatibility repairs

These ten raw `.lpx` fixtures are the exact read-only upstream snapshot captured
at **2026-10-02 10:55:24 UTC**. `provenance.json` records the official URL, full
current source SHA-256, full prior source SHA-256, exact original line numbers
and hashes, replacement hashes, and expected repaired full-file SHA-256.
The previous intent comes from the tracked `Loon/` source at revision
`a991b1d3a6b9af719dedc1be8a2c767e8f4228f0`.

The approved repairs are limited to:

- Eight files: fifteen empty object/array replacements across thirteen directives
  use explicit JQ with the same existing-path guards as the previous conversion.
  Strings in any other source or endpoint are not coerced.
- JiaXiaoDrive: restore the exact baseline URL guard and all twelve deletion
  paths that the malformed upstream migration lost. The V2 `/i` URL flag is
  retained, and no deletion rule is silently discarded.
- SF-Express: restore the exact complete baseline JSON payload. Independently
  decoding the raw action arguments proved that all 432 characters / 446 UTF-8
  bytes of the current body are an unchanged prefix of the baseline body.
  The latter has 23,756 UTF-8 bytes and three root `obj` entries. Its hash is
  recorded instead of duplicating the complete large prior source file.

`source_repairs.py` contains the reviewed replacement bytes so conversion needs
no historical checkout, network, or downloaded code. All file and line assertions
are checked before returning corrected text. Raw upstream files remain intact;
correction occurs only in memory and emits explicit `source-repair-applied`
reports, including original/repaired hashes and prior-source provenance.

An unknown version of one of these filenames is **not** patched with old data.
It receives a fatal `source-repair-blocked` report and requires renewed review.
The exact known baseline and already-repaired versions are accepted unchanged.
Other filenames are outside this policy. A corrected future upstream version
must be reviewed and its obsolete repair pin removed or superseded explicitly.

The tests execute only generated JQ on synthetic JSON; no upstream JavaScript
runs. They verify all fifteen typed replacements, missing-target/parent guards,
all twelve deletion paths, unchanged unrelated source lines, policy-mismatch
atomicity, strict generated JSON validation, and preservation of fixture bytes.
