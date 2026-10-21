# Remote JQ comment serialization

Reviewed on 2026-10-21 following
[the failed scheduled update](https://github.com/deanxizian/loon_to_surge/actions/runs/39486337145).
All 275 downloads completed, but real jq compilation rejected the candidate;
the previous published output was retained.

The changed upstream [Amap detail program](https://kelee.one/Resource/JQLang/Amap/search_poi_detail.jq)
has inline comments after list entries and function definitions. The downloaded
11,158-byte version has SHA-256
`7def102b752835f8cbe63167b75dbe19997cb532f7e35d8283de4eeb5f2d4eb6`.
It compiles as downloaded. The old loader removed only comment-only lines,
then joined the remaining lines, allowing the first inline `#` to consume the
rest of the program. This is a serialization defect, not invalid upstream JQ
or a new Loon/Surge rule type.

`amap-detail-minimal.jq` is a synthetic reproduction of that layout and its
module/reference filtering, rather than a patched copy of the upstream source.
`tests/test_jq_program.py` compares real jq outputs before and after serialization,
including literal hashes, quote/backslash escaping, string line breaks, nested
interpolation, cached downloads, legacy/V2 publication, and failure preservation.

Primary references:

- [JQ comments](https://jqlang.org/manual/#comments) and
  [interpolation](https://jqlang.org/manual/#string-interpolation).
- [JQ 1.7.1 lexer](https://github.com/jqlang/jq/blob/jq-1.7.1/src/lexer.l)
  versus [JQ 1.8.1 lexer](https://github.com/jqlang/jq/blob/jq-1.8.1/src/lexer.l):
  odd-backslash comment continuation is version dependent. It is rejected
  pending confirmation of both clients' runtime semantics. Ordinary comments,
  including even-backslash endings and an EOF comment, can be removed safely.
- [Surge Body Rewrite](https://manual.nssurge.com/http/body-rewrite.html): JQ
  expressions occupy one rule line and invalid programs are skipped by Surge.

The real jq compiler remains mandatory for publication. Source downloads and
remote cache text are retained as received; only emitted expressions are
compacted. Static and synthetic JSON comparisons do not constitute device
traffic validation.
