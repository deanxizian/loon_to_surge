# JQ serialization audit

Reviewed on 2026-10-21 against the raw Loon inputs and the six live remote JQ
resources. Synthetic semantic regressions live in `tests/test_jq_program.py`.
The audit covered inline legacy / V2 programs, remote programs, generated JSON
add/delete/replace expressions, profile tokenization and independent compilation.

## Findings and regression oracles

- An apostrophe in a valid JQ string (`"O'Hara"`) previously became `\'`, which
  is not a JQ escape. It now becomes `\u0027` inside the JQ string, while the
  profile retains the documented single-quoted JQ form. Real `jq` comparisons
  cover nested interpolation, literal Unicode escapes and backslash parity.
- Inline comments and decoded V2 newlines previously bypassed remote-program
  compaction. All paths now remove only code comments and serialize actual
  string line breaks and controls as JSON escapes. Generated JSON values and
  deletion paths use the same serializer. Source files remain untouched.
- A source-location expression (`$__loc__`) changes when inlined; it is rejected
  in code, including interpolation, but allowed as literal string/comment text.
  Version-dependent backslash-continued comments remain rejected.
- `jq -n 'def audit: (unknown_filter); null'` succeeds because the unused body
  is not resolved. Validation now compiles each expression directly after `empty`,
  catching unknown functions/variables without running filters or introducing
  wrapper names that could mask undefined source calls. A regression
  with `halt_error(42)` verifies the absence of execution. Comment-safe wrapper
  lines and their source mapping provide accurate module/line diagnostics.
- Publication tests cover both inline dialects, real remote download/cache
  paths, no-op comments, and preservation of all prior output bytes on failure.

The existing published corpus passed the strengthened compiler. These new edge
cases were reproduced with synthetic valid inputs; they are not claims that
additional currently published plugins are broken. Static compilation and
bounded JQ data comparisons do not establish on-device traffic behavior.

## Primary references

- [JQ strings and interpolation](https://jqlang.org/manual/#string-interpolation)
- [JQ source locations](https://jqlang.org/manual/#__loc__)
- [JQ empty](https://jqlang.org/manual/#empty)
- [Surge JQ Body Rewrite](https://manual.nssurge.com/http/body-rewrite.html)
- [Loon V2 strings and JSON Actions](https://nsloon.app/docs/Rewrite/rewrite_v2/)

## Upstream cross-check

- [Loon docs changes through Build 1009](https://github.com/Loon0x00/Loon0x00.github.io/compare/032b2720f7d4b557cb5434765cbe426cea9a7b4e...b0d130e98a79b5eb755c37593d76867ff47edc29):
  new Mac gateway, DHCP, performance articles and release notes; the only
  change under `docs/` formats the IP rule headings. No new JQ syntax.
- [Script-Hub changes since the previous review](https://github.com/Script-Hub-Org/Script-Hub/compare/b31b010d111aa81e8b89635f08d401c960d29538...d9d7473831c057ac0c28ba15c01a0a351099d95d):
  V2 intermediate conversion, quoting/regex handling, Stash behavior, and Mac
  process-rule preservation. This converter retains its stricter documented
  cross-app semantics and verified Object adapters.
- [LoonKissSurge latest commit](https://github.com/QingRex/LoonKissSurge/commit/913ec005f544221e6c56a7d0ecec81c4b3b914bb)
  remains dated 2026-04-19.
- Nine Surge manual articles with local 2026-10-17 snapshots have identical
  article HTML on 2026-10-21: profile format/module/requirements, domain rules,
  script overview/request/response/API, and IP Rewrite. Current body rewrite
  and process-rule pages still report the 2026-10-14 site build; no new JQ
  conversion syntax was found.
- GET with the project's Loon User-Agent still returned HTTP 404 for
  `CommonScript/replace-body.js` and `EasyBike/mobileconfig-gateway.js` under
  `https://kelee.one/Resource/JavaScript/`. Their dependent modules remain hidden.
