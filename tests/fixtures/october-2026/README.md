# October 2026 compatibility review

Reviewed on 2026-10-17. Executable examples live in
`tests/test_october_syntax.py`; they are synthetic configurations, not downloaded
JavaScript. The tests exercise the complete staged publication path and mutate
outputs to check that independent validation rejects missing version/platform
guards and invalid routes/actions.

## Primary evidence

- [Loon documentation, 2026-10-10](https://github.com/Loon0x00/Loon0x00.github.io/commit/46cf0a51288906e35aed13ff53155c5bbb057723):
  plugin `include-tun`, `ipv6-vif`, IP Rewrite and SSE Mock content type.
- [Loon documentation, 2026-10-14](https://github.com/Loon0x00/Loon0x00.github.io/commit/032b2720f7d4b557cb5434765cbe426cea9a7b4e):
  domain wildcards and Mac process matching.
- [Surge domain rules](https://manual.nssurge.com/rules/domain.html):
  complete, case-insensitive glob matching and applicable rule flags.
- [Surge process rules](https://manual.nssurge.com/rules/process.html):
  case-sensitive matching, absolute path and directory-prefix modes, no
  pre-matching. Unlike Loon filename matching, this is case-sensitive; filename
  expressions are therefore excluded. Undocumented path character classes and
  NOT's handling of unknown process identity are also excluded. Only explicitly
  macOS-only plugins enter the supported path subset.
- [Surge IP Rewrite](https://manual.nssurge.com/features/ip-rewrite.html):
  IP-layer actions, first matching line, VIF routing prerequisites and minimum
  iOS 5.23 / Mac 6.10 versions.
- [Surge General](https://manual.nssurge.com/profile/general.html) and
  [modules](https://manual.nssurge.com/profile/module.html): route-list append and
  `ipv6-vif=disabled`. Loon plugin `auto/always` has no overriding effect, so
  these source declarations do not generate a Surge General override.
- [Surge Core Version](https://manual.nssurge.com/profile/requirement.html):
  6.10 maps to `6010000`. The new features use this conservative common gate;
  existing feature-only modules retain their previous requirements.

Raw Loon downloads remain unchanged. A repeated destination retains its first
IP Rewrite action, but malformed later actions and duplicate sections still
block publication. The two unavailable script URLs are separately recorded in
`unavailable-scripts.json`; hiding them does not certify that they recovered.

This review establishes documented conversion behavior and static validation.
It does not claim on-device traffic testing or timed SSE streaming emulation.
