# Kelee V2 source-quality regression evidence

`source-cases.json` contains exact focused source lines from the authorized,
read-only upstream snapshot captured at 2026-10-02 10:55:24 UTC. Each case records
its official source URL, original line number, and full-source SHA-256. Prior
lines come from the repository's `Loon/` baseline at
`a991b1d3a6b9af719dedc1be8a2c767e8f4228f0`; their file and line hashes are recorded.
These fixtures are never fetched at test or conversion runtime.

- Eight modules / fifteen expanded operations changed empty objects or arrays
  into String values during migration. The guard identifies only these verified
  filename + URL scope + action + path + literal combinations. It does not
  coerce strings globally. A corrected explicit JQ operation clears the blocker.
- SF-Express's upstream line 18 supplies a 446-byte truncated JSON mock. The
  previous payload was 23,756 bytes, valid JSON with three root `obj` entries.
  Its prior body hash/shape replaces duplicating that large payload. A test
  independently decodes the current action arguments with Python's JSON decoder,
  without the converter or Loon parser, to verify source truncation.
- Six Chelaile endpoints intentionally use `**YGKJ` / `YGKJ##` framing in both
  snapshots despite a JSON Content-Type. The exception is limited to those exact
  filename / URL regex / flags combinations, and the unwrapped payload must
  still be valid JSON. Malformed inner JSON or framing is blocked.

Loon's current specification describes String, Number, Boolean, null and variable
JSON values, without JSON auto-decoding of strings:
https://nsloon.app/docs/Rewrite/rewrite_v2/#json

The helper only inspects Rewrite V2. Existing converter validation continues to
own legacy syntax, invalid V2 syntax, unsupported conditions and action types.
Remote or dynamic JSON mocks emit an explicit validation-scope warning, not a
claim that their future bytes are valid. No network or upstream JavaScript runs.

`validate_generated_json_mock(source_filename, url_pattern, body)` independently
validates emitted Map Local payloads after Base64 decoding by the caller. It
uses the manifest's source filename and exact generated pattern. The six
Chelaile scopes accept either the legacy pattern or its exact `(?i:...)` wrapper;
other filenames, scopes, flags, or trailing pattern content do not inherit the
protocol exception. Invalid content raises `ValueError`.
