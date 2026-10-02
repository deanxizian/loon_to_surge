# Script V2 type review, 2026-10-02

The public JavaScript was downloaded and statically read, never executed. The
source-review.json records URL, SHA-256 and representative excerpts. The converter
must fetch and match the digest before publishing an adapted Object argument.
A fetch failure or changed digest is a fatal publication blocker, not a green
module exclusion. This verifies the reviewed version at conversion time; remote
script URLs remain mutable after publication, so it does not freeze runtime code.

Supported codecs are deliberately limited:

- Spotify: type-dispatch accepts JSON String or Object, then shares one processing
  path. Boolean switch values must remain JSON Booleans, not quoted strings.
- Netease: tries JSON.parse($argument), falls back to Object; the same property
  operations then consume the result. Boolean switches remain JSON Booleans.
- YouTube ads: its platform factory selects Surge unless $loon/$task is present.
  Surge's decodeParams parses JSON; Loon reads the Object properties. Only reviewed
  Boolean switches and finite quote-safe captionLang choices are representable.
  The upstream debug argument is not consumed by the current shared handlers;
  conversion does not fix that upstream behavior.
- YouTube subtitles: String arguments split on '&' and '='; Object arguments pass
  through. BOTH then normalize Settings recursively, including 'true'/'false' to
  Boolean. Only known Boolean switches and finite delimiter-safe Type/Position
  choices are adapted. There is no generic query encoding assumption.

Retained exclusions:

- FollowRSS and IThome read $argument properties directly. Surge's String cannot
  satisfy those reads. Serializing JSON would silently lose all those values.
- Tieba's String branch converts 'false' to false, but its Object branch preserves
  the source select's String 'false'. removeThread uses its truthiness. Those
  behaviors differ, so changing it to a Boolean would be an upstream behavior fix,
  not a faithful conversion.
- WPS's input variables are unrestricted Strings. Its query parser does not URL
  decode, and splits values at '&' and '='. No lossless placeholder escaping is
  available for that entire declared domain. API-key-shaped assumptions are not
  an enforceable source restriction. DAY is not present in the source Object and
  must not be silently added.
- Bilibili and Apple Weather are outside this adapter allowlist; their independent
  policy/runtime exclusions must not be relaxed by seeing a familiar parse token.

Dynamic enable is adapted only from a declared Boolean switch with no other use
of that variable anywhere in the module. True maps to the empty line prefix;
false maps to '#'. The generated Surge parameter is therefore a line-prefix
parameter, and its UI is not the original Loon Boolean switch. Only values from the original declared domain are supported;
Surge exposes free-text parameters and does not enforce the original choices.

Dynamic Cron input/select defaults (and every finite choice) must be numeric,
five/six fields, in range, free of quotes/backslashes/control characters and any
placeholder-like syntax. Surge substitutes the module parameter into a quoted
cronexp; a user editing Surge parameters must supply a valid Cron expression.

Primary references:
- https://manual.nssurge.com/scripting/api.html ($argument is a String)
- https://manual.nssurge.com/profile/module.html (textual parameter replacement)
- https://manual.nssurge.com/scripting/cron.html (5/6-field cronexp)
