"""Bounded, source-verified Script V2 argument adapters.

This module never executes downloaded JavaScript. An Object adapter is enabled only
for a reviewed exact URL AND SHA-256, and only for representable declaration types.
A callable supplied by the converter must load the current bytes. An unavailable or
changed source is deliberately unsupported, never an invitation to guess a codec.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import hashlib
import json
import re

try:
    from loon_rewrite_v2 import RewriteV2Error, V2String, V2Variable, parse_v2_value
    from loon_script_v2 import V2ArgumentObject, V2Script, is_script_v2_line, parse_script_v2_line
except ModuleNotFoundError:
    from scripts.loon_rewrite_v2 import RewriteV2Error, V2String, V2Variable, parse_v2_value
    from scripts.loon_script_v2 import V2ArgumentObject, V2Script, is_script_v2_line, parse_script_v2_line


class ScriptSourceVerificationError(RuntimeError):
    """A reviewed adapter cannot be verified now; stop publication, do not exclude."""


class UnverifiedScriptArgument(ValueError):
    """Valid source whose typed semantics cannot be preserved by this adapter."""


@dataclass(frozen=True)
class ArgumentDeclaration:
    name: str
    kind: str
    values: tuple[str | bool, ...]

    @property
    def default(self) -> str | bool:
        return self.values[0]


@dataclass(frozen=True)
class ScriptV2Context:
    declarations: Mapping[str, ArgumentDeclaration]
    non_enable_names: frozenset[str]
    declaration_errors: Mapping[str, str]


@dataclass(frozen=True)
class ObjectAdapter:
    sha256: str
    codec: str
    boolean_keys: frozenset[str]
    string_keys: frozenset[str] = frozenset()


BASE = "https://kelee.one/Resource/JavaScript/"
# Reviewed read-only on 2026-10-02. Tests/fixtures/script-v2-compat records the
# exact parse branches and exclusions. A URL alone is NOT sufficient evidence.
VERIFIED_OBJECT_ADAPTERS = {
    BASE + "Spotify/Spotify_remove_ads.js": ObjectAdapter(
        "198cb5869d9710c56ed1945156c8f6227fdf9d19da38ee1c8870f4d72f26c6c8",
        "json", frozenset({"tab", "useractivity"})),
    BASE + "NeteaseCloudMusic/NeteaseCloudMusic_remove_ads.js": ObjectAdapter(
        "20c13c7c598b8e59058493e2143d5c62d27ce6ac2917d04c400fa16caa092528",
        "json", frozenset({"MY", "DT", "FX", "PRGG", "PRRK", "PRDRD", "PRSCVPT", "PRST", "PRRR", "HMPR", "PRMST", "PRCN"})),
    BASE + "YouTube/YouTube_remove_ads/YouTube_remove_ads_request.js": ObjectAdapter(
        "af0646890f9847aa4576181b0637e31b86a3e2f6dd4d2041a56ffa971aacc10b",
        "json", frozenset({"blockUpload", "blockShorts", "blockImmersive", "debug"}), frozenset({"captionLang"})),
    BASE + "YouTube/YouTube_remove_ads/YouTube_remove_ads_response.js": ObjectAdapter(
        "b926d339069a8f54e84bd5d29e8c8364ee9ea72bb170197e281b04eda49e3568",
        "json", frozenset({"blockUpload", "blockShorts", "blockImmersive", "debug"}), frozenset({"captionLang"})),
    BASE + "YouTube/YouTube_Subtitles_Translate/YouTube_Subtitles_request.js": ObjectAdapter(
        "069cb5f3158c7777a8c0dbac926d3ce0ca605587d3123c386dc65a15d51fabc8",
        "query-normalized", frozenset({"AutoCC", "ShowOnly"}), frozenset({"Type", "Position"})),
    BASE + "YouTube/YouTube_Subtitles_Translate/YouTube_Subtitles_response.js": ObjectAdapter(
        "624bec4a6b3162971a458e2ccb097efd20a906016b82293c341d344152edc09c",
        "query-normalized", frozenset({"AutoCC", "ShowOnly"}), frozenset({"Type", "Position"})),
}
UNSUPPORTED_OBJECT_REASONS = {
    BASE + "FollowRSS/FollowRSS_checkin.js": "script reads Object properties directly and has no String argument adapter",
    BASE + "IThome/IThome_remove_ads.js": "script reads Object properties directly and has no String argument adapter",
    BASE + "Tieba/tieba-proto.js": "String branch coerces quoted select strings to Boolean, changing false-string truthiness",
    BASE + "WPS/WPS_checkin.js": "raw query parser cannot losslessly carry unrestricted input strings containing '&' or '='",
}


def _normalized_name(name: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", name.strip())
    return ("ARG_" if value and not re.match(r"[A-Za-z_]", value) else "") + (value or "ARG")


def placeholder(name: str) -> str:
    return "{{{" + _normalized_name(name) + "}}}"


def _tokens(text: str) -> list[str]:
    """Split legacy argument declarations without interpreting metadata as V2."""
    result, start, quote, escaped = [], 0, "", False
    for index, char in enumerate(text):
        if quote:
            if char == quote and not escaped:
                quote = ""
            escaped = char == "\\" and not escaped
        elif char in {'"', "'"}:
            quote = char
        elif char == ",":
            result.append(text[start:index].strip())
            start = index + 1
    if quote:
        raise UnverifiedScriptArgument("unterminated argument declaration quote")
    result.append(text[start:].strip())
    return result


def _scalar(text: str) -> str | bool:
    # Argument declarations are legacy syntax, not V2 action strings. In
    # particular, backticks would survive the module-default renderer literally.
    if text not in {"true", "false"} and not (text.startswith('"') and text.endswith('"')):
        raise UnverifiedScriptArgument("argument requires a double-quoted String or Boolean declaration")
    value = parse_v2_value(text)
    if isinstance(value, bool):
        return value
    if isinstance(value, V2String) and all(isinstance(part, str) for part in value.parts):
        return "".join(value.parts)
    raise UnverifiedScriptArgument("argument requires a static String or Boolean declaration")


def _declaration(line: str) -> ArgumentDeclaration:
    name, separator, text = line.partition("=")
    name = name.strip()
    if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name):
        raise UnverifiedScriptArgument("argument name or declaration is invalid")
    tokens = _tokens(text)
    if len(tokens) < 2 or tokens[0] not in {"switch", "select", "input"}:
        raise UnverifiedScriptArgument("argument type must be switch, select, or input")
    kind = tokens[0]
    metadata_names = {match.group(1).lower() for token in tokens[1:]
                      if (match := re.match(r"^([A-Za-z_][\w-]*)\s*=", token))}
    if "type" in metadata_names:
        raise UnverifiedScriptArgument("explicit argument type metadata has not been verified")
    if metadata_names - {"tag", "desc"}:
        raise UnverifiedScriptArgument("unknown argument declaration metadata has not been verified")
    values = []
    metadata_started = False
    for token in tokens[1:]:
        if re.match(r"^(?:tag|desc)\s*=", token, re.I):
            metadata_started = True
            continue
        if metadata_started:
            raise UnverifiedScriptArgument("argument metadata must contain only tag= or desc= fields")
        values.append(_scalar(token))
    if not values:
        raise UnverifiedScriptArgument("argument has no default")
    if kind == "switch" and (len(values) != 2 or any(type(v) is not bool for v in values) or set(values) != {False, True}):
        raise UnverifiedScriptArgument("switch requires two distinct Boolean values")
    if kind == "input" and (len(values) != 1 or not isinstance(values[0], str)):
        raise UnverifiedScriptArgument("input requires one String default")
    if kind == "select" and (len(values) < 2 or any(type(v) is not type(values[0]) for v in values)):
        raise UnverifiedScriptArgument("select requires at least two consistently typed values")
    return ArgumentDeclaration(name, kind, tuple(values))


def _value_names(value: object) -> set[str]:
    if isinstance(value, V2Variable):
        return {value.name}
    if isinstance(value, V2String):
        return {part.name for part in value.parts if isinstance(part, V2Variable)}
    if isinstance(value, V2ArgumentObject):
        return {part.name for part in value.variables}
    return set()


def build_script_v2_context(argument_lines: Iterable[str], script_lines: Iterable[str],
                            other_section_lines: Iterable[str] = ()) -> ScriptV2Context:
    declarations: dict[str, ArgumentDeclaration] = {}
    errors: dict[str, str] = {}
    normalized: dict[str, str] = {}
    for line in argument_lines:
        name = line.partition("=")[0].strip()
        try:
            declaration = _declaration(line)
            if name in declarations or name in errors:
                raise UnverifiedScriptArgument(f"duplicate argument declaration: {name}")
            normalized_name = _normalized_name(name)
            if normalized_name in normalized:
                previous = normalized[normalized_name]
                errors[previous] = f"argument name collision with {name}"
                raise UnverifiedScriptArgument(f"argument name collision with {previous}")
            normalized[normalized_name] = name
            declarations[name] = declaration
        except (RewriteV2Error, UnverifiedScriptArgument) as exc:
            errors[name] = str(exc)
    non_enable: set[str] = set()
    # Legacy usage is deliberately conservative, including legacy enable; mixing
    # typed V2 toggles with an untyped legacy reference needs separate review.
    scan_lines = list(other_section_lines)
    for line in script_lines:
        if not is_script_v2_line(line):
            scan_lines.append(line)
            continue
        try:
            script = parse_script_v2_line(line)
        except RewriteV2Error:
            scan_lines.append(line)
            continue  # The main parser is responsible for fatal diagnostics.
        non_enable.update(_value_names(script.schedule))
        non_enable.update(_value_names(script.argument))
        non_enable.update(_value_names(script.path))
        for key, value in script.properties.items():
            if key != "enable":
                non_enable.update(_value_names(value))
        scan_lines.append(script.condition or "")
    for line in scan_lines:
        non_enable.update(re.findall(r"\$?\{([A-Za-z_][A-Za-z0-9_.-]*)\}", line))
    return ScriptV2Context(declarations, frozenset(non_enable), errors)


def _lookup(context: ScriptV2Context, name: str) -> ArgumentDeclaration:
    if name in context.declaration_errors:
        raise UnverifiedScriptArgument(f"{name}: {context.declaration_errors[name]}")
    if name not in context.declarations:
        raise UnverifiedScriptArgument(f"plugin argument {name!r} is not declared")
    return context.declarations[name]


def _safe_finite_values(declaration: ArgumentDeclaration, *, boolean: bool) -> None:
    if boolean:
        if declaration.kind not in {"switch", "select"} or any(type(v) is not bool for v in declaration.values):
            raise UnverifiedScriptArgument(f"{declaration.name} requires Boolean values, not Boolean-looking strings")
    elif declaration.kind != "select" or any(not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", v) for v in declaration.values):
        raise UnverifiedScriptArgument(f"{declaration.name} requires finite, quote-safe String choices")


def serialize_object_argument(script: V2Script, context: ScriptV2Context,
                              source_loader: Callable[[str], bytes] | None) -> str:
    if not isinstance(script.argument, V2ArgumentObject):
        raise TypeError("Object argument expected")
    path = "".join(script.path.parts)
    adapter = VERIFIED_OBJECT_ADAPTERS.get(path)
    if adapter is None:
        reason = UNSUPPORTED_OBJECT_REASONS.get(path, "no reviewed Surge String adapter for this script URL")
        raise UnverifiedScriptArgument(reason)
    if source_loader is None:
        raise ScriptSourceVerificationError("current script bytes are required to verify the reviewed Object adapter")
    try:
        data = source_loader(path)
    except Exception as exc:
        raise ScriptSourceVerificationError(f"unable to verify current Object adapter source: {type(exc).__name__}") from exc
    if not isinstance(data, bytes) or hashlib.sha256(data).hexdigest() != adapter.sha256:
        raise ScriptSourceVerificationError("script source digest differs from the reviewed Object adapter")
    pairs = []
    for variable in script.argument.variables:
        name = variable.name
        declaration = _lookup(context, name)
        if name not in adapter.boolean_keys | adapter.string_keys:
            raise UnverifiedScriptArgument(f"Object property {name!r} was not reviewed for this adapter")
        boolean = name in adapter.boolean_keys
        _safe_finite_values(declaration, boolean=boolean)
        value = placeholder(name)
        if adapter.codec == "json":
            pairs.append(json.dumps(name) + ":" + (value if boolean else json.dumps(value)))
        elif adapter.codec == "query-normalized":
            pairs.append(name + "=" + value)
        else:
            raise UnverifiedScriptArgument("unrecognized reviewed adapter codec")
    return "{" + ",".join(pairs) + "}" if adapter.codec == "json" else "&".join(pairs)


def _validate_cron(text: str) -> None:
    fields = text.split(" ")
    if len(fields) not in {5, 6} or any(not field for field in fields):
        raise UnverifiedScriptArgument("dynamic Cron default must have five or six single-space-separated fields")
    bounds = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    if len(fields) == 6:
        bounds.insert(0, (0, 59))
    for field, (low, high) in zip(fields, bounds):
        for part in field.split(","):
            match = re.fullmatch(r"(\*|[0-9]{1,3}(?:-[0-9]{1,3})?)(?:/([0-9]{1,3}))?", part)
            if not match or match.group(2) is not None and int(match.group(2)) == 0:
                raise UnverifiedScriptArgument("dynamic Cron declaration contains unsafe or unsupported syntax")
            if match.group(1) != "*":
                values = [int(value) for value in match.group(1).split("-")]
                if values[0] > values[-1] or any(not low <= value <= high for value in values):
                    raise UnverifiedScriptArgument("dynamic Cron declaration contains an out-of-range field")


@dataclass(frozen=True)
class AdaptedScriptV2:
    script: V2Script
    argument_override: str | None = None
    cron_override: str | None = None
    enable_prefix: str | None = None
    toggle_defaults: tuple[tuple[str, str], ...] = ()
    argument_codec: str | None = None
    source_sha256: str | None = None

    def apply_parts(self, parts: list[str]) -> list[str]:
        """Call only after prepare_script_v2(self.script) validated normal syntax."""
        output = list(parts)
        if self.argument_override is not None:
            output = [part for part in output if not part.startswith("argument=")]
            output.append("argument=" + json.dumps(self.argument_override, ensure_ascii=False))
        if self.cron_override is not None:
            output = ["cronexp=" + json.dumps(self.cron_override) if part.startswith("cronexp=") else part for part in output]
        return output


def adapt_script_v2(script: V2Script, context: ScriptV2Context, *,
                    source_loader: Callable[[str], bytes] | None = None) -> AdaptedScriptV2:
    """Remove only verified typed features, retaining normal parser validation.

    The caller must pass the returned script through its usual prepare_script_v2,
    then apply_parts and emit enable_prefix when present. Merge toggle_defaults
    into the module defaults. Never use the prepared script alone as the result.
    """
    argument_override = cron_override = enable_prefix = None
    toggle_defaults: tuple[tuple[str, str], ...] = ()
    prepared = script
    argument_codec = source_sha256 = None
    if isinstance(script.argument, V2ArgumentObject):
        argument_override = serialize_object_argument(script, context, source_loader)
        adapter = VERIFIED_OBJECT_ADAPTERS["".join(script.path.parts)]
        argument_codec, source_sha256 = adapter.codec, adapter.sha256
        prepared = replace(prepared, argument=None)
    if isinstance(script.schedule, V2Variable):
        declaration = _lookup(context, script.schedule.name)
        if declaration.kind not in {"input", "select"} or any(not isinstance(value, str) for value in declaration.values):
            raise UnverifiedScriptArgument("dynamic Cron requires a String input or String select declaration")
        for value in declaration.values:
            _validate_cron(value)
        cron_override = placeholder(declaration.name)
        prepared = replace(prepared, schedule=V2String((declaration.default,)))
    enable = script.properties.get("enable")
    if isinstance(enable, V2Variable):
        declaration = _lookup(context, enable.name)
        if declaration.kind != "switch" or any(type(v) is not bool for v in declaration.values):
            raise UnverifiedScriptArgument("dynamic enable requires a Boolean switch declaration")
        if enable.name in context.non_enable_names:
            raise UnverifiedScriptArgument("dynamic enable argument is shared with non-enable semantics")
        properties = dict(prepared.properties)
        properties.pop("enable")
        prepared = replace(prepared, properties=properties)
        enable_prefix = placeholder(enable.name)
        toggle_defaults = ((enable.name, "" if declaration.default else "#"),)
    return AdaptedScriptV2(prepared, argument_override, cron_override, enable_prefix, toggle_defaults, argument_codec, source_sha256)
