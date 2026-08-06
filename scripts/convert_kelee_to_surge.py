from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from stable_output import file_contents_match, json_payload_matches, previous_timestamp, tree_contents_match
except ModuleNotFoundError:
    from scripts.stable_output import file_contents_match, json_payload_matches, previous_timestamp, tree_contents_match

try:
    from loon_rewrite_v2 import (
        RewriteV2Error,
        V2Action,
        V2Array,
        V2Number,
        V2Regex,
        V2String,
        V2UrlCondition,
        V2Value,
        V2Variable,
        is_rewrite_v2_line,
        parse_rewrite_v2_line,
        parse_url_only_condition,
    )
except ModuleNotFoundError:
    from scripts.loon_rewrite_v2 import (
        RewriteV2Error,
        V2Action,
        V2Array,
        V2Number,
        V2Regex,
        V2String,
        V2UrlCondition,
        V2Value,
        V2Variable,
        is_rewrite_v2_line,
        parse_rewrite_v2_line,
        parse_url_only_condition,
    )


WINDOWS_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')
SECTION_ORDER = (
    "General",
    "Rule",
    "URL Rewrite",
    "Header Rewrite",
    "Body Rewrite",
    "Map Local",
    "Panel",
    "Script",
    "MITM",
)
JQ_PATH_CACHE: dict[str, str] = {}
LOON_USER_AGENT = "Loon/860 CFNetwork/3826.500.111.2.2 Darwin/24.4.0"
DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
IP_RULE_TYPES = {"IP-CIDR", "IP-CIDR6"}
LOGICAL_RULE_TYPES = {"AND", "OR", "NOT"}
PRE_MATCHING_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-SET",
    "DOMAIN-WILDCARD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "IP-ASN",
    "SUBNET",
    "DEST-PORT",
    "SRC-PORT",
    "SRC-IP",
}
MODULE_RULE_POLICIES = frozenset({"DIRECT", "REJECT", "REJECT-TINYGIF"})
FATAL_REPORT_KINDS = {
    "argument-default",
    "argument-name-collision",
    "argument-parse",
    "general-pass-through",
    "jq-path-inline-failed",
    "mitm-unsupported",
    "unsupported-header-rewrite",
    "unsupported-rewrite",
    "unsupported-script",
    "unsupported-system",
}
LOON_SCRIPT_COMMON_PROPERTIES = {
    "argument",
    "debug",
    "enable",
    "engine",
    "script-path",
    "script-update-interval",
    "tag",
    "timeout",
}
LOON_SCRIPT_TYPE_PROPERTIES = {
    "cron": {"wake-system"},
    "generic": {"img-url"},
    "http-request": {"ability", "binary-body-mode", "max-size", "requires-body"},
    "http-response": {"ability", "binary-body-mode", "max-size", "requires-body"},
}
NODE_LINK_CHECK_SCRIPT_PATH = "https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js"
WARP_PANEL_SCRIPT_PATH = "https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js"
VERIFIED_SURGE_GENERIC_SCRIPT_PATHS = frozenset({NODE_LINK_CHECK_SCRIPT_PATH, WARP_PANEL_SCRIPT_PATH})
LOON_MOCK_CONTENT_TYPES = {
    "json": "application/json",
    "text": "text/plain",
    "css": "text/css",
    "html": "text/html",
    "javascript": "text/javascript",
    "plain": "text/plain",
    "png": "image/png",
    "gif": "image/gif",
    "jpeg": "image/jpeg",
    "tiff": "image/tiff",
    "svg": "image/svg+xml",
    "mp4": "video/mp4",
    "form-data": "multipart/form-data",
}
JQ_COMPATIBILITY_REWRITES = (
    ('type=="object"then', 'type=="object" then'),
    (
        'type=="object"and .name as $name|$name|IN(namesToRemove[])|not',
        'type=="object" and (.name as $name|$name|IN(namesToRemove[])|not)',
    ),
    (')else .end;removeParentIfNameMatches', ') else . end;removeParentIfNameMatches'),
)


def timestamp() -> str:
    value = datetime.now().astimezone()
    text = value.strftime("%Y-%m-%d %H:%M:%S %z")
    return f"{text[:-2]}:{text[-2:]}"


def assert_under_root(path: Path, root: Path) -> None:
    resolved_path = path.resolve()
    resolved_root = root.resolve()
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise RuntimeError(f"Refusing to modify path outside workspace: {resolved_path}") from exc


def split_top_level(text: str | None, delimiter: str = ",") -> list[str]:
    if not text:
        return []

    items: list[str] = []
    builder: list[str] = []
    quote = ""
    round_depth = 0
    square_depth = 0
    curly_depth = 0
    previous = ""

    for char in text:
        if quote:
            builder.append(char)
            if char == quote and previous != "\\":
                quote = ""
            previous = char
            continue

        if char in ("'", '"'):
            quote = char
            builder.append(char)
        elif char == "(":
            round_depth += 1
            builder.append(char)
        elif char == ")":
            round_depth = max(0, round_depth - 1)
            builder.append(char)
        elif char == "[":
            square_depth += 1
            builder.append(char)
        elif char == "]":
            square_depth = max(0, square_depth - 1)
            builder.append(char)
        elif char == "{":
            curly_depth += 1
            builder.append(char)
        elif char == "}":
            curly_depth = max(0, curly_depth - 1)
            builder.append(char)
        elif char == delimiter and round_depth == 0 and square_depth == 0 and curly_depth == 0:
            item = "".join(builder).strip()
            if item:
                items.append(item)
            builder = []
        else:
            builder.append(char)

        previous = char

    item = "".join(builder).strip()
    if item:
        items.append(item)
    return items


def strip_rule_inline_comment(text: str) -> str:
    quote = ""
    previous = ""

    for index, char in enumerate(text):
        if quote:
            if char == quote and previous != "\\":
                quote = ""
        else:
            if char in ("'", '"'):
                quote = char
            elif (
                char == "/"
                and index + 1 < len(text)
                and text[index + 1] == "/"
                and (index == 0 or text[index - 1].isspace())
            ):
                return text[:index].rstrip()

        previous = char

    return text.strip()


def split_first(text: str | None, delimiter: str) -> tuple[str, str]:
    if text is None:
        return "", ""
    index = text.find(delimiter)
    if index < 0:
        return text, ""
    return text[:index], text[index + len(delimiter) :]


def quote_jq_string(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def surge_argument_name(name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", name.strip())
    if not normalized:
        return "ARG"
    if not re.match(r"[A-Za-z_]", normalized):
        normalized = "ARG_" + normalized
    return normalized


def surge_argument_placeholder(name: str) -> str:
    return f"%{surge_argument_name(name)}%"


def convert_placeholder(text: str) -> str:
    return re.sub(
        r"\{([A-Za-z0-9_.-]+)\}",
        lambda match: surge_argument_placeholder(match.group(1)),
        text,
    )


def convert_argument_value(value: str) -> str:
    converted = convert_placeholder(value.strip())
    unquoted = converted
    if len(unquoted) >= 2 and unquoted[0] == unquoted[-1] and unquoted[0] in ("'", '"'):
        unquoted = unquoted[1:-1]
    return '"' + unquoted.replace('"', '\\"') + '"'


def collect_loon_placeholder_names(text: str) -> set[str]:
    return set(re.findall(r"(?<!\{)\{([A-Za-z0-9_.-]+)\}(?!\})", text))


def convert_json_value(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"true|false|null|\[\]|\{\}|-?\d+(\.\d+)?", value):
        return value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return quote_jq_string(value[1:-1])
    return quote_jq_string(value)


def convert_path_to_jq_array(path: str) -> str:
    segments: list[str | int] = []
    builder: list[str] = []
    i = 0

    def flush_token() -> None:
        nonlocal builder
        if builder:
            segments.append("".join(builder))
            builder = []

    while i < len(path):
        char = path[i]
        if char == ".":
            flush_token()
        elif char == "[":
            flush_token()
            end = path.find("]", i + 1)
            if end < 0:
                builder.append(char)
            else:
                inside = path[i + 1 : end].strip()
                if len(inside) >= 2 and inside[0] == inside[-1] and inside[0] in ("'", '"'):
                    segments.append(inside[1:-1])
                elif re.fullmatch(r"-?\d+", inside):
                    segments.append(int(inside))
                else:
                    segments.append(inside)
                i = end
        else:
            builder.append(char)
        i += 1

    flush_token()
    return json.dumps(segments, ensure_ascii=False, separators=(",", ":"))


def path_segments(path: str) -> list[str | int]:
    return json.loads(convert_path_to_jq_array(path))


def jq_array(segments: list[str | int]) -> str:
    return json.dumps(segments, ensure_ascii=False, separators=(",", ":"))


def convert_delete_paths_to_jq(paths: list[str]) -> list[str]:
    return ["'delpaths([" + convert_path_to_jq_array(path) + "])'" for path in paths]


def convert_delete_source_to_jq(
    text: str,
    report: list[dict[str, str]],
    file: str,
    line: str,
) -> list[str]:
    stripped = text.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
        expression = stripped[1:-1].strip()
        if re.match(r"^(?:del|delpaths)\s*\(", expression):
            add_report(
                report,
                file,
                "rewrite-action-corrected",
                "JSON delete contains a complete JQ expression; converted as JQ instead of splitting it into key paths.",
                line,
            )
            return [quote_jq_expression(expression)]

    paths = [item for item in re.split(r"\s+", stripped) if item]
    return convert_delete_paths_to_jq(paths)


def convert_replace_pair_to_jq(path_text: str, value_text: str) -> str:
    segments = path_segments(path_text)
    if not segments:
        return "'" + convert_json_value(value_text) + "'"

    parent = jq_array(segments[:-1])
    key = json.dumps(segments[-1], ensure_ascii=False, separators=(",", ":"))
    path = jq_array(segments)
    value = convert_json_value(value_text)
    return f"'if (try (getpath({parent}) | has({key})) catch false) then (setpath({path}; {value})) else . end'"


def convert_replace_pairs_to_jq(text: str) -> list[str]:
    tokens = [token for token in re.split(r"\s+", text.strip()) if token]
    parts: list[str] = []
    for index in range(0, len(tokens) - 1, 2):
        parts.append(convert_replace_pair_to_jq(tokens[index], tokens[index + 1]))
    return parts


def fetch_jq_path(url: str) -> str:
    if url not in JQ_PATH_CACHE:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": LOON_USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh-Hans;q=0.9",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8")
        JQ_PATH_CACHE[url] = " ".join(line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return JQ_PATH_CACHE[url]


def quote_jq_expression(text: str) -> str:
    return "'" + text.replace("'", "\\'") + "'"


def convert_jq_expression(text: str, report: list[dict[str, str]], file: str, line: str) -> str | None:
    stripped = text.strip()
    if not stripped or stripped in ("''", '""'):
        add_report(
            report,
            file,
            "rewrite-empty-skipped",
            "Empty JQ expression was skipped because Surge requires a non-empty JQ program.",
            line,
        )
        return None

    match = re.fullmatch(r'jq-path=(["\']?)(.+?)\1', stripped)
    if not match:
        quote = stripped[0] if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"') else ""
        expression = stripped[1:-1] if quote else stripped
        original_expression = expression
        for old, new in JQ_COMPATIBILITY_REWRITES:
            expression = expression.replace(old, new)
        if expression != original_expression:
            add_report(
                report,
                file,
                "jq-expression-corrected",
                "Normalized missing JQ token separators and variable-binding grouping so the expression compiles.",
                line,
            )
            return quote_jq_expression(expression)
        return stripped

    url = match.group(2)
    try:
        return quote_jq_expression(fetch_jq_path(url))
    except Exception as exc:  # noqa: BLE001 - keep converting the module and report the fallback.
        add_report(report, file, "jq-path-inline-failed", f"Unable to inline jq-path {url}: {exc}", line)
        return text


def parse_properties(text: str | None) -> OrderedDict[str, str]:
    props: OrderedDict[str, str] = OrderedDict()
    for part in split_top_level(text, ","):
        key, value = split_first(part, "=")
        key = key.strip()
        if key:
            props[key] = value.strip()
    return props


def unquote_property_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def unverified_generic_scripts(
    lines: list[str],
    verified_paths: frozenset[str] = VERIFIED_SURGE_GENERIC_SCRIPT_PATHS,
) -> list[tuple[str, str]]:
    unverified: list[tuple[str, str]] = []
    for line in lines:
        match = re.match(r"^generic(?:\s+(.*))?$", line)
        if not match:
            continue
        path = unquote_property_value(parse_properties(match.group(1)).get("script-path", ""))
        if path and path not in verified_paths:
            unverified.append((line, path))
    return unverified


def generic_script_properties(lines: list[str]) -> list[tuple[str, OrderedDict[str, str]]]:
    scripts: list[tuple[str, OrderedDict[str, str]]] = []
    for line in lines:
        match = re.match(r"^generic(?:\s+(.*))?$", line)
        if match:
            scripts.append((line, parse_properties(match.group(1))))
    return scripts


def merge_query_argument(argument: str, key: str, value: str) -> str:
    text = unquote_property_value(argument)
    parts = [part for part in text.split("&") if part]
    keys = {part.partition("=")[0].strip().lower() for part in parts}
    if key.lower() not in keys:
        parts.insert(0, f"{key}={value}")
    return "&".join(parts)


def validate_script_properties(
    script_type: str,
    text: str | None,
    props: OrderedDict[str, str],
    report: list[dict[str, str]],
    file: str,
    line: str,
) -> bool:
    errors: list[str] = []
    duplicate_same_values: set[str] = set()
    seen: dict[str, str] = {}
    for part in split_top_level(text, ","):
        key, value = split_first(part, "=")
        key = key.strip()
        value = value.strip()
        if "=" not in part or not key:
            errors.append(f"Malformed script property: {part}")
            continue
        if key in seen:
            if seen[key] == value:
                duplicate_same_values.add(key)
            else:
                errors.append(f"Conflicting duplicate script property: {key}")
        seen[key] = value

    allowed = LOON_SCRIPT_COMMON_PROPERTIES | LOON_SCRIPT_TYPE_PROPERTIES[script_type]
    unknown = sorted(set(props) - allowed)
    if unknown:
        errors.append(f"Unsupported {script_type} property/properties: {', '.join(unknown)}")

    if not props.get("script-path"):
        errors.append("Missing non-empty script-path")

    empty = sorted(key for key, value in props.items() if not value and key != "argument")
    if empty:
        errors.append(f"Empty script property/properties: {', '.join(empty)}")

    for key in ("binary-body-mode", "debug", "requires-body", "wake-system"):
        if key in props and props[key].lower() not in {"true", "false"}:
            errors.append(f"{key} must be true or false")

    if "engine" in props and props["engine"].lower() not in {"auto", "jsc", "webview"}:
        errors.append("engine must be auto, jsc, or webview")

    if "enable" in props:
        enable = props["enable"]
        normalized = normalized_argument_default(enable)
        if not enable_argument_name(enable) and normalized not in {"true", "false", "1", "0", "on", "off", "yes", "no"}:
            errors.append("enable must be a boolean value or an {Argument} placeholder")

    if errors:
        add_report(report, file, "unsupported-script", "; ".join(errors), line)
        return False
    if duplicate_same_values:
        add_report(
            report,
            file,
            "script-property-corrected",
            "Removed duplicate script property/properties with identical values: "
            + ", ".join(sorted(duplicate_same_values)),
            line,
        )
    return True


def collect_argument_defaults(lines: list[str]) -> OrderedDict[str, str]:
    defaults: OrderedDict[str, str] = OrderedDict()
    for line in lines:
        name, value = split_first(line, "=")
        if not value:
            continue
        parts = split_top_level(value, ",")
        if len(parts) >= 2:
            defaults[name.strip()] = parts[1].strip()
    return defaults


def normalized_argument_default(value: str) -> str:
    normalized = value.strip()
    if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in ("'", '"'):
        normalized = normalized[1:-1]
    return normalized.strip().lower()


def surge_toggle_default(value: str) -> str:
    normalized = normalized_argument_default(value)
    return "#" if normalized in {"", "false", "0", "off", "no", "#"} else ""


def enable_argument_name(value: str) -> str | None:
    match = re.fullmatch(r"\{([A-Za-z0-9_.-]+)\}", value.strip())
    if match:
        return match.group(1)
    return None


def collect_enable_argument_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for line in lines:
        match = re.match(r"^(?:http-request|http-response)\s+\S+(?:\s+(.*))?$", line)
        if not match:
            match = re.match(r"^cron\s+\S+(?:\s+(.*))?$", line)
        if not match:
            match = re.match(r"^generic(?:\s+(.*))?$", line)
        if not match:
            continue
        props = parse_properties(match.group(1))
        if "enable" in props:
            name = enable_argument_name(props["enable"])
            if name:
                names.add(name)
    return names


def collect_script_argument_names(lines: list[str]) -> set[str]:
    names: set[str] = set()
    for line in lines:
        match = re.match(r"^(?:http-request|http-response)\s+\S+(?:\s+(.*))?$", line)
        if match:
            props = parse_properties(match.group(1))
            if "argument" in props:
                names.update(collect_loon_placeholder_names(props["argument"]))
            continue

        match = re.match(r"^cron\s+(\S+)(?:\s+(.*))?$", line)
        if match:
            cron, props_text = match.groups()
            names.update(collect_loon_placeholder_names(cron))
            props = parse_properties(props_text)
            if "argument" in props:
                names.update(collect_loon_placeholder_names(props["argument"]))
            continue

        match = re.match(r"^generic(?:\s+(.*))?$", line)
        if match:
            props = parse_properties(match.group(1))
            if "argument" in props:
                names.update(collect_loon_placeholder_names(props["argument"]))
    return names


def collect_enable_toggle_defaults(
    lines: list[str],
    argument_defaults: dict[str, str],
    shared_argument_names: set[str],
) -> dict[str, str]:
    defaults: dict[str, str] = {}
    for name in collect_enable_argument_names(lines):
        if name in shared_argument_names:
            continue
        if name in argument_defaults:
            defaults[name] = surge_toggle_default(argument_defaults[name])
    return defaults


def add_report(report: list[dict[str, str]], file: str, kind: str, message: str, line: str) -> None:
    report.append({"file": file, "kind": kind, "message": message, "line": line})


def fatal_report_items(report: list[dict[str, str]]) -> list[dict[str, str]]:
    return [item for item in report if item["kind"] in FATAL_REPORT_KINDS]


def fatal_report_message(items: list[dict[str, str]]) -> str:
    details = "\n".join(
        f"- {item['file']} [{item['kind']}]: {item['message']}\n  {item['line']}" for item in items
    )
    return f"Conversion stopped because {len(items)} item(s) could not be converted safely:\n{details}"


def is_reject_policy(policy: str) -> bool:
    return policy.upper().startswith("REJECT")


def ensure_rule_option(parts: list[str], option: str, start_index: int) -> None:
    if option not in (part.strip() for part in parts[start_index:]):
        parts.append(option)


def remove_rule_option(parts: list[str], option: str, start_index: int) -> None:
    parts[:] = parts[:start_index] + [part for part in parts[start_index:] if part.strip() != option]


def is_wrapped_parentheses(text: str) -> bool:
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return False

    quote = ""
    depth = 0
    previous = ""

    for index, char in enumerate(text):
        if quote:
            if char == quote and previous != "\\":
                quote = ""
            previous = char
            continue

        if char in ("'", '"'):
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
            if depth < 0:
                return False
        previous = char

    return depth == 0


def strip_wrapping_parentheses(text: str) -> str:
    stripped = text.strip()
    if is_wrapped_parentheses(stripped):
        return stripped[1:-1].strip()
    return stripped


def convert_logical_matcher_group(text: str) -> str:
    inner = strip_wrapping_parentheses(text)
    converted: list[str] = []
    for item in split_top_level(inner, ","):
        matcher = strip_wrapping_parentheses(item)
        converted.append(f"({convert_rule_line(matcher, matcher_only=True)})")
    return "(" + ",".join(converted) + ")"


def matcher_supports_pre_matching(text: str) -> bool:
    normalized = re.sub(r"\s*,\s*", ",", text).strip()
    parts = split_top_level(normalized, ",")
    if not parts:
        return False

    rule_type = parts[0].strip().upper()
    if rule_type in LOGICAL_RULE_TYPES and len(parts) >= 2:
        return logical_group_supports_pre_matching(parts[1])
    return rule_type in PRE_MATCHING_RULE_TYPES


def logical_group_supports_pre_matching(text: str) -> bool:
    inner = strip_wrapping_parentheses(text)
    items = split_top_level(inner, ",")
    return bool(items) and all(matcher_supports_pre_matching(strip_wrapping_parentheses(item)) for item in items)


def convert_rule_line(line: str, matcher_only: bool = False) -> str:
    normalized = re.sub(r"\s*,\s*", ",", line).strip()
    parts = split_top_level(normalized, ",")
    if not parts:
        return normalized

    rule_type = parts[0].strip().upper()
    if rule_type in LOGICAL_RULE_TYPES and len(parts) >= 2:
        parts[1] = convert_logical_matcher_group(parts[1])
        if not matcher_only and len(parts) >= 3:
            option_start = 3
            if is_reject_policy(parts[2].strip().upper()) and logical_group_supports_pre_matching(parts[1]):
                ensure_rule_option(parts, "pre-matching", option_start)
            else:
                remove_rule_option(parts, "pre-matching", option_start)
        return ",".join(parts)

    min_parts = 2 if matcher_only else 3
    if len(parts) < min_parts:
        return normalized

    option_start = 2 if matcher_only else 3
    policy = "" if matcher_only else parts[2].strip().upper()
    reject_policy = is_reject_policy(policy)

    if rule_type in DOMAIN_RULE_TYPES:
        ensure_rule_option(parts, "extended-matching", option_start)
        if not matcher_only:
            if reject_policy:
                ensure_rule_option(parts, "pre-matching", option_start)
            else:
                remove_rule_option(parts, "pre-matching", option_start)
    elif rule_type == "URL-REGEX":
        ensure_rule_option(parts, "extended-matching", option_start)
    elif rule_type in IP_RULE_TYPES:
        ensure_rule_option(parts, "no-resolve", option_start)
        if not matcher_only:
            if reject_policy:
                ensure_rule_option(parts, "pre-matching", option_start)
            else:
                remove_rule_option(parts, "pre-matching", option_start)

    return ",".join(parts)


def is_bare_domain_rule(line: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+", line.strip()))


def append_unique_rule(output: list[str], line: str) -> None:
    if line not in output:
        output.append(line)


def ensure_mock_option(mock: str, key: str, value: str) -> str:
    if re.search(rf"\b{re.escape(key)}=", mock):
        return mock
    return f"{mock} {key}={value}".strip()


MOCK_OPTION_KEYS = ("data-type", "data-path", "data", "status-code", "header", "mock-data-is-base64")


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def mock_option_value(mock: str, key: str) -> str | None:
    match = re.search(rf"(?:(?<=^)|(?<=\s)){re.escape(key)}=(\"[^\"]*\"|\S+)", mock)
    if not match:
        return None
    value = match.group(1)
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def set_mock_scalar_option(mock: str, key: str, value: str) -> str:
    replacement = f"{key}={value}"
    if re.search(rf"(?:(?<=^)|(?<=\s)){re.escape(key)}=", mock):
        return re.sub(rf"(?:(?<=^)|(?<=\s)){re.escape(key)}=\S+", replacement, mock, count=1)
    return f"{replacement} {mock}".strip()


def remove_mock_scalar_option(mock: str, key: str) -> str:
    return normalize_spaces(re.sub(rf"(?:(?<=^)|(?<=\s)){re.escape(key)}=\S+", "", mock, count=1))


def find_quoted_mock_option(mock: str, key: str) -> tuple[int, int] | None:
    match = re.search(rf"(?:(?<=^)|(?<=\s)){re.escape(key)}=\"", mock)
    if not match:
        return None

    value_start = match.end()
    next_option = "|".join(re.escape(item) for item in MOCK_OPTION_KEYS)
    tail = mock[value_start:]
    closing_before_next = re.search(rf"\"\s+(?:{next_option})=", tail)
    if closing_before_next:
        return value_start, value_start + closing_before_next.start()

    closing_quote = mock.rfind('"')
    if closing_quote < value_start:
        return None
    return value_start, closing_quote


def quoted_mock_option_value(mock: str, key: str) -> str | None:
    span = find_quoted_mock_option(mock, key)
    if not span:
        return None
    value_start, value_end = span
    return mock[value_start:value_end]


def replace_quoted_mock_option_value(mock: str, key: str, value: str) -> str:
    span = find_quoted_mock_option(mock, key)
    if not span:
        return mock
    value_start, value_end = span
    return mock[:value_start] + value + mock[value_end:]


def looks_like_json_text(value: str) -> bool:
    stripped = value.strip()
    return (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]"))


def normalize_mock_inline_data(mock: str, original_data_type: str | None) -> str:
    data_value = quoted_mock_option_value(mock, "data")
    if data_value is None:
        return mock

    if mock_option_value(mock, "mock-data-is-base64") == "true":
        mock = set_mock_scalar_option(mock, "data-type", "base64")
        return remove_mock_scalar_option(mock, "mock-data-is-base64")

    if '"' not in data_value and "\n" not in data_value and "\r" not in data_value:
        return mock

    encoded = base64.b64encode(data_value.encode("utf-8")).decode("ascii")
    mock = set_mock_scalar_option(mock, "data-type", "base64")
    mock = replace_quoted_mock_option_value(mock, "data", encoded)
    if mock_option_value(mock, "header") is None:
        if original_data_type == "json" or looks_like_json_text(data_value):
            mock = ensure_mock_option(mock, "header", '"Content-Type:application/json"')
        else:
            mock = ensure_mock_option(mock, "header", '"Content-Type:text/plain"')
    return mock


def convert_mock_response_options(text: str) -> str:
    mock = re.sub(r"^mock-response-body\s+", "", text)
    original_data_type = mock_option_value(mock, "data-type")

    if re.search(r"\bdata-path=", mock):
        if re.search(r"\bdata-type=", mock):
            mock = re.sub(r"\bdata-type=\S+", "data-type=file", mock, count=1)
        else:
            mock = f"data-type=file {mock}"
        mock = re.sub(r"\bdata-path=", "data=", mock, count=1)
        content_type = LOON_MOCK_CONTENT_TYPES.get(original_data_type or "")
        if content_type:
            mock = ensure_mock_option(mock, "header", f'"Content-Type:{content_type}"')
    elif original_data_type == "json":
        mock = mock.replace("data-type=json", "data-type=text")
        mock = ensure_mock_option(mock, "header", '"Content-Type:application/json"')
    else:
        mock = normalize_mock_inline_data(mock, original_data_type)

    if not re.search(r"\bdata-path=", mock):
        mock = normalize_mock_inline_data(mock, original_data_type)

    if not re.search(r"(?:(?<=^)|(?<=\s))data=", mock) and original_data_type in {"text", "plain"}:
        mock = ensure_mock_option(mock, "data", '""')
        mock = ensure_mock_option(mock, "status-code", "200")
        mock = ensure_mock_option(mock, "header", '"Content-Type:text/plain"')

    return ensure_mock_option(mock, "status-code", "200")


def quote_property_value(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in ("'", '"'):
        return stripped
    return '"' + stripped.replace('"', '\\"') + '"'


def format_script_pattern(pattern: str) -> str:
    if any(char in pattern for char in (",", " ")):
        return quote_property_value(pattern)
    return pattern


def clean_hostname_list(text: str) -> str:
    return ", ".join(item.strip() for item in split_top_level(text, ",") if item.strip())


def v2_constant_string(value: V2Value, description: str) -> str:
    if not isinstance(value, V2String) or any(isinstance(part, V2Variable) for part in value.parts):
        raise RewriteV2Error(f"{description} must be a constant string")
    return "".join(part for part in value.parts if isinstance(part, str))


def v2_regex_capture_group_count(pattern: str) -> int:
    count = 0
    in_character_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_character_class = True
        elif char == "]" and in_character_class:
            in_character_class = False
        elif char == "(" and not in_character_class:
            if not pattern.startswith("?", index + 1):
                count += 1
            elif pattern.startswith("?<", index + 1) and not pattern.startswith(("?<=", "?<!"), index + 1):
                count += 1
        index += 1
    return count


def reject_v2_url_action_capture_syntax(value: V2Value, description: str) -> None:
    if not isinstance(value, V2String):
        return
    if any(isinstance(part, str) and re.search(r"\$\d+", part) for part in value.parts):
        raise RewriteV2Error(
            f"{description} uses $n syntax; Loon URL Actions require a named condition capture such as ${{item.1}}"
        )


def v2_render_template(
    value: V2Value,
    condition: V2UrlCondition,
    argument_names: set[str],
    description: str,
    *,
    allow_url_captures: bool = False,
) -> str:
    if isinstance(value, V2Variable):
        parts: tuple[str | V2Variable, ...] = (value,)
    elif isinstance(value, V2String):
        parts = value.parts
    else:
        raise RewriteV2Error(f"{description} must be a string")

    rendered: list[str] = []
    for part in parts:
        if isinstance(part, str):
            rendered.append(part)
            continue

        capture = re.fullmatch(r"(.+)\.(\d+)", part.name)
        if capture and capture.group(1) == condition.capture_name:
            if not allow_url_captures:
                raise RewriteV2Error(f"{description} cannot preserve URL capture variable ${{{part.name}}} in Surge")
            capture_index = int(capture.group(2))
            if str(capture_index) != capture.group(2):
                raise RewriteV2Error(f"{description} uses a non-canonical capture index: {capture.group(2)}")
            capture_count = v2_regex_capture_group_count(condition.regex.pattern)
            if capture_index > capture_count:
                raise RewriteV2Error(
                    f"{description} references capture {capture_index}, but the URL condition has {capture_count} group(s)"
                )
            rendered.append(f"${capture_index}")
        elif part.name in argument_names:
            rendered.append(surge_argument_placeholder(part.name))
        else:
            raise RewriteV2Error(f"{description} references unsupported or undefined variable ${{{part.name}}}")
    return "".join(rendered)


def v2_regex_pattern(value: V2Value, description: str) -> str:
    if not isinstance(value, V2Regex):
        raise RewriteV2Error(f"{description} must be a regular expression")
    if value.flags:
        raise RewriteV2Error(
            f"{description} uses Loon regex flags /{value.flags}; no equivalent is emitted without verified Surge semantics"
        )
    return value.pattern


def v2_url_pattern(condition: V2UrlCondition) -> str:
    pattern = v2_regex_pattern(condition.regex, "URL condition")
    if re.search(r"\s", pattern):
        raise RewriteV2Error("URL condition contains literal whitespace that cannot be emitted as a Surge pattern token")
    return pattern


def v2_integer(value: V2Value, description: str, minimum: int | None = None, maximum: int | None = None) -> int:
    if not isinstance(value, V2Number) or not re.fullmatch(r"-?\d+", value.text):
        raise RewriteV2Error(f"{description} must be an integer")
    result = int(value.text)
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise RewriteV2Error(f"{description} must be between {minimum} and {maximum}")
    return result


def expand_v2_arguments(action: V2Action, expected: int) -> list[tuple[V2Value, ...]]:
    if len(action.arguments) != expected:
        raise RewriteV2Error(f"{action.name} expects {expected} arguments, got {len(action.arguments)}")

    arrays = [argument for argument in action.arguments if isinstance(argument, V2Array)]
    if not arrays:
        return [action.arguments]
    if len(arrays) != expected:
        raise RewriteV2Error(f"{action.name} cannot mix array and scalar arguments")

    lengths = {len(array.items) for array in arrays}
    if lengths == {0}:
        raise RewriteV2Error(f"{action.name} array arguments cannot be empty")
    if len(lengths) != 1:
        raise RewriteV2Error(f"{action.name} array arguments must have equal lengths")
    return [tuple(array.items[index] for array in arrays) for index in range(next(iter(lengths)))]


def single_v2_arguments(action: V2Action, expected: int) -> tuple[V2Value, ...]:
    if len(action.arguments) != expected:
        raise RewriteV2Error(f"{action.name} expects {expected} arguments, got {len(action.arguments)}")
    if any(isinstance(argument, V2Array) for argument in action.arguments):
        raise RewriteV2Error(f"{action.name} does not support batch array arguments")
    return action.arguments


def quote_surge_rewrite_token(value: str, description: str, *, always: bool = False) -> str:
    if "\n" in value or "\r" in value:
        raise RewriteV2Error(f"{description} contains a newline that cannot be represented safely in one Surge line")
    if not always and value and not re.search(r"\s", value) and not any(quote in value for quote in ("'", '"')):
        return value
    return "'" + value.replace("'", "\\'") + "'"


def v2_json_value(value: V2Value, description: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, V2Number):
        return value.text
    if isinstance(value, V2String):
        if any(isinstance(part, V2Variable) for part in value.parts):
            raise RewriteV2Error(f"{description} contains a dynamic variable whose JSON type cannot be preserved")
        return json.dumps("".join(part for part in value.parts if isinstance(part, str)), ensure_ascii=False)
    if isinstance(value, V2Variable):
        raise RewriteV2Error(f"{description} uses a typed plugin variable that cannot be safely embedded in Surge JQ")
    raise RewriteV2Error(f"{description} uses an unsupported JSON value")


def v2_map_local_inline(pattern: str, body: str, status: int, content_type: str | None = None) -> str:
    if body:
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
        result = f'{pattern} data-type=base64 data="{encoded}" status-code={status}'
    else:
        result = f'{pattern} data-type=text data="" status-code={status}'
    if content_type:
        result += f' header="Content-Type:{content_type}"'
    return result


def convert_v2_url_action(
    action: V2Action,
    phase: str,
    pattern: str,
    condition: V2UrlCondition,
    argument_names: set[str],
) -> list[tuple[str, str]] | None:
    if action.name == "url.replace":
        if phase != "request":
            raise RewriteV2Error("url.replace is only valid in the request phase")
        arguments = single_v2_arguments(action, 1)
        reject_v2_url_action_capture_syntax(arguments[0], "url.replace replacement")
        replacement = v2_render_template(
            arguments[0], condition, argument_names, "url.replace replacement", allow_url_captures=True
        )
        if re.search(r"\s", replacement):
            raise RewriteV2Error("url.replace replacement contains literal whitespace")
        return [("URL Rewrite", f"{pattern} {replacement} header")]

    if action.name == "redirect":
        if phase != "request":
            raise RewriteV2Error("redirect is only valid in the request phase")
        arguments = single_v2_arguments(action, 2)
        status = v2_integer(arguments[0], "redirect status")
        if status not in (302, 307):
            raise RewriteV2Error("Surge URL Rewrite redirect status must be 302 or 307")
        reject_v2_url_action_capture_syntax(arguments[1], "redirect replacement")
        replacement = v2_render_template(
            arguments[1], condition, argument_names, "redirect replacement", allow_url_captures=True
        )
        if re.search(r"\s", replacement):
            raise RewriteV2Error("redirect replacement contains literal whitespace")
        return [("URL Rewrite", f"{pattern} {replacement} {status}")]

    return None


def convert_v2_reject_action(action: V2Action, phase: str, pattern: str) -> list[tuple[str, str]] | None:
    if not action.name.startswith("reject"):
        return None
    if phase != "request":
        raise RewriteV2Error(f"{action.name} is only valid in the request phase")
    if action.name == "reject_video":
        raise RewriteV2Error("reject_video has no verified native Surge Map Local equivalent")

    if action.name == "reject":
        if len(action.arguments) not in (1, 2):
            raise RewriteV2Error(f"reject expects 1 or 2 arguments, got {len(action.arguments)}")
        status = v2_integer(action.arguments[0], "reject status", 100, 599)
        body = v2_constant_string(action.arguments[1], "reject body") if len(action.arguments) == 2 else ""
        return [("Map Local", v2_map_local_inline(pattern, body, status, "text/plain" if body else None))]

    status = v2_integer(single_v2_arguments(action, 1)[0], f"{action.name} status", 100, 599)
    if action.name == "reject_img":
        return [("Map Local", f"{pattern} data-type=tiny-gif status-code={status}")]
    if action.name == "reject_dict":
        return [("Map Local", v2_map_local_inline(pattern, "{}", status, "application/json"))]
    if action.name == "reject_array":
        return [("Map Local", v2_map_local_inline(pattern, "[]", status, "application/json"))]
    raise RewriteV2Error(f"Unsupported Rewrite V2 reject Action: {action.name}")


def convert_v2_header_action(
    action: V2Action,
    phase: str,
    pattern: str,
    condition: V2UrlCondition,
    argument_names: set[str],
) -> list[tuple[str, str]] | None:
    matched = re.fullmatch(r"(request|response)\.header\.(add|set|del|replace)", action.name)
    if not matched:
        return None
    action_phase, operation = matched.groups()
    if action_phase != phase:
        raise RewriteV2Error(f"{action.name} cannot be used in the {phase} phase")

    direction = f"http-{phase}"
    expected = {"add": 2, "set": 2, "del": 1, "replace": 3}[operation]
    converted: list[tuple[str, str]] = []
    for arguments in expand_v2_arguments(action, expected):
        header_name = v2_render_template(arguments[0], condition, argument_names, f"{action.name} header name")
        if not header_name or re.search(r"[\s:]", header_name):
            raise RewriteV2Error(f"{action.name} header name is invalid for Surge")
        quoted_name = quote_surge_rewrite_token(header_name, "Header name")

        if operation == "del":
            converted.append(("Header Rewrite", f"{direction} {pattern} header-del {quoted_name}"))
            continue

        if operation in ("add", "set"):
            header_value = v2_render_template(arguments[1], condition, argument_names, f"{action.name} value")
            quoted_value = quote_surge_rewrite_token(header_value, "Header value")
            if operation == "set":
                converted.append(("Header Rewrite", f"{direction} {pattern} header-del {quoted_name}"))
            converted.append(("Header Rewrite", f"{direction} {pattern} header-add {quoted_name} {quoted_value}"))
            continue

        header_regex = v2_regex_pattern(arguments[1], f"{action.name} regular expression")
        replacement = v2_render_template(arguments[2], condition, argument_names, f"{action.name} replacement")
        converted.append(
            (
                "Header Rewrite",
                f"{direction} {pattern} header-replace-regex {quoted_name} "
                f"{quote_surge_rewrite_token(header_regex, 'Header regular expression', always=True)} "
                f"{quote_surge_rewrite_token(replacement, 'Header replacement', always=True)}",
            )
        )
    return converted


def convert_v2_body_action(
    action: V2Action,
    phase: str,
    pattern: str,
    condition: V2UrlCondition,
    argument_names: set[str],
) -> list[tuple[str, str]] | None:
    matched = re.fullmatch(r"(request|response)\.body\.replace", action.name)
    if not matched:
        return None
    if matched.group(1) != phase:
        raise RewriteV2Error(f"{action.name} cannot be used in the {phase} phase")

    converted: list[tuple[str, str]] = []
    for arguments in expand_v2_arguments(action, 2):
        body_regex = v2_regex_pattern(arguments[0], f"{action.name} regular expression")
        replacement = v2_render_template(arguments[1], condition, argument_names, f"{action.name} replacement")
        converted.append(
            (
                "Body Rewrite",
                f"http-{phase} {pattern} "
                f"{quote_surge_rewrite_token(body_regex, 'Body regular expression', always=True)} "
                f"{quote_surge_rewrite_token(replacement, 'Body replacement', always=True)}",
            )
        )
    return converted


def convert_v2_json_action(action: V2Action, phase: str, pattern: str) -> list[tuple[str, str]] | None:
    matched = re.fullmatch(r"(request|response)\.json\.(add|delete|replace|jq|jq_file)", action.name)
    if not matched:
        return None
    action_phase, operation = matched.groups()
    if action_phase != phase:
        raise RewriteV2Error(f"{action.name} cannot be used in the {phase} phase")

    direction = f"http-{phase}-jq"
    converted: list[tuple[str, str]] = []
    if operation == "delete":
        for arguments in expand_v2_arguments(action, 1):
            path = v2_constant_string(arguments[0], f"{action.name} path")
            converted.append(("Body Rewrite", f"{direction} {pattern} 'delpaths([{convert_path_to_jq_array(path)}])'"))
        return converted

    if operation in ("add", "replace"):
        for arguments in expand_v2_arguments(action, 2):
            path_text = v2_constant_string(arguments[0], f"{action.name} path")
            segments = path_segments(path_text)
            if not segments:
                raise RewriteV2Error(f"{action.name} path cannot be empty")
            path = jq_array(segments)
            value = v2_json_value(arguments[1], f"{action.name} value")
            if operation == "add":
                expression = f"setpath({path}; {value})"
            else:
                parent = jq_array(segments[:-1])
                key = json.dumps(segments[-1], ensure_ascii=False, separators=(",", ":"))
                expression = (
                    f"if (try (getpath({parent}) | has({key})) catch false) "
                    f"then (setpath({path}; {value})) else . end"
                )
            converted.append(("Body Rewrite", f"{direction} {pattern} {quote_jq_expression(expression)}"))
        return converted

    arguments = single_v2_arguments(action, 1)
    source = v2_constant_string(arguments[0], f"{action.name} expression")
    if operation == "jq_file":
        if not re.match(r"^https?://", source):
            raise RewriteV2Error("Relative jq_file resources are not downloaded with standalone Kelee .lpx files")
        try:
            source = fetch_jq_path(source)
        except Exception as exc:  # noqa: BLE001 - turn remote resource failures into a fatal conversion report.
            raise RewriteV2Error(f"Unable to inline jq_file {source}: {exc}") from exc
    converted.append(("Body Rewrite", f"{direction} {pattern} {quote_jq_expression(source)}"))
    return converted


def convert_v2_mock_action(action: V2Action, phase: str, pattern: str) -> list[tuple[str, str]] | None:
    matched = re.fullmatch(r"(request|response)\.body\.(mock|mock_file)", action.name)
    if not matched:
        return None
    action_phase, operation = matched.groups()
    if action_phase != phase:
        raise RewriteV2Error(f"{action.name} cannot be used in the {phase} phase")
    if phase == "request":
        raise RewriteV2Error(f"{action.name} has no verified native Surge equivalent that also preserves content type")

    minimum = 2
    maximum = 4
    if not minimum <= len(action.arguments) <= maximum:
        raise RewriteV2Error(f"{action.name} expects between {minimum} and {maximum} arguments")
    if any(isinstance(argument, V2Array) for argument in action.arguments):
        raise RewriteV2Error(f"{action.name} does not support batch array arguments")

    content_kind = v2_constant_string(action.arguments[0], f"{action.name} content type")
    if content_kind not in LOON_MOCK_CONTENT_TYPES:
        raise RewriteV2Error(f"{action.name} uses unsupported content type: {content_kind}")
    content_type = LOON_MOCK_CONTENT_TYPES[content_kind]
    status = v2_integer(action.arguments[2], f"{action.name} status", 100, 599) if len(action.arguments) >= 3 else 200
    base64_mode = action.arguments[3] if len(action.arguments) >= 4 else False
    if not isinstance(base64_mode, bool):
        raise RewriteV2Error(f"{action.name} Base64 flag must be Boolean")

    data = v2_constant_string(action.arguments[1], f"{action.name} body")
    if operation == "mock_file":
        if base64_mode:
            raise RewriteV2Error("response.body.mock_file Base64 resources cannot be represented by Surge Map Local")
        if not re.match(r"^https?://", data):
            raise RewriteV2Error("Relative mock_file resources are not downloaded with standalone Kelee .lpx files")
        escaped_data = data.replace('"', '\\"')
        return [
            (
                "Map Local",
                f'{pattern} data-type=file data="{escaped_data}" status-code={status} '
                f'header="Content-Type:{content_type}"',
            )
        ]

    if base64_mode:
        try:
            base64.b64decode(data, validate=True)
        except Exception as exc:  # noqa: BLE001 - report invalid source data as a conversion error.
            raise RewriteV2Error(f"{action.name} body is not valid Base64") from exc
        encoded = data
    else:
        encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
    return [
        (
            "Map Local",
            f'{pattern} data-type=base64 data="{encoded}" status-code={status} header="Content-Type:{content_type}"',
        )
    ]


def convert_rewrite_v2_line(
    line: str,
    sections: OrderedDict[str, list[str]],
    report: list[dict[str, str]],
    file: str,
    argument_names: set[str],
) -> None:
    try:
        rewrite = parse_rewrite_v2_line(line)
        condition = parse_url_only_condition(rewrite.condition)
        if condition.capture_name and condition.capture_name in argument_names:
            raise RewriteV2Error(
                f"URL capture name {condition.capture_name!r} conflicts with a declared plugin argument"
            )
        pattern = v2_url_pattern(condition)
        converted: list[tuple[str, str]] = []

        for action in rewrite.actions:
            action_lines = (
                convert_v2_url_action(action, rewrite.phase, pattern, condition, argument_names)
                or convert_v2_reject_action(action, rewrite.phase, pattern)
                or convert_v2_header_action(action, rewrite.phase, pattern, condition, argument_names)
                or convert_v2_body_action(action, rewrite.phase, pattern, condition, argument_names)
                or convert_v2_json_action(action, rewrite.phase, pattern)
                or convert_v2_mock_action(action, rewrite.phase, pattern)
            )
            if not action_lines:
                raise RewriteV2Error(f"Unsupported Rewrite V2 Action: {action.name}")
            converted.extend(action_lines)

        target_sections = {section for section, _ in converted}
        if len(target_sections) != 1:
            raise RewriteV2Error(
                "Actions cross Surge processing stages; splitting them would not preserve Loon's left-to-right execution order"
            )
        if len(rewrite.actions) > 1 and target_sections & {"URL Rewrite", "Map Local"}:
            raise RewriteV2Error("Multiple terminal URL or mock Actions cannot be represented as one Surge operation")

        for section, converted_line in converted:
            sections[section].append(converted_line)
    except RewriteV2Error as exc:
        add_report(report, file, "unsupported-rewrite", f"Rewrite V2: {exc}", line)


def convert_rewrite_line(
    line: str,
    sections: OrderedDict[str, list[str]],
    report: list[dict[str, str]],
    file: str,
    argument_names: set[str] | None = None,
) -> None:
    if is_rewrite_v2_line(line):
        convert_rewrite_v2_line(line, sections, report, file, argument_names or set())
        return

    inline_match = re.match(r"^(http-request|http-response)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line)
    if inline_match:
        kind, pattern, action, rest = inline_match.groups()
        rest = rest or ""

        if action == "response-body-json-jq":
            expression = convert_jq_expression(rest, report, file, line)
            if expression is not None:
                sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
        elif action == "response-body-json-del":
            for expression in convert_delete_source_to_jq(rest, report, file, line):
                sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
        elif action == "response-body-json-replace":
            for expression in convert_replace_pairs_to_jq(rest):
                sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
        elif action in ("response-body-replace-regex", "request-body-replace-regex"):
            first, second = split_first(rest, " ")
            sections["Body Rewrite"].append(f"{kind} {pattern} {first} {second}")
        else:
            add_report(report, file, "unsupported-rewrite", f"Unsupported inline rewrite action: {action}", line)
        return

    match = re.match(r"^(\S+)\s+(\S+)(?:\s+(.*))?$", line)
    if not match:
        add_report(report, file, "unsupported-rewrite", "Unable to parse rewrite line", line)
        return

    pattern, action, rest = match.groups()
    rest = rest or ""

    if action == "reject":
        sections["URL Rewrite"].append(f"{pattern} _ reject")
    elif action == "reject-dict":
        sections["Map Local"].append(f'{pattern} data-type=text data="{{}}" status-code=200 header="Content-Type:application/json"')
    elif action == "reject-img":
        sections["Map Local"].append(f"{pattern} data-type=tiny-gif status-code=200")
    elif action == "reject-200":
        sections["Map Local"].append(f'{pattern} data-type=text data="" status-code=200')
    elif action == "mock-response-body":
        sections["Map Local"].append(f"{pattern} {convert_mock_response_options(rest)}")
    elif action == "response-body-json-jq":
        expression = convert_jq_expression(rest, report, file, line)
        if expression is not None:
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
    elif action == "response-body-json-del":
        for expression in convert_delete_source_to_jq(rest, report, file, line):
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
    elif action == "response-body-json-replace":
        for expression in convert_replace_pairs_to_jq(rest):
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {expression}")
    elif action == "response-body-replace-regex":
        first, second = split_first(rest, " ")
        sections["Body Rewrite"].append(f"http-response {pattern} {first} {second}")
    elif action == "request-body-replace-regex":
        first, second = split_first(rest, " ")
        sections["Body Rewrite"].append(f"http-request {pattern} {first} {second}")
    elif action == "response-header-add":
        sections["Header Rewrite"].append(f"http-response {pattern} header-add {rest}")
    elif action == "header-replace-regex":
        tokens = [token for token in re.split(r"\s+", rest.strip()) if token]
        if len(tokens) >= 3:
            header_name = tokens[0]
            regex = tokens[1]
            value = " ".join(tokens[2:])
            sections["Header Rewrite"].append(f"http-request {pattern} header-replace-regex '{header_name}' '{regex}' '{value}'")
        else:
            add_report(report, file, "unsupported-header-rewrite", "Unable to parse header-replace-regex", line)
    elif action == "header":
        sections["URL Rewrite"].append(f"{pattern} {rest} header")
    elif re.fullmatch(r"\d{3}", action):
        sections["URL Rewrite"].append(f"{pattern} {rest} {action}")
    else:
        add_report(report, file, "unsupported-rewrite", f"Unsupported rewrite action: {action}", line)


def script_enable_prefix(
    props: OrderedDict[str, str],
    argument_defaults: dict[str, str],
    shared_argument_names: set[str],
    report: list[dict[str, str]],
    file: str,
    line: str,
) -> str:
    if "enable" not in props:
        return ""

    name = enable_argument_name(props["enable"])
    if name:
        if name in shared_argument_names:
            prefix = surge_toggle_default(argument_defaults.get(name, ""))
            add_report(
                report,
                file,
                "script-enable-shared-commented" if prefix == "#" else "script-enable-shared-kept",
                "Loon enable argument is also used as a script argument; script line was fixed to the default state to preserve the argument value.",
                line,
            )
            return prefix

        add_report(
            report,
            file,
            "script-enable-toggle-emitted",
            "Loon enable option was emitted as a Surge module line-prefix toggle.",
            line,
        )
        return surge_argument_placeholder(name)

    prefix = surge_toggle_default(props["enable"])
    if prefix == "#":
        add_report(
            report,
            file,
            "script-enable-direct-commented",
            "Loon enable option defaults to false; script line was emitted as a commented Surge line.",
            line,
        )
        return prefix

    add_report(
        report,
        file,
        "script-enable-direct-kept",
        "Loon enable option defaults to true; script was kept and the static enable option was not emitted.",
        line,
    )
    return ""


def convert_script_line(
    line: str,
    output: list[str],
    report: list[dict[str, str]],
    file: str,
    argument_defaults: dict[str, str] | None = None,
    shared_argument_names: set[str] | None = None,
) -> None:
    argument_defaults = argument_defaults or {}
    shared_argument_names = shared_argument_names or set()
    match = re.match(r"^(http-request|http-response)\s+(\S+)(?:\s+(.*))?$", line)
    if match:
        script_type, pattern, props_text = match.groups()
        props = parse_properties(props_text)
        if not validate_script_properties(script_type, props_text, props, report, file, line):
            return
        prefix = script_enable_prefix(props, argument_defaults, shared_argument_names, report, file, line)
        name = props.get("tag") or f"{script_type} {len(output) + 1}"
        parts = [f"type={script_type}", f"pattern={format_script_pattern(pattern)}"]

        for key in (
            "script-path",
            "requires-body",
            "binary-body-mode",
            "timeout",
            "engine",
            "max-size",
            "ability",
            "script-update-interval",
            "debug",
        ):
            if key in props:
                if key in ("requires-body", "binary-body-mode") and props[key] == "false":
                    continue
                parts.append(f"{key}={props[key]}")
        if props.get("argument"):
            parts.append(f"argument={convert_argument_value(props['argument'])}")

        output.append(f"{prefix}{name} = " + ", ".join(parts))
        return

    match = re.match(r"^cron\s+(\S+)(?:\s+(.*))?$", line)
    if match:
        cron, props_text = match.groups()
        cron = convert_placeholder(cron)
        props = parse_properties(props_text)
        if not validate_script_properties("cron", props_text, props, report, file, line):
            return
        prefix = script_enable_prefix(props, argument_defaults, shared_argument_names, report, file, line)
        name = props.get("tag") or f"cron {len(output) + 1}"
        parts = ["type=cron", f'cronexp="{cron}"']

        for key in ("script-path", "timeout", "engine", "wake-system", "script-update-interval", "debug"):
            if key in props:
                parts.append(f"{key}={props[key]}")
        if props.get("argument"):
            parts.append(f"argument={convert_argument_value(props['argument'])}")

        output.append(f"{prefix}{name} = " + ", ".join(parts))
        return

    match = re.match(r"^generic(?:\s+(.*))?$", line)
    if match:
        props_text = match.group(1)
        props = parse_properties(props_text)
        if not validate_script_properties("generic", props_text, props, report, file, line):
            return
        prefix = script_enable_prefix(props, argument_defaults, shared_argument_names, report, file, line)
        name = props.get("tag") or f"generic {len(output) + 1}"
        parts = ["type=generic"]
        for key in ("script-path", "timeout", "engine", "script-update-interval", "debug"):
            if key in props:
                parts.append(f"{key}={props[key]}")
        argument = props.get("argument", "")
        if unquote_property_value(props["script-path"]) == NODE_LINK_CHECK_SCRIPT_PATH:
            argument = merge_query_argument(argument, "policy", "{Policy}")
        if argument:
            parts.append(f"argument={convert_argument_value(argument)}")
        output.append(f"{prefix}{name} = " + ", ".join(parts))
        return

    add_report(report, file, "unsupported-script", "Unsupported script line", line)


def convert_argument_lines(
    lines: list[str],
    report: list[dict[str, str]],
    file: str,
    toggle_defaults: dict[str, str] | None = None,
    used_names: set[str] | None = None,
) -> list[tuple[str, str]]:
    toggle_defaults = toggle_defaults or {}
    used_names = used_names or set()
    items: list[tuple[str, str]] = []
    source_names: dict[str, str] = {}
    for line in lines:
        name, value = split_first(line, "=")
        if not value:
            add_report(report, file, "argument-parse", "Unable to parse argument line", line)
            continue
        name = name.strip()
        if not name:
            add_report(report, file, "argument-parse", "Argument name is empty", line)
            continue
        converted_name = surge_argument_name(name)
        if converted_name in source_names:
            previous_name = source_names[converted_name]
            message = (
                f"Argument {name!r} is declared more than once."
                if previous_name == name
                else f"Argument names {previous_name!r} and {name!r} both normalize to {converted_name!r}."
            )
            add_report(
                report,
                file,
                "argument-name-collision",
                message,
                line,
            )
            continue
        source_names[converted_name] = name
        parts = split_top_level(value, ",")
        if len(parts) < 2:
            add_report(report, file, "argument-default", "Unable to find argument default value", line)
            continue
        if name not in used_names:
            add_report(
                report,
                file,
                "argument-unused-dropped",
                "Declared Loon argument is not referenced by any converted module line and was removed.",
                line,
            )
            continue
        default_value = toggle_defaults[name] if name in toggle_defaults else parts[1].strip()
        items.append((converted_name, unquote_property_value(default_value)))
    return items


def safe_module_filename(name: str, seen: dict[str, int]) -> str:
    safe = "".join("_" if char in WINDOWS_INVALID_FILENAME_CHARS or ord(char) < 32 else char for char in name)
    if not safe.strip():
        safe = "module"
    safe = f"{safe}.sgmodule"

    if safe not in seen:
        seen[safe] = 1
        return safe

    stem = Path(safe).stem
    while True:
        seen[safe] += 1
        candidate = f"{stem}-{seen[safe]}.sgmodule"
        if candidate not in seen:
            seen[candidate] = 1
            return candidate


def parse_lpx(path: Path) -> tuple[OrderedDict[str, str], dict[str, list[str]]]:
    metadata: OrderedDict[str, str] = OrderedDict()
    source_sections: dict[str, list[str]] = {}
    current_section: str | None = None

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("#!"):
            key, value = split_first(line[2:], "=")
            key = key.strip()
            value = value.strip()
            if value:
                metadata[key] = value
            continue

        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1]
            source_sections.setdefault(current_section, [])
            continue

        if line.startswith("#") or line.startswith(";"):
            continue
        if current_section is not None:
            source_sections[current_section].append(line)

    return metadata, source_sections


def section_lines(source_sections: dict[str, list[str]], name: str) -> list[str]:
    if name in source_sections:
        return source_sections[name]
    lowered = name.lower()
    for section_name, lines in source_sections.items():
        if section_name.lower() == lowered:
            return lines
    return []


def has_section(source_sections: dict[str, list[str]], name: str) -> bool:
    return bool(section_lines(source_sections, name))


def unsupported_module_rule_policies(source_sections: dict[str, list[str]]) -> list[tuple[str, str]]:
    unsupported: list[tuple[str, str]] = []
    for raw_line in section_lines(source_sections, "Rule"):
        line = strip_rule_inline_comment(raw_line)
        if not line or is_bare_domain_rule(line):
            continue
        if re.match(r"^\S+\s+\d{3}\s+.+$", line):
            continue

        parts = split_top_level(line, ",")
        if len(parts) < 3:
            continue
        rule_type = parts[0].strip().upper()
        policy = parts[2].strip().upper()
        if rule_type == "URL-REGEX" and policy in {"REJECT-DICT", "REJECT-IMG"}:
            continue
        if policy not in MODULE_RULE_POLICIES:
            unsupported.append((line, policy))
    return unsupported


def convert_system_metadata(
    value: str | None,
    report: list[dict[str, str]],
    file: str,
) -> str | None:
    if not value:
        return None

    targets: set[str] = set()
    unsupported: list[str] = []
    aliases = {
        "ios": "ios",
        "ipados": "ios",
        "mac": "mac",
        "macos": "mac",
        "watchos": None,
    }
    for raw_platform in value.split(","):
        platform = raw_platform.strip()
        if not platform:
            continue
        mapped = aliases.get(platform.lower(), "unsupported")
        if mapped == "unsupported":
            unsupported.append(platform)
        elif mapped:
            targets.add(mapped)

    if unsupported:
        add_report(
            report,
            file,
            "unsupported-system",
            "Unknown Loon system value(s) cannot be mapped to Surge: " + ", ".join(unsupported),
            f"#!system={value}",
        )
    if not targets and not unsupported:
        add_report(
            report,
            file,
            "unsupported-system",
            "The Loon system restriction has no supported Surge target (ios or mac).",
            f"#!system={value}",
        )
    if not targets:
        return None
    if targets == {"ios", "mac"}:
        return None
    return next(iter(targets))


def convert_file(
    path: Path,
    output_root: Path,
    report: list[dict[str, str]],
    seen_files: dict[str, int],
) -> dict[str, Any] | None:
    metadata, source_sections = parse_lpx(path)
    unsupported_rules = unsupported_module_rule_policies(source_sections)
    if unsupported_rules:
        policies = ", ".join(dict.fromkeys(policy for _, policy in unsupported_rules))
        add_report(
            report,
            path.name,
            "module-excluded",
            "Module was excluded from Surge output because module rules may only use DIRECT, REJECT, or "
            f"REJECT-TINYGIF; found: {policies}.",
            unsupported_rules[0][0],
        )
        return None

    sections: OrderedDict[str, list[str]] = OrderedDict((name, []) for name in SECTION_ORDER)
    argument_lines = section_lines(source_sections, "Argument")
    argument_defaults = collect_argument_defaults(argument_lines)
    script_lines = section_lines(source_sections, "Script")
    generic_scripts = generic_script_properties(script_lines)
    generic_paths = {
        unquote_property_value(props.get("script-path", ""))
        for _, props in generic_scripts
        if props.get("script-path")
    }
    unverified_generic = unverified_generic_scripts(script_lines)
    if unverified_generic:
        paths = ", ".join(dict.fromkeys(item[1] for item in unverified_generic))
        add_report(
            report,
            path.name,
            "module-excluded",
            "Module was excluded from Surge output because generic script compatibility is not verified: "
            + paths
            + ". Loon generic scripts may depend on selected-node context that Surge does not provide.",
            unverified_generic[0][0],
        )
        return None

    if NODE_LINK_CHECK_SCRIPT_PATH in generic_paths:
        metadata["desc"] = (
            "Checks the proxy chain for a Surge policy using Sub-Store node data. "
            "Configure Policy when installing; default: PROXY."
        )
        metadata.pop("openUrl", None)
        node_link_line = next(
            line
            for line, props in generic_scripts
            if unquote_property_value(props.get("script-path", "")) == NODE_LINK_CHECK_SCRIPT_PATH
        )
        add_report(
            report,
            path.name,
            "generic-script-adapted",
            "Added a Surge Policy module argument and passed it to NodeLinkCheck as $argument.policy; default is PROXY.",
            node_link_line,
        )

    if WARP_PANEL_SCRIPT_PATH in generic_paths:
        metadata["desc"] = "Displays WARP details for the current Surge route in an information panel."
        warp_line, warp_props = next(
            (line, props)
            for line, props in generic_scripts
            if unquote_property_value(props.get("script-path", "")) == WARP_PANEL_SCRIPT_PATH
        )
        script_name = warp_props.get("tag") or "WARP INFO"
        sections["Panel"].append(
            f'{script_name} = title={json.dumps(script_name, ensure_ascii=False)}, '
            'content="Refresh to query the current Surge route.", style=info, '
            f"script-name={script_name}"
        )
        add_report(
            report,
            path.name,
            "generic-script-adapted",
            "Added a Surge information Panel linked to the verified WARP generic script.",
            warp_line,
        )
    shared_enable_argument_names = collect_enable_argument_names(script_lines) & collect_script_argument_names(script_lines)

    for line in section_lines(source_sections, "General"):
        match = re.match(r"^real-ip\s*=\s*(.+)$", line, flags=re.IGNORECASE)
        if match:
            sections["General"].append(f"always-real-ip = %APPEND% {match.group(1).strip()}")
        else:
            sections["General"].append(line)
            add_report(report, path.name, "general-pass-through", "General line passed through without conversion.", line)

    for raw_rule_line in section_lines(source_sections, "Rule"):
        line = strip_rule_inline_comment(raw_rule_line)
        if not line:
            continue

        rewrite_match = re.match(r"^(\S+)\s+(\d{3})\s+(.+)$", line)
        if rewrite_match:
            pattern, status_code, replacement = rewrite_match.groups()
            sections["URL Rewrite"].append(f"{pattern} {replacement.strip()} {status_code}")
            continue

        if is_bare_domain_rule(line):
            append_unique_rule(sections["Rule"], convert_rule_line(f"DOMAIN,{line},REJECT"))
            continue

        rule_parts = split_top_level(line, ",")
        if len(rule_parts) >= 3 and rule_parts[0].strip().upper() == "URL-REGEX":
            pattern = rule_parts[1].strip()
            if len(pattern) >= 2 and pattern[0] == pattern[-1] and pattern[0] in ("'", '"'):
                pattern = pattern[1:-1]
            policy = rule_parts[2].strip().upper()
            if policy == "REJECT-DICT":
                sections["Map Local"].append(f'{pattern} data-type=text data="{{}}" status-code=200 header="Content-Type:application/json"')
                continue
            if policy == "REJECT-IMG":
                sections["Map Local"].append(f"{pattern} data-type=tiny-gif status-code=200")
                continue

        sections["Rule"].append(convert_rule_line(line))

    for line in section_lines(source_sections, "Rewrite"):
        convert_rewrite_line(line, sections, report, path.name, set(argument_defaults))

    for line in script_lines:
        convert_script_line(line, sections["Script"], report, path.name, argument_defaults, shared_enable_argument_names)

    for line in section_lines(source_sections, "MitM"):
        match = re.match(r"^hostname\s*=\s*(.+)$", line, flags=re.IGNORECASE)
        if match:
            hostnames = clean_hostname_list(match.group(1))
            if hostnames:
                sections["MITM"].append(f"hostname = %APPEND% {hostnames}")
        else:
            add_report(report, path.name, "mitm-unsupported", "Unsupported MitM line", line)

    output: list[str] = []
    surge_system = convert_system_metadata(metadata.get("system"), report, path.name)
    for key in ("name", "desc", "author", "icon"):
        if key in metadata:
            output.append(f"#!{key}={metadata[key]}")
    output.append("#!category=iKeLee")
    for key in ("openUrl", "open", "tag", "system_version", "loon_version", "homepage", "date"):
        if key in metadata:
            output.append(f"#!{key}={metadata[key]}")
    if surge_system:
        output.append(f"#!system={surge_system}")
    if sections["Body Rewrite"] or sections["Map Local"]:
        output.append("#!requirement=CORE_VERSION>=20")

    toggle_defaults = collect_enable_toggle_defaults(script_lines, argument_defaults, shared_enable_argument_names)
    used_argument_names: set[str] = set()
    for section_name, lines in source_sections.items():
        if section_name.lower() != "argument":
            used_argument_names.update(collect_loon_placeholder_names("\n".join(lines)))
    argument_items = convert_argument_lines(
        argument_lines,
        report,
        path.name,
        toggle_defaults,
        used_argument_names,
    )
    if NODE_LINK_CHECK_SCRIPT_PATH in generic_paths and "Policy" not in argument_defaults:
        argument_items.append(("Policy", "PROXY"))
    if argument_items:
        output.append("#!arguments=" + urllib.parse.urlencode(argument_items))

    for section_name in SECTION_ORDER:
        lines = sections[section_name]
        if lines:
            output.append("")
            output.append(f"[{section_name}]")
            output.extend(lines)
    output.append("")

    module_name = metadata.get("name") or path.stem
    target_name = safe_module_filename(module_name, seen_files)
    (output_root / target_name).write_text("\n".join(output), encoding="utf-8", newline="\n")

    return {
        "source": path.name,
        "output": target_name,
        "name": module_name,
        "sections": [name for name, lines in sections.items() if lines],
    }


def replace_tree(source: Path, target: Path, root: Path) -> None:
    assert_under_root(target, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        shutil.rmtree(target)
    shutil.move(str(source), str(target))


def replace_file(source: Path, target: Path, root: Path) -> None:
    assert_under_root(target, root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    shutil.move(str(source), str(target))


def convert_kelee_to_surge(input_dir: str, output_dir: str, report_path: str) -> None:
    root = Path.cwd().resolve()
    input_root = root / input_dir
    output_root = root / output_dir
    report_full_path = root / report_path
    report_dir = report_full_path.parent
    manifest_full_path = report_dir / "modules.index.json"

    temp_root = Path(tempfile.mkdtemp(prefix="loon_to_surge_convert_"))
    temp_output_root = temp_root / "modules"
    temp_report_dir = temp_root / "report"
    temp_report_full_path = temp_report_dir / "convert-report.json"
    temp_manifest_path = temp_report_dir / "modules.index.json"
    temp_output_root.mkdir(parents=True, exist_ok=True)
    temp_report_dir.mkdir(parents=True, exist_ok=True)

    try:
        report: list[dict[str, str]] = []
        manifest: list[dict[str, Any]] = []
        seen_files: dict[str, int] = {}
        files = sorted(input_root.glob("*.lpx"), key=lambda item: item.name)

        for file_path in files:
            converted = convert_file(file_path, temp_output_root, report, seen_files)
            if converted is not None:
                manifest.append(converted)

        fatal_items = fatal_report_items(report)
        if fatal_items:
            raise RuntimeError(fatal_report_message(fatal_items))

        temp_manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=4), encoding="utf-8", newline="\n")
        summary = {
            "generated_at": "",
            "input_dir": input_dir,
            "output_dir": output_dir,
            "total": len(files),
            "converted": len(manifest),
            "excluded": len(files) - len(manifest),
            "warnings": len(report),
            "items": report,
        }
        modules_unchanged = tree_contents_match(temp_output_root, output_root, {"modules.index.json", "convert-report.json"})
        manifest_unchanged = file_contents_match(temp_manifest_path, manifest_full_path)
        report_unchanged = json_payload_matches(report_full_path, summary, "generated_at")
        if modules_unchanged and manifest_unchanged and report_unchanged:
            summary["generated_at"] = previous_timestamp(report_full_path, "generated_at") or timestamp()
        else:
            summary["generated_at"] = timestamp()
        temp_report_full_path.write_text(json.dumps(summary, ensure_ascii=False, indent=4), encoding="utf-8", newline="\n")

        replace_tree(temp_output_root, output_root, root)
        replace_file(temp_manifest_path, manifest_full_path, root)
        replace_file(temp_report_full_path, report_full_path, root)

        print(f"Converted {len(manifest)} of {len(files)} modules.")
        print(f"Excluded: {len(files) - len(manifest)}")
        print(f"Output: {output_root}")
        print(f"Manifest: {manifest_full_path}")
        print(f"Report: {report_full_path}")
        print(f"Warnings: {len(report)}")
    finally:
        if temp_root.exists():
            shutil.rmtree(temp_root)


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Kelee Loon modules to Surge modules.")
    parser.add_argument("--input-dir", default="Loon")
    parser.add_argument("--output-dir", default="Surge")
    parser.add_argument("--report-path", default="Surge/convert-report.json")
    args = parser.parse_args()
    convert_kelee_to_surge(args.input_dir, args.output_dir, args.report_path)


if __name__ == "__main__":
    main()
