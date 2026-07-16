from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import tempfile
import urllib.request
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from stable_output import file_contents_match, json_payload_matches, previous_timestamp, tree_contents_match
except ModuleNotFoundError:
    from scripts.stable_output import file_contents_match, json_payload_matches, previous_timestamp, tree_contents_match


WINDOWS_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')
SECTION_ORDER = ("General", "Rule", "URL Rewrite", "Header Rewrite", "Body Rewrite", "Map Local", "Script", "MITM")
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


def convert_placeholder(text: str) -> str:
    return re.sub(r"\{([A-Za-z0-9_.-]+)\}", r"{{{\1}}}", text)


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


def convert_jq_expression(text: str, report: list[dict[str, str]], file: str, line: str) -> str:
    match = re.fullmatch(r'jq-path=(["\']?)(.+?)\1', text.strip())
    if not match:
        return text

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
        if value:
            props[key.strip()] = value.strip()
    return props


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
        mock = ensure_mock_option(mock, "header", '"Content-Type:text/plain"')
    elif original_data_type == "json":
        mock = mock.replace("data-type=json", "data-type=text")
        mock = ensure_mock_option(mock, "header", '"Content-Type:application/json"')
    else:
        mock = normalize_mock_inline_data(mock, original_data_type)

    if not re.search(r"\bdata-path=", mock):
        mock = normalize_mock_inline_data(mock, original_data_type)

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


def convert_rewrite_line(line: str, sections: OrderedDict[str, list[str]], report: list[dict[str, str]], file: str) -> None:
    inline_match = re.match(r"^(http-request|http-response)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line)
    if inline_match:
        kind, pattern, action, rest = inline_match.groups()
        rest = rest or ""

        if action == "response-body-json-jq":
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_jq_expression(rest, report, file, line)}")
        elif action == "response-body-json-del":
            paths = [item for item in re.split(r"\s+", rest.strip()) if item]
            for expression in convert_delete_paths_to_jq(paths):
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
        sections["URL Rewrite"].append(f"{pattern} - reject")
    elif action == "reject-dict":
        sections["Map Local"].append(f'{pattern} data-type=text data="{{}}" status-code=200 header="Content-Type:application/json"')
    elif action == "reject-img":
        sections["Map Local"].append(f"{pattern} data-type=tiny-gif status-code=200")
    elif action == "reject-200":
        sections["Map Local"].append(f'{pattern} data-type=text data=" " status-code=200')
    elif action == "mock-response-body":
        sections["Map Local"].append(f"{pattern} {convert_mock_response_options(rest)}")
    elif action == "response-body-json-jq":
        sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_jq_expression(rest, report, file, line)}")
    elif action == "response-body-json-del":
        paths = [item for item in re.split(r"\s+", rest.strip()) if item]
        for expression in convert_delete_paths_to_jq(paths):
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
        return f"{{{{{{{name}}}}}}}"

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
        prefix = script_enable_prefix(props, argument_defaults, shared_argument_names, report, file, line)
        name = props.get("tag") or f"{script_type} {len(output) + 1}"
        parts = [f"type={script_type}", f"pattern={format_script_pattern(pattern)}"]

        for key in ("script-path", "requires-body", "binary-body-mode", "timeout", "engine", "max-size", "ability"):
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
        prefix = script_enable_prefix(props, argument_defaults, shared_argument_names, report, file, line)
        name = props.get("tag") or f"cron {len(output) + 1}"
        parts = ["type=cron", f"cronexp={cron}"]

        for key in ("script-path", "timeout", "engine", "wake-system"):
            if key in props:
                parts.append(f"{key}={props[key]}")
        if props.get("argument"):
            parts.append(f"argument={convert_argument_value(props['argument'])}")

        output.append(f"{prefix}{name} = " + ", ".join(parts))
        return

    match = re.match(r"^generic(?:\s+(.*))?$", line)
    if match:
        props = parse_properties(match.group(1))
        name = props.get("tag") or f"generic {len(output) + 1}"
        parts = ["type=generic"]
        for key in ("script-path", "timeout", "engine", "img-url"):
            if key in props:
                parts.append(f"{key}={props[key]}")
        output.append(f"{name} = " + ", ".join(parts))
        return

    add_report(report, file, "unsupported-script", "Unsupported script line", line)


def convert_argument_lines(
    lines: list[str],
    report: list[dict[str, str]],
    file: str,
    toggle_defaults: dict[str, str] | None = None,
) -> list[str]:
    toggle_defaults = toggle_defaults or {}
    items: list[str] = []
    for line in lines:
        name, value = split_first(line, "=")
        if not value:
            add_report(report, file, "argument-parse", "Unable to parse argument line", line)
            continue
        name = name.strip()
        parts = split_top_level(value, ",")
        if len(parts) < 2:
            add_report(report, file, "argument-default", "Unable to find argument default value", line)
            continue
        default_value = toggle_defaults[name] if name in toggle_defaults else parts[1].strip()
        items.append(f"{name}:{default_value}")
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


def convert_file(path: Path, output_root: Path, report: list[dict[str, str]], seen_files: dict[str, int]) -> dict[str, Any]:
    metadata, source_sections = parse_lpx(path)
    sections: OrderedDict[str, list[str]] = OrderedDict((name, []) for name in SECTION_ORDER)
    argument_lines = section_lines(source_sections, "Argument")
    argument_defaults = collect_argument_defaults(argument_lines)
    script_lines = section_lines(source_sections, "Script")
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

        if len(rule_parts) >= 3 and rule_parts[2].strip().upper() == "PROXY":
            add_report(
                report,
                path.name,
                "external-policy",
                "Rule uses PROXY, which requires the target Surge profile to define a PROXY policy or policy group.",
                line,
            )

        sections["Rule"].append(convert_rule_line(line))

    for line in section_lines(source_sections, "Rewrite"):
        convert_rewrite_line(line, sections, report, path.name)

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
    for key in ("name", "desc", "author", "icon"):
        if key in metadata:
            output.append(f"#!{key}={metadata[key]}")
    output.append("#!category=iKeLee")
    for key in ("openUrl", "open", "tag", "system", "system_version", "loon_version", "homepage", "date"):
        if key in metadata:
            output.append(f"#!{key}={metadata[key]}")

    if argument_lines:
        toggle_defaults = collect_enable_toggle_defaults(script_lines, argument_defaults, shared_enable_argument_names)
        argument_items = convert_argument_lines(argument_lines, report, path.name, toggle_defaults)
        if argument_items:
            output.append("#!arguments=" + ",".join(argument_items))

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
            manifest.append(convert_file(file_path, temp_output_root, report, seen_files))

        temp_manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=4), encoding="utf-8", newline="\n")
        summary = {
            "generated_at": "",
            "input_dir": input_dir,
            "output_dir": output_dir,
            "total": len(files),
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

        print(f"Converted {len(files)} modules.")
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
