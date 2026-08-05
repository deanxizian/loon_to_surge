from __future__ import annotations

from dataclasses import dataclass
import re
from typing import TypeAlias


class RewriteV2Error(ValueError):
    pass


@dataclass(frozen=True)
class V2Variable:
    name: str


@dataclass(frozen=True)
class V2String:
    parts: tuple[str | V2Variable, ...]


@dataclass(frozen=True)
class V2Regex:
    pattern: str
    flags: str


@dataclass(frozen=True)
class V2Number:
    text: str


@dataclass(frozen=True)
class V2Array:
    items: tuple[V2Value, ...]


V2Value: TypeAlias = V2String | V2Regex | V2Variable | V2Number | V2Array | bool | None


@dataclass(frozen=True)
class V2Action:
    name: str
    arguments: tuple[V2Value, ...]


@dataclass(frozen=True)
class V2Rewrite:
    phase: str
    condition: str
    actions: tuple[V2Action, ...]


@dataclass(frozen=True)
class V2UrlCondition:
    regex: V2Regex
    capture_name: str | None


def is_rewrite_v2_line(line: str) -> bool:
    return re.match(r"^(?:request|response)\s+if\s+", line.strip()) is not None


def _is_escaped(text: str, index: int) -> bool:
    count = 0
    index -= 1
    while index >= 0 and text[index] == "\\":
        count += 1
        index -= 1
    return count % 2 == 1


def _looks_like_regex_start(text: str, index: int) -> bool:
    prefix = text[:index].rstrip()
    if not prefix:
        return True
    return prefix.endswith("~=") or prefix[-1] in "(,[=:"


def _split_top_level(text: str, delimiter: str, *, word: bool = False) -> list[str]:
    parts: list[str] = []
    start = 0
    quote = ""
    round_depth = 0
    square_depth = 0
    curly_depth = 0
    index = 0

    while index < len(text):
        char = text[index]

        if quote == "regex":
            if char == "\\":
                index += 2
                continue
            if char == "/":
                quote = ""
            index += 1
            continue

        if quote == "`":
            if char == "`" and index + 1 < len(text) and text[index + 1] == "`":
                index += 2
                continue
            if char == "`":
                quote = ""
            index += 1
            continue

        if quote:
            if char == quote and not _is_escaped(text, index):
                quote = ""
            index += 1
            continue

        at_top_level = round_depth == 0 and square_depth == 0 and curly_depth == 0
        if at_top_level and text.startswith(delimiter, index):
            before_ok = not word or index == 0 or text[index - 1].isspace()
            after_index = index + len(delimiter)
            after_ok = not word or after_index == len(text) or text[after_index].isspace()
            if before_ok and after_ok:
                parts.append(text[start:index].strip())
                start = after_index
                index = after_index
                continue

        if char in ('"', "'"):
            quote = char
        elif char == "`":
            quote = char
        elif char == "/" and _looks_like_regex_start(text, index):
            quote = "regex"
        elif char == "(":
            round_depth += 1
        elif char == ")":
            round_depth -= 1
            if round_depth < 0:
                raise RewriteV2Error("Unexpected closing parenthesis")
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth -= 1
            if square_depth < 0:
                raise RewriteV2Error("Unexpected closing bracket")
        elif char == "{":
            curly_depth += 1
        elif char == "}":
            curly_depth -= 1
            if curly_depth < 0:
                raise RewriteV2Error("Unexpected closing brace")

        index += 1

    if quote:
        raise RewriteV2Error("Unterminated string, raw string, or regular expression")
    if round_depth or square_depth or curly_depth:
        raise RewriteV2Error("Unbalanced Rewrite V2 delimiters")

    parts.append(text[start:].strip())
    return parts


def _decode_quoted_string(text: str) -> V2String:
    inner = text[1:-1]
    parts: list[str | V2Variable] = []
    buffer: list[str] = []

    def flush() -> None:
        if buffer:
            parts.append("".join(buffer))
            buffer.clear()

    index = 0
    while index < len(inner):
        char = inner[index]
        if char == "\\":
            if inner.startswith("\\${", index):
                buffer.append("${")
                index += 3
                continue
            if index + 1 >= len(inner):
                raise RewriteV2Error("Trailing backslash in string")
            escaped = inner[index + 1]
            replacements = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
            if escaped not in replacements:
                raise RewriteV2Error(f"Unsupported string escape: \\{escaped}")
            buffer.append(replacements[escaped])
            index += 2
            continue

        if inner.startswith("${", index):
            end = inner.find("}", index + 2)
            if end < 0:
                raise RewriteV2Error("Unterminated variable in string")
            name = inner[index + 2 : end].strip()
            if not name:
                raise RewriteV2Error("Empty variable name")
            flush()
            parts.append(V2Variable(name))
            index = end + 1
            continue

        if char == '"':
            raise RewriteV2Error("Unescaped double quote in string")

        buffer.append(char)
        index += 1

    flush()
    return V2String(tuple(parts))


def _decode_raw_string(text: str) -> V2String:
    inner = text[1:-1]
    result: list[str] = []
    index = 0
    while index < len(inner):
        if inner[index] == "`" and index + 1 < len(inner) and inner[index + 1] == "`":
            result.append("`")
            index += 2
        elif inner[index] == "`":
            raise RewriteV2Error("A literal backtick in a raw string must be written as two backticks")
        else:
            result.append(inner[index])
            index += 1
    return V2String(("".join(result),))


def _parse_regex(text: str) -> V2Regex:
    if not text.startswith("/"):
        raise RewriteV2Error("Regular expression must start with /")

    index = 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "/":
            flags = text[index + 1 :]
            if not re.fullmatch(r"[ims]*", flags):
                raise RewriteV2Error(f"Unsupported regular expression flags: {flags}")
            if len(set(flags)) != len(flags):
                raise RewriteV2Error(f"Duplicate regular expression flags: {flags}")
            return V2Regex(text[1:index], flags)
        index += 1

    raise RewriteV2Error("Unterminated regular expression")


def parse_v2_value(text: str) -> V2Value:
    text = text.strip()
    if not text:
        raise RewriteV2Error("Missing Action argument")

    if text.startswith('"'):
        if len(text) < 2 or not text.endswith('"') or _is_escaped(text, len(text) - 1):
            raise RewriteV2Error("Unterminated string")
        return _decode_quoted_string(text)

    if text.startswith("`"):
        if len(text) < 2 or not text.endswith("`"):
            raise RewriteV2Error("Unterminated raw string")
        return _decode_raw_string(text)

    if text.startswith("/"):
        return _parse_regex(text)

    if text.startswith("["):
        if not text.endswith("]"):
            raise RewriteV2Error("Unterminated array")
        inner = text[1:-1].strip()
        if not inner:
            return V2Array(())
        return V2Array(tuple(parse_v2_value(item) for item in _split_top_level(inner, ",")))

    variable = re.fullmatch(r"\$\{(.+)\}", text)
    if variable:
        name = variable.group(1).strip()
        if not name:
            raise RewriteV2Error("Empty variable name")
        return V2Variable(name)

    if text == "true":
        return True
    if text == "false":
        return False
    if text == "null":
        return None
    if re.fullmatch(r"-?(?:0|[1-9]\d*)(?:\.\d+)?", text):
        return V2Number(text)

    raise RewriteV2Error(f"Unsupported value syntax: {text}")


def _parse_action(text: str) -> V2Action:
    matched = re.match(r"^([A-Za-z_][A-Za-z0-9_.]*)\s*\(", text)
    if not matched or not text.endswith(")"):
        raise RewriteV2Error(f"Invalid Action syntax: {text}")

    name = matched.group(1)
    arguments_text = text[matched.end() : -1].strip()
    if not arguments_text:
        arguments: tuple[V2Value, ...] = ()
    else:
        arguments = tuple(parse_v2_value(item) for item in _split_top_level(arguments_text, ","))
    return V2Action(name, arguments)


def parse_rewrite_v2_line(line: str) -> V2Rewrite:
    matched = re.match(r"^(request|response)\s+if\s+", line.strip())
    if not matched:
        raise RewriteV2Error("Rewrite V2 line must start with request if or response if")

    phase = matched.group(1)
    remainder = line.strip()[matched.end() :]
    pieces = _split_top_level(remainder, "then", word=True)
    if len(pieces) != 2 or not all(pieces):
        raise RewriteV2Error("Rewrite V2 line must contain one top-level then")

    condition, action_text = pieces
    action_parts = _split_top_level(action_text, "|")
    if not action_parts or any(not item for item in action_parts):
        raise RewriteV2Error("Rewrite V2 line contains an empty Action")
    return V2Rewrite(phase, condition, tuple(_parse_action(item) for item in action_parts))


def _is_outer_parenthesized(text: str) -> bool:
    text = text.strip()
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return False

    quote = ""
    depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "regex":
            if char == "\\":
                index += 2
                continue
            if char == "/":
                quote = ""
        elif quote:
            if char == quote and not _is_escaped(text, index):
                quote = ""
        elif char in ('"', "'", "`"):
            quote = char
        elif char == "/" and _looks_like_regex_start(text, index):
            quote = "regex"
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
        index += 1
    return depth == 0 and not quote


def parse_url_only_condition(text: str) -> V2UrlCondition:
    condition = text.strip()
    while _is_outer_parenthesized(condition):
        condition = condition[1:-1].strip()

    if len(_split_top_level(condition, "&&")) != 1 or len(_split_top_level(condition, "||")) != 1:
        raise RewriteV2Error("Only a single URL condition can be mapped to native Surge rewrite sections")

    matched = re.match(r"^\$\{url\}\s*(~=|==)\s*", condition)
    if not matched:
        raise RewriteV2Error("Only a single ${url} condition can be mapped to native Surge rewrite sections")

    operator = matched.group(1)
    value_text = condition[matched.end() :].strip()
    capture_name: str | None = None

    if operator == "~=":
        pieces = _split_top_level(value_text, "as", word=True)
        if len(pieces) == 2:
            value_text, capture_name = pieces
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", capture_name):
                raise RewriteV2Error(f"Invalid capture name: {capture_name}")
        elif len(pieces) != 1:
            raise RewriteV2Error("URL condition contains more than one capture declaration")

    value = parse_v2_value(value_text)
    if operator == "~=":
        if not isinstance(value, V2Regex):
            raise RewriteV2Error("The ~= URL condition requires a regular expression literal")
        return V2UrlCondition(value, capture_name)

    if capture_name:
        raise RewriteV2Error("The == URL condition cannot declare a capture")
    if not isinstance(value, V2String) or any(isinstance(part, V2Variable) for part in value.parts):
        raise RewriteV2Error("The == URL condition requires a constant string")
    literal = "".join(part for part in value.parts if isinstance(part, str))
    return V2UrlCondition(V2Regex("^" + re.escape(literal) + "$", ""), None)
