from __future__ import annotations

from dataclasses import dataclass
import math
import re

try:
    from loon_rewrite_v2 import RewriteV2Error, V2Number, V2String, V2Value, V2Variable, parse_v2_value, split_v2_top_level
except ModuleNotFoundError:
    from scripts.loon_rewrite_v2 import (
        RewriteV2Error, V2Number, V2String, V2Value, V2Variable, parse_v2_value, split_v2_top_level,
    )


@dataclass(frozen=True)
class V2ArgumentObject:
    variables: tuple[V2Variable, ...]


@dataclass(frozen=True)
class V2Script:
    trigger: str
    condition: str | None
    schedule: V2String | V2Variable | None
    path: V2String
    argument: V2String | V2ArgumentObject | None
    properties: dict[str, V2Value]


def is_script_v2_line(line: str) -> bool:
    line = line.strip()
    if re.match(r"^(?:request|response)\s+if\b|^(?:generic|network-changed)\s+then\b", line):
        return True
    if re.match(r"^cron\s+", line):
        try:
            return len(split_v2_top_level(line, "then", word=True)) > 1
        except RewriteV2Error:
            # Malformed V2 must still reach the V2 parser and produce a fatal diagnostic.
            return re.match(r'^cron\s+(?:["`]|\$\{)', line) is not None
    return False


def parse_script_argument(text: str) -> V2String | V2ArgumentObject:
    if text.startswith("{") and text.endswith("}"):
        variables = tuple(parse_v2_value(item) for item in split_v2_top_level(text[1:-1], ","))
        if not all(isinstance(item, V2Variable) for item in variables):
            raise RewriteV2Error("Script Object argument may only contain plugin variables")
        if len({item.name for item in variables}) != len(variables):
            raise RewriteV2Error("Script Object argument contains duplicate variables")
        return V2ArgumentObject(variables)
    value = parse_v2_value(text)
    if not isinstance(value, V2String):
        raise RewriteV2Error("Script argument must be a String or plugin Object")
    return value


def validate_property(name: str, value: V2Value, trigger: str) -> None:
    if name in {"requires_body", "binary_body_mode"}:
        if trigger not in {"request", "response"} or not isinstance(value, bool):
            raise RewriteV2Error(f"{name} requires a static Boolean and an HTTP trigger")
    elif name in {"enable", "debug"}:
        if not isinstance(value, (bool, V2Variable)):
            raise RewriteV2Error(f"{name} must be a Boolean or plugin variable")
    elif name in {"tag", "img_url"}:
        if not isinstance(value, V2String) or any(isinstance(part, V2Variable) for part in value.parts):
            raise RewriteV2Error(f"{name} must be a static String")
    elif name == "timeout":
        if not isinstance(value, (V2Number, V2Variable)):
            raise RewriteV2Error("timeout must be a Number or plugin variable")
        if isinstance(value, V2Number) and (not math.isfinite(float(value.text)) or float(value.text) <= 0):
            raise RewriteV2Error("timeout must be finite and positive")
    else:
        raise RewriteV2Error(f"Unknown Script V2 property: {name}")


def parse_script_v2_line(line: str) -> V2Script:
    matched = re.match(r"^(request|response|cron|generic|network-changed)\b\s*", line.strip())
    if not matched:
        raise RewriteV2Error("Unknown Script V2 trigger")
    trigger = matched.group(1)
    pieces = split_v2_top_level(line.strip()[matched.end():], "then", word=True)
    if len(pieces) != 2 or not pieces[1]:
        raise RewriteV2Error("Script V2 must contain one top-level then and script Action")
    head, tail = pieces
    condition = None
    schedule = None
    if trigger in {"request", "response"}:
        http_head = re.fullmatch(r"if\s+(.+)", head)
        if not http_head:
            raise RewriteV2Error("HTTP Script V2 requires an if condition")
        condition = http_head.group(1).strip()
    elif trigger == "cron":
        schedule = parse_v2_value(head)
        if not isinstance(schedule, (V2String, V2Variable)):
            raise RewriteV2Error("Cron schedule must be a String or plugin variable")
    elif head:
        raise RewriteV2Error(f"{trigger} does not accept a condition or schedule")

    action_and_properties = split_v2_top_level(tail, "with", word=True)
    if len(action_and_properties) > 2:
        raise RewriteV2Error("Script V2 contains more than one top-level with")
    action = re.fullmatch(r"script\s*\((.*)\)", action_and_properties[0])
    if not action:
        raise RewriteV2Error("Script V2 requires one script(...) Action")
    arguments = split_v2_top_level(action.group(1), ",")
    if len(arguments) not in {1, 2}:
        raise RewriteV2Error("script(...) expects a path and at most one argument")
    path = parse_v2_value(arguments[0])
    if not isinstance(path, V2String) or any(isinstance(part, V2Variable) for part in path.parts):
        raise RewriteV2Error("Script path must be a static String")
    if not "".join(path.parts).strip():
        raise RewriteV2Error("Script path must not be empty")
    argument = parse_script_argument(arguments[1]) if len(arguments) == 2 else None

    properties: dict[str, V2Value] = {}
    if len(action_and_properties) == 2:
        for item in split_v2_top_level(action_and_properties[1], ","):
            name, separator, source = item.partition("=")
            name = name.strip()
            if not separator or not name or not source.strip():
                raise RewriteV2Error(f"Invalid Script V2 property: {item}")
            if name in properties:
                raise RewriteV2Error(f"Duplicate Script V2 property: {name}")
            value = parse_v2_value(source)
            validate_property(name, value, trigger)
            properties[name] = value
    return V2Script(trigger, condition, schedule, path, argument, properties)
