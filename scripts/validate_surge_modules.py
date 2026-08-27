from __future__ import annotations

import argparse
import base64
from collections import Counter
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent))

from convert_kelee_to_surge import (  # noqa: E402
    BASE_MODULE_FEATURE_REQUIREMENT,
    DOMAIN_RULE_TYPES,
    FATAL_REPORT_KINDS,
    IP_RULE_TYPES,
    LOGICAL_RULE_TYPES,
    MODULE_RULE_POLICIES,
    PRE_MATCHING_RULE_TYPES,
    RULE_TYPE_OPTIONS,
    SECTION_ORDER,
    SUPPORTED_RULE_TYPES,
    SURGE_5_14_FEATURE_REQUIREMENT,
    VERIFIED_SURGE_GENERIC_SCRIPT_PATHS,
    split_top_level,
    strip_wrapping_parentheses,
    unquote_property_value,
)


INFORMATIONAL_REPORT_KINDS = {
    "argument-unused-dropped",
    "generic-script-adapted",
    "jq-expression-corrected",
    "module-excluded",
    "rewrite-action-corrected",
    "rewrite-empty-skipped",
    "script-enable-direct-commented",
    "script-enable-direct-kept",
    "script-enable-shared-commented",
    "script-enable-shared-kept",
    "script-enable-toggle-emitted",
    "script-property-corrected",
}
MAP_LOCAL_DATA_TYPES = {"base64", "file", "text", "tiny-gif"}
MAP_LOCAL_OPTIONS = {"data", "data-type", "header", "status-code"}
SCRIPT_COMMON_OPTIONS = {"argument", "debug", "engine", "script-path", "script-update-interval", "timeout", "type"}
SCRIPT_TYPE_OPTIONS = {
    "cron": {"cronexp", "wake-system"},
    "generic": set(),
    "http-request": {"ability", "binary-body-mode", "max-size", "pattern", "requires-body"},
    "http-response": {"ability", "binary-body-mode", "max-size", "pattern", "requires-body"},
}


class SurgeValidationError(RuntimeError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        details = "\n".join(f"- {item}" for item in errors)
        super().__init__(f"Surge validation failed with {len(errors)} error(s):\n{details}")


def tokenize_surge_line(line: str) -> list[str]:
    tokens: list[str] = []
    token: list[str] = []
    quote = ""
    escaped = False
    token_started = False

    for char in line:
        if escaped:
            token.append(char)
            escaped = False
            token_started = True
            continue
        if quote and char == "\\":
            token.append(char)
            escaped = True
            token_started = True
            continue
        if char in ("'", '"'):
            if quote == char:
                quote = ""
            elif not quote:
                quote = char
                token_started = True
            else:
                token.append(char)
            continue
        if char.isspace() and not quote:
            if token_started:
                tokens.append("".join(token))
                token = []
                token_started = False
            continue
        token.append(char)
        token_started = True

    if quote:
        raise ValueError("unclosed quote")
    if escaped:
        raise ValueError("trailing escape")
    if token_started:
        tokens.append("".join(token))
    return tokens


def parse_sections(text: str, file: str, errors: list[str]) -> tuple[list[str], dict[str, list[tuple[int, str]]]]:
    sections: dict[str, list[tuple[int, str]]] = {}
    order: list[str] = []
    current: str | None = None

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        matched = re.fullmatch(r"\[([^\]]+)\]", stripped)
        if matched:
            current = matched.group(1)
            if current in sections:
                errors.append(f"{file}:{number}: duplicate section [{current}]")
            else:
                sections[current] = []
                order.append(current)
            continue
        if current and stripped:
            sections[current].append((number, stripped))

    return order, sections


def module_arguments(text: str, file: str, errors: list[str]) -> set[str]:
    lines = [item for item in text.splitlines() if item.startswith("#!arguments=")]
    if not lines:
        return set()
    if len(lines) > 1:
        errors.append(f"{file}: must contain at most one #!arguments line")

    payload = lines[0].removeprefix("#!arguments=")
    if not payload:
        errors.append(f"{file}: #!arguments must declare at least one argument")
        return set()
    arguments: set[str] = set()
    for item in split_top_level(payload, ","):
        key, separator, default = item.partition(":")
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            errors.append(f"{file}: invalid module argument name: {key!r}")
            continue
        if separator and any(char in default for char in ("\r", "\n")):
            errors.append(f"{file}: invalid line break in default for module argument: {key}")
        if key in arguments:
            errors.append(f"{file}: duplicate module argument name: {key}")
        arguments.add(key)
    return arguments


def effective_section_line(section: str, line: str) -> str | None:
    if section == "Script" and re.match(r"^#\s*.+\s=\s*type=", line):
        return line[1:].lstrip()
    if line.startswith(("#", ";", "//")):
        return None
    return line


def validate_nested_rule_matcher(prefix: str, matcher: str, errors: list[str]) -> None:
    text = strip_wrapping_parentheses(matcher)
    parts = split_top_level(text, ",")
    if len(parts) < 2:
        errors.append(f"{prefix}: invalid logical Rule matcher: {matcher}")
        return

    rule_type = parts[0].strip().upper()
    if rule_type not in SUPPORTED_RULE_TYPES:
        errors.append(f"{prefix}: unsupported logical Rule matcher type: {rule_type or '<empty>'}")
        return

    options = {part.strip().lower() for part in parts[2:]}
    unknown_options = sorted(options - RULE_TYPE_OPTIONS[rule_type])
    if unknown_options:
        errors.append(f"{prefix}: unsupported {rule_type} matcher option(s): {unknown_options}")
    if rule_type in DOMAIN_RULE_TYPES | {"URL-REGEX"} and "extended-matching" not in options:
        errors.append(f"{prefix}: logical domain or URL matcher is missing extended-matching: {matcher}")
    if rule_type in IP_RULE_TYPES and "no-resolve" not in options:
        errors.append(f"{prefix}: logical IP matcher is missing no-resolve: {matcher}")
    if "pre-matching" in options:
        errors.append(f"{prefix}: nested logical matcher contains pre-matching: {matcher}")

    if rule_type in LOGICAL_RULE_TYPES:
        group = strip_wrapping_parentheses(parts[1])
        children = split_top_level(group, ",")
        if not children:
            errors.append(f"{prefix}: logical Rule matcher contains no children: {matcher}")
        for child in children:
            validate_nested_rule_matcher(prefix, child, errors)


def validate_section_line(file: str, number: int, section: str, line: str, errors: list[str]) -> None:
    effective = effective_section_line(section, line)
    if effective is None:
        return

    try:
        tokens = tokenize_surge_line(effective)
    except ValueError as exc:
        errors.append(f"{file}:{number}: {exc}: {line}")
        return

    prefix = f"{file}:{number}"
    if section == "General":
        if "=" not in effective:
            errors.append(f"{prefix}: invalid General line: {line}")
        return

    if section == "Rule":
        parts = split_top_level(effective, ",")
        if len(parts) < 3:
            errors.append(f"{prefix}: invalid Rule line: {line}")
            return

        rule_type = parts[0].strip().upper()
        policy = parts[2].strip().upper()
        options = {part.strip().lower() for part in parts[3:]}
        if rule_type not in SUPPORTED_RULE_TYPES:
            errors.append(f"{prefix}: unsupported Rule type: {rule_type or '<empty>'}")
            return
        unknown_options = sorted(options - RULE_TYPE_OPTIONS[rule_type])
        if unknown_options:
            errors.append(f"{prefix}: unsupported {rule_type} Rule option(s): {unknown_options}")
        if policy not in MODULE_RULE_POLICIES:
            errors.append(
                f"{prefix}: module Rule policy must be DIRECT, REJECT, or REJECT-TINYGIF: {line}"
            )
        if rule_type in DOMAIN_RULE_TYPES | {"URL-REGEX"} and "extended-matching" not in options:
            errors.append(f"{prefix}: domain or URL rule is missing extended-matching: {line}")
        if not policy.startswith("REJECT") and "pre-matching" in options:
            errors.append(f"{prefix}: non-REJECT rule contains pre-matching: {line}")
        if rule_type in IP_RULE_TYPES:
            if "no-resolve" not in options:
                errors.append(f"{prefix}: IP rule is missing no-resolve: {line}")
        if (
            rule_type not in LOGICAL_RULE_TYPES
            and rule_type in PRE_MATCHING_RULE_TYPES
            and policy.startswith("REJECT")
            and "pre-matching" not in options
        ):
            errors.append(f"{prefix}: REJECT rule is missing pre-matching: {line}")
        if rule_type in LOGICAL_RULE_TYPES:
            group = strip_wrapping_parentheses(parts[1])
            children = split_top_level(group, ",")
            if not children:
                errors.append(f"{prefix}: logical Rule contains no matchers: {line}")
            for child in children:
                validate_nested_rule_matcher(prefix, child, errors)
        return

    if section == "URL Rewrite":
        if len(tokens) != 3 or tokens[-1] not in {"302", "307", "header", "reject"}:
            errors.append(f"{prefix}: invalid URL Rewrite shape: {tokens}")
        elif tokens[-1] == "reject" and tokens[1] != "_":
            errors.append(f"{prefix}: URL Rewrite reject replacement must be _: {line}")
        return

    if section == "Header Rewrite":
        if len(tokens) < 4 or tokens[0] not in {"http-request", "http-response"}:
            errors.append(f"{prefix}: invalid Header Rewrite prefix: {tokens}")
            return
        expected = {
            "header-add": 5,
            "header-del": 4,
            "header-replace": 5,
            "header-replace-regex": 6,
        }.get(tokens[2])
        if expected is None or len(tokens) != expected:
            errors.append(f"{prefix}: invalid Header Rewrite action or arity: {tokens}")
        return

    if section == "Body Rewrite":
        directions = {"http-request", "http-request-jq", "http-response", "http-response-jq"}
        if not tokens or tokens[0] not in directions:
            errors.append(f"{prefix}: invalid Body Rewrite prefix: {tokens}")
        elif tokens[0].endswith("-jq") and (len(tokens) != 3 or not tokens[2].strip()):
            errors.append(f"{prefix}: invalid JQ Body Rewrite expression: {tokens}")
        elif not tokens[0].endswith("-jq") and (len(tokens) < 4 or (len(tokens) - 2) % 2):
            errors.append(f"{prefix}: invalid regex Body Rewrite arity: {tokens}")
        return

    if section == "Map Local":
        options: dict[str, str] = {}
        for token in tokens[1:]:
            if "=" not in token:
                errors.append(f"{prefix}: invalid Map Local option: {token}")
                continue
            key, value = token.split("=", 1)
            if key in options:
                errors.append(f"{prefix}: duplicate Map Local option: {key}")
            options[key] = value

        unknown = sorted(set(options) - MAP_LOCAL_OPTIONS)
        if unknown:
            errors.append(f"{prefix}: unknown Map Local option(s): {unknown}")
        data_type = options.get("data-type")
        if data_type not in MAP_LOCAL_DATA_TYPES:
            errors.append(f"{prefix}: invalid Map Local data-type: {data_type!r}")
        if data_type != "tiny-gif" and "data" not in options:
            errors.append(f"{prefix}: Map Local is missing data")
        status = options.get("status-code")
        if status is None or not re.fullmatch(r"\d{3}", status) or not 200 <= int(status) <= 999:
            errors.append(f"{prefix}: invalid or missing Map Local status-code")
        if data_type == "base64":
            try:
                base64.b64decode(options.get("data", ""), validate=True)
            except Exception:
                errors.append(f"{prefix}: invalid Map Local base64 data")
        return

    if section == "Panel":
        if " = " not in effective:
            errors.append(f"{prefix}: invalid Panel line: {line}")
            return
        _, properties_text = effective.split(" = ", 1)
        properties: dict[str, str] = {}
        for item in split_top_level(properties_text, ","):
            if "=" not in item:
                errors.append(f"{prefix}: invalid Panel property: {item}")
                continue
            key, value = item.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                errors.append(f"{prefix}: empty Panel property: {item}")
                continue
            if key in properties:
                errors.append(f"{prefix}: duplicate Panel property: {key}")
            properties[key] = value

        allowed = {"content", "icon", "icon-color", "script-name", "style", "title", "update-interval"}
        unknown = sorted(set(properties) - allowed)
        if unknown:
            errors.append(f"{prefix}: unsupported Panel property/properties: {unknown}")
        missing = sorted({"content", "script-name", "title"} - set(properties))
        if missing:
            errors.append(f"{prefix}: missing Panel property/properties: {missing}")
        if "style" in properties and properties["style"] not in {"alert", "error", "good", "info"}:
            errors.append(f"{prefix}: invalid Panel style: {properties['style']}")
        return

    if section == "Script":
        if " = type=" not in effective:
            errors.append(f"{prefix}: invalid Script line: {line}")
            return

        _, properties_text = effective.split(" = ", 1)
        properties: dict[str, str] = {}
        for item in split_top_level(properties_text, ","):
            if "=" not in item:
                errors.append(f"{prefix}: invalid Script property: {item}")
                continue
            key, value = item.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key or not value:
                errors.append(f"{prefix}: empty Script property: {item}")
                continue
            if key in properties:
                errors.append(f"{prefix}: duplicate Script property: {key}")
            properties[key] = value

        script_type = properties.get("type")
        type_options = SCRIPT_TYPE_OPTIONS.get(script_type or "")
        if type_options is None:
            errors.append(f"{prefix}: unsupported Script type: {script_type!r}")
            return
        unknown = sorted(set(properties) - SCRIPT_COMMON_OPTIONS - type_options)
        if unknown:
            errors.append(f"{prefix}: unsupported {script_type} Script option(s): {unknown}")
        if "script-path" not in properties:
            errors.append(f"{prefix}: Script is missing script-path")
        elif script_type == "generic":
            script_path = unquote_property_value(properties["script-path"])
            if script_path not in VERIFIED_SURGE_GENERIC_SCRIPT_PATHS:
                errors.append(f"{prefix}: generic script-path is not verified for Surge: {script_path}")
        if script_type in {"http-request", "http-response"} and "pattern" not in properties:
            errors.append(f"{prefix}: {script_type} Script is missing pattern")
        if script_type == "cron" and "cronexp" not in properties:
            errors.append(f"{prefix}: cron Script is missing cronexp")
        for key in ("binary-body-mode", "debug", "requires-body", "wake-system"):
            if key in properties and properties[key].lower() not in {"true", "false"}:
                errors.append(f"{prefix}: {key} must be true or false")
        if "engine" in properties and properties["engine"].lower() not in {"auto", "jsc", "webview"}:
            errors.append(f"{prefix}: engine must be auto, jsc, or webview")
        return

    if section == "MITM" and not re.match(r"^hostname\s*=\s*%APPEND%\s+\S", effective):
        errors.append(f"{prefix}: invalid MITM line: {line}")


def validate_surge_modules(
    loon_dir: str = "Loon",
    surge_dir: str = "Surge",
    report_path: str = "Surge/convert-report.json",
    jq_command: str | None = None,
    require_jq: bool = False,
) -> dict[str, Any]:
    root = Path.cwd().resolve()
    input_root = root / loon_dir
    output_root = root / surge_dir
    report_full_path = root / report_path
    manifest_path = report_full_path.parent / "modules.index.json"
    errors: list[str] = []

    loon_files = sorted(input_root.glob("*.lpx"), key=lambda item: item.name)
    surge_files = sorted(output_root.glob("*.sgmodule"), key=lambda item: item.name)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = json.loads(report_full_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SurgeValidationError([f"Unable to read manifest or report: {exc}"]) from exc

    if not isinstance(manifest, list):
        raise SurgeValidationError(["modules.index.json must contain a JSON array"])
    if not isinstance(report, dict) or not isinstance(report.get("items"), list):
        raise SurgeValidationError(["convert-report.json has an invalid structure"])

    items = report["items"]
    manifest_outputs = [item.get("output") for item in manifest if isinstance(item, dict)]
    manifest_sources = [item.get("source") for item in manifest if isinstance(item, dict)]
    excluded_items = [item for item in items if isinstance(item, dict) and item.get("kind") == "module-excluded"]
    excluded_sources = [item.get("file") for item in excluded_items]
    input_sources = {item.name for item in loon_files}
    converted_sources = set(manifest_sources)
    excluded_source_set = set(excluded_sources)

    actual_counts = {
        "Loon": len(loon_files),
        "report total": report.get("total"),
        "Surge": len(surge_files),
        "manifest": len(manifest),
        "report converted": report.get("converted"),
        "excluded reports": len(excluded_items),
        "report excluded": report.get("excluded"),
    }
    if actual_counts["report total"] != actual_counts["Loon"]:
        errors.append("input module count mismatch: " + ", ".join(f"{key}={value}" for key, value in actual_counts.items()))
    if len({actual_counts["Surge"], actual_counts["manifest"], actual_counts["report converted"]}) != 1:
        errors.append("converted module count mismatch: " + ", ".join(f"{key}={value}" for key, value in actual_counts.items()))
    if actual_counts["excluded reports"] != actual_counts["report excluded"]:
        errors.append("excluded module count mismatch: " + ", ".join(f"{key}={value}" for key, value in actual_counts.items()))

    if len(manifest_outputs) != len(manifest):
        errors.append("manifest contains a non-object entry")
    if len(set(manifest_outputs)) != len(manifest_outputs):
        errors.append("manifest contains duplicate output names")
    if len(set(manifest_sources)) != len(manifest_sources):
        errors.append("manifest contains duplicate source names")
    if len(excluded_source_set) != len(excluded_sources):
        errors.append("conversion report contains duplicate excluded module names")
    if converted_sources & excluded_source_set:
        errors.append("a Loon source is both converted and excluded")
    if converted_sources | excluded_source_set != input_sources:
        errors.append("converted and excluded source names do not exactly cover Loon files")
    if set(manifest_outputs) != {item.name for item in surge_files}:
        errors.append("manifest output names do not match Surge files")

    if report.get("warnings") != len(items):
        errors.append("report warning count does not match its item count")
    known_report_kinds = FATAL_REPORT_KINDS | INFORMATIONAL_REPORT_KINDS
    unknown_report_kinds = sorted({item.get("kind") for item in items} - known_report_kinds)
    if unknown_report_kinds:
        errors.append(f"report contains unknown warning kinds: {unknown_report_kinds}")
    fatal_items = [item for item in items if item.get("kind") in FATAL_REPORT_KINDS]
    if fatal_items:
        errors.append(f"report contains {len(fatal_items)} fatal conversion item(s)")

    manifest_by_output = {
        item["output"]: item for item in manifest if isinstance(item, dict) and isinstance(item.get("output"), str)
    }
    section_modules: Counter[str] = Counter()
    section_lines: Counter[str] = Counter()
    jq_expressions: list[tuple[str, int, str]] = []

    for path in surge_files:
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"{path.name}: UTF-8 read failed: {exc}")
            continue

        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{path.name}: contains a UTF-8 BOM")
        if b"\x00" in raw:
            errors.append(f"{path.name}: contains NUL")
        if b"\r" in raw:
            errors.append(f"{path.name}: contains CR line endings")
        if not text.endswith("\n"):
            errors.append(f"{path.name}: missing final newline")
        if sum(line.startswith("#!name=") for line in text.splitlines()) != 1:
            errors.append(f"{path.name}: must contain exactly one #!name")
        system_lines = [line for line in text.splitlines() if line.startswith("#!system=")]
        if len(system_lines) > 1:
            errors.append(f"{path.name}: must contain at most one #!system line")
        elif system_lines and system_lines[0].removeprefix("#!system=") not in {"ios", "mac"}:
            errors.append(f"{path.name}: #!system must be ios or mac")

        order, sections = parse_sections(text, path.name, errors)
        if not order:
            errors.append(f"{path.name}: contains no effective Surge section")
        unknown_sections = [name for name in order if name not in SECTION_ORDER]
        if unknown_sections:
            errors.append(f"{path.name}: unknown sections: {unknown_sections}")
        indexes = [SECTION_ORDER.index(name) for name in order if name in SECTION_ORDER]
        if indexes != sorted(indexes):
            errors.append(f"{path.name}: invalid section order: {order}")
        requirement_lines = [line for line in text.splitlines() if line.startswith("#!requirement=")]
        if len(requirement_lines) > 1:
            errors.append(f"{path.name}: must contain at most one #!requirement line")
        has_base_module_feature = (
            "Body Rewrite" in sections
            or "Map Local" in sections
            or any(line.startswith("#!arguments=") for line in text.splitlines())
            or any(
                "extended-matching" in line
                for _, line in sections.get("Rule", [])
            )
        )
        has_jq_rewrite = any(
            re.match(r"^http-(?:request|response)-jq\s", line)
            for _, line in sections.get("Body Rewrite", [])
        )
        has_modern_rule_feature = any(
            "pre-matching" in {part.strip().lower() for part in split_top_level(line, ",")[3:]}
            or re.search(r"(?:^|\()URL-REGEX,", line) is not None
            for _, line in sections.get("Rule", [])
        )
        expected_requirement = (
            SURGE_5_14_FEATURE_REQUIREMENT
            if has_jq_rewrite or has_modern_rule_feature
            else BASE_MODULE_FEATURE_REQUIREMENT
            if has_base_module_feature
            else None
        )
        if expected_requirement and requirement_lines != [f"#!requirement={expected_requirement}"]:
            errors.append(
                f"{path.name}: expected #!requirement={expected_requirement} for its HTTP rewrite features"
            )
        elif not expected_requirement and requirement_lines:
            errors.append(f"{path.name}: unexpected #!requirement without a version-gated module feature")

        panel_script_names: set[str] = set()
        script_names: set[str] = set()
        for name, lines in sections.items():
            if not lines:
                errors.append(f"{path.name}: empty section [{name}]")
            section_modules[name] += 1
            section_lines[name] += len(lines)
            for number, line in lines:
                validate_section_line(path.name, number, name, line, errors)
                effective = effective_section_line(name, line)
                if effective and name == "Panel" and " = " in effective:
                    for item in split_top_level(effective.split(" = ", 1)[1], ","):
                        key, separator, value = item.partition("=")
                        if separator and key.strip() == "script-name":
                            panel_script_names.add(unquote_property_value(value))
                if effective and name == "Script" and " = " in effective:
                    script_names.add(effective.split(" = ", 1)[0].strip())
                if name == "Body Rewrite":
                    try:
                        tokens = tokenize_surge_line(line)
                    except ValueError:
                        continue
                    if tokens and tokens[0].endswith("-jq") and len(tokens) == 3 and tokens[2].strip():
                        jq_expressions.append((path.name, number, tokens[2]))

        missing_panel_scripts = sorted(panel_script_names - script_names)
        if missing_panel_scripts:
            errors.append(f"{path.name}: Panel references missing Script names: {missing_panel_scripts}")

        manifest_item = manifest_by_output.get(path.name)
        if manifest_item and order != manifest_item.get("sections"):
            errors.append(
                f"{path.name}: manifest sections {manifest_item.get('sections')!r} do not match actual sections {order!r}"
            )

        forbidden = {
            "Loon Rewrite V2": r"^(?:request|response)\s+if\s+.+\s+then\s+",
            "Loon enable": r"\benable\s*=",
            "Loon enabled?": r"\benabled\?\s*=",
            "bare Loon argument placeholder": r"(?<!\{)\{[A-Za-z_][A-Za-z0-9_.-]*\}(?!\})",
            "Loon mock option": r"\b(?:data-path|mock-data-is-base64)=",
        }
        for label, pattern in forbidden.items():
            for number, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line):
                    errors.append(f"{path.name}:{number}: residual {label}: {line}")

        declared = module_arguments(text, path.name, errors)
        replacement_text = "\n".join(
            line for line in text.splitlines() if not line.startswith("#!arguments=")
        )
        referenced = set(re.findall(r"\{\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}\}", replacement_text))
        built_in_placeholders = {"APPEND", "DEVICE_NAME", "GATEWAY_ADDRESS", "INSERT", "PROFILE_DIR", "SSID"}
        legacy_percent_placeholders = {
            name
            for name in re.findall(r"%([A-Za-z_][A-Za-z0-9_]*)%", replacement_text)
            if name not in built_in_placeholders and not re.fullmatch(r"[0-9A-Fa-f]{2}", name)
        }
        if legacy_percent_placeholders:
            errors.append(
                f"{path.name}: legacy percent module argument placeholders: {sorted(legacy_percent_placeholders)}"
            )
        missing_arguments = sorted(referenced - declared)
        if missing_arguments:
            errors.append(f"{path.name}: undeclared module arguments: {missing_arguments}")
        unused_arguments = sorted(declared - referenced)
        if unused_arguments:
            errors.append(f"{path.name}: unused module arguments: {unused_arguments}")

    resolved_jq = shutil.which(jq_command or "jq")
    if not resolved_jq and require_jq:
        errors.append("jq executable is required but was not found")
    if resolved_jq and jq_expressions:
        with tempfile.TemporaryDirectory(prefix="surge_jq_validation_") as temp_dir:
            program_path = Path(temp_dir) / "all-expressions.jq"
            definitions = [f"def __surge_audit_{index}: ({expression});" for index, (_, _, expression) in enumerate(jq_expressions)]
            program_path.write_text("\n".join(definitions) + "\nnull\n", encoding="utf-8", newline="\n")
            result = subprocess.run(
                [resolved_jq, "-n", "-f", str(program_path)],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        if result.returncode != 0:
            program_lines = sorted({int(item) for item in re.findall(r"line (\d+)", result.stderr)})
            sources = []
            for program_line in program_lines:
                if 1 <= program_line <= len(jq_expressions):
                    file, number, _ = jq_expressions[program_line - 1]
                    sources.append(f"{file}:{number}")
            source_text = f" ({', '.join(sources)})" if sources else ""
            errors.append(f"jq failed to compile generated expressions{source_text}: {result.stderr.strip()}")

    if errors:
        raise SurgeValidationError(errors)

    return {
        "modules": len(surge_files),
        "warnings": len(items),
        "warning_kinds": dict(sorted(Counter(item["kind"] for item in items).items())),
        "section_modules": {name: section_modules[name] for name in SECTION_ORDER},
        "section_lines": {name: section_lines[name] for name in SECTION_ORDER},
        "jq_compiled": bool(resolved_jq),
        "jq_expressions": len(jq_expressions),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate generated Surge modules and conversion metadata.")
    parser.add_argument("--loon-dir", default="Loon")
    parser.add_argument("--surge-dir", default="Surge")
    parser.add_argument("--report-path", default="Surge/convert-report.json")
    parser.add_argument("--jq-command", help="jq executable used to compile all generated JQ expressions")
    parser.add_argument("--require-jq", action="store_true", help="fail if jq is unavailable")
    args = parser.parse_args()

    summary = validate_surge_modules(
        args.loon_dir,
        args.surge_dir,
        args.report_path,
        jq_command=args.jq_command,
        require_jq=args.require_jq,
    )
    print(f"Validated {summary['modules']} Surge modules.")
    print(f"Warnings: {summary['warnings']} {summary['warning_kinds']}")
    print(f"JQ expressions: {summary['jq_expressions']} (compiled={summary['jq_compiled']})")


if __name__ == "__main__":
    main()
