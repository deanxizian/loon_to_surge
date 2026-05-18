from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any


WINDOWS_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')
SECTION_ORDER = ("General", "Rule", "URL Rewrite", "Header Rewrite", "Body Rewrite", "Map Local", "Script", "MITM")


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


def convert_delete_paths_to_jq(paths: list[str]) -> str:
    converted = [convert_path_to_jq_array(path) for path in paths]
    return "'delpaths([" + ",".join(converted) + "])'"


def convert_replace_pairs_to_jq(text: str) -> str:
    tokens = [token for token in re.split(r"\s+", text.strip()) if token]
    parts: list[str] = []
    for index in range(0, len(tokens) - 1, 2):
        path = convert_path_to_jq_array(tokens[index])
        value = convert_json_value(tokens[index + 1])
        parts.append(f"setpath({path}; {value})")
    return "'" + " | ".join(parts) + "'"


def parse_properties(text: str | None) -> OrderedDict[str, str]:
    props: OrderedDict[str, str] = OrderedDict()
    for part in split_top_level(text, ","):
        key, value = split_first(part, "=")
        if value:
            props[key.strip()] = value.strip()
    return props


def add_report(report: list[dict[str, str]], file: str, kind: str, message: str, line: str) -> None:
    report.append({"file": file, "kind": kind, "message": message, "line": line})


def is_reject_policy(policy: str) -> bool:
    return policy.upper().startswith("REJECT")


def ensure_rule_option(parts: list[str], option: str) -> None:
    if option not in (part.strip() for part in parts[3:]):
        parts.append(option)


def remove_rule_option(parts: list[str], option: str) -> None:
    parts[:] = parts[:3] + [part for part in parts[3:] if part.strip() != option]


def convert_rule_line(line: str) -> str:
    normalized = re.sub(r"\s*,\s*", ",", line).strip()
    parts = split_top_level(normalized, ",")
    if len(parts) < 3:
        return normalized

    rule_type = parts[0].strip().upper()
    policy = parts[2].strip().upper()
    reject_policy = is_reject_policy(policy)

    if rule_type in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"):
        ensure_rule_option(parts, "extended-matching")
        if reject_policy:
            ensure_rule_option(parts, "pre-matching")
        else:
            remove_rule_option(parts, "pre-matching")
    elif rule_type == "URL-REGEX":
        ensure_rule_option(parts, "extended-matching")
    elif rule_type in ("IP-CIDR", "IP-CIDR6"):
        ensure_rule_option(parts, "no-resolve")
        if reject_policy:
            ensure_rule_option(parts, "pre-matching")
        else:
            remove_rule_option(parts, "pre-matching")

    return ",".join(parts)


def convert_rewrite_line(line: str, sections: OrderedDict[str, list[str]], report: list[dict[str, str]], file: str) -> None:
    inline_match = re.match(r"^(http-request|http-response)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", line)
    if inline_match:
        kind, pattern, action, rest = inline_match.groups()
        rest = rest or ""

        if action == "response-body-json-jq":
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {rest}")
        elif action == "response-body-json-del":
            paths = [item for item in re.split(r"\s+", rest.strip()) if item]
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_delete_paths_to_jq(paths)}")
        elif action == "response-body-json-replace":
            sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_replace_pairs_to_jq(rest)}")
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
        mock = re.sub(r"^mock-response-body\s+", "", rest)
        if "data-type=json" in mock:
            mock = mock.replace("data-type=json", "data-type=text")
            if "header=" not in mock:
                mock += ' header="Content-Type:application/json"'
        if "status-code=" not in mock:
            mock += " status-code=200"
        sections["Map Local"].append(f"{pattern} {mock}")
    elif action == "response-body-json-jq":
        sections["Body Rewrite"].append(f"http-response-jq {pattern} {rest}")
    elif action == "response-body-json-del":
        paths = [item for item in re.split(r"\s+", rest.strip()) if item]
        sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_delete_paths_to_jq(paths)}")
    elif action == "response-body-json-replace":
        sections["Body Rewrite"].append(f"http-response-jq {pattern} {convert_replace_pairs_to_jq(rest)}")
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


def convert_script_line(line: str, output: list[str], report: list[dict[str, str]], file: str) -> None:
    match = re.match(r"^(http-request|http-response)\s+(\S+)(?:\s+(.*))?$", line)
    if match:
        script_type, pattern, props_text = match.groups()
        props = parse_properties(props_text)
        name = props.get("tag") or f"{script_type} {len(output) + 1}"
        parts = [f"type={script_type}", f"pattern={pattern}"]

        for key in ("script-path", "requires-body", "binary-body-mode", "timeout", "engine", "max-size", "ability"):
            if key in props:
                if key in ("requires-body", "binary-body-mode") and props[key] == "false":
                    continue
                parts.append(f"{key}={props[key]}")
        if props.get("argument"):
            parts.append(f"argument={convert_argument_value(props['argument'])}")
        if "enable" in props:
            add_report(report, file, "script-enable-dropped", "Loon enable option was not emitted because Surge module support is not equivalent.", line)

        output.append(f"{name} = " + ", ".join(parts))
        return

    match = re.match(r"^cron\s+(\S+)(?:\s+(.*))?$", line)
    if match:
        cron, props_text = match.groups()
        cron = convert_placeholder(cron)
        props = parse_properties(props_text)
        name = props.get("tag") or f"cron {len(output) + 1}"
        parts = ["type=cron", f"cronexp={cron}"]

        for key in ("script-path", "timeout", "engine", "wake-system"):
            if key in props:
                parts.append(f"{key}={props[key]}")
        if props.get("argument"):
            parts.append(f"argument={convert_argument_value(props['argument'])}")
        if "enable" in props:
            add_report(report, file, "script-enable-dropped", "Loon enable option was not emitted because Surge module support is not equivalent.", line)

        output.append(f"{name} = " + ", ".join(parts))
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


def convert_argument_lines(lines: list[str], report: list[dict[str, str]], file: str) -> list[str]:
    items: list[str] = []
    for line in lines:
        name, value = split_first(line, "=")
        if not value:
            add_report(report, file, "argument-parse", "Unable to parse argument line", line)
            continue
        parts = split_top_level(value, ",")
        if len(parts) < 2:
            add_report(report, file, "argument-default", "Unable to find argument default value", line)
            continue
        items.append(f"{name.strip()}:{parts[1].strip()}")
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

    for line in section_lines(source_sections, "General"):
        match = re.match(r"^real-ip\s*=\s*(.+)$", line, flags=re.IGNORECASE)
        if match:
            sections["General"].append(f"always-real-ip = %APPEND% {match.group(1).strip()}")
        else:
            sections["General"].append(line)
            add_report(report, path.name, "general-pass-through", "General line passed through without conversion.", line)

    for line in section_lines(source_sections, "Rule"):
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
            add_report(report, path.name, "external-policy", "Rule uses PROXY, which requires the target Surge profile to define a PROXY policy or policy group.", line)

        sections["Rule"].append(convert_rule_line(line))

    for line in section_lines(source_sections, "Rewrite"):
        convert_rewrite_line(line, sections, report, path.name)

    for line in section_lines(source_sections, "Script"):
        convert_script_line(line, sections["Script"], report, path.name)

    for line in section_lines(source_sections, "MitM"):
        match = re.match(r"^hostname\s*=\s*(.+)$", line, flags=re.IGNORECASE)
        if match:
            sections["MITM"].append(f"hostname = %APPEND% {match.group(1).strip()}")
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

    if has_section(source_sections, "Argument"):
        argument_items = convert_argument_lines(section_lines(source_sections, "Argument"), report, path.name)
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
            "generated_at": timestamp(),
            "input_dir": input_dir,
            "output_dir": output_dir,
            "total": len(files),
            "warnings": len(report),
            "items": report,
        }
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
