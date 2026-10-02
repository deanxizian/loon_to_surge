"""Offline, fail-closed checks for demonstrable source payload defects.

This module does not repair source data, execute scripts, fetch resources, or
claim complete Loon validation. The converter remains responsible for syntax
and unsupported-feature checks. Blocking reports use ``source-quality``;
``source-quality-unverified`` reports describe checks that could not be made.
"""
from __future__ import annotations

import base64
import binascii
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
import json

try:
    from loon_rewrite_v2 import (
        RewriteV2Error, V2Action, V2Array, V2Rewrite, V2String, V2UrlCondition,
        V2Value, is_rewrite_v2_line, parse_rewrite_v2_line, parse_url_only_condition,
    )
except ModuleNotFoundError:
    from scripts.loon_rewrite_v2 import (
        RewriteV2Error, V2Action, V2Array, V2Rewrite, V2String, V2UrlCondition,
        V2Value, is_rewrite_v2_line, parse_rewrite_v2_line, parse_url_only_condition,
    )

BLOCKING_REPORT_KIND = "source-quality"
UNVERIFIED_REPORT_KIND = "source-quality-unverified"

# Exact filename, URL scope, action, JSON path and literal are all required.
# Evidence: tests/fixtures/kelee-v2-quality/source-cases.json.
# Strings are NOT generally coerced or rejected.
_KNOWN_TYPE_DRIFT: dict[tuple[str, str, str, str, str, str], str] = {
    ('BaiduMap_remove_ads.lpx', '^https:\\/\\/newclient\\.map\\.baidu\\.com\\/(client\\/)?usersystem\\/mine\\/page\\?', 'i', 'response.json.replace', 'data', '{}'): 'object',
    ('DiDi_remove_ads.lpx', '^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.querySellCardSummary', 'i', 'response.json.replace', 'data', '{}'): 'object',
    ('DiDi_remove_ads.lpx', '^https:\\/\\/htwkop\\.xiaojukeji\\.com(:443)?\\/gateway\\?api=hm\\.fa\\.queryWelfareCenter', 'i', 'response.json.replace', 'data', '{}'): 'object',
    ('DigitalHeartbeat_remove_ads.lpx', '^https:\\/\\/api-changzheng\\.chinaath\\.com\\/changzheng-common-proxy-api\\/api\\/advertising\\/proxy\\/getOpenScreenAdvertising$', 'i', 'response.json.replace', 'data.advertisingList', '[]'): 'array',
    ('Keep_remove_ads.lpx', '^https:\\/\\/api\\.gotokeep\\.com\\/twins\\/v4\\/feed\\/entryDetail\\?', 'i', 'response.json.replace', 'data', '{}'): 'object',
    ('MeiRiSaiChe_remove_ads.lpx', '^https:\\/\\/api\\.romielf\\.com\\/index\\/indexv\\d\\?', 'i', 'response.json.replace', 'data.advertisement', '[]'): 'array',
    ('MeiRiSaiChe_remove_ads.lpx', '^https:\\/\\/api\\.romielf\\.com\\/index\\/indexv\\d\\?', 'i', 'response.json.replace', 'data.listadvertising', '[]'): 'array',
    ('PangguaiLife_remove_ads.lpx', '^https:\\/\\/userapi\\.qiekj\\.com\\/local-life\\/tab-order$', 'i', 'response.json.replace', 'data', '[]'): 'array',
    ('PangguaiLife_remove_ads.lpx', '^https:\\/\\/userapi\\.qiekj\\.com\\/integralGoods\\/queryIntegralGoodsCategoryList$', 'i', 'response.json.replace', 'data', '[]'): 'array',
    ('QiDian_remove_ads.lpx', '^https:\\/\\/magev6\\.if\\.qidian\\.com\\/argus\\/api\\/v2\\/dailyrecommend\\/getdailyrecommend\\?', 'i', 'response.json.replace', 'Data.Items', '[]'): 'array',
    ('RedPaper_remove_ads.lpx', '^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/banner_list$', 'i', 'response.json.replace', 'data', '{}'): 'object',
    ('RedPaper_remove_ads.lpx', '^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v1\\/search\\/hot_list$', 'i', 'response.json.replace', 'data.items', '[]'): 'array',
    ('RedPaper_remove_ads.lpx', '^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/hint', 'i', 'response.json.replace', 'data.hint_words', '[]'): 'array',
    ('RedPaper_remove_ads.lpx', '^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/trending\\?', 'i', 'response.json.replace', 'data.queries', '[]'): 'array',
    ('RedPaper_remove_ads.lpx', '^https:\\/\\/edith\\.xiaohongshu\\.com\\/api\\/sns\\/v4\\/search\\/trending\\?', 'i', 'response.json.replace', 'data.hint_word', '{}'): 'object',
}

# Chelaile uses this documented-in-source envelope in both verified snapshots.
# The inner JSON still must validate; this is not an arbitrary content bypass.
_FRAMED_JSON_SCOPES: frozenset[tuple[str, str, str]] = frozenset({
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/api\\.chelaile\\.net\\.cn\\/encourage\\/activity\\/control\\?', 'i'),
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/api\\.chelaile\\.net\\.cn\\/goocity\\/config\\/notices\\?', 'i'),
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/api\\.chelaile\\.net\\.cn\\/goocity\\/flowPos\\/home\\?', 'i'),
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/api\\.chelaile\\.net\\.cn\\/goocity\\/flowPos\\/listByPos\\?', 'i'),
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/api\\.chelaile\\.net\\.cn\\/led-weather\\/v\\d\\/condition_brief\\?', 'i'),
    ('Chelaile_remove_ads.lpx', '^https:\\/\\/web\\.chelaile\\.net\\.cn\\/api\\/operative_position\\/infoflow\\/getInfo\\?', 'i'),
})


def _static_string(value: V2Value) -> str | None:
    if isinstance(value, V2String) and all(isinstance(part, str) for part in value.parts):
        return "".join(value.parts)
    return None


def _url_condition(rewrite: V2Rewrite) -> V2UrlCondition | None:
    try:
        return parse_url_only_condition(rewrite.condition)
    except RewriteV2Error:
        # Unsupported conditions are checked by the converter, not weakened here.
        return None


def _replacement_pairs(action: V2Action) -> list[tuple[V2Value, V2Value]]:
    if len(action.arguments) != 2:
        return []
    first, second = action.arguments
    if isinstance(first, V2Array) and isinstance(second, V2Array):
        if len(first.items) != len(second.items):
            return []  # Invalid action shape remains the converter's responsibility.
        return list(zip(first.items, second.items))
    if isinstance(first, V2Array) or isinstance(second, V2Array):
        return []
    return [(first, second)]


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"Non-JSON numeric constant: {value}")


def _validate_json(text: str) -> None:
    # Python otherwise accepts NaN and Infinity, which are not JSON values.
    text.encode("utf-8")
    json.loads(text, parse_constant=_reject_non_json_constant)



def validate_generated_json_mock(
    source_filename: str, url_pattern: str, body: bytes | str,
) -> None:
    """Validate decoded JSON Map Local data independently of source reports.

    ``source_filename`` must come from the source/output manifest. ``url_pattern``
    is the exact emitted Surge pattern token. Only the six verified Chelaile
    scopes accept protocol framing, under either their legacy spelling or the
    exact V2 ``(?i:...)`` wrapper. All other inputs require ordinary strict JSON.
    No data is fetched, mutated, repaired, or returned. Raises ``ValueError`` on
    invalid content, including invalid UTF-8 or excessive JSON nesting.
    """
    try:
        if isinstance(body, bytes):
            text = body.decode("utf-8")
        elif isinstance(body, str):
            text = body
        else:
            raise ValueError("JSON mock body must be bytes or a String")
        allow_framing = any(
            source_filename == filename
            and url_pattern in (pattern, f"(?i:{pattern})")
            for filename, pattern, flags in _FRAMED_JSON_SCOPES
            if flags == "i"
        )
        if allow_framing and text.startswith("**YGKJ"):
            if not text.endswith("YGKJ##"):
                raise ValueError("Known Chelaile JSON envelope is missing the YGKJ## suffix")
            text = text[len("**YGKJ"):-len("YGKJ##")]
        _validate_json(text)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(f"Invalid generated JSON mock: {exc}") from exc


def _json_mock_problem(
    filename: str, rewrite: V2Rewrite, action: V2Action,
) -> tuple[str, str, str] | None:
    if action.name not in {
        "request.body.mock", "response.body.mock",
        "request.body.mock_file", "response.body.mock_file",
    } or len(action.arguments) < 2:
        return None
    content_type = _static_string(action.arguments[0])
    if content_type is None:
        return (UNVERIFIED_REPORT_KIND, "dynamic-mock-content-type",
                "Mock Content-Type is dynamic; JSON payload validation was not performed.")
    if content_type != "json":
        return None
    if action.name.endswith("_file"):
        return (UNVERIFIED_REPORT_KIND, "remote-runtime-not-validated",
                "JSON mock_file payload is resolved at runtime; its bytes were not fetched or validated offline.")

    body = _static_string(action.arguments[1])
    if body is None:
        return (UNVERIFIED_REPORT_KIND, "dynamic-json-not-validated",
                "JSON mock body contains dynamic values; the final payload was not validated offline.")
    base64_index = 3 if action.name.startswith("response.") else 2
    encoded = action.arguments[base64_index] if len(action.arguments) > base64_index else False
    if not isinstance(encoded, bool):
        return (UNVERIFIED_REPORT_KIND, "dynamic-encoding-not-validated",
                "JSON mock Base64 flag is not a static Boolean; payload validation was not performed.")
    try:
        if encoded:
            body = base64.b64decode(body, validate=True).decode("utf-8")
        condition = _url_condition(rewrite)
        scope = (filename, condition.regex.pattern, condition.regex.flags) if condition else None
        if rewrite.phase == "response" and scope in _FRAMED_JSON_SCOPES and body.startswith("**YGKJ"):
            if not body.endswith("YGKJ##"):
                raise ValueError("Known Chelaile JSON envelope is missing the YGKJ## suffix")
            body = body[len("**YGKJ"):-len("YGKJ##")]
        _validate_json(body)
    except (ValueError, UnicodeError, binascii.Error, RecursionError) as exc:
        return (BLOCKING_REPORT_KIND, "invalid-json-mock",
                f"{action.name} declares JSON but its {'Base64-decoded ' if encoded else ''}inline body "
                f"is not valid UTF-8 JSON: {exc}. Publication must stop; source bytes were not repaired.")
    return None


def _source_line_numbers(source_text: str | None) -> dict[str, deque[int]]:
    numbers: dict[str, deque[int]] = defaultdict(deque)
    section = ""
    for number, raw in enumerate((source_text or "").splitlines(), 1):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
        elif section == "rewrite" and line and not line.startswith(("#", ";")):
            numbers[line].append(number)
    return numbers


def inspect_source_quality(
    filename: str,
    source_sections: Mapping[str, Sequence[str]],
    *,
    source_text: str | None = None,
) -> list[dict[str, str]]:
    """Return precise diagnostics without mutating source or generated output.

    Call with the basename and parsed Loon sections before conversion/publication.
    Every ``source-quality`` diagnostic is fatal. The unverified kind is a
    warning only; normal converter capability checks must still run. Supplying
    original text adds a one-based ``line_number``; ``line`` always contains the
    source instruction. This intentionally checks Rewrite V2 only. Legacy and
    malformed syntax must still go through the normal converter checks.
    """
    reports: list[dict[str, str]] = []
    numbers = _source_line_numbers(source_text)
    for section, lines in source_sections.items():
        if section.lower() != "rewrite":
            continue
        for raw in lines:
            line = raw.strip()
            line_number = numbers[line].popleft() if numbers.get(line) else None
            if not is_rewrite_v2_line(line):
                continue
            try:
                rewrite = parse_rewrite_v2_line(line)
            except RewriteV2Error:
                continue  # Never hide/replace the converter's fatal syntax report.
            condition = _url_condition(rewrite)

            def report(kind: str, reason: str, message: str) -> None:
                item = {"file": filename, "kind": kind, "reason": reason, "message": message, "line": line}
                if line_number is not None:
                    item["line_number"] = str(line_number)
                reports.append(item)

            for action in rewrite.actions:
                problem = _json_mock_problem(filename, rewrite, action)
                if problem is not None:
                    report(*problem)
                if rewrite.phase != "response" or action.name != "response.json.replace" or condition is None:
                    continue
                for path_value, replacement in _replacement_pairs(action):
                    path, literal = _static_string(path_value), _static_string(replacement)
                    if path is None or literal is None:
                        continue
                    key = (filename, condition.regex.pattern, condition.regex.flags, action.name, path, literal)
                    before = _KNOWN_TYPE_DRIFT.get(key)
                    if before is not None:
                        report(BLOCKING_REPORT_KIND, "known-json-type-drift",
                               f"Verified 2026-10-02 upstream migration changes JSON path {path!r} "
                               f"from an empty {before} to the String {literal!r} at this exact URL scope. "
                               "This differs from the verified previous source. Publication must stop; "
                               "use an upstream-corrected typed operation or explicitly reviewed repair, "
                               "not automatic string coercion.")
    return reports
