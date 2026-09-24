"""Read-only remote script audit; findings are review hints, not runtime verdicts."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import re
import time
from typing import Any
import urllib.error
import urllib.request

try:
    from convert_kelee_to_surge import LOON_USER_AGENT, split_top_level, unquote_property_value
except ModuleNotFoundError:
    from scripts.convert_kelee_to_surge import LOON_USER_AGENT, split_top_level, unquote_property_value


MAX_SCRIPT_BYTES = 8 * 1024 * 1024


def collect_script_urls(surge_dir: Path) -> dict[str, list[dict[str, Any]]]:
    references: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(surge_dir.glob("*.sgmodule")):
        section = ""
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.strip()
            if re.fullmatch(r"\[[^\]]+\]", line):
                section = line[1:-1]
                continue
            if section != "Script" or not line or line.startswith((";", "//")):
                continue
            # Include disabled scripts: users can enable them after import.
            if line.startswith("#"):
                line = line[1:].lstrip()
            _, separator, properties = line.partition("=")
            if not separator:
                continue
            for item in split_top_level(properties):
                key, _, value = item.partition("=")
                if key.strip() == "script-path":
                    url = unquote_property_value(value.strip())
                    if re.match(r"^https?://", url):
                        references.setdefault(url, []).append({"module": path.name, "line": number})
    return dict(sorted(references.items()))


def member_pattern(root: str, *members: str) -> re.Pattern[str]:
    pattern = r"(?<![\w$])" + re.escape(root)
    for member in members:
        escaped = re.escape(member)
        pattern += rf'''(?:\s*\.\s*{escaped}\b|\s*\[\s*["']{escaped}["']\s*\])'''
    return re.compile(pattern)


API_PATTERNS = {
    "$utils.gzip": member_pattern("$utils", "gzip"),
    "$crypto.aes": member_pattern("$crypto", "aes"),
    "$dns.query": member_pattern("$dns", "query"),
}
PLATFORM_MARKERS = {
    "$loon": re.compile(r"(?<![\w$])\$loon\b"),
    "$environment.surge-version": member_pattern("$environment", "surge-version"),
    "$environment.surge-build": member_pattern("$environment", "surge-build"),
}


def inspect_source(source: str) -> dict[str, Any]:
    hits = []
    for api, pattern in API_PATTERNS.items():
        for match in pattern.finditer(source):
            hits.append({
                "api": api,
                "line": source.count("\n", 0, match.start()) + 1,
                "context": source[max(0, match.start() - 100):match.end() + 100].replace("\n", " "),
            })
    return {
        "api_hits": sorted(hits, key=lambda item: (item["line"], item["api"])),
        "platform_markers": [label for label, pattern in PLATFORM_MARKERS.items() if pattern.search(source)],
    }


def download_script(url: str, timeout: float, user_agent: str) -> tuple[bytes, str, str]:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(MAX_SCRIPT_BYTES + 1)
                if len(data) > MAX_SCRIPT_BYTES:
                    raise ValueError(f"Script exceeds {MAX_SCRIPT_BYTES} bytes")
                return data, response.geturl(), response.headers.get_content_type()
        except urllib.error.HTTPError as exc:
            retry = attempt == 0 and (exc.code == 429 or 500 <= exc.code <= 599)
            exc.close()
            if not retry:
                raise
        except (urllib.error.URLError, TimeoutError, HTTPException):
            if attempt:
                raise
        time.sleep(1)
    raise AssertionError("Unreachable retry state")


def audit_script(url: str, references: list[dict[str, Any]], timeout: float, user_agent: str) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url, "references": references}
    try:
        data, final_url, content_type = download_script(url, timeout, user_agent)
        result.update({"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                       "final_url": final_url, "content_type": content_type})
        source = data.decode("utf-8-sig")
        if not source.strip() or content_type == "text/html" or re.match(r"\s*(?:<!doctype html|<html)\b", source, re.I):
            result.update({"status": "download-failed", "error": "Expected JavaScript; received empty content or HTML"})
        else:
            inspection = inspect_source(source)
            result.update(inspection)
            result["status"] = "needs-review" if inspection["api_hits"] else "ok"
    except (OSError, ValueError, HTTPException) as exc:
        result.update({"status": "download-failed", "error": f"{type(exc).__name__}: {exc}"})
    return result


def check_remote_scripts(surge_dir: Path, *, workers: int = 6, timeout: float = 20,
                         user_agent: str = LOON_USER_AGENT) -> dict[str, Any]:
    urls = collect_script_urls(surge_dir)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda url: audit_script(url, urls[url], timeout, user_agent), urls))
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user_agent": user_agent,
        "scope": "Lexical inspection only; platform markers do not prove a guard, and no hits do not prove compatibility.",
        "summary": {"total": len(results), **{
            status: sum(item["status"] == status for item in results)
            for status in ("ok", "needs-review", "download-failed")
        }},
        "scripts": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surge-dir", type=Path, default=Path("Surge"))
    parser.add_argument("--report-path", type=Path, default=Path(".tmp/remote-script-audit.json"))
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--user-agent", default=LOON_USER_AGENT)
    parser.add_argument("--strict", action="store_true", help="Exit nonzero on download failures or API review findings")
    args = parser.parse_args()
    if not args.surge_dir.is_dir() or not any(args.surge_dir.glob("*.sgmodule")):
        parser.error("surge-dir must contain generated .sgmodule files")
    if not 1 <= args.workers <= 16 or args.timeout <= 0:
        parser.error("workers must be 1..16 and timeout must be positive")
    report = check_remote_scripts(args.surge_dir, workers=args.workers, timeout=args.timeout, user_agent=args.user_agent)
    args.report_path.parent.mkdir(parents=True, exist_ok=True)
    args.report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], ensure_ascii=False))
    print(f"Remote script audit: {args.report_path}")
    for item in report["scripts"]:
        if item["status"] != "ok":
            detail = item.get("error") or ", ".join(sorted({hit["api"] for hit in item["api_hits"]}))
            print(f"{item['status']}: {item['url']}: {detail}")
    if args.strict and any(item["status"] != "ok" for item in report["scripts"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
