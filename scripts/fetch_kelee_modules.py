from __future__ import annotations

import argparse
import json
import math
import shutil
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    from stable_output import json_payload_matches, previous_timestamp, tree_contents_match
except ModuleNotFoundError:
    from scripts.stable_output import json_payload_matches, previous_timestamp, tree_contents_match


LOON_USER_AGENT = "Loon/860 CFNetwork/3826.500.111.2.2 Darwin/24.4.0"
WINDOWS_INVALID_FILENAME_CHARS = set('<>:"/\\|?*')
MIN_RETAINED_MODULE_RATIO = 0.8


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


def request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={
            "User-Agent": LOON_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh-Hans;q=0.9",
        },
    )


def download_bytes(url: str, attempts: int = 5) -> bytes:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request(url), timeout=60) as response:
                return response.read()
        except Exception as exc:  # noqa: BLE001 - retry transient network and TLS failures.
            last_error = exc
            if attempt == attempts:
                break
            time.sleep(min(2**attempt, 10))
    raise RuntimeError(f"Failed to download after {attempts} attempts: {last_error}") from last_error


def plugin_url(install_url: str) -> str:
    parsed = urllib.parse.urlparse(install_url)
    if parsed.scheme == "loon" and parsed.netloc == "import":
        query = urllib.parse.parse_qs(parsed.query)
        values = query.get("plugin")
        if values:
            return values[0]
    return install_url


def safe_filename_from_url(url: str, seen: dict[str, int]) -> str:
    parsed = urllib.parse.urlparse(url)
    name = urllib.parse.unquote(Path(parsed.path).name) or "module.lpx"
    name = "".join("_" if char in WINDOWS_INVALID_FILENAME_CHARS or ord(char) < 32 else char for char in name)

    if name not in seen:
        seen[name] = 1
        return name

    stem = Path(name).stem
    suffix = Path(name).suffix
    while True:
        seen[name] += 1
        candidate = f"{stem}-{seen[name]}{suffix}"
        if candidate not in seen:
            seen[candidate] = 1
            return candidate


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


def validate_plugin_list(
    data: object,
    previous_count: int,
    allow_large_drop: bool = False,
) -> list[dict[str, object]]:
    if not isinstance(data, dict) or not isinstance(data.get("lists"), list):
        raise RuntimeError("Kelee list.json must contain a lists array")

    plugins = data["lists"]
    if not plugins:
        raise RuntimeError("Kelee list.json contains no modules; refusing to replace the existing module tree")

    source_urls: set[str] = set()
    for index, plugin in enumerate(plugins, start=1):
        if not isinstance(plugin, dict) or not isinstance(plugin.get("url"), str) or not plugin["url"].strip():
            raise RuntimeError(f"Kelee list.json module {index} has no valid URL")
        source_url = plugin_url(plugin["url"].strip())
        parsed = urllib.parse.urlparse(source_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError(f"Kelee list.json module {index} resolves to an unsupported URL: {source_url}")
        normalized_url = parsed._replace(fragment="").geturl()
        if normalized_url in source_urls:
            raise RuntimeError(f"Kelee list.json contains a duplicate module URL: {normalized_url}")
        source_urls.add(normalized_url)

    if previous_count and not allow_large_drop:
        minimum_count = math.ceil(previous_count * MIN_RETAINED_MODULE_RATIO)
        if len(plugins) < minimum_count:
            raise RuntimeError(
                f"Kelee module count dropped from {previous_count} to {len(plugins)}, below the "
                f"{MIN_RETAINED_MODULE_RATIO:.0%} safety threshold; review upstream and rerun with "
                "--allow-large-drop if the removal is intentional"
            )
    return plugins


def fetch_kelee_modules(base_url: str, output_dir: str, allow_large_drop: bool = False) -> None:
    root = Path.cwd().resolve()
    output_root = root / output_dir
    raw_list_path = output_root / "list.json"
    index_path = output_root / "modules.index.json"

    temp_root = Path(tempfile.mkdtemp(prefix="loon_to_surge_kelee_fetch_"))
    temp_output_root = temp_root / "Loon"
    temp_raw_list_path = temp_output_root / "list.json"
    temp_index_path = temp_output_root / "modules.index.json"
    temp_output_root.mkdir(parents=True, exist_ok=True)

    try:
        list_url = f"{base_url.rstrip('/')}/list.json"
        raw_json = download_bytes(list_url)
        temp_raw_list_path.write_bytes(raw_json)

        data = json.loads(raw_json.decode("utf-8"))
        previous_count = sum(1 for _ in output_root.glob("*.lpx"))
        plugins = validate_plugin_list(data, previous_count, allow_large_drop)
        seen_names: dict[str, int] = {}
        index: list[dict[str, object]] = []
        failures: list[dict[str, object]] = []

        total = len(plugins)
        for current, plugin in enumerate(plugins, start=1):
            source_url = plugin_url(str(plugin.get("url", "")).strip())
            file_name = safe_filename_from_url(source_url, seen_names)
            target_path = temp_output_root / file_name
            print(f"Downloading {current}/{total}: {plugin.get('name', file_name)}")

            try:
                target_path.write_bytes(download_bytes(source_url))
                index.append(
                    {
                        "index": plugin.get("index"),
                        "name": plugin.get("name"),
                        "desc": plugin.get("desc"),
                        "tag": plugin.get("tag"),
                        "icon": plugin.get("icon"),
                        "date": plugin.get("date"),
                        "author": plugin.get("author"),
                        "install_url": plugin.get("url"),
                        "source_url": source_url,
                        "file": file_name,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - keep scraping and report all failures.
                failures.append(
                    {
                        "index": plugin.get("index"),
                        "name": plugin.get("name"),
                        "source_url": source_url,
                        "error": str(exc),
                    }
                )

        result = {
            "source": base_url,
            "fetched_at": "",
            "total": total,
            "downloaded": len(index),
            "failed": len(failures),
            "modules": index,
            "failures": failures,
        }
        content_unchanged = tree_contents_match(temp_output_root, output_root, {"modules.index.json"})
        index_unchanged = json_payload_matches(index_path, result, "fetched_at")
        if content_unchanged and index_unchanged:
            result["fetched_at"] = previous_timestamp(index_path, "fetched_at") or timestamp()
        else:
            result["fetched_at"] = timestamp()
        temp_index_path.write_text(json.dumps(result, ensure_ascii=False, indent=4), encoding="utf-8", newline="\n")

        if failures:
            print(f"Downloaded {len(index)} / {total} modules. Failed: {len(failures)}.")
            for failure in failures:
                print(f"- {failure['index']} {failure['name']}: {failure['error']}")
            raise SystemExit(1)

        replace_tree(temp_output_root, output_root, root)

        print(f"Downloaded {len(index)} / {total} modules.")
        print(f"Raw list: {raw_list_path}")
        print(f"Index: {index_path}")
        print(f"Modules: {output_root}")
    finally:
        if temp_root.exists():
            shutil.rmtree(temp_root)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch Loon modules from Kelee PluginHub.")
    parser.add_argument("--base-url", default="https://hub.kelee.one")
    parser.add_argument("--output-dir", default="Loon")
    parser.add_argument("--allow-large-drop", action="store_true")
    args = parser.parse_args()
    fetch_kelee_modules(args.base_url, args.output_dir, args.allow_large_drop)


if __name__ == "__main__":
    main()
