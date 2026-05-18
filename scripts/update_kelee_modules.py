from __future__ import annotations

import argparse
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent))

from convert_kelee_to_surge import convert_kelee_to_surge  # noqa: E402
from fetch_kelee_modules import fetch_kelee_modules  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch latest Kelee modules and convert them to Surge modules.")
    parser.add_argument("--base-url", default="https://hub.kelee.one")
    parser.add_argument("--loon-dir", default="Loon")
    parser.add_argument("--surge-dir", default="Surge")
    parser.add_argument("--report-path", default="Surge/convert-report.json")
    args = parser.parse_args()

    fetch_kelee_modules(args.base_url, args.loon_dir)
    convert_kelee_to_surge(args.loon_dir, args.surge_dir, args.report_path)


if __name__ == "__main__":
    main()
