from __future__ import annotations

import json
import urllib.request


CURRENT_VERSION = "0.2.9"
URL = "https://pypi.org/pypi/vulnclaw/json"


def main() -> None:
    with urllib.request.urlopen(URL, timeout=15) as response:
        data = json.load(response)
    latest = str(data["info"]["version"])
    print(f"vendored={CURRENT_VERSION} latest={latest}")
    if latest != CURRENT_VERSION:
        print("A newer release exists. Review it manually before vendoring.")


if __name__ == "__main__":
    main()
