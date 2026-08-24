"""Send one image to a running remove-ai-marks service and save verified output."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import urllib.request


def post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--service-url", default="http://127.0.0.1:8765")
    args = parser.parse_args()

    original = args.input.read_bytes()
    payload = {
        "name": args.input.name,
        "file": base64.b64encode(original).decode("ascii"),
    }

    inspection = post_json(f"{args.service_url}/inspect", payload)
    if not inspection.get("ok"):
        raise RuntimeError(f"inspection failed: {inspection}")

    result = post_json(f"{args.service_url}/clean", payload)
    if not result.get("ok"):
        raise RuntimeError(f"cleaning failed: {result}")

    cleaned = base64.b64decode(result.pop("cleaned"), validate=True)
    post_inspection = result.get("report", {}).get("post_inspection", {})
    if post_inspection.get("metadata_count") != 0:
        raise RuntimeError(f"post-inspection still found metadata: {post_inspection}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(cleaned)
    args.report.write_text(
        json.dumps(
            {
                "input_inspection": inspection,
                "clean_result": result,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
