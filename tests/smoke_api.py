"""Smoke-test a running service through its public HTTP API."""

import base64
import binascii
import json
import os
import struct
import urllib.request
import zlib


SERVICE_URL = os.getenv("SERVICE_URL", "http://127.0.0.1:8765")


def png_chunk(chunk_type, payload):
    crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def marked_png():
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    provenance = png_chunk(b"caBX", b"c2pa container smoke test")
    pixels = png_chunk(b"IDAT", zlib.compress(b"\x00\x20\x80\xff"))
    iend = png_chunk(b"IEND", b"")
    return signature + ihdr + provenance + pixels + iend


def post(endpoint, payload):
    request = urllib.request.Request(
        f"{SERVICE_URL}{endpoint}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def main():
    original = marked_png()
    payload = {
        "name": "smoke.png",
        "file": base64.b64encode(original).decode("ascii"),
    }
    inspection = post("/inspect", payload)
    assert inspection["ok"] is True
    assert inspection["report"]["metadata_count"] == 1
    assert inspection["report"]["metadata"][0]["type"] == "caBX"

    result = post("/clean", payload)
    assert result["ok"] is True
    assert result["report"]["removed_count"] == 1
    assert result["report"]["post_inspection"]["metadata_count"] == 0
    cleaned = base64.b64decode(result["cleaned"])
    assert b"caBX" not in cleaned
    assert b"IDAT" in cleaned
    print("Docker API smoke test passed: caBX removed and pixels preserved.")


if __name__ == "__main__":
    main()
