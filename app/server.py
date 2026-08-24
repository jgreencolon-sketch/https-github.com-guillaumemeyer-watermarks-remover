"""Small standard-library HTTP service for deterministic image metadata cleaning."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .cleaner import CleanerError, clean_file, inspect_file


HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8765"))
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(70 * 1024 * 1024)))
API_KEY = os.getenv("WATERMARKS_SERVER_API_KEY", "")


def inspection_report(items):
    metadata = [item.as_dict() for item in items]
    return {
        "suspicious": bool(metadata),
        "confidence": "confirmed" if metadata else "informational",
        "metadata": metadata,
        "metadata_count": len(metadata),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "RemoveAIMarks/1.0"

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}", flush=True)

    def do_GET(self):
        if not self._authorized():
            return
        if self.path == "/health":
            self._json(200, {"ok": True, "version": __version__})
            return
        if self.path == "/capabilities":
            self._json(
                200,
                {
                    "ok": True,
                    "version": __version__,
                    "formats": ["png", "jpeg", "webp"],
                    "container_metadata_cleaning": True,
                    "official_vendor_detection": False,
                    "c2pa_soft_binding": False,
                    "pixel_backends": {},
                    "scorers": {},
                },
            )
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        if self.path not in {"/inspect", "/clean"}:
            self._json(404, {"ok": False, "error": "not found"})
            return
        try:
            payload = self._read_json()
            name = payload.get("name")
            encoded = payload.get("file")
            if not isinstance(name, str) or not name:
                raise CleanerError("name must be a non-empty string")
            if not isinstance(encoded, str) or not encoded:
                raise CleanerError("file must be a non-empty base64 string")
            try:
                file_bytes = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise CleanerError("file is not valid base64") from exc
            if self.path == "/inspect":
                kind, items = inspect_file(name, file_bytes)
                report = inspection_report(items)
                self._json(
                    200,
                    {
                        "ok": True,
                        "kind": kind,
                        "suspicious": report["suspicious"],
                        "report": report,
                    },
                )
                return

            options = payload.get("options") or {}
            if not isinstance(options, dict):
                raise CleanerError("options must be an object")
            if options.get("remove_pixel"):
                self._json(
                    422,
                    {
                        "ok": False,
                        "error": "pixel-domain removal is not configured",
                    },
                )
                return
            kind, cleaned, removed = clean_file(
                name,
                file_bytes,
                keep_non_ai_metadata=bool(options.get("keep_non_ai_metadata")),
            )
            _post_kind, remaining = inspect_file(name, cleaned)
            self._json(
                200,
                {
                    "ok": True,
                    "kind": kind,
                    "cleaned": base64.b64encode(cleaned).decode("ascii"),
                    "report": {
                        "removed": [item.as_dict() for item in removed],
                        "removed_count": len(removed),
                        "removed_payload_bytes": sum(item.bytes for item in removed),
                        "input_sha256": hashlib.sha256(file_bytes).hexdigest(),
                        "output_sha256": hashlib.sha256(cleaned).hexdigest(),
                        "input_bytes": len(file_bytes),
                        "output_bytes": len(cleaned),
                        "post_inspection": inspection_report(remaining),
                    },
                },
            )
        except CleanerError as exc:
            self._json(400, {"ok": False, "error": str(exc)})
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid JSON"})
        except Exception:
            self._json(500, {"ok": False, "error": "internal server error"})

    def _authorized(self):
        if not API_KEY:
            return True
        expected = f"Bearer {API_KEY}"
        provided = self.headers.get("Authorization", "")
        if hmac.compare_digest(provided, expected):
            return True
        self._json(401, {"ok": False, "error": "unauthorized"})
        return False

    def _read_json(self):
        content_length = self.headers.get("Content-Length")
        if content_length is None:
            raise CleanerError("Content-Length is required")
        length = int(content_length)
        if length < 1 or length > MAX_BODY_BYTES:
            raise CleanerError("request body is empty or too large")
        return json.loads(self.rfile.read(length))

    def _json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"remove-ai-marks service listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
