from __future__ import annotations

import json
import mimetypes
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict

from avscan_core import (
    OUT_DIR,
    PROJECT_ROOT,
    UserFacingError,
    evaluate_binary_detection,
    run_sigma_scan_with_zircolite,
    run_yara_scan,
)


FRONTEND_DIR = PROJECT_ROOT / "frontend"


def _read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        if isinstance(data, dict):
            return data
        raise ValueError("JSON body must be an object")
    except Exception as e:
        raise UserFacingError(f"无效 JSON 请求体: {e}")


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _serve_static(handler: BaseHTTPRequestHandler, rel_path: str) -> bool:
    if rel_path in {"", "/"}:
        file_path = FRONTEND_DIR / "index.html"
    else:
        rel = rel_path.lstrip("/")
        if ".." in Path(rel).parts:
            return False
        file_path = FRONTEND_DIR / rel

    if not file_path.is_file():
        return False

    ctype, _ = mimetypes.guess_type(str(file_path))
    ctype = ctype or "application/octet-stream"
    data = file_path.read_bytes()

    handler.send_response(200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)
    return True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            _json_response(self, 405, {"error": "Method Not Allowed"})
            return

        if _serve_static(self, self.path):
            return

        _json_response(self, 404, {"error": "Not Found"})

    def do_POST(self) -> None:
        try:
            if self.path == "/api/scan-files":
                body = _read_json_body(self)
                result = run_yara_scan(
                    target=str(body.get("target") or ""),
                    yara_rules_dir=body.get("yara_rules_dir"),
                    out_path=body.get("out_path"),
                    threads=int(body.get("threads") or 4),
                )
                _json_response(self, 200, result)
                return

            if self.path == "/api/scan-logs":
                body = _read_json_body(self)
                result = run_sigma_scan_with_zircolite(
                    events_path=str(body.get("events_path") or ""),
                    sigma_rules_dir=body.get("sigma_rules_dir"),
                    out_path=body.get("out_path"),
                    max_events=int(body.get("max_events") or 0),
                )
                _json_response(self, 200, result)
                return

            if self.path == "/api/evaluate":
                body = _read_json_body(self)
                result = evaluate_binary_detection(
                    truth_csv=str(body.get("truth_csv") or ""),
                    scan_json=str(body.get("scan_json") or ""),
                    out_path=body.get("out_path"),
                )
                _json_response(self, 200, result)
                return

            _json_response(self, 404, {"error": "Not Found"})

        except UserFacingError as e:
            _json_response(self, 400, {"error": str(e)})
        except Exception:
            _json_response(self, 500, {"error": "Internal Server Error", "detail": traceback.format_exc()})


def main() -> None:
    host = "127.0.0.1"
    port = 8000
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"avscan backend listening on http://{host}:{port}")
    print("Static frontend: /")
    print("API: POST /api/scan-files  /api/scan-logs  /api/evaluate")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
