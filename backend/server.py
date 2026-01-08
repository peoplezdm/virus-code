from __future__ import annotations

import json
import mimetypes
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional

from avscan_core import (
    OUT_DIR,
    PROJECT_ROOT,
    UserFacingError,
    evaluate_binary_detection,
    run_sigma_scan_with_zircolite,
    run_yara_scan,
)


FRONTEND_DIR = PROJECT_ROOT / "frontend"


_JOBS_LOCK = threading.Lock()
_JOBS: Dict[str, Dict[str, Any]] = {}


def _now_ts() -> float:
    return time.time()


def _new_job(kind: str) -> Dict[str, Any]:
    job_id = uuid.uuid4().hex
    job = {
        "id": job_id,
        "kind": kind,
        "status": "queued",  # queued|running|succeeded|failed
        "created_at": _now_ts(),
        "started_at": None,
        "finished_at": None,
        "current": {"stage": None, "message": None, "progress": None},
        "logs": [],
        "result": None,
        "error": None,
    }
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    return job


def _job_log(job_id: str, message: str) -> None:
    entry = {"ts": _now_ts(), "message": str(message)}
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["logs"].append(entry)


def _job_update(
    job_id: str,
    *,
    stage: Optional[str] = None,
    message: Optional[str] = None,
    progress: Optional[int] = None,
) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        cur = job.get("current") or {}
        if stage is not None:
            cur["stage"] = stage
        if message is not None:
            cur["message"] = message
        if progress is not None:
            cur["progress"] = int(progress)
        job["current"] = cur


def _job_start(job_id: str) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["started_at"] = _now_ts()


def _job_finish_success(job_id: str, result: Dict[str, Any]) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["status"] = "succeeded"
        job["finished_at"] = _now_ts()
        job["result"] = result


def _job_finish_error(job_id: str, error: str) -> None:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return
        job["status"] = "failed"
        job["finished_at"] = _now_ts()
        job["error"] = str(error)


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
    try:
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
        # Client disconnected while we were responding.
        return


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
    try:
        handler.wfile.write(data)
    except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, OSError):
        return True
    return True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        if self.path.startswith("/api/jobs/"):
            job_id = self.path[len("/api/jobs/") :].strip().strip("/")
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                payload = json.loads(json.dumps(job)) if job else None
            if not payload:
                _json_response(self, 404, {"error": "Not Found"})
                return
            _json_response(self, 200, payload)
            return

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
                job = _new_job("scan-files")

                def worker() -> None:
                    _job_start(job["id"])
                    _job_log(job["id"], "任务开始：文件扫描（YARA）")
                    try:
                        result = run_yara_scan(
                            target=str(body.get("target") or ""),
                            yara_rules_dir=body.get("yara_rules_dir"),
                            out_path=body.get("out_path"),
                            threads=int(body.get("threads") or 4),
                            progress_cb=lambda stage, message, percent: (
                                _job_update(job["id"], stage=stage, message=message, progress=percent),
                                _job_log(job["id"], message),
                            ),
                        )
                        _job_finish_success(job["id"], result)
                        _job_log(job["id"], "任务完成：文件扫描（YARA）")
                    except Exception as e:
                        _job_finish_error(job["id"], str(e))
                        _job_log(job["id"], f"任务失败：{e}")

                threading.Thread(target=worker, daemon=True).start()
                _json_response(self, 202, {"job_id": job["id"], "status_url": f"/api/jobs/{job['id']}"})
                return

            if self.path == "/api/scan-logs":
                body = _read_json_body(self)
                job = _new_job("scan-logs")

                def worker() -> None:
                    _job_start(job["id"])
                    _job_log(job["id"], "任务开始：日志扫描（Sigma/Zircolite）")
                    try:
                        result = run_sigma_scan_with_zircolite(
                            events_path=str(body.get("events_path") or ""),
                            sigma_rules_dir=body.get("sigma_rules_dir"),
                            out_path=body.get("out_path"),
                            max_events=int(body.get("max_events") or 0),
                            progress_cb=lambda stage, message, percent: (
                                _job_update(job["id"], stage=stage, message=message, progress=percent),
                                _job_log(job["id"], message),
                            ),
                        )
                        _job_finish_success(job["id"], result)
                        _job_log(job["id"], "任务完成：日志扫描（Sigma/Zircolite）")
                    except Exception as e:
                        _job_finish_error(job["id"], str(e))
                        _job_log(job["id"], f"任务失败：{e}")

                threading.Thread(target=worker, daemon=True).start()
                _json_response(self, 202, {"job_id": job["id"], "status_url": f"/api/jobs/{job['id']}"})
                return

            if self.path == "/api/evaluate":
                body = _read_json_body(self)
                job = _new_job("evaluate")

                def worker() -> None:
                    _job_start(job["id"])
                    _job_log(job["id"], "任务开始：指标评测（evaluate）")
                    try:
                        result = evaluate_binary_detection(
                            truth_csv=str(body.get("truth_csv") or ""),
                            scan_json=str(body.get("scan_json") or ""),
                            out_path=body.get("out_path"),
                            progress_cb=lambda stage, message, percent: (
                                _job_update(job["id"], stage=stage, message=message, progress=percent),
                                _job_log(job["id"], message),
                            ),
                        )
                        _job_finish_success(job["id"], result)
                        _job_log(job["id"], "任务完成：指标评测（evaluate）")
                    except Exception as e:
                        _job_finish_error(job["id"], str(e))
                        _job_log(job["id"], f"任务失败：{e}")

                threading.Thread(target=worker, daemon=True).start()
                _json_response(self, 202, {"job_id": job["id"], "status_url": f"/api/jobs/{job['id']}"})
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
