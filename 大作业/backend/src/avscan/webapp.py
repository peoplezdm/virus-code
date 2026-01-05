from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .evaluate import evaluate_from_scan
from .scan_files import scan_files
from .scan_logs import scan_logs


def _repo_root() -> Path:
    # backend/src/avscan/webapp.py -> repo_root = parents[3]
    return Path(__file__).resolve().parents[3]


class ScanFilesRequest(BaseModel):
    target: str = Field(..., description="File or directory path")
    yara_rules_dir: str | None = None
    out_path: str | None = None
    threads: int = 4


class ScanLogsRequest(BaseModel):
    events_path: str = Field(..., description=".json or .jsonl events file")
    sigma_rules_dir: str | None = None
    out_path: str | None = None
    max_events: int = 0


class EvaluateRequest(BaseModel):
    truth_csv: str
    scan_json: str
    out_path: str | None = None


def create_app() -> FastAPI:
    repo_root = _repo_root()
    app = FastAPI(title="avscan", version="0.1.0")

    frontend_dir = repo_root / "frontend"
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/scan-files")
    def api_scan_files(req: ScanFilesRequest) -> Any:
        target = Path(req.target)
        yara_rules_dir = Path(req.yara_rules_dir) if req.yara_rules_dir else (repo_root / "rules" / "yara")
        out_path = Path(req.out_path) if req.out_path else (repo_root / "out" / "scan_files.json")

        try:
            scan_files(target=target, yara_rules_dir=yara_rules_dir, out_path=out_path, threads=req.threads)
        except FileNotFoundError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"scan-files failed: {e}")

        data = out_path.read_text(encoding="utf-8")
        return JSONResponse(content=_json_loads_safe(data))

    @app.post("/api/scan-logs")
    def api_scan_logs(req: ScanLogsRequest) -> Any:
        events_path = Path(req.events_path)
        sigma_rules_dir = Path(req.sigma_rules_dir) if req.sigma_rules_dir else (repo_root / "rules" / "sigma")
        out_path = Path(req.out_path) if req.out_path else (repo_root / "out" / "scan_logs.json")

        try:
            scan_logs(
                events_path=events_path,
                sigma_rules_dir=sigma_rules_dir,
                out_path=out_path,
                max_events=req.max_events,
            )
        except (FileNotFoundError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"scan-logs failed: {e}")

        data = out_path.read_text(encoding="utf-8")
        return JSONResponse(content=_json_loads_safe(data))

    @app.post("/api/evaluate")
    def api_evaluate(req: EvaluateRequest) -> Any:
        truth_csv = Path(req.truth_csv)
        scan_json = Path(req.scan_json)
        out_path = Path(req.out_path) if req.out_path else (repo_root / "out" / "metrics.json")

        try:
            evaluate_from_scan(truth_csv=truth_csv, scan_json=scan_json, out_path=out_path)
        except (FileNotFoundError, ValueError) as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"evaluate failed: {e}")

        data = out_path.read_text(encoding="utf-8")
        return JSONResponse(content=_json_loads_safe(data))

    return app


def _json_loads_safe(text: str) -> Any:
    import json

    return json.loads(text)
