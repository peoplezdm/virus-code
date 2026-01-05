from __future__ import annotations

import argparse
from pathlib import Path

from .evaluate import evaluate_from_scan
from .scan_files import scan_files
from .scan_logs import scan_logs
from .utils import ensure_parent_dir
from .webapp import create_app


def _repo_root() -> Path:
    # backend/src/avscan/cli.py -> repo_root = parents[3]
    return Path(__file__).resolve().parents[3]


def build_parser() -> argparse.ArgumentParser:
    repo_root = _repo_root()

    parser = argparse.ArgumentParser(
        prog="avscan",
        description="Course project scanner: YARA (files) + Sigma (logs)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("scan-files", help="Scan files/directories with YARA rules")
    p1.add_argument("--target", required=True, help="File or directory to scan")
    p1.add_argument(
        "--yara-rules",
        default=str(repo_root / "rules" / "yara"),
        help="YARA rules dir (default: repo_root/rules/yara)",
    )
    p1.add_argument(
        "--out",
        default=str(repo_root / "out" / "scan_files.json"),
        help="Output JSON path (default: repo_root/out/scan_files.json)",
    )
    p1.add_argument("--threads", type=int, default=4, help="Worker threads")

    p2 = sub.add_parser("scan-logs", help="Scan events (JSON/JSONL) with Sigma rules")
    p2.add_argument("--events", required=True, help="Events file: .json or .jsonl")
    p2.add_argument(
        "--sigma-rules",
        default=str(repo_root / "rules" / "sigma"),
        help="Sigma rules dir (default: repo_root/rules/sigma)",
    )
    p2.add_argument(
        "--out",
        default=str(repo_root / "out" / "scan_logs.json"),
        help="Output JSON path (default: repo_root/out/scan_logs.json)",
    )
    p2.add_argument("--max-events", type=int, default=0, help="0 means unlimited")

    p3 = sub.add_parser("evaluate", help="Compute metrics (accuracy/FPR/FNR/...) from scan results")
    p3.add_argument("--truth", required=True, help="Ground truth CSV")
    p3.add_argument("--scan-json", required=True, help="Scan output JSON (from scan-files or scan-logs)")
    p3.add_argument(
        "--out",
        default=str(repo_root / "out" / "metrics.json"),
        help="Output metrics JSON path (default: repo_root/out/metrics.json)",
    )

    p4 = sub.add_parser("serve", help="Run web UI + API server")
    p4.add_argument("--host", default="127.0.0.1", help="Bind host")
    p4.add_argument("--port", type=int, default=8000, help="Bind port")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "scan-files":
        out_path = Path(args.out)
        ensure_parent_dir(out_path)
        scan_files(
            target=Path(args.target),
            yara_rules_dir=Path(args.yara_rules),
            out_path=out_path,
            threads=args.threads,
        )
        return 0

    if args.cmd == "scan-logs":
        out_path = Path(args.out)
        ensure_parent_dir(out_path)
        scan_logs(
            events_path=Path(args.events),
            sigma_rules_dir=Path(args.sigma_rules),
            out_path=out_path,
            max_events=args.max_events,
        )
        return 0

    if args.cmd == "evaluate":
        out_path = Path(args.out)
        ensure_parent_dir(out_path)
        evaluate_from_scan(
            truth_csv=Path(args.truth),
            scan_json=Path(args.scan_json),
            out_path=out_path,
        )
        return 0

    if args.cmd == "serve":
        import uvicorn

        app = create_app()
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    parser.error("unknown command")
    return 2
