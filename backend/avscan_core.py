from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import locale
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
OUT_DIR = PROJECT_ROOT / "out"


class UserFacingError(RuntimeError):
    pass


_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _decode_cli_bytes(data: bytes) -> str:
    if not data:
        return ""

    # Prefer UTF-8 when possible, but fall back to the OS preferred encoding
    # (e.g. cp936/gbk on many Chinese Windows machines) for readable Chinese output.
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        enc = locale.getpreferredencoding(False) or "utf-8"
        return data.decode(enc, errors="replace")


def _strip_ansi(s: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", s or "")


def resolve_user_path(path_str: str, *, base_dir: Path = PROJECT_ROOT) -> Path:
    if not path_str:
        raise UserFacingError("路径不能为空")

    # Users often paste Windows paths wrapped in quotes.
    s = str(path_str).strip()
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    s = s.strip('"').strip("'").strip()

    p = Path(s)
    return p if p.is_absolute() else (base_dir / p).resolve()


def ensure_parent_dir(file_path: Path) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)


def _collect_yara_rule_files(rules_dir: Path) -> List[Path]:
    exts = {".yar", ".yara", ".rule"}
    if rules_dir.is_file():
        return [rules_dir]
    if not rules_dir.exists():
        raise UserFacingError(f"规则路径不存在: {rules_dir}")
    if not rules_dir.is_dir():
        raise UserFacingError(f"规则路径不是目录或文件: {rules_dir}")

    files: List[Path] = []
    for p in rules_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in exts:
            files.append(p)
    files.sort()
    return files


def _write_yara_merged_rules(rule_files: List[Path]) -> Path:
    if not rule_files:
        raise UserFacingError("YARA 规则目录为空：未找到 .yar/.yara/.rule")

    tmp_dir = Path(tempfile.mkdtemp(prefix="avscan_yara_"))
    bundle_path = tmp_dir / "all_rules_merged.yar"

    # NOTE: On Windows, yara.exe may fail to open include files when the include path
    # contains non-ASCII characters (e.g. Chinese). To avoid this, concatenate all rule
    # contents into a single temporary ruleset file (no includes).
    parts: List[str] = []
    for p in rule_files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = p.read_text(errors="replace")

        parts.append(f"\n// ---- BEGIN {p.name} ----\n")
        parts.append(text)
        if not text.endswith("\n"):
            parts.append("\n")
        parts.append(f"// ---- END {p.name} ----\n")

    bundle_path.write_text("".join(parts), encoding="utf-8")
    return bundle_path


def run_yara_scan(
    *,
    target: str,
    yara_rules_dir: Optional[str] = None,
    out_path: Optional[str] = None,
    threads: int = 4,
) -> Dict[str, Any]:
    yara_exe = BACKEND_DIR / "yara64.exe"
    if not yara_exe.is_file():
        raise UserFacingError(f"找不到 YARA 可执行文件: {yara_exe}")

    target_path = resolve_user_path(target)
    if not target_path.exists():
        raise UserFacingError(f"目标路径不存在: {target_path}")

    rules_dir = (
        resolve_user_path(yara_rules_dir, base_dir=PROJECT_ROOT)
        if yara_rules_dir
        else (PROJECT_ROOT / "rules" / "yara")
    )

    rule_files = _collect_yara_rule_files(rules_dir)
    merged_rules = _write_yara_merged_rules(rule_files)

    threads_i = int(threads) if threads else 4
    if threads_i < 1:
        threads_i = 1

    cmd: List[str] = [str(yara_exe), "-p", str(threads_i)]
    if target_path.is_dir():
        cmd.append("-r")
    cmd.extend([str(merged_rules), str(target_path)])

    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")

    if proc.returncode != 0:
        raise UserFacingError(
            f"YARA 执行失败(退出码 {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )

    detections_by_file: Dict[str, List[str]] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        rule, fpath = parts
        detections_by_file.setdefault(fpath, []).append(rule)

    result: Dict[str, Any] = {
        "engine": "yara",
        "engine_path": str(yara_exe),
        "target": str(target_path),
        "rules_dir": str(rules_dir),
        "rules_count": len(rule_files),
        "threads": threads_i,
        "hits_files": len(detections_by_file),
        "hits_total": sum(len(v) for v in detections_by_file.values()),
        "detections": detections_by_file,
    }

    out_file = resolve_user_path(out_path, base_dir=PROJECT_ROOT) if out_path else (OUT_DIR / "scan_files.json")
    ensure_parent_dir(out_file)
    out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    result["out_path"] = str(out_file)
    return result


def _detect_zircolite_input_mode(events_file: Path) -> str:
    suffix = events_file.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"

    if suffix == ".json":
        try:
            with events_file.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(50):
                    ch = f.read(1)
                    if not ch:
                        break
                    if ch.isspace():
                        continue
                    if ch == "[":
                        return "json_array"
                    if ch == "{":
                        return "jsonl"
                    break
        except Exception:
            return "jsonl"

    return "jsonl"


def _truncate_events_if_needed(events_path: Path, *, max_events: int) -> Tuple[Path, bool]:
    if max_events <= 0:
        return events_path, False

    mode = _detect_zircolite_input_mode(events_path)
    tmp_dir = Path(tempfile.mkdtemp(prefix="avscan_events_"))
    out_file = tmp_dir / events_path.name

    if mode == "json_array":
        data = json.loads(events_path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, list):
            data = data[:max_events]
        out_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return out_file, True

    kept = 0
    with events_path.open("r", encoding="utf-8", errors="replace") as src, out_file.open("w", encoding="utf-8") as dst:
        for line in src:
            if not line.strip():
                continue
            dst.write(line)
            kept += 1
            if kept >= max_events:
                break
    return out_file, True


def run_sigma_scan_with_zircolite(
    *,
    events_path: str,
    sigma_rules_dir: Optional[str] = None,
    out_path: Optional[str] = None,
    max_events: int = 0,
) -> Dict[str, Any]:
    zir_dir = BACKEND_DIR / "Zircolite-master"
    zir_py = zir_dir / "zircolite.py"
    if not zir_py.is_file():
        raise UserFacingError(f"找不到 Zircolite 入口脚本: {zir_py}")

    events_file = resolve_user_path(events_path)
    if not events_file.exists():
        raise UserFacingError(f"事件文件不存在: {events_file}")

    rules_path = (
        resolve_user_path(sigma_rules_dir, base_dir=PROJECT_ROOT)
        if sigma_rules_dir
        else (PROJECT_ROOT / "rules" / "sigma")
    )
    if not rules_path.exists():
        raise UserFacingError(f"Sigma 规则目录不存在: {rules_path}")

    out_file = resolve_user_path(out_path, base_dir=PROJECT_ROOT) if out_path else (OUT_DIR / "scan_logs.json")
    ensure_parent_dir(out_file)

    python_exe = os.environ.get("PYTHON") or sys.executable

    # Zircolite supports multiple input formats. For EVTX, do NOT pass JSON flags.
    # Otherwise Zircolite will try to parse the binary EVTX as JSON and fail.
    if events_file.suffix.lower() == ".evtx":
        input_mode = "evtx"
        truncated_events_file = events_file
        truncated = False
        cmd = [
            python_exe,
            str(zir_py),
            "--events",
            str(events_file),
            "--ruleset",
            str(rules_path),
            "--pipeline",
            "sysmon",
            "-o",
            str(out_file),
        ]
    else:
        max_events_i = int(max_events) if max_events else 0
        truncated_events_file, truncated = _truncate_events_if_needed(events_file, max_events=max_events_i)

        input_mode = _detect_zircolite_input_mode(truncated_events_file)
        input_flag = "--jsonl" if input_mode == "jsonl" else "--json-array-input"

        cmd = [
            python_exe,
            str(zir_py),
            "--events",
            str(truncated_events_file),
            "--ruleset",
            str(rules_path),
            input_flag,
            "-o",
            str(out_file),
        ]

    proc = subprocess.run(cmd, cwd=str(zir_dir), capture_output=True)

    stdout_text = _strip_ansi(_decode_cli_bytes(proc.stdout))
    stderr_text = _strip_ansi(_decode_cli_bytes(proc.stderr))

    if proc.returncode != 0:
        msg = (stderr_text.strip() or stdout_text.strip())
        msg_l = msg.lower()
        if "unicodedecodeerror" in msg_l or "codec can't decode" in msg_l:
            raise UserFacingError(
                "Zircolite 读取事件文件时发生编码错误（UnicodeDecodeError）。\n"
                "请确保输入的 .json/.jsonl 为 UTF-8 编码；若文件来自 EVTX 转换，建议重新导出为 UTF-8。\n"
                f"退出码 {proc.returncode}: {msg}"
            )

        raise UserFacingError(
            "Zircolite 执行失败。常见原因：未安装 Zircolite 依赖（需要 pip 安装 requirements.txt）。\n"
            f"退出码 {proc.returncode}: {msg}"
        )

    hits = None
    try:
        if out_file.is_file():
            content = out_file.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("["):
                parsed = json.loads(content)
                if isinstance(parsed, list):
                    hits = len(parsed)
    except Exception:
        hits = None

    return {
        "engine": "zircolite",
        "engine_path": str(zir_py),
        "events_path": str(events_file),
        "events_used": str(truncated_events_file),
        "events_truncated": truncated,
        "rules_dir": str(rules_path),
        "input_mode": input_mode,
        "out_path": str(out_file),
        "hits": hits,
        "stdout_tail": "\n".join(stdout_text.splitlines()[-40:]),
    }


def _normalize_truth_label(v: str) -> Optional[int]:
    s = (v or "").strip().lower()
    if s in {"1", "true", "yes", "y", "malicious", "malware", "bad"}:
        return 1
    if s in {"0", "false", "no", "n", "benign", "clean", "good"}:
        return 0
    return None


def _is_abs_path(p: str) -> bool:
    try:
        return Path(p).is_absolute()
    except Exception:
        return False


def evaluate_binary_detection(*, truth_csv: str, scan_json: str, out_path: Optional[str] = None) -> Dict[str, Any]:
    truth_path = resolve_user_path(truth_csv)
    scan_path = resolve_user_path(scan_json)
    if not truth_path.is_file():
        raise UserFacingError(f"truth.csv 不存在: {truth_path}")
    if not scan_path.is_file():
        raise UserFacingError(f"scan JSON 不存在: {scan_path}")

    scan = json.loads(scan_path.read_text(encoding="utf-8", errors="replace"))

    predicted: Dict[str, int] = {}
    if isinstance(scan, dict) and scan.get("engine") == "yara":
        detections = scan.get("detections") or {}
        if isinstance(detections, dict):
            for fpath, rules in detections.items():
                predicted[str(fpath)] = 1 if rules else 0
    else:
        raise UserFacingError("evaluate 目前只支持使用 /api/scan-files 生成的 YARA 扫描 JSON")

    tp = fp = tn = fn = 0
    skipped_rows = 0

    with truth_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise UserFacingError("truth.csv 缺少表头")

        def pick(row: Dict[str, str], keys: Iterable[str]) -> str:
            for k in keys:
                if k in row and row[k] is not None:
                    return str(row[k])
            return ""

        for row in reader:
            sample = pick(row, ["sample", "path", "file", "filepath", "filename"]).strip()
            label_raw = pick(row, ["label", "truth", "is_malicious", "malicious", "y"]).strip()
            label = _normalize_truth_label(label_raw)
            if not sample or label is None:
                skipped_rows += 1
                continue

            sample_path = str(resolve_user_path(sample)) if not _is_abs_path(sample) else str(Path(sample))
            pred = predicted.get(sample_path, 0)

            if label == 1 and pred == 1:
                tp += 1
            elif label == 0 and pred == 1:
                fp += 1
            elif label == 0 and pred == 0:
                tn += 1
            elif label == 1 and pred == 0:
                fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    result: Dict[str, Any] = {
        "truth_csv": str(truth_path),
        "scan_json": str(scan_path),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
        },
        "skipped_rows": skipped_rows,
    }

    out_file = resolve_user_path(out_path, base_dir=PROJECT_ROOT) if out_path else (OUT_DIR / "metrics.json")
    ensure_parent_dir(out_file)
    out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    result["out_path"] = str(out_file)
    return result
