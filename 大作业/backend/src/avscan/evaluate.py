from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path

from .utils import read_json, write_json


@dataclass
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float


def _safe_div(num: float, den: float) -> float:
    return float(num / den) if den else 0.0


def evaluate_from_scan(truth_csv: Path, scan_json: Path, out_path: Path) -> None:
    truth = _load_truth(truth_csv)
    scan = read_json(scan_json)

    detected = set()
    if isinstance(scan, dict) and isinstance(scan.get("findings"), list):
        for f in scan["findings"]:
            if isinstance(f, dict):
                if "file" in f:
                    detected.add(str(f["file"]))
                elif "event_index" in f:
                    detected.add(str(f["event_index"]))

    tp = sum(1 for k, y in truth.items() if y == 1 and k in detected)
    fn = sum(1 for k, y in truth.items() if y == 1 and k not in detected)
    fp = sum(1 for k, y in truth.items() if y == 0 and k in detected)
    tn = sum(1 for k, y in truth.items() if y == 0 and k not in detected)

    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)

    metrics = Metrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        fnr=fnr,
    )

    out = {
        "truth_count": len(truth),
        "detected_count": len(detected),
        "metrics": asdict(metrics),
    }
    write_json(out_path, out)


def _load_truth(path: Path) -> dict[str, int]:
    if not path.exists():
        raise FileNotFoundError(f"truth.csv not found: {path}")

    out: dict[str, int] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "key" not in reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("truth.csv must have headers: key,label")
        for row in reader:
            key = str(row["key"]).strip()
            label = int(str(row["label"]).strip())
            out[key] = 1 if label else 0
    return out
