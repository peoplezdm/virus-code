from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import iter_files, write_json
from .yara_engine import YaraEngine, YaraMatch


@dataclass
class FileScanFinding:
    file: str
    rule: str
    namespace: str | None
    tags: list[str]


@dataclass
class FileScanResult:
    scanned_at: str
    target: str
    engine: str
    rules_dir: str
    total_files: int
    infected_files: int
    findings: list[FileScanFinding]


def scan_files(target: Path, yara_rules_dir: Path, out_path: Path, threads: int = 4) -> None:
    engine = YaraEngine.from_rules_dir(yara_rules_dir)

    all_files = list(iter_files(target))
    findings: list[FileScanFinding] = []

    def scan_one(path: Path) -> list[FileScanFinding]:
        matches: list[YaraMatch] = engine.scan_file(path)
        out: list[FileScanFinding] = []
        for m in matches:
            out.append(
                FileScanFinding(
                    file=str(path),
                    rule=m.rule,
                    namespace=m.namespace,
                    tags=m.tags,
                )
            )
        return out

    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        futures = {ex.submit(scan_one, p): p for p in all_files}
        for fut in as_completed(futures):
            findings.extend(fut.result())

    infected = {f.file for f in findings}

    result = FileScanResult(
        scanned_at=datetime.now(timezone.utc).isoformat(),
        target=str(target),
        engine="yara-python",
        rules_dir=str(yara_rules_dir),
        total_files=len(all_files),
        infected_files=len(infected),
        findings=findings,
    )

    write_json(out_path, asdict(result))
