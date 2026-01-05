from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .sigma_engine import SigmaEngine, SigmaHit
from .utils import write_json


@dataclass
class LogScanFinding:
    event_index: int
    rule_id: str | None
    title: str
    level: str | None


@dataclass
class LogScanResult:
    scanned_at: str
    events_path: str
    engine: str
    rules_dir: str
    total_events: int
    matched_events: int
    findings: list[LogScanFinding]


def scan_logs(
    events_path: Path,
    sigma_rules_dir: Path,
    out_path: Path,
    max_events: int = 0,
) -> None:
    engine = SigmaEngine.from_rules_dir(sigma_rules_dir)

    hits: list[SigmaHit] = []
    total = 0
    for idx, event in engine.iter_events(events_path):
        total += 1
        if max_events and total > max_events:
            break
        hits.extend(engine.match_event(idx, event))

    findings = [
        LogScanFinding(
            event_index=h.event_index,
            rule_id=h.rule_id,
            title=h.title,
            level=h.level,
        )
        for h in hits
    ]

    matched_events = len({f.event_index for f in findings})

    result = LogScanResult(
        scanned_at=datetime.now(timezone.utc).isoformat(),
        events_path=str(events_path),
        engine="sigma-minimal",
        rules_dir=str(sigma_rules_dir),
        total_events=total,
        matched_events=matched_events,
        findings=findings,
    )
    write_json(out_path, asdict(result))
