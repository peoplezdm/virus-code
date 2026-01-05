from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str | None
    title: str
    level: str | None
    detection: dict[str, Any]


@dataclass(frozen=True)
class SigmaHit:
    event_index: int
    rule_id: str | None
    title: str
    level: str | None


class SigmaEngine:
    """极简 Sigma 规则匹配器（满足课程最低要求的可运行子集）。"""

    def __init__(self, rules: list[SigmaRule]):
        self._rules = rules

    @staticmethod
    def from_rules_dir(rules_dir: Path) -> "SigmaEngine":
        if not rules_dir.exists():
            raise FileNotFoundError(f"Sigma rules dir not found: {rules_dir}")

        rule_files = sorted(
            [p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".yml", ".yaml"}]
        )
        if not rule_files:
            raise FileNotFoundError(f"No .yml/.yaml files found in: {rules_dir}")

        rules: list[SigmaRule] = []
        for p in rule_files:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                continue
            det = doc.get("detection")
            if not isinstance(det, dict):
                continue
            rules.append(
                SigmaRule(
                    rule_id=doc.get("id"),
                    title=str(doc.get("title", p.stem)),
                    level=doc.get("level"),
                    detection=det,
                )
            )

        return SigmaEngine(rules)

    def iter_events(self, events_path: Path) -> Iterable[tuple[int, dict[str, Any]]]:
        if not events_path.exists():
            raise FileNotFoundError(f"Events file not found: {events_path}")

        suf = events_path.suffix.lower()
        if suf == ".jsonl":
            with events_path.open("r", encoding="utf-8") as f:
                for idx, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    yield idx, json.loads(line)
            return

        if suf == ".json":
            data = json.loads(events_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for idx, ev in enumerate(data):
                    if isinstance(ev, dict):
                        yield idx, ev
                return
            if isinstance(data, dict):
                yield 0, data
                return

        raise ValueError("Events must be .jsonl or .json")

    def match_event(self, event_index: int, event: dict[str, Any]) -> list[SigmaHit]:
        hits: list[SigmaHit] = []
        for rule in self._rules:
            if self._match_rule(event, rule):
                hits.append(
                    SigmaHit(
                        event_index=event_index,
                        rule_id=rule.rule_id,
                        title=rule.title,
                        level=rule.level,
                    )
                )
        return hits

    def _match_rule(self, event: dict[str, Any], rule: SigmaRule) -> bool:
        det = rule.detection
        condition = det.get("condition")
        selectors = {k: v for k, v in det.items() if k != "condition"}
        if not selectors:
            return False

        def match_selector(sel: Any) -> bool:
            if not isinstance(sel, dict):
                return False
            for field, expected in sel.items():
                actual = event.get(field)
                if isinstance(expected, list):
                    if actual not in expected:
                        return False
                else:
                    if actual != expected:
                        return False
            return True

        if not condition:
            return any(match_selector(v) for v in selectors.values())

        tokens = str(condition).strip().split()
        if len(tokens) == 1:
            sel = selectors.get(tokens[0])
            return match_selector(sel)

        def eval_token(tok: str) -> bool:
            return match_selector(selectors.get(tok))

        cur: bool | None = None
        op: str | None = None
        for tok in tokens:
            low = tok.lower()
            if low in {"and", "or"}:
                op = low
                continue
            val = eval_token(tok)
            if cur is None:
                cur = val
            else:
                if op == "and":
                    cur = cur and val
                elif op == "or":
                    cur = cur or val
                else:
                    return False
        return bool(cur)
