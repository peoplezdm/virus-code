from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yara


@dataclass(frozen=True)
class YaraMatch:
    rule: str
    namespace: str | None
    tags: list[str]


class YaraEngine:
    def __init__(self, rules: yara.Rules):
        self._rules = rules

    @staticmethod
    def from_rules_dir(rules_dir: Path) -> "YaraEngine":
        if not rules_dir.exists():
            raise FileNotFoundError(f"YARA rules dir not found: {rules_dir}")

        rule_files = sorted(
            [p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".yar", ".yara"}]
        )
        if not rule_files:
            raise FileNotFoundError(f"No .yar/.yara files found in: {rules_dir}")

        filepaths: dict[str, str] = {}
        for idx, p in enumerate(rule_files):
            filepaths[f"r{idx}_{p.stem}"] = str(p)

        rules = yara.compile(filepaths=filepaths)
        return YaraEngine(rules)

    def scan_file(self, path: Path) -> list[YaraMatch]:
        try:
            matches = self._rules.match(str(path))
        except yara.Error:
            return []

        out: list[YaraMatch] = []
        for m in matches:
            out.append(YaraMatch(rule=m.rule, namespace=m.namespace, tags=list(m.tags)))
        return out
