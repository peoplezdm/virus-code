from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return
    for path in target.rglob("*"):
        if path.is_file():
            yield path


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
