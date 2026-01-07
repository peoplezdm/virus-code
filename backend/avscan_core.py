from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import tempfile
import locale
import threading
import time
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
OUT_DIR = PROJECT_ROOT / "out"


class UserFacingError(RuntimeError):
    pass


ProgressCallback = Callable[[str, str, Optional[int]], None]


def _progress(cb: Optional[ProgressCallback], stage: str, message: str, percent: Optional[int] = None) -> None:
    if cb is None:
        return
    try:
        cb(stage, message, percent)
    except Exception:
        # Progress reporting must never break the main workflow.
        return


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


_YARA_FATAL_RE = re.compile(r"(^|\n)\s*error:\s*", re.IGNORECASE)


def _yara_has_fatal_error(stderr_text: str) -> bool:
    return bool(_YARA_FATAL_RE.search(stderr_text or ""))


def _run_yara(
    cmd: List[str],
    *,
    cwd: Optional[Path] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def _summarize_yara_error(stderr_text: str, *, max_lines: int = 10) -> str:
    s = _strip_ansi(stderr_text or "").strip()
    if not s:
        return ""
    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    # Prefer the first few error lines.
    err_lines = [ln for ln in lines if ln.lower().startswith("error:")]
    picked = err_lines[:max_lines] if err_lines else lines[:max_lines]
    return "\n".join(picked)


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

    include_re = re.compile(r"^\s*include\s+(['\"])([^'\"]+)\1\s*$", re.IGNORECASE)

    def read_with_includes(file_path: Path, *, stack: List[Path], seen: set[str]) -> str:
        key = str(file_path.resolve())
        if key in seen:
            return ""
        if key in {str(p.resolve()) for p in stack}:
            cycle = " -> ".join([p.name for p in stack] + [file_path.name])
            raise UserFacingError(f"YARA include 发生循环引用: {cycle}")
        if not file_path.is_file():
            raise UserFacingError(f"YARA include 文件不存在: {file_path}")

        stack.append(file_path)
        try:
            try:
                raw = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                raw = file_path.read_text(errors="replace")

            out_lines: List[str] = []
            for line in raw.splitlines():
                m = include_re.match(line)
                if not m:
                    out_lines.append(line)
                    continue

                inc_rel = m.group(2).strip()
                # Resolve includes relative to the file containing the directive.
                inc_path = (file_path.parent / inc_rel).resolve()
                if not inc_path.is_file():
                    raise UserFacingError(
                        f"YARA include 找不到文件: {inc_rel} (from {file_path})"
                    )
                out_lines.append(f"\n// ---- BEGIN include {inc_rel} (from {file_path.name}) ----")
                out_lines.append(read_with_includes(inc_path, stack=stack, seen=seen))
                out_lines.append(f"// ---- END include {inc_rel} ----\n")

            seen.add(key)
            return "\n".join(out_lines) + "\n"
        finally:
            stack.pop()

    # NOTE: On Windows, yara.exe may fail to open include files when the include path
    # contains non-ASCII characters (e.g. Chinese). To avoid this, inline all includes
    # and concatenate everything into a single temporary ruleset file.
    parts: List[str] = []
    seen: set[str] = set()
    for p in rule_files:
        parts.append(f"\n// ---- BEGIN {p} ----\n")
        parts.append(read_with_includes(p, stack=[], seen=seen))
        parts.append(f"// ---- END {p} ----\n")

    bundle_path.write_text("".join(parts), encoding="utf-8")
    return bundle_path


def run_yara_scan(
    *,
    target: str,
    yara_rules_dir: Optional[str] = None,
    out_path: Optional[str] = None,
    threads: int = 4,
    progress_cb: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    _progress(progress_cb, "prepare", "正在检查 YARA 可执行文件...", 5)
    yara_exe = BACKEND_DIR / "yara64.exe"
    if not yara_exe.is_file():
        raise UserFacingError(f"找不到 YARA 可执行文件: {yara_exe}")

    _progress(progress_cb, "prepare", "正在解析目标路径...", 10)
    target_path = resolve_user_path(target)
    if not target_path.exists():
        raise UserFacingError(f"目标路径不存在: {target_path}")

    _progress(progress_cb, "prepare", "正在定位规则目录...", 15)
    rules_dir = (
        resolve_user_path(yara_rules_dir, base_dir=PROJECT_ROOT)
        if yara_rules_dir
        else (PROJECT_ROOT / "rules" / "yara")
    )

    _progress(progress_cb, "rules", "正在收集 YARA 规则文件...", 20)
    rule_files = _collect_yara_rule_files(rules_dir)

    # Many third-party rule packs contain rules incompatible with the bundled yara64.exe
    # (unknown modules, duplicated identifiers, syntax errors...). When compiling everything
    # into one large file, a single bad rule can make the whole scan silently return no hits.
    # To keep scans useful, we split large rule directories by top-level folder and skip
    # bundles that fail to compile.
    bundles: List[Tuple[str, Path, List[Path]]] = []
    skipped_bundles: List[Dict[str, Any]] = []

    if len(rule_files) > 200 and rules_dir.is_dir():
        # Split by top-level dir first. If a top-level pack is still huge, split one more
        # level so that a small incompatible subset doesn't invalidate the whole pack.
        top_groups: Dict[str, List[Path]] = {}
        for p in rule_files:
            rel = p.relative_to(rules_dir)
            top = rel.parts[0] if rel.parts else "(root)"
            top_groups.setdefault(top, []).append(p)

        second_groups: Dict[str, List[Path]] = {}
        for top, files in top_groups.items():
            if len(files) <= 200:
                second_groups[top] = files
                continue
            for p in files:
                rel = p.relative_to(rules_dir)
                sub = rel.parts[1] if len(rel.parts) > 1 else "(root)"
                key = f"{top}/{sub}"
                second_groups.setdefault(key, []).append(p)

        _progress(progress_cb, "rules", f"规则较多：将按目录分组编译（{len(second_groups)} 组）...", 30)
        for name, files in sorted(second_groups.items(), key=lambda kv: kv[0].lower()):
            merged = _write_yara_merged_rules(sorted(files))
            bundles.append((name, merged, files))
    else:
        _progress(progress_cb, "rules", "正在合并 YARA 规则...", 30)
        merged_rules = _write_yara_merged_rules(rule_files)
        bundles.append(("all", merged_rules, rule_files))

    threads_i = int(threads) if threads else 4
    if threads_i < 1:
        threads_i = 1

    # Fine-grained progress for directory scans: enumerate files and scan per-file.
    detections_by_file: Dict[str, List[str]] = {}
    detections_lock = threading.Lock()

    # Validate bundles once so we can skip ones that don't compile.
    def validate_bundle(bundle_name: str, merged_path: Path, sample_file: Path) -> Optional[str]:
        cmd_check: List[str] = [str(yara_exe), str(merged_path), str(sample_file)]
        proc = _run_yara(cmd_check)
        # Some yara builds may return 1 even when compilation fails; stderr is authoritative.
        if _yara_has_fatal_error(proc.stderr):
            return _summarize_yara_error(proc.stderr)
        if proc.returncode not in (0, 1):
            return _summarize_yara_error(proc.stderr) or (proc.stdout.strip() or f"退出码 {proc.returncode}")
        return None

    if target_path.is_dir():
        _progress(progress_cb, "prepare", "正在枚举待扫描文件...", 35)
        scan_files = [p for p in target_path.rglob("*") if p.is_file()]
        total = len(scan_files)
        if total == 0:
            raise UserFacingError(f"目录下未找到可扫描文件: {target_path}")

        # Validate bundles against the first file.
        sample = scan_files[0]
        valid_bundles: List[Tuple[str, Path]] = []
        for name, merged, files in bundles:
            err = validate_bundle(name, merged, sample)
            if err:
                skipped_bundles.append(
                    {
                        "bundle": name,
                        "rules_count": len(files),
                        "error": err,
                    }
                )
                brief = (err.splitlines()[0].strip() if err else "存在编译错误")
                _progress(progress_cb, "rules", f"跳过规则组 {name}：{brief}", 36)
                continue
            valid_bundles.append((name, merged))

        if not valid_bundles:
            details = "\n\n".join(
                [
                    f"[{b['bundle']}]\n{b['error']}"
                    for b in skipped_bundles[:5]
                ]
            )
            raise UserFacingError(
                "YARA 规则集编译失败：没有任何可用规则组。\n"
                "建议：改用 rules/yara/course，或清理/更新不兼容的第三方规则集。\n\n"
                + details
            )

        done_counter = 0
        done_lock = threading.Lock()
        last_emit = 0.0

        def emit_progress(force: bool = False) -> None:
            nonlocal last_emit
            now = time.monotonic()
            if (not force) and (now - last_emit) < 0.2:
                return
            last_emit = now
            with done_lock:
                done = done_counter
            pct = 30 + int(60 * (done / total))
            _progress(progress_cb, "run", f"正在扫描文件：{done}/{total}", pct)

        def scan_one(file_path: Path) -> List[Tuple[str, str]]:
            # Return list of (rule, file_path) detections
            hits: List[Tuple[str, str]] = []
            for _bundle_name, merged in valid_bundles:
                cmd_one: List[str] = [str(yara_exe), str(merged), str(file_path)]
                proc = _run_yara(cmd_one)
                if _yara_has_fatal_error(proc.stderr):
                    # Bundle was validated, so this should be rare; treat as hard error.
                    msg = _summarize_yara_error(proc.stderr) or "规则编译失败"
                    raise UserFacingError(f"YARA 扫描失败（规则编译错误）: {msg}")
                if proc.returncode not in (0, 1):
                    msg = _summarize_yara_error(proc.stderr) or (proc.stdout.strip() or f"退出码 {proc.returncode}")
                    raise UserFacingError(f"YARA 扫描文件失败: {file_path} ({msg})")

                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(maxsplit=1)
                    if len(parts) != 2:
                        continue
                    rule, fpath = parts
                    hits.append((rule, fpath))
            return hits

        _progress(progress_cb, "run", f"开始并发扫描：共 {total} 个文件...", 30)
        emit_progress(force=True)

        max_workers = threads_i if threads_i >= 1 else 1
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(scan_one, p) for p in scan_files]
            for fut in as_completed(futures):
                hits = fut.result()
                if hits:
                    with detections_lock:
                        for rule, fpath in hits:
                            detections_by_file.setdefault(fpath, []).append(rule)

                with done_lock:
                    done_counter += 1
                emit_progress()

        emit_progress(force=True)
    else:
        # Single file: run all valid bundles and aggregate results.
        valid_bundles: List[Tuple[str, Path]] = []
        for name, merged, files in bundles:
            err = validate_bundle(name, merged, target_path)
            if err:
                skipped_bundles.append(
                    {
                        "bundle": name,
                        "rules_count": len(files),
                        "error": err,
                    }
                )
                continue
            valid_bundles.append((name, merged))

        if not valid_bundles:
            details = "\n\n".join(
                [
                    f"[{b['bundle']}]\n{b['error']}"
                    for b in skipped_bundles[:5]
                ]
            )
            raise UserFacingError(
                "YARA 规则集编译失败：没有任何可用规则组。\n"
                "建议：改用 rules/yara/course，或清理/更新不兼容的第三方规则集。\n\n"
                + details
            )

        _progress(progress_cb, "run", "正在执行 YARA 扫描...", 60)
        for _bundle_name, merged in valid_bundles:
            cmd: List[str] = [str(yara_exe), "-p", str(threads_i), str(merged), str(target_path)]
            proc = _run_yara(cmd)
            if _yara_has_fatal_error(proc.stderr):
                msg = _summarize_yara_error(proc.stderr) or "规则编译失败"
                raise UserFacingError(f"YARA 执行失败（规则编译错误）: {msg}")
            if proc.returncode not in (0, 1):
                raise UserFacingError(
                    f"YARA 执行失败(退出码 {proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
                )

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
        "rules_bundles": [
            {"bundle": name, "rules_count": len(files)}
            for (name, _merged, files) in bundles
        ],
        "rules_bundles_skipped": skipped_bundles,
        "threads": threads_i,
        "hits_files": len(detections_by_file),
        "hits_total": sum(len(v) for v in detections_by_file.values()),
        "detections": detections_by_file,
    }

    out_file = resolve_user_path(out_path, base_dir=PROJECT_ROOT) if out_path else (OUT_DIR / "scan_files.json")
    _progress(progress_cb, "write", "正在写出扫描结果 JSON...", 90)
    ensure_parent_dir(out_file)
    out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    result["out_path"] = str(out_file)
    _progress(progress_cb, "done", "文件扫描完成", 100)
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
    progress_cb: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    _progress(progress_cb, "prepare", "正在检查 Zircolite 入口脚本...", 5)
    zir_dir = BACKEND_DIR / "Zircolite-master"
    zir_py = zir_dir / "zircolite.py"
    if not zir_py.is_file():
        raise UserFacingError(f"找不到 Zircolite 入口脚本: {zir_py}")

    _progress(progress_cb, "prepare", "正在解析事件文件路径...", 10)
    events_file = resolve_user_path(events_path)
    if not events_file.exists():
        raise UserFacingError(f"事件文件不存在: {events_file}")

    _progress(progress_cb, "prepare", "正在定位 Sigma 规则目录...", 15)
    rules_path = (
        resolve_user_path(sigma_rules_dir, base_dir=PROJECT_ROOT)
        if sigma_rules_dir
        else (PROJECT_ROOT / "rules" / "sigma")
    )
    if not rules_path.exists():
        raise UserFacingError(f"Sigma 规则目录不存在: {rules_path}")

    _progress(progress_cb, "prepare", "正在准备输出文件...", 20)
    out_file = resolve_user_path(out_path, base_dir=PROJECT_ROOT) if out_path else (OUT_DIR / "scan_logs.json")
    ensure_parent_dir(out_file)

    python_exe = os.environ.get("PYTHON") or sys.executable

    # Zircolite supports multiple input formats. For EVTX, do NOT pass JSON flags.
    # Otherwise Zircolite will try to parse the binary EVTX as JSON and fail.
    if events_file.suffix.lower() == ".evtx":
        _progress(progress_cb, "prepare", "检测到 EVTX：将使用 evtx 输入模式...", 30)
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
        _progress(progress_cb, "prepare", "正在按需截断事件（max_events）...", 30)
        max_events_i = int(max_events) if max_events else 0
        truncated_events_file, truncated = _truncate_events_if_needed(events_file, max_events=max_events_i)

        _progress(progress_cb, "prepare", "正在检测输入格式...", 35)
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

    _progress(progress_cb, "run", "正在执行 Zircolite 扫描...", 40)

    # Stream stdout/stderr to parse tqdm percentage for finer progress.
    percent_re = re.compile(r"(\d{1,3})%")
    max_overall = 40

    def run_with_stream_progress() -> Tuple[int, str, str]:
        nonlocal max_overall
        proc = subprocess.Popen(
            cmd,
            cwd=str(zir_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        q: Queue[Tuple[str, bytes]] = Queue()

        def reader(name: str, stream):
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    q.put((name, chunk))
            finally:
                q.put((name, b""))

        t1 = threading.Thread(target=reader, args=("stdout", proc.stdout), daemon=True)
        t2 = threading.Thread(target=reader, args=("stderr", proc.stderr), daemon=True)
        t1.start()
        t2.start()

        partial: Dict[str, str] = {"stdout": "", "stderr": ""}
        stdout_keep: List[str] = []
        stderr_keep: List[str] = []

        def keep_tail(buf: List[str], line: str, limit: int = 200) -> None:
            if not line:
                return
            buf.append(line)
            if len(buf) > limit:
                del buf[: len(buf) - limit]

        done_streams = {"stdout": False, "stderr": False}

        while True:
            try:
                name, chunk = q.get(timeout=0.1)
            except Exception:
                if proc.poll() is not None and all(done_streams.values()):
                    break
                continue

            if chunk == b"":
                done_streams[name] = True
                if proc.poll() is not None and all(done_streams.values()):
                    break
                continue

            text = _strip_ansi(_decode_cli_bytes(chunk))
            if not text:
                continue
            # tqdm updates often use carriage returns.
            combined = partial[name] + text
            parts = re.split(r"[\r\n]", combined)
            partial[name] = parts[-1]
            for seg in parts[:-1]:
                seg = seg.strip()
                if not seg:
                    continue
                # Capture tail output for debugging.
                if name == "stdout":
                    keep_tail(stdout_keep, seg)
                else:
                    keep_tail(stderr_keep, seg)

                m = percent_re.search(seg)
                if m:
                    p = int(m.group(1))
                    if p < 0:
                        p = 0
                    if p > 100:
                        p = 100
                    # Map tqdm percent into a monotonic overall percent range [40..95].
                    mapped = 40 + int(p * 0.55)
                    if mapped > max_overall:
                        max_overall = mapped
                        _progress(progress_cb, "run", seg[:200], max_overall)

        rc = proc.wait()
        # Flush remaining partials
        for name, rest in partial.items():
            rest = (rest or "").strip()
            if rest:
                if name == "stdout":
                    keep_tail(stdout_keep, rest)
                else:
                    keep_tail(stderr_keep, rest)

        return rc, "\n".join(stdout_keep), "\n".join(stderr_keep)

    returncode, stdout_text, stderr_text = run_with_stream_progress()

    if returncode != 0:
        msg = (stderr_text.strip() or stdout_text.strip())
        msg_l = msg.lower()
        if "unicodedecodeerror" in msg_l or "codec can't decode" in msg_l:
            raise UserFacingError(
                "Zircolite 读取事件文件时发生编码错误（UnicodeDecodeError）。\n"
                "请确保输入的 .json/.jsonl 为 UTF-8 编码；若文件来自 EVTX 转换，建议重新导出为 UTF-8。\n"
                f"退出码 {returncode}: {msg}"
            )

        raise UserFacingError(
            "Zircolite 执行失败。常见原因：未安装 Zircolite 依赖（需要 pip 安装 requirements.txt）。\n"
            f"退出码 {returncode}: {msg}"
        )

    hits = None
    try:
        if out_file.is_file():
            _progress(progress_cb, "parse", "正在解析扫描输出...", 85)
            content = out_file.read_text(encoding="utf-8", errors="replace").strip()
            if content.startswith("["):
                parsed = json.loads(content)
                if isinstance(parsed, list):
                    hits = len(parsed)
    except Exception:
        hits = None

    _progress(progress_cb, "done", "日志扫描完成", 100)
    # Prefer stdout tail if available, otherwise stderr tail.
    stdout_tail = stdout_text.strip() or stderr_text.strip()
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
        "stdout_tail": "\n".join(stdout_tail.splitlines()[-40:]),
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


def evaluate_binary_detection(
    *,
    truth_csv: str,
    scan_json: str,
    out_path: Optional[str] = None,
    progress_cb: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    _progress(progress_cb, "prepare", "正在检查输入文件...", 10)
    truth_path = resolve_user_path(truth_csv)
    scan_path = resolve_user_path(scan_json)
    if not truth_path.is_file():
        raise UserFacingError(f"truth.csv 不存在: {truth_path}")
    if not scan_path.is_file():
        raise UserFacingError(f"scan JSON 不存在: {scan_path}")

    _progress(progress_cb, "prepare", "正在读取扫描 JSON...", 20)
    scan = json.loads(scan_path.read_text(encoding="utf-8", errors="replace"))

    predicted: Dict[str, int] = {}
    if isinstance(scan, dict) and scan.get("engine") == "yara":
        _progress(progress_cb, "prepare", "正在提取预测标签...", 30)
        detections = scan.get("detections") or {}
        if isinstance(detections, dict):
            for fpath, rules in detections.items():
                predicted[str(fpath)] = 1 if rules else 0
    else:
        raise UserFacingError("evaluate 目前只支持使用 /api/scan-files 生成的 YARA 扫描 JSON")

    tp = fp = tn = fn = 0
    skipped_rows = 0

    def pick(row: Dict[str, str], keys: Iterable[str]) -> str:
        for k in keys:
            if k in row and row[k] is not None:
                return str(row[k])
        return ""

    # Count total rows for finer progress percentage.
    _progress(progress_cb, "prepare", "正在统计 truth.csv 行数...", 40)
    total_rows = 0
    with truth_path.open("r", encoding="utf-8", errors="replace", newline="") as f_count:
        reader_count = csv.DictReader(f_count)
        if not reader_count.fieldnames:
            raise UserFacingError("truth.csv 缺少表头")
        for row in reader_count:
            sample = pick(row, ["sample", "path", "file", "filepath", "filename"]).strip()
            label_raw = pick(row, ["label", "truth", "is_malicious", "malicious", "y"]).strip()
            if sample and (_normalize_truth_label(label_raw) is not None):
                total_rows += 1

    processed = 0
    last_emit = 0.0

    def emit_progress(force: bool = False) -> None:
        nonlocal last_emit
        if total_rows <= 0:
            return
        now = time.monotonic()
        if (not force) and (now - last_emit) < 0.2:
            return
        last_emit = now
        pct = 50 + int(45 * (processed / total_rows))
        _progress(progress_cb, "run", f"正在评测：{processed}/{total_rows}", pct)

    _progress(progress_cb, "run", "开始逐行评测 truth.csv...", 50)
    emit_progress(force=True)

    with truth_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise UserFacingError("truth.csv 缺少表头")

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

                processed += 1
                emit_progress()

            emit_progress(force=True)

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
    _progress(progress_cb, "write", "正在写出评测结果 JSON...", 90)
    ensure_parent_dir(out_file)
    out_file.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    result["out_path"] = str(out_file)
    _progress(progress_cb, "done", "指标计算完成", 100)
    return result
