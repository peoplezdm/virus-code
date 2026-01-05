# 课程大作业：杀毒/检测工具（YARA + Sigma）

目录分工（按你要求）：
- `frontend/`：前端（可选进阶 GUI，占位）
- `backend/`：后端/引擎（Python CLI：YARA 扫文件 + Sigma 扫日志 + 指标评测）
- `rules/`：规则（你们自行编写/收集）

## Kali / Linux 快速开始

```bash
cd /path/to/大作业/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m avscan --help
```

## 扫描（最低要求）

- 文件扫描（YARA）：

```bash
python -m avscan scan-files --target "/path/to/course_samples" --out "../out/scan_files.json"
```

- 日志扫描（Sigma，需要 events.jsonl / events.json）：

```bash
python -m avscan scan-logs --events "/path/to/events.jsonl" --out "../out/scan_logs.json"
```

- 指标评测：

```bash
python -m avscan evaluate --truth "../docs/truth.csv" --scan-json "../out/scan_files.json" --out "../out/metrics.json"
```

## Web 前端（真正一键触发）

启动后端 Web 服务（会同时提供前端页面 + API）：

```bash
cd /path/to/大作业/backend
source .venv/bin/activate
python -m avscan serve --host 127.0.0.1 --port 8000
```

浏览器打开：
- `http://127.0.0.1:8000/`
