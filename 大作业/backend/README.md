# backend

Python 后端与扫描引擎（CLI）：
- YARA：文件/目录静态扫描
- Sigma：日志事件（JSON/JSONL）规则匹配
- evaluate：输出 TP/FP/FN/TN、准确率、误报率、漏报率等

从本目录运行 `python -m avscan ...`。
默认规则目录会自动指向仓库根目录的 `rules/`。
