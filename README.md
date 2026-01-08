# avscan（课程大作业）使用教程

本项目提供一个最小可用的本地 Web 界面与后端 API：

- **文件扫描（YARA）**：使用 `yara-python` 扫描文件/目录（不再依赖 `yara64.exe`）
- **日志扫描（Sigma）**：调用官方仓库版 Zircolite：`backend/Zircolite-master/zircolite.py`
- **指标评测（evaluate）**：对文件扫描结果做二分类指标计算

> 运行环境：Windows（PowerShell）

---

## 1. 环境准备

### 1.1 安装 Python

建议 Python 3.10+（Zircolite 官方仓库版在 Python 3.8+ 可用，但 3.10 更稳）。

验证：

```powershell
python --version
```

### 1.2（推荐）创建虚拟环境

在项目根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> 如果 PowerShell 不允许执行脚本，可用：
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 1.3 安装 Zircolite 依赖（Sigma 扫描必需）

### 1.3.1 安装后端依赖（YARA 引擎必需）

文件扫描（YARA）使用 `yara-python`，在项目根目录执行：

```powershell
python -m pip install -r .\backend\requirements.txt
```

Sigma 扫描通过 `backend/Zircolite-master/zircolite.py` 执行，因此需要安装其依赖。

在项目根目录执行：

```powershell
python -m pip install -r .\backend\Zircolite-master\requirements.txt
```

（可选）更完整依赖：

```powershell
python -m pip install -r .\backend\Zircolite-master\requirements.full.txt
```

---

## 2. 启动

在项目根目录执行：

```powershell
python .\backend\server.py
```

看到类似输出说明启动成功：

```text
avscan backend listening on http://127.0.0.1:8000
```

浏览器打开：

- http://127.0.0.1:8000/

---

## 3. 规则与路径约定

项目中约定：

- YARA 规则目录：`rules/yara/`（支持 `.yar/.yara/.rule`）
- Sigma 规则目录：`rules/sigma/`（支持原生 Sigma YAML 或目录；也支持 Zircolite JSON ruleset）
- 输出目录：`out/`

前端页面输入框支持：

- 绝对路径：`E:\\...\\file`
- 相对路径（相对于项目根目录）：`rules/yara`、`out/scan_files.json`

> 你可以粘贴带引号的路径（如 `"E:\\xxx"`），后端会自动去掉首尾引号。

---

## 4. 使用：文件扫描（YARA）

### 4.1 准备 YARA 规则

把你编写的 YARA 规则放入：

- `rules/yara/`（可分子目录，例如 `rules/yara/course/lab6/...`）

### 4.2 在页面触发扫描

在页面的 **1) 文件扫描（YARA）**：

- 目标路径：填写要扫描的文件或目录（建议目录）
- YARA 规则目录：留空则默认 `rules/yara`
- 输出 JSON：留空则默认 `out/scan_files.json`

输出字段说明：

- `hits_files`：至少命中 1 条规则的文件数量
- `hits_total`：所有命中的总次数（一个文件命中多条规则会累计）

---

## 5. 使用：日志扫描（Sigma / Zircolite）

Zircolite 是“基于日志事件”的检测工具，不是对二进制文件做静态扫描。

你需要提供 **事件日志文件**，例如：

- Windows EVTX：`.evtx`
- JSON Lines：`.jsonl` / `.ndjson`（一行一个事件对象）
- JSON Array：`.json`（整体是 `[...]` 数组）

在页面的 **2) 日志扫描（Sigma）**：

- 事件文件：填写 `.evtx` / `.jsonl` / `.json` 等日志路径
- Sigma 规则目录：留空则默认 `rules/sigma`
- 输出 JSON：留空则默认 `out/scan_logs.json`
- 最大事件数：用于截断输入（0=不截断）

> 注意：把“二进制样本目录”填到这里会报错，因为那不是日志。

---

## 6. 使用：指标评测（evaluate）

评测接口目前按“二分类”理解文件扫描结果（YARA）：命中任意规则=预测为恶意。

在页面的 **3) 指标评测（evaluate）**：

- truth.csv：真实标签 CSV
- scan 输出 JSON：通常填 `out/scan_files.json`
- 输出 JSON：留空则默认 `out/metrics.json`

truth.csv 支持较灵活的列名：

- 样本列：`sample` / `path` / `file` / `filepath` / `filename`
- 标签列：`label` / `truth` / `is_malicious` / `malicious`

标签支持：`1/0`、`true/false`、`yes/no`、`malicious/benign` 等。

---

## 7. 常见问题（FAQ）

### 7.1 YARA 报 include 找不到文件（含中文路径）

已在后端规避：后端会把所有规则内容合并为一个临时 ruleset 执行，避免 Windows 下 YARA 对 include 路径的 Unicode 兼容问题。

### 7.2 YARA 报 syntax error / expecting string identifier

通常是规则里 `strings:` 区域写成了：

```yara
strings:
	s1 = "abc"   // ❌
```

正确写法必须以 `$` 开头：

```yara
strings:
	$s1 = "abc"  // ✅
```

### 7.3 Sigma 扫描报 Zircolite 执行失败 / 缺依赖

先安装依赖：

```powershell
python -m pip install -r .\backend\Zircolite-master\requirements.txt
```

---

## 8. 目录结构（简要）

```text
backend/                 # 后端 API + 官方工具
	server.py              # HTTP 服务（同时提供静态前端）
	avscan_core.py          # YARA（yara-python）与 Zircolite
	# yara64.exe（已不再需要，可留存）
	Zircolite-master/

frontend/                # Web 界面
rules/
	yara/                   # 你的 YARA 规则
	sigma/                  # 你的 Sigma 规则
out/                     # 输出目录
```
