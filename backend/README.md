# backend

本目录提供后端 API，负责调用下载的官方工具：

- **YARA**：使用 `yara-python`（纯 Python 调用 libyara，不再依赖 `yara64.exe`）
- **Sigma**：固定调用官方仓库版 Zircolite：`backend/Zircolite-master/zircolite.py`

## 运行

在项目根目录执行：

```powershell
python .\backend\server.py
```

浏览器打开：

- http://127.0.0.1:8000/

## API

- `POST /api/scan-files`
  - body: `{ target, yara_rules_dir?, out_path?, threads? }`
- `POST /api/scan-logs`
  - body: `{ events_path, sigma_rules_dir?, out_path?, max_events? }`
- `POST /api/evaluate`
  - body: `{ truth_csv, scan_json, out_path? }`

## 依赖（Sigma 扫描必需）

文件扫描（YARA）使用 `yara-python`，先安装：

```powershell
python -m pip install -r .\backend\requirements.txt
```

Sigma 扫描会执行 Zircolite 的 Python 脚本，因此需要先安装依赖：

```powershell
python -m pip install -r .\backend\Zircolite-master\requirements.txt
```

（可选）更完整依赖：

```powershell
python -m pip install -r .\backend\Zircolite-master\requirements.full.txt
```

## 常见问题

- **YARA include + 中文路径失败**：后端会把所有规则内容合并成一个临时 ruleset 执行，绕开 include 路径的 Unicode 兼容问题。
- **YARA syntax error / expecting string identifier**：通常是 `strings:` 里写成了 `s1 = "..."`，必须写成 `$s1 = "..."`。
