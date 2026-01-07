# 这是一个用于测试的脚本，把相关地址填入下面的相关位置，然后运行即可

import sys
from pathlib import Path

# 设置项目根目录
PROJECT_ROOT = Path(r"D:\virus-code-main\virus-code-main")
sys.path.append(str(PROJECT_ROOT / "backend"))

from backend.avscan_core import run_yara_scan, UserFacingError

def main():
    try:
        result = run_yara_scan(
            target=r"C:\Users\ASUS\Desktop\example",
            yara_rules_dir=r"D:\virus-code-main\virus-code-main\rules\yara",
            out_path=r"D:\virus-code-main\virus-code-main\out\test.json"
        )
        print("扫描完成！结果已保存至:", result["out_path"])
        print(f"共检测到 {result['hits_files']} 个文件匹配，总计 {result['hits_total']} 个规则命中")
    except UserFacingError as e:
        print(f"用户错误: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"系统错误: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()