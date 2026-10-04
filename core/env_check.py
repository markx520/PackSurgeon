# -*- encoding: utf-8 -*-
"""PackSurgeon Environment & Dependency Probing Sentinel"""

import sys
import shutil
import subprocess


def probe_environment(verbose: bool = False) -> dict:
    """
    自包含环境体检探针，返回环境各组件状态。
    """
    status = {
        "python": sys.version_split() if hasattr(sys, "version_split") else sys.version.split()[0],
        "node": None,
        "playwright": False,
    }

    # 1. 检测 Node.js
    node_bin = shutil.which("node")
    if node_bin:
        try:
            res = subprocess.run([node_bin, "-v"], capture_output=True, text=True, timeout=5)
            status["node"] = res.stdout.strip()
        except Exception:
            status["node"] = "installed_unreachable"

    # 2. 检测 Playwright
    try:
        import playwright
        status["playwright"] = True
    except ImportError:
        status["playwright"] = False

    if verbose:
        print("=" * 65)
        print("=== PackSurgeon 工业级运行基建环境自检 ===")
        print(f"[*] Python 运行环境 : {status['python']} (正常)")
        print(f"[*] Node.js 运行时  : {status['node'] or '未检测到 (AST脱壳引擎将降级)'}")
        print(f"[*] Playwright 驱动 : {'已就绪' if status['playwright'] else '未安装 (动态嗅探将受限)'}")
        print("=" * 65)

    return status
