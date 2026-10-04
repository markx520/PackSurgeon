# -*- encoding: utf-8 -*-
"""PackSurgeon Analyzer Engine (API Heuristics & Secret Audit)"""

import os
import sys
import subprocess
import shutil

API_SURGEON_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_surgeon.js")


def run_api_surgeon(target_path: str, output_file: str = None) -> bool:
    """
    运行 API 抓包报文微创手术刀，提炼高信噪比业务契约。
    """
    if not os.path.exists(target_path):
        print(f"[ERROR] 目标路径不存在: {target_path}")
        return False

    node_bin = shutil.which("node")
    if not node_bin:
        print("[WARN] 系统未探测到 Node.js 运行时，跳过 API 微创提纯。")
        return False

    cmd = [node_bin, API_SURGEON_SCRIPT, os.path.abspath(target_path)]
    if output_file:
        cmd.extend(["-o", os.path.abspath(output_file)])

    print(f"[INFO] 正在启动 API 微创提纯引擎: {target_path}")
    try:
        res = subprocess.run(cmd, capture_output=False, check=False)
        return res.returncode == 0
    except Exception as e:
        print(f"[WARN] 调度 API 提纯引擎发生异常: {e}")
        return False
