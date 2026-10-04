# -*- encoding: utf-8 -*-
"""PackSurgeon AST Deobfuscator Engine"""

import os
import sys
import subprocess
import shutil

ENGINE_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deobfuscate.js")


def run_deobfuscator(input_dir: str, output_dir: str = None) -> bool:
    """
    基于 Node.js 与 Webcrack 引擎执行 AST 批量语法脱壳与解混淆。
    """
    if not os.path.exists(input_dir):
        print(f"[ERROR] 目标输入目录不存在: {input_dir}")
        return False

    if not output_dir:
        output_dir = f"{input_dir}_已解混淆"

    node_bin = shutil.which("node")
    if not node_bin:
        print("[WARN] 系统未探测到 Node.js 运行时，将跳过 AST 语法脱壳层，使用原始脚本继续分析。")
        print("[TIP] 安装 Node.js 18+ 后可激活现代 Webpack 分块解压与 AST 变量还原能力。")
        return False

    cmd = [node_bin, ENGINE_SCRIPT, os.path.abspath(input_dir), os.path.abspath(output_dir)]
    print(f"[INFO] 正在启动 AST 脱壳解混淆引擎: {input_dir} -> {output_dir}")
    try:
        res = subprocess.run(cmd, capture_output=False, check=False)
        if res.returncode == 0:
            print(f"[SUCCESS] AST 语法脱壳完成: {output_dir}")
            return True
        else:
            print(f"[WARN] AST 脱壳进程退出异常 (退出码: {res.returncode})，降级使用原始文件。")
            return False
    except Exception as e:
        print(f"[WARN] 调度 AST 脱壳引擎发生异常: {e}")
        return False
