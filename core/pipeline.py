# -*- encoding: utf-8 -*-
"""
PackSurgeon Core Pipeline Orchestrator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
全生命周期前端逆向与资产挖掘流水线中枢。
自动闭环串联：动态多引擎嗅探 -> AST脱壳解混淆 -> 凭据挖掘 -> 接口微创提纯 -> 交互式报告。
"""

import os
import sys
import time
import argparse
from urllib.parse import urlparse

from core.env_check import probe_environment
from engines.deobfuscator import run_deobfuscator
from engines.analyzer import run_api_surgeon
from lib.runner.offline_dir_scan import run_offline_dir_scan
from lib.common.banner import RandomBanner


class PipelineContext:
    def __init__(self, target_url: str, output_base: str = None, proxy: str = None, interactive: bool = False):
        self.target_url = target_url
        self.proxy = proxy
        self.interactive = interactive

        # 规范化目标标识
        parsed = urlparse(target_url)
        netloc = parsed.netloc.replace(":", "_").replace(".", "_") or "target"
        self.target_tag = netloc

        if not output_base:
            self.download_dir = os.path.abspath(f"site_download_{self.target_tag}")
        else:
            self.download_dir = os.path.abspath(output_base)

        self.deobf_dir = f"{self.download_dir}_已解混淆"
        self.report_path = None


def execute_full_pipeline(context: PipelineContext, silent: bool = False) -> int:
    """
    执行 PackSurgeon 全链路一体化自动化逆向工程流水线。
    """
    start_time = time.time()
    if not silent:
        RandomBanner()
        print("=" * 70)
        print(">>> PackSurgeon 工业级全链路逆向流水线启动 <<<")
        print(f"[*] 目标地址       : {context.target_url}")
        print(f"[*] 原始资产目录   : {context.download_dir}")
        print(f"[*] 解混淆明文目录 : {context.deobf_dir}")
        if context.proxy:
            print(f"[*] 上游代理服务   : {context.proxy}")
        print("=" * 70)

    # 0. 环境自检
    env = probe_environment(verbose=False)

    # 1. Phase 1: 动态自适应嗅探与 HTTP 录制
    print("\n[PHASE 1/4] 启动浏览器多内核自适应嗅探引擎...")
    crawler_cmd_args = [
        "-u", context.target_url,
        "-o", context.download_dir,
        "--no-crack"  # 由 pipeline 统一接管后续解混淆阶段
    ]
    if context.interactive:
        crawler_cmd_args.append("-i")
    if context.proxy:
        crawler_cmd_args.extend(["-p", context.proxy])

    from engines.crawler.downloader import run_with_args
    try:
        run_with_args(crawler_cmd_args)
    except Exception as e:
        print(f"[ERROR] 动态嗅探引擎执行异常: {e}")
        return 1

    if not os.path.exists(context.download_dir):
        print(f"[ERROR] 未捕获到目标站点资产: {context.download_dir}")
        return 1

    # 2. Phase 2: AST 语法树脱壳解混淆
    print("\n[PHASE 2/4] 启动 AST 语法树脱壳与 Webpack 分块解压引擎...")
    deobf_success = False
    if env.get("node"):
        deobf_success = run_deobfuscator(context.download_dir, context.deobf_dir)
    else:
        print("[WARN] 系统未探测到 Node.js 运行时，跳过 AST 脱壳，直接使用原始分块执行审计。")

    target_scan_dir = context.deobf_dir if (deobf_success and os.path.exists(context.deobf_dir)) else context.download_dir

    # 3. Phase 3: 离线代码深度敏感凭据与 API 接口挖掘
    print(f"\n[PHASE 3/4] 启动深度敏感凭据挖掘引擎: {target_scan_dir}")
    scan_opts = argparse.Namespace(
        dir=target_scan_dir,
        finder=True,
        silent=silent,
        output=f"PackSurgeon_Audit_{context.target_tag}"
    )
    try:
        run_offline_dir_scan(scan_opts)
    except Exception as e:
        print(f"[WARN] 离线凭据审计阶段异常: {e}")

    # 4. Phase 4: API 接口微创提纯 (如果录制了 HTTP 报文)
    print("\n[PHASE 4/4] 检查并启动 API 报文微创手术刀提纯...")
    for root, _, files in os.walk(context.download_dir):
        for f in files:
            if f.endswith(".http"):
                http_fp = os.path.join(root, f)
                run_api_surgeon(http_fp)

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(">>> PackSurgeon 端到端全链路闭环逆向作业达标完成 <<<")
    print(f"[+] 总耗时         : {elapsed:.2f} 秒")
    print(f"[+] 原始分块资产   : {context.download_dir}")
    if os.path.exists(context.deobf_dir):
        print(f"[+] 解密明文代码   : {context.deobf_dir}")
    print("=" * 70 + "\n")
    return 0
