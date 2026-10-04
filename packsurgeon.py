#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
PackSurgeon: 基于 AST 与多引擎自适应的前端逆向与全链路资产挖掘平台
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Copyright 2026 markx520
Licensed under the Apache License, Version 2.0.
"""

import os
import sys
import argparse

# 确保项目根目录在 sys.path 首位
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def print_banner_safely():
    try:
        from lib.common.banner import RandomBanner
        RandomBanner()
    except Exception:
        print("=== PackSurgeon (Frontend Reverse & Reconnaissance Platform) ===")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="packsurgeon",
        description="PackSurgeon: 基于 AST 语法树与多引擎自适应的前端打包资产全生命周期逆向与资产挖掘工作台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例指令:
  1. 一键全自动闭环审计 (抓取 + AST脱壳 + 凭据挖掘 + 接口提纯 + 出大盘报告):
     python packsurgeon.py run -u "https://example.com" -p "http://127.0.0.1:7890"

  2. 独立动态嗅探抓取:
     python packsurgeon.py crawl -u "https://example.com" -i -o "my_site_assets"

  3. 独立 AST 批量语法脱壳与 Webpack 分块解压:
     python packsurgeon.py unpack -i "my_site_assets" -o "my_site_assets_已解混淆"

  4. 独立离线代码目录敏感凭据挖掘:
     python packsurgeon.py scan --dir "my_site_assets_已解混淆"

  5. 运行环境与运行时体检:
     python packsurgeon.py doctor
        """
    )
    parser.add_argument("-v", "--version", action="version", version="PackSurgeon v1.6.0-enterprise")

    subparsers = parser.add_subparsers(dest="subcommand", help="核心子命令模块")

    # 1. run 子命令: 一体化端到端流水线
    run_parser = subparsers.add_parser("run", help="执行全生命周期自动化逆向流水线 (推荐)")
    run_parser.add_argument("-u", "--url", required=True, help="目标站点入口 URL")
    run_parser.add_argument("-o", "--output", default=None, help="资产输出目录 (默认自动按域名命名)")
    run_parser.add_argument("-p", "--proxy", default=None, help="上游代理地址 (如: http://127.0.0.1:7890)")
    run_parser.add_argument("-i", "--interactive", action="store_true", default=False, help="启用人机交互模式")
    run_parser.add_argument("-s", "--silent", action="store_true", default=False, help="静默模式")

    # 2. crawl 子命令: 独立动态嗅探
    crawl_parser = subparsers.add_parser("crawl", help="启动多内核动态自适应嗅探与 HTTP 录制")
    crawl_parser.add_argument("-u", "--url", required=True, help="目标站点入口 URL")
    crawl_parser.add_argument("-o", "--output", default="site_download", help="资产输出目录")
    crawl_parser.add_argument("-p", "--proxy", default=None, help="上游代理地址")
    crawl_parser.add_argument("-i", "--interactive", action="store_true", default=False, help="启用交互式手动浏览")
    crawl_parser.add_argument("--engine", choices=["auto", "camoufox", "patchright", "chrome"], default="auto", help="指定浏览器内核")
    crawl_parser.add_argument("--depth", type=int, default=2, help="自动链接探索深度")
    crawl_parser.add_argument("--no-explore", action="store_true", default=False, help="禁用自动探索")
    crawl_parser.add_argument("--no-assets", action="store_true", default=False, help="仅录制 API 报文，跳过静态文件")
    crawl_parser.add_argument("--no-crack", action="store_true", default=False, help="抓取完成后不自动触发脱壳")

    # 3. unpack 子命令: 独立 AST 批量语法脱壳
    unpack_parser = subparsers.add_parser("unpack", help="对指定代码目录执行批量 AST 脱壳与 Webpack 分块解包")
    unpack_parser.add_argument("-i", "--input", required=True, help="待解混淆的原始代码目录")
    unpack_parser.add_argument("-o", "--output", default=None, help="解密明文输出目录 (默认: <input>_已解混淆)")

    # 4. scan 子命令: 独立代码审计与凭据挖掘
    scan_parser = subparsers.add_parser("scan", help="对本地目录或在线 URL 执行敏感凭据挖掘")
    scan_parser.add_argument("--dir", default=None, help="指定待审计的本地代码目录")
    scan_parser.add_argument("-u", "--url", default=None, help="在线扫描单个目标 URL")
    scan_parser.add_argument("-l", "--list", default=None, help="批量目标清单文件路径")
    scan_parser.add_argument("-j", "--js", default=None, help="仅分析指定的单个 JS 文件 URL")
    scan_parser.add_argument("--finder", action="store_true", default=True, help="启用敏感特征深度审计 (默认启用)")
    scan_parser.add_argument("-s", "--silent", action="store_true", default=False, help="静默模式")
    scan_parser.add_argument("-p", "--proxy", default=None, help="上游代理服务")

    # 5. doctor 子命令: 环境基建健康检查
    subparsers.add_parser("doctor", help="运行环境健康检查探针 (Python, Node.js, Playwright)")

    return parser


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        print_banner_safely()
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if args.subcommand == "doctor":
        from core.env_check import probe_environment
        probe_environment(verbose=True)
        sys.exit(0)

    elif args.subcommand == "run":
        try:
            from core.pipeline import PipelineContext, execute_full_pipeline
        except ModuleNotFoundError as e:
            print(f"[ERROR] 缺少运行依赖: {e}。请执行: pip install -r requirements.txt")
            sys.exit(1)

        ctx = PipelineContext(
            target_url=args.url,
            output_base=args.output,
            proxy=args.proxy,
            interactive=args.interactive
        )
        ret = execute_full_pipeline(ctx, silent=args.silent)
        sys.exit(ret)

    elif args.subcommand == "crawl":
        try:
            from engines.crawler.downloader import run_with_args as run_crawler_args
        except ModuleNotFoundError as e:
            print(f"[ERROR] 缺少爬虫依赖: {e}。请执行: pip install -r requirements.txt")
            sys.exit(1)

        crawl_args = ["-u", args.url, "-o", args.output]
        if args.proxy: crawl_args.extend(["-p", args.proxy])
        if args.interactive: crawl_args.append("-i")
        if args.engine: crawl_args.extend(["--engine", args.engine])
        if args.depth: crawl_args.extend(["--depth", str(args.depth)])
        if args.no_explore: crawl_args.append("--no-explore")
        if args.no_assets: crawl_args.append("--no-assets")
        if args.no_crack: crawl_args.append("--no-crack")
        run_crawler_args(crawl_args)
        sys.exit(0)

    elif args.subcommand == "unpack":
        try:
            from engines.deobfuscator import run_deobfuscator
        except Exception as e:
            print(f"[ERROR] 加载脱壳引擎失败: {e}")
            sys.exit(1)
        ok = run_deobfuscator(args.input, args.output)
        sys.exit(0 if ok else 1)

    elif args.subcommand == "scan":
        try:
            if args.dir:
                from lib.runner.offline_dir_scan import run_offline_dir_scan
                run_offline_dir_scan(args)
            elif args.url:
                from lib.runner.scan_orchestrator import run_single_target_scan
                run_single_target_scan(args)
            elif args.list:
                from lib.runner.scan_orchestrator import run_batch_scan
                run_batch_scan(args)
            else:
                print("[ERROR] scan 子命令需要指定 --dir <目录> 或 -u <URL> 或 -l <文件>")
                sys.exit(2)
        except ModuleNotFoundError as e:
            print(f"[ERROR] 缺少扫描依赖: {e}。请先执行: pip install -r requirements.txt")
            sys.exit(1)
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断操作，PackSurgeon 正常退出。")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] 运行遇到未处理异常: {e}")
        sys.exit(1)
