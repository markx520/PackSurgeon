#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
offline_dir_scan.py
~~~~~~~~~~~~~~~~~~~
Packer-InfoFinder 离线本地 JS 目录深度扫描与敏感信息挖掘引擎
支持直接对 site_downloader 下载并脱壳的本地前端工程进行离线批量审计，
提取所有已知敏感凭据、API Key、内部 API 接口与前端路由。
"""

import os
import sys
import time
import html
from types import SimpleNamespace

from lib.common.create_log import creatLog, start_new_task, get_current_log_name
from lib.Database import DatabaseType
from lib.JsFinder.JsFinderModule import JsFinderModule


def run_offline_dir_scan(options):
    """离线本地目录深度扫描执行器。"""
    raw_dir = getattr(options, "dir", "") or ""
    target_dir = os.path.abspath(raw_dir.strip())
    if not os.path.exists(target_dir):
        print(f"[ERROR] 指定的离线目录不存在: {target_dir}")
        return

    logger = creatLog().get_logger()
    dir_name = os.path.basename(target_dir.rstrip(r"\/"))
    print("=" * 65)
    print(f"=== Packer-InfoFinder 离线目录深度敏感信息挖掘模式 ===")
    print("=" * 65)
    print(f"目标目录 : {target_dir}")

    # 1. 递归收集所有 JS 文件
    js_files = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.lower().endswith(".js"):
                js_files.append(os.path.join(root, f))

    if not js_files:
        print("[!] 目标目录下未发现任何 .js 文件，扫描终止。")
        return

    print(f"待分析 JS 文件总计 : {len(js_files)} 个")
    print("-" * 65)

    # 2. 初始化本地任务与数据库
    project_tag = start_new_task()
    db = DatabaseType(project_tag)
    db.createDatabase()
    db.createProjectDatabase(f"offline://{dir_name}", 1, "0")

    js_finder = JsFinderModule(project_tag, options)

    # 3. 逐个文件执行深度敏感词与接口路径提取
    all_findings = {}
    all_api_paths = set()
    all_routes = set()
    scanned_count = 0
    t0 = time.time()

    for idx, filepath in enumerate(js_files, 1):
        rel_path = os.path.relpath(filepath, target_dir)
        try:
            res = js_finder.process_js_file(filepath)
            matches, unique_paths, path_mappings, routes, sm_findings, path_findings, perf_stats = res
            scanned_count += 1
            if unique_paths:
                all_api_paths.update(unique_paths)
            if routes:
                all_routes.update(routes)

            if matches:
                all_findings[rel_path] = matches
                hit_count = sum(len(v) for v in matches.values())
                print(f"[{idx}/{len(js_files)}] [HIT] 发现敏感特征: {rel_path} (共 {hit_count} 项)")
            else:
                if getattr(options, "silent", None) is None:
                    print(f"[{idx}/{len(js_files)}] [PASS] {rel_path} (发现 {len(unique_paths)} 个API接口)")
        except Exception as e:
            logger.error(f"分析文件异常 {rel_path}: {e}")

    total_time = max(time.time() - t0, 0.01)

    # 4. 统计与生成离线审计报告
    total_matches = sum(sum(len(v) for v in m.values()) for m in all_findings.values())
    report_filename = f"Finder_离线敏感信息审计报告_{dir_name}.html"
    report_path = os.path.abspath(report_filename)
    _generate_offline_html_report(report_path, target_dir, dir_name, scanned_count, all_findings, all_api_paths, all_routes, total_time)

    print("=" * 65)
    print(f"离线扫描完成: 分析 JS 文件 {scanned_count} 个 | 命中文件 {len(all_findings)} 个 | 敏感信息 {total_matches} 条")
    print(f"提取 API 接口: {len(all_api_paths)} 个 | 前端路由: {len(all_routes)} 个")
    print(f"总耗时: {total_time:.2f} 秒")
    print(f"交互式审计报告已生成: {report_path}")
    print("=" * 65)


def _generate_offline_html_report(report_path, target_dir, dir_name, scanned_count, findings, api_paths, routes, total_time):
    """生成轻量高信噪比 HTML 离线报告。"""
    total_findings_count = sum(sum(len(v) for v in m.values()) for m in findings.values())
    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Packer-InfoFinder 离线审计报告 - {html.escape(dir_name)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 20px; background: #f8f9fa; color: #333; }}
  .container {{ max-width: 1200px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
  h1 {{ color: #1a73e8; border-bottom: 2px solid #e8f0fe; padding-bottom: 12px; margin-top: 0; }}
  h2 {{ color: #202124; margin-top: 30px; border-bottom: 1px solid #dadce0; padding-bottom: 8px; }}
  .meta-box {{ display: flex; gap: 20px; background: #e8f0fe; padding: 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }}
  .meta-item {{ flex: 1; }}
  .meta-item strong {{ display: block; color: #174ea6; font-size: 16px; margin-top: 4px; }}
  .file-card {{ border: 1px solid #dadce0; border-radius: 6px; margin-bottom: 15px; overflow: hidden; }}
  .file-header {{ background: #f1f3f4; padding: 10px 15px; font-weight: bold; font-family: monospace; font-size: 13px; color: #202124; }}
  .finding-table {{ width: 100%; border-collapse: collapse; }}
  .finding-table th, .finding-table td {{ padding: 8px 12px; text-align: left; border-top: 1px solid #ebebeb; font-size: 13px; }}
  .finding-table th {{ background: #fafafa; color: #5f6368; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: #fce8e6; color: #c5221f; }}
  .val-code {{ font-family: monospace; background: #f8f9fa; padding: 2px 4px; border-radius: 3px; word-break: break-all; }}
  .path-list {{ max-height: 350px; overflow-y: auto; background: #202124; color: #8ab4f8; font-family: monospace; padding: 15px; border-radius: 6px; line-height: 1.6; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Packer-InfoFinder 离线目录敏感信息挖掘报告</h1>
  <div class="meta-box">
    <div class="meta-item">分析目录: <strong>{html.escape(dir_name)}</strong></div>
    <div class="meta-item">扫描 JS 文件: <strong>{scanned_count} 个</strong></div>
    <div class="meta-item">发现敏感信息: <strong>{total_findings_count} 条</strong></div>
    <div class="meta-item">发现 API 接口: <strong>{len(api_paths)} 个</strong></div>
    <div class="meta-item">分析耗时: <strong>{total_time:.2f} 秒</strong></div>
  </div>

  <h2>敏感信息与凭据发现</h2>
"""
    if not findings:
        html_content += "<p style='color: #1e8e3e; font-weight: bold;'>未在该目录下发现已知高风险敏感凭据与 API Key。</p>"
    else:
        for rel_path, rule_dict in findings.items():
            hit_sum = sum(len(v) for v in rule_dict.values())
            html_content += f"""
  <div class="file-card">
    <div class="file-header">文件: {html.escape(rel_path)} ({hit_sum} 条发现)</div>
    <table class="finding-table">
      <thead>
        <tr><th style="width: 25%;">规则名称</th><th style="width: 75%;">捕获凭据/特征值</th></tr>
      </thead>
      <tbody>
"""
            for rule_name, items in rule_dict.items():
                for it in items:
                    matched_val = it[0] if isinstance(it, (tuple, list)) else str(it)
                    html_content += f"""
        <tr>
          <td><span class="badge">{html.escape(str(rule_name))}</span></td>
          <td><span class="val-code">{html.escape(str(matched_val)[:200])}</span></td>
        </tr>
"""
            html_content += """
      </tbody>
    </table>
  </div>
"""

    if api_paths:
        html_content += f"""
  <h2>发现的 API 接口与后端路径 (共 {len(api_paths)} 个)</h2>
  <div class="path-list">
"""
        for p in sorted(api_paths):
            html_content += f"    <div>{html.escape(str(p))}</div>\n"
        html_content += "  </div>\n"

    html_content += """
</div>
</body>
</html>
"""
    with open(report_path, "w", encoding="utf-8") as fp:
        fp.write(html_content)
