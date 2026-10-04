# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import sys
import time
import json
import hashlib
import sqlite3
import multiprocessing
from types import SimpleNamespace
from urllib.parse import urlparse

from lib.Controller import Project
from lib.TestProxy import testProxy
from lib.report.finder_overview import (
    parse_detailed_report,
    append_to_overview_report,
    append_row_to_overview_report,
    finalize_overview_report,
)


def read_urls(file_path):
    """读取 URL 文件"""
    try:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"文件 {file_path} 不存在")

        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, IOError, PermissionError) as e:
        print(f"文件操作失败: {e}")
        sys.exit(1)


def _checkpoint_path_for_list(list_file_path):
    try:
        abs_path = os.path.abspath(list_file_path or "")
        digest = hashlib.md5(abs_path.encode("utf-8", errors="ignore")).hexdigest()[:12]
        base_dir = os.path.abspath("tmp")
        os.makedirs(base_dir, exist_ok=True)
        return os.path.join(base_dir, f".batch_checkpoint_{digest}.json")
    except Exception:
        return ""


def _load_checkpoint(checkpoint_path):
    if not checkpoint_path or not os.path.exists(checkpoint_path):
        return {"version": 1, "urls": {}, "updated_at": int(time.time())}
    try:
        with open(checkpoint_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"version": 1, "urls": {}, "updated_at": int(time.time())}
        if "urls" not in data or not isinstance(data["urls"], dict):
            data["urls"] = {}
        return data
    except Exception:
        return {"version": 1, "urls": {}, "updated_at": int(time.time())}


def _save_checkpoint(checkpoint_path, data):
    if not checkpoint_path:
        return
    tmp_path = checkpoint_path + ".tmp"
    data["updated_at"] = int(time.time())
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, checkpoint_path)


def _mark_checkpoint_status(checkpoint_data, url, status, attempts=1, error_msg=""):
    urls = checkpoint_data.setdefault("urls", {})
    row = urls.setdefault(url, {})
    row["status"] = status
    row["attempts"] = int(row.get("attempts", 0)) + int(max(1, attempts))
    if error_msg:
        row["last_error"] = str(error_msg)[:500]
    else:
        row["last_error"] = ""
    if status == "timeout":
        row["timeout_count"] = int(row.get("timeout_count", 0)) + 1
    row["finished_at"] = int(time.time())


def _compute_adaptive_timeout(base_timeout, retry_count, timeout_count):
    """
    自适应单URL超时：
    - 首次使用用户指定值
    - 重试或历史超时越多，预算越大（上限 600s）
    """
    try:
        base = int(base_timeout or 0)
        if base <= 0:
            return 0
        retry_factor = 1.0 + (0.8 * max(0, retry_count))
        history_factor = 1.0 + (0.3 * max(0, timeout_count))
        timeout_val = int(base * retry_factor * history_factor)
        timeout_val = max(base, timeout_val)
        timeout_val = min(600, timeout_val)
        return timeout_val
    except Exception:
        return int(base_timeout or 0)


def _scan_single_url_worker(options_dict, url):
    """子进程中执行单个URL的完整扫描，避免单个目标卡死影响整个批量任务。"""
    # 在子进程中重新构造一个简单的options对象，避免直接跨进程序列化optparse.Values
    opts = SimpleNamespace(**options_dict)
    opts.url = url
    Project(url, opts).parseStart()


def _terminate_process(process, join_timeout=3):
    """尽最大努力回收子进程，避免 Ctrl+C/超时后残留。"""
    if not process:
        return
    try:
        if process.is_alive():
            process.terminate()
            process.join(join_timeout)
        if process.is_alive():
            # Python 3.7+ 可用 kill，作为 terminate 失败时兜底。
            process.kill()
            process.join(1)
    except Exception:
        pass
    finally:
        try:
            if not process.is_alive():
                process.close()
        except Exception:
            pass


def run_single_url_with_timeout(options, url, timeout_seconds):
    """在子进程中执行单个URL扫描，并施加总超时时间。超时会抛出 TimeoutError。"""
    # 将optparse.Values转换为普通dict以便在子进程中重建
    options_dict = vars(options).copy()
    process = multiprocessing.Process(
        target=_scan_single_url_worker,
        args=(options_dict, url),
    )
    process.start()
    try:
        process.join(timeout_seconds)
    except KeyboardInterrupt:
        _terminate_process(process)
        raise

    if process.is_alive():
        # 超时仍未结束，强制终止子进程
        _terminate_process(process)
        raise TimeoutError(f"单个URL扫描超时（超过 {timeout_seconds} 秒）")

    # 非0退出码视为扫描失败
    if process.exitcode != 0:
        raise RuntimeError(f"子进程扫描失败，exitcode={process.exitcode}")

    _terminate_process(process)


def get_latest_project_tag_for_host(host, batch_start_ts):
    """从 main.db 中获取本次批量任务中指定主机的最新 projectTag。"""
    main_db_path = os.path.abspath(os.path.join(os.getcwd(), "main.db"))
    if not os.path.exists(main_db_path):
        return None

    try:
        conn = sqlite3.connect(main_db_path, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT tag, time FROM project WHERE host = ? AND time >= ? ORDER BY time DESC LIMIT 1",
            (host, batch_start_ts),
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None
    except Exception as e:
        print(f"[警告] 无法从 main.db 获取项目标签: {e}")
        return None


def run_batch_scan(options, is_batch_finder_scan=False, overview_report_path=None):
    """执行批量扫描编排流程。"""
    urls = read_urls(options.list)
    total_urls = len(urls)

    if total_urls == 0:
        print("[错误] URL列表文件为空或无有效URL")
        sys.exit(1)

    print(f"开始扫描 {total_urls} 个 URL...")
    print("==================================================")

    # 批量扫描配置（可根据需求调整）
    # 速度优先：max_retries=0, url_interval=0
    # 平衡模式：max_retries=1, url_interval=0.5
    # 稳定优先：max_retries=2, url_interval=1
    batch_max_retries = 1  # 重试次数：0=无重试(最快), 1=平衡, 2=稳定
    batch_url_interval = 0.5  # URL间隔(秒)：0=最快, 0.5=平衡, 1=稳定

    # URL 总超时时间（秒），由命令行参数控制：
    # - 0 或未设置：不对单个 URL 的总扫描时间做限制
    # - >0：在子进程中执行单个 URL 扫描，并施加总超时时间
    per_url_timeout = getattr(options, "url_timeout", 0) or 0

    # Finder 总览报告依赖完整重跑，避免 checkpoint 跳过造成报告缺项。
    resume_enabled = not is_batch_finder_scan
    checkpoint_path = _checkpoint_path_for_list(options.list) if resume_enabled else ""
    checkpoint_data = _load_checkpoint(checkpoint_path) if resume_enabled else {"urls": {}}

    plan = []
    resumed_success = 0
    for idx, url in enumerate(urls, 1):
        row = checkpoint_data.get("urls", {}).get(url, {})
        if row.get("status") == "success":
            resumed_success += 1
            continue
        plan.append((idx, url))

    if resume_enabled and resumed_success > 0:
        print(f"[checkpoint] 检测到历史成功记录 {resumed_success} 个，将从未完成URL继续。")

    # 记录批量任务启动时间，用于从 main.db 中区分本次扫描的记录
    batch_start_ts = int(time.time())

    # 统计变量
    success_count = 0
    error_count = 0
    for i, url in plan:
        print(f"\n[{i}/{total_urls}] 开始扫描 URL: {url}")
        print("==================================================")

        # 重试机制
        max_retries = batch_max_retries
        retry_count = 0
        scan_success = False

        while retry_count <= max_retries and not scan_success:
            try:
                if retry_count > 0:
                    print(f"[!] 第 {retry_count} 次重试...")
                    time.sleep(2 * retry_count)  # 重试前等待

                # 网络连通性测试（仅首次或重试时显示）
                if retry_count == 0 or i == 1:
                    testProxy(options, 1)

                # 根据参数决定是否对单个 URL 施加总超时时间
                if per_url_timeout and per_url_timeout > 0:
                    previous_timeout_count = 0
                    if resume_enabled:
                        row = checkpoint_data.get("urls", {}).get(url, {})
                        previous_timeout_count = int(row.get("timeout_count", 0))
                    effective_timeout = _compute_adaptive_timeout(
                        per_url_timeout,
                        retry_count,
                        previous_timeout_count,
                    )
                    # 在子进程中执行单个URL扫描，并施加总超时时间
                    run_single_url_with_timeout(options, url, effective_timeout)
                else:
                    # 不启用总超时，直接在当前进程中执行扫描
                    options_dict = vars(options).copy()
                    _scan_single_url_worker(options_dict, url)

                # 扫描成功
                scan_success = True
                success_count += 1
                if resume_enabled:
                    _mark_checkpoint_status(checkpoint_data, url, "success", attempts=retry_count + 1, error_msg="")
                    _save_checkpoint(checkpoint_path, checkpoint_data)

                if is_batch_finder_scan:
                    host = urlparse(url).netloc.replace(":", "_")
                    project_tag = get_latest_project_tag_for_host(host, batch_start_ts)

                    summary_text = ""
                    details_data = {}
                    detailed_report_path = None

                    if not project_tag:
                        summary_text = "未找到当前扫描对应的项目标签（可能扫描失败或未创建数据库）"
                    else:
                        report_dir = os.path.join("tmp", f"{project_tag}_{host}", "finder_results")
                        report_file = os.path.join(report_dir, "sensitive_info.html")

                        if os.path.exists(report_file):
                            detailed_report_path = report_file
                            summary_text, details_data = parse_detailed_report(detailed_report_path)
                        else:
                            summary_text = "未生成报告文件 (可能未发现JS或未找到敏感信息)"

                    row_html = append_to_overview_report(i, url, summary_text, details_data, detailed_report_path)
                    append_row_to_overview_report(overview_report_path, row_html)
                    print(f"[+] 已处理 {url} 的扫描结果。")

                # 批量扫描时添加间隔，避免对目标服务器造成压力
                if i < total_urls and batch_url_interval > 0:
                    time.sleep(batch_url_interval)

            except KeyboardInterrupt:
                print("\n[!] 用户中断扫描")
                if resume_enabled:
                    try:
                        _save_checkpoint(checkpoint_path, checkpoint_data)
                    except Exception:
                        pass
                if is_batch_finder_scan and overview_report_path:
                    print(f"\n[v] 已生成部分扫描结果报告: {os.path.abspath(overview_report_path)}")
                sys.exit(130)

            except Exception as e:
                retry_count += 1
                error_msg = str(e)
                is_timeout_error = isinstance(e, TimeoutError) or ("超时" in error_msg)

                # 判断是否是可重试的错误
                retryable_errors = [
                    "connection",
                    "timeout",
                    "unable to open database file",
                    "database is locked",
                    "网络",
                    "连接"
                ]

                is_retryable = any(keyword in error_msg.lower() for keyword in retryable_errors)
                if is_timeout_error:
                    is_retryable = True

                if is_retryable and retry_count <= max_retries:
                    print(f"[警告] 扫描URL {url} 时发生可恢复错误: {error_msg}")
                    print(f"[提示] 将在 {2 * retry_count} 秒后重试...")
                    continue

                # 不可重试或已达最大重试次数
                print(f"[错误] 扫描URL {url} 时发生严重错误: {error_msg}")
                error_count += 1
                if resume_enabled:
                    status = "timeout" if is_timeout_error else "failed"
                    _mark_checkpoint_status(checkpoint_data, url, status, attempts=retry_count, error_msg=error_msg)
                    _save_checkpoint(checkpoint_path, checkpoint_data)

                if is_batch_finder_scan:
                    error_summary = f"扫描失败: {error_msg}"
                    if retry_count > 0:
                        error_summary += f" (已重试{retry_count}次)"
                    row_html = append_to_overview_report(i, url, error_summary, {}, None)
                    append_row_to_overview_report(overview_report_path, row_html)
                break  # 跳出重试循环，继续下一个URL

    if resume_enabled and checkpoint_path:
        remaining = []
        for url in urls:
            row = checkpoint_data.get("urls", {}).get(url, {})
            if row.get("status") != "success":
                remaining.append(url)
        if not remaining:
            try:
                os.remove(checkpoint_path)
                print("[checkpoint] 所有URL已成功，已清理检查点文件。")
            except Exception:
                pass

    # 输出统计信息
    print("\n" + "=" * 50)
    print("批量扫描统计信息：")
    print(f"  总计URL数: {total_urls}")
    success_total = success_count + resumed_success
    print(f"  成功扫描: {success_total} ({success_total * 100 // total_urls if total_urls > 0 else 0}%)")
    print(f"  失败数量: {error_count} ({error_count * 100 // total_urls if total_urls > 0 else 0}%)")
    print("=" * 50)

    if is_batch_finder_scan and overview_report_path:
        print(f"\n[v] 所有URL扫描完毕。交互式总览报告已成功生成: {os.path.abspath(overview_report_path)}")
    else:
        print(f"\n所有 {total_urls} 个 URL 扫描完毕。")


def run_single_target_scan(options):
    """执行单目标扫描。"""
    try:
        testProxy(options, 1)
        per_url_timeout = getattr(options, "url_timeout", 0) or 0

        if per_url_timeout and per_url_timeout > 0:
            run_single_url_with_timeout(options, options.url, per_url_timeout)
        else:
            Project(options.url, options).parseStart()
    except KeyboardInterrupt:
        print("\n[!] 用户中断单目标扫描")
        sys.exit(130)
