# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
from urllib.parse import urlparse

from lib.TestProxy import testProxy
from lib.Database import DatabaseType
from lib.DownloadJs import DownloadJs
from lib.recover_split import RecoverSplit
from lib.JsFinder.JsFinderModule import JsFinderModule
from lib.common.create_log import creatLog, start_new_task, get_current_log_name


def run_js_only_scan(options):
    """仅基于 -j 指定的 JS URL 进行分析，不访问入口 HTML。"""
    js_value = getattr(options, "js", "") or ""
    js_value = js_value.strip()
    if not js_value:
        print("[!] -j 参数为空，未指定 JS URL")
        return

    js_urls = [u.strip() for u in js_value.split(",") if u.strip()]
    if not js_urls:
        print("[!] 未能从 -j 参数中解析出有效的 JS URL")
        return

    primary_js_url = js_urls[0]
    parsed = urlparse(primary_js_url)
    if not parsed.scheme or not parsed.netloc:
        print(f"[!] 无效的 JS URL：{primary_js_url}")
        return

    # 如果 options.url 为空，则默认填充为 primary_js_url，方便后续模块复用 host / referer 等逻辑
    if getattr(options, "url", None) is None:
        options.url = primary_js_url

    # 网络连通性检测
    testProxy(options, 1)

    # 为 JS-only 模式显式分配新的 projectTag，避免复用同进程旧任务标签
    project_tag = start_new_task()

    db = DatabaseType(project_tag)
    db.createDatabase()
    # 为 JS-only 模式创建一个项目记录，type 固定为 1，cloneTag 为 "0"
    db.createProjectDatabase(primary_js_url, 1, "0")

    logger = creatLog().get_logger()

    # 计算缓存数据库路径
    project_path = db.getPathfromDB()
    if project_path:
        db_path = os.path.abspath(os.path.join(project_path, f"{project_tag}.db"))
        logger.info("[+] 缓存文件路径：" + db_path)
    logger.info("[+] 日志文件路径：" + os.path.abspath(get_current_log_name()))

    # 1) 先下载指定的 JS 文件
    host = parsed.netloc.replace(":", "_")
    downloader = DownloadJs(js_urls, options)
    downloader.downloadJs(project_tag, host, 0)

    # 2) 再进行 JS 代码拆分 / 还原分析（分析已下载的文件）
    RecoverSplit(project_tag, options).recoverStart()

    # 可选：敏感信息扫描
    if getattr(options, "finder", False):
        js_finder = JsFinderModule(project_tag, options)
        js_finder.start_scan()

    logger.info("[v] JS URL 分析完成")

