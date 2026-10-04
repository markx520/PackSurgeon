#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
整站下载脚本 - 基于 Playwright 网络拦截

功能：
  - 以有头浏览器（可视）启动，手动登录后按回车开始抓取
  - 拦截所有 HTML / JS / CSS / JSON 响应并保存到本地
  - 自动点击页面链接/菜单，触发 SPA 路由和异步 chunk 加载
  - 按域名 + URL 路径结构保存文件
  - 按需控制前端资源下载（支持 --no-assets 跳过全部前端资源，或通过 --asset-types 精细化指定类型）

用法：
  python site_downloader.py -u https://example.com
  python site_downloader.py -u https://example.com -o ./output
  python site_downloader.py -u https://example.com --no-assets        # 仅抓取API报文，跳过前端所有静态文件(HTML/JS/CSS/JSON)
  python site_downloader.py -u https://example.com --asset-types js,css # 仅抓取JS和CSS文件，跳过HTML/JSON
  python site_downloader.py -u https://example.com -i                 # 纯交互模式（前台手动操作）
  python site_downloader.py -u https://example.com --headless         # 无头模式（已有Cookie时）
  python site_downloader.py -u https://example.com -c "key=val;k2=v2" # 注入Cookie
  python site_downloader.py -u https://example.com --depth 3          # 链接探索深度
  python site_downloader.py -u https://example.com --wait 8           # 每页等待秒数
"""

import os
import sys
import re
import json
import argparse
import hashlib
import time
import select
import shutil
import subprocess
from urllib.parse import urlparse, urljoin, unquote

# 强制标准输出启用行缓冲与 UTF-8，确保在 IDE 后台与管道中实时推送日志
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)
        sys.stderr.reconfigure(encoding='utf-8', line_buffering=True)
except Exception:
    pass


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Playwright 整站下载工具（HTML + JS + CSS + JSON）")
    parser.add_argument("-u", "--url", required=True, help="目标站点入口 URL")
    parser.add_argument("-o", "--output", default="site_download", help="输出目录（默认: site_download）")
    parser.add_argument("-c", "--cookie", default=None, help="Cookie 字符串（格式: key=val;key2=val2）")
    parser.add_argument("--headless", action="store_true", default=False, help="无头模式（默认有头，方便手动登录）")
    parser.add_argument("--depth", type=int, default=2, help="链接探索最大深度（默认: 2）")
    parser.add_argument("--wait", type=int, default=5, help="每个页面等待动态加载的秒数（默认: 5）")
    parser.add_argument("--timeout", type=int, default=30, help="页面导航超时秒数（默认: 30）")
    parser.add_argument("--no-explore", action="store_true", default=False, help="禁用自动链接探索，只抓取入口页面的资源")
    parser.add_argument("--pages", default=None, help="登录后额外访问的页面路径（逗号分隔），如: /sqsp/view/dksq/invoice-agent-apply,/another/page")
    parser.add_argument("-i", "--interactive", action="store_true", default=False, help="纯交互模式：打开浏览器由用户完全手动操作，关闭自动结束")
    parser.add_argument("--no-proxy", action="store_true", default=False, help="禁用系统/本地代理，直连目标网站")
    parser.add_argument("-p", "--proxy", default=None, help="指定 HTTP/SOCKS5 代理服务器地址（如: http://127.0.0.1:7890）")
    parser.add_argument("--engine", choices=["auto", "camoufox", "patchright", "chrome"], default="auto", help="指定浏览器内核（默认: auto 智能自适应匹配；可选: camoufox 顶尖C++魔改隐身内核, patchright 无痕Chromium内核, chrome 原生Playwright内核）")
    parser.add_argument("--cdp", default=None, help="CDP 远程调试地址 (如: http://localhost:9222)，接管现有的 Chrome")
    parser.add_argument("--mobile", action="store_true", default=False, help="强制启用移动端指纹仿真（iPhone/Android UA + 触摸事件 + 移动端视口）")
    parser.add_argument("--user-data-dir", default=None, help="指定 Chrome 用户数据目录（使用真实持久化 Profile 替代默认无痕冷启动）")
    parser.add_argument("--no-assets", "--api-only", action="store_true", dest="no_assets", default=False, help="按需跳过前端所有静态资源下载（HTML/JS/CSS/JSON），仅录制 API 动态接口报文至 _api_records/")
    parser.add_argument("--asset-types", default="all", help="按需指定下载的前端资源类型（逗号分隔，可选: all, js, html, css, json；默认: all）")
    parser.add_argument("--no-api", action="store_true", default=False, help="禁用 API 接口报文录制，仅抓取前端静态资源")
    parser.add_argument("--no-crack", action="store_true", default=False, help="下载完成后跳过自动 AST 语法脱壳与微创提纯")
    return parser.parse_args(args)


# ──────────────────── 文件保存逻辑 ────────────────────

def url_to_local_path(url, output_dir):
    """将 URL 转换为本地文件路径，保持域名+路径的目录结构。"""
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_")
    path = unquote(parsed.path).strip("/")

    if not path:
        path = "index.html"
    elif path.endswith("/"):
        path = path + "index.html"

    # 移除查询参数中不适合做文件名的字符，但保留短 query 以区分同路径文件
    if parsed.query:
        safe_query = re.sub(r'[<>:"|?*\\]', '_', parsed.query)[:60]
        query_hash = hashlib.md5(parsed.query.encode()).hexdigest()[:8]
        base, ext = os.path.splitext(path)
        if ext:
            path = f"{base}_q{query_hash}{ext}"
        else:
            path = f"{path}_q{query_hash}"

    # 清理非法文件名字符（Windows 兼容）
    path = re.sub(r'[<>:"|?*]', '_', path)

    # 确保文件有合理的扩展名
    _, ext = os.path.splitext(path)
    if not ext:
        path += ".html"

    return os.path.join(output_dir, host, path)


def save_content(local_path, content):
    """保存内容到本地文件。"""
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    encoding = None if isinstance(content, bytes) else "utf-8"
    with open(local_path, mode, encoding=encoding) as f:
        f.write(content)


# ──────────────────── 资源类型判断与黑名单过滤 ────────────────────

# 需要拦截保存的 Content-Type
INTERCEPT_TYPES = {
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/json",
    "text/json",
    "text/css",
}

# 文件扩展名兜底判断
INTERCEPT_EXTENSIONS = {".js", ".html", ".htm", ".json", ".mjs", ".css"}

# 过滤黑名单：忽略的域名与 URL 特征（如 Google 翻译插件、沉浸式翻译等，避免重复抓取污染与占用本地磁盘）
IGNORE_DOMAIN_SUFFIXES = (
    "translate.google.com",
    "translate.googleapis.com",
    "translate-pa.googleapis.com",
    "translate.google.cn",
    "translate.gstatic.com",
    "translate.googleusercontent.com",
    "api.immersivetranslate.com",
    "fanyi.baidu.com",
    "fanyi.youdao.com",
    "api.cognitive.microsofttranslator.com",
    "edge.microsoft.com",
)

IGNORE_URL_PATTERNS = (
    "/translate_a/",
    "/translate_static/",
    "/translate_http/",
    "/translate_element/",
    "translate.js",
    "element.js?cb=googleTranslate",
    "google-translate",
)


def is_ignored_translation_url(url: str) -> bool:
    """判断 URL 是否属于需排除的翻译/噪音插件请求。"""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        # 1. 匹配域名黑名单
        for domain in IGNORE_DOMAIN_SUFFIXES:
            if host == domain or host.endswith("." + domain):
                return True

        # 2. 匹配路径特征
        url_lower = url.lower()
        for pattern in IGNORE_URL_PATTERNS:
            if pattern in url_lower:
                return True

        return False
    except Exception:
        return False


def should_intercept(response):
    """判断是否需要作为静态文件拦截该响应。"""
    url = response.url

    # 0. 优先排除翻译插件与噪音黑名单
    if is_ignored_translation_url(url):
        return False

    content_type = response.headers.get("content-type", "")

    # 跳过 data: / blob: / chrome-extension: 等特殊协议
    if not url.startswith("http"):
        return False

    # 按 Content-Type 判断
    ct_lower = content_type.lower().split(";")[0].strip()
    if ct_lower in INTERCEPT_TYPES:
        return True

    # 按扩展名兜底
    path = urlparse(url).path.lower()
    _, ext = os.path.splitext(path.split("?")[0])
    if ext in INTERCEPT_EXTENSIONS:
        return True

    return False


# ──────────────────── API 接口请求与响应报文录制 ────────────────────

STATIC_MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".ogg", ".flv", ".avi", ".wav", ".m3u8", ".ts", ".map"
}

def is_api_traffic(request, response) -> bool:
    """判断当前请求是否属于需要独立保存请求文和响应文原文的 API 接口。"""
    try:
        url = response.url
        method = request.method.upper()
        resource_type = getattr(request, "resource_type", "") or ""
        content_type = response.headers.get("content-type", "").lower()

        # 0. 协议与翻译插件过滤
        if not url.startswith("http"):
            return False
        if is_ignored_translation_url(url):
            return False

        parsed = urlparse(url)
        path = parsed.path.lower()
        _, ext = os.path.splitext(path)

        # 1. 严格排除静态多媒体与样式文件
        if ext in STATIC_MEDIA_EXTENSIONS:
            return False
        if resource_type in ("image", "stylesheet", "font", "media", "texttrack"):
            return False
        if any(content_type.startswith(prefix) for prefix in ("image/", "text/css", "font/", "audio/", "video/")):
            return False

        # 2. 排除纯静态 JS 脚本请求（由静态下载流程捕获并由 webcrack 解密）
        if method == "GET" and resource_type == "script" and ext in (".js", ".mjs"):
            # 若 URL 带有动态 API 接口特征，依然作为 API 捕获
            if not any(k in path for k in ("/api/", "/ajax/", "/service/", "/v1/", "/v2/", "/v3/")) and "callback=" not in parsed.query:
                return False

        # 3. 排除普通静态 HTML 主文档导航（POST 表单除外）
        if method == "GET" and resource_type == "document" and ext in (".html", ".htm", "") and not parsed.query:
            if not any(k in path for k in ("/api/", "/service/", "/gateway/", "/rest/")):
                return False

        # 4. 判定为 API 接口的决定性特征
        if method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            return True
        if resource_type in ("xhr", "fetch"):
            return True
        if any(ct in content_type for ct in ("application/json", "text/json", "application/xml", "text/xml", "application/graphql", "application/x-www-form-urlencoded", "application/octet-stream", "application/grpc")):
            return True
        if any(k in path for k in ("/api/", "/service/", "/ajax/", "/gateway/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql", "/auth/", "/login", "/oauth", "/ticket", "/shunt", "/query", "/action", "/submit")):
            return True

        return False
    except Exception:
        return False


# 过滤高 Token 消耗且零逆向价值的浏览器默认噪音 Header
DROP_REQ_HEADERS = {
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "sec-fetch-storage-access",
    "accept-encoding", "accept-language", "priority", "connection", "upgrade-insecure-requests"
}

DROP_RESP_HEADERS = {
    "transfer-encoding", "connection", "vary", "alt-svc", "strict-transport-security",
    "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-expose-headers"
}

def clean_headers(headers: dict, drop_set: set) -> dict:
    return {k: v for k, v in headers.items() if k.lower() not in drop_set}


def save_api_record(request, response, output_dir, api_seq_counter, api_index_entries):
    """将单个 API 请求的完整请求文和响应文原文保存为极致紧凑且高信噪比的独立 .http 文件。"""
    try:
        api_seq_counter[0] += 1
        seq_id = api_seq_counter[0]

        url = request.url
        method = request.method.upper()
        resource_type = getattr(request, "resource_type", "") or "unknown"
        req_headers = dict(request.headers)
        req_body = request.post_data or ""

        resp_status = response.status
        resp_status_text = response.status_text or ""
        resp_headers = dict(response.headers)
        resp_body_bytes = b""
        try:
            resp_body_bytes = response.body() or b""
        except Exception:
            pass

        records_dir = os.path.join(output_dir, "_api_records")
        os.makedirs(records_dir, exist_ok=True)

        parsed = urlparse(url)
        host = (parsed.hostname or "unknown").replace(":", "_")
        path_slug = re.sub(r'[^\w\-]', '_', parsed.path.strip('/'))[:45]
        if not path_slug:
            path_slug = "root"

        file_base = f"{seq_id:04d}_{method}_{host}_{path_slug}"
        http_path = os.path.join(records_dir, f"{file_base}.http")

        # 过滤噪音 Headers
        clean_req_h = clean_headers(req_headers, DROP_REQ_HEADERS)
        clean_resp_h = clean_headers(resp_headers, DROP_RESP_HEADERS)

        # 紧凑处理请求体
        req_body_str = req_body if isinstance(req_body, str) else req_body.decode('utf-8', errors='replace')
        if req_body_str:
            try:
                req_json = json.loads(req_body_str)
                req_body_display = json.dumps(req_json, ensure_ascii=False)
            except Exception:
                req_body_display = req_body_str.strip()
        else:
            req_body_display = ""

        # 紧凑处理响应体
        resp_body_str = ""
        if resp_body_bytes:
            try:
                resp_body_str = resp_body_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    resp_body_str = resp_body_bytes.decode('gbk')
                except Exception:
                    resp_body_str = f"[Binary data: {len(resp_body_bytes)} bytes]"

        if resp_body_str and not resp_body_str.startswith("[Binary data"):
            try:
                resp_json = json.loads(resp_body_str)
                resp_body_display = json.dumps(resp_json, ensure_ascii=False)
            except Exception:
                resp_body_display = resp_body_str.strip()
        else:
            resp_body_display = resp_body_str.strip()

        curr_time = time.strftime('%Y-%m-%d %H:%M:%S')

        # 写入高信噪比、极省 Token 的标准 .http 报文
        query_part = f"?{parsed.query}" if parsed.query else ""
        path_part = parsed.path or "/"

        lines = [
            f"### #{seq_id:04d} [{curr_time}] {method} {url} [{resp_status} {resp_status_text}]",
            f">>> REQUEST >>>",
            f"{method} {path_part}{query_part} HTTP/1.1",
            f"Host: {parsed.netloc}"
        ]
        for k, v in sorted(clean_req_h.items()):
            if k.lower() != "host":
                lines.append(f"{k}: {v}")
        if req_body_display:
            lines.append("")
            lines.append(req_body_display)

        lines.append("")
        lines.append("<<< RESPONSE <<<")
        lines.append(f"HTTP/1.1 {resp_status} {resp_status_text}")
        for k, v in sorted(clean_resp_h.items()):
            lines.append(f"{k}: {v}")
        if resp_body_display:
            lines.append("")
            lines.append(resp_body_display)

        content = "\n".join(lines) + "\n"
        with open(http_path, "w", encoding="utf-8") as f:
            f.write(content)

        # 记录索引
        index_line = f"| #{seq_id:04d} | `{curr_time}` | `{method}` | `{resp_status} {resp_status_text}` | `{resource_type}` | `{url}` | [`{file_base}.http`](file:///{http_path.replace(chr(92), '/')} ) |\n"
        api_index_entries.append(index_line)

        # 追加写入总索引文件 _api_index.md
        index_file = os.path.join(records_dir, "_api_index.md")
        if not os.path.exists(index_file):
            with open(index_file, "w", encoding="utf-8") as f:
                f.write("# 捕获的 API 接口请求与响应报文总索引\n\n")
                f.write("| 序号 | 捕获时间 | 请求方法 | 响应状态 | 资源类型 | 请求 URL | 抓包详情文件 |\n")
                f.write("| :---: | :---: | :---: | :---: | :---: | :--- | :--- |\n")
        
        with open(index_file, "a", encoding="utf-8") as f:
            f.write(index_line)

        # 实时打印提示
        display_url = url if len(url) <= 85 else url[:82] + "..."
        print(f"  [API] [#{seq_id:04d}] {method} {resp_status} {display_url}", flush=True)

    except Exception:
        pass


# ──────────────────── Cookie 注入 ────────────────────

def inject_cookies(context, cookie_string, url):
    """将 Cookie 字符串注入浏览器上下文。"""
    if not cookie_string:
        return

    parsed = urlparse(url)
    domain = parsed.hostname
    cookies = []
    for pair in cookie_string.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, _, value = pair.partition("=")
        cookies.append({
            "name": name.strip(),
            "value": value.strip(),
            "domain": domain,
            "path": "/",
            "httpOnly": False,
            "secure": url.startswith("https"),
        })

    if cookies:
        context.add_cookies(cookies)
        print(f"[Cookie] 已注入 {len(cookies)} 个 Cookie")


# ──────────────────── 链接提取 ────────────────────

def extract_links(page, base_url):
    """从当前页面提取所有同域链接。"""
    try:
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        links = page.evaluate("""() => {
            const anchors = document.querySelectorAll('a[href]');
            return Array.from(anchors).map(a => a.href).filter(h => h && h.startsWith('http'));
        }""")

        same_domain_links = []
        for link in links:
            parsed_link = urlparse(link)
            if parsed_link.netloc == base_domain:
                # 去掉 fragment
                clean = link.split("#")[0]
                if clean:
                    same_domain_links.append(clean)

        return list(set(same_domain_links))
    except Exception:
        return []


# ──────────────────── 非阻塞键盘检测 ────────────────────

def check_enter_pressed():
    """非阻塞检测用户是否按了回车键（跨平台兼容）。"""
    try:
        if sys.platform == 'win32':
            import msvcrt
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ('\r', '\n'):
                    return True
            return False
        else:
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                sys.stdin.readline()
                return True
            return False
    except Exception:
        return False


def select_browser_engine(target_url, engine_arg, cdp_arg):
    """
    智能自适应选择最佳浏览器引擎：
    - 若指定了 cdp，则走 CDP 零侵入真实浏览器接管模式；
    - 若显式指定了 camoufox / patchright / chrome，直接使用用户指定的引擎；
    - 若为 auto（默认），根据目标 URL 风控与业务特征智能推导。
    """
    if cdp_arg:
        return "cdp", "用户指定了 CDP 调试地址，启用真实已有浏览器接管模式"

    if engine_arg and engine_arg != "auto":
        return engine_arg, f"用户显式指定浏览器引擎: {engine_arg}"

    url_lower = target_url.lower()

    # 1. 票务、秒杀、人机验证（Cloudflare 5秒盾/Turnstile, Kasada, DataDome, 极验等）
    high_anti_bot_keywords = [
        "ticket", "ticketing", "booking", "concert", "show",
        "cloudflare", "turnstile", "kasada", "datadome", "perimeterx",
        "geetest", "recaptcha", "hcaptcha", "captcha", "challenge",
        "claude", "anthropic", "openai", "chatgpt"
    ]
    if any(k in url_lower for k in high_anti_bot_keywords):
        return "camoufox", "检测到高防票务/风控人机验证特征，匹配 Camoufox C++ 顶级魔改抗检测内核（CreepJS满分）"

    # 2. 移动端/H5 专属业务（需严密硬件与触摸屏仿真）
    if any(k in url_lower for k in ("//m.", "mobile.", "h5.", "/h5/", "/wap/")):
        return "camoufox", "检测到移动端/H5业务形态，匹配 Camoufox 真实硬件指纹与触控模型"

    # 3. 复杂现代企业应用、电商大厂、SSO 认证、Google/社交生态（需严密 Chrome V8 特性且防 CDP 泄漏）
    patchright_keywords = [
        "taobao", "tmall", "jd.com", "douyin", "kuaishou", "xiaohongshu", "alipay",
        "google", "apple", "microsoft", "wechat", "weixin", "sso", "login", "admin", "oauth",
        "zhihu", "bilibili", "weibo", "feishu", "dingtalk"
    ]
    if any(k in url_lower for k in patchright_keywords):
        return "patchright", "检测到大型现代Web应用/生态SSO体系，匹配 Patchright Chromium 驱动级无痕防检测内核"

    # 4. 政府公开信息、高校科研、公共资讯与普通文档类网站
    if any(k in url_lower for k in (".gov.cn", ".edu.cn", "news", "doc", "wiki", "portal", "info")):
        return "chrome", "检测到公共政企/文档/资讯类常规站点，采用高兼容性 Chrome 原生 Playwright 内核"

    # 默认兜底：推荐使用 Patchright 进行兼顾隐身与 Chrome 兼容性的安全探测
    return "patchright", "通用站点自适应安全探测，默认选用 Patchright Chromium 驱动级防检测内核"


# ──────────────────── 主流程 ────────────────────

def main(argv=None):
    args = parse_args(argv)

    target_url = args.url
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # 下载统计
    saved_files = {}
    saved_count = {"html": 0, "js": 0, "css": 0, "json": 0, "other": 0}
    visited_urls = set()
    url_queue = [(target_url, 0)]
    browse_phase_count = [0]
    api_seq_counter = [0]
    api_index_entries = []

    # 前端静态资源按需下载策略解析
    enabled_asset_types = set()
    if not args.no_assets:
        if args.asset_types.lower() == "all":
            enabled_asset_types = {"html", "js", "css", "json", "other"}
        else:
            for t in args.asset_types.lower().split(","):
                t = t.strip()
                if t in ("html", "htm"): enabled_asset_types.add("html")
                elif t in ("js", "mjs", "javascript"): enabled_asset_types.add("js")
                elif t in ("css", "style", "stylesheet"): enabled_asset_types.add("css")
                elif t in ("json",): enabled_asset_types.add("json")
                elif t in ("other",): enabled_asset_types.add("other")

    print("═" * 60)
    if args.no_assets or not enabled_asset_types:
        print("  [静态资源策略] 前端资源下载: 【已跳过 (--no-assets / --api-only 纯接口录制模式)】")
    else:
        types_desc = ", ".join(sorted(t.upper() for t in enabled_asset_types))
        print(f"  [静态资源策略] 前端资源下载: 【已启用 (按需匹配: {types_desc})】")

    if args.no_api:
        print("  [接口录制策略] 动态 API 录制: 【已禁用 (--no-api)】")
    else:
        print("  [接口录制策略] 动态 API 录制: 【已启用 (独立录制至 _api_records/ 目录)】")
    print("═" * 60)

    def on_response(response):
        """响应拦截回调。"""
        try:
            req = response.request
            # 1. 动态 API 接口报文录制 (如果未被 --no-api 禁用)
            if not args.no_api and is_api_traffic(req, response):
                save_api_record(req, response, output_dir, api_seq_counter, api_index_entries)

            # 2. 按需决定是否下载前端静态资源
            if args.no_assets or not enabled_asset_types:
                return

            if response.status < 200 or response.status >= 400 or not should_intercept(response):
                return
            url = response.url
            if url in saved_files:
                return

            # 根据资源扩展名判定具体类型
            path_part = urlparse(url).path.split("?")[0].lower()
            ext = os.path.splitext(path_part)[1]
            tag_type = (
                "html" if ext in (".html", ".htm")
                else ("js" if ext in (".js", ".mjs")
                else ("css" if ext == ".css"
                else ("json" if ext == ".json"
                else "other")))
            )

            # 严格按需类型过滤
            if tag_type not in enabled_asset_types:
                return

            body = response.body()
            if not body:
                return
            local_path = url_to_local_path(url, output_dir)
            save_content(local_path, body)
            saved_files[url] = local_path
            tag = (
                "HTML" if tag_type == "html"
                else (" JS " if tag_type == "js"
                else ("CSS " if tag_type == "css"
                else ("JSON" if tag_type == "json"
                else "FILE")))
            )
            saved_count[tag_type] += 1
            browse_phase_count[0] += 1
            display_url = url if len(url) <= 90 else url[:87] + "..."
            print(f"  [{tag}] [累计:{sum(saved_count.values())}] {display_url}", flush=True)
        except Exception:
            pass

    is_mobile = args.mobile or any(k in target_url.lower() for k in ("//m.", "mobile.", "h5.", "/h5/", "/wap/"))
    if is_mobile:
        print("[*] 检测到移动端/H5目标，已开启【移动端视口与触摸事件仿真】（390x844 视口 + Touch 支持）")

    # 智能引擎决策
    active_engine, reason = select_browser_engine(target_url, args.engine, args.cdp)
    print("═" * 60)
    print(f"  [浏览器内核适配] 选定模式: 【{active_engine.upper()}】")
    print(f"  [适配决策依据] {reason}")
    print("═" * 60)

    # 1. CDP 远程接管模式
    if active_engine == "cdp":
        from playwright.sync_api import sync_playwright
        print(f"[*] 正在尝试通过 CDP 连接至远程浏览器: {args.cdp}")
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp(args.cdp)
            context = browser.contexts[0] if len(browser.contexts) > 0 else browser.new_context()
            safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)

    # 2. Patchright 驱动级防检测 Chromium 模式
    elif active_engine == "patchright":
        print("[*] 正在启动【Patchright 驱动级无痕 Chromium/Chrome 内核】（抹除CDP泄漏 / 真实V8引擎）...")
        from patchright.sync_api import sync_playwright as patchright_sync
        with patchright_sync() as p:
            browser_args = ["--ignore-certificate-errors", "--start-maximized"]
            if args.no_proxy: browser_args.append("--proxy-server=direct://")
            elif args.proxy: browser_args.append(f"--proxy-server={args.proxy}")
            context_kwargs = {
                "ignore_https_errors": True,
                "viewport": {"width": 390, "height": 844} if is_mobile else None,
                "is_mobile": is_mobile,
                "has_touch": is_mobile
            }
            if is_mobile:
                context_kwargs["user_agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

            if args.user_data_dir:
                print(f"[*] 使用持久化 Chrome 用户目录: {args.user_data_dir}")
                context = p.chromium.launch_persistent_context(os.path.abspath(args.user_data_dir), channel="chrome", headless=args.headless, args=browser_args, **context_kwargs)
                browser = None
            else:
                browser = p.chromium.launch(channel="chrome", headless=args.headless, args=browser_args)
                context = browser.new_context(**context_kwargs)
            safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)

    # 3. Chrome 原生 Playwright 传统模式
    elif active_engine == "chrome":
        print("[*] 正在启动【Chrome 原生 Playwright 内核】（经典兼容模式）...")
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser_args = ["--ignore-certificate-errors", "--disable-blink-features=AutomationControlled", "--start-maximized"]
            if args.no_proxy: browser_args.append("--proxy-server=direct://")
            elif args.proxy: browser_args.append(f"--proxy-server={args.proxy}")
            context_kwargs = {
                "ignore_https_errors": True,
                "viewport": {"width": 390, "height": 844} if is_mobile else None,
                "is_mobile": is_mobile,
                "has_touch": is_mobile
            }
            if is_mobile:
                context_kwargs["user_agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

            if args.user_data_dir:
                print(f"[*] 使用持久化 Chrome 用户目录: {args.user_data_dir}")
                context = p.chromium.launch_persistent_context(os.path.abspath(args.user_data_dir), channel="chrome", headless=args.headless, args=browser_args, **context_kwargs)
                browser = None
            else:
                browser = p.chromium.launch(channel="chrome", headless=args.headless, args=browser_args)
                context = browser.new_context(**context_kwargs)
            safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)

    # 4. Camoufox 顶尖 C++ 魔改隐身引擎
    else:
        print("[*] 正在启动【Camoufox C++魔改抗检测隐身浏览器】（CreepJS满分 / 零webdriver / 沙盒化JS隔离）...")
        camoufox_launched = False
        try:
            from camoufox.sync_api import Camoufox
            camoufox_options = {
                "headless": args.headless,
                "os": "windows",
                "locale": "zh-CN",
                "humanize": True,
                "i_know_what_im_doing": True
            }
            if args.proxy and not args.no_proxy:
                camoufox_options["proxy"] = {"server": args.proxy}

            with Camoufox(**camoufox_options) as browser:
                context_kwargs = {
                    "ignore_https_errors": True,
                }
                if is_mobile:
                    context_kwargs["viewport"] = {"width": 390, "height": 844}
                    context_kwargs["has_touch"] = True

                context = browser.new_context(**context_kwargs)
                camoufox_launched = True
                safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)
        except Exception as e:
            if not camoufox_launched:
                print(f"\n[!] Camoufox C++ 引擎启动受阻: {e}")
                print("[*] 正在自动平滑切换至【Patchright 驱动级无痕 Chromium】内核继续接管抓取...")
                from patchright.sync_api import sync_playwright as patchright_sync
                with patchright_sync() as p:
                    browser_args = ["--ignore-certificate-errors", "--start-maximized"]
                    if args.no_proxy: browser_args.append("--proxy-server=direct://")
                    elif args.proxy: browser_args.append(f"--proxy-server={args.proxy}")
                    context_kwargs = {
                        "ignore_https_errors": True,
                        "viewport": {"width": 390, "height": 844} if is_mobile else None,
                        "is_mobile": is_mobile,
                        "has_touch": is_mobile
                    }
                    if is_mobile:
                        context_kwargs["user_agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

                    if args.user_data_dir:
                        print(f"[*] 使用持久化 Chrome 用户目录: {args.user_data_dir}")
                        context = p.chromium.launch_persistent_context(os.path.abspath(args.user_data_dir), channel="chrome", headless=args.headless, args=browser_args, **context_kwargs)
                        browser = None
                    else:
                        browser = p.chromium.launch(channel="chrome", headless=args.headless, args=browser_args)
                        context = browser.new_context(**context_kwargs)
                    safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)
            else:
                raise

    # ── 统计输出 ──
    total = sum(saved_count.values())
    _print_summary(saved_count, total, len(visited_urls), api_seq_counter[0], output_dir, args.no_assets)
    _save_manifest(saved_files, target_url, total, output_dir, args.no_assets)

    # ── 阶段 5：自动端到端 AST 解混淆与微创提纯流水线 ──
    if not args.no_crack and not args.no_assets and saved_count.get("js", 0) > 0:
        _trigger_auto_deobfuscate(output_dir)

def get_active_page(context):
    """获取当前可用的活动页面，若所有页面均已关闭则返回 None。"""
    try:
        alive = [p for p in context.pages if not p.is_closed()]
        return alive[0] if alive else None
    except Exception:
        return None


def run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response):
    """运行统一的浏览器交互与抓取探索主流程。"""
    # 注入 Cookie
    inject_cookies(context, args.cookie, target_url)

    # 监听所有新弹出的标签页
    context.on("page", lambda new_page: new_page.on("response", on_response))
    
    # 针对当前上下文已经存在的页面进行追溯挂载
    for p_page in context.pages:
        p_page.on("response", on_response)

    page = get_active_page(context) or (context.new_page() if not context.pages else context.pages[0])

    if args.interactive:
        print("\n[+] 纯交互模式已启动：隐身浏览器已打开！")
        print("[+] 已经开启全局抓包，您点击弹出的任何新标签页都会被自动监听拦截。")
        print("[+] 抓取结束后，【关闭所有浏览器窗口】，程序即可自动结算并退出。\n")
        try:
            page.goto(target_url, wait_until="domcontentloaded", timeout=args.timeout * 1000)
        except Exception as e:
            print(f"[警告] 页面初始加载状态: {e}")
        
        # 持续等待直到用户关闭所有浏览器标签页
        while True:
            try:
                alive_pages = [p for p in context.pages if not p.is_closed()]
                if len(alive_pages) == 0:
                    break
                alive_pages[0].wait_for_timeout(500)
            except Exception:
                break
        
        print("\n[!] 检测到浏览器已关闭，结束抓取流程。")
        try:
            if browser:
                browser.close()
            else:
                context.close()
        except:
            pass
        return

    # ── 阶段 1：首页加载 ──
    print(f"\n[1/4] 正在加载入口页面...")
    try:
        page.goto(target_url, wait_until="networkidle", timeout=args.timeout * 1000)
    except Exception as e:
        print(f"[警告] 页面加载超时或出错: {e}")
        print("[提示] 将继续处理已加载的资源...")

    # ── 阶段 2：等待用户登录 ──
    if not args.headless and not args.cookie:
        print("────────────────────────────────────────────────────────────")
        print("  [操作提示] 浏览器已打开，若需登录请在浏览器中完成操作")
        print("  操作完成后，回到此终端按 [回车] 进入下一步（若已关闭窗口将直接结算）...")
        print("────────────────────────────────────────────────────────────")
        input()

        page = get_active_page(context)
        if not page:
            print("[!] 检测到浏览器窗口已被关闭，跳过后续探索直接结算。")
            return

        print("[+] 正在重新加载首页以刷新登录态资源...")
        # 登录后重新加载页面以触发资源加载
        try:
            page.goto(target_url, wait_until="networkidle", timeout=args.timeout * 1000)
        except Exception:
            pass

    # 等待动态资源加载
    print(f"\n[2/4] 等待动态资源加载（{args.wait} 秒）...")
    page = get_active_page(context)
    if not page:
        print("[!] 浏览器已关闭，结束抓取。")
        return

    try:
        page.wait_for_timeout(args.wait * 1000)
    except Exception:
        print("[!] 页面等待超时或浏览器已关闭，跳过后续探索。")
        return

    # 尝试滚动页面触发懒加载
    try:
        page = get_active_page(context)
        if page:
            page.evaluate("""async () => {
                const delay = ms => new Promise(r => setTimeout(r, ms));
                const height = document.body.scrollHeight;
                for (let i = 0; i < height; i += 400) {
                    window.scrollTo(0, i);
                    await delay(200);
                }
                window.scrollTo(0, 0);
            }""")
            page.wait_for_timeout(2000)
    except Exception:
        pass

    visited_urls.add(target_url)

    # ── 阶段 2.5：自动访问额外指定页面（--pages） ──
    if args.pages:
        extra_paths = [p.strip() for p in args.pages.split(",") if p.strip()]
        if extra_paths:
            print(f"\n[2.5/4] 自动访问 {len(extra_paths)} 个额外业务页面...")
            parsed_base = urlparse(target_url)
            for idx, path in enumerate(extra_paths, 1):
                page = get_active_page(context)
                if not page:
                    print("[!] 浏览器已关闭，终止额外页面访问。")
                    return
                if path.startswith("http"):
                    extra_url = path
                else:
                    extra_url = f"{parsed_base.scheme}://{parsed_base.netloc}{path}"

                print(f"\n  📄 [{idx}/{len(extra_paths)}] 访问: {extra_url}")
                visited_urls.add(extra_url)
                try:
                    page.goto(extra_url, wait_until="networkidle", timeout=args.timeout * 1000)
                    page.wait_for_timeout(args.wait * 1000)

                    page.evaluate("""async () => {
                        const delay = ms => new Promise(r => setTimeout(r, ms));
                        for (let i = 0; i < document.body.scrollHeight; i += 400) {
                            window.scrollTo(0, i);
                            await delay(200);
                        }
                        window.scrollTo(0, 0);
                    }""")
                    page.wait_for_timeout(2000)

                    count_now = sum(saved_count.values())
                    print(f"  ✅ 完成，当前累计 {count_now} 个文件")
                except Exception as e:
                    if "Target page, context or browser has been closed" in str(e) or "Target closed" in str(e):
                        print("[!] 浏览器已关闭，终止额外页面访问。")
                        return
                    print(f"  ⚠ 访问失败: {e}")

    # ── 阶段 3：手动浏览阶段 ──
    if not args.headless:
        browse_phase_count[0] = 0
        count_before_browse = sum(saved_count.values())

        print("\n" + "═" * 60)
        print("  🌐 手动浏览阶段")
        print("═" * 60)
        print("  现在请在浏览器中自由浏览，点击各个功能菜单和页面。")
        print("  脚本会在后台持续拦截并保存所有 JS / HTML / JSON 文件及 API 请求/响应报文。")
        print("  每发现新文件都会实时显示在终端中。")
        print("")
        print("  💡 提示：尽量多点击不同的功能模块，每个页面都可能")
        print("     触发加载新的 Webpack chunk 与动态 API 请求。")
        print("")
        print("  ✅ 浏览完毕后，回到此终端按 [回车] 进入自动探索阶段（若已关闭窗口将直接结算）...")
        print("═" * 60)

        browser_alive = True
        while True:
            if check_enter_pressed():
                break

            if browser_alive:
                page = get_active_page(context)
                if not page:
                    browser_alive = False
                    break
                try:
                    page.wait_for_timeout(500)
                except Exception:
                    browser_alive = False
                    break
            else:
                time.sleep(0.5)

        browse_new = sum(saved_count.values()) - count_before_browse
        print(f"\n[+] 手动浏览阶段结束，新增 {browse_new} 个文件")
        print(f"    （累计: HTML {saved_count['html']} / JS {saved_count['js']} / JSON {saved_count['json']} / API报文 {api_seq_counter[0]}）")

        if not browser_alive:
            print("[!] 浏览器已关闭，跳过自动探索阶段")
            try:
                if browser:
                    browser.close()
                else:
                    context.close()
            except:
                pass
            return

    # ── 阶段 4：自动链接探索 ──
    if not args.no_explore:
        page = get_active_page(context)
        if not page:
            print("\n[4/4] 浏览器已关闭，跳过自动探索阶段")
            return

        print(f"\n[4/4] 开始自动探索同域链接（最大深度: {args.depth}）...")

        initial_links = extract_links(page, target_url)
        for link in initial_links:
            if link not in visited_urls:
                url_queue.append((link, 1))

        if url_queue:
            print(f"  发现 {len(url_queue)} 个待探索链接")

        while url_queue:
            page = get_active_page(context)
            if not page:
                print("  [!] 浏览器已关闭，结束自动链接探索。")
                break

            current_url, depth = url_queue.pop(0)

            if depth > args.depth:
                continue
            if current_url in visited_urls:
                continue

            visited_urls.add(current_url)

            try:
                short_url = current_url if len(current_url) <= 70 else current_url[:67] + "..."
                print(f"\n  → 探索 [{depth}/{args.depth}]: {short_url}")
                page.goto(current_url, wait_until="networkidle", timeout=args.timeout * 1000)
                page.wait_for_timeout(args.wait * 1000)

                page.evaluate("""async () => {
                    const delay = ms => new Promise(r => setTimeout(r, ms));
                    for (let i = 0; i < document.body.scrollHeight; i += 400) {
                        window.scrollTo(0, i);
                        await delay(150);
                    }
                }""")
                page.wait_for_timeout(1000)

            except Exception as e:
                err_msg = str(e)
                if "Target page, context or browser has been closed" in err_msg or "Target closed" in err_msg:
                    print(f"  [!] 检测到浏览器已关闭，终止自动探索。")
                    break
                print(f"  ⚠ 跳过: {e}")
                continue

            if depth < args.depth:
                page = get_active_page(context)
                if not page:
                    break
                new_links = extract_links(page, target_url)
                for link in new_links:
                    if link not in visited_urls:
                        url_queue.append((link, depth + 1))
    else:
        print("\n[4/4] 已跳过链接探索（--no-explore）")

    try:
        if browser:
            browser.close()
        else:
            context.close()
    except:
        pass


def safe_run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response):
    """安全包装运行会话，优雅处理浏览器被用户主动关闭的情况。"""
    try:
        run_session(context, browser, target_url, args, output_dir, saved_count, saved_files, visited_urls, url_queue, browse_phase_count, api_seq_counter, api_index_entries, on_response)
    except Exception as e:
        err_str = str(e)
        if "Target page, context or browser has been closed" in err_str or "Target closed" in err_str:
            print("\n[!] 浏览器已由用户或系统关闭，安全结束并完成数据结算。")
        else:
            raise



def _print_summary(saved_count, total, visited_count, api_count, output_dir, no_assets=False):
    """输出下载统计。"""
    print("\n" + "=" * 60)
    print("  下载与录制完成！")
    print("=" * 60)
    if no_assets:
        print("  前端静态资源  : 【已按指令跳过下载 (--no-assets / --api-only 纯接口录制模式)】")
    else:
        print(f"  HTML 文件     : {saved_count['html']}")
        print(f"  JS   文件     : {saved_count['js']}")
        print(f"  CSS  文件     : {saved_count['css']}")
        print(f"  JSON 文件     : {saved_count['json']}")
        print(f"  其他静态文件  : {saved_count['other']}")
        print(f"  ─────────────────────")
        print(f"  静态资源总计  : {total} 个文件")
    print(f"  API 接口报文  : {api_count} 个独立记录（已保存至 _api_records/ 目录）")
    if visited_count > 0:
        print(f"  探索页面      : {visited_count} 个")
    print(f"  输出目录      : {output_dir}")
    print("=" * 60)


def _save_manifest(saved_files, target_url, total, output_dir, no_assets=False):
    """保存下载清单。"""
    manifest_path = os.path.join(output_dir, "_download_manifest.txt")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(f"# 整站下载清单\n")
        f.write(f"# 目标: {target_url}\n")
        f.write(f"# 时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        if no_assets:
            f.write(f"# 状态: 已按指令跳过前端静态资源下载 (--no-assets / --api-only)\n\n")
        else:
            f.write(f"# 总计: {total} 个文件\n\n")
            for url, local in sorted(saved_files.items()):
                f.write(f"{url}\n  -> {local}\n\n")
    if not no_assets:
        print(f"\n  下载清单已保存: {manifest_path}")


def _trigger_auto_deobfuscate(output_dir):
    """自动触发 AST 语法解混淆引擎对下载目录进行批量脱壳与微创提纯。"""
    try:
        from engines.deobfuscator import run_deobfuscator
        run_deobfuscator(output_dir)
    except Exception as e:
        print(f"\n[WARN] 自动脱壳流水线执行异常: {e}")


run_with_args = main


if __name__ == "__main__":
    main()


