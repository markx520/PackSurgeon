# !/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os
import requests
import base64
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import sqlite3
import warnings
import random
import re
import logging
import time
import shutil
import subprocess
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict
from threading import Thread
from queue import Queue, Empty

from lib.common import readConfig
from lib.common.utils import Utils
from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource
from lib.common.textdecode import decode_bytes_robust


class DownloadJs():

    def __init__(self, jsRealPaths, options, discovery_source: Optional[DiscoverySource] = None):
        """
        Initialize DownloadJs with JS paths and options.
        
        Args:
            jsRealPaths: List of JS file URLs to download
            options: Command line options
            discovery_source: The method by which these JS files were discovered
                             (Requirements 4.1)
        """
        warnings.filterwarnings('ignore')
        self.jsRealPaths = jsRealPaths
        self.blacklist_domains = readConfig.ReadConfig().getValue('blacklist', 'domain')
        self.blacklistFilenames = readConfig.ReadConfig().getValue('blacklist', 'filename')
        self.options = options
        self.discovery_source = discovery_source or DiscoverySource.STATIC_HTML
        self.proxy_data = Utils().build_proxies(self.options.proxy)
        self.UserAgent = [
            "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 9.50",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.133 Safari/534.16",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.11 TaoBrowser/2.0 Safari/536.11",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.3.4000 Chrome/30.0.1599.101 Safari/537.36",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; SE 2.X MetaSr 1.0)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E; LBBROWSER)",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0",
            "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; TencentTraveler 4.0)"
        ]
        self.log = creatLog().get_logger()
        self.successful_path_patterns = {}
        self.webpack_public_path = None
        self._skip_existing_marker = "__SKIP_EXISTING__"
        self._db_retry_limit = 6
        self._db_writer_queue = None
        self._db_writer_thread = None
        self._db_writer_db_path = None
        self._db_writer_stop_token = object()

        # 降噪：收紧 urllib3 重试日志，只在严重错误时输出（避免长串 Retrying(...) 提示刷屏）
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
        
        # Discovery source prefix mapping for logging (Requirements 4.2)
        self._source_prefix_map = {
            DiscoverySource.STATIC_HTML: "[STATIC]",
            DiscoverySource.IFRAME: "[IFRAME]",
            DiscoverySource.INLINE_PATTERN: "[PATTERN]",
            DiscoverySource.BROWSER_INTERCEPT: "[BROWSER]",
            DiscoverySource.ASYNC_RECOVERY: "[RECOVER]",
        }

        # --- 优化：初始化一个具备重试功能的 session ---
        self.session = requests.Session()
        # 定义重试策略
        retry_strategy = Retry(
            total=3,  # 总重试次数
            status_forcelist=[429, 500, 502, 503, 504],  # 需要重试的状态码
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1  # 重试之间的延迟因子
        )
        # ######################## START: 代码修改区域 ########################
        # 创建一个带有重试策略的适配器，并增大连接池大小以匹配线程数
        adapter = HTTPAdapter(
            pool_connections=100,      # 总连接池数量，可以设置得大一些
            pool_maxsize=30,           # 关键：每个连接池的最大连接数，使其等于或大于 max_workers (30)
            max_retries=retry_strategy
        )
        # ######################## END: 代码修改区域 ##########################

        # 为 http 和 https 协议挂载此适配器
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        # ----------------------------------------------------------------

    def _get_source_prefix(self, source: Optional[DiscoverySource] = None) -> str:
        """
        Get the log prefix for a discovery source.
        
        Args:
            source: The discovery source, defaults to instance discovery_source
        
        Returns:
            Log prefix string like [STATIC], [IFRAME], [PATTERN], [BROWSER]
        
        Requirements: 4.2
        """
        src = source or self.discovery_source
        return self._source_prefix_map.get(src, "[STATIC]")

    def _append_sourcemap_report(self, project_root, message):
        try:
            sourcemap_dir = os.path.join(project_root, "sourcemaps")
            if not os.path.exists(sourcemap_dir):
                os.makedirs(sourcemap_dir)
            report_path = os.path.join(sourcemap_dir, "sourcemap_report.txt")
            with open(report_path, 'a', encoding='utf-8') as rf:
                rf.write(message.strip() + "\n")
        except Exception as e:
            # 静默失败，避免影响主流程
            self.log.debug(f"写入sourcemap报告失败: {e}")

    def _extract_sourcemap_reference(self, js_text):
        try:
            # 支持 //# 和 /*# 两种形式，允许在行中间出现（压缩后的JS）
            # 优先匹配行首的注释
            m1 = re.search(r"^[\t ]*\/\/#\s*sourceMappingURL\s*=\s*(.+)$", js_text, re.MULTILINE)
            if m1:
                return ('ref', m1.group(1).strip())
            # 匹配行中间的 //# 注释（压缩后的JS可能没有换行）
            m1b = re.search(r"\/\/#\s*sourceMappingURL\s*=\s*([^\s]+)", js_text)
            if m1b:
                return ('ref', m1b.group(1).strip())
            # 匹配 /*# ... */ 块注释形式
            m2 = re.search(r"\/\*#\s*sourceMappingURL\s*=\s*(.+?)\s*\*\/", js_text, re.DOTALL)
            if m2:
                return ('ref', m2.group(1).strip())
        except Exception:
            pass
        return None

    @staticmethod
    def _sanitize_map_folder_name(raw_name):
        name = os.path.basename(str(raw_name or "").strip())
        if not name:
            name = "unknown.map"
        name = re.sub(r'[:*?"<>|/\\]+', '_', name)
        if not name.lower().endswith(".map"):
            name = f"{name}.map"
        return name

    @staticmethod
    def _restore_output_dir_for_map(project_root, map_local_path):
        map_name = DownloadJs._sanitize_map_folder_name(map_local_path)
        return os.path.join(project_root, "sourcemaps", map_name)

    @staticmethod
    def _count_files_in_dir(directory):
        if not directory or not os.path.exists(directory):
            return 0
        total = 0
        for _, _, files in os.walk(directory):
            total += len(files)
        return total

    def _merge_move_dir(self, src_dir, dst_dir):
        os.makedirs(dst_dir, exist_ok=True)
        for name in os.listdir(src_dir):
            src_path = os.path.join(src_dir, name)
            dst_path = os.path.join(dst_dir, name)
            if os.path.isdir(src_path):
                if os.path.exists(dst_path) and os.path.isdir(dst_path):
                    self._merge_move_dir(src_path, dst_path)
                    try:
                        os.rmdir(src_path)
                    except Exception:
                        pass
                elif not os.path.exists(dst_path):
                    shutil.move(src_path, dst_path)
            else:
                if not os.path.exists(dst_path):
                    shutil.move(src_path, dst_path)

    def _flatten_webpack_root(self, output_dir):
        """
        reverse-sourcemap 常见会在输出根生成 webpack/ 顶层目录。
        这里统一下沉一层，直接保留 webpack 下内容到 output_dir 根。
        """
        try:
            webpack_root = os.path.join(output_dir, "webpack")
            if not os.path.isdir(webpack_root):
                return
            self._merge_move_dir(webpack_root, output_dir)
            try:
                os.rmdir(webpack_root)
            except Exception:
                pass
        except Exception:
            pass

    def _restore_sources_with_reverse_sourcemap(self, map_bytes, map_name, project_root):
        reverse_bin = shutil.which("reverse-sourcemap")
        if not reverse_bin:
            raise RuntimeError("未找到 reverse-sourcemap 命令")

        output_dir = self._restore_output_dir_for_map(project_root, map_name)
        os.makedirs(output_dir, exist_ok=True)

        before_count = self._count_files_in_dir(output_dir)
        tmp_map_name = f".reverse_input_{int(time.time() * 1000)}_{random.randint(1000, 9999)}.map"
        tmp_map_path = os.path.join(output_dir, tmp_map_name)
        try:
            with open(tmp_map_path, "wb") as tf:
                tf.write(map_bytes if isinstance(map_bytes, (bytes, bytearray)) else bytes(map_bytes or b""))

            # 使用 cwd + 相对 map 名，避免 reverse-sourcemap 将系统绝对临时目录折叠进输出路径。
            cmd = [reverse_bin, "-v", tmp_map_name, "-o", "."]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                cwd=output_dir,
            )
            if result.returncode != 0:
                stderr_text = (result.stderr or "").strip()
                stdout_text = (result.stdout or "").strip()
                detail = stderr_text or stdout_text or "unknown error"
                detail = detail.replace("\n", " ")[:320]
                raise RuntimeError(f"reverse-sourcemap 执行失败: {detail}")

            self._flatten_webpack_root(output_dir)
        finally:
            if tmp_map_path:
                try:
                    os.remove(tmp_map_path)
                except Exception:
                    pass

        after_count = self._count_files_in_dir(output_dir)
        return output_dir, max(0, after_count - before_count), after_count

    def _handle_sourcemap(self, js_text, js_url, project_root, js_local_tag, js_filename):
        ref = self._extract_sourcemap_reference(js_text)
        if not ref:
            return

        _, ref_value = ref
        try:
            if ref_value.startswith('data:'):
                comma_idx = ref_value.find('base64,')
                if comma_idx != -1:
                    b64_data = ref_value[comma_idx + len('base64,'):]
                    try:
                        map_bytes = base64.b64decode(b64_data)
                    except Exception:
                        self._append_sourcemap_report(project_root, f"JS {js_filename}: data:URL base64 解码失败")
                        return
                else:
                    comma = ref_value.find(',')
                    if comma != -1:
                        raw_data = ref_value[comma+1:]
                        try:
                            from urllib.parse import unquote
                            raw_data = unquote(raw_data)
                        except Exception:
                            pass
                        map_bytes = raw_data.encode('utf-8')
                    else:
                        map_bytes = b''

                map_name = f"{js_local_tag}.{js_filename}.map"
                try:
                    output_dir, new_count, total_count = self._restore_sources_with_reverse_sourcemap(
                        map_bytes,
                        map_name,
                        project_root,
                    )
                    self._append_sourcemap_report(
                        project_root,
                        f"JS {js_filename}: reverse-sourcemap 还原完成 ({os.path.basename(output_dir)}), 新增 {new_count}, 总计 {total_count}",
                    )
                except Exception as e:
                    self._append_sourcemap_report(project_root, f"JS {js_filename}: reverse-sourcemap 还原失败: {e}")
                return

            map_url = urljoin(js_url, ref_value)
            map_bytes = None
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    resp = self.session.get(map_url, timeout=(10, 30))
                    resp.raise_for_status()
                    map_bytes = resp.content
                    break
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.log.debug(f"[SourceMap] 下载重试 {attempt + 1}/{max_retries}: {map_url}")
                        continue
                    else:
                        self._append_sourcemap_report(project_root, f"JS {js_filename}: 下载 SourceMap 失败 {map_url}: {e}")
                    return
            
            if not map_bytes:
                return

            parsed_map = urlparse(map_url)
            map_name = os.path.basename(parsed_map.path or "").strip() or f"{js_local_tag}.{js_filename}.map"
            try:
                output_dir, new_count, total_count = self._restore_sources_with_reverse_sourcemap(
                    map_bytes,
                    map_name,
                    project_root,
                )
                self._append_sourcemap_report(
                    project_root,
                    f"JS {js_filename}: reverse-sourcemap 还原完成 ({os.path.basename(output_dir)}), 新增 {new_count}, 总计 {total_count}",
                )
            except Exception as e:
                self._append_sourcemap_report(project_root, f"JS {js_filename}: reverse-sourcemap 还原失败: {e}")
        except Exception as e:
            self._append_sourcemap_report(project_root, f"JS {js_filename}: 处理 SourceMap 失败: {e}")

    def analyze_path_patterns(self, successful_path):
        try:
            parsed_url = urlparse(successful_path)
            path = parsed_url.path
            filename = path.split('/')[-1]
            if 'chunk' in filename:
                directory = '/'.join(path.split('/')[:-1]) + '/'
                if 'chunk' not in self.successful_path_patterns:
                    self.successful_path_patterns['chunk'] = []
                if directory not in self.successful_path_patterns['chunk']:
                    self.successful_path_patterns['chunk'].append(directory)
        except Exception as e:
            self.log.error(f"[Err] 分析路径模式时出错: {str(e)}")

    def extract_webpack_public_path(self, js_content):
        patterns = [
            r'__webpack_require__\.p\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'\.p\s*=\s*[\'"]([^\'"]+)[\'"]',
        ]
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            if matches:
                return matches[0]
        return None

    def infer_path(self, original_path):
        try:
            parsed_url = urlparse(original_path)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            filename = os.path.basename(parsed_url.path)
            possible_paths = {original_path} # 使用集合自动去重

            if 'chunk' in self.successful_path_patterns:
                for directory in self.successful_path_patterns['chunk']:
                    possible_paths.add(urljoin(base_url, f"{directory}{filename}"))
            
            return list(possible_paths)
        except Exception as e:
            self.log.error(f"[Err] 推断路径时出错: {str(e)}")
            return [original_path]

    def _contains_control_chars(self, text):
        try:
            return bool(re.search(r'[\r\n\t\u2028\u2029]', text or ''))
        except Exception:
            return True

    def _looks_like_code_snippet(self, text):
        try:
            if not text:
                return False

            # 要求关键词后紧跟代码上下文（括号/花括号/空格+变量），而非单独出现在路径中
            if re.search(r'(?i)\b(?:function|return)\s*[\({]', text):
                return True

            if re.search(r'(?i)\b(?:requirejs|define|module\.exports|exports\.)\b', text):
                return True

            # 同时出现 { 和 } 才判定为代码块，单个分号不触发
            if re.search(r'\{[^}]*\}', text) or '=>' in text:
                return True

            if text.count('(') > 8 and len(text) > 80:
                return True

            return False
        except Exception:
            return True

    def _is_sane_js_url(self, js_url):
        """
        预请求 URL 兜底校验：拒绝明显污染的候选，避免把整段 JS 当成 URL 下载。
        """
        try:
            if not js_url:
                return False

            text = str(js_url).strip()
            if not text:
                return False

            if len(text) > 1000:
                return False

            if self._contains_control_chars(text):
                return False

            parsed = urlparse(text)
            if not (parsed.scheme and parsed.netloc):
                return False

            if parsed.scheme not in ('http', 'https'):
                return False

            combined = (parsed.path or '') + ('?' + parsed.query if parsed.query else '')
            if self._contains_control_chars(combined):
                return False

            if any(ch in combined for ch in ('"', "'", '`')):
                return False

            # 拦截常见表达式残留/污染 URL
            lower_combined = combined.lower()
            lower_path = (parsed.path or "").lower()

            # 过滤非JS资源（避免把源码路径/类型声明当作 chunk 下载）
            if lower_path.endswith(('.vue', '.d.ts')):
                return False

            if re.search(r'(?i)(?:%0a|%0d|%5c[nr])', lower_combined):
                return False

            if re.search(r'(?i)\.concat\s*\(', lower_combined):
                return False

            # 形如 /x.js/assets/... 基本是错误拼接
            if re.search(r'(?i)\.js/(?:assets|static|chunks?|scripts?|js)/', lower_combined):
                return False

            # 避免把绝对URL片段拼进 path（例如 /https://xxx/...）
            if re.search(r'https?://', combined):
                return False

            if self._looks_like_code_snippet(combined):
                return False

            if re.search(r'\s', combined):
                return False

            return True
        except Exception:
            return False

    def _get_trusted_candidate_domains(self) -> List[str]:
        try:
            raw = getattr(self.options, '_trusted_js_domains', None)
            if not raw:
                return []
            domains = []
            for item in raw:
                text = str(item or '').strip().lower()
                if text and text not in domains:
                    domains.append(text)
            return domains
        except Exception:
            return []

    def _score_candidate_url(self, js_url: str, primary_domain: str, trusted_domains: List[str] = None) -> int:
        """
        对同名候选 URL 打分，分高者优先尝试。
        """
        try:
            parsed = urlparse(js_url or "")
            if not (parsed.scheme and parsed.netloc):
                return -50

            score = 0
            domain = parsed.netloc.lower()
            path = (parsed.path or "").lower()
            full = js_url.lower()

            if primary_domain and domain == primary_domain:
                score += 10
            elif trusted_domains and domain in set(trusted_domains):
                score += 6

            if re.search(r'/(?:assets|static|scripts?|chunks?|js)/', path):
                score += 4

            if re.search(r'[0-9a-f]{6,}\.js(?:$|\?)', path):
                score += 2

            if re.search(r'(?i)\.js/(?:assets|static|scripts?|chunks?|js)/', path):
                score -= 10

            if re.search(r'(?i)(?:%0a|%0d|%5c[nr])', full):
                score -= 12

            if re.search(r'(?i)\.concat\s*\(', full):
                score -= 15

            if "/./" in path or "/../" in path:
                score -= 4

            return score
        except Exception:
            return -50

    def _rank_candidate_urls(self, candidates: List[str], primary_domain: str, max_candidates: int = 5) -> List[str]:
        """
        对同名文件候选 URL 去重、过滤并排序，限制尝试数量。
        """
        trusted_domains = self._get_trusted_candidate_domains()
        seen = set()
        scored = []
        for raw in candidates or []:
            url = (raw or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            if not self._is_sane_js_url(url):
                continue
            parsed = urlparse(url)
            domain = (parsed.netloc or '').lower()
            scored.append((self._score_candidate_url(url, primary_domain, trusted_domains), url, domain))

        scored.sort(key=lambda item: (-item[0], len(item[1]), item[1]))

        ordered = []
        chosen = set()

        def _take_first(predicate):
            for _, url, domain in scored:
                if url in chosen:
                    continue
                if predicate(domain):
                    chosen.add(url)
                    ordered.append(url)
                    return True
            return False

        if primary_domain:
            _take_first(lambda domain: domain == primary_domain)
        if trusted_domains:
            _take_first(lambda domain: domain in set(trusted_domains) and domain != primary_domain)

        for _, url, _ in scored:
            if url in chosen:
                continue
            chosen.add(url)
            ordered.append(url)
        if max_candidates and len(ordered) > max_candidates:
            ordered = ordered[:max_candidates]
        return ordered

    def _push_failure_record(self, failure_records, url, human):
        if failure_records is None:
            return
        try:
            failure_records.append({
                "url": str(url or ""),
                "human": str(human or "请求失败"),
            })
        except Exception:
            pass

    def _is_db_locked_error(self, error: Exception) -> bool:
        msg = str(error).lower()
        return (
            "database is locked" in msg
            or "database table is locked" in msg
            or "database schema is locked" in msg
            or "database is busy" in msg
        )

    def _sleep_db_backoff(self, attempt: int) -> None:
        base = 0.08 * (2 ** attempt)
        jitter = random.uniform(0, 0.05)
        time.sleep(min(1.5, base + jitter))

    def _connect_sqlite(self, db_path: str):
        conn = sqlite3.connect(db_path, timeout=30.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=60000")
        except Exception:
            # 兜底：PRAGMA 设置失败不影响主流程
            pass
        return conn

    def _is_db_writer_alive(self) -> bool:
        return self._db_writer_thread is not None and self._db_writer_thread.is_alive()

    def _start_db_writer(self, db_path: str) -> bool:
        """
        启动单线程数据库写入消费者。
        返回:
          - True: 本次新启动了写入线程
          - False: 已有同库写入线程在运行
        """
        if self._is_db_writer_alive():
            if self._db_writer_db_path == db_path:
                return False
            self._stop_db_writer()

        task_queue = Queue()
        ready_queue = Queue(maxsize=1)
        writer = Thread(
            target=self._db_writer_loop,
            args=(db_path, task_queue, ready_queue),
            daemon=True,
            name="DownloadJsDBWriter",
        )
        self._db_writer_queue = task_queue
        self._db_writer_thread = writer
        self._db_writer_db_path = db_path
        writer.start()

        try:
            ok, payload = ready_queue.get(timeout=10)
        except Empty:
            self._db_writer_queue = None
            self._db_writer_thread = None
            self._db_writer_db_path = None
            raise RuntimeError("数据库写入线程启动超时")

        if not ok:
            self._db_writer_queue = None
            self._db_writer_thread = None
            self._db_writer_db_path = None
            if isinstance(payload, Exception):
                raise payload
            raise RuntimeError(str(payload))
        return True

    def _stop_db_writer(self):
        if not self._is_db_writer_alive():
            self._db_writer_queue = None
            self._db_writer_thread = None
            self._db_writer_db_path = None
            return

        thread = self._db_writer_thread
        queue_ref = self._db_writer_queue

        try:
            queue_ref.put(self._db_writer_stop_token)
        except Exception:
            pass

        thread.join(timeout=10)
        if thread.is_alive():
            self.log.warning("[警告] 数据库写入线程未能在10秒内退出")

        self._db_writer_queue = None
        self._db_writer_thread = None
        self._db_writer_db_path = None

    def _db_writer_execute_with_retry(self, conn, cursor, op, payload):
        for attempt in range(self._db_retry_limit):
            try:
                if op == "prepare_record":
                    check_sql = (
                        "SELECT id, COALESCE(success, 0), COALESCE(spilt, 0) "
                        "FROM js_file WHERE path=? ORDER BY id DESC LIMIT 1"
                    )
                    cursor.execute(check_sql, (payload["js_real_path"],))
                    row = cursor.fetchone()
                    if row and int(row[1] or 0) == 1:
                        # 统计口径修复：
                        # 异步恢复阶段再次命中已存在的静态JS时，将其升级标记为 spilt=999，
                        # 避免“文件已存在但异步统计为0”。
                        if int(payload["spilt_id"] or 0) == 999 and int(row[2] or 0) != 999:
                            cursor.execute("UPDATE js_file SET spilt=999 WHERE id=?", (row[0],))
                        conn.commit()
                        return self._skip_existing_marker

                    if row and int(row[1] or 0) != 1:
                        cursor.execute(
                            "DELETE FROM js_file WHERE path=? AND COALESCE(success, 0) != 1",
                            (payload["js_real_path"],),
                        )

                    if payload["spilt_id"] == 0:
                        sql = "INSERT INTO js_file(name,path,local,discovery_source) VALUES(?, ?, ?, ?)"
                        cursor.execute(
                            sql,
                            (
                                payload["js_filename"],
                                payload["js_real_path"],
                                payload["local_name"],
                                payload["source_value"],
                            ),
                        )
                    else:
                        sql = "INSERT INTO js_file(name,path,local,spilt,discovery_source) VALUES(?, ?, ?, ?, ?)"
                        cursor.execute(
                            sql,
                            (
                                payload["js_filename"],
                                payload["js_real_path"],
                                payload["local_name"],
                                payload["spilt_id"],
                                payload["source_value"],
                            ),
                        )

                    conn.commit()
                    return True

                if op == "mark_success":
                    cursor.execute("UPDATE js_file SET success=1 WHERE local=?", (payload["local_name"],))
                    conn.commit()
                    return True

                raise RuntimeError(f"未知数据库操作: {op}")

            except sqlite3.OperationalError as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                if self._is_db_locked_error(e) and attempt < self._db_retry_limit - 1:
                    self._sleep_db_backoff(attempt)
                    continue
                raise
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
        return True

    def _db_writer_loop(self, db_path: str, task_queue: Queue, ready_queue: Queue):
        conn = None
        try:
            conn = self._connect_sqlite(db_path)
            cursor = conn.cursor()
            ready_queue.put((True, None))

            while True:
                task = task_queue.get()
                if task is self._db_writer_stop_token:
                    break

                op, payload, response_queue = task
                try:
                    result = self._db_writer_execute_with_retry(conn, cursor, op, payload)
                    response_queue.put((True, result))
                except Exception as e:
                    response_queue.put((False, e))
        except Exception as e:
            try:
                ready_queue.put((False, e))
            except Exception:
                pass
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _db_request(self, op: str, **payload):
        if not self._is_db_writer_alive() or self._db_writer_queue is None:
            raise RuntimeError("数据库写入线程未启动")

        response_queue = Queue(maxsize=1)
        self._db_writer_queue.put((op, payload, response_queue))
        try:
            ok, value = response_queue.get(timeout=120)
        except Empty:
            raise RuntimeError("数据库写入操作超时")

        if ok:
            return value
        if isinstance(value, Exception):
            raise value
        raise RuntimeError(str(value))

    def _prepare_download_record(self, db_path, js_real_path, js_filename, local_name, spilt_id, source_value):
        if self._db_writer_db_path and self._db_writer_db_path != db_path:
            raise RuntimeError("数据库写入线程与目标数据库不一致")
        return self._db_request(
            "prepare_record",
            js_real_path=js_real_path,
            js_filename=js_filename,
            local_name=local_name,
            spilt_id=spilt_id,
            source_value=source_value,
        )

    def _mark_download_success(self, db_path, local_name):
        if self._db_writer_db_path and self._db_writer_db_path != db_path:
            raise RuntimeError("数据库写入线程与目标数据库不一致")
        self._db_request("mark_success", local_name=local_name)

    def jsBlacklist(self):
        newList = self.jsRealPaths[:]
        for jsRealPath in newList:
            res = urlparse(jsRealPath)
            domain = res.netloc.lower()
            filename = Utils().getFilename(jsRealPath).lower()
            for d in self.blacklist_domains.split(","):
                if d in domain:
                    self.jsRealPaths.remove(jsRealPath)
                    break
            for f in self.blacklistFilenames.split(","):
                if f in filename:
                    if jsRealPath in self.jsRealPaths:
                        self.jsRealPaths.remove(jsRealPath)
                    break
        return self.jsRealPaths

    def download_single_js(
        self,
        jsRealPath,
        tag,
        host,
        spiltId,
        discovery_source: Optional[DiscoverySource] = None,
        quiet_fail: bool = False,
        failure_records: Optional[List[Dict[str, str]]] = None,
    ):
        """
        优化后的单个JS下载方法
        - 增加数据库连接超时
        - 使用参数化查询防止SQL注入
        - 增强错误处理
        - 存储发现来源 (Requirements 4.1)
        
        Args:
            jsRealPath: JS file URL
            tag: Project tag
            host: Host domain
            spiltId: Split ID for chunked files
            discovery_source: The method by which this JS file was discovered
        """
        jsFilename = Utils().getFilename(jsRealPath)
        jsTag = Utils().creatTag(6)
        PATH = "tmp/" + tag + "_" + host + "/" + tag + ".db"
        db_path = os.sep.join(PATH.split('/'))
        
        # Use instance discovery_source if not provided
        source = discovery_source or self.discovery_source
        source_value = source.value if isinstance(source, DiscoverySource) else str(source)
        prefix = self._get_source_prefix(source)

        if not self._is_sane_js_url(jsRealPath):
            preview = str(jsRealPath)
            if len(preview) > 180:
                preview = preview[:180] + '...'
            self.log.debug(f"{prefix} [Skip] 拒绝可疑URL候选: {preview}")
            self._push_failure_record(failure_records, jsRealPath, "URL无效")
            return None

        saved_file_path = None
        try:
            local_name = f"{jsTag}.{jsFilename}"
            record_state = self._prepare_download_record(
                db_path=db_path,
                js_real_path=jsRealPath,
                js_filename=jsFilename,
                local_name=local_name,
                spilt_id=spiltId,
                source_value=source_value,
            )

            if record_state == self._skip_existing_marker:
                self.log.info(Utils().tellTime() + f"{prefix} URL已存在，跳过: {jsFilename}")
                return self._skip_existing_marker

            sslFlag = int(self.options.ssl_flag)
            header = {
                'User-Agent': random.choice(self.UserAgent),
                'Accept': 'application/javascript, text/javascript, */*; q=0.01',
            }
            extra_header = str(getattr(self.options, 'head', '') or '')
            if ':' in extra_header:
                h_key, h_val = extra_header.split(':', 1)
                h_key = h_key.strip()
                if h_key:
                    header[h_key] = h_val.strip()
            # 如果用户没有通过 -d 显式指定 Referer，则默认使用原始 URL 作为 Referer，避免为空
            if 'Referer' not in header and getattr(self.options, 'url', None):
                header['Referer'] = self.options.url

            if self.options.cookie:
                header['Cookie'] = self.options.cookie

            # --- 优化：使用 session 并配合健壮的超时和错误处理 ---
            # 超时：10秒连接，30秒读取响应。
            request_kwargs = {
                "stream": True,
                "timeout": (10, 30),
                "headers": header,
                "verify": not sslFlag,
            }
            if self.proxy_data:
                request_kwargs["proxies"] = self.proxy_data
            response = self.session.get(jsRealPath, **request_kwargs)
            
            # 如果 HTTP 请求返回不成功的状态码，这将引发 HTTPError，并由重试机制处理。
            response.raise_for_status()

            self.analyze_path_patterns(jsRealPath)
            
            jsFileData = response.content
            if jsFileData.strip().lower().startswith((b'<!doctype html>', b'<html')):
                if not quiet_fail:
                    self.log.error(f"{prefix} [Err] 下载内容为HTML，非JS: {jsFilename}")
                content_type = response.headers.get('Content-Type', '')
                self.log.debug(f"{prefix} [Debug] HTML响应URL: {jsRealPath} | Content-Type: {content_type}")
                self._push_failure_record(failure_records, jsRealPath, "下载内容为HTML")
                return

            js_text, decoded_encoding = decode_bytes_robust(
                jsFileData,
                content_type=response.headers.get('Content-Type', ''),
                hinted_encoding=(getattr(response, 'encoding', None) or getattr(response, 'apparent_encoding', None) or ''),
            )

            if not self.webpack_public_path:
                self.webpack_public_path = self.extract_webpack_public_path(js_text)

            file_path = f"tmp{os.sep}{tag}_{host}{os.sep}{jsTag}.{jsFilename}"
            with open(file_path, "wb") as js_file:
                js_file.write(jsFileData)
            saved_file_path = os.path.normpath(file_path)

            # 下载成功后再更新 success，缩短每次事务占用时长
            self._mark_download_success(db_path, local_name)
            self.log.info(Utils().tellTime() + f"{prefix} 下载成功: {jsFilename}")
            if decoded_encoding not in ('utf-8', 'utf-8-sig'):
                self.log.debug(f"{prefix} [编码] {jsFilename} 自动识别为 {decoded_encoding}")

            # 尝试下载并解析 SourceMap（非阻塞关键路径）
            try:
                project_root = f"tmp{os.sep}{tag}_{host}"
                self._handle_sourcemap(js_text, jsRealPath, project_root, jsTag, jsFilename)
            except Exception as e:
                self.log.debug(f"SourceMap 处理跳过: {e}")

            return saved_file_path

        except requests.exceptions.RequestException as e:
            # 这将捕获所有重试失败后的错误。
            msg = str(e)
            # 去掉冗长的 URL，保留紧凑原因（例如 "404 Client Error: Not Found"）
            short = msg.split(" for url: ")[0] if " for url: " in msg else msg
            # 尝试从错误消息中提取状态码
            code_match = re.search(r"\b(\d{3})\b", short)
            if code_match:
                code = code_match.group(1)
                if code == "404":
                    human = "资源不存在(404)"
                elif code == "403":
                    human = "访问被禁止(403)"
                elif code == "500":
                    human = "服务器内部错误(500)"
                else:
                    human = f"请求失败({code})"
            else:
                human = short
            failed_url = msg.split(' for url: ', 1)[1] if " for url: " in msg else jsRealPath
            self._push_failure_record(failure_records, failed_url, human)
            if not quiet_fail:
                self.log.error(f"{prefix} [Err] 重试多次仍失败: {jsFilename} ({human})")
                self.log.debug(f"[Debug] 失败请求URL: {failed_url}")
        except sqlite3.OperationalError as e:
            # 数据库锁定或其他操作错误
            self._push_failure_record(failure_records, jsRealPath, "数据库操作错误")
            if "database is locked" in str(e).lower():
                if not quiet_fail:
                    self.log.error(f"{prefix} [Err] 数据库被锁定: {jsFilename} - 建议减少并发线程数")
            else:
                if not quiet_fail:
                    self.log.error(f"{prefix} [Err] 数据库操作错误: {jsFilename}, 错误: {str(e)}")
        except Exception as e:
            self._push_failure_record(failure_records, jsRealPath, f"未知错误: {str(e)}")
            if not quiet_fail:
                self.log.error(f"{prefix} [Err] 下载或处理过程中发生未知错误: {jsFilename}, 错误: {str(e)}")
        return saved_file_path

    def _download_with_candidates(self, js_filename, candidates, tag, host, spiltId, source):
        """
        同名文件候选URL串行尝试，避免同一文件的多条错误日志刷屏。
        """
        prefix = self._get_source_prefix(source)
        fail_records = []

        for candidate in candidates:
            result = self.download_single_js(
                candidate,
                tag,
                host,
                spiltId,
                discovery_source=source,
                quiet_fail=True,
                failure_records=fail_records,
            )
            if result == self._skip_existing_marker:
                return None
            if result:
                return result

        if candidates:
            last_human = fail_records[-1]["human"] if fail_records else "请求失败"
            self.log.error(f"{prefix} [Err] 候选URL全部失败: {js_filename} (尝试{len(candidates)}个, 最后错误: {last_human})")
            for rec in fail_records[:3]:
                self.log.debug(f"[Debug] 失败请求URL: {rec['url']}")

        return None

    def downloadJs(self, tag, host, spiltId):
        self.jsRealPaths = list(set(self.jsRealPaths))
        try:
            self.jsRealPaths = self.jsBlacklist()
        except Exception as e:
            self.log.error("[Err] %s" % e)

        filtered_urls = []
        for jsUrl in self.jsRealPaths:
            try:
                if self._is_sane_js_url(jsUrl):
                    filtered_urls.append(jsUrl)
                else:
                    self.log.debug(f"已忽略可疑/无效URL: {str(jsUrl)[:180]}")
            except Exception as e:
                self.log.error(f"URL解析错误: {jsUrl}, {str(e)}")

        if not filtered_urls:
            return []

        # 二次去重，保持顺序
        deduped_urls = []
        seen_urls = set()
        for url in filtered_urls:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            deduped_urls.append(url)

        primary_domain = urlparse(getattr(self.options, 'url', '') or '').netloc.lower()
        db_path = os.sep.join(f"tmp/{tag}_{host}/{tag}.db".split('/'))
        writer_started_here = False

        try:
            writer_started_here = self._start_db_writer(db_path)

            # 同名候选聚合：避免同一文件在不同基准路径下重复失败刷屏
            grouped_candidates = {}
            for url in deduped_urls:
                filename = Utils().getFilename(url) or url
                grouped_candidates.setdefault(filename, []).append(url)

            # --- 优化：增加并发工作线程数 ---
            # 对于像下载这样的I/O密集型任务，更多的线程可以显著提高速度。
            # 这个值可以根据网络状况和目标服务器的性能进行调整。
            max_workers = 30
            downloaded_files = []

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                for filename, candidates in grouped_candidates.items():
                    ranked = self._rank_candidate_urls(candidates, primary_domain, max_candidates=5)
                    if not ranked:
                        continue
                    futures.append(
                        executor.submit(
                            self._download_with_candidates,
                            filename,
                            ranked,
                            tag,
                            host,
                            spiltId,
                            self.discovery_source,
                        )
                    )
                for future in as_completed(futures):
                    try:
                        local_file_path = future.result()
                        if local_file_path:
                            downloaded_files.append(os.path.normpath(local_file_path))
                    except Exception as e:
                        self.log.error(f"[Err] 一个下载任务线程出现异常: {e}")

            if not downloaded_files:
                return []

            seen = set()
            unique_files = []
            for local_path in downloaded_files:
                if local_path in seen:
                    continue
                seen.add(local_path)
                unique_files.append(local_path)

            return unique_files
        finally:
            if writer_started_here:
                self._stop_db_writer()

    def creatInsideJs(self, tag, host, scriptInside, url, discovery_source: Optional[DiscoverySource] = None):
        """
        优化后的内联JS创建方法 - 增加超时和参数化查询
        
        Args:
            tag: Project tag
            host: Host domain
            scriptInside: Inline JS content
            url: Source URL
            discovery_source: The method by which this JS was discovered (Requirements 4.1)
        """
        writer_started_here = False
        try:
            jsRealPath = url
            jsFilename = "7777777.script.inside.html.js"
            jsTag = Utils().creatTag(6)
            PATH = "tmp/" + tag + "_" + host + "/" + tag + ".db"
            
            # Use instance discovery_source if not provided
            source = discovery_source or self.discovery_source
            source_value = source.value if isinstance(source, DiscoverySource) else str(source)
            db_path = os.sep.join(PATH.split('/'))
            local_name = f'{jsTag}.{jsFilename}'

            if (not self._is_db_writer_alive()) or (self._db_writer_db_path != db_path):
                writer_started_here = self._start_db_writer(db_path)

            # 先写入占位记录
            record_state = self._prepare_download_record(
                db_path=db_path,
                js_real_path=jsRealPath,
                js_filename=jsFilename,
                local_name=local_name,
                spilt_id=0,
                source_value=source_value,
            )
            if record_state == self._skip_existing_marker:
                prefix = self._get_source_prefix(source)
                self.log.info(Utils().tellTime() + f"{prefix} URL已存在，跳过: {jsFilename}")
                return
            
            prefix = self._get_source_prefix(source)
            self.log.info(Utils().tellTime() + f"{prefix} 正在下载：" + jsFilename)
            file_path = f"tmp{os.sep}{tag}_{host}{os.sep}{jsTag}.{jsFilename}"
            with open(file_path, "wb") as js_file:
                js_file.write(str.encode(scriptInside))

            # 标记为成功
            self._mark_download_success(db_path, local_name)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e).lower():
                self.log.error(f"[Err] 数据库被锁定 - {e}")
            else:
                self.log.error(f"[Err] 数据库操作错误 - {e}")
        except Exception as e:
            self.log.error("[Err] %s" % e)
        finally:
            if writer_started_here:
                self._stop_db_writer()
