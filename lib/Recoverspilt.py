#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import os, re, sqlite3, hashlib, time, random, multiprocessing, queue, json
from threading import Lock, Thread
from urllib.parse import urlparse, urljoin
from lib.common.utils import Utils
from lib.Database import DatabaseType
from lib.DownloadJs import DownloadJs
from lib.common.CreatLog import creatLog
from lib.common.models import DiscoverySource
import deno_vm
import esprima


def _deno_vm_eval_worker(js_code_func, name_list, result_queue):
    """在独立子进程中执行 deno_vm，便于超时后强制终止。"""
    try:
        import deno_vm as _deno_vm

        found = set()
        with _deno_vm.VM() as vm:
            vm.run(js_code_func)
            for name in name_list:
                try:
                    param = int(name) if str(name).isdigit() else name
                    result = vm.call("js_compile", param)
                    if result and "undefined" not in str(result):
                        found.add(str(result))
                except Exception:
                    continue

        result_queue.put({
            "ok": True,
            "filenames": sorted(found),
        })
    except Exception as e:
        try:
            result_queue.put({
                "ok": False,
                "error": str(e),
                "error_type": type(e).__name__,
            })
        except Exception:
            pass


class RecoverSpilt():

    def __init__(self, projectTag, options):
        self.projectTag = projectTag
        self.options = options
        self.log = creatLog().get_logger()
        self.processed_files = set()
        self._processed_original_names = set()
        self._processed_source_fingerprints = set()
        self.pending_js_files = set()
        self.js_split_id_counter = 1
        # VM 保护策略：
        # 1) 文件级熔断：触发异常的文件本轮不再尝试 VM；
        # 2) 全局冷却：连续多次异常时短暂禁用 VM，之后自动恢复。
        self._vm_broken = False
        self._vm_file_blocklist = set()
        self._vm_global_failures = 0
        self._vm_global_failure_threshold = 3
        self._vm_disabled_until = 0.0
        self._vm_cooldown_seconds = 25
        self._vm_cooldown_notice_logged = False
        self._known_static_dirs_cache = None
        self._db_retry_limit = 6
        self._db_lock = Lock()
        self._recover_checkpoint_path = ""
        self._recover_checkpoint_dirty = False
        self._recover_checkpoint_last_flush = 0.0
        self._recover_checkpoint_min_interval = 2.0
        self._local_source_cache = {}
        self._sourcemap_root_marker = "/sourcemaps/"
        self._sourcemap_sources_marker = "/sourcemaps/sources/"
        self._sourcemap_mirror_name_re = re.compile(
            r"^sm_[0-9a-f]{40}\.(?:js|mjs|cjs)$",
            re.IGNORECASE,
        )
        try:
            dom_scan_limit = int(getattr(self.options, "dom_scan_max_chars", 900000) or 900000)
        except Exception:
            dom_scan_limit = 900000
        # 为了稳定性给下限，避免被错误配置到过小值导致识别能力明显退化。
        self._dom_scan_max_chars = max(120000, dom_scan_limit)
        self._dom_loader_complex_pattern_limit = 260000
        self._dom_loader_hard_skip_chars = 2000000
        self._webpack_literal_scan_max_chars = 420000
        self._webpack_literal_hard_skip_chars = 2000000
        self._ast_scan_hard_skip_chars = 2800000
        self._regex_scan_max_chars = 420000
        self._regex_scan_hard_skip_chars = 1800000
        try:
            scan_window_overlap = int(getattr(self.options, "scan_window_overlap_chars", 14000) or 14000)
        except Exception:
            scan_window_overlap = 14000
        self._scan_window_overlap_chars = max(2000, min(scan_window_overlap, 90000))
        try:
            regex_max_windows = int(getattr(self.options, "regex_scan_max_windows", 8) or 8)
        except Exception:
            regex_max_windows = 8
        self._regex_scan_max_windows = max(2, min(regex_max_windows, 16))
        try:
            ast_window_chars = int(getattr(self.options, "ast_scan_window_max_chars", 360000) or 360000)
        except Exception:
            ast_window_chars = 360000
        self._ast_scan_window_max_chars = max(140000, ast_window_chars)
        try:
            ast_max_windows = int(getattr(self.options, "ast_scan_max_windows", 6) or 6)
        except Exception:
            ast_max_windows = 6
        self._ast_scan_max_windows = max(2, min(ast_max_windows, 12))
        self._runtime_chunk_ids_cache = {}
        self._runtime_bundle_profile_cache = {}
        self._trusted_external_origins = set()
        self._trusted_external_domains = set()

    def _extract_sourcemap_relative_path(self, file_path):
        try:
            normalized = os.path.normpath(file_path or "").replace("\\", "/")
            if self._sourcemap_sources_marker in normalized:
                return normalized.split(self._sourcemap_sources_marker, 1)[1].strip("/")

            if self._sourcemap_root_marker not in normalized:
                return ""
            tail = normalized.split(self._sourcemap_root_marker, 1)[1].strip("/")
            if not tail:
                return ""
            first, sep, rest = tail.partition("/")
            if not sep or not first.lower().endswith(".map") or not rest:
                return ""
            return f"{first}/{rest}"
        except Exception:
            return ""

    def _is_sourcemap_source_file(self, file_path):
        try:
            return bool(self._extract_sourcemap_relative_path(file_path))
        except Exception:
            return False

    def _is_sourcemap_mirror_file(self, file_path):
        try:
            basename = os.path.basename(file_path or "")
            return bool(self._sourcemap_mirror_name_re.match(basename))
        except Exception:
            return False

    def _should_include_recover_file(self, file_path):
        try:
            normalized = os.path.normpath(file_path or "")
            if not normalized.endswith((".js", ".mjs")):
                return False
            if self._is_sourcemap_source_file(normalized):
                return False
            if self._is_sourcemap_mirror_file(normalized):
                return False
            return True
        except Exception:
            return False

    def _get_dom_scan_content(self, js_content, jsFilePath):
        text = js_content or ""
        if len(text) <= self._dom_scan_max_chars:
            return text
        trimmed = text[:self._dom_scan_max_chars]
        self.log.debug(
            f"[Debug] DOM加载器扫描已截断: {Utils().getFilename(jsFilePath)}"
        )
        return trimmed

    def _should_skip_dom_loader(self, content_len):
        try:
            return int(content_len or 0) > self._dom_loader_hard_skip_chars
        except Exception:
            return False

    def _get_webpack_literal_scan_content(self, js_content, jsFilePath):
        text = js_content or ""
        if len(text) <= self._webpack_literal_scan_max_chars:
            return text
        trimmed = text[:self._webpack_literal_scan_max_chars]
        self.log.debug(
            f"[Debug] Webpack字面量检测已截断: {Utils().getFilename(jsFilePath)}"
        )
        return trimmed

    def _should_skip_webpack_literal_scan(self, content_len):
        try:
            return int(content_len or 0) > self._webpack_literal_hard_skip_chars
        except Exception:
            return False

    def _should_skip_ast_scan(self, content_len):
        try:
            return int(content_len or 0) > self._ast_scan_hard_skip_chars
        except Exception:
            return False

    def _should_skip_regex_scan(self, content_len):
        try:
            return int(content_len or 0) > self._regex_scan_hard_skip_chars
        except Exception:
            return False

    def _get_regex_scan_content(self, js_content, jsFilePath):
        text = js_content or ""
        if len(text) <= self._regex_scan_max_chars:
            return text
        trimmed = text[:self._regex_scan_max_chars]
        self.log.debug(
            f"[Debug] Regex扫描已截断: {Utils().getFilename(jsFilePath)}"
        )
        return trimmed

    def _estimate_scan_window_count(self, content_len, window_chars, max_windows, hard_skip_chars=0):
        try:
            size = max(1, int(content_len or 0))
            width = max(1, int(window_chars or 1))
            cap = max(1, int(max_windows or 1))
            if size <= width:
                return 1
            if hard_skip_chars and size > int(hard_skip_chars):
                return cap
            approx = (size + width - 1) // width
            return max(2, min(cap, approx))
        except Exception:
            return max(1, int(max_windows or 1))

    def _collect_loader_anchor_positions(self, text, limit=64):
        try:
            if not text:
                return []
            lowered = str(text).lower()
            tokens = [
                ".e=function",
                ".u=function",
                ".e=e=>",
                ".u=e=>",
                ".e=>",
                ".u=>",
                "createelement(\"script\")",
                "createelement('script')",
                "promise.all(object.keys(",
                "reduce(((",
                ".src=",
                "setattribute(\"src\"",
                "setattribute('src'",
                ".js\"",
                ".js'",
                ".mjs\"",
                ".mjs'",
                ".cjs\"",
                ".cjs'",
            ]
            anchors = []
            seen = set()
            max_hits = max(8, int(limit or 64))
            for token in tokens:
                cursor = 0
                while cursor < len(lowered) and len(anchors) < max_hits:
                    idx = lowered.find(token, cursor)
                    if idx < 0:
                        break
                    if idx not in seen:
                        anchors.append(idx)
                        seen.add(idx)
                    cursor = idx + max(1, len(token))
                if len(anchors) >= max_hits:
                    break
            anchors.sort()
            return anchors
        except Exception:
            return []

    def _snap_scan_window_boundaries(self, text, start, end, max_shift=2400):
        try:
            n = len(text or "")
            if n <= 0:
                return 0, 0
            start = max(0, min(int(start or 0), n - 1))
            end = max(start + 1, min(int(end or n), n))
            shift = max(120, int(max_shift or 2400))
            separators = ";\n\r}"

            snapped_start = start
            lower = max(0, start - shift)
            upper = min(n - 1, start + shift)
            for i in range(start, lower, -1):
                if text[i - 1] in separators:
                    snapped_start = i
                    break
            if snapped_start == start:
                for i in range(start, upper):
                    if text[i] in separators:
                        snapped_start = i + 1
                        break

            snapped_end = end
            upper_end = min(n - 1, end + shift)
            lower_end = max(0, end - shift)
            for i in range(end, upper_end):
                if text[i] in separators:
                    snapped_end = i + 1
                    break
            if snapped_end == end:
                for i in range(end, lower_end, -1):
                    if text[i - 1] in separators:
                        snapped_end = i
                        break

            snapped_start = max(0, min(snapped_start, n - 1))
            snapped_end = max(snapped_start + 1, min(snapped_end, n))
            return snapped_start, snapped_end
        except Exception:
            return int(start or 0), int(end or 0)

    def _build_scan_windows(self, text, window_chars, max_windows=1, overlap_chars=0, anchor_positions=None):
        raw = text or ""
        total = len(raw)
        if total <= 0:
            return []

        width = max(1200, int(window_chars or 1200))
        cap = max(1, int(max_windows or 1))
        overlap = max(0, int(overlap_chars or 0))

        if total <= width:
            return [(0, total, raw)]

        selected = []
        dedupe_gap = max(6000, width // 5)
        half = width // 2
        overlap_half = overlap // 2

        def _append_window(start_pos):
            if len(selected) >= cap:
                return
            s = max(0, min(int(start_pos or 0), total - width))
            e = min(total, s + width)
            s = max(0, s - overlap_half)
            e = min(total, e + overlap_half)
            s, e = self._snap_scan_window_boundaries(raw, s, e)
            if e - s < 240:
                return
            for old_s, old_e in selected:
                if abs(s - old_s) <= dedupe_gap and abs(e - old_e) <= dedupe_gap:
                    return
            selected.append((s, e))

        _append_window(0)
        if cap > 1:
            _append_window(total - width)

        for pos in (anchor_positions or []):
            if len(selected) >= cap:
                break
            _append_window(int(pos) - half)

        remaining = cap - len(selected)
        if remaining > 0:
            span = max(1, total - width)
            for idx in range(remaining):
                ratio = float(idx + 1) / float(remaining + 1)
                _append_window(int(span * ratio))

        selected.sort(key=lambda item: item[0])
        windows = []
        for s, e in selected[:cap]:
            windows.append((s, e, raw[s:e]))
        return windows

    def _compute_full_coverage_window_width(self, total_chars, base_window_chars, overlap_chars=0, target_segments=0, max_window_chars=0):
        try:
            total = max(1, int(total_chars or 0))
            base = max(1200, int(base_window_chars or 1200))
            if total <= base:
                return total

            overlap = max(0, int(overlap_chars or 0))
            target = max(1, int(target_segments or 0))
            width = base
            if target > 0:
                required = (total + max(0, target - 1) * overlap + target - 1) // target
                width = max(base, required)

            if max_window_chars and int(max_window_chars) > 0:
                width = min(width, max(base, int(max_window_chars)))
            return max(base, width)
        except Exception:
            return max(1200, int(base_window_chars or 1200))

    def _build_full_coverage_windows(
        self,
        text,
        window_chars,
        overlap_chars=0,
        target_segments=0,
        max_window_chars=0,
        anchor_positions=None,
    ):
        raw = text or ""
        total = len(raw)
        if total <= 0:
            return []

        width = self._compute_full_coverage_window_width(
            total,
            window_chars,
            overlap_chars=overlap_chars,
            target_segments=target_segments,
            max_window_chars=max_window_chars,
        )
        overlap = max(0, min(int(overlap_chars or 0), max(0, width // 3)))

        if total <= width:
            windows = [(0, total, raw)]
        else:
            step = max(1, width - overlap)
            selected = []
            start = 0
            while start < total:
                end = min(total, start + width)
                if end <= start:
                    break
                snapped_start, snapped_end = self._snap_scan_window_boundaries(raw, start, end)
                if snapped_end - snapped_start < min(240, max(120, width // 8)):
                    snapped_start, snapped_end = start, end
                if not selected or (snapped_start, snapped_end) != selected[-1]:
                    selected.append((snapped_start, snapped_end))
                if end >= total:
                    break
                next_start = start + step
                if next_start <= start:
                    next_start = end
                start = next_start

            windows = [(s, e, raw[s:e]) for s, e in selected if e > s]

        anchors = sorted(
            {
                int(pos)
                for pos in (anchor_positions or [])
                if isinstance(pos, int) or str(pos).isdigit()
            }
        )
        anchors = [pos for pos in anchors if 0 <= pos < total]
        if not anchors or not windows:
            return windows

        def _count_anchor_hits(start_pos, end_pos):
            hits = 0
            for pos in anchors:
                if pos < start_pos:
                    continue
                if pos >= end_pos:
                    break
                hits += 1
            return hits

        return sorted(windows, key=lambda item: (-_count_anchor_hits(item[0], item[1]), item[0]))

    def _get_db_connection(self):
        projectDBPath = DatabaseType(self.projectTag).getPathfromDB() + self.projectTag + ".db"
        conn = sqlite3.connect(os.sep.join(projectDBPath.split('/')), timeout=30.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=60000")
        except Exception:
            pass
        return conn

    def _checkpoint_path_from_project(self, project_path):
        try:
            return os.path.join(os.path.abspath(project_path), "recover_checkpoint.json")
        except Exception:
            return ""

    def _mark_recover_checkpoint_dirty(self):
        self._recover_checkpoint_dirty = True

    def _flush_recover_checkpoint(self, round_index=0, force=False):
        if not self._recover_checkpoint_path:
            return
        if not self._recover_checkpoint_dirty and not force:
            return

        now = time.time()
        if (not force) and (now - self._recover_checkpoint_last_flush < self._recover_checkpoint_min_interval):
            return

        payload = {
            "version": 1,
            "project_tag": self.projectTag,
            "round_index": int(round_index or 0),
            "updated_at": int(now),
            "processed_files": sorted(self.processed_files),
            "processed_original_names": sorted(self._processed_original_names),
            "processed_source_fingerprints": sorted(self._processed_source_fingerprints),
            "pending_js_files": sorted(self.pending_js_files),
        }

        tmp_path = self._recover_checkpoint_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp_path, self._recover_checkpoint_path)
            self._recover_checkpoint_last_flush = now
            self._recover_checkpoint_dirty = False
        except Exception as e:
            self.log.debug(f"[Debug] 写入恢复检查点失败: {e}")

    def _load_recover_checkpoint(self, project_path):
        self._recover_checkpoint_path = self._checkpoint_path_from_project(project_path)
        if not self._recover_checkpoint_path or not os.path.exists(self._recover_checkpoint_path):
            return
        try:
            with open(self._recover_checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return

            processed_files = data.get("processed_files") or []
            processed_names = data.get("processed_original_names") or []
            processed_fingerprints = data.get("processed_source_fingerprints") or []
            pending = data.get("pending_js_files") or []

            if isinstance(processed_files, list):
                self.processed_files.update(str(x) for x in processed_files if x)
            if isinstance(processed_names, list):
                self._processed_original_names.update(str(x) for x in processed_names if x)
            if isinstance(processed_fingerprints, list):
                self._processed_source_fingerprints.update(str(x) for x in processed_fingerprints if x)
            if isinstance(pending, list):
                self.pending_js_files.update(str(x) for x in pending if x)

            if (not self._processed_source_fingerprints) and self._processed_original_names:
                self._processed_source_fingerprints.update(
                    f"legacy:{name}" for name in self._processed_original_names
                )

            self.log.info(
                f"[checkpoint] 已加载恢复检查点: 已处理 {len(self._processed_source_fingerprints)} 个来源指纹，"
                f"待下载 {len(self.pending_js_files)} 个URL"
            )
        except Exception as e:
            self.log.debug(f"[Debug] 读取恢复检查点失败: {e}")

    def _clear_recover_checkpoint(self):
        if not self._recover_checkpoint_path:
            return
        try:
            if os.path.exists(self._recover_checkpoint_path):
                os.remove(self._recover_checkpoint_path)
        except Exception:
            pass

    def _init_split_id_counter(self):
        conn = None
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            self._execute_db_with_retry(cursor, "SELECT COALESCE(MAX(id), 0) FROM js_split_tree", (), context="init split id")
            row = cursor.fetchone()
            max_id = int(row[0] or 0) if row else 0
            self.js_split_id_counter = max_id + 1
        except Exception:
            # 保持默认初始值，避免影响主流程。
            if self.js_split_id_counter <= 0:
                self.js_split_id_counter = 1
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _get_source_url_by_local(self, local_name):
        if not local_name:
            return ""
        cached = self._local_source_cache.get(local_name)
        if cached is not None:
            return cached
        conn = None
        try:
            conn = self._get_db_connection()
            with self._db_lock:
                cursor = conn.cursor()
                self._execute_db_with_retry(
                    cursor,
                    "SELECT path FROM js_file WHERE local=? ORDER BY id DESC LIMIT 1",
                    (local_name,),
                    context="lookup source url by local",
                )
                row = cursor.fetchone()
            result = str(row[0]).strip() if row and row[0] else ""
            self._local_source_cache[local_name] = result
            return result
        except Exception:
            self._local_source_cache[local_name] = ""
            return ""
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _extract_original_name(self, basename):
        dot_idx = basename.find('.')
        if dot_idx > 0:
            return basename[dot_idx + 1:]
        return basename

    def _compute_file_sha1(self, file_path):
        """
        计算文件内容 SHA1，用于“基于代码内容”的去重。
        去重应围绕可执行内容本身，而不是依赖 URL 后缀或站点命名习惯。
        """
        try:
            h = hashlib.sha1()
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _build_processing_fingerprint(self, jsFilePath):
        basename = os.path.basename(jsFilePath or "")
        original_name = self._extract_original_name(basename)
        content_sha1 = self._compute_file_sha1(jsFilePath)

        source_url = self._get_source_url_by_local(basename)
        if source_url:
            normalized = source_url.strip()
            if normalized:
                if content_sha1:
                    return f"url:{normalized}#sha1:{content_sha1}"
                return f"url:{normalized}#local:{basename}"

        normalized_path = os.path.normpath(jsFilePath or "").replace("\\", "/")
        source_path = self._extract_sourcemap_relative_path(normalized_path)
        if source_path:
            if content_sha1:
                return f"source:{source_path}#sha1:{content_sha1}"
            return f"source:{source_path}"

        if content_sha1:
            return f"content:{content_sha1}"

        return f"legacy:{original_name}"

    def _extract_first_param_name(self, func_node):
        try:
            params = getattr(func_node, 'params', None) or []
            if not params:
                return 'e'
            first = params[0]
            if hasattr(first, 'name') and getattr(first, 'name', None):
                return first.name
            left = getattr(first, 'left', None)
            if left is not None and hasattr(left, 'name') and getattr(left, 'name', None):
                return left.name
            arg = getattr(first, 'argument', None)
            if arg is not None and hasattr(arg, 'name') and getattr(arg, 'name', None):
                return arg.name
            return 'e'
        except Exception:
            return 'e'

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

    def _execute_db_with_retry(self, cursor, sql, params=(), context=""):
        for attempt in range(self._db_retry_limit):
            try:
                cursor.execute(sql, params)
                return
            except sqlite3.OperationalError as e:
                if self._is_db_locked_error(e) and attempt < self._db_retry_limit - 1:
                    self._sleep_db_backoff(attempt)
                    continue
                raise

    def _commit_with_retry(self, conn, context=""):
        for attempt in range(self._db_retry_limit):
            try:
                conn.commit()
                return
            except sqlite3.OperationalError as e:
                if self._is_db_locked_error(e) and attempt < self._db_retry_limit - 1:
                    self._sleep_db_backoff(attempt)
                    continue
                raise

    def _vm_source_key(self, source_file):
        try:
            return os.path.basename(source_file or "").strip()
        except Exception:
            return ""

    def _can_try_vm_for_source(self, source_file):
        source_key = self._vm_source_key(source_file)
        now = time.time()

        if self._vm_disabled_until > 0:
            if now < self._vm_disabled_until:
                if not self._vm_cooldown_notice_logged:
                    remain = max(0, int(self._vm_disabled_until - now))
                    self.log.debug(f"[VM] 冷却中，剩余约 {remain}s，跳过 VM")
                    self._vm_cooldown_notice_logged = True
                self._vm_broken = True
                return False
            # 冷却结束自动恢复
            self._vm_disabled_until = 0.0
            self._vm_broken = False
            self._vm_global_failures = 0
            self._vm_cooldown_notice_logged = False
            self.log.debug("[VM] 冷却结束，恢复 VM 尝试")

        if source_key and source_key in self._vm_file_blocklist:
            self.log.debug(f"[VM] 当前文件已熔断，跳过 VM: {source_key}")
            return False
        return True

    def _mark_vm_failure(self, source_file, reason=""):
        source_key = self._vm_source_key(source_file)
        if source_key:
            self._vm_file_blocklist.add(source_key)

        self._vm_global_failures += 1
        if self._vm_global_failures >= self._vm_global_failure_threshold:
            self._vm_broken = True
            self._vm_disabled_until = time.time() + self._vm_cooldown_seconds
            self._vm_cooldown_notice_logged = False
            self.log.warning(
                f"[VM] 连续异常达到阈值，暂停 VM {self._vm_cooldown_seconds}s，原因: {reason[:120]}"
            )
        elif reason:
            self.log.debug(f"[VM] 标记文件级熔断: {source_key}，原因: {reason[:120]}")

    def _mark_vm_success(self):
        if self._vm_global_failures > 0:
            self._vm_global_failures -= 1

    def _reset_deno_server(self):
        """超时/崩溃后重置 Deno server，使后续 VM 调用可恢复。"""
        bridge = getattr(deno_vm, "DEFAULT_BRIDGE", None)
        if bridge:
            # close 可能阻塞；超时后强制终止底层进程，避免 reset 本身挂住。
            self._close_bridge_with_timeout(bridge, timeout=1.2)

        # 兼容 deno_vm 不同版本的全局 bridge 名称
        try:
            deno_vm.DEFAULT_BRIDGE = None
        except Exception:
            pass
        try:
            deno_vm._default_server = None
        except Exception:
            pass

    def _force_kill_bridge_process(self, bridge):
        try:
            proc = getattr(bridge, "process", None)
            if not proc:
                return
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass
        except Exception:
            pass

    def _close_bridge_with_timeout(self, bridge, timeout=1.2):
        if not bridge:
            return

        def _close():
            try:
                bridge.close()
            except Exception:
                pass

        closer = Thread(target=_close, daemon=True)
        closer.start()
        closer.join(timeout=timeout)
        if closer.is_alive():
            self._force_kill_bridge_process(bridge)

    def _is_vm_safe_expression(self, expr):
        """
        判断表达式是否适合 VM 求值。
        避免把带异步副作用/浏览器上下文依赖的代码喂给 deno_vm，
        这类表达式容易触发 child worker 异常并导致 Broken pipe。
        """
        try:
            text = str(expr or "")
            if not text:
                return False

            lowered = text.lower()
            if len(text) > 8000:
                return False

            if text.count("{") > 40 or text.count("(") > 80:
                return False

            risky_tokens = [
                "new promise",
                "promise.resolve",
                "promise.reject",
                ".then(",
                ".catch(",
                ".finally(",
                "async ",
                "await ",
                "settimeout(",
                "setinterval(",
                "requestanimationframe(",
                "window.",
                "document.",
                "navigator.",
                "location.",
                "globalthis",
                "process.",
                "import(",
                "require(",
                "fetch(",
                "xmlhttprequest",
                "websocket",
                "self.document",
                "self.window",
                "self.location",
                "self.navigator",
            ]
            for token in risky_tokens:
                if token in lowered:
                    return False

            # 函数定义/箭头函数/动态构造器调用，容易触发副作用与 VM 崩溃
            if "=>" in text:
                return False
            if re.search(r"\bfunction\b", text):
                return False
            if re.search(r"\bnew\s+[A-Za-z_$][\w$]*\s*\(", text):
                return False

            # 限制函数调用：仅放行少量纯转换函数，避免业务调用副作用
            allowed_calls = {
                "string", "number", "boolean",
                "parseint", "parsefloat",
                "encodeuri", "encodeuricomponent",
                "decodeuri", "decodeuricomponent",
            }
            for call_name in re.findall(r"\b([A-Za-z_$][\w$]*)\s*\(", text):
                lower_name = call_name.lower()
                # 跳过关键字（如 if/for 等）
                if lower_name in {"if", "for", "while", "switch", "catch", "return"}:
                    continue
                if lower_name not in allowed_calls:
                    return False
            return True
        except Exception:
            return False

    def _execute_in_deno(self, js_code_func, name_list, timeout=15, source_file=None):
        if not self._can_try_vm_for_source(source_file):
            return set()

        filenames_found = set()
        result_queue = multiprocessing.Queue(maxsize=1)
        worker = multiprocessing.Process(
            target=_deno_vm_eval_worker,
            args=(js_code_func, list(name_list), result_queue),
            daemon=True,
        )
        worker.start()
        worker.join(timeout=timeout)

        if worker.is_alive():
            self.log.warning(f"[VM] Deno VM 执行超时（{timeout}s），已终止当前 VM worker")
            try:
                worker.terminate()
                worker.join(timeout=1.0)
            except Exception:
                pass
            if worker.is_alive():
                try:
                    worker.kill()
                    worker.join(timeout=1.0)
                except Exception:
                    pass
            self._mark_vm_failure(source_file, reason="timeout")
            self._reset_deno_server()
            return filenames_found

        payload = None
        try:
            payload = result_queue.get_nowait()
        except queue.Empty:
            payload = None
        except Exception:
            payload = None
        finally:
            try:
                result_queue.close()
            except Exception:
                pass

        if worker.exitcode not in (0, None):
            self._mark_vm_failure(source_file, reason=f"worker_exitcode={worker.exitcode}")
            self._reset_deno_server()
            return filenames_found

        if not payload:
            self._mark_vm_failure(source_file, reason="empty_result")
            self._reset_deno_server()
            return filenames_found

        if payload.get("ok"):
            self._mark_vm_success()
            values = payload.get("filenames") or []
            return set(values)

        err_msg = str(payload.get("error") or "")
        lower_err = err_msg.lower()
        if (
            'broken pipe' in lower_err
            or 'brokenpipeerror' in lower_err
            or 'unhandled error in child worker' in lower_err
            or 'cannot read properties of undefined' in lower_err
            or 'uncaught (in worker' in lower_err
        ):
            self.log.warning(f"[VM] Deno VM 执行异常，已切换为模板回退")
            self._mark_vm_failure(source_file, reason=err_msg)
            self._reset_deno_server()
            return filenames_found
        raise RuntimeError(err_msg if err_msg else "unknown deno vm error")

    @staticmethod
    def _is_bracket_balanced(expr):
        """检查表达式的 {}[]() 是否平衡，不平衡说明提取越界。"""
        depth = {'(': 0, '[': 0, '{': 0}
        pairs = {')': '(', ']': '[', '}': '{'}
        in_str = None
        prev = None
        for ch in expr:
            if in_str:
                if ch == in_str and prev != '\\':
                    in_str = None
            else:
                if ch in ('"', "'", '`'):
                    in_str = ch
                elif ch in depth:
                    depth[ch] += 1
                elif ch in pairs:
                    depth[pairs[ch]] -= 1
                    if depth[pairs[ch]] < 0:
                        return False
            prev = ch
        return all(v == 0 for v in depth.values())

    def _sanitize_code_body(self, code_body):
        """
        移除运行时 publicPath 前缀（*.p +），避免依赖外部上下文。
        例如：i.p + "static/js/" -> "static/js/"
        """
        try:
            sanitized = re.sub(r"[A-Za-z_$][\w$]*\.p\s*\+\s*", "", code_body)
            sanitized = re.sub(r"__webpack_require__\.p\s*\+\s*", "", sanitized)
            return sanitized
        except Exception:
            return code_body

    def _extract_keys_robust(self, code_text):
        """
        解析对象字面量的键，兼容 引号/标识符/数字键，用于枚举可能的 chunkId/name。
        """
        try:
            keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', code_text)
            result = set()
            for a, b, c, d in keys:
                key = a or b or c or d
                if key is not None and key != "":
                    result.add(str(key))
            return list(result)
        except Exception:
            return []

    def _extract_keys_followed_by_param(self, code_text, param_name):
        """
        在 return 表达式中，优先提取 "{...}[param]" 这种紧邻对象取下标的键集合，
        使用平衡括号向后/向前扫描，兼容对象值内部包含嵌套花括号的情况。
        """
        try:
            results = set()
            bracket_pat = re.compile(r"\[\s*" + re.escape(param_name) + r"\s*\]")
            for m in bracket_pat.finditer(code_text):
                idx = m.start() - 1
                # 跳过空白与外围括号包裹
                while idx >= 0 and code_text[idx].isspace():
                    idx -= 1
                # 若遇到右括号，回退到与之匹配的左括号（处理 ({...})[e] 情况）
                if idx >= 0 and code_text[idx] == ')':
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == ')':
                            depth += 1
                        elif ch == '(':
                            depth -= 1
                        idx -= 1
                    while idx >= 0 and code_text[idx].isspace():
                        idx -= 1
                # 现在应位于 '}' 处；向前做花括号配对，截出 { ... }
                if idx >= 0 and code_text[idx] == '}':
                    end_brace = idx
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == '}':
                            depth += 1
                        elif ch == '{':
                            depth -= 1
                        idx -= 1
                    start_brace = idx + 1
                    if start_brace >= 0 and end_brace > start_brace:
                        obj_text = code_text[start_brace:end_brace+1]
                        keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', obj_text)
                        for a,b,c,d in keys:
                            k = a or b or c or d
                            if k:
                                results.add(str(k))
            return list(results)
        except Exception:
            return []

    def _extract_keys_by_ast(self, code_text):
        """
        使用 esprima 对表达式进行 AST 解析，直接提取其中所有 ObjectExpression 的键。
        作为正则失败时的通用兜底方案。
        """
        try:
            wrapper = f"function __W(e){{ return {code_text}; }}"
            ast = esprima.parseScript(wrapper, {'range': True, 'tolerant': True})
            found = set()

            def walk(node):
                if not node or not isinstance(node, esprima.nodes.Node):
                    return
                if getattr(node, 'type', None) == 'ObjectExpression':
                    for prop in getattr(node, 'properties', []):
                        key_node = getattr(prop, 'key', None)
                        k = None
                        if key_node is None:
                            continue
                        # Identifier key
                        if hasattr(key_node, 'name') and key_node.name is not None:
                            k = key_node.name
                        # Literal key (string/number)
                        elif hasattr(key_node, 'value') and key_node.value is not None:
                            k = str(key_node.value)
                        if k is not None and k != "":
                            found.add(str(k))
                # walk children
                for attr in dir(node):
                    if attr.startswith('_'):
                        continue
                    child = getattr(node, attr)
                    if isinstance(child, esprima.nodes.Node):
                        walk(child)
                    elif isinstance(child, list):
                        for it in child:
                            if isinstance(it, esprima.nodes.Node):
                                walk(it)

            walk(ast)
            return list(found)
        except Exception:
            return []

    def _find_indexed_vars(self, code_text, param_name):
        """
        在返回表达式中查找形如: ident[param_name] 的下标访问，返回 ident 列表。
        例如返回 ['t','n'] 对应 t[e], n[e]。
        """
        try:
            idents = re.findall(r"([A-Za-z_$][\w$]*)\s*\[\s*" + re.escape(param_name) + r"\s*\]", code_text)
            return list(set(idents))
        except Exception:
            return []

    def _extract_object_keys_from_parent_by_ast(self, var_names, parent_js_content):
        """
        在父JS内容中，使用AST查找 变量=对象字面量 的定义，从而提取键集合。
        支持: var/let/const 声明中的 ObjectExpression，或赋值表达式中的 ObjectExpression。
        """
        results = set()
        try:
            ast = esprima.parseScript(parent_js_content, {'range': True, 'tolerant': True})
        except Exception:
            return results

        def collect_from_object(obj_expr):
            for prop in getattr(obj_expr, 'properties', []):
                key_node = getattr(prop, 'key', None)
                k = None
                if key_node is None:
                    continue
                if hasattr(key_node, 'name') and key_node.name is not None:
                    k = key_node.name
                elif hasattr(key_node, 'value') and key_node.value is not None:
                    k = str(key_node.value)
                if k is not None and k != "":
                    results.add(str(k))

        def walk(node):
            if not node or not isinstance(node, esprima.nodes.Node):
                return
            ntype = getattr(node, 'type', None)
            if ntype == 'VariableDeclarator':
                id_node = getattr(node, 'id', None)
                init = getattr(node, 'init', None)
                if id_node and getattr(id_node, 'name', None) in var_names and getattr(init, 'type', None) == 'ObjectExpression':
                    collect_from_object(init)
            elif ntype == 'AssignmentExpression' and getattr(node, 'operator', None) == '=':
                left = getattr(node, 'left', None)
                right = getattr(node, 'right', None)
                if getattr(right, 'type', None) == 'ObjectExpression':
                    # 情况1：简单变量赋值  v = { ... }
                    if getattr(left, 'type', None) == 'Identifier' and getattr(left, 'name', None) in var_names:
                        collect_from_object(right)
                    # 情况2：对象属性赋值  obj.v = { ... } 或 obj["v"] = { ... }
                    elif getattr(left, 'type', None) == 'MemberExpression':
                        prop = getattr(left, 'property', None)
                        pname = None
                        if prop is not None:
                            if getattr(left, 'computed', False):
                                # obj["v"]
                                if hasattr(prop, 'value') and prop.value is not None:
                                    pname = str(prop.value)
                            else:
                                # obj.v
                                if hasattr(prop, 'name') and prop.name is not None:
                                    pname = prop.name
                        if pname in var_names:
                            collect_from_object(right)
            for attr in dir(node):
                if attr.startswith('_'):
                    continue
                child = getattr(node, attr)
                if isinstance(child, esprima.nodes.Node):
                    walk(child)
                elif isinstance(child, list):
                    for it in child:
                        if isinstance(it, esprima.nodes.Node):
                            walk(it)

        walk(ast)
        return results

    def _iter_object_texts_for_param(self, code_text, param_name):
        """
        返回表达式中，找到所有形如 { ... }[param_name] 的对象文本（包含花括号）。
        使用平衡括号向后/向前扫描，避免被嵌套干扰。
        """
        texts = []
        try:
            bracket_pat = re.compile(r"\[\s*" + re.escape(param_name) + r"\s*\]")
            for m in bracket_pat.finditer(code_text):
                idx = m.start() - 1
                while idx >= 0 and code_text[idx].isspace():
                    idx -= 1
                if idx >= 0 and code_text[idx] == ')':
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == ')':
                            depth += 1
                        elif ch == '(':
                            depth -= 1
                        idx -= 1
                    while idx >= 0 and code_text[idx].isspace():
                        idx -= 1
                if idx >= 0 and code_text[idx] == '}':
                    end_brace = idx
                    depth = 1
                    idx -= 1
                    while idx >= 0 and depth > 0:
                        ch = code_text[idx]
                        if ch == '}':
                            depth += 1
                        elif ch == '{':
                            depth -= 1
                        idx -= 1
                    start_brace = idx + 1
                    if start_brace >= 0 and end_brace > start_brace:
                        texts.append(code_text[start_brace:end_brace+1])
        except Exception:
            pass
        return texts

    def _find_balanced_block(self, text, start_pos):
        """
        从 start_pos 处的 '{' 开始，返回与之匹配的大括号内的文本（不包含最外层花括号）。
        尽量忽略字符串中的花括号干扰（简单跳过引号片段）。
        """
        try:
            n = len(text)
            if start_pos < 0 or start_pos >= n or text[start_pos] != '{':
                return ''
            depth = 0
            i = start_pos
            while i < n:
                ch = text[i]
                if ch == '"' or ch == '\'':
                    q = ch
                    i += 1
                    # 跳过带转义的字符串内容
                    while i < n:
                        if text[i] == '\\':
                            i += 2
                            continue
                        if text[i] == q:
                            i += 1
                            break
                        i += 1
                    continue
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return text[start_pos+1:i]
                i += 1
        except Exception:
            pass
        return ''

    def _extract_assignment_expression(self, text, expr_start, max_chars=220000):
        """
        从赋值表达式起点提取右值，兼容超长单行与无分号场景。
        在顶层遇到分号/换行/疑似下一条赋值时停止。
        """
        try:
            raw = text or ""
            n = len(raw)
            if n <= 0:
                return ""

            i = max(0, min(int(expr_start or 0), n))
            while i < n and raw[i].isspace():
                i += 1
            start = i
            if start >= n:
                return ""

            hard_end = min(n, start + max(2000, int(max_chars or 220000)))
            quote = None
            escape = False
            depth_paren = 0
            depth_bracket = 0
            depth_brace = 0

            while i < hard_end:
                ch = raw[i]
                if quote is not None:
                    if escape:
                        escape = False
                    elif ch == "\\":
                        escape = True
                    elif ch == quote:
                        quote = None
                    i += 1
                    continue

                if ch in ('"', "'", "`"):
                    quote = ch
                    i += 1
                    continue

                if ch == "(":
                    depth_paren += 1
                elif ch == ")":
                    depth_paren = max(0, depth_paren - 1)
                elif ch == "[":
                    depth_bracket += 1
                elif ch == "]":
                    depth_bracket = max(0, depth_bracket - 1)
                elif ch == "{":
                    depth_brace += 1
                elif ch == "}":
                    # 顶层右花括号通常意味着当前表达式已结束
                    if depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                        break
                    depth_brace = max(0, depth_brace - 1)
                elif depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                    if ch == ";" or ch == "\n" or ch == "\r":
                        break
                    if ch == ",":
                        tail = raw[i + 1:i + 92]
                        if re.match(r"\s*(?:[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*|[A-Za-z_$][\w$]*)\s*=", tail):
                            break
                i += 1

            expr = raw[start:i].strip()
            if expr.lower().startswith("return "):
                expr = expr[7:].strip()
            if expr.endswith(","):
                expr = expr[:-1].rstrip()
            return expr
        except Exception:
            return ""

    def _extract_return_expr_from_func_body(self, body_text):
        """
        从函数体中提取第一条 return 表达式（不含分号）。
        """
        try:
            exprs = self._extract_return_exprs_from_func_body(body_text, max_items=1)
            return exprs[0] if exprs else ''
        except Exception:
            return ''

    def _extract_return_exprs_from_func_body(self, body_text, max_items=12):
        """
        从函数体中尽量提取多条 return 表达式（不含分号）。
        使用轻量级词法扫描，尽量避免字符串与嵌套括号中的分号干扰。
        """
        results = []
        try:
            text = body_text or ''
            n = len(text)
            idx = 0

            while idx < n and len(results) < max_items:
                m = re.search(r"\breturn\b", text[idx:])
                if not m:
                    break

                start = idx + m.end()
                i = start
                quote = None
                escape = False
                depth_paren = 0
                depth_bracket = 0
                depth_brace = 0

                while i < n:
                    ch = text[i]

                    if quote is not None:
                        if escape:
                            escape = False
                        elif ch == '\\':
                            escape = True
                        elif ch == quote:
                            quote = None
                        i += 1
                        continue

                    if ch in ('"', "'", '`'):
                        quote = ch
                        i += 1
                        continue

                    if ch == '(':
                        depth_paren += 1
                    elif ch == ')':
                        depth_paren = max(0, depth_paren - 1)
                    elif ch == '[':
                        depth_bracket += 1
                    elif ch == ']':
                        depth_bracket = max(0, depth_bracket - 1)
                    elif ch == '{':
                        depth_brace += 1
                    elif ch == '}':
                        if depth_brace == 0:
                            break
                        depth_brace = max(0, depth_brace - 1)
                    elif ch == ';' and depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                        break

                    i += 1

                expr = text[start:i].strip()
                if expr:
                    results.append(expr)

                idx = i + 1
        except Exception:
            return results

        return results

    def _make_expr_signature(self, param_name, expr_text):
        """
        生成表达式去重签名，避免 AST/Regex 重复解析同一片段。
        """
        try:
            param = str(param_name or 'e').strip()
            expr = str(expr_text or '')
            normalized = re.sub(r'\s+', '', expr)
            if len(normalized) > 5000:
                normalized = normalized[:5000]
            digest = hashlib.sha1(normalized.encode('utf-8', errors='ignore')).hexdigest()
            return f"{param}:{digest}"
        except Exception:
            return f"{param_name}:fallback"

    def _mark_expr_seen(self, shared_seen, param_name, expr_text):
        """
        标记表达式去重。返回 True 表示首次出现，可继续处理。
        """
        if shared_seen is None:
            return True
        try:
            key = self._make_expr_signature(param_name, expr_text)
            if key in shared_seen:
                return False
            shared_seen.add(key)
            return True
        except Exception:
            return True

    def _collect_return_exprs_from_ast_node(self, node, js_content, results, max_items=18, visited=None):
        """
        从 AST 节点递归收集可还原表达式：
        - ReturnStatement argument
        - script.src = <expr>
        - xxx.setAttribute("src", <expr>)
        """
        if visited is None:
            visited = set()

        try:
            if len(results) >= max_items:
                return
            if not node or not isinstance(node, esprima.nodes.Node):
                return

            node_id = id(node)
            if node_id in visited:
                return
            visited.add(node_id)

            if getattr(node, 'type', None) == 'ReturnStatement' and getattr(node, 'argument', None):
                arg = node.argument
                if hasattr(arg, 'range') and arg.range:
                    start, end = arg.range
                    expr = js_content[start:end]
                    if expr and len(results) < max_items:
                        results.append(expr)
                return

            # 常见 webpack runtime 形态：script.src = ...
            if (
                getattr(node, 'type', None) == 'AssignmentExpression'
                and getattr(node, 'operator', None) == '='
                and getattr(node, 'left', None) is not None
                and getattr(node, 'right', None) is not None
            ):
                left = node.left
                prop_name = None
                if getattr(left, 'type', None) == 'MemberExpression':
                    prop = getattr(left, 'property', None)
                    if getattr(left, 'computed', False):
                        if hasattr(prop, 'value') and prop.value is not None:
                            prop_name = str(prop.value)
                    else:
                        prop_name = getattr(prop, 'name', None)

                if prop_name and str(prop_name).lower() == 'src':
                    right = node.right
                    if hasattr(right, 'range') and right.range:
                        start, end = right.range
                        expr = js_content[start:end]
                        if expr and len(results) < max_items:
                            results.append(expr)

            # 兼容 setAttribute("src", expr) 写法
            if getattr(node, 'type', None) == 'CallExpression' and getattr(node, 'callee', None) is not None:
                callee = node.callee
                if getattr(callee, 'type', None) == 'MemberExpression':
                    prop = getattr(callee, 'property', None)
                    method_name = getattr(prop, 'name', None)
                    if method_name == 'setAttribute':
                        args = getattr(node, 'arguments', []) or []
                        if len(args) >= 2:
                            first = args[0]
                            second = args[1]
                            first_val = getattr(first, 'value', None)
                            if isinstance(first_val, str) and first_val.lower() == 'src':
                                if hasattr(second, 'range') and second.range:
                                    start, end = second.range
                                    expr = js_content[start:end]
                                    if expr and len(results) < max_items:
                                        results.append(expr)

            for key in dir(node):
                if key.startswith('_'):
                    continue
                child = getattr(node, key)
                if isinstance(child, esprima.nodes.Node):
                    self._collect_return_exprs_from_ast_node(child, js_content, results, max_items=max_items, visited=visited)
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, esprima.nodes.Node):
                            self._collect_return_exprs_from_ast_node(item, js_content, results, max_items=max_items, visited=visited)
        except Exception:
            return

    def _extract_candidate_exprs_from_function_ast(self, func_node, js_content):
        """
        从函数 AST 中提取候选表达式：
        - 块体函数：收集多条 return argument
        - 表达式体箭头函数：直接取 body
        """
        exprs = []
        try:
            body = getattr(func_node, 'body', None)
            if not body:
                return exprs

            if getattr(body, 'type', None) == 'BlockStatement':
                self._collect_return_exprs_from_ast_node(body, js_content, exprs, max_items=18)
            elif hasattr(body, 'range') and body.range:
                start, end = body.range
                expr = js_content[start:end]
                if expr:
                    exprs.append(expr)

            # 局部去重，保持顺序
            unique = []
            seen_local = set()
            for expr in exprs:
                sig = self._make_expr_signature('_', expr)
                if sig in seen_local:
                    continue
                seen_local.add(sig)
                unique.append(expr)
            return unique
        except Exception:
            return exprs

    def _parse_kv_from_object_text(self, obj_text):
        """
        从对象字面量文本中解析 key->value（字符串/标识符/数字）映射。
        仅做简单场景解析，足以应对 webpack 名称与 hash 映射。
        """
        mapping = {}
        try:
            pat = re.compile(r'[{},]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))')
            for a,b,c,d,e,f,g,h in pat.findall(obj_text):
                k = a or b or c or d
                v = e or f or g or h
                if k is not None and v is not None and k != "":
                    mapping[str(k)] = str(v)
        except Exception:
            pass
        return mapping

    def _extract_string_literals(self, code_text):
        """
        提取表达式内出现的字符串字面量（保持出现顺序）。
        """
        strings = []
        try:
            for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', code_text):
                s = m.group(1) if m.group(1) is not None else m.group(2)
                strings.append(s)
        except Exception:
            pass
        return strings

    def _normalize_candidate_name(self, value):
        try:
            text = str(value).strip()
            if not text:
                return ""

            text = text.replace("\\/", "/")
            text = text.replace("\\u2028", "").replace("\\u2029", "")
            text = text.replace("\u2028", "").replace("\u2029", "")

            for _ in range(3):
                if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'", "`"):
                    text = text[1:-1].strip()
                    continue
                if len(text) >= 2 and text[0] == '(' and text[-1] == ')':
                    text = text[1:-1].strip()
                    continue
                break

            return text
        except Exception:
            return ""

    def _looks_like_code_fragment(self, text):
        try:
            if not text:
                return False

            if re.search(r'[\r\n\t\u2028\u2029]', text):
                return True

            if re.search(r'(?i)\b(?:function|return|requirejs|define|module\.exports|exports\.|window\.|document\.)\b', text):
                return True

            if re.search(r'=>|[{}]|`', text):
                return True

            if ';' in text and len(text) > 120:
                return True

            if (text.count('(') + text.count(')')) > 8 and len(text) > 90:
                return True

            return False
        except Exception:
            return True

    def _is_reasonable_module_id(self, module_id):
        try:
            text = self._normalize_candidate_name(module_id)
            if not text:
                return False

            if len(text) > 120:
                return False

            if re.search(r'\s', text):
                return False

            if re.search(r'[\r\n\t\u2028\u2029]', text):
                return False

            if re.search(r'(?i)^https?://', text):
                return False

            if self._looks_like_code_fragment(text):
                return False

            if not re.search(r'[A-Za-z0-9]', text):
                return False

            if not re.fullmatch(r'[A-Za-z0-9_@./:+%$~\-]+', text):
                return False

            return True
        except Exception:
            return False

    def _filter_module_ids(self, module_ids, max_items=600):
        results = []
        seen = set()
        try:
            for raw_id in (module_ids or []):
                cleaned = self._normalize_candidate_name(raw_id)
                if not self._is_reasonable_module_id(cleaned):
                    continue
                if cleaned in seen:
                    continue
                seen.add(cleaned)
                results.append(cleaned)
                if len(results) >= max_items:
                    break
        except Exception:
            return results
        return results

    def _is_high_conf_chunk_name(self, module_id):
        try:
            text = str(module_id)
            if not text:
                return False

            if re.fullmatch(r'\d{1,6}', text):
                return True

            if re.search(r'(?i)(?:chunk|runtime|vendor|manifest|polyfills|async|lazy)', text):
                return True

            if re.search(r'[_\-/]', text):
                return True

            if re.search(r'\d', text):
                return True

            if re.search(r'(?i)[0-9a-f]{6,}', text):
                return True

            if text in {"main", "app", "index", "common", "home", "login"}:
                return True

            return False
        except Exception:
            return False

    def _has_param_path_join_hint(self, expr, param_name):
        """判断表达式是否存在“参数参与路径拼接”的强信号。"""
        try:
            if not expr or not param_name:
                return False

            p = re.escape(param_name)
            patterns = [
                r'["\'][^"\']*/[^"\']*["\']\s*\+\s*(?:[^;]{0,160}?\[\s*' + p + r'\s*\]|' + p + r')',
                r'(?:\[\s*' + p + r'\s*\]|' + p + r')\s*\+\s*["\'][^"\']*\.(?:js|mjs|cjs)',
                r'\[\s*' + p + r'\s*\].{0,240}\.(?:js|mjs|cjs)\b',
                r'`[^`]{0,320}\$\{\s*' + p + r'(?:\s*\.\s*toString\s*\(\s*\))?\s*\}[^`]{0,320}`',
                r'["\'][^"\']*/[^"\']*["\']\s*\+\s*(?:String\s*\(\s*' + p + r'\s*\)|' + p + r'\s*\.\s*toString\s*\(\s*\))',
                r'(?:String\s*\(\s*' + p + r'\s*\)|' + p + r'\s*\.\s*toString\s*\(\s*\))\s*\+\s*["\'][^"\']*\.(?:js|mjs|cjs)',
            ]
            return any(re.search(pt, expr, re.I) for pt in patterns)
        except Exception:
            return False

    def _looks_context_require_map(self, mapping):
        """识别 webpack context require 映射（./x.js -> moduleId），这类不是远端 chunk URL。"""
        try:
            if not mapping or len(mapping) < 3:
                return False

            items = list(mapping.items())[:400]
            total = max(1, len(items))

            rel_key_ratio = sum(
                1
                for k, _ in items
                if str(k).startswith('./') and str(k).lower().endswith(('.js', '.mjs', '.cjs'))
            ) / total

            numeric_val_ratio = sum(
                1
                for _, v in items
                if re.fullmatch(r'\d{1,7}', str(v).strip() or '')
            ) / total

            return rel_key_ratio >= 0.6 and numeric_val_ratio >= 0.6
        except Exception:
            return False

    def _select_names_for_no_map_template(self, name_list, context_is_loader):
        cleaned = self._filter_module_ids(name_list)
        if not cleaned:
            return []

        high_conf = [n for n in cleaned if self._is_high_conf_chunk_name(n)]

        if not context_is_loader:
            return high_conf[:120]

        if high_conf:
            return high_conf[:120]

        semantic_allow = {
            "main", "index", "app", "home", "login", "common",
            "vendor", "runtime", "manifest", "polyfills",
        }
        semantic = [
            n for n in cleaned
            if n.lower() in semantic_allow
            or n.lower().startswith(("chunk", "vendor", "runtime"))
        ]
        if semantic:
            return semantic[:20]

        return []

    def _score_candidate_path(self, candidate_path):
        try:
            text = self._normalize_candidate_name(candidate_path)
            if not text:
                return -10

            score = 0
            lower = text.lower()
            no_query = lower.split('?', 1)[0].split('#', 1)[0]

            if re.search(r'\.(?:js|mjs|cjs)(?:$|\?)', lower):
                score += 5
            elif re.search(r'(?:[?&](?:module|import|js|format)=|[?&]type=module\b)', lower):
                score += 4

            if re.search(r'(?i)(?:^|/)(?:assets|static|scripts?|chunks?|js|dist|build|bundles?|modules?|_next|_nuxt|__build|packed|compiled|generated|out|public)/', no_query):
                score += 2

            if re.search(r'(?i)(?:^|[\/._-])(?:chunk|runtime|vendor|manifest|lazy|async|entry|polyfill|framework|main|app|common|shared)(?:$|[\/._-])', no_query):
                score += 2

            if re.search(r'(?i)[0-9a-f]{6,}', no_query):
                score += 1

            if text.startswith(('http://', 'https://', '/', './', '../')):
                score += 1

            if len(text) <= 180:
                score += 1
            elif len(text) > 320:
                score -= 4

            if self._looks_like_code_fragment(text):
                score -= 8

            if re.search(r'\s', text):
                score -= 3

            if re.search(r'["\'`]', text):
                score -= 3

            return score
        except Exception:
            return -10

    def _filter_chunk_candidates(self, candidates, context_is_loader=True, max_items=240):
        accepted = []
        try:
            for raw in (candidates or []):
                normalized = self._normalize_candidate_name(raw)
                if not normalized:
                    continue

                if not self._is_js_like_candidate(normalized):
                    continue

                score = self._score_candidate_path(normalized)
                threshold = 1 if context_is_loader else 2
                if score < threshold:
                    continue

                accepted.append((score, normalized))

            accepted.sort(key=lambda item: (-item[0], len(item[1]), item[1]))

            results = []
            seen = set()
            for _, candidate in accepted:
                if candidate in seen:
                    continue
                seen.add(candidate)
                results.append(candidate)
                if len(results) >= max_items:
                    break

            return set(results)
        except Exception:
            return set()

    def _is_js_like_candidate(self, path):
        """
        判断一个路径是否“更像 JS/chunk 资源”。

        兼容：
        - 显式 .js/.mjs/.cjs
        - 无后缀但具备 chunk/assets/static 语义的路径
        - 带 ?module/?import 等查询参数
        """
        try:
            if not path:
                return False

            text = self._normalize_candidate_name(path)
            if not text:
                return False

            if len(text) > 320:
                return False

            if re.search(r'[\r\n\t\u2028\u2029]', text):
                return False

            if re.search(r'\s', text):
                return False

            lower = text.lower()

            # 过滤明显不是脚本路径的 MIME type/源码注释片段
            if re.search(r'(?i)\b(?:audio|video|application)/(?:x-|vnd\.apple\.)?mpegurl\b', lower):
                return False
            if 'sourcemappingurl' in lower or 'sourceurl' in lower:
                return False

            # 过滤明显污染的“路径片段”，避免把表达式残片当作资源路径
            if re.search(r'(?i)(?:%0a|%0d|%5c[nr])', text):
                return False

            if re.search(r'(?i)\.concat\s*\(', text):
                return False

            if re.search(r'[\[\]{}]', text):
                return False

            if re.search(r'https?://', text) and not lower.startswith(('http://', 'https://', '//')):
                return False

            if re.search(r'(?i)\.js/(?:assets|static|chunks?|scripts?|js)/', text):
                return False

            if self._looks_like_code_fragment(text):
                return False

            if lower.startswith(('javascript:', 'data:', 'about:', 'blob:', 'mailto:')):
                return False

            no_query = lower.split('?', 1)[0].split('#', 1)[0]

            static_exts = (
                '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.webp', '.woff', '.woff2', '.ttf', '.eot', '.map', '.json',
                '.txt', '.html', '.htm', '.xml', '.pdf', '.zip', '.rar', '.7z',
                '.vue', '.d.ts',
            )
            if no_query.endswith(static_exts):
                return False

            if no_query.endswith(('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx')):
                return True

            if re.search(r'(?:[?&](?:module|import|js|format)=|[?&]type=module\b)', lower):
                return True

            # 无后缀场景：优先判断是否具备 chunk/assets 语义和版本哈希
            has_bundle_dir = re.search(r'(?i)(?:^|/)(?:assets|static|scripts?|chunks?|js|dist|build|bundles?|modules?|_next|_nuxt|__build|packed|compiled|generated|out|public)/', no_query)
            has_bundle_name = re.search(r'(?i)(?:^|[\/._-])(?:chunk|runtime|vendor|manifest|bootstrap|lazy|async|entry|index|polyfill|framework|main|app|common|shared)(?:$|[\/._-])', no_query)
            has_hash = re.search(r'(?i)[0-9a-f]{6,}', no_query)
            if (has_bundle_dir and (has_hash or has_bundle_name)) or (has_bundle_name and '/' in no_query):
                return True

            return False
        except Exception:
            return False

    def _looks_async_loader_expr(self, expr, param_name):
        """判断 return 表达式是否像异步 chunk 加载器。"""
        try:
            if not expr:
                return False

            # 允许 [e] / +e / e+ / `${e}` / String(e) / e.toString() 这几类参数参与形式
            has_param_usage = bool(
                re.search(r"\[\s*" + re.escape(param_name) + r"\s*\]", expr)
                or re.search(r"\+\s*" + re.escape(param_name) + r"\b", expr)
                or re.search(r"\b" + re.escape(param_name) + r"\s*\+", expr)
                or re.search(r"\$\{\s*" + re.escape(param_name) + r"(?:\s*\.\s*toString\s*\(\s*\))?\s*\}", expr)
                or re.search(r"\bString\s*\(\s*" + re.escape(param_name) + r"\s*\)", expr)
                or re.search(r"\b" + re.escape(param_name) + r"\s*\.\s*toString\s*\(\s*\)", expr)
            )
            if not has_param_usage:
                return False

            loader_hint = re.search(
                r'(?i)(?:\.(?:js|mjs|cjs)\b|(?:chunk|runtime|vendor|manifest|lazy|async|publicpath)\b|/(?:assets?|static|scripts?|js|chunks?)/|\?module\b|\?import\b)',
                expr,
            )
            return bool(loader_hint)
        except Exception:
            return False

    def _get_runtime_bundle_profile(self, js_content, jsFilePath):
        """
        返回 runtime 判断画像，供 Regex 与 generic loader 复用。
        tier:
          - strong_runtime: 典型 runtime/入口文件
          - weak_loader:     不足以认定为 runtime，但明显像脚本加载器容器
          - normal:          普通业务文件
        """
        try:
            text = js_content or ""
            filename = Utils().getFilename(jsFilePath).lower()
            cache_key = f"{filename}:{len(text)}"
            cached = self._runtime_bundle_profile_cache.get(cache_key)
            if cached is not None:
                return dict(cached)

            if not text:
                profile = {
                    "score": 0,
                    "tier": "normal",
                    "is_runtime_like": False,
                    "has_loader_keywords": False,
                    "has_asset_join": False,
                }
                self._runtime_bundle_profile_cache[cache_key] = dict(profile)
                return profile

            if len(text) > 280000:
                scan_text = text[:190000] + "\n" + text[-90000:]
            else:
                scan_text = text

            score = 0
            core_markers = [
                r'__webpack_require__',
                r'webpackJsonp',
                r'installedChunks',
                r'jsonpScriptSrc',
                r'publicPath',
                r'__webpack_init_sharing__',
                r'container\.get\s*\(',
                r'container\.init\s*\(',
            ]
            core_hits = 0
            for marker in core_markers:
                if re.search(marker, scan_text):
                    core_hits += 1
            score += core_hits * 2

            if re.search(r'(?i)(?:vendor|vendors|runtime|main|index|app|umi|bootstrap|manifest|entry|loader)', filename):
                score += 1

            has_function_loader = bool(
                re.search(r'\.(?:u|e)\s*=\s*function', scan_text)
                or re.search(r'\b(?:u|e)\s*:\s*function\s*\(', scan_text)
            )
            has_arrow_loader = bool(
                re.search(
                    r'\.(?:u|e)\s*=\s*(?:\(\s*[A-Za-z_$][\w$]*\s*\)|[A-Za-z_$][\w$]*)\s*=>',
                    scan_text,
                )
                or re.search(
                    r'\b(?:u|e)\s*:\s*(?:\(\s*[A-Za-z_$][\w$]*\s*\)|[A-Za-z_$][\w$]*)\s*=>',
                    scan_text,
                )
            )
            if has_function_loader:
                score += 2
            if has_arrow_loader:
                score += 2

            has_loader_orchestration = bool(
                re.search(r'Promise\.all\s*\(', scan_text)
                and re.search(r'Object\.keys\s*\(', scan_text)
                and re.search(r'reduce\s*\(', scan_text)
            )
            if has_loader_orchestration:
                score += 2

            has_asset_join = bool(
                re.search(r'["\'][^"\']*/(?:assets|static|scripts?|chunks?|js)/', scan_text, re.I)
                or re.search(r'(?i)(?:chunk|runtime|vendor|manifest|polyfills|jsonpscriptsrc|remoteentry)', scan_text)
            )
            if has_asset_join:
                score += 1

            has_loader_keywords = bool(
                re.search(
                    r'(?i)(?:loadscript|importscript|createelement\s*\(\s*[\'\"]script|document\.write|\.src\s*=|loadresources|loadassets|import\s*\(|new\s+URL\s*\()',
                    scan_text[:140000],
                )
            )
            if has_loader_keywords and has_asset_join:
                score += 1

            has_loader_shape = has_function_loader or has_arrow_loader or has_loader_orchestration
            if has_loader_shape and (core_hits > 0 or has_asset_join) and score >= 3:
                tier = "strong_runtime"
            elif has_loader_keywords and (has_asset_join or re.search(r'(?i)(?:app|main|index|loader|bootstrap|entry)', filename)):
                tier = "weak_loader"
            else:
                tier = "normal"

            profile = {
                "score": score,
                "tier": tier,
                "is_runtime_like": tier == "strong_runtime",
                "has_loader_keywords": has_loader_keywords,
                "has_asset_join": has_asset_join,
            }
            self._runtime_bundle_profile_cache[cache_key] = dict(profile)
            return profile
        except Exception:
            return {
                "score": 0,
                "tier": "normal",
                "is_runtime_like": False,
                "has_loader_keywords": False,
                "has_asset_join": False,
            }

    def _is_runtime_like_bundle(self, js_content, jsFilePath):
        """
        判断当前文件是否更像打包 runtime/入口文件。
        用于控制 Regex 强回退扫描范围，避免在业务 chunk 上过拟合。
        """
        try:
            profile = self._get_runtime_bundle_profile(js_content, jsFilePath)
            return bool(profile.get("is_runtime_like"))
        except Exception:
            return False

    def _looks_runtime_loader_expr(self, expr, param_name):
        """
        判断是否是 runtime/chunk 生成表达式。
        该判定允许超长表达式，但要求满足更强结构特征以避免误报。
        """
        try:
            text = (expr or "").strip()
            if not text or not param_name:
                return False

            if len(text) > 220000:
                return False

            if not self._looks_async_loader_expr(text, param_name):
                return False

            if not self._has_param_path_join_hint(text, param_name):
                return False

            p = re.escape(param_name)
            has_map_usage = bool(
                re.search(r"\{[\s\S]{0,80000}\}\s*\[\s*" + p + r"\s*\]", text)
                or re.search(r"[A-Za-z_$][\w$]*\s*\[\s*" + p + r"\s*\]", text)
            )
            if not has_map_usage:
                return False

            if not re.search(r'\.(?:js|mjs|cjs)\b', text, re.I):
                return False

            if re.search(r'(?i)/api/', text) and not re.search(r'(?i)/(?:api/)?(?:assets|static|scripts?|chunks?|js|modules?)/', text):
                return False

            return True
        except Exception:
            return False

    def _looks_strong_async_loader_expr(self, expr, param_name, runtime_like=False):
        """
        比 _looks_async_loader_expr 更严格的判定，过滤业务 URL 拼接误报。
        """
        try:
            text = (expr or '').strip()
            if not text:
                return False

            max_len = 2400 if runtime_like else 900
            if len(text) > max_len:
                return False

            if not self._looks_async_loader_expr(text, param_name):
                return False

            if not self._has_param_path_join_hint(text, param_name):
                return False

            # 业务接口 URL 拼接常见噪声：/api/** + query placeholder
            if re.search(r'(?i)/api/', text) and not re.search(r'(?i)/(?:api/)?(?:assets|static|scripts?|chunks?|js|modules?)/', text):
                return False

            if re.search(r'(?i)\b(?:audio|video|application)/(?:x-|vnd\.apple\.)?mpegurl\b', text):
                return False

            if re.search(r'\?(?:[A-Za-z0-9_]+\s*=)', text) and not re.search(r'(?i)(?:chunk|runtime|vendor|manifest|publicpath|__webpack_require__)', text):
                return False

            has_runtime_token = bool(re.search(r'(?i)(?:__webpack_require__|\.p\b|\.u\b|webpack|chunk|publicpath|installedchunks|jsonpscriptsrc)', text))
            map_usage = bool(
                re.search(r"\{[^{}]{0,2400}\}\s*\[\s*" + re.escape(param_name) + r"\s*\]", text)
                or re.search(r"[A-Za-z_$][\w$]*\s*\[\s*" + re.escape(param_name) + r"\s*\]", text)
            )
            js_dir_hint = bool(re.search(r'(?i)["\'][^"\']*/(?:js|assets|static|scripts|chunks?)/', text))

            return has_runtime_token or map_usage or js_dir_hint
        except Exception:
            return False

    def _extract_runtime_chunk_ids(self, parent_js_content, cache_key="", max_items=260):
        """
        从 runtime 的 `.e=function(e){...}` 守卫映射中提取 chunk id。
        典型模式: n={"chunk-xxxx":1,login:1}
        """
        text = parent_js_content or ""
        if not text:
            return []

        cache_token = f"{cache_key}:{len(text)}"
        cached = self._runtime_chunk_ids_cache.get(cache_token)
        if cached is not None:
            return list(cached)

        extracted = []
        seen = set()

        def _collect_from_mapping(mapping):
            if len(mapping) < 3:
                return False
            items = list(mapping.items())[:600]
            total = max(1, len(items))
            numeric_guard_ratio = sum(
                1 for _, v in items if str(v).lower() in {"0", "1", "true", "false"}
            ) / total
            high_conf_ratio = sum(
                1 for k, _ in items if self._is_high_conf_chunk_name(k)
            ) / total
            if numeric_guard_ratio < 0.6 or high_conf_ratio < 0.45:
                return False

            added = False
            for k, _ in items:
                kid = self._normalize_candidate_name(k)
                if not self._is_reasonable_module_id(kid):
                    continue
                if kid in seen:
                    continue
                seen.add(kid)
                extracted.append(kid)
                added = True
                if len(extracted) >= max_items:
                    break
            return added

        def _scan_object_mappings(scan_text):
            obj_pat = re.compile(
                r"(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\{([^{}]{20,18000})\}|"
                r"\b[A-Za-z_$][\w$]*\s*=\s*\{([^{}]{20,18000})\}|"
                r"\binstalledChunks\s*=\s*\{([^{}]{20,18000})\}|"
                r"\be\s*:\s*\{([^{}]{20,18000})\}",
                re.DOTALL,
            )
            for obj_m in obj_pat.finditer(scan_text):
                obj_body = ""
                for idx in range(1, 5):
                    obj_body = obj_m.group(idx) or obj_body
                if not obj_body:
                    continue
                mapping = self._parse_kv_from_object_text("{" + obj_body + "}")
                if not mapping:
                    continue
                _collect_from_mapping(mapping)
                if len(extracted) >= max_items:
                    break

        try:
            scan_window = text
            if len(scan_window) > self._regex_scan_max_chars:
                scan_window = scan_window[:self._regex_scan_max_chars]

            bodies = []

            e_func_pat = re.compile(
                r"(?:\.|\b)e\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{",
                re.I,
            )
            for m in e_func_pat.finditer(scan_window):
                brace_start = m.end() - 1
                body = self._find_balanced_block(scan_window, brace_start)
                if body:
                    bodies.append(body[:32000])

            e_prop_func_pat = re.compile(
                r"(?:^|[,{])\s*e\s*:\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{",
                re.I,
            )
            for m in e_prop_func_pat.finditer(scan_window):
                brace_start = m.end() - 1
                body = self._find_balanced_block(scan_window, brace_start)
                if body:
                    bodies.append(body[:32000])

            e_arrow_pat = re.compile(
                r"(?:\.|\b)e\s*=\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>",
                re.I,
            )
            for m in e_arrow_pat.finditer(scan_window):
                arrow_start = m.end()
                while arrow_start < len(scan_window) and scan_window[arrow_start].isspace():
                    arrow_start += 1
                if arrow_start < len(scan_window) and scan_window[arrow_start] == '{':
                    body = self._find_balanced_block(scan_window, arrow_start)
                else:
                    body = self._extract_assignment_expression(scan_window, arrow_start, max_chars=32000)
                if body:
                    bodies.append((body or "")[:32000])

            e_prop_arrow_pat = re.compile(
                r"(?:^|[,{])\s*e\s*:\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>",
                re.I,
            )
            for m in e_prop_arrow_pat.finditer(scan_window):
                arrow_start = m.end()
                while arrow_start < len(scan_window) and scan_window[arrow_start].isspace():
                    arrow_start += 1
                if arrow_start < len(scan_window) and scan_window[arrow_start] == '{':
                    body = self._find_balanced_block(scan_window, arrow_start)
                else:
                    body = self._extract_assignment_expression(scan_window, arrow_start, max_chars=32000)
                if body:
                    bodies.append((body or "")[:32000])

            if not bodies:
                bodies = [scan_window[:48000]]

            for body in bodies:
                _scan_object_mappings(body)
                if len(extracted) >= max_items:
                    break

            if len(extracted) < max_items:
                _scan_object_mappings(scan_window[:64000])
        except Exception:
            pass

        filtered = self._filter_module_ids(extracted, max_items=max_items)
        self._runtime_chunk_ids_cache[cache_token] = list(filtered)
        return filtered

    def _merge_runtime_chunk_ids_if_needed(self, name_list, sanitized, param_name, jsFilePath, parent_js_content):
        """
        loader 形态为 `({map}[e]||e)` 时，尝试合并 runtime 的 chunkMap（如 u.e 内守卫对象）。
        """
        try:
            merged = list(name_list or [])
            if not merged:
                return merged
            if len(merged) >= 40:
                return merged
            if not param_name:
                return merged
            if not re.search(r"\|\|\s*" + re.escape(param_name) + r"\b", sanitized):
                return merged
            if not self._has_param_path_join_hint(sanitized, param_name):
                return merged

            runtime_ids = self._extract_runtime_chunk_ids(
                parent_js_content,
                cache_key=Utils().getFilename(jsFilePath),
            )
            if not runtime_ids:
                return merged

            before = len(merged)
            merged = self._filter_module_ids(merged + runtime_ids)
            if len(merged) > before:
                self.log.debug(
                    f"[Debug] 结合runtime chunkMap扩展模块ID: {Utils().getFilename(jsFilePath)} ({before} -> {len(merged)})"
                )
            return merged
        except Exception:
            return list(name_list or [])

    def _try_build_filenames_without_vm(self, sanitized, param_name, name_list):
        """
        不依赖 Deno VM，通过结构化模板组装方式生成候选 chunk 文件名。
        典型模式: "prefix/" + ({nameMap}[e]||e) + "." + {hashMap}[e] + ".js"
        """
        filenames = set()
        name_list = self._filter_module_ids(name_list)
        if not name_list:
            return filenames

        param_candidates = []
        try:
            if param_name:
                param_candidates.append(str(param_name))
            for candidate_param in re.findall(r"\[\s*([A-Za-z_$][\w$]*)\s*\]", sanitized):
                if candidate_param not in param_candidates:
                    param_candidates.append(candidate_param)
                if len(param_candidates) >= 8:
                    break
        except Exception:
            pass
        if not param_candidates:
            param_candidates = ["e"]

        selected_param = param_candidates[0]
        context_is_loader = self._looks_async_loader_expr(sanitized, selected_param)

        def _extract_prefix_ext_qs():
            strings = self._extract_string_literals(sanitized)
            prefix = ''
            ext = None
            tail = ''
            qs = ''
            join_suffix = ''

            try:
                banned_ext = re.compile(r'\.(?:png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|json|txt|html?)$', re.I)
                dir_like = [s for s in strings if s.endswith('/') and not banned_ext.search(s)]
                preferred = [s for s in dir_like if re.search(r'(?:^|/)(?:js|assets|static|scripts)/$', s)]
                if preferred:
                    prefix = preferred[0]
                elif dir_like:
                    prefix = dir_like[0]
                else:
                    cand = [s for s in strings if '/' in s and not banned_ext.search(s)]
                    prefix = cand[0] if cand else ''
            except Exception:
                pass

            if not prefix and strings:
                prefix = strings[0] if strings[0].endswith('/') else ''

            for s in reversed(strings):
                m = re.search(r'(\.[A-Za-z0-9][A-Za-z0-9._-]{0,80})?\.(js|mjs|cjs)(\?[^"\']*)?$', s)
                if m:
                    tail = m.group(1) or ''
                    ext = m.group(2)
                    qs = m.group(3) or ''
                    break

            if not qs and ext is None:
                m2 = re.search(r'(\.[A-Za-z0-9][A-Za-z0-9._-]{0,80})?\.(js|mjs|cjs)(\?[^"\'\s]*)?', sanitized)
                if m2:
                    tail = m2.group(1) or ''
                    ext = m2.group(2)
                    qs = m2.group(3) or ''

            if not qs:
                for s in reversed(strings):
                    if '?' in s:
                        idx = s.find('?')
                        qs = s[idx:]
                        break

            try:
                if re.search(r"\|\|\s*" + re.escape(selected_param) + r"\b", sanitized):
                    for s in reversed(strings):
                        m_suffix = re.fullmatch(
                            r"([0-9]{5,64}|[0-9a-fA-F]{6,64})\.(js|mjs|cjs)(\?[^\"']*)?",
                            s,
                            re.I
                        )
                        if not m_suffix:
                            continue
                        join_suffix = m_suffix.group(1) or ''
                        ext = (m_suffix.group(2) or ext)
                        if m_suffix.group(3):
                            qs = m_suffix.group(3)
                        break
            except Exception:
                pass

            return prefix, ext, tail, qs, join_suffix

        try:
            maps = []
            for candidate_param in param_candidates:
                obj_texts = self._iter_object_texts_for_param(sanitized, candidate_param)
                candidate_maps = [self._parse_kv_from_object_text(t) for t in obj_texts]
                candidate_maps = [m for m in candidate_maps if m]
                if candidate_maps:
                    maps = candidate_maps
                    selected_param = candidate_param
                    break

            context_is_loader = self._looks_async_loader_expr(sanitized, selected_param)

            # 关键门槛：仅当表达式中存在“参数参与路径拼接”的信号时才允许模板扩展
            has_param_path_join = self._has_param_path_join_hint(sanitized, selected_param)
            if not has_param_path_join:
                return set()

            prefix, ext, tail, qs, join_suffix = _extract_prefix_ext_qs()

            if not maps:
                names_to_use = self._select_names_for_no_map_template(name_list, context_is_loader)
                if not names_to_use:
                    return set()

                for name in names_to_use:
                    if ext:
                        filenames.add(f"{prefix}{name}{join_suffix}{tail}.{ext}{qs}")
                    else:
                        filenames.add(f"{prefix}{name}{qs}")

                return self._filter_chunk_candidates(filenames, context_is_loader=context_is_loader)

            def is_hexish(s):
                return bool(re.fullmatch(r'[0-9a-fA-F]{4,64}', s or ''))

            name_map = {}
            hash_map = {}

            if len(maps) == 1:
                only = maps[0]
                if self._looks_context_require_map(only):
                    return set()
                vals = list(only.values())[:50]
                hex_ratio = sum(1 for v in vals if is_hexish(v)) / max(1, len(vals))
                eq_ratio = sum(1 for k, v in only.items() if k == v) / max(1, len(only))
                if hex_ratio >= 0.5 and eq_ratio < 0.5:
                    hash_map = only
                else:
                    name_map = only
            else:
                scored = []
                for mp in maps:
                    if self._looks_context_require_map(mp):
                        continue
                    vals = list(mp.values())[:50]
                    hex_ratio = sum(1 for v in vals if is_hexish(v)) / max(1, len(vals))
                    eq_ratio = sum(1 for k, v in mp.items() if k == v) / max(1, len(mp))
                    scored.append((hex_ratio, eq_ratio, mp))
                if not scored:
                    return set()
                scored.sort(key=lambda x: (x[0], -x[1]), reverse=True)
                hash_map = scored[0][2]
                for _, _, mp in scored[1:]:
                    if mp is not hash_map:
                        name_map = mp
                        break
                if not name_map:
                    name_map = hash_map

            for name in name_list:
                nm = self._normalize_candidate_name(name_map.get(name, name))
                if not self._is_reasonable_module_id(nm):
                    continue

                hv = self._normalize_candidate_name(hash_map.get(name, ''))
                if hv and not is_hexish(hv):
                    hv = ''

                # 兜底：当 name_map 未命中但模块ID本身是纯数字时，尝试直接用数字ID查 hash_map
                if not hv and name_map and re.fullmatch(r'\d{1,6}', nm):
                    fallback_hv = self._normalize_candidate_name(hash_map.get(nm, ''))
                    if fallback_hv and is_hexish(fallback_hv):
                        hv = fallback_hv

                if hv:
                    if ext:
                        filenames.add(f"{prefix}{nm}.{hv}{tail}.{ext}{qs}")
                    else:
                        filenames.add(f"{prefix}{nm}.{hv}{qs}")
                elif not hash_map:
                    if ext:
                        filenames.add(f"{prefix}{nm}{join_suffix}{tail}.{ext}{qs}")
                    else:
                        filenames.add(f"{prefix}{nm}{qs}")
        except Exception:
            pass

        return self._filter_chunk_candidates(filenames, context_is_loader=context_is_loader)


    def _extract_object_keys_from_parent_by_regex(self, var_names, parent_js_content):
        """
        正则兜底：在父JS中查找 ident = { ... } 的对象字面量，并解析其键。
        """
        results = set()
        try:
            for v in var_names:
                # 1) var/let/const v = { ... }
                pat = re.compile(r"(?:var|let|const)\s+" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                m = pat.search(parent_js_content)
                # 2) v = { ... }
                if not m:
                    pat2 = re.compile(r"\b" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat2.search(parent_js_content)
                # 3) obj.v = { ... }
                if not m:
                    pat3 = re.compile(r"[A-Za-z_$][\w$]*\s*\.\s*" + re.escape(v) + r"\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat3.search(parent_js_content)
                # 4) obj["v"] = { ... }
                if not m:
                    pat4 = re.compile(r"[A-Za-z_$][\w$]*\s*\[\s*([\"\'])" + re.escape(v) + r"\1\s*\]\s*=\s*\{([^{}]+?)\}", re.DOTALL)
                    m = pat4.search(parent_js_content)
                if m:
                    # 对于 pat4，分组不同，统一取最后一个分组作为对象体
                    obj_body = m.group(m.lastindex) if m.lastindex else m.group(1)
                    keys = re.findall(r'[{,]\s*(?:"((?:[^"\\]|\\.)+)"|\'((?:[^\'\\]|\\.)+)\'|([A-Za-z_$][\w$]*)|(\d+))\s*:', '{'+obj_body+'}')
                    for a,b,c,d in keys:
                        k = a or b or c or d
                        if k:
                            results.add(str(k))
        except Exception:
            pass
        return results


    def compile_from_ast(self, code_body, param_name, jsFilePath, parent_js_content):
        try:
            # 1) 去除 runtime publicPath 前缀，避免依赖 i.p/__webpack_require__.p
            sanitized = self._sanitize_code_body(code_body)
            context_is_loader = self._looks_async_loader_expr(sanitized, param_name)
            # 2) 优先提取与参数相邻的对象键，其次鲁棒正则，再用 AST 作为兜底
            nameList = list(set(self._extract_keys_followed_by_param(sanitized, param_name)))
            if not nameList:
                nameList = list(set(self._extract_keys_robust(sanitized)))
            if not nameList:
                nameList = list(set(self._extract_keys_by_ast(sanitized)))
            if not nameList:
                # 3) 若表达式内未出现对象字面量，尝试解析 ident[param] 中的 ident 在父JS中的对象定义
                indexed_vars = self._find_indexed_vars(sanitized, param_name)
                if indexed_vars:
                    from_parent_ast = self._extract_object_keys_from_parent_by_ast(indexed_vars, parent_js_content)
                    from_parent_regex = set()
                    if not from_parent_ast:
                        from_parent_regex = self._extract_object_keys_from_parent_by_regex(indexed_vars, parent_js_content)
                    nameList = list(set(from_parent_ast) | set(from_parent_regex))
            nameList = self._filter_module_ids(nameList)
            nameList = self._merge_runtime_chunk_ids_if_needed(
                nameList,
                sanitized,
                param_name,
                jsFilePath,
                parent_js_content,
            )
            if not nameList:
                # 输出少量调试信息，便于定位
                self.log.debug(f"在 {Utils().getFilename(jsFilePath)} 中未提取到有效的JS模块ID (AST)，expr_head={sanitized[:180]} ... len={len(sanitized)}")
                return

            self.log.info(f"  → 提取到 {len(nameList)} 个模块ID (AST)")
            # 3) 优先走模板拼接（零执行副作用），模板失败才尝试 VM 求值
            alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
            if alt:
                self._log_filenames_success_once(jsFilePath, alt, "Template")
                self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                return

            filenames_found = set()
            # 4) 注入常见别名桩，谨慎使用 VM，仅在足够安全时执行
            prefix_stub = "var __webpack_require__={p:''},i={p:''},t={p:''},n={p:''},r={p:''},o={p:''},a={p:''};"
            vm_available = self._can_try_vm_for_source(jsFilePath)
            can_try_vm = (
                vm_available
                and len(nameList) <= 20
                and len(sanitized) <= 8000
                and not context_is_loader
                and self._is_bracket_balanced(sanitized)
                and self._is_vm_safe_expression(sanitized)
            )

            if can_try_vm:
                js_code_func = f"{prefix_stub} function js_compile({param_name}){{ try{{ return {sanitized}; }}catch(e){{ return undefined; }} }}"
                filenames_found = self._execute_in_deno(js_code_func, nameList, source_file=jsFilePath)
            else:
                if not vm_available:
                    self.log.debug(f"  → 当前文件/全局VM处于熔断或冷却，跳过 VM 求值")
                elif context_is_loader:
                    self.log.debug(f"  → 异步加载器上下文，跳过 VM 求值")
                elif not self._is_bracket_balanced(sanitized):
                    self.log.debug(f"  → 表达式括号不平衡，跳过 VM 求值")
                elif not self._is_vm_safe_expression(sanitized):
                    self.log.debug(f"  → 表达式包含异步/环境依赖，跳过 VM 求值")
                elif len(nameList) > 20 or len(sanitized) > 8000:
                    self.log.debug(f"  → 表达式规模较大，跳过 VM 求值")

            filenames_found = self._filter_chunk_candidates(filenames_found, context_is_loader=context_is_loader)

            if filenames_found:
                self._log_filenames_success_once(jsFilePath, filenames_found, "AST")
                self._add_to_pending_list(filenames_found, jsFilePath, parent_js_content, code_body)
            else:
                # 提示：虽然提取到模块ID，但没能拼出有效的 chunk 文件名
                self.log.debug(f"  → 未能解析出有效异步JS文件名")
        except Exception as e:
            err_msg = str(e)
            if 'Broken pipe' in err_msg or 'Errno 32' in err_msg:
                self.log.warning(f"[VM] Deno VM 连接断开，当前文件进入熔断")
                self._mark_vm_failure(jsFilePath, reason=err_msg)
                self._reset_deno_server()
            else:
                self.log.error(f"[Err] AST代码编译过程中出错: {e}")

    def compile_from_regex(self, code_body, param_name, jsFilePath, parent_js_content):
        """返回是否成功新增了候选文件名（用于上层判断是否命中）。"""
        added_any = False
        try:
            # 1) 去除 runtime publicPath 前缀
            sanitized = self._sanitize_code_body(code_body)
            context_is_loader = self._looks_async_loader_expr(sanitized, param_name)
            # 2) 更健壮的对象键名提取：优先从 "{...}[e]" 模式提取，再回退到通用正则与 AST
            nameList = list(set(self._extract_keys_followed_by_param(sanitized, param_name)))
            if not nameList:
                nameList = list(set(self._extract_keys_robust(sanitized)))
            if not nameList:
                nameList = list(set(self._extract_keys_by_ast(sanitized)))
            if not nameList:
                # 若表达式内未出现对象字面量，尝试从父JS中解析被下标访问的变量所绑定的对象
                indexed_vars = self._find_indexed_vars(sanitized, param_name)
                if indexed_vars:
                    from_parent_ast = self._extract_object_keys_from_parent_by_ast(indexed_vars, parent_js_content)
                    from_parent_regex = set()
                    if not from_parent_ast:
                        from_parent_regex = self._extract_object_keys_from_parent_by_regex(indexed_vars, parent_js_content)
                    nameList = list(set(from_parent_ast) | set(from_parent_regex))
            nameList = self._filter_module_ids(nameList)
            nameList = self._merge_runtime_chunk_ids_if_needed(
                nameList,
                sanitized,
                param_name,
                jsFilePath,
                parent_js_content,
            )
            if not nameList:
                self.log.debug(f"Regex回退时未能提取到JS模块ID，expr_head={sanitized[:180]} ... len={len(sanitized)} in {Utils().getFilename(jsFilePath)}")
                return False

            # 3) 对同一文件内“完全相同的一组模块ID”做去重，只在第一次命中时打印提示
            id_set = frozenset(nameList)
            file_key = Utils().getFilename(jsFilePath)
            if not hasattr(self, "_seen_module_id_sets"):
                self._seen_module_id_sets = {}
            seen_for_file = self._seen_module_id_sets.setdefault(file_key, set())
            is_dup_ids = id_set in seen_for_file
            if not is_dup_ids:
                seen_for_file.add(id_set)
                self.log.info(f"  → 提取到 {len(nameList)} 个模块ID (Regex)")
            else:
                # 重复的模块ID集合，降噪为 debug 日志
                self.log.debug(f"  → 跳过重复的模块ID集合")

            # 优先模板回退，避免 VM 子进程副作用
            alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
            if alt:
                self._log_filenames_success_once(jsFilePath, alt, "Template")
                self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                added_any = True
                return added_any

            filenames_found = set()
            vm_available = self._can_try_vm_for_source(jsFilePath)
            can_try_vm = (
                vm_available
                and len(nameList) <= 20
                and len(sanitized) <= 8000
                and not context_is_loader
                and self._is_bracket_balanced(sanitized)
                and self._is_vm_safe_expression(sanitized)
            )
            if can_try_vm:
                prefix_stub = "var __webpack_require__={p:''},i={p:''},t={p:''},n={p:''},r={p:''},o={p:''},a={p:''};"
                jsCodeFunc = f"{prefix_stub} function js_compile({param_name}){{ try{{ return {sanitized}; }}catch(e){{ return undefined; }} }}"
                filenames_found = self._execute_in_deno(jsCodeFunc, nameList, source_file=jsFilePath)
            else:
                if not vm_available:
                    self.log.debug(f"  → 当前文件/全局VM处于熔断或冷却，跳过 VM 求值")
                elif context_is_loader:
                    self.log.debug(f"  → 异步加载器上下文，跳过 VM 求值")
                elif not self._is_bracket_balanced(sanitized):
                    self.log.debug(f"  → 表达式括号不平衡，跳过 VM 求值")
                elif not self._is_vm_safe_expression(sanitized):
                    self.log.debug(f"  → 表达式包含异步/环境依赖，跳过 VM 求值")
                elif len(nameList) > 20 or len(sanitized) > 8000:
                    self.log.debug(f"  → 表达式规模较大，跳过 VM 求值")
            filenames_found = self._filter_chunk_candidates(filenames_found, context_is_loader=context_is_loader)

            if filenames_found:
                self._log_filenames_success_once(jsFilePath, filenames_found, "Regex")
                self._add_to_pending_list(filenames_found, jsFilePath, parent_js_content, code_body)
                added_any = True
            else:
                # 提示：虽然提取到模块ID，但没能拼出有效的 chunk 文件名
                self.log.debug(f"  → 未能解析出有效异步JS文件名")
        except Exception as e:
            err_msg = str(e)
            if 'Broken pipe' in err_msg or 'Errno 32' in err_msg:
                self.log.warning(f"[VM] Deno VM 连接断开，当前文件进入熔断")
                self._mark_vm_failure(jsFilePath, reason=err_msg)
                self._reset_deno_server()
            else:
                # 降噪：不再以错误级别输出该信息，改为调试级别
                self.log.debug(f"[Debug] Regex代码编译过程中出错: {e}")
                # 捕获异常时也尝试模板拼接回退
                try:
                    alt = self._try_build_filenames_without_vm(sanitized, param_name, nameList)
                    if alt:
                        self._log_filenames_success_once(jsFilePath, alt, "Template")
                        self._add_to_pending_list(alt, jsFilePath, parent_js_content, code_body)
                        added_any = True
                    else:
                        # 与正常分支保持一致：提示本表达式最终未能还原出有效异步 JS 文件名
                        self.log.debug(f"  → 未能解析出有效异步JS文件名")
                except Exception:
                    # 模板回退本身出错时，静默忽略，避免打断整体流程
                    pass
        return added_any

    def _log_filenames_success_once(self, jsFilePath, filenames, source_label):
        """对同一文件内完全相同的一组异步JS文件名只打印一次成功日志，其余降为 debug。"""
        if not filenames:
            return
        file_key = Utils().getFilename(jsFilePath)
        key = frozenset(filenames)
        if not hasattr(self, "_seen_success_filename_sets"):
            self._seen_success_filename_sets = {}
        seen = self._seen_success_filename_sets.setdefault(file_key, set())
        if key in seen:
            self.log.debug(f"  → 跳过重复的文件名集合 ({source_label})")
            return
        seen.add(key)
        self.log.info(f"  ✓ 解析出 {len(filenames)} 个异步JS ({source_label})")

    def _pick_preferred_source_url(self, paths):
        try:
            candidates = [str(item).strip() for item in (paths or []) if str(item).strip()]
            if not candidates:
                return ""

            target_host = urlparse(getattr(self.options, "url", "") or "").netloc.lower()
            same_host = []
            for item in candidates:
                parsed = urlparse(item)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    continue
                if target_host and parsed.netloc.lower() == target_host:
                    same_host.append(item)

            if same_host:
                same_host.sort(key=lambda item: (len(urlparse(item).path or ""), item))
                return same_host[0]

            candidates.sort(key=lambda item: (len(urlparse(item).path or ""), item))
            return candidates[0]
        except Exception:
            return ""

    def _remember_trusted_external_origins(self, origins):
        try:
            if not hasattr(self.options, "_trusted_js_domains"):
                self.options._trusted_js_domains = set()
            if not hasattr(self.options, "_trusted_js_origins"):
                self.options._trusted_js_origins = set()

            for raw in origins or []:
                origin = self._get_url_origin(raw)
                if not origin:
                    continue
                self._trusted_external_origins.add(origin)
                self.options._trusted_js_origins.add(origin)
                domain = urlparse(origin).netloc.lower()
                if domain:
                    self._trusted_external_domains.add(domain)
                    self.options._trusted_js_domains.add(domain)
        except Exception:
            return

    def _normalize_public_path_candidate(self, candidate, parent_js_url=""):
        try:
            text = self._normalize_candidate_name(candidate)
            if not text:
                return ""
            if re.search(r'(?i)\b(?:audio|video|application)/(?:x-|vnd\.apple\.)?mpegurl\b', text):
                return ""
            if re.search(r'(?i)(?:%0a|%0d|%5c[nr])', text):
                return ""
            if re.search(r'\s', text):
                return ""

            parsed = urlparse(text)
            is_absolute = bool(parsed.scheme and parsed.netloc)
            raw_path = parsed.path if is_absolute else text
            if not raw_path:
                return ""

            if raw_path.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.eot', '.map', '.json', '.txt', '.html', '.htm')):
                return ""

            if re.search(r'\.(?:js|mjs|cjs|jsx|ts|tsx)(?:$|\?)', raw_path, re.I):
                if is_absolute:
                    base = text.split('?', 1)[0].split('#', 1)[0]
                    return base.rsplit('/', 1)[0] + '/'
                raw_path = raw_path.rsplit('/', 1)[0] + '/'

            if not raw_path.endswith('/'):
                has_static_marker = re.search(r'(?i)(?:^|/)(?:assets|static|scripts?|chunks?|js|dist|build|bundles?|modules?|_next|_nuxt)/', raw_path)
                if has_static_marker:
                    raw_path = raw_path.rstrip('/') + '/'
                else:
                    return ""

            if is_absolute:
                origin = f"{parsed.scheme}://{parsed.netloc}"
                return urljoin(origin + '/', raw_path.lstrip('/'))

            if raw_path.startswith(('./', '../', '/')):
                return urljoin(parent_js_url or getattr(self.options, 'url', '') or '', raw_path)
            return raw_path
        except Exception:
            return ""

    def _extract_public_path_candidates(self, parent_js_content, parent_js_url=""):
        candidates = []
        seen = set()
        try:
            text = parent_js_content or ""
            if not text:
                return []

            assign_pat = re.compile(
                r'(?:__webpack_require__\.p|[A-Za-z_$][\w$]*\.p|__webpack_public_path__|(?:PUBLIC_PATH|publicPath))\s*=\s*',
                re.I,
            )
            for m in assign_pat.finditer(text):
                expr = self._extract_assignment_expression(text, m.end(), max_chars=1800)
                if not expr:
                    continue
                literals = self._extract_string_literals(expr)
                if '`' in expr:
                    template_literals = re.findall(r'`([^`]+)`', expr)
                    literals.extend(template_literals)

                for lit in literals:
                    normalized = self._normalize_public_path_candidate(lit, parent_js_url=parent_js_url)
                    if not normalized or normalized in seen:
                        continue
                    seen.add(normalized)
                    candidates.append(normalized)

            fallback_patterns = [
                r'location\.origin\s*\+\s*(["\'][^"\']+["\'])',
                r'(?:document\.)?currentScript\.src\s*\+\s*(["\'][^"\']+["\'])',
                r'document\.baseURI\s*\+\s*(["\'][^"\']+["\'])',
                r'new\s+URL\(\s*(["\'][^"\']+["\'])\s*,\s*import\.meta\.url\s*\)',
            ]
            for pat in fallback_patterns:
                for m in re.finditer(pat, text, re.I):
                    lit = (m.group(1) or '').strip()
                    normalized = self._normalize_public_path_candidate(lit, parent_js_url=parent_js_url)
                    if not normalized or normalized in seen:
                        continue
                    seen.add(normalized)
                    candidates.append(normalized)
        except Exception:
            return candidates
        return candidates

    def _extract_trusted_external_origins(self, parent_js_content, parent_js_url=""):
        origins = set()
        try:
            for item in self._extract_public_path_candidates(parent_js_content, parent_js_url=parent_js_url):
                origin = self._get_url_origin(item)
                if origin:
                    origins.add(origin)

            env = self._extract_simple_env(parent_js_content)
            for _, value in (env or {}).items():
                origin = self._get_url_origin(value)
                if origin:
                    origins.add(origin)

            for value in getattr(self, "_custom_loader_base_paths", set()):
                origin = self._get_url_origin(value)
                if origin:
                    origins.add(origin)

            for m in re.finditer(r'https?://[^\s\'"`]+', parent_js_content or '', re.I):
                origin = self._get_url_origin(m.group(0))
                if origin:
                    origins.add(origin)
        except Exception:
            return list(origins)
        return sorted(origins)


    def _resolve_parent_js_url(self, cursor, jsFilePath, localFile):
        self._execute_db_with_retry(cursor, "SELECT path FROM js_file WHERE local=?", (localFile,), context="resolve parent by local")
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]

        normalized_path = jsFilePath.replace("\\", "/")
        parent_token = ""
        if self._sourcemap_sources_marker in normalized_path:
            parent_part = normalized_path.split(self._sourcemap_sources_marker, 1)[1]
            parent_token = parent_part.split("/", 1)[0].strip()
        elif self._sourcemap_root_marker in normalized_path:
            tail = normalized_path.split(self._sourcemap_root_marker, 1)[1]
            parent_token = tail.split("/", 1)[0].strip()
            if parent_token.lower().endswith(".map"):
                parent_token = parent_token[:-4]

        if parent_token:
            self._execute_db_with_retry(cursor, "SELECT path FROM js_file WHERE local=?", (parent_token,), context="resolve parent by token")
            row = cursor.fetchone()
            if row and row[0]:
                return row[0]

        original_name = self._extract_original_name(localFile)
        if original_name:
            self._execute_db_with_retry(
                cursor,
                "SELECT path FROM js_file WHERE name=? AND success=1 ORDER BY id DESC LIMIT 8",
                (original_name,),
                context="resolve parent by basename",
            )
            rows = cursor.fetchall() or []
            preferred = self._pick_preferred_source_url([row[0] for row in rows if row and row[0]])
            if preferred:
                return preferred

        if getattr(self.options, "url", None):
            return self.options.url

        return ""


    def _add_to_pending_list(self, filenames_found, jsFilePath, parent_js_content, code_snippet):
        localFile = os.path.basename(jsFilePath)
        jsSplitId = self.js_split_id_counter
        self.js_split_id_counter += 1

        jsUrlPath = ""
        conn = self._get_db_connection()
        try:
            with self._db_lock:
                cursor = conn.cursor()
                jsUrlPath = self._resolve_parent_js_url(cursor, jsFilePath, localFile)
        finally:
            conn.close()

        if not jsUrlPath:
            self.log.debug(f"[Debug] 无法确定父JS URL，跳过本次候选合成: {localFile}")
            conn = self._get_db_connection()
            try:
                with self._db_lock:
                    cursor = conn.cursor()
                    sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name, js_result, success) VALUES(?, ?, ?, ?, ?)"
                    self._execute_db_with_retry(
                        cursor,
                        sql,
                        (jsSplitId, code_snippet, localFile, "[[parent_js_unresolved]]", 0),
                        context="insert unresolved parent js_split_tree",
                    )
                    self._commit_with_retry(conn, context="commit unresolved parent js_split_tree")
            finally:
                conn.close()
            self._mark_recover_checkpoint_dirty()
            return

        filtered_candidates = self._filter_chunk_candidates(filenames_found, context_is_loader=True)
        if not filtered_candidates:
            self.log.debug(f"[Debug] 已过滤掉可疑候选路径: {localFile}")
            # 即便未命中有效候选，也保留表达式记录用于后续审计与调试。
            conn = self._get_db_connection()
            try:
                with self._db_lock:
                    cursor = conn.cursor()
                    sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name, js_result, success) VALUES(?, ?, ?, ?, ?)"
                    self._execute_db_with_retry(
                        cursor,
                        sql,
                        (jsSplitId, code_snippet, localFile, "[[all_candidates_filtered]]", 0),
                        context="insert empty js_split_tree result",
                    )
                    self._commit_with_retry(conn, context="commit empty js_split_tree result")
            finally:
                conn.close()
            self._mark_recover_checkpoint_dirty()
            return

        resolved_paths = self.getRealFilePath(list(filtered_candidates), jsUrlPath, parent_js_content)
        resolved_paths = list(dict.fromkeys(resolved_paths))

        # 结果原子落库：候选一旦解析出来就写入 js_split_tree，避免超时中断导致“日志有结果、DB无记录”。
        conn = self._get_db_connection()
        try:
            with self._db_lock:
                cursor = conn.cursor()
                result_text = "\n".join(resolved_paths[:300])
                sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name, js_result, success) VALUES(?, ?, ?, ?, ?)"
                self._execute_db_with_retry(
                    cursor,
                    sql,
                    (jsSplitId, code_snippet, localFile, result_text, 1 if resolved_paths else 0),
                    context="insert js_split_tree with result",
                )
                self._commit_with_retry(conn, context="commit js_split_tree with result")
        finally:
            conn.close()

        self.pending_js_files.update(resolved_paths)
        self._mark_recover_checkpoint_dirty()

    def _add_to_pending_list_with_base(self, filenames_found, jsFilePath, base_url, parent_js_content, code_snippet):
        localFile = os.path.basename(jsFilePath)
        jsSplitId = self.js_split_id_counter
        self.js_split_id_counter += 1

        filtered_candidates = self._filter_chunk_candidates(filenames_found, context_is_loader=False)
        if not filtered_candidates:
            conn = self._get_db_connection()
            try:
                with self._db_lock:
                    cursor = conn.cursor()
                    sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name, js_result, success) VALUES(?, ?, ?, ?, ?)"
                    self._execute_db_with_retry(
                        cursor,
                        sql,
                        (jsSplitId, code_snippet, localFile, "[[all_candidates_filtered]]", 0),
                        context="insert empty js_split_tree base result",
                    )
                    self._commit_with_retry(conn, context="commit empty js_split_tree base result")
            finally:
                conn.close()
            self._mark_recover_checkpoint_dirty()
            return

        resolved_paths = self.getRealFilePath(list(filtered_candidates), base_url, parent_js_content)
        resolved_paths = list(dict.fromkeys(resolved_paths))

        conn = self._get_db_connection()
        try:
            with self._db_lock:
                cursor = conn.cursor()
                result_text = "\n".join(resolved_paths[:300])
                sql = "INSERT OR IGNORE INTO js_split_tree(id, jsCode, js_name, js_result, success) VALUES(?, ?, ?, ?, ?)"
                self._execute_db_with_retry(
                    cursor,
                    sql,
                    (jsSplitId, code_snippet, localFile, result_text, 1 if resolved_paths else 0),
                    context="insert js_split_tree with base result",
                )
                self._commit_with_retry(conn, context="commit js_split_tree with base result")
        finally:
            conn.close()

        self.pending_js_files.update(resolved_paths)
        self._mark_recover_checkpoint_dirty()
    def _is_downloadable_static_candidate(self, candidate, source_label=""):
        try:
            text = self._normalize_candidate_name(candidate)
            if not text or not self._is_js_like_candidate(text):
                return False

            lower = text.lower()
            label = str(source_label or "").lower()

            if label == 'manifest/import-map detector' and lower.startswith(('http://', 'https://', '//')):
                return False

            if lower.startswith(('http://', 'https://', '//')):
                return True

            if lower.startswith('/'):
                return True

            if self._looks_root_based_relative_path(text):
                return True

            has_static_semantics = bool(
                re.search(r'(?i)(?:^|/)(?:assets|static|scripts?|chunks?|js|dist|build|bundles?|modules?|_next|_nuxt|public)/', lower)
                or re.search(r'(?i)(?:^|[\/._-])(?:chunk|runtime|vendor|manifest|lazy|async|entry|framework|main|app|common|shared|remoteentry)(?:$|[\/._-])', lower)
                or re.search(r'(?i)[0-9a-f]{6,}', lower)
            )
            strong_manifest_semantics = bool(
                re.search(r'(?i)(?:^|/)(?:assets|static|scripts?|chunks?|js|_next|_nuxt|public)/', lower)
                or re.search(r'(?i)(?:^|[\/._-])(?:chunk|runtime|vendor|manifest|lazy|async|entry|framework|remoteentry)(?:$|[\/._-])', lower)
                or re.search(r'(?i)[0-9a-f]{6,}', lower)
            )

            if label == 'explicit external js url detector':
                return False

            if label == 'manifest/import-map detector':
                return strong_manifest_semantics

            if lower.startswith(('./', '../')):
                if '/node_modules/' in f'/{lower}/' or lower.startswith('node_modules/'):
                    return False
                return label == 'vite/rollup detector' or has_static_semantics

            if '/' in text:
                return has_static_semantics

            if label == 'vite/rollup detector':
                return True

            return has_static_semantics
        except Exception:
            return False

    def _add_static_paths(self, paths, jsFilePath, parent_js_content, source_label='Static path detector'):
        """
        将静态检测器发现的路径加入待下载列表，复用统一的URL构建逻辑。
        仅处理 .js/.mjs。
        """
        try:
            if not paths:
                return set()
            # 仅保留“像真实可下载资源”的静态路径，避免把内部模块名推进下载队列。
            norm = {
                p for p in paths
                if self._is_downloadable_static_candidate(p, source_label=source_label)
            }
            if not norm:
                return set()
            self._add_to_pending_list(set(norm), jsFilePath, parent_js_content, source_label)
            return set(norm)
        except Exception:
            return set()

    def _scan_explicit_external_js_urls(self, js_content, jsFilePath):
        try:
            text = js_content or ''
            found = set()
            for m in re.finditer(r'(["\'])(https?://[^"\']+?\.(?:js|mjs|cjs)(?:\?[^"\']*)?)\1', text, re.I):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)
            for m in re.finditer(r'(["\'])(//[^"\']+?\.(?:js|mjs|cjs)(?:\?[^"\']*)?)\1', text, re.I):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)

            if found:
                accepted = self._add_static_paths(found, jsFilePath, js_content, 'Explicit external JS URL detector')
                if accepted:
                    self.log.info(f"显式外链JS检测器: 发现 {len(accepted)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
        except Exception:
            return

    def _expand_static_template_literal(self, raw_template):
        try:
            text = str(raw_template or "")
            if not text:
                return []
            if '${' not in text:
                return [text]

            def _replace(match):
                inner = (match.group(1) or '').strip()
                string_match = re.fullmatch(r'([\'"])([^\'"]+)\1', inner)
                if string_match:
                    return string_match.group(2)
                if re.fullmatch(r'\d{1,6}', inner):
                    return inner
                return '__DYNAMIC__'

            replaced = re.sub(r'\$\{\s*([^{}]+?)\s*\}', _replace, text)
            if '__DYNAMIC__' in replaced:
                return []
            return [replaced]
        except Exception:
            return []

    def _scan_module_federation(self, js_content, jsFilePath):
        try:
            text = js_content or ''
            if not re.search(r'(?i)(?:remoteEntry\.js|__webpack_init_sharing__|container\.get\s*\(|container\.init\s*\()', text):
                return

            found = set()
            for m in re.finditer(r'(["\'])([^"\']*remoteEntry\.js(?:\?[^"\']*)?)\1', text, re.I):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)

            if found:
                accepted = self._add_static_paths(found, jsFilePath, js_content, 'Module Federation detector')
                if accepted:
                    self.log.info(f"Module Federation检测器: 发现 {len(accepted)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
        except Exception:
            return

    def _scan_static_manifest_imports(self, js_content, jsFilePath):
        try:
            text = js_content or ''
            if not re.search(r'(?i)(?:importmap|manifest|["\']imports["\']\s*:)', text):
                return

            found = set()
            for m in re.finditer(r'(["\'])([^"\']+(?:\.js|\.mjs|\.cjs)(?:\?[^"\']*)?)\1', text, re.I):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)

            if found:
                accepted = self._add_static_paths(found, jsFilePath, js_content, 'Manifest/import-map detector')
                if accepted:
                    self.log.info(f"Manifest/import-map检测器: 发现 {len(accepted)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
        except Exception:
            return

    def _scan_vite_rollup(self, js_content, jsFilePath):
        """
        Vite/Rollup 检测器：
        - new URL("...", import.meta.url)
        - import("...") 静态字符串字面量
        - 仅做静态可裁剪模板的扩展，不执行任意动态表达式
        """
        try:
            vite_url_pat = re.compile(r"new\s+URL\(\s*([\"'])([^\"']+)\1\s*,\s*import\.meta\.url\s*\)")
            vite_import_pat = re.compile(r"import\s*\(\s*([\"'])([^\"']+)\1\s*\)")
            vite_url_tpl_pat = re.compile(r"new\s+URL\(\s*`([^`]+)`\s*,\s*import\.meta\.url\s*\)")
            vite_import_tpl_pat = re.compile(r"import\s*\(\s*`([^`]+)`\s*\)")
            found = set()
            for m in vite_url_pat.finditer(js_content):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)
            for m in vite_import_pat.finditer(js_content):
                candidate = (m.group(2) or '').strip()
                if self._is_js_like_candidate(candidate):
                    found.add(candidate)
            for m in vite_url_tpl_pat.finditer(js_content):
                for candidate in self._expand_static_template_literal(m.group(1)):
                    if self._is_js_like_candidate(candidate):
                        found.add(candidate)
            for m in vite_import_tpl_pat.finditer(js_content):
                for candidate in self._expand_static_template_literal(m.group(1)):
                    if self._is_js_like_candidate(candidate):
                        found.add(candidate)

            if found:
                accepted = self._add_static_paths(found, jsFilePath, js_content, 'Vite/Rollup detector')
                if accepted:
                    self.log.info(f"Vite/Rollup检测器: 发现 {len(accepted)} 个静态路径/导入: {Utils().getFilename(jsFilePath)}")
        except Exception:
            return
    def _should_scan_generic_loader(self, js_content, jsFilePath, runtime_like=False, runtime_profile=None):
        """
        控制 generic_loader 扫描范围，减少大体积业务库误报。
        """
        try:
            if runtime_like:
                return True

            profile = runtime_profile or self._get_runtime_bundle_profile(js_content, jsFilePath)
            if profile.get("tier") == "weak_loader":
                return True

            filename = Utils().getFilename(jsFilePath).lower()
            size = len(js_content or "")

            keyword_hint = bool(
                re.search(
                    r'(?i)(?:loadscript|importscript|createelement\s*\(\s*[\'"]script|document\.write|\.src\s*=|loadresources|loadassets)',
                    js_content[:120000],
                )
            )
            name_hint = bool(re.search(r'(?i)(?:app|main|index|runtime|loader|bootstrap|entry)', filename))

            if size <= 700000 and keyword_hint:
                return True
            if size <= 320000 and name_hint:
                return True
            if size <= 950000 and keyword_hint and profile.get("has_asset_join"):
                return True

            return False
        except Exception:
            return False

    def _scan_custom_loader(self, js_content, jsFilePath, runtime_like=False, runtime_profile=None):
        """
        通用自定义加载器检测器 - 增强版
        
        检测模式：
        1. 任意 basePath 变量定义：var xxxPath = '/api/'; var BASE_URL = '/static/';
        2. 任意加载函数调用：load(...), loadScript(...), require(...), importScript(...)
        3. basePath + 相对路径拼接模式
        4. 数组形式的资源列表: ['a.js', 'b.js']
        
        示例:
            var _API_Path = '/proxyApi/ecity_js_api1.0';
            var BASE_URL = '/static/js/';
            var cdnPath = 'https://cdn.example.com/';
            _load('frame/libs/react.js', 'frame/js/jquery.js');
            loadScript('/vendor/lodash.js');
        """
        try:
            if not self._should_scan_generic_loader(
                js_content,
                jsFilePath,
                runtime_like=runtime_like,
                runtime_profile=runtime_profile,
            ):
                return

            # 1) 通用 basePath 变量名模式 - 检测常见命名
            base_path_patterns = [
                # 常见命名: xxxPath, xxx_path, BASE_URL, CDN_URL, STATIC_URL 等
                r"\b([A-Za-z_$][\w$]*(?:Path|PATH|_path|Url|URL|_url|Base|BASE|Root|ROOT))\s*=\s*(['\"])([^'\"]+)\2",
                # 全大写常量: API_PATH, STATIC_PATH, CDN_BASE 等
                r"\b([A-Z][A-Z0-9_]*(?:PATH|URL|BASE|ROOT|CDN|STATIC|ASSETS))\s*=\s*(['\"])([^'\"]+)\3",
                # 通用赋值: var/let/const xxx = '/path/'（以 / 结尾的路径）
                r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"])(/[^'\"]*?/)\2",
            ]
            
            base_paths = set(getattr(self, "_custom_loader_base_paths", set()))
            for pat in base_path_patterns:
                for m in re.finditer(pat, js_content):
                    # 根据分组数量提取路径值
                    groups = m.groups()
                    path_value = groups[-1] if len(groups) >= 2 else None
                    if path_value and path_value.strip():
                        base = path_value.strip()
                        # 过滤掉明显不是路径的值
                        if not re.search(r'\.(?:png|jpe?g|gif|svg|ico|css|html?)$', base, re.I):
                            if not hasattr(self, "_custom_loader_base_paths"):
                                self._custom_loader_base_paths = set()
                            self._custom_loader_base_paths.add(base)
                            base_paths.add(base)

            # 2) 通用加载函数名模式
            loader_func_patterns = [
                r"\b(load|loadScript|loadJS|importScript|_load|loadModule|fetchScript)\s*\(",
                r"\b(loadScripts|loadResources|loadAssets|importScripts)\s*\(",
            ]
            
            found_paths = set()
            
            for func_pat in loader_func_patterns:
                for m in re.finditer(func_pat + r"(.*?)\)", js_content, re.DOTALL | re.I):
                    args_src = m.group(2) if m.lastindex >= 2 else m.group(1)
                    # 从参数中提取字符串字面量路径，交给 JS-like 判定
                    for sm in re.finditer(r"(['\"])([^'\"]+)\1", args_src):
                        raw = (sm.group(2) or '').strip()
                        if not raw:
                            continue
                        # 通用加载器仅接受显式 JS 后缀，避免把 MIME type / 普通包名当成异步脚本路径。
                        if not re.search(r'\.(?:js|mjs|cjs)(?:\?|$)', raw, re.I):
                            continue
                        if not self._is_js_like_candidate(raw):
                            continue
                        
                        # 绝对 URL 直接加入
                        if re.match(r"^https?://", raw, re.I):
                            found_paths.add(raw)
                            continue
                        
                        # 绝对路径直接加入
                        if raw.startswith('/'):
                            found_paths.add(raw)
                            # 同时尝试与 base_paths 组合
                            for base in base_paths:
                                if base.startswith(('http://', 'https://')):
                                    found_paths.add(base.rstrip('/') + raw)
                            continue
                        
                        # 相对路径：与所有 base_paths 组合
                        if base_paths:
                            for base in base_paths:
                                base = base.rstrip('/') or ''
                                path = base + '/' + raw if base else raw
                                found_paths.add(path)
                        else:
                            # 无 base_path 时直接加入相对路径
                            found_paths.add(raw)

            # 3) 检测数组形式的资源列表
            array_pat = re.compile(r"\[\s*(['\"][^'\"]+['\"](?:\s*,\s*['\"][^'\"]+['\"])+)\s*\]")
            for m in array_pat.finditer(js_content):
                arr_content = m.group(1)
                for sm in re.finditer(r"['\"]([^'\"]+)['\"]", arr_content):
                    raw = sm.group(1).strip()
                    if raw:
                        if not re.search(r'\.(?:js|mjs|cjs)(?:\?|$)', raw, re.I):
                            continue
                        if not self._is_js_like_candidate(raw):
                            continue
                        if re.match(r"^https?://", raw, re.I) or raw.startswith('/'):
                            found_paths.add(raw)
                        elif base_paths:
                            for base in base_paths:
                                found_paths.add(base.rstrip('/') + '/' + raw)
                        else:
                            found_paths.add(raw)

            if found_paths:
                max_items = 120 if runtime_like else 40
                filtered = self._filter_chunk_candidates(found_paths, context_is_loader=False, max_items=max_items)
                if filtered:
                    dropped = len(found_paths) - len(filtered)
                    if dropped > 0:
                        self.log.debug(
                            f"[Debug] generic_loader 已过滤噪声候选 {dropped} 个: {Utils().getFilename(jsFilePath)}"
                        )
                    self.log.info(f"通用加载器检测: 发现 {len(filtered)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
                    self._add_to_pending_list(filtered, jsFilePath, js_content, 'generic_loader')
        except Exception as e:
            self.log.debug(f"[Debug] 通用加载器扫描失败: {e}")
            return
    # 通用配置对象名列表 - 增强版
    CONFIG_OBJECT_NAMES = [
        'SITE_CONFIG', 'APP_CONFIG', 'CONFIG', '__CONFIG__', 
        'window.config', 'window.CONFIG', 'window.appConfig',
        'window.siteConfig', 'window.APP_CONFIG', 'window.SITE_CONFIG',
        '__webpack_public_path__', 'publicPath', 'PUBLIC_PATH',
        'ENV', 'env', '__ENV__', 'settings', 'SETTINGS',
        'globalConfig', 'GLOBAL_CONFIG', 'appSettings', 'APP_SETTINGS',
    ]

    def _eval_concat(self, expr, env):
        """
        通用配置对象拼接求值器 - 增强版
        
        在不执行任意代码的前提下，尝试对由字符串与配置变量拼接的表达式求值。
        支持多种常见配置对象名：SITE_CONFIG, APP_CONFIG, CONFIG, __CONFIG__ 等
        
        例如：
            window.SITE_CONFIG.cdnUrl + '/static/js/app.js'
            window.config.basePath + '/vendor/lodash.js'
            __CONFIG__.staticUrl + '/js/main.js'
        """
        try:
            if not expr:
                return None
            
            replaced = expr
            
            # 遍历所有已知配置对象名，替换其属性访问
            for config_name in self.CONFIG_OBJECT_NAMES:
                for k, v in env.items():
                    # 处理 window.xxx 前缀
                    if config_name.startswith('window.'):
                        base_name = config_name
                    else:
                        base_name = r"(?:window\.)?" + re.escape(config_name)
                    
                    # 点号访问: CONFIG.key
                    pat1 = re.compile(base_name + r"\s*\.\s*" + re.escape(k) + r"\b")
                    # 方括号访问: CONFIG["key"] 或 CONFIG['key']
                    pat2 = re.compile(base_name + r"\s*\[\s*([\"'])" + re.escape(k) + r"\1\s*\]")
                    
                    replaced = pat1.sub(lambda m: "'" + v + "'", replaced)
                    replaced = pat2.sub(lambda m: "'" + v + "'", replaced)

            # 仅允许 '...'+"..."+('...')+(...) 这类形式
            tmp = re.sub(r"\s+", "", replaced)
            probe = re.sub(r"([\'\"](?:\\.|[^\'\"])*[\'\"]|\+|\(|\))", "", tmp)
            if probe != "":
                return None

            # 依次取出字符串字面量并拼接
            out = []
            for m in re.finditer(r"([\'\"])((?:\\.|[^\'\"])*)\1", replaced):
                out.append(m.group(2))
            return "".join(out) if out else None
        except Exception:
            return None

    def _extract_simple_env(self, js_content):
        """
        通用配置对象解析器 - 增强版
        
        解析多种常见配置对象的赋值，支持字符串与已解析变量的拼接推导。
        支持的配置对象名：SITE_CONFIG, APP_CONFIG, CONFIG, __CONFIG__, 
                        window.config, globalConfig 等
        
        支持最多三轮迭代解析，先解析直接字面量，再解析依赖已知变量的拼接。
        """
        env = {}
        try:
            # 构建通用配置对象匹配模式
            config_names_pattern = '|'.join(
                re.escape(name) if not name.startswith('window.') 
                else re.escape(name)
                for name in self.CONFIG_OBJECT_NAMES
            )
            
            # 匹配 CONFIG.key = value 或 CONFIG["key"] = value
            assign_pat = re.compile(
                r"(?:(?:window\.)?(?:" + config_names_pattern + r"))\s*"
                r"(?:\[\s*([\"'])([^\"']+)\1\s*\]|\.\s*([A-Za-z_$][\w$]*))\s*=\s*([^;]+);",
                re.DOTALL,
            )
            assigns = assign_pat.findall(js_content)
            raw = []
            for q, key1, key2, expr in assigns:
                key = key1 or key2
                if not key:
                    continue
                raw.append((key, expr))
            
            # 额外检测：var/let/const xxx = { key: value } 形式的配置对象
            # 匹配常见配置变量名
            config_var_pat = re.compile(
                r"(?:var|let|const)\s+(config|CONFIG|appConfig|siteConfig|settings|SETTINGS|env|ENV)\s*=\s*\{([^}]+)\}",
                re.DOTALL | re.I
            )
            for m in config_var_pat.finditer(js_content):
                obj_body = m.group(2)
                # 提取 key: "value" 或 key: 'value'
                for kv in re.finditer(r"([A-Za-z_$][\w$]*)\s*:\s*([\"'])([^\"']*)\2", obj_body):
                    key = kv.group(1)
                    val = kv.group(3)
                    if key and val:
                        raw.append((key, f'"{val}"'))

            changed = True
            rounds = 0
            while changed and rounds < 3:
                changed = False
                rounds += 1
                for key, expr in raw:
                    if key in env:
                        continue
                    src = expr.strip()
                    # 纯字符串
                    m = re.fullmatch(r"([\"'])(.*)\1", src, re.DOTALL)
                    if m:
                        env[key] = m.group(2)
                        changed = True
                        continue
                    # 拼接可求值
                    val = self._eval_concat(src, env)
                    if val is not None:
                        env[key] = val
                        changed = True
            return env
        except Exception:
            return env

    def _scan_dom_loader(self, js_content, jsFilePath):
        """
        通用 DOM 加载器检测 - 增强版
        
        检测模式：
        1. document.write('<script src="...">') 中的 src
        2. 任意资源列表对象: { js: [...] }, { scripts: [...] }, { resources: [...] }
        3. script.src = '...' 赋值
        4. 动态创建 script 元素并设置 src
        5. 配置对象中的 JS 路径拼接
        
        解析出的相对路径交由统一 URL 构建逻辑处理。
        """
        try:
            raw_len = len(js_content or "")
            found = set()
            if raw_len <= 0:
                return

            dom_windows = self._build_full_coverage_windows(
                js_content,
                window_chars=min(self._dom_scan_max_chars, 320000),
                overlap_chars=min(self._scan_window_overlap_chars, 12000),
                target_segments=18 if raw_len > self._dom_loader_hard_skip_chars else 0,
                max_window_chars=max(520000, min(self._dom_scan_max_chars, 520000)),
                anchor_positions=self._collect_loader_anchor_positions(js_content, limit=96),
            )
            if not dom_windows:
                dom_windows = [(0, raw_len, js_content)]
            if raw_len > self._dom_loader_hard_skip_chars:
                self.log.debug(
                    f"[Debug] DOM加载器改为全覆盖分窗扫描: {Utils().getFilename(jsFilePath)} windows={len(dom_windows)}"
                )

            resource_list_patterns = [
                r"\b\w+\s*=\s*\{[\s\S]*?\b(js|scripts|jsList|scriptList|jsFiles)\s*:\s*\[([\s\S]*?)\]",
                r"\b(resources|assets|files|modules)\s*:\s*\{[\s\S]*?\b(js|scripts)\s*:\s*\[([\s\S]*?)\]",
                r"\b(scripts|jsList|jsFiles|scriptList)\s*=\s*\[([\s\S]*?)\]",
            ]

            for _, _, dom_scan_content in dom_windows:
                if not dom_scan_content:
                    continue
                lightweight_mode = len(dom_scan_content) > 620000
                env = {} if lightweight_mode else self._extract_simple_env(dom_scan_content)

                # 1) document.write 中的 <script src="...">
                for m in re.finditer(r"document\.write(?:ln)?\(\s*([\"'])((?:\\.|[^\"'])*)\1\s*\)", dom_scan_content, re.DOTALL | re.I):
                    html = m.group(2)
                    for m2 in re.finditer(r"src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", html, re.I):
                        found.add(m2.group(2))

                if not lightweight_mode:
                    for pat in resource_list_patterns:
                        for m in re.finditer(pat, dom_scan_content, re.I):
                            arr = m.group(m.lastindex)
                            items = self._parse_array_items(arr)

                            for it in items:
                                if not it:
                                    continue
                                lit = None
                                mstr = re.fullmatch(r"([\"'])([^\"']+?(?:\.(?:js|mjs))(?:\?[^\"']*)?)\1", it, re.I)
                                if mstr:
                                    lit = mstr.group(2)
                                else:
                                    lit = self._eval_concat(it, env)
                                if lit and re.search(r"\.(?:js|mjs)(?:\?|$)", lit, re.I):
                                    found.add(lit)

                # 3) script.src = '...' 赋值
                for m in re.finditer(r"\.src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", dom_scan_content, re.I):
                    found.add(m.group(2))

                # 4) createElement('script') 后的 src 设置
                for m in re.finditer(r"createElement\s*\(\s*[\"']script[\"']\s*\)[\s\S]{0,200}?\.src\s*=\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\1", dom_scan_content, re.I):
                    found.add(m.group(2))

                # 5) 配置对象中的路径属性
                for m in re.finditer(r"\b(src|url|path|file)\s*:\s*([\"'])([^\"']+?\.(?:js|mjs)(?:\?[^\"']*)?)\2", dom_scan_content, re.I):
                    found.add(m.group(3))

            if found:
                self.log.info(f"DOM 加载器检测: 发现 {len(found)} 个静态JS路径: {Utils().getFilename(jsFilePath)}")
                base = getattr(self.options, 'url', None)
                if base:
                    self._add_to_pending_list_with_base(found, jsFilePath, base, js_content, 'dom_loader')
                else:
                    self._add_static_paths(found, jsFilePath, js_content)
        except Exception:
            return
    
    def _parse_array_items(self, arr_content):
        """
        解析数组内容，支持括号与字符串内逗号。
        """
        items = []
        cur = []
        q = None
        depth = 0
        for ch in arr_content:
            if q is not None:
                cur.append(ch)
                if ch == q and (len(cur) < 2 or cur[-2] != '\\'):
                    q = None
                continue
            if ch in ('\"', "'"):
                q = ch
                cur.append(ch)
                continue
            if ch in '([':
                depth += 1
                cur.append(ch)
                continue
            if ch in ')]':
                depth = max(0, depth - 1)
                cur.append(ch)
                continue
            if ch == ',' and depth == 0:
                items.append(''.join(cur).strip())
                cur = []
                continue
            cur.append(ch)
        if cur:
            items.append(''.join(cur).strip())
        return items

    def _scan_webpack_literal_chunks(self, js_content, jsFilePath):
        """
        Webpack5 简易 chunk 检测器：

        适配形如：
            __webpack_require__.u = function(e){ return "js/" + e + ".js"; }
            __webpack_require__.e("src_views_xxx").then(...)
        的模式，不依赖对象字面量映射，直接从 .e("id") 中提取 chunkId，
        再根据 .u 的返回模板拼接出 JS 路径。
        """
        try:
            raw_len = len(js_content or "")
            loaders = {}
            if raw_len <= 0:
                return

            literal_windows = self._build_full_coverage_windows(
                js_content,
                window_chars=self._webpack_literal_scan_max_chars,
                overlap_chars=min(self._scan_window_overlap_chars, 12000),
                target_segments=14 if raw_len > self._webpack_literal_hard_skip_chars else 0,
                max_window_chars=max(self._webpack_literal_scan_max_chars, 840000),
                anchor_positions=self._collect_loader_anchor_positions(js_content, limit=96),
            )
            if not literal_windows:
                literal_windows = [(0, raw_len, js_content)]
            if raw_len > self._webpack_literal_hard_skip_chars:
                self.log.debug(
                    f"[Debug] Webpack字面量检测改为全覆盖分窗扫描: {Utils().getFilename(jsFilePath)} windows={len(literal_windows)}"
                )

            # 1) 普通 function 形式：obj.u = function(e){ return "js"+e +".js"; }
            func_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{"\
                r"[^;]{0,200}?return\s*([^;]+?);",
                re.DOTALL
            )
            for _, _, scan_content in literal_windows:
                if not scan_content:
                    continue
                for m in func_pat.finditer(scan_content):
                    obj_name = m.group(1)
                    param = m.group(2)
                    ret_expr = m.group(3)
                    m2 = re.search(
                        r"([\"'])([^\"']*?)\1\s*\+\s*"
                        + re.escape(param)
                        + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
                        ret_expr
                    )
                    if not m2:
                        continue
                    prefix = m2.group(2) or ""
                    loaders[obj_name] = prefix

            # 2) 箭头函数形式：obj.u = e => "js"+e+".js";
            arrow_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*([^;]+?);",
                re.DOTALL
            )
            for _, _, scan_content in literal_windows:
                if not scan_content:
                    continue
                for m in arrow_pat.finditer(scan_content):
                    obj_name = m.group(1)
                    param = m.group(2)
                    ret_expr = m.group(3)
                    m2 = re.search(
                        r"([\"'])([^\"']*?)\1\s*\+\s*"
                        + re.escape(param)
                        + r"\s*\+\s*([\"'])\.js(?:\?[^\"']*)?\3",
                        ret_expr
                    )
                    if not m2:
                        continue
                    prefix = m2.group(2) or ""
                    loaders.setdefault(obj_name, prefix)

            if not loaders:
                return

            candidates = set()
            for _, _, scan_content in literal_windows:
                if not scan_content:
                    continue
                for obj_name, prefix in loaders.items():
                    call_pat = re.compile(
                        re.escape(obj_name) + r"\.e\(\s*(?:/\*.*?\*/\s*)?([\"'])(.+?)\1\s*\)",
                        re.DOTALL
                    )
                    for m in call_pat.finditer(scan_content):
                        chunk_id = (m.group(2) or "").strip()
                        if not chunk_id:
                            continue
                        filename = f"{prefix}{chunk_id}.js"
                        candidates.add(filename)

            if candidates:
                self.log.info(
                    f"Webpack简易chunk检测器: 发现 {len(candidates)} 个静态JS路径: {Utils().getFilename(jsFilePath)}"
                )
                self._add_to_pending_list(candidates, jsFilePath, js_content, 'webpack_literal_chunks')
        except Exception as e:
            # 低优先级调试信息
            self.log.debug(f"[Debug] Webpack 简易 chunk 检测失败: {e}")
            return


    def _build_full_url(self, path, script_url):
        """
        统一 URL 拼接：
        - 绝对 URL 原样返回
        - // 协议相对 URL 继承 script_url 协议
        - / 开头按 origin 拼接
        - 其余按 urljoin(script_url, path)
        """
        try:
            candidate = self._normalize_candidate_name(path)
            if not candidate:
                return ""

            script_url_parts = urlparse(script_url or "")
            base_origin = ""
            if script_url_parts.scheme and script_url_parts.netloc:
                base_origin = f"{script_url_parts.scheme}://{script_url_parts.netloc}"

            if candidate.startswith(('http://', 'https://')):
                return candidate

            if candidate.startswith('//'):
                scheme = script_url_parts.scheme or 'https'
                return f"{scheme}:{candidate}"

            if candidate.startswith('/'):
                return urljoin(base_origin, candidate) if base_origin else urljoin(script_url, candidate)

            return urljoin(script_url, candidate)
        except Exception as e:
            self.log.error(f"构建URL时出错: path='{path}', script_url='{script_url}', error='{e}'")
            return urljoin(script_url, path) # Fallback

    def _get_url_origin(self, url):
        try:
            parsed = urlparse(url or "")
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
            return ""
        except Exception:
            return ""

    def _is_suspicious_chunk_path(self, path):
        try:
            text = self._normalize_candidate_name(path)
            if not text:
                return True
            lower = text.lower()

            if re.search(r'[\r\n\t\u2028\u2029]', text):
                return True

            if re.search(r'(?i)(?:%0a|%0d|%5c[nr])', lower):
                return True

            if re.search(r'(?i)\.concat\s*\(', lower):
                return True

            if re.search(r'https?://', text) and not lower.startswith(('http://', 'https://', '//')):
                return True

            if re.search(r'(?i)\.js/(?:assets|static|chunks?|scripts?|js)/', lower):
                return True

            return False
        except Exception:
            return True

    def _looks_root_based_relative_path(self, path):
        """
        判断一个“非 ./ ../ / 开头”的路径是否更像站点根上的静态资源路径。
        """
        try:
            text = self._normalize_candidate_name(path)
            if not text:
                return False
            lower = text.lower()
            if lower.startswith(('http://', 'https://', '//', '/', './', '../')):
                return False

            root_markers = ('assets/', 'static/', 'scripts/', 'script/', 'chunks/', 'chunk/', 'js/')
            if lower.startswith(root_markers):
                return True

            if re.search(r'/(?:assets|static|scripts?|chunks?|js)/', lower):
                return True

            return False
        except Exception:
            return False

    def _strip_to_static_marker(self, path):
        """
        若路径前缀被路由污染（例如 /a/b/assets/v1/x.js），
        返回从静态目录标记开始的相对路径（assets/v1/x.js）。
        """
        try:
            text = self._normalize_candidate_name(path)
            if not text:
                return ""
            if text.startswith(('http://', 'https://', '//')):
                return ""

            parsed = urlparse(text)
            raw_path = parsed.path or ""
            if not raw_path:
                return ""

            marker = re.search(r'(?i)/(?:assets|static|scripts?|chunks?|js)/', raw_path)
            if not marker:
                return ""

            # 若标记本来就在根部（/assets/...），无需额外裁剪
            prefix = raw_path[:marker.start()]
            if prefix in ("", "/"):
                return ""

            stripped = raw_path[marker.start():].lstrip("/")
            if not stripped:
                return ""

            suffix = ""
            if parsed.query:
                suffix += "?" + parsed.query
            if parsed.fragment:
                suffix += "#" + parsed.fragment
            return stripped + suffix
        except Exception:
            return ""

    def _load_known_static_dirs(self):
        """
        从已成功下载记录中学习静态目录（按 host 聚合），用于跨站点通用回退。
        """
        if self._known_static_dirs_cache is not None:
            return self._known_static_dirs_cache

        cache = {}
        conn = None
        try:
            conn = self._get_db_connection()
            cursor = conn.cursor()
            self._execute_db_with_retry(cursor, "SELECT path FROM js_file WHERE success=1", (), context="load static dirs")
            rows = cursor.fetchall() or []
            for row in rows:
                path = row[0] if row else ""
                if not path:
                    continue
                parsed = urlparse(path)
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    continue
                if not parsed.path or "/" not in parsed.path:
                    continue
                directory = parsed.path.rsplit("/", 1)[0] + "/"
                if not re.search(r'(?i)/(?:assets|static|scripts?|chunks?|js)/', directory):
                    continue
                host = parsed.netloc.lower()
                cache.setdefault(host, set()).add(directory)
        except Exception as e:
            self.log.debug(f"[Debug] 加载已知静态目录失败: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

        self._known_static_dirs_cache = cache
        return cache

    def _build_known_dir_candidates(self, relative_path, parent_js_url):
        """
        基于“已成功静态目录”推导候选 URL。
        例如已知 /subapp/assets/v10.1.0/，遇到 assets/v10.1.0/a.js 时可回推到该目录。
        """
        results = []
        try:
            rel = self._normalize_candidate_name(relative_path)
            if not rel:
                return results
            if rel.startswith(('/', './', '../', 'http://', 'https://', '//')):
                return results

            if self._is_suspicious_chunk_path(rel):
                return results

            parsed_parent = urlparse(parent_js_url or "")
            if not parsed_parent.netloc:
                return results
            host = parsed_parent.netloc.lower()
            scheme = parsed_parent.scheme or "https"

            parsed_rel = urlparse(rel)
            rel_path = (parsed_rel.path or "").lstrip("/")
            if not rel_path or "/" not in rel_path:
                return results

            rel_dir = rel_path.rsplit("/", 1)[0] + "/"
            rel_file = rel_path.rsplit("/", 1)[-1]
            suffix = ""
            if parsed_rel.query:
                suffix += "?" + parsed_rel.query
            if parsed_rel.fragment:
                suffix += "#" + parsed_rel.fragment

            known_dirs = self._load_known_static_dirs().get(host, set())
            rel_dir_lower = rel_dir.lower()
            for directory in known_dirs:
                d_lower = directory.lower()
                # 目录后缀匹配：兼容 /assets/vx/ 与 /subapp/assets/vx/
                if d_lower.endswith("/" + rel_dir_lower) or d_lower.endswith(rel_dir_lower):
                    results.append(f"{scheme}://{host}{directory}{rel_file}{suffix}")
        except Exception:
            return results
        return results

    def _build_public_path_tail_candidate(self, public_path, chunk_name, parent_js_url):
        """
        当 publicPath 带有路由前缀时（如 /admin/x/assets/v1/），
        额外生成基于静态目录尾段（/assets/v1/）的候选，提升跨站点兼容性。
        """
        try:
            pp = (public_path or "").strip()
            name = self._normalize_candidate_name(chunk_name)
            if not pp or not name:
                return ""
            if name.startswith(('/', './', '../', 'http://', 'https://', '//')):
                return ""
            if self._is_suspicious_chunk_path(name):
                return ""

            parsed_pp = urlparse(pp)
            raw_path = parsed_pp.path if (parsed_pp.scheme or parsed_pp.netloc) else pp
            raw_path = (raw_path or "").split("?", 1)[0].split("#", 1)[0]
            if not raw_path:
                return ""

            marker = re.search(r'(?i)/(?:assets|static|scripts?|chunks?|js)/', raw_path)
            if not marker:
                return ""

            tail_dir = raw_path[marker.start():]
            if not tail_dir.endswith("/"):
                tail_dir += "/"

            normalized_raw = raw_path if raw_path.endswith("/") else (raw_path + "/")
            if tail_dir == normalized_raw:
                return ""

            origin = ""
            if parsed_pp.scheme and parsed_pp.netloc:
                origin = f"{parsed_pp.scheme}://{parsed_pp.netloc}"
            if not origin:
                origin = self._get_url_origin(parent_js_url)
            if not origin:
                return ""

            return urljoin(origin + "/", tail_dir.lstrip("/") + name)
        except Exception:
            return ""

    def _should_extend_recover_rounds(self, round_index, downloaded_files, new_queue, unique_count, base_rounds=8, hard_rounds=12):
        try:
            if int(round_index or 0) < int(base_rounds or 8):
                return False
            if int(round_index or 0) >= int(hard_rounds or 12):
                return False
            if not downloaded_files or not new_queue:
                return False

            downloaded_names = {
                os.path.basename(item).split('?', 1)[0].strip()
                for item in (downloaded_files or [])
                if item
            }
            downloaded_names.discard("")
            if not downloaded_names:
                return False

            total_unique = max(1, int(unique_count or 0) or len(downloaded_names))
            success_ratio = len(downloaded_names) / total_unique
            return success_ratio >= 0.35
        except Exception:
            return False

    def _build_static_tail_candidate_from_base(self, base_url, chunk_name):
        """
        从父JS所在目录推断静态目录尾段候选。
        例如 base=/a/b/assets/v1/main.js, chunk=x.js -> /assets/v1/x.js
        """
        try:
            name = self._normalize_candidate_name(chunk_name)
            if not name:
                return ""
            if name.startswith(('/', './', '../', 'http://', 'https://', '//')):
                return ""
            if self._is_suspicious_chunk_path(name):
                return ""

            parsed = urlparse(base_url or "")
            if not (parsed.scheme and parsed.netloc):
                return ""

            path = parsed.path or ""
            if "/" not in path:
                return ""
            base_dir = path.rsplit("/", 1)[0] + "/"

            marker = re.search(r'(?i)/(?:assets|static|scripts?|chunks?|js)/', base_dir)
            if not marker:
                return ""

            tail_dir = base_dir[marker.start():]
            if tail_dir == base_dir:
                return ""

            origin = f"{parsed.scheme}://{parsed.netloc}"
            return urljoin(origin + "/", tail_dir.lstrip("/") + name)
        except Exception:
            return ""

    def _dedupe_urls(self, urls):
        out = []
        seen = set()
        for item in urls or []:
            if not item:
                continue
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out

    def getRealFilePath(self, jsFileNames, jsUrlpath, parent_js_content):
        jsRealPaths = []
        public_path_candidates = self._extract_public_path_candidates(parent_js_content, parent_js_url=jsUrlpath)
        public_base_urls = []
        seen_public_bases = set()
        for candidate in public_path_candidates:
            base_url = candidate if candidate.startswith(('http://', 'https://')) else urljoin(jsUrlpath, candidate)
            if not base_url or base_url in seen_public_bases:
                continue
            seen_public_bases.add(base_url)
            public_base_urls.append(base_url)

        if public_base_urls:
            script_key = Utils().getFilename(jsUrlpath)
            if not hasattr(self, "_logged_public_paths"):
                self._logged_public_paths = set()
            for public_path in public_base_urls[:3]:
                log_key = (script_key, public_path)
                if log_key in self._logged_public_paths:
                    continue
                self._logged_public_paths.add(log_key)
                self.log.info(
                    f"在 {script_key} 中成功提取到 publicPath: '{public_path}'，将优先基于该路径来合并资源 URL。",
                )
        else:
            self.log.debug("未能在父JS中自动提取 publicPath，将使用父JS的URL作为基础。")

        trusted_origins = [self._get_url_origin(jsUrlpath)]
        trusted_origins.extend(self._extract_trusted_external_origins(parent_js_content, parent_js_url=jsUrlpath))
        if getattr(self.options, 'url', None):
            trusted_origins.append(self._get_url_origin(self.options.url))
        trusted_origins = [item for item in self._dedupe_urls(trusted_origins) if item]
        self._remember_trusted_external_origins(trusted_origins)

        public_path = public_path_candidates[0] if public_path_candidates else None
        base_url_for_build = public_base_urls[0] if public_base_urls else jsUrlpath
        has_valid_public = bool(public_base_urls)

        # 安全网：若候选名是 'chunk-xxxx.js' 且父JS内存在映射 '"chunk-xxxx": "hash"'，则补全为 'chunk-xxxx.hash.js'
        def _patch_chunk_without_hash(path: str) -> str:
            try:
                # 已经带 hash 的直接跳过
                if re.search(r"/(?:chunk-[0-9a-fA-F]{6,})\.[0-9a-fA-F]{6,}\.js(?:\?|$)", path):
                    return path
                m = re.search(r"/(chunk-[0-9a-fA-F]{6,})\.js(?:\?|$)", path)
                if not m:
                    return path
                key = m.group(1)
                m2 = re.search(r"[\"']" + re.escape(key) + r"[\"']\s*:\s*[\"']([0-9a-fA-F]{6,})[\"']", parent_js_content)
                if m2:
                    hv = m2.group(1)
                    return path.replace(key + ".js", f"{key}.{hv}.js")
            except Exception:
                pass
            return path

        # 兜底：若候选为 '/123.js' 这类纯数字 chunk，尝试依据父JS中的 hashMap 补全为 '/123.<hash>.js'
        def _patch_numeric_without_hash(path: str) -> str:
            try:
                m = re.search(r"(?:^|/)(\d{1,6})\.js(?:\?|$)", path)
                if not m:
                    return path

                chunk_id = m.group(1)
                hash_match = re.search(
                    r"(?:[\"']" + re.escape(chunk_id) + r"[\"']|\b" + re.escape(chunk_id) + r"\b)\s*:\s*[\"']([0-9a-fA-F]{6,64})[\"']",
                    parent_js_content,
                )
                if not hash_match:
                    return path

                hv = hash_match.group(1)
                return re.sub(
                    r"(^|/)" + re.escape(chunk_id) + r"\.js(?=\?|$)",
                    lambda mm: f"{mm.group(1)}{chunk_id}.{hv}.js",
                    path,
                    count=1,
                )
            except Exception:
                return path

        for jsFileName in jsFileNames:
            # 仅下载 JS-like 资源（含无后缀 chunk 场景），显式跳过 CSS/图片等
            if not self._is_js_like_candidate(jsFileName):
                continue
            if self._is_suspicious_chunk_path(jsFileName):
                continue
            # 针对常见 webpack chunk 命名的修补（避免生成无 hash 的错误请求）
            jsFileName = _patch_chunk_without_hash(jsFileName)
            jsFileName = _patch_numeric_without_hash(jsFileName)

            if has_valid_public:
                # 更通用规则：当存在明确的 publicPath 时，除显式相对路径(./、../)外，
                # 一律按 publicPath 作为构建根路径来解析，避免出现 /admin/login + "static/js/..." => /admin/static/js/... 这类错误。
                if jsFileName.startswith(("./", "../")):
                    base_for_this = jsUrlpath
                else:
                    base_for_this = base_url_for_build
            else:
                # 无 publicPath 时，保留此前基于父 JS 目录的启发式逻辑，兼容 Vite/Rollup 等场景
                if jsFileName.startswith(("./", "../")):
                    base_for_this = jsUrlpath
                elif "/" in jsFileName:
                    base_for_this = jsUrlpath
                else:
                    base_for_this = base_url_for_build

            candidate_urls = []
            normalized_name = self._normalize_candidate_name(jsFileName)
            looks_root_based = self._looks_root_based_relative_path(normalized_name)
            stripped_static_name = self._strip_to_static_marker(normalized_name)

            # 通用修复：对 assets/static/js/chunks 这类“根静态目录”候选，
            # 无论是否提取到了 publicPath，都先并行尝试站点根与历史目录，避免被错误路由前缀绑死。
            if looks_root_based:
                for origin in trusted_origins or [self._get_url_origin(jsUrlpath) or self._get_url_origin(base_for_this)]:
                    if origin:
                        candidate_urls.append(urljoin(origin + "/", normalized_name.lstrip("/")))
                candidate_urls.extend(self._build_known_dir_candidates(normalized_name, jsUrlpath))

            if stripped_static_name:
                for origin in trusted_origins or [self._get_url_origin(jsUrlpath) or self._get_url_origin(base_for_this)]:
                    if origin:
                        candidate_urls.append(urljoin(origin + "/", stripped_static_name.lstrip("/")))
                candidate_urls.extend(self._build_known_dir_candidates(stripped_static_name, jsUrlpath))

            if has_valid_public:
                tail_candidate = self._build_public_path_tail_candidate(public_path, normalized_name, jsUrlpath)
                if tail_candidate:
                    candidate_urls.append(tail_candidate)

            for extra_public_base in public_base_urls[1:4]:
                extra_tail_candidate = self._build_static_tail_candidate_from_base(extra_public_base, normalized_name)
                if extra_tail_candidate:
                    candidate_urls.append(extra_tail_candidate)
                extra_primary = self._build_full_url(normalized_name, extra_public_base)
                if extra_primary:
                    candidate_urls.append(extra_primary)

            base_tail_candidate = self._build_static_tail_candidate_from_base(base_for_this, normalized_name)
            if base_tail_candidate:
                candidate_urls.append(base_tail_candidate)

            primary_url = self._build_full_url(normalized_name, base_for_this)
            if primary_url:
                candidate_urls.append(primary_url)

            # 仅在“简单文件名”场景下再尝试父JS目录二次拼接，避免生成 /.../js/.../js/... 这类重复目录候选。
            normalized_path_only = normalized_name.split('?', 1)[0].split('#', 1)[0]
            simple_name = ('/' not in normalized_path_only and not normalized_path_only.startswith(('./', '../')))
            if base_for_this != jsUrlpath and simple_name:
                secondary_url = self._build_full_url(normalized_name, jsUrlpath)
                if secondary_url:
                    candidate_urls.append(secondary_url)

            for candidate in self._dedupe_urls(candidate_urls):
                jsRealPaths.append(candidate)

        return self._dedupe_urls(jsRealPaths)

    def checkCodeSpilting(self, jsFilePath):
        if jsFilePath in self.processed_files:
            return
        basename = os.path.basename(jsFilePath)
        original_name = self._extract_original_name(basename)
        fingerprint = self._build_processing_fingerprint(jsFilePath)
        if fingerprint in self._processed_source_fingerprints:
            self.log.debug(f"[Debug] 跳过重复文件（来源已分析）: {basename}, fp={fingerprint[:120]}")
            self.processed_files.add(jsFilePath)
            self._mark_recover_checkpoint_dirty()
            return
        self.processed_files.add(jsFilePath)
        self._processed_original_names.add(original_name)
        self._processed_source_fingerprints.add(fingerprint)
        self._mark_recover_checkpoint_dirty()

        try:
            with open(jsFilePath, 'r', encoding='UTF-8', errors="ignore") as f:
                js_content = f.read()
                self.log.info(
                    f"[{Utils().tellTime()}] 正在分析: {Utils().getFilename(jsFilePath)}"
                )
                runtime_profile = self._get_runtime_bundle_profile(js_content, jsFilePath)
                runtime_like = bool(runtime_profile.get("is_runtime_like"))

                # Vite/Rollup detector: scan for new URL(..., import.meta.url) and static import("...")
                self._scan_explicit_external_js_urls(js_content, jsFilePath)
                self._scan_vite_rollup(js_content, jsFilePath)
                self._scan_module_federation(js_content, jsFilePath)
                self._scan_static_manifest_imports(js_content, jsFilePath)

                # 自定义脚本加载器（例如 _API_Path + _load(...)）
                self._scan_custom_loader(
                    js_content,
                    jsFilePath,
                    runtime_like=runtime_like,
                    runtime_profile=runtime_profile,
                )
                self._scan_dom_loader(js_content, jsFilePath)
                # Webpack5 简单 chunk 命名模式：obj.u = function(e){ return "js/" + e + ".js"; }
                self._scan_webpack_literal_chunks(js_content, jsFilePath)


            shared_seen = set()
            ast_hits = self._analyze_with_ast(js_content, jsFilePath, shared_seen=shared_seen)
            regex_hits = self._analyze_with_regex(js_content, jsFilePath, shared_seen=shared_seen)

            if ast_hits <= 0 and regex_hits <= 0:
                self.log.debug(f"AST/Regex均未命中可还原表达式: {Utils().getFilename(jsFilePath)}")

        except Exception as e:
            self.log.error(f"[Err] 分析文件 {Utils().getFilename(jsFilePath)} 时发生未知错误: {e}")

    def _analyze_with_ast(self, js_content, jsFilePath, shared_seen=None):
        try:
            raw_len = len(js_content or "")
            if raw_len <= 0:
                return 0

            # 常规文件优先整文件 AST，保持既有识别精度。
            if not self._should_skip_ast_scan(raw_len):
                ast = esprima.parseScript(js_content, {'range': True, 'tolerant': True})
                return self._traverse_ast(ast, js_content, jsFilePath, shared_seen=shared_seen)

            anchors = self._collect_loader_anchor_positions(js_content, limit=96)
            windows = self._build_full_coverage_windows(
                js_content,
                window_chars=self._ast_scan_window_max_chars,
                overlap_chars=self._scan_window_overlap_chars,
                target_segments=max(self._ast_scan_max_windows, 12),
                max_window_chars=max(self._ast_scan_window_max_chars, 1200000),
                anchor_positions=anchors,
            )
            if not windows:
                return 0

            self.log.debug(
                f"[Debug] AST超大文件全覆盖分窗扫描: {Utils().getFilename(jsFilePath)} windows={len(windows)}"
            )
            ast_hits = 0
            for _, _, segment in windows:
                if not segment:
                    continue
                try:
                    ast = esprima.parseScript(segment, {'range': True, 'tolerant': True})
                except Exception:
                    continue
                ast_hits += self._traverse_ast(
                    ast,
                    segment,
                    jsFilePath,
                    shared_seen=shared_seen,
                    max_hits=96,
                )
            return ast_hits
        except Exception as e:
            self.log.debug(f"[Debug] AST解析文件 {Utils().getFilename(jsFilePath)} 时失败: {e}")
            return 0

    def _process_ast_function_candidate(self, func_node, param_name, js_content, jsFilePath, shared_seen=None):
        """
        处理 AST 命中的函数候选，提取多条 return 表达式并尝试还原。
        返回本函数候选产生的命中次数（表达式级）。
        """
        hits = 0
        try:
            exprs = self._extract_candidate_exprs_from_function_ast(func_node, js_content)
            for code_body in exprs:
                if not code_body:
                    continue

                # 防止极长表达式影响分析时延
                if len(code_body) > 20000:
                    continue

                if not self._looks_async_loader_expr(code_body, param_name):
                    continue

                if not self._mark_expr_seen(shared_seen, param_name, code_body):
                    continue

                self.log.info(f"AST发现可能的异步加载函数: {Utils().getFilename(jsFilePath)}")
                self.compile_from_ast(code_body, param_name, jsFilePath, js_content)
                hits += 1

                if hits >= 18:
                    break
        except Exception:
            return hits

        return hits

    def _traverse_ast(self, node, js_content, jsFilePath, shared_seen=None, max_hits=64):
        if not node or not isinstance(node, esprima.nodes.Node):
            return 0

        total_hits = 0

        # 1) 通用：任意赋值为函数/箭头函数的形式
        if node.type == 'AssignmentExpression' and node.operator == '=' and \
           getattr(node.right, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):

            func_node = node.right
            param_name = self._extract_first_param_name(func_node)
            total_hits += self._process_ast_function_candidate(
                func_node,
                param_name,
                js_content,
                jsFilePath,
                shared_seen=shared_seen,
            )
            if total_hits >= max_hits:
                return total_hits

        # 2) 变量声明直接初始化为函数/箭头函数
        if node.type == 'VariableDeclarator':
            init = getattr(node, 'init', None)
            if getattr(init, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):
                func_node = init
                param_name = self._extract_first_param_name(func_node)
                total_hits += self._process_ast_function_candidate(
                    func_node,
                    param_name,
                    js_content,
                    jsFilePath,
                    shared_seen=shared_seen,
                )
                if total_hits >= max_hits:
                    return total_hits

        # 3) 函数声明：function u(e) { ... }
        if node.type == 'FunctionDeclaration':
            param_name = self._extract_first_param_name(node)
            total_hits += self._process_ast_function_candidate(
                node,
                param_name,
                js_content,
                jsFilePath,
                shared_seen=shared_seen,
            )
            if total_hits >= max_hits:
                return total_hits

        # 4) 对象字面量中的函数属性：{ u: function(e){...} } / { u: (e)=>... }
        if node.type == 'Property':
            value = getattr(node, 'value', None)
            if getattr(value, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):
                param_name = self._extract_first_param_name(value)
                total_hits += self._process_ast_function_candidate(
                    value,
                    param_name,
                    js_content,
                    jsFilePath,
                    shared_seen=shared_seen,
                )
                if total_hits >= max_hits:
                    return total_hits

        # 5) class 方法：class X { u(e) { ... } }
        if node.type == 'MethodDefinition':
            value = getattr(node, 'value', None)
            if getattr(value, 'type', None) in ('FunctionExpression', 'ArrowFunctionExpression'):
                param_name = self._extract_first_param_name(value)
                total_hits += self._process_ast_function_candidate(
                    value,
                    param_name,
                    js_content,
                    jsFilePath,
                    shared_seen=shared_seen,
                )
                if total_hits >= max_hits:
                    return total_hits

        for key in dir(node):
            if not key.startswith('_'):
                child = getattr(node, key)
                if isinstance(child, esprima.nodes.Node):
                    total_hits += self._traverse_ast(
                        child,
                        js_content,
                        jsFilePath,
                        shared_seen=shared_seen,
                        max_hits=max_hits,
                    )
                    if total_hits >= max_hits:
                        return total_hits
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, esprima.nodes.Node):
                            total_hits += self._traverse_ast(
                                item,
                                js_content,
                                jsFilePath,
                                shared_seen=shared_seen,
                                max_hits=max_hits,
                            )
                            if total_hits >= max_hits:
                                return total_hits
        return total_hits

    def _analyze_with_regex(self, js_content, jsFilePath, shared_seen=None):
        try:
            raw_len = len(js_content or "")
            if raw_len <= 0:
                return 0

            anchors = self._collect_loader_anchor_positions(js_content, limit=128)
            windows = self._build_full_coverage_windows(
                js_content,
                window_chars=self._regex_scan_max_chars,
                overlap_chars=self._scan_window_overlap_chars,
                target_segments=max(self._regex_scan_max_windows, 16),
                max_window_chars=max(self._regex_scan_max_chars, 900000),
                anchor_positions=anchors,
            )
            if not windows:
                scan_content = self._get_regex_scan_content(js_content, jsFilePath)
                windows = [(0, len(scan_content), scan_content)] if scan_content else []
            if not windows:
                return 0

            if self._should_skip_regex_scan(raw_len):
                self.log.debug(
                    f"[Debug] Regex超大文件全覆盖分窗扫描: {Utils().getFilename(jsFilePath)} windows={len(windows)}"
                )

            regex_hits = 0
            for _, _, scan_content in windows:
                if not scan_content:
                    continue
                regex_hits += self._analyze_with_regex_content(
                    scan_content,
                    jsFilePath,
                    shared_seen=shared_seen,
                )
            return regex_hits
        except Exception as e:
            self.log.debug(f"[Debug] Regex 回退解析失败: {e}")
            return 0

    def _analyze_with_regex_content(self, scan_content, jsFilePath, shared_seen=None):
        try:
            scan_content = scan_content or ""
            if not scan_content:
                return 0
            # 正则与父上下文解析统一使用扫描窗口，避免在超大 vendor 包上重复全量解析。
            parent_scan_content = scan_content
            produced_any = False
            regex_hits = 0
            runtime_like = self._is_runtime_like_bundle(scan_content, jsFilePath)
            max_candidate_exprs = 64
            scanned_candidate_exprs = 0
            cap_notice_logged = False

            def _can_scan_more():
                nonlocal scanned_candidate_exprs, cap_notice_logged
                if scanned_candidate_exprs >= max_candidate_exprs:
                    if not cap_notice_logged:
                        self.log.debug(
                            f"[Debug] Regex候选扫描达到上限，提前停止: {Utils().getFilename(jsFilePath)}"
                        )
                        cap_notice_logged = True
                    return False
                scanned_candidate_exprs += 1
                return True

            # 非 runtime 文件只做轻量扫描，避免把业务 URL 当成异步 chunk 加载器
            if not runtime_like:
                patterns = [
                    re.compile(r"=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
                    re.compile(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
                ]

                seen_exprs = set()

                def _try_light(param_name, return_expr):
                    nonlocal produced_any, regex_hits
                    expr = (return_expr or '').strip()
                    if not expr or len(expr) >= 12000:
                        return
                    if not _can_scan_more():
                        return
                    key = (param_name, expr)
                    if key in seen_exprs:
                        return
                    if not self._mark_expr_seen(shared_seen, param_name, expr):
                        seen_exprs.add(key)
                        return
                    seen_exprs.add(key)
                    if not self._looks_strong_async_loader_expr(expr, param_name, runtime_like=False):
                        return
                    added = self.compile_from_regex(expr, param_name, jsFilePath, parent_scan_content)
                    if added:
                        produced_any = True
                        regex_hits += 1

                for pat in patterns:
                    for param_name, return_expr in pat.findall(scan_content):
                        _try_light(param_name, return_expr)

                return regex_hits

            # 在单个文件作用域内，对“参数名 + 返回表达式”做一次去重，避免重复解析/重复日志
            seen_exprs = set()

            def _try_compile_regex_expr(param_name, return_expr, log_label=None, need_async_hint=False, allow_long_expr=False):
                nonlocal produced_any, regex_hits

                if not return_expr:
                    return False

                expr = return_expr.strip()
                if not expr:
                    return False

                if len(expr) >= 12000:
                    if not allow_long_expr:
                        if runtime_like and self._looks_runtime_loader_expr(expr, param_name):
                            allow_long_expr = True
                        else:
                            return False

                if not _can_scan_more():
                    return False

                if need_async_hint and not self._looks_strong_async_loader_expr(expr, param_name, runtime_like=runtime_like):
                    return False

                local_key = (param_name, expr)
                if local_key in seen_exprs:
                    return False

                if not self._mark_expr_seen(shared_seen, param_name, expr):
                    seen_exprs.add(local_key)
                    return False

                seen_exprs.add(local_key)

                if log_label:
                    self.log.info(f"Regex发现可能的异步加载函数({log_label}): {Utils().getFilename(jsFilePath)}")

                added = self.compile_from_regex(expr, param_name, jsFilePath, parent_scan_content)
                if added:
                    produced_any = True
                    regex_hits += 1
                return added

            # d) runtime arrow 长表达式专用提取：兼容超长单行、无分号场景。
            runtime_arrow_loader_pat = re.compile(
                r"([A-Za-z_$][\w$]*)\.u\s*=\s*(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*))\s*=>",
                re.I,
            )
            for m in runtime_arrow_loader_pat.finditer(scan_content):
                param_name = m.group(2) or m.group(3) or ""
                if not param_name:
                    continue
                expr = self._extract_assignment_expression(
                    scan_content,
                    m.end(),
                    max_chars=max(220000, self._regex_scan_max_chars),
                )
                if not expr:
                    continue
                if not self._looks_runtime_loader_expr(expr, param_name):
                    continue
                _try_compile_regex_expr(
                    param_name,
                    expr,
                    log_label="runtime arrow",
                    need_async_hint=False,
                    allow_long_expr=True,
                )

            # 通用模式：函数/箭头函数体内直接 return '...js'（仅当表达式不超长时尝试）
            patterns = [
                re.compile(r"=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
                re.compile(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{[^{}]*?return\s+(.+?['\"]\.(?:js|mjs)[^;]*?)\s*;?[^}]*\}", re.DOTALL),
            ]
            for pat in patterns:
                matches = pat.findall(scan_content)
                for m in matches:
                    param_name, return_expr = m
                    _try_compile_regex_expr(param_name, return_expr, need_async_hint=True)

            # 更通用的强力回退：无论上面是否命中，都额外扫描任意 “= function(p){...}” / “= (p)=>{...}”
            # 仅当成功生成候选文件名时，才算一次有效命中
            # a) 常规函数形式
            for m in re.finditer(r"=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{", scan_content):
                param_name = m.group(1)
                brace_start = m.end() - 1
                body = self._find_balanced_block(scan_content, brace_start)
                if body:
                    return_exprs = self._extract_return_exprs_from_func_body(body, max_items=8)
                    for return_expr in return_exprs:
                        _try_compile_regex_expr(param_name, return_expr, log_label="function", need_async_hint=True)

            # b) 箭头函数块体形式
            for m in re.finditer(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*\{", scan_content):
                param_name = m.group(1)
                brace_start = m.end() - 1
                body = self._find_balanced_block(scan_content, brace_start)
                if body:
                    return_exprs = self._extract_return_exprs_from_func_body(body, max_items=8)
                    for return_expr in return_exprs:
                        _try_compile_regex_expr(param_name, return_expr, log_label="arrow {}", need_async_hint=True)

            # c) 箭头函数表达式体形式：u=(e)=> prefix + {...}[e] + ".js"
            for m in re.finditer(r"=\s*\(?\s*([A-Za-z_$][\w$]*)\s*\)?\s*=>\s*(?!\{)\s*([^;\n]+)", scan_content):
                param_name = m.group(1)
                return_expr = m.group(2)
                _try_compile_regex_expr(param_name, return_expr, log_label="arrow expr", need_async_hint=True)

            # 其它常见回退：document.createElement("script") 场景（不会阻止上述扫描）
            if (not produced_any) and "document.createElement(\"script\")" in scan_content:
                pattern = re.compile(r"\w\.p\+\"(.*?)\.js\"")
                jsCodeList = pattern.findall(scan_content)
                if jsCodeList:
                    self.log.info(f"Regex发现 {len(jsCodeList)} 个可能的异步加载片段: {Utils().getFilename(jsFilePath)}")
                    for jsCode in jsCodeList:
                        if len(jsCode) < 120000:
                            full_js_code = '"' + jsCode + '.js"'
                            # 尝试从片段中推断真实的模块参数名（如 a、t 等），否则回退为 "e"
                            m_param = re.search(r'\[\s*([A-Za-z_$][\w$]*)\s*\]', full_js_code)
                            param_name = m_param.group(1) if m_param else "e"
                            _try_compile_regex_expr(param_name, full_js_code)

            return regex_hits

        except Exception as e:
            self.log.debug(f"[Debug] Regex 回退解析失败: {e}")
            return 0

    def recoverStart(self):
        projectPath = DatabaseType(self.projectTag).getPathfromDB()

        if not projectPath or not os.path.exists(projectPath):
            self.log.error("[Err] 项目目录不存在，无法执行异步JS恢复")
            return

        target_url = getattr(self.options, 'url', None) or ''
        domain = urlparse(target_url).netloc
        if ":" in domain:
            domain = domain.replace(":", "_")
        if not domain:
            directory_name = os.path.basename(os.path.normpath(projectPath))
            prefix = f"{self.projectTag}_"
            if directory_name.startswith(prefix):
                domain = directory_name[len(prefix):]

        if not domain:
            self.log.error("[Err] 无法确定项目域名，异步JS下载阶段将跳过")
            return

        self._load_recover_checkpoint(projectPath)
        self._init_split_id_counter()
        self.log.info("--- 开始混合模式分析 (AST为主, Regex为辅) ---")

        initial_queue = []
        skipped_sourcemap_sources = 0
        skipped_sourcemap_mirrors = 0
        for parent, _, filenames in os.walk(projectPath, followlinks=True):
            for filename in filenames:
                candidate = os.path.normpath(os.path.join(parent, filename))
                if self._should_include_recover_file(candidate):
                    initial_queue.append(candidate)
                elif self._is_sourcemap_source_file(candidate):
                    skipped_sourcemap_sources += 1
                elif self._is_sourcemap_mirror_file(candidate):
                    skipped_sourcemap_mirrors += 1

        if not initial_queue:
            self.log.info("[*] 未发现可分析的 JS 文件")
            return
        if skipped_sourcemap_sources > 0:
            self.log.info(
                f"[*] 已跳过 SourceMap 还原源码 {skipped_sourcemap_sources} 个（默认不参与恢复轮次）"
            )
        if skipped_sourcemap_mirrors > 0:
            self.log.info(
                f"[*] 已跳过 SourceMap 镜像文件 {skipped_sourcemap_mirrors} 个（避免重复分析）"
            )

        analysis_queue = list(dict.fromkeys(initial_queue))
        base_max_rounds = 8
        hard_max_rounds = 12
        max_rounds = base_max_rounds
        round_index = 1

        while round_index <= max_rounds:
            round_files = []
            while analysis_queue:
                file_path = os.path.normpath(analysis_queue.pop(0))
                if file_path in self.processed_files:
                    continue
                if not os.path.exists(file_path):
                    continue
                round_files.append(file_path)

            if not round_files and not self.pending_js_files:
                if round_index == 1:
                    self.log.info("[*] 未发现新的异步JS文件")
                self._flush_recover_checkpoint(round_index=round_index, force=True)
                break

            if round_files:
                self.log.info(f"[+] 第 {round_index} 轮：待分析JS文件 {len(round_files)} 个")
                for js_file_path in round_files:
                    self.checkCodeSpilting(js_file_path)
                    self._flush_recover_checkpoint(round_index=round_index, force=False)

            if not self.pending_js_files:
                self._flush_recover_checkpoint(round_index=round_index, force=True)
                break

            self._mark_recover_checkpoint_dirty()
            self._flush_recover_checkpoint(round_index=round_index, force=True)

            pending_urls = sorted(self.pending_js_files)
            self.pending_js_files.clear()
            self._mark_recover_checkpoint_dirty()
            # 按文件名统计唯一文件数，pending_urls中同一文件可能有多个候选URL
            unique_filenames = set()
            for u in pending_urls:
                fname = u.rsplit('/', 1)[-1].split('?')[0].strip()
                if fname:
                    unique_filenames.add(fname)
            unique_count = len(unique_filenames) if unique_filenames else len(pending_urls)
            self.log.info(f"[+] 第 {round_index} 轮：发现 {unique_count} 个异步JS文件（{len(pending_urls)} 个候选URL），开始下载...")

            downloaded_files = DownloadJs(
                pending_urls,
                self.options,
                DiscoverySource.ASYNC_RECOVERY,
            ).downloadJs(self.projectTag, domain, 999)
            if downloaded_files:
                new_queue = [
                    os.path.normpath(path)
                    for path in downloaded_files
                    if path and self._should_include_recover_file(path)
                ]
                if new_queue:
                    # 仅分析“本轮新增下载文件”
                    analysis_queue.extend(new_queue)
                    self._mark_recover_checkpoint_dirty()
                    if self._should_extend_recover_rounds(
                        round_index,
                        downloaded_files,
                        new_queue,
                        unique_count,
                        base_rounds=base_max_rounds,
                        hard_rounds=hard_max_rounds,
                    ):
                        next_cap = min(hard_max_rounds, max(max_rounds, round_index + 1))
                        if next_cap > max_rounds:
                            max_rounds = next_cap
                            self.log.info(f"[+] 恢复链仍在产生新文件，已将最大恢复轮次扩展到 {max_rounds}")

            self._flush_recover_checkpoint(round_index=round_index, force=True)

            round_index += 1

        if round_index > max_rounds:
            self.log.warning(f"[!] 已达到最大恢复轮次 {max_rounds}，停止继续递归恢复")
            self._flush_recover_checkpoint(round_index=max_rounds, force=True)
            return

        # 正常完成后清理检查点，避免后续扫描误判为续跑。
        self._clear_recover_checkpoint()


# 规范命名别名，兼容历史类名。
RecoverSplit = RecoverSpilt
