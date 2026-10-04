#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import re
import os
import json
import base64
import time
import html # 修复: 导入 html 模块
import requests
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from typing import Dict, List, Tuple, Set, Optional
from collections import Counter, defaultdict
from types import SimpleNamespace
from urllib.parse import urlparse

from lib.common.CreatLog import creatLog
from lib.common.utils import Utils
from lib.common.textdecode import decode_bytes_robust
from lib.Database import DatabaseType
import multiprocessing


@dataclass(frozen=True)
class RuleSpec:
    name: str
    pattern: str
    flags: int
    hint_tokens: Tuple[str, ...]
    category: str
    verifier_name: str = ""


class PrefilterIndex:
    def __init__(self, rule_specs: List[RuleSpec]):
        self.backend = "python-substring"
        self._fallback_rule_indexes: Set[int] = set()
        self._token_to_rule_indexes: Dict[str, Set[int]] = defaultdict(set)

        for idx, rule in enumerate(rule_specs):
            tokens = tuple(tok.lower() for tok in (rule.hint_tokens or ()) if tok)
            if not tokens:
                self._fallback_rule_indexes.add(idx)
                continue
            for token in tokens:
                self._token_to_rule_indexes[token].add(idx)

        self._token_items = tuple(sorted(self._token_to_rule_indexes.items(), key=lambda item: (-len(item[0]), item[0])))

        try:
            import ahocorasick  # type: ignore

            automaton = ahocorasick.Automaton()
            for token, indexes in self._token_items:
                automaton.add_word(token, (token, tuple(sorted(indexes))))
            automaton.make_automaton()
            self._aho_automaton = automaton
            self.backend = "ahocorasick"
        except Exception:
            self._aho_automaton = None

    def candidate_rule_indexes(self, text_lower: str) -> Tuple[Set[int], Dict[str, int]]:
        stats = {
            "token_checks": 0,
            "tokens_hit": 0,
            "fallback_rules": len(self._fallback_rule_indexes),
        }
        candidates = set(self._fallback_rule_indexes)
        if not text_lower:
            return candidates, stats

        if self._aho_automaton is not None:
            seen_tokens = set()
            for _, payload in self._aho_automaton.iter(text_lower):
                token, indexes = payload
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                stats["tokens_hit"] += 1
                candidates.update(indexes)
            stats["token_checks"] = len(self._token_items)
            return candidates, stats

        for token, indexes in self._token_items:
            stats["token_checks"] += 1
            if token not in text_lower:
                continue
            stats["tokens_hit"] += 1
            candidates.update(indexes)
        return candidates, stats


class MatchEngine:
    def __init__(self, rule_specs: List[RuleSpec], owner: "JsFinderModule"):
        self.owner = owner
        self.rule_specs = list(rule_specs)
        self.compiled_patterns = [re.compile(rule.pattern, rule.flags) for rule in self.rule_specs]
        self.prefilter = PrefilterIndex(self.rule_specs)

    def _build_targeted_subsegments(
        self,
        rule: RuleSpec,
        seg_offset: int,
        seg_text: str,
        seg_text_lower: str,
    ) -> List[Tuple[int, str]]:
        if not seg_text:
            return []
        safe_expensive_rules = {
            'Password',
            'Internal_IP',
            'HTTP_Authorization_Header',
            'Github_Token',
            'AppSecret_AppKey',
            'WeCom_Credential',
            'Feishu_Credential',
        }
        unsafe_targeted_rules = {
            'Username/Account',
            '敏感配置信息',
        }
        allow_targeted = (
            rule.category == "token-gated"
            or (rule.category == "expensive-regex" and rule.name in safe_expensive_rules)
        )
        if rule.name in unsafe_targeted_rules:
            allow_targeted = False
        if not rule.hint_tokens or not allow_targeted:
            return [(seg_offset, seg_text)]

        radius = 900 if rule.category == "expensive-regex" else 420
        min_window = 1200 if rule.category == "expensive-regex" else 700
        ranges: List[Tuple[int, int]] = []
        total_len = len(seg_text)
        hit_count = 0

        for token in rule.hint_tokens:
            if not token:
                continue
            start = 0
            token_len = len(token)
            while start < total_len:
                idx = seg_text_lower.find(token, start)
                if idx < 0:
                    break
                hit_count += 1
                win_start = max(0, idx - radius)
                win_end = min(total_len, idx + token_len + radius)
                if win_end - win_start < min_window:
                    deficit = min_window - (win_end - win_start)
                    left_pad = deficit // 2
                    right_pad = deficit - left_pad
                    win_start = max(0, win_start - left_pad)
                    win_end = min(total_len, win_end + right_pad)
                ranges.append((win_start, win_end))
                if hit_count >= 256:
                    return [(seg_offset, seg_text)]
                start = idx + max(1, token_len)

        if not ranges:
            return []

        ranges.sort(key=lambda item: item[0])
        merged: List[Tuple[int, int]] = []
        for start, end in ranges:
            if not merged:
                merged.append((start, end))
                continue
            prev_start, prev_end = merged[-1]
            if start <= prev_end + 80:
                merged[-1] = (prev_start, max(prev_end, end))
            else:
                merged.append((start, end))

        covered = sum(end - start for start, end in merged)
        if covered >= int(total_len * 0.72) or len(merged) >= 48:
            return [(seg_offset, seg_text)]

        return [
            (seg_offset + start, seg_text[start:end])
            for start, end in merged
            if end > start
        ]

    def scan(self, content: str, filename: str, scan_segments: Optional[List[Tuple[int, str]]] = None) -> Tuple[Dict[str, List[Tuple[str, str, str]]], Dict[str, int]]:
        matches: Dict[str, List[Tuple[str, str, str]]] = {}
        segments = scan_segments or [(0, content)]
        prepared_segments = [
            (int(seg_offset or 0), seg_text or "", (seg_text or "").lower())
            for seg_offset, seg_text in segments
        ]
        line_starts: Optional[List[int]] = None
        stats = {
            "segments": len(prepared_segments),
            "rule_runs": 0,
            "rule_candidates": 0,
            "targeted_subsegments": 0,
            "prefilter_token_checks": 0,
            "prefilter_tokens_hit": 0,
            "prefilter_rules_skipped": 0,
            "total_matches": 0,
        }

        for seg_offset, seg_text, seg_text_lower in prepared_segments:
            if not seg_text:
                continue
            candidate_indexes, prefilter_stats = self.prefilter.candidate_rule_indexes(seg_text_lower)
            stats["prefilter_token_checks"] += prefilter_stats["token_checks"]
            stats["prefilter_tokens_hit"] += prefilter_stats["tokens_hit"]
            stats["rule_candidates"] += len(candidate_indexes)
            stats["prefilter_rules_skipped"] += max(0, len(self.rule_specs) - len(candidate_indexes))

            for rule_idx in sorted(candidate_indexes):
                rule = self.rule_specs[rule_idx]
                compiled_pattern = self.compiled_patterns[rule_idx]
                pattern_matches = matches.setdefault(rule.name, [])
                seen_for_rule = set(pattern_matches)
                try:
                    subsegments = self._build_targeted_subsegments(rule, seg_offset, seg_text, seg_text_lower)
                    if not subsegments:
                        continue
                    stats["targeted_subsegments"] += max(0, len(subsegments) - 1)
                    for sub_offset, sub_text in subsegments:
                        stats["rule_runs"] += 1
                        for match in compiled_pattern.finditer(sub_text):
                            if line_starts is None:
                                line_starts = self.owner._build_line_starts(content)
                            normalized = self.owner._normalize_rule_match(rule, match, filename, content, sub_offset, line_starts)
                            if normalized is None:
                                continue
                            if normalized in seen_for_rule:
                                continue
                            seen_for_rule.add(normalized)
                            pattern_matches.append(normalized)
                            stats["total_matches"] += 1
                except re.error as e:
                    self.owner.log.error(f"正则表达式 '{rule.name}' 无效: {e}")
                    continue

        return {name: values for name, values in matches.items() if values}, stats


_FINDER_WORKER_INSTANCE: Optional["JsFinderModule"] = None


def _finder_worker_init(payload: Dict) -> None:
    global _FINDER_WORKER_INSTANCE
    _FINDER_WORKER_INSTANCE = JsFinderModule._from_worker_payload(payload)


def _finder_worker_process_js_file(file_path: str, sm_source_roots: Optional[List[str]] = None):
    if _FINDER_WORKER_INSTANCE is None:
        raise RuntimeError("Finder worker is not initialized")
    return _FINDER_WORKER_INSTANCE.process_js_file(file_path, sm_source_roots)

class JsFinderModule:
    def __init__(self, projectTag, options):
        self.projectTag = projectTag
        self.options = options
        self.log = creatLog().get_logger()

        # --- 修复：确保每个项目的输出目录是唯一的 ---
        self.output_directory = os.path.join(DatabaseType(self.projectTag).getPathfromDB(), 'finder_results')

        self.regex_patterns = self.load_regex_patterns()
        self._compiled_path_patterns = self._build_path_patterns()
        self._compiled_route_patterns = self._build_route_patterns()
        try:
            parsed = urlparse(getattr(self.options, 'url', '') or '')
            self.target_netloc = (parsed.netloc or '').lower()
            self.target_host_no_port = self.target_netloc.split(':')[0]
            labels = [p for p in self.target_host_no_port.split('.') if p]
            self.base_domain = '.'.join(labels[-2:]) if len(labels) >= 2 else self.target_host_no_port
        except Exception:
            self.target_netloc = ''
            self.target_host_no_port = ''
            self.base_domain = ''

        self.blacklist_domains = self.load_blacklist_domains()
        # 末段词表/资源聚合的配置
        self._verbs = {'add','create','new','update','edit','change','delete','remove','clear','reset','list','get','query','search','detail','info','show','save','export','import','upload','download'}
        self._suffix_detail_like = {'detail','info','list','page','pages','all'}
        self._stop_tokens = {'api','tmp','tmpl','tmple','template','v1','v2','v3'}
        self._synonyms = {'companty':'company','permissions':'permission','menus':'menu','roles':'role','users':'user','usernames':'username','pwd':'password'}

        # 接口路径提取降噪配置（借鉴 JS Analyzer 思路并保留业务接口覆盖）
        self._path_noise_strings = {
            'http://', 'https://', '/#', '/?', '//', '/,', '/g,', '/g,s=', '/g,s=r('
        }
        self._path_noise_patterns = [
            re.compile(r'^\+'),
            re.compile(r'^\$?\{'),
            re.compile(r'^#'),
            re.compile(r'^\?'),
            re.compile(r'^[A-Za-z]:\\'),
            re.compile(r'\s'),
            re.compile(r'^\d+(?:\.\d+)?$'),
            re.compile(r'^[DMYmdy]{1,4}/[DMYmdy]{1,4}/[DMYmdy]{1,4}$'),
            re.compile(r'^\d{1,4}/\d{1,2}/\d{1,4}$'),
            re.compile(r'^/\*'),
            re.compile(r'^/[a-zA-Z]$'),
            re.compile(r'^/:[^/]+'),
            re.compile(r'(?:\(\?:|\(\?!|\(\?=)'),
            re.compile(r'[<>{}|`\\\[\]()*]'),
            re.compile(r'\b(?:undefined|null)\b', re.IGNORECASE),
            re.compile(r'_ngcontent', re.IGNORECASE),
        ]
        self._module_prefixes = (
            './', '../',
            './lib', '../lib', './utils', '../utils',
            './node_modules', '../node_modules',
            './src', '../src', './dist', '../dist',
        )
        self._path_static_exts = (
            '.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.webp', '.map', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4',
            '.avi', '.mov', '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz', '.vue',
            '.ts', '.tsx', '.jsx'
        )
        self._mime_prefixes = (
            'application/', 'text/', 'image/', 'audio/', 'video/', 'font/', 'multipart/'
        )
        self._timezone_prefixes = {
            'africa', 'america', 'asia', 'europe', 'pacific', 'atlantic', 'indian', 'antarctica', 'arctic'
        }
        self._path_keep_keywords = {
            'api', 'rest', 'graphql', 'auth', 'oauth', 'login', 'logout', 'token',
            'admin', 'dashboard', 'internal', 'config', 'upload', 'download', 'rpc',
            'openapi', 'v1', 'v2', 'v3',
            'ws', 'wss', 'socket', 'stream', 'webhook', 'callback', 'notify', 'push',
            'payment', 'order', 'user', 'account', 'member', 'register', 'signup',
        }
        # 大文件敏感扫描优化：默认采样窗口，避免在超大 bundle 上全量正则导致长时间卡住。
        try:
            scan_window = int(getattr(self.options, 'finder_scan_window_chars', 360000) or 360000)
        except Exception:
            scan_window = 360000
        self._finder_scan_window_chars = max(120000, scan_window)
        try:
            scan_windows = int(getattr(self.options, 'finder_scan_max_windows', 3) or 3)
        except Exception:
            scan_windows = 3
        self._finder_scan_max_windows = max(2, min(scan_windows, 8))
        try:
            scan_overlap = int(getattr(self.options, 'finder_scan_overlap_chars', 12000) or 12000)
        except Exception:
            scan_overlap = 12000
        self._finder_scan_overlap_chars = max(0, min(scan_overlap, 120000))
        try:
            hard_skip = int(getattr(self.options, 'finder_scan_hard_skip_chars', 5000000) or 5000000)
        except Exception:
            hard_skip = 5000000
        self._finder_scan_hard_skip_chars = max(self._finder_scan_window_chars * 2, hard_skip)
        self._perf_stats: Dict[str, object] = {}
        self._use_process_backend = False
        self._pattern_scan_hints = self._build_pattern_scan_hints()
        self._rule_specs = self._build_rule_specs()
        self.compiled_regex_patterns = {
            rule.name: re.compile(rule.pattern, rule.flags)
            for rule in self._rule_specs
        }
        self._match_engine = MatchEngine(self._rule_specs, self)

    @classmethod
    def _from_worker_payload(cls, payload: Dict) -> "JsFinderModule":
        inst = cls.__new__(cls)
        inst.projectTag = payload.get("projectTag", "")
        inst.options = SimpleNamespace(url=payload.get("target_url", ""))
        inst.log = creatLog().get_logger()
        inst.output_directory = payload.get("output_directory", "")
        inst.regex_patterns = dict(payload.get("regex_patterns") or {})
        inst.target_netloc = payload.get("target_netloc", "")
        inst.target_host_no_port = payload.get("target_host_no_port", "")
        inst.base_domain = payload.get("base_domain", "")
        inst.blacklist_domains = set(payload.get("blacklist_domains") or [])
        inst._verbs = set(payload.get("verbs") or [])
        inst._suffix_detail_like = set(payload.get("suffix_detail_like") or [])
        inst._stop_tokens = set(payload.get("stop_tokens") or [])
        inst._synonyms = dict(payload.get("synonyms") or {})
        inst._path_noise_strings = set(payload.get("path_noise_strings") or [])
        inst._path_noise_patterns = [re.compile(p, re.IGNORECASE if ignore_case else 0) for p, ignore_case in (payload.get("path_noise_patterns") or [])]
        inst._module_prefixes = tuple(payload.get("module_prefixes") or ())
        inst._path_static_exts = tuple(payload.get("path_static_exts") or ())
        inst._mime_prefixes = tuple(payload.get("mime_prefixes") or ())
        inst._timezone_prefixes = set(payload.get("timezone_prefixes") or [])
        inst._path_keep_keywords = set(payload.get("path_keep_keywords") or [])
        inst._finder_scan_window_chars = int(payload.get("finder_scan_window_chars") or 360000)
        inst._finder_scan_max_windows = int(payload.get("finder_scan_max_windows") or 3)
        inst._finder_scan_overlap_chars = int(payload.get("finder_scan_overlap_chars") or 12000)
        inst._finder_scan_hard_skip_chars = int(payload.get("finder_scan_hard_skip_chars") or 5000000)
        inst._compiled_path_patterns = cls._build_path_patterns()
        inst._compiled_route_patterns = cls._build_route_patterns()
        inst._perf_stats = {}
        inst._use_process_backend = False
        inst._pattern_scan_hints = inst._build_pattern_scan_hints()
        inst._rule_specs = inst._build_rule_specs()
        inst.compiled_regex_patterns = {
            rule.name: re.compile(rule.pattern, rule.flags)
            for rule in inst._rule_specs
        }
        inst._match_engine = MatchEngine(inst._rule_specs, inst)
        return inst

    def _build_worker_payload(self) -> Dict:
        return {
            "projectTag": self.projectTag,
            "target_url": getattr(self.options, 'url', '') or '',
            "output_directory": self.output_directory,
            "regex_patterns": self.regex_patterns,
            "target_netloc": self.target_netloc,
            "target_host_no_port": self.target_host_no_port,
            "base_domain": self.base_domain,
            "blacklist_domains": sorted(self.blacklist_domains),
            "verbs": sorted(self._verbs),
            "suffix_detail_like": sorted(self._suffix_detail_like),
            "stop_tokens": sorted(self._stop_tokens),
            "synonyms": dict(self._synonyms),
            "path_noise_strings": sorted(self._path_noise_strings),
            "path_noise_patterns": [
                (pattern.pattern, bool(pattern.flags & re.IGNORECASE))
                for pattern in self._path_noise_patterns
            ],
            "module_prefixes": list(self._module_prefixes),
            "path_static_exts": list(self._path_static_exts),
            "mime_prefixes": list(self._mime_prefixes),
            "timezone_prefixes": sorted(self._timezone_prefixes),
            "path_keep_keywords": sorted(self._path_keep_keywords),
            "finder_scan_window_chars": self._finder_scan_window_chars,
            "finder_scan_max_windows": self._finder_scan_max_windows,
            "finder_scan_overlap_chars": self._finder_scan_overlap_chars,
            "finder_scan_hard_skip_chars": self._finder_scan_hard_skip_chars,
        }


    def load_regex_patterns(self):
        """加载正则表达式模式"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'config.json')
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                return config.get('regex_patterns', {})
        except Exception as e:
            self.log.error(f"加载配置文件失败: {e}")

        return {
            # === 云服务 AccessKey ===
            'Oss云存储桶': r"(?i)(?:access[-_]?key[-_]?(?:id|secret)?|secret[-_]?(?:access)?[-_]?key)\s*[:=]\s*['\"]?([0-9a-zA-Z\-_=]{6,128})['\"]?",
            "aliyun_oss_url": r"(?<![a-zA-Z0-9-])[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.oss[-\w]*\.aliyuncs\.com(?![a-zA-Z0-9-])",
            'Aliyun_AccessKeyId': r'(?<![A-Za-z0-9_])LTAI[A-Za-z\d]{12,30}',
            'Tencent_SecretId': r'AKID[A-Za-z\d]{13,40}',
            'JDCloud_AccessKey': r'JDC_[0-9A-Z]{25,40}',
            'AWS_AccessKeyId': r'["\']?(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}["\']?',
            'Aliyun_TemporaryKey_1': r'(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}',
            'Aliyun_TemporaryKey_2': r'AKLT[a-zA-Z0-9-_]{16,28}',
            'Google_API_Key': r'AIza[0-9A-Za-z_\-]{35}',
            'Huawei_Cloud_AK': r'(?<![a-zA-Z0-9])AK[a-zA-Z0-9]{10,40}(?![a-zA-Z0-9])',
            'Tencent_COS_URL': r'(?<![a-zA-Z0-9-])[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.cos\.[a-z0-9-]+\.myqcloud\.com(?![a-zA-Z0-9-])',

            # === 大模型与现代 AI 平台 API Key ===
            'OpenAI_API_Key': r'\b(?:sk-[a-zA-Z0-9]{32,64}|sk-proj-[a-zA-Z0-9_\-]{40,160})\b',
            'Claude_API_Key': r'\bsk-ant-[a-zA-Z0-9_\-]{32,120}\b',
            'DeepSeek_API_Key': r'\bsk-[0-9a-f]{32}\b',

            # === Token/JWT ===
            'json_web_token': r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}',
            'HTTP_Bearer_Token': r'[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}',
            'HTTP_Basic_Auth_Header': r'[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}',
            'HTTP_Authorization_Header': r'["\'\[]*[Aa]uthorization["\'\]]*\s*[:=]\s*[\'"]?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}[\'"]?',
            'Slack_Token': r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
            'Google_OAuth2_Token': r'\bya29\.[a-zA-Z0-9_-]{30,}\b',
            'Facebook_Access_Token': r'EAACEdEose0cBA[A-Za-z0-9]+',

            # === Git/代码托管平台 ===
            'GitLab_PAT': r'glpat-[a-zA-Z0-9\-=_]{20,22}',
            'Github_PAT_New': r'(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}',
            "Github_Token": r"(?i)github[-_]?token\s*[:=]\s*['\"]?(gh[psuro]_[0-9a-zA-Z]{36,})['\"]?",

            # === 第三方服务 ===
            'Basic Auth Credentials': r'(?<=://)[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}',
            'Cloudinary Basic Auth': r'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+',
            "LinkedIn Secret Key": r"(?i)linkedin[-_]?secret\s*[:=]\s*['\"][0-9a-zA-Z]{16}['\"]",
            'Mailchamp API Key': r'(?i)[0-9a-f]{32}-us\d{1,2}',
            'Mailgun API Key': r'(?i)key-[0-9a-zA-Z]{32}',
            'APID_Token': r'APID[a-zA-Z0-9]{32,42}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',
            'Stripe API Key': r'(?i)[rs]k_(?:live|test)_[0-9a-zA-Z]{24,}',
            'Algolia_Admin_Key': r'(?i)algolia.{0,32}([a-z0-9]{32})\b',
            'Cloudflare_API_Token': r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b',
            'Cloudflare_Service_Key': r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b',
            'Facebook_App_ID': r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b',
            'Facebook_Secret': r'(?i)(?:facebook|fb).{0,32}(?:api|app|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b',
            'Segment_API_Token': r'\bsgp_[A-Z0-9_-]{60,70}\b',

            # === 国内平台 ===
            'WeChat_AppID': r'["\'](wx[a-z0-9]{15,18})["\']',
            'WeCom_CorpID': r'["\'](ww[a-z0-9]{15,18})["\']',
            'WeChat_gh_ID': r'["\'](gh_[a-z0-9]{11,13})["\']',
            'Webhook_QY_Weixin': r'https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}',
            'Webhook_DingTalk': r'https://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}',
            'Webhook_Feishu': r'https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}',
            'AppSecret_AppKey': r'(?i)(?:app[-_]?(?:secret|key|id))\s*[:=]\s*[\'"]?[a-zA-Z0-9\-_]{8,}[\'"]?',
            'WeCom_Credential': r'(?i)(?:corp[-_]?(?:id|secret)|corpsecret)\s*[:=]\s*[\'"]?[a-zA-Z0-9\-_]{8,}[\'"]?',
            'Feishu_Credential': r'(?i)(?:app[-_]?(?:id|secret))\s*[:=]\s*[\'"]?cli_[a-zA-Z0-9\-_]{10,}[\'"]?',

            # === 个人敏感信息 ===
            "国内手机号码": r'(?<![0-9a-zA-Z_])((?:(?:\+|00)?86[-\s]?)?1[3-9]\d{9})(?![0-9a-zA-Z_])',
            "身份证号码": r'(?<!\d)(?!0{6,}|1{6,})([1-6]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)',
            'Email_Address': r"(?i)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.(?!js\b|css\b|jpg\b|jpeg\b|png\b|ico\b|svg\b|gif\b|woff\b|ttf\b|map\b)[a-zA-Z]{2,6}\b",
            'Internal_IP': r"(?<![0-9.])(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?![0-9.])",

            # === 敏感配置/凭证 ===
            '敏感配置信息': r"(?i)(?:^|[^\w])(?:appkey|secret|token|auth|access|admin|api_key|secret_key|private_key|encryption_key|signing_key|master_key|client_secret|api_secret|db_password|db_host|db_user|VideoWebPlugin|playMode|snapDir|SnapDir|videoDir)[\w]{0,10}\s*[:=]\s*(?:[^,\}\s;]+|['\"].*?['\"])",
            "Password": r"(?i)[\w.'\"]*(?:[Pp](?:ass|wd|asswd|assword)|initPassw(?:or)?d|defaultPassw(?:or)?d|newP(?:ass|ws|wd)|mail[-_.]?(?:pass(?:word)?|pwd)|smtp[-_.]?(?:pass(?:word)?|pwd)|ftp[-_.]?(?:pass(?:word)?|pwd)|email[-_.]?(?:host[-_.]?)?(?:pass(?:word)?|pwd|passwd)|初始密码|默认密码)[\w'\"]*\s*[:=]\s*(?:['\"](?!null\b|undefined\b|true\b|false\b|\s*['\"])([^'\"]{1,200})['\"]|(?!null\b|undefined\b|true\b|false\b|\s)([^\s,;'\"}{)\]]{3,80}))",
            "Username/Account": r"(?i)['\"]?[\w.]*(?:user[-_]?(?:name|id)?|account[-_]?(?:name|id)?|login[-_]?(?:name|id)?|admin[-_]?(?:name|id)?|mail[-_.]?(?:user(?:name)?)|smtp[-_.]?(?:user(?:name)?)|ftp[-_.]?(?:user(?:name)?)|email[-_.]?(?:host[-_.]?)?user(?:name)?|SSO[-_.]?user(?:name)?|created?[-_]?(?:by|r|on|at)|updated?[-_]?(?:by|r|on|at)|creator|operator)[\w]*['\"]?\s*[:=]\s*(?:['\"]([^'\"]+)['\"]|([^\s,;'\"}{)\]]{2,80}))",

            # === 数据库连接 ===
            'JDBC_Connection': r'jdbc:[a-z:]+(?://|@//)[a-zA-Z0-9.\-_:;=/@?,&]+',
            'MongoDB_URI': r'mongodb(?:\+srv)?://[^\s"\'<>]+',
            'Redis_URI': r'redis://[a-zA-Z0-9.\-_:;=/@?,&%]+',
            'MySQL_URI': (
                r'my'
                r'sql://[a-zA-Z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-zA-Z0-9.\-]+)(?::\d{2,5})?(?:/[^\s"\'?:]+)?(?:\?[^\s"\']*)?'
            ),
            'PostgreSQL_URI': r'postgres(?:ql)?://[^\s"\'<>]+',

            # === 私钥/证书 ===
            'Private_Key': r'-----BEGIN\s+(?:RSA\s+|EC\s+)?PRIVATE\s+KEY-----',
            'Certificate': r'-----BEGIN\s+CERTIFICATE-----',

            # === 安全组件/端点识别 ===
            'Java_Deserialization': r'javax\.faces\.ViewState',
            'Upload_Form': r'type\s*=\s*[\'"]file[\'"]',
            'GraphQL_Endpoint': r'(?:/graphi?ql\b|__graphiql)',
            'Swagger_UI': r'(?i)(?:swagger-ui\.html|swagger-resources|/api-docs|/v[23]/api-docs|swaggerVersion)',
            'Spring_Actuator': r'(?i)(?:/actuator(?:/[a-z]+)?|/mappings\b|/env(?:/[a-z]+)?|/heapdump\b|/jolokia\b)',
            'Shiro_Key': r'(?:rememberMe=|=deleteMe)',
            'Druid_Console': r'(?i)Druid\s+Stat\s+Index',
            'Ueditor': r'ueditor\.(?:config|all)\.js',

            # === 网络/协议 ===
            'SSH_URI': r'ssh://[a-zA-Z0-9.\-_:@/]+',
            'OSS_URI': r'(?<![a-zA-Z])oss://[a-zA-Z0-9.\-_/]+',
            'MAC_Address': r'(?<![a-fA-F0-9:])(?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}(?![a-fA-F0-9:])',
            'Windows_Path': r'(?<![\\w])[a-zA-Z]:\\\\(?:\w+\\\\){1,}(?:\w+\.\w+)?',

            # === 云存储URL ===
            'AWS_S3_URL': r'https?://[a-zA-Z0-9.\-]+\.s3[a-zA-Z0-9.\-]*\.amazonaws\.com[^\s"\'<>]*',
            'Azure_Blob_URL': r'https?://[a-zA-Z0-9.\-]+\.blob\.core\.windows\.net[^\s"\'<>]*',
            'GCS_URL': r'https?://storage\.googleapis\.com/[^\s"\'<>]+',

            # === 敏感文件引用 ===
            'Sensitive_File_Ref': r'["\'][a-zA-Z0-9_/.\-]+\.(?:sql|csv|env|bak|backup|old|orig|key|pem|crt|cer|p12|pfx|conf|config|cfg|ini|log|sh|bat|ps1|py|rb|pl|dump|sqlite|db)["\']',
        }

    @staticmethod
    def _verify_id_card_checksum(id_number: str) -> bool:
        """验证18位身份证号码最后一位校验码"""
        if len(id_number) != 18:
            return False
        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_chars = '10X98765432'
        try:
            total = sum(int(id_number[i]) * weights[i] for i in range(17))
            expected = check_chars[total % 11]
            return id_number[17].upper() == expected
        except (ValueError, IndexError):
            return False

    @staticmethod
    def _build_line_starts(text: str) -> List[int]:
        starts = [0]
        for idx, ch in enumerate(text):
            if ch == '\n':
                starts.append(idx + 1)
        return starts

    @staticmethod
    def _line_number_by_offset(line_starts: List[int], offset: int) -> int:
        if not line_starts:
            return 1
        return max(1, bisect_right(line_starts, max(0, int(offset))))

    @staticmethod
    def _build_content_scan_segments(
        content: str,
        window_chars: int = 360000,
        max_windows: int = 3,
        overlap_chars: int = 12000,
        hard_skip_chars: int = 5000000,
    ) -> List[Tuple[int, str]]:
        """
        为超大文本构建“全覆盖”扫描分段。

        旧逻辑在超大文件上只抽样首尾/少量窗口，容易漏掉中段敏感信息。
        这里改为完整覆盖全文，同时在超大文件上自适应放大窗口，
        以控制分段数量，兼顾完整性与性能。

        返回 [(start_offset, segment_text), ...]。
        """
        text = content or ""
        text_len = len(text)
        if text_len == 0:
            return [(0, "")]

        window = max(120000, int(window_chars or 360000))
        windows = max(2, min(int(max_windows or 3), 8))
        overlap = max(0, min(int(overlap_chars or 12000), window // 2))
        hard_skip = max(window * 2, int(hard_skip_chars or 5000000))

        if text_len <= window * windows:
            return [(0, text)]

        if text_len > hard_skip:
            target_segments = 24
            adaptive_window = (text_len + target_segments - 1) // target_segments
            max_window = max(window, min(2400000, window * 6))
            window = min(max_window, max(window, adaptive_window + overlap))
            overlap = max(0, min(overlap, window // 3))

        step = max(1, window - overlap)
        segments: List[Tuple[int, str]] = []
        start = 0
        while start < text_len:
            end = min(text_len, start + window)
            if end <= start:
                break
            segments.append((start, text[start:end]))
            if end >= text_len:
                break
            next_start = start + step
            if next_start <= start:
                next_start = end
            start = next_start

        return segments or [(0, text)]

    @staticmethod
    def _build_path_patterns() -> List[re.Pattern]:
        """构建并预编译路径提取正则，避免每文件重复 compile。"""
        return [
            re.compile(r'''["'`]((?:(?:https?|wss?|ftp):)?//[^\s"'`<>]{6,})["'`]'''),
            re.compile(r'''["'`]((?:/|\.\./|\./)[^"'`<>|*()\[\]\\]{2,})["'`]'''),
            re.compile(r'''(?i)(?:src|href|url|api|endpoint|baseUrl|baseURL|apiUrl|apiURL|requestUrl|serverUrl|action|formaction|data-(?:src|href|url))\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''(?i)(?:path|route|uri|URI|pathname)\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''(?:fetch|request|useFetch|useSWR|useQuery|axios\.(?:get|post|put|delete|patch|request)|(?:\$?(?:http|axios|api|service))\.(?:get|post|put|delete|patch|request)|\.ajax)\s*\(\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''window\.location\.(?:href|pathname)\s*=\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''["'`]([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?#][^"'`]{0,})?)["'`]'''),
            re.compile(r'''["'`]([a-zA-Z0-9_\-/.]{1,}/[a-zA-Z0-9_\-/.]{3,}(?:[\?#][^"'`]{0,})?)["'`]'''),
            re.compile(r'''(?i)\b\w+(?:_?url|_?api|_?path|_?endpoint|_?uri)\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''["'`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+((?:/|https?://)[^\s"'`]+)["'`]'''),
            re.compile(r'''(?i)\b\w*(?:url|api|path|endpoint|uri|base|host|server|prefix|root)\w*\s*\+\s*["'`]([a-zA-Z0-9_\-/.]+)["'`]'''),
            re.compile(r'''["'`]((?:/|\.\./|\./)[^"'`|*\\]{2,})["'`]'''),
            re.compile(r'''(?i)\\"(?:src|href|url|api|endpoint|baseUrl|baseURL|apiUrl|apiURL|requestUrl|serverUrl)\\"\s*[:=]\s*\\"([^"\\]+)\\"'''),
            re.compile(r'''(?i)\\"(?:path|route|uri|URI|pathname)\\"\s*[:=]\s*\\"([^"\\]+)\\"'''),
            re.compile(r'''\\"((?:https?:)?//[^"\\\s<>]{6,})\\"'''),
            re.compile(r'''\\"((?:/|\.\./|\./)(?:\\/|[^"\\<>|*()\[\]]){2,})\\"'''),
        ]

    @staticmethod
    def _build_route_patterns() -> List[re.Pattern]:
        """构建并预编译 SourceMap 路由提取正则。"""
        return [
            re.compile(r'''(?i)(?:^|[\s,{])path\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''(?i)(?:^|[\s,{])redirect\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''(?i)(?:^|[\s,{])alias\s*[:=]\s*["'`]([^"'`]+)["'`]'''),
            re.compile(r'''\\"path\\"\s*:\s*\\"([^"\\]+)\\"'''),
            re.compile(r'''\\"redirect\\"\s*:\s*\\"([^"\\]+)\\"'''),
            re.compile(r'''\\"alias\\"\s*:\s*\\"([^"\\]+)\\"'''),
        ]

    def _build_pattern_scan_hints(self) -> Dict[str, Tuple[str, ...]]:
        """
        为确定性较强的模式提供快速提示词，减少无意义正则遍历。
        未命中的模式不做过滤，确保召回不降。
        """
        base_hints: Dict[str, Tuple[str, ...]] = {
            'Aliyun_AccessKeyId': ('ltai',),
            'Tencent_SecretId': ('akid',),
            'JDCloud_AccessKey': ('jdc_',),
            'AWS_AccessKeyId': ('akia', 'agpa', 'aida', 'aroa', 'aipa', 'anpa', 'anva', 'asia'),
            'Aliyun_TemporaryKey_1': ('aklt', 'aktp'),
            'Aliyun_TemporaryKey_2': ('aklt',),
            'Google_API_Key': ('aiza',),
            'json_web_token': ('eyj',),
            'HTTP_Bearer_Token': ('bearer',),
            'HTTP_Basic_Auth_Header': ('basic ',),
            'Github_PAT_New': ('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'),
            'JDBC_Connection': ('jdbc:',),
            'MongoDB_URI': ('mongodb://', 'mongodb+srv://'),
            'Redis_URI': ('redis://',),
            'MySQL_URI': ('mysql://',),
            'PostgreSQL_URI': ('postgres://', 'postgresql://'),
            'Private_Key': ('-----begin', 'private key-----'),
            'Certificate': ('-----begin', 'certificate-----'),
            'AWS_S3_URL': ('.amazonaws.com', '.s3'),
            'Azure_Blob_URL': ('.blob.core.windows.net',),
            'GCS_URL': ('storage.googleapis.com',),
            'Webhook_QY_Weixin': ('qyapi.weixin.qq.com',),
            'Webhook_DingTalk': ('oapi.dingtalk.com/robot/send',),
            'Webhook_Feishu': ('open.feishu.cn/open-apis/bot/v2/hook',),
            'Password': ('password', 'passwd', 'pwd', 'pass', '默认密码', '初始密码'),
            'Username/Account': ('user', 'username', 'userid', 'account', 'login', 'admin', 'operator', 'creator', 'created', 'updated'),
            '敏感配置信息': ('appkey', 'secret', 'token', 'auth', 'access', 'api_key', 'secret_key', 'private_key', 'client_secret', 'db_password'),
            'Internal_IP': ('127.0.0.1', '192.168.', '10.', '172.'),
            'HTTP_Authorization_Header': ('authorization',),
            'Github_Token': ('github', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'),
            'AppSecret_AppKey': ('appsecret', 'appkey', 'appid'),
            'WeCom_Credential': ('corpsecret', 'corpid',),
            'Feishu_Credential': ('cli_', 'appsecret', 'appid'),
        }
        hints: Dict[str, Tuple[str, ...]] = {}
        for pattern_name in self.regex_patterns.keys():
            tokens = base_hints.get(pattern_name)
            if tokens:
                hints[pattern_name] = tuple(t.lower() for t in tokens if t)
        return hints

    @staticmethod
    def _filter_gateable_hint_tokens(tokens: Tuple[str, ...]) -> Tuple[str, ...]:
        """
        仅保留“高置信、低歧义”的自动推断 hint。
        目标是提速而不牺牲召回，因此自动推断的纯字母语义词（如 password、corpsecret、facebook）
        一律不用于 gating，避免把宽规则误收窄成窄规则。
        """
        safe = []
        for token in tokens or ():
            text = str(token or '').strip().lower()
            if not text:
                continue
            if len(text) >= 6 and ('.' in text or '_' in text or '-' in text or ':' in text or text.startswith('-----')):
                safe.append(text)
                continue
        return tuple(dict.fromkeys(safe))

    @staticmethod
    def _infer_hint_tokens_from_pattern(pattern: str, limit: int = 4) -> Tuple[str, ...]:
        """保守地从 regex 中提取稳定字面量；提取失败时返回空，避免误杀召回。"""
        try:
            raw_candidates = re.findall(r'[A-Za-z0-9][A-Za-z0-9._:/-]{3,}', pattern or '')
            tokens: List[str] = []
            seen = set()
            bad_fragments = ('a-z', 'A-Z', '0-9', '\\d', '(?:', '(?=', '(?!', '(?<=', '(?<!')
            for item in raw_candidates:
                token = str(item or '').strip().lower()
                if not token or token in seen:
                    continue
                if any(fragment in token for fragment in bad_fragments):
                    continue
                if token.endswith(('.js', '.css', '.png', '.jpg')) and '/' not in token and '.' not in token[:-3]:
                    continue
                if token in {'http', 'https', 'true', 'false', 'null', 'undefined', 'token', 'secret', 'password'}:
                    continue
                seen.add(token)
                tokens.append(token)
                if len(tokens) >= limit:
                    break
            return tuple(tokens)
        except Exception:
            return ()

    @staticmethod
    def _categorize_rule(pattern_name: str, pattern: str, verifier_name: str, hint_tokens: Tuple[str, ...]) -> str:
        if verifier_name:
            return 'post-validated'
        if hint_tokens:
            return 'token-gated'
        if len(pattern or '') > 180 or '.{0,' in (pattern or '') or '(?<' in (pattern or ''):
            return 'expensive-regex'
        return 'literal-heavy'

    @staticmethod
    def _get_verifier_name(pattern_name: str) -> str:
        mapping = {
            '身份证号码': 'verify_id_card',
            'Aliyun_AccessKeyId': 'verify_aliyun_ak',
        }
        return mapping.get(pattern_name, '')

    def _build_rule_specs(self) -> List[RuleSpec]:
        rule_specs: List[RuleSpec] = []
        for pattern_name, pattern in self.regex_patterns.items():
            explicit_hints = tuple(tok.lower() for tok in self._pattern_scan_hints.get(pattern_name, ()))
            inferred_hints = self._infer_hint_tokens_from_pattern(pattern)
            hint_tokens = explicit_hints or self._filter_gateable_hint_tokens(inferred_hints)
            verifier_name = self._get_verifier_name(pattern_name)
            category = self._categorize_rule(pattern_name, pattern, verifier_name, hint_tokens)
            rule_specs.append(
                RuleSpec(
                    name=pattern_name,
                    pattern=pattern,
                    flags=re.MULTILINE | re.DOTALL,
                    hint_tokens=hint_tokens,
                    category=category,
                    verifier_name=verifier_name,
                )
            )
        return rule_specs

    def _run_rule_verifier(self, rule: RuleSpec, match: re.Match, matched_text: str) -> Optional[str]:
        verifier_name = rule.verifier_name or ''
        if verifier_name == 'verify_id_card':
            id_num = match.group(1) if match.lastindex else matched_text
            id_num = id_num.strip()
            if not self._verify_id_card_checksum(id_num):
                return None
            return matched_text
        if verifier_name == 'verify_aliyun_ak':
            ak_body = matched_text[4:]
            if len(ak_body) < 12 or len(ak_body) > 20:
                return None
            return matched_text
        return matched_text

    def _normalize_rule_match(
        self,
        rule: RuleSpec,
        match: re.Match,
        filename: str,
        content: str,
        seg_offset: int,
        line_starts: Optional[List[int]],
    ) -> Optional[Tuple[str, str, str]]:
        try:
            matched_text = match.group(0)
            verified_text = self._run_rule_verifier(rule, match, matched_text)
            if verified_text is None:
                return None
            start_pos = int(seg_offset) + match.start()
            if line_starts is None:
                return None
            line_num = self._line_number_by_offset(line_starts, start_pos)
            context_start = max(0, start_pos - 300)
            context_end = min(len(content), start_pos + len(matched_text) + 300)
            context = content[context_start:context_end].strip()
            context = context.replace('\n', ' ').replace('\r', ' ')
            return (
                verified_text,
                f"{filename}:Line {line_num}",
                context,
            )
        except Exception:
            return None

    def find_matches_legacy(
        self,
        content: str,
        filename: str,
        scan_segments: Optional[List[Tuple[int, str]]] = None,
    ) -> Dict[str, List[Tuple[str, str, str]]]:
        matches = {}
        segments = scan_segments or [(0, content)]
        prepared_segments = [
            (int(seg_offset or 0), seg_text or "", (seg_text or "").lower())
            for seg_offset, seg_text in segments
        ]
        line_starts: Optional[List[int]] = None

        for pattern_name, compiled_pattern in self.compiled_regex_patterns.items():
            pattern_matches = set()
            hint_tokens = self._pattern_scan_hints.get(pattern_name)
            rule = next((item for item in self._rule_specs if item.name == pattern_name), None)
            try:
                for seg_offset, seg_text, seg_text_lower in prepared_segments:
                    if not seg_text:
                        continue
                    if hint_tokens and not any(tok in seg_text_lower for tok in hint_tokens):
                        continue
                    for match in compiled_pattern.finditer(seg_text):
                        if line_starts is None:
                            line_starts = self._build_line_starts(content)
                        normalized = self._normalize_rule_match(rule, match, filename, content, seg_offset, line_starts) if rule else None
                        if normalized is None:
                            continue
                        pattern_matches.add(normalized)
            except re.error as e:
                self.log.error(f"正则表达式 '{pattern_name}' 无效: {e}")
                continue

            if pattern_matches:
                matches[pattern_name] = list(pattern_matches)

        return matches

    def _find_matches_with_stats(
        self,
        content: str,
        filename: str,
        scan_segments: Optional[List[Tuple[int, str]]] = None,
    ) -> Tuple[Dict[str, List[Tuple[str, str, str]]], Dict[str, int]]:
        matches, stats = self._match_engine.scan(content, filename, scan_segments=scan_segments)
        return matches, stats

    def find_matches(
        self,
        content: str,
        filename: str,
        scan_segments: Optional[List[Tuple[int, str]]] = None,
    ) -> Dict[str, List[Tuple[str, str, str]]]:
        """在JavaScript内容中查找匹配的敏感信息"""
        matches, stats = self._find_matches_with_stats(content, filename, scan_segments=scan_segments)
        self._perf_stats.setdefault('match_runs', 0)
        self._perf_stats['match_runs'] = int(self._perf_stats.get('match_runs', 0)) + 1
        for key, value in stats.items():
            self._perf_stats[key] = int(self._perf_stats.get(key, 0)) + int(value)
        self._perf_stats['prefilter_backend'] = self._match_engine.prefilter.backend
        return matches

    @staticmethod
    def _build_path_context(content: str, start_pos: int, match_len: int, radius: int = 220) -> str:
        try:
            start = max(0, int(start_pos or 0) - int(radius or 220))
            end = min(len(content or ''), int(start_pos or 0) + int(match_len or 0) + int(radius or 220))
            snippet = (content or '')[start:end].strip()
            return snippet.replace('\n', ' ').replace('\r', ' ')
        except Exception:
            return ''

    @staticmethod
    def _line_value_from_source(source: str) -> int:
        try:
            if ':Line ' not in str(source or ''):
                return 0
            return int(str(source).rsplit(':Line ', 1)[1])
        except Exception:
            return 0

    def extract_paths(
        self,
        content: str,
        filename: str,
        scan_segments: Optional[List[Tuple[int, str]]] = None,
    ) -> Tuple[List[str], List[str], List[Dict[str, object]]]:
        """从JavaScript内容中提取路径，并保留可视化上下文证据。"""
        paths = set()
        mapping_set = set()
        path_to_file_mapping = []
        path_findings: List[Dict[str, object]] = []
        findings_seen = set()
        findings_count: Dict[str, int] = defaultdict(int)
        max_findings_per_path = 20
        segments = scan_segments or [(0, content)]
        line_starts: Optional[List[int]] = None

        for pattern in self._compiled_path_patterns:
            for seg_offset, seg_text in segments:
                if not seg_text:
                    continue
                for match in pattern.finditer(seg_text):
                    candidate = self._extract_match_value(match)
                    path = self._normalize_path_candidate(candidate)
                    if not self._is_acceptable_path(path):
                        continue
                    paths.add(path)
                    mapping = f"{filename}----{path}"
                    if mapping not in mapping_set:
                        mapping_set.add(mapping)
                        path_to_file_mapping.append(mapping)

                    if findings_count.get(path, 0) >= max_findings_per_path:
                        continue
                    absolute_pos = int(seg_offset or 0) + match.start()
                    if line_starts is None:
                        line_starts = self._build_line_starts(content)
                    line_num = self._line_number_by_offset(line_starts, absolute_pos)
                    source = f"{filename}:Line {line_num}"
                    context = self._build_path_context(content, absolute_pos, len(match.group(0) or path))
                    finding_key = (path, source, context, 'JS')
                    if finding_key in findings_seen:
                        continue
                    findings_seen.add(finding_key)
                    findings_count[path] = findings_count.get(path, 0) + 1
                    path_findings.append({
                        'path': path,
                        'source': source,
                        'context': context,
                        'source_kind': 'JS',
                        'filename': filename,
                        'line': line_num,
                    })

        return sorted(paths), path_to_file_mapping, path_findings

    def _extract_match_value(self, match: re.Match) -> str:
        """优先取捕获组，避免把 'url:' / 'path=' 前缀误当作路径内容。"""
        try:
            if match.lastindex:
                for i in range(1, match.lastindex + 1):
                    value = match.group(i)
                    if value:
                        return value
            return match.group(0) or ""
        except Exception:
            return ""

    def _normalize_path_candidate(self, raw: str) -> str:
        """对提取值做轻量标准化，提升匹配与去重稳定性。"""
        try:
            path = (raw or "").strip()
            if not path:
                return ""

            # 去掉首尾包裹符，保留中间内容
            path = path.strip(" \t\r\n'\"`")

            # 常见 JS 转义
            path = path.replace("\\/", "/")

            # 去掉结尾拼接残片与分隔符
            path = re.sub(r'[),;]+$', '', path)

            # 模板字符串插值剥离：${xxx} → 空，然后合并连续斜杠
            path = re.sub(r'\$\{[^}]*\}', '', path)
            path = re.sub(r'/{2,}', '/', path)

            # 路径参数占位符标准化：{userId} → :userId, [id] → :id, <int:id> → :id
            path = re.sub(r'\{(\w+)\}', r':\1', path)
            path = re.sub(r'\[(\w+)\]', r':\1', path)
            path = re.sub(r'<(?:\w+:)?(\w+)>', r':\1', path)

            path = path.strip()
            return path
        except Exception:
            return ""

    def _has_keep_keyword(self, text: str) -> bool:
        lower = (text or "").lower()
        return any(k in lower for k in self._path_keep_keywords)

    def _is_acceptable_path(self, path: str) -> bool:
        """接口路径过滤：兼顾召回与降噪。"""
        try:
            if not path or len(path) < 2:
                return False

            if path in self._path_noise_strings:
                return False

            for pattern in self._path_noise_patterns:
                if pattern.search(path):
                    return False

            lower = path.lower()
            if lower.startswith(self._mime_prefixes):
                return False

            # 过滤常见时区噪声（如 Africa/Cairo）
            parts = [p for p in path.split('/') if p]
            if len(parts) == 2 and parts[0].lower() in self._timezone_prefixes and parts[1][:1].isupper():
                return False

            # 过滤模块导入路径（保留明显接口关键词）
            if path.startswith(self._module_prefixes) and not self._has_keep_keyword(path):
                return False

            # 绝对URL/协议相对URL的域名与资源过滤
            if path.startswith(('http://', 'https://', '//')):
                parse_target = path if not path.startswith('//') else 'https:' + path
                parsed = urlparse(parse_target)
                host_no_port = (parsed.netloc or '').lower().split(':')[0]
                route = (parsed.path or '').lower()

                if not host_no_port:
                    return False
                if host_no_port in self.blacklist_domains:
                    return False
                if not self.is_first_party_host(host_no_port):
                    return False
                if route.endswith(self._path_static_exts):
                    return False
                if route in ('', '/'):
                    return False
                return True

            # 非绝对URL：需要形如 /x 或 a/b
            if not (path.startswith('/') or '/' in path):
                return False

            # 过滤静态资源后缀
            pure = path.split('?', 1)[0].split('#', 1)[0].lower()
            if pure.endswith(self._path_static_exts):
                return False

            # 对裸相对路径进行额外门槛，避免纳入大量语言包/模板路径
            if (not path.startswith('/')) and (not self._has_keep_keyword(path)):
                segs = [s for s in path.split('/') if s]
                if len(segs) < 2:
                    return False
                # 比如 a/b 这种过短路径噪声较高
                if len(segs[0]) <= 1 and len(segs[1]) <= 2:
                    return False

            return True
        except Exception:
            return False

    def load_blacklist_domains(self) -> Set[str]:
        domains: Set[str] = set()
        try:
            from configparser import ConfigParser
            cfg = ConfigParser()
            cfg.read(os.path.join(os.getcwd(), 'config.ini'), encoding='utf-8')
            if cfg.has_section('blacklist') and cfg.has_option('blacklist', 'domain'):
                raw = cfg.get('blacklist', 'domain')
                for item in raw.split(','):
                    d = item.strip().lower()
                    if d:
                        domains.add(d)
        except Exception:
            pass
        return domains

    def is_first_party_host(self, host_no_port: str) -> bool:
        if not host_no_port:
            return False
        if self.target_host_no_port and host_no_port == self.target_host_no_port:
            return True
        if self.base_domain and (host_no_port == self.base_domain or host_no_port.endswith('.' + self.base_domain)):
            return True
        return False

    def _looks_like_router_source(self, content: str, filename: str) -> bool:
        """判断源码是否像路由配置文件，避免在普通源码中误提取 route/path 字段。"""
        try:
            text = content or ""
            name = (filename or "").lower()
            name_hints = ('router', 'routes', 'route', 'layout', 'menu')
            if any(h in name for h in name_hints):
                return True

            router_hints = [
                r'\bcreateRouter\s*\(',
                r'\bnew\s+Router\s*\(',
                r'\brouter\.addRoute\s*\(',
                r'\bcreateBrowserRouter\s*\(',
                r'\bcreateHashRouter\s*\(',
                r'\buseRoutes\s*\(',
                r'\bRouteRecordRaw\b',
                r'\broutes\s*[:=]\s*\[',
                r'\bmeta\s*:',
                r'\bchildren\s*:',
            ]
            return any(re.search(p, text) for p in router_hints)
        except Exception:
            return False

    def _normalize_route_candidate(self, raw: str) -> str:
        """标准化路由字符串，尽量转为可用路径。"""
        try:
            route = self._normalize_path_candidate(raw)
            if not route:
                return ""

            # 忽略模板变量与明显非路径值
            if '${' in route or route in ('*', '**', '/*', '(.*)', ':pathMatch(.*)*'):
                return ""

            # 兼容 Vue Router 通配参数形式: /:pathMatch(.*)* -> /:pathMatch
            route = re.sub(r':([A-Za-z_][\w]*)\([^)]*\)\*?', r':\1', route)

            if route.startswith(('http://', 'https://', '//')):
                parsed = urlparse(route if not route.startswith('//') else ('https:' + route))
                route = parsed.path or ""
                if parsed.query:
                    route = route + '?' + parsed.query
                if parsed.fragment:
                    route = route + '#' + parsed.fragment

            # 子路由常见写法是 "users/list"，统一补成 "/users/list"
            if route and not route.startswith('/'):
                if route.startswith(('./', '../')):
                    return ""
                route = '/' + route.lstrip('/')

            return route.strip()
        except Exception:
            return ""

    def extract_sourcemap_routes(self, content: str, filename: str) -> Tuple[List[str], List[str], List[Dict[str, object]]]:
        """
        从 SourceMap 还原源码中提取路由路径，并并入 paths.html。
        返回 (route_paths, route_mappings, route_findings)。
        """
        route_paths = set()
        route_mappings = []
        route_findings: List[Dict[str, object]] = []
        route_seen = set()
        route_count: Dict[str, int] = defaultdict(int)
        max_findings_per_path = 20

        try:
            if not self._looks_like_router_source(content, filename):
                return [], [], []

            line_starts = self._build_line_starts(content)
            for pattern in self._compiled_route_patterns:
                for match in pattern.finditer(content):
                    candidate = self._extract_match_value(match)
                    route = self._normalize_route_candidate(candidate)
                    if not route:
                        continue
                    if not self._is_acceptable_path(route):
                        continue
                    route_paths.add(route)
                    route_mappings.append(f"{filename}----[SM_ROUTE]{route}")
                    if route_count.get(route, 0) >= max_findings_per_path:
                        continue
                    line_num = self._line_number_by_offset(line_starts, match.start())
                    source = f"{filename}:Line {line_num}"
                    context = self._build_path_context(content, match.start(), len(match.group(0) or route))
                    finding_key = (route, source, context, 'SM_ROUTE')
                    if finding_key in route_seen:
                        continue
                    route_seen.add(finding_key)
                    route_count[route] = route_count.get(route, 0) + 1
                    route_findings.append({
                        'path': route,
                        'source': source,
                        'context': context,
                        'source_kind': 'SM_ROUTE',
                        'filename': filename,
                        'line': line_num,
                    })
        except Exception:
            return [], [], []

        return sorted(route_paths), route_mappings, route_findings

    @staticmethod
    def _is_path_under(path: str, parent: str) -> bool:
        try:
            normalized_path = os.path.normpath(path or "").replace("\\", "/")
            normalized_parent = os.path.normpath(parent or "").replace("\\", "/").rstrip("/")
            if not normalized_parent:
                return False
            return normalized_path == normalized_parent or normalized_path.startswith(normalized_parent + "/")
        except Exception:
            return False

    @staticmethod
    def _is_sourcemap_mirror_filename(filename: str) -> bool:
        try:
            return bool(re.match(r"^sm_[0-9a-f]{40}\.(?:js|mjs|cjs)$", str(filename or ""), re.IGNORECASE))
        except Exception:
            return False

    @staticmethod
    def _should_skip_sourcemap_source_file(file_path: str, sm_source_root: str) -> bool:
        """
        SourceMap 还原源码中优先跳过第三方依赖目录，减少敏感扫描耗时。
        """
        try:
            normalized_file = os.path.normpath(file_path or "").replace("\\", "/")
            normalized_root = os.path.normpath(sm_source_root or "").replace("\\", "/").rstrip("/")
            if not normalized_root:
                return False
            relative = normalized_file
            if normalized_file.startswith(normalized_root + "/"):
                relative = normalized_file[len(normalized_root) + 1:]
            lower_relative = relative.lower()
            return (
                lower_relative.startswith("node_modules/")
                or "/node_modules/" in f"/{lower_relative}/"
                or lower_relative.startswith(".pnpm/")
                or "/.pnpm/" in f"/{lower_relative}/"
            )
        except Exception:
            return False

    @staticmethod
    def _list_sourcemap_source_roots(js_files_dir: str) -> List[str]:
        sourcemap_root = os.path.join(js_files_dir, "sourcemaps")
        if not os.path.isdir(sourcemap_root):
            return []

        roots = []
        legacy_root = os.path.join(sourcemap_root, "sources")
        if os.path.isdir(legacy_root):
            roots.append(legacy_root)

        try:
            for name in os.listdir(sourcemap_root):
                full = os.path.join(sourcemap_root, name)
                if not os.path.isdir(full):
                    continue
                if name == "sources":
                    continue
                if name.lower().endswith(".map"):
                    roots.append(full)
        except Exception:
            pass

        dedup = []
        seen = set()
        for root in roots:
            normalized = os.path.normpath(root)
            if normalized in seen:
                continue
            seen.add(normalized)
            dedup.append(normalized)
        return dedup

    def _choose_processing_backend(self, file_paths: List[str]) -> Tuple[str, int]:
        try:
            cpu_total = max(1, multiprocessing.cpu_count())
            if not file_paths:
                return "thread", 1
            total_size = 0
            large_files = 0
            for path in file_paths:
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                total_size += size
                if size >= 900000:
                    large_files += 1

            if cpu_total >= 3 and (len(file_paths) >= 40 or large_files >= 8 or total_size >= 40 * 1024 * 1024):
                return "process", min(max(2, cpu_total - 1), 6)
            return "thread", min(max(2, cpu_total), 4)
        except Exception:
            return "thread", min(4, max(1, multiprocessing.cpu_count()))

    def _write_perf_stats(self, total_count: int, original_count: int, sm_count: int, start_ts: float) -> None:
        try:
            payload = dict(self._perf_stats or {})
            payload.update({
                'total_files': int(total_count or 0),
                'original_files': int(original_count or 0),
                'sourcemap_files': int(sm_count or 0),
                'elapsed_seconds': round(max(0.0, time.perf_counter() - float(start_ts or 0.0)), 6),
            })
            self._perf_stats = payload
        except Exception as e:
            self.log.debug(f"[Finder] 汇总性能统计失败: {e}")


    def _render_progress_bar(self, processed: int, total_count: int, hits: int, start_ts: float, width: int = 18) -> str:
        total = max(1, int(total_count or 0))
        done = max(0, int(processed or 0))
        ratio = min(1.0, max(0.0, done / total))
        filled = int(round(width * ratio))
        bar = '█' * filled + '░' * max(0, width - filled)
        elapsed = max(0.0, time.perf_counter() - float(start_ts or 0.0))
        rate = (done / elapsed) if elapsed > 0 else 0.0
        remaining = max(0, total - done)
        eta = (remaining / rate) if rate > 0 else 0.0
        return (
            f"[Finder] {done}/{total} | {ratio * 100:5.1f}% | {bar} | "
            f"hits {int(hits or 0)} | {elapsed:5.1f}s | ETA {eta:5.1f}s | {self._perf_stats.get('scan_backend', 'thread')}"
        )

    def _emit_progress_line(self, processed: int, total_count: int, hits: int, start_ts: float, force_newline: bool = False) -> None:
        try:
            line = self._render_progress_bar(processed, total_count, hits, start_ts)
            print('\r' + line, end='\n' if force_newline else '', flush=True)
        except Exception:
            if force_newline:
                self.log.info(f"[Finder] 扫描进度: {processed}/{total_count}")

    @staticmethod
    def _is_process_pool_broken(error: Exception) -> bool:
        if isinstance(error, BrokenProcessPool):
            return True
        msg = str(error or '').lower()
        return 'process pool was terminated abruptly' in msg or ('process pool' in msg and 'terminated abruptly' in msg)

    def _merge_file_scan_result(
        self,
        result,
        all_matches: Dict,
        all_unique_paths: Set[str],
        all_path_mappings: List[str],
        all_path_findings: List[Dict[str, object]],
    ) -> int:
        matches, unique_paths, path_mappings, route_paths, route_mappings, path_findings, perf_stats = result
        for pattern_name, pattern_matches in matches.items():
            if pattern_name not in all_matches:
                all_matches[pattern_name] = []
            all_matches[pattern_name].extend(pattern_matches)
        all_unique_paths.update(unique_paths)
        all_path_mappings.extend(path_mappings)
        all_unique_paths.update(route_paths)
        all_path_mappings.extend(route_mappings)
        all_path_findings.extend(path_findings)
        for key, value in (perf_stats or {}).items():
            self._perf_stats[key] = int(self._perf_stats.get(key, 0)) + int(value or 0)
        return len(route_paths)

    def _scan_file_batch(
        self,
        file_paths: List[str],
        sm_source_roots: Optional[List[str]],
        backend: str,
        max_workers: int,
        total_count: int,
        processed: int,
        start_ts: float,
        all_matches: Dict,
        all_unique_paths: Set[str],
        all_path_mappings: List[str],
        all_path_findings: List[Dict[str, object]],
    ) -> Tuple[int, int, List[str]]:
        executor_kwargs = {'max_workers': max_workers}
        if backend == 'process':
            executor_cls = ProcessPoolExecutor
            executor_kwargs['initializer'] = _finder_worker_init
            executor_kwargs['initargs'] = (self._build_worker_payload(),)
        else:
            executor_cls = ThreadPoolExecutor

        completed_paths: Set[str] = set()
        remaining_paths: List[str] = []
        sm_route_total = 0

        with executor_cls(**executor_kwargs) as executor:
            future_to_file = {}
            for fp in file_paths:
                if backend == 'process':
                    future = executor.submit(_finder_worker_process_js_file, fp, sm_source_roots)
                else:
                    future = executor.submit(self.process_js_file, fp, sm_source_roots)
                future_to_file[future] = fp

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                except Exception as e:
                    if backend == 'process' and self._is_process_pool_broken(e):
                        self.log.warning('[Finder] 进程池异常，剩余文件将回退到线程模式继续扫描')
                        remaining_paths = [path for path in file_paths if path not in completed_paths]
                        break
                    self.log.error(f"[Finder] 扫描失败: {os.path.basename(file_path)} -> {e}")
                    self._perf_stats['files_failed'] = int(self._perf_stats.get('files_failed', 0)) + 1
                    completed_paths.add(file_path)
                    processed += 1
                    total_hits = sum(len(items) for items in all_matches.values())
                    self._emit_progress_line(processed, total_count, total_hits, start_ts, force_newline=(processed == total_count))
                    continue

                sm_route_total += self._merge_file_scan_result(
                    result,
                    all_matches,
                    all_unique_paths,
                    all_path_mappings,
                    all_path_findings,
                )
                completed_paths.add(file_path)
                processed += 1
                total_hits = sum(len(items) for items in all_matches.values())
                self._emit_progress_line(processed, total_count, total_hits, start_ts, force_newline=(processed == total_count))

        return processed, sm_route_total, remaining_paths

    def process_js_file(self, file_path: str, sm_source_roots: Optional[List[str]] = None) -> Tuple[Dict, List, List, List, List, List[Dict[str, object]], Dict[str, int]]:
        """处理单个JavaScript文件"""
        perf_stats: Dict[str, int] = {
            'files_processed': 1,
            'match_runs': 1,
            'segments': 0,
            'rule_runs': 0,
            'rule_candidates': 0,
            'prefilter_token_checks': 0,
            'prefilter_tokens_hit': 0,
            'prefilter_rules_skipped': 0,
            'total_matches': 0,
        }
        try:
            with open(file_path, 'rb') as file:
                raw_bytes = file.read()
            content, detected_encoding = decode_bytes_robust(raw_bytes)
        except Exception as e:
            self.log.error(f"无法读取文件 {file_path}: {e}")
            perf_stats['files_failed'] = 1
            return {}, [], [], [], [], [], perf_stats

        filename = os.path.basename(file_path)
        if detected_encoding not in ('utf-8', 'utf-8-sig'):
            self.log.debug(f"[Finder] 文件编码自动识别: {filename} -> {detected_encoding}")

        scan_segments = self._build_content_scan_segments(
            content,
            window_chars=self._finder_scan_window_chars,
            max_windows=self._finder_scan_max_windows,
            overlap_chars=self._finder_scan_overlap_chars,
            hard_skip_chars=self._finder_scan_hard_skip_chars,
        )
        perf_stats['segments'] = len(scan_segments)
        matches, match_stats = self._find_matches_with_stats(content, filename, scan_segments=scan_segments)
        unique_paths, path_mappings, path_findings = self.extract_paths(content, filename, scan_segments=scan_segments)
        for key, value in (match_stats or {}).items():
            perf_stats[key] = int(value or 0)

        route_paths, route_mappings, route_findings = [], [], []
        try:
            if sm_source_roots and any(self._is_path_under(file_path, root) for root in sm_source_roots):
                route_paths, route_mappings, route_findings = self.extract_sourcemap_routes(content, filename)
        except Exception:
            route_paths, route_mappings, route_findings = [], [], []

        path_findings.extend(route_findings)
        return matches, unique_paths, path_mappings, route_paths, route_mappings, path_findings, perf_stats

    def process_js_files(self, js_files_dir: str) -> None:
        """处理目录中的所有JavaScript文件与由SourceMap还原的源码"""
        start_ts = time.perf_counter()
        if not os.path.exists(js_files_dir):
            self.log.error(f"目录不存在: {js_files_dir}")
            return False

        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        # 统计原始与 SourceMap 还原文件，避免重复计数
        source_exts = ('.js', '.jsx', '.ts', '.tsx', '.vue')
        sourcemap_root = os.path.join(js_files_dir, "sourcemaps")
        sm_source_roots = self._list_sourcemap_source_roots(js_files_dir)
        sm_sources_exists = bool(sm_source_roots)

        original_paths_set = set()
        sm_paths_set = set()

        for root, _, files in os.walk(js_files_dir):
            # 跳过 SourceMap 还原目录，避免与后续统计重复
            if os.path.isdir(sourcemap_root) and self._is_path_under(root, sourcemap_root):
                continue
            for file in files:
                if not file.endswith(source_exts):
                    continue
                if self._is_sourcemap_mirror_filename(file):
                    continue
                original_paths_set.add(os.path.join(root, file))

        if sm_sources_exists:
            for sm_source_root in sm_source_roots:
                for root, _, files in os.walk(sm_source_root):
                    for file in files:
                        if not file.endswith(source_exts):
                            continue
                        file_path = os.path.join(root, file)
                        if self._should_skip_sourcemap_source_file(file_path, sm_source_root):
                            continue
                        sm_paths_set.add(file_path)

        # 合并去重
        total_paths_set = original_paths_set | sm_paths_set
        file_paths = list(total_paths_set)

        if not file_paths:
            self.log.info("未找到JavaScript文件")
            return False

        original_count = len(original_paths_set)
        sm_count = len(sm_paths_set)
        total_count = len(file_paths)

        if sm_count > 0:
            self.log.info(f"找到 {total_count} 个源文件（原始 {original_count} + SourceMap还原 {sm_count}），开始扫描敏感信息...")
        else:
            self.log.info(f"找到 {original_count} 个源文件（无SourceMap新增），开始扫描敏感信息...")

        all_matches = {}
        all_unique_paths = set()
        all_path_mappings = []
        all_path_findings: List[Dict[str, object]] = []
        sm_route_total = 0

        self._perf_stats = {
            'prefilter_backend': self._match_engine.prefilter.backend,
            'scan_backend': 'thread',
            'max_workers': 1,
            'match_runs': 0,
            'segments': 0,
            'rule_runs': 0,
            'rule_candidates': 0,
            'prefilter_token_checks': 0,
            'prefilter_tokens_hit': 0,
            'prefilter_rules_skipped': 0,
            'total_matches': 0,
            'files_processed': 0,
            'files_failed': 0,
        }

        backend, max_workers = self._choose_processing_backend(file_paths)
        self._perf_stats['scan_backend'] = backend
        self._perf_stats['max_workers'] = int(max_workers)

        processed = 0
        processed, batch_routes, remaining_paths = self._scan_file_batch(
            file_paths,
            sm_source_roots,
            backend,
            max_workers,
            total_count,
            processed,
            start_ts,
            all_matches,
            all_unique_paths,
            all_path_mappings,
            all_path_findings,
        )
        sm_route_total += batch_routes

        if remaining_paths:
            fallback_workers = min(max(2, multiprocessing.cpu_count()), 4)
            self._perf_stats['scan_backend'] = f"{backend}->thread"
            self._perf_stats['max_workers'] = int(fallback_workers)
            processed, batch_routes, _ = self._scan_file_batch(
                remaining_paths,
                sm_source_roots,
                'thread',
                fallback_workers,
                total_count,
                processed,
                start_ts,
                all_matches,
                all_unique_paths,
                all_path_mappings,
                all_path_findings,
            )
            sm_route_total += batch_routes

        self.save_results(all_matches, sorted(all_unique_paths), sorted(all_path_mappings), all_path_findings)
        self._write_perf_stats(total_count, original_count, sm_count, start_ts)
        if sm_route_total > 0:
            self.log.info(f"[SM_ROUTE] 额外提取到 {sm_route_total} 条路由路径（已并入 paths.html）")

        total_matches = sum(len(m) for m in all_matches.values())
        self.log.info(f"敏感信息扫描完成，共发现 {total_matches} 个匹配项")
        for pattern_name, pattern_matches in all_matches.items():
            if pattern_matches:
                self.log.info(f"- {pattern_name}: {len(pattern_matches)} 个匹配")

        return True

    def generate_html_output(self, matches: Dict[str, List[Tuple[str, str, str]]]) -> str:
        """生成与总览报告相同格式的交互式HTML输出"""
        html_path = os.path.join(self.output_directory, 'sensitive_info.html')

        scan_time = Utils().tellTime()
        total_matches = sum(len(pattern_matches) for pattern_matches in matches.values())
        sorted_patterns = sorted(matches.items(), key=lambda x: len(x[1]), reverse=True)

        # 将matches数据按分类组织
        findings_by_type = {}
        for pattern_name, pattern_matches in sorted_patterns:
            if not pattern_matches:
                continue
            findings_by_type[pattern_name] = [
                {
                    "match": match_text,
                    "source": source,
                    "context": context
                }
                for match_text, source, context in pattern_matches
            ]

        # 编码为Base64（与总览报告相同）
        try:
            json_string = json.dumps(findings_by_type, ensure_ascii=False)
            json_bytes = json_string.encode('utf-8')
            b64_bytes = base64.b64encode(json_bytes)
            b64_string = b64_bytes.decode('ascii')
        except Exception:
            b64_string = ""

        # 生成摘要文本
        if not findings_by_type:
            summary_text = "未发现敏感信息"
            summary_class = "summary-not-found"
        else:
            summary_parts = [f"{ftype}: {len(items)}" for ftype, items in findings_by_type.items()]
            summary_text = ", ".join(summary_parts)
            summary_class = "summary-found"

        # 使用与总览报告完全相同的样式和脚本
        html_content = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>单目标敏感信息扫描报告</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif; margin: 0 auto; max-width: 1600px; padding: 20px; background-color: #f8f9fa; color: #333; }}
        h1, h2 {{ text-align: center; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); background-color: #fff; }}
        th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; word-break: break-all; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .data-row:nth-child(even) {{ background-color: #f9f9f9; }}
        .data-row:hover {{ background-color: #e9ecef; cursor: pointer; }}
        .data-row.active {{ background-color: #d1e7fd; }}
        a {{ color: #007bff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .summary-found {{ color: #dc3545; font-weight: bold; }}
        .summary-not-found {{ color: #6c757d; }}
        .summary-error {{ color: #ffc107; }}
        .footer {{ text-align: center; margin-top: 30px; color: #888; font-size: 0.9em; }}
        .hidden {{ display: none; }}
        .detail-cell {{ padding: 0; }}
        .detail-container {{ padding: 20px; background-color: #fdfdfd; border-top: 2px solid #007bff; }}
        .tabs {{ display: flex; border-bottom: 1px solid #ccc; margin-bottom: 15px; flex-wrap: wrap; }}
        .tab-link {{ padding: 10px 15px; cursor: pointer; border: 1px solid transparent; border-bottom: none; margin-bottom: -1px; background: #f1f1f1; border-radius: 4px 4px 0 0; margin-right: 5px; }}
        .tab-link.active {{ background: #fff; border-color: #ccc #ccc #fff; }}
        .tab-content {{ padding: 10px; }}
        .match-list-item {{ list-style: none; padding: 10px; border: 1px solid #eee; margin-bottom: 8px; border-radius: 4px; background: #fff; }}
        .match-list-item:hover {{ background: #f7f7f7; }}
        .match-header {{ cursor: pointer; font-weight: bold; color: #c0392b; font-family: monospace; }}
        .match-source {{ font-size: 0.8em; color: #777; margin-left: 15px; }}
        .match-context {{ background-color: #f0f0f0; padding: 10px; border-radius: 4px; margin-top: 10px; font-family: monospace; white-space: pre-wrap; word-break: break-all; font-size: 0.9em; border-left: 3px solid #6c757d; }}
        .highlight {{ background-color: #ff9999; padding: 2px 0; border-radius: 2px; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>单目标敏感信息扫描报告</h1>
    <h2>扫描时间: {scan_time}</h2>
    <table id="main-table">
        <thead>
            <tr>
                <th style="width:10%">类型统计</th>
                <th style="width:70%">扫描结果摘要 (点击展开查看详情)</th>
                <th style="width:20%">总匹配项数</th>
            </tr>
        </thead>
        <tbody>
            <tr class="data-row" data-id="1">
                <td>{len(findings_by_type)} 种类型</td>
                <td class="{summary_class}">{html.escape(summary_text)}</td>
                <td>{total_matches}</td>
            </tr>
        </tbody>
    </table>
    <div class="footer">
        <p>报告由 Packer-InfoFinder 工具生成</p>
    </div>

    <script type="application/json-base64" id="json-1" class="hidden">
    {b64_string}
    </script>

    <script>
        document.addEventListener('DOMContentLoaded', function() {{
            const mainTableBody = document.querySelector('#main-table tbody');

            // Unicode-safe Base64解码函数
            function b64DecodeUnicode(str) {{
                try {{
                    return decodeURIComponent(atob(str).split('').map(function(c) {{
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }}).join(''));
                }} catch (e) {{
                    console.error("Base64 decoding failed:", e);
                    return '';
                }}
            }}

            mainTableBody.addEventListener('click', function(e) {{
                const dataRow = e.target.closest('.data-row');
                if (!dataRow) return;

                const detailRowId = `detail-${{dataRow.dataset.id}}`;
                let detailRow = document.getElementById(detailRowId);

                if (detailRow) {{
                    dataRow.classList.toggle('active');
                    detailRow.classList.toggle('hidden');
                }} else {{
                    dataRow.classList.add('active');
                    detailRow = document.createElement('tr');
                    detailRow.id = detailRowId;
                    const detailCell = detailRow.insertCell(0);
                    detailCell.colSpan = 3;
                    detailCell.classList.add('detail-cell');
                    dataRow.insertAdjacentElement('afterend', detailRow);

                    const jsonDataScript = document.getElementById(`json-${{dataRow.dataset.id}}`);
                    try {{
                        const b64Data = jsonDataScript.textContent.trim();
                        if (!b64Data) throw new Error("No data found.");

                        const jsonText = b64DecodeUnicode(b64Data);
                        if (!jsonText) throw new Error("Decoded data is empty.");

                        const findings = JSON.parse(jsonText);
                        detailCell.innerHTML = createDetailView(findings, dataRow.dataset.id);
                        attachDetailEventListeners(detailRow);
                    }} catch (err) {{
                        detailCell.innerHTML = `<div class="detail-container">无法加载详细信息: ${{err.message}}</div>`;
                    }}
                }}
            }});

            function createDetailView(findings, id) {{
                if (Object.keys(findings).length === 0) {{
                    return `<div class="detail-container">无详细信息</div>`;
                }}
                let tabsHtml = '<div class="tabs">';
                let contentHtml = '';
                let isFirstTab = true;
                let tabIndex = 0;

                for (const type in findings) {{
                    const safeId = `tab-${{id}}-${{tabIndex}}`;
                    tabsHtml += `<div class="tab-link ${{isFirstTab ? 'active' : ''}}" data-tab="${{safeId}}">${{escapeHtml(type)}} (${{findings[type].length}})</div>`;

                    let matchesHtml = '<ul style="padding:0;">';
                    findings[type].forEach((item, index) => {{
                        const contextId = `context-${{id}}-${{tabIndex}}-${{index}}`;

                        const safeMatch = escapeHtml(item.match);
                        const safeContext = escapeHtml(item.context);
                        const highlightedContext = safeContext.split(safeMatch).join(`<span class="highlight">${{safeMatch}}</span>`);

                        matchesHtml += `
                            <li class="match-list-item">
                                <div class="match-header" data-target="${{contextId}}">
                                    ${{safeMatch}}
                                    <span class="match-source">${{escapeHtml(item.source)}}</span>
                                </div>
                                <div id="${{contextId}}" class="match-context hidden">
                                    ${{highlightedContext}}
                                </div>
                            </li>`;
                    }});
                    matchesHtml += '</ul>';

                    contentHtml += `<div id="${{safeId}}" class="tab-content ${{isFirstTab ? '' : 'hidden'}}">${{matchesHtml}}</div>`;
                    isFirstTab = false;
                    tabIndex++;
                }}
                tabsHtml += '</div>';

                return `<div class="detail-container">${{tabsHtml}}${{contentHtml}}</div>`;
            }}

            function attachDetailEventListeners(detailRow) {{
                detailRow.addEventListener('click', function(e) {{
                    if (e.target.classList.contains('tab-link')) {{
                        const tabId = e.target.dataset.tab;
                        detailRow.querySelectorAll('.tab-link').forEach(t => t.classList.remove('active'));
                        e.target.classList.add('active');
                        detailRow.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
                        detailRow.querySelector(`#${{tabId}}`).classList.remove('hidden');
                    }} else if (e.target.closest('.match-header')) {{
                        const header = e.target.closest('.match-header');
                        const contextDiv = document.getElementById(header.dataset.target);
                        if (contextDiv) {{
                            contextDiv.classList.toggle('hidden');
                        }}
                    }}
                }});
            }}

            function escapeHtml(str) {{
                if (typeof str !== 'string') return '';
                const p = document.createElement("p");
                p.textContent = str;
                return p.innerHTML;
            }}
        }});
    </script>
</body>
</html>
"""

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return html_path

    def _build_paths_text(self, unique_paths: List[str], path_mappings: List[str]) -> str:
        lines = ["[--------------------独立路径列表-----------------------]"]
        lines.extend(unique_paths)
        lines.append("")
        lines.append("[------------------文件路径对应关系-----------------------]")
        lines.extend(path_mappings)
        return "\n".join(lines).strip() + "\n"

    @staticmethod
    def _normalize_path_finding_entry(finding: Dict[str, object]) -> Dict[str, object]:
        source = str(finding.get('source') or '').strip()
        source_kind = str(finding.get('source_kind') or 'JS').strip() or 'JS'
        context = str(finding.get('context') or '').strip()
        filename = str(finding.get('filename') or source.split(':Line ', 1)[0] or '').strip()
        line = int(finding.get('line') or JsFinderModule._line_value_from_source(source) or 0)
        return {
            'path': str(finding.get('path') or '').strip(),
            'source': source,
            'source_kind': source_kind,
            'context': context,
            'filename': filename,
            'line': line,
        }

    def _build_paths_payload(self, unique_paths: List[str], path_mappings: List[str], path_findings: List[Dict[str, object]]) -> Dict[str, object]:
        plain_text = self._build_paths_text(unique_paths, path_mappings)
        grouped: Dict[str, List[Dict[str, object]]] = defaultdict(list)
        seen_keys = set()
        for raw in path_findings or []:
            normalized = self._normalize_path_finding_entry(raw)
            path_value = normalized['path']
            if not path_value:
                continue
            key = (path_value, normalized['source'], normalized['context'], normalized['source_kind'])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            grouped[path_value].append(normalized)

        for mapping in path_mappings or []:
            if '----' not in mapping:
                continue
            source, raw_path = mapping.split('----', 1)
            source_kind = 'SM_ROUTE' if raw_path.startswith('[SM_ROUTE]') else 'JS'
            path_value = raw_path[len('[SM_ROUTE]'):] if source_kind == 'SM_ROUTE' else raw_path
            path_value = str(path_value or '').strip()
            if not path_value or path_value in grouped:
                continue
            grouped[path_value].append({
                'path': path_value,
                'source': str(source or '').strip(),
                'source_kind': source_kind,
                'context': '',
                'filename': str(source or '').strip(),
                'line': 0,
            })

        entries = []
        for path_value in sorted(unique_paths):
            findings = [self._normalize_path_finding_entry(item) for item in grouped.get(path_value, [])]
            findings.sort(key=lambda item: (str(item.get('filename') or ''), int(item.get('line') or 0), str(item.get('source_kind') or ''), str(item.get('source') or '')))
            source_kinds = sorted({str(item.get('source_kind') or 'JS') for item in findings})
            entries.append({
                'path': path_value,
                'count': len(findings),
                'source_kinds': source_kinds,
                'findings': findings,
            })

        return {
            'entries': entries,
            'plain_text': plain_text,
            'total_paths': len(unique_paths),
        }

    def generate_paths_html(self, unique_paths: List[str], path_mappings: List[str], path_findings: List[Dict[str, object]]) -> str:
        html_path = os.path.join(self.output_directory, 'paths.html')
        payload = self._build_paths_payload(unique_paths, path_mappings, path_findings)
        payload_json = json.dumps(payload, ensure_ascii=False).replace('</', '<\\/')
        html_content = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Finder 路径视图</title>
    <style>
        :root { color-scheme: light dark; }
        body { margin:0; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:#f5f7fb; color:#1f2937; }
        .page { padding:16px; }
        .toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:12px; }
        .toolbar input { flex:1 1 280px; min-width:220px; padding:10px 12px; border:1px solid #d1d5db; border-radius:10px; }
        .toolbar button { padding:9px 12px; border:0; border-radius:10px; background:#2563eb; color:#fff; cursor:pointer; }
        .toolbar button.secondary { background:#4b5563; }
        .summary { margin-bottom:12px; color:#4b5563; font-size:14px; }
        .tabs { display:flex; gap:8px; margin-bottom:12px; }
        .tab-btn { padding:8px 12px; border-radius:999px; border:1px solid #cbd5e1; background:#fff; cursor:pointer; }
        .tab-btn.active { background:#1d4ed8; color:#fff; border-color:#1d4ed8; }
        .hidden { display:none !important; }
        .layout { display:grid; grid-template-columns:minmax(320px, 38%) minmax(0, 1fr); gap:12px; min-height:70vh; }
        .panel { background:#fff; border:1px solid #e5e7eb; border-radius:14px; overflow:hidden; box-shadow:0 6px 20px rgba(15,23,42,.06); }
        .panel-header { padding:12px 14px; border-bottom:1px solid #e5e7eb; font-weight:600; }
        .path-list { max-height:70vh; overflow:auto; }
        .path-item { display:flex; align-items:center; gap:8px; padding:10px 12px; border-bottom:1px solid #f1f5f9; cursor:pointer; }
        .path-item.active { background:#eff6ff; }
        .path-item:hover { background:#f8fafc; }
                .path-text { flex:1; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; word-break:break-all; }
        .badge { background:#e0e7ff; color:#3730a3; border-radius:999px; padding:2px 8px; font-size:12px; }
        .kind { background:#dcfce7; color:#166534; border-radius:999px; padding:2px 8px; font-size:12px; }
        .copy-btn { padding:6px 10px; border:0; border-radius:8px; background:#e5e7eb; cursor:pointer; }
        .details { padding:14px; max-height:70vh; overflow:auto; }
        .detail-title { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:15px; margin:0 0 10px; word-break:break-all; }
        .finding-card { border:1px solid #e5e7eb; border-radius:12px; padding:10px 12px; margin-bottom:10px; background:#f8fafc; }
        .finding-meta { display:flex; gap:8px; flex-wrap:wrap; font-size:12px; color:#4b5563; margin-bottom:6px; }
        .context { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; white-space:pre-wrap; word-break:break-word; background:#fff; padding:10px; border-radius:10px; border:1px solid #e5e7eb; }
        mark { background:#fde68a; color:#92400e; padding:0 2px; border-radius:4px; }
        .plain-text-wrap { background:#fff; border:1px solid #e5e7eb; border-radius:14px; padding:12px; }
        textarea { width:100%; min-height:72vh; border:0; resize:vertical; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
        .empty { color:#6b7280; padding:18px; }
    </style>
</head>
<body>
    <div class="page">
        <div class="toolbar">
            <input id="searchInput" type="search" placeholder="搜索路径关键字，如 /api、login、graphql">
            <button id="copyVisibleBtn">复制当前列表</button>
        </div>
        <div class="summary" id="summaryText"></div>
        <div class="tabs">
            <button class="tab-btn active" data-tab="browser">路径浏览</button>
            <button class="tab-btn" data-tab="plain">纯文本视图</button>
        </div>
        <div id="browserTab" class="layout">
            <div class="panel">
                <div class="panel-header">路径列表</div>
                <div id="pathList" class="path-list"></div>
            </div>
            <div class="panel">
                <div class="panel-header">路径上下文</div>
                <div id="detailPanel" class="details"></div>
            </div>
        </div>
        <div id="plainTab" class="plain-text-wrap hidden">
            <textarea id="plainTextView" readonly></textarea>
        </div>
    </div>
    <script id="paths-data" type="application/json">__PAYLOAD_JSON__</script>
    <script>
        const payload = JSON.parse(document.getElementById('paths-data').textContent || '{}');
        const entries = Array.isArray(payload.entries) ? payload.entries : [];
                let activePath = entries.length ? entries[0].path : '';
        let searchTerm = '';

        const searchInput = document.getElementById('searchInput');
        const pathList = document.getElementById('pathList');
        const detailPanel = document.getElementById('detailPanel');
        const plainTextView = document.getElementById('plainTextView');
        const summaryText = document.getElementById('summaryText');
        const copyVisibleBtn = document.getElementById('copyVisibleBtn');
        const browserTab = document.getElementById('browserTab');
        const plainTab = document.getElementById('plainTab');
        if (plainTextView) {
            plainTextView.value = payload.plain_text || '';
        }

        function escapeHtml(str) {
            if (typeof str !== 'string') return '';
            return str.replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
        }

        function highlightContext(context, pathValue) {
            const safeContext = escapeHtml(context || '');
            const safePath = escapeHtml(pathValue || '');
            if (!safePath) return safeContext;
            return safeContext.split(safePath).join(`<mark>${safePath}</mark>`);
        }

        function getFilteredEntries() {
            const keyword = (searchTerm || '').trim().toLowerCase();
            if (!keyword) return entries;
            return entries.filter(item => (item.path || '').toLowerCase().includes(keyword));
        }

        function renderSummary(filtered) {
            if (summaryText) {
                summaryText.textContent = `共 ${entries.length} 条路径，当前可见 ${filtered.length} 条；支持搜索、复制当前列表、复制当前路径。`;
            }
        }

        function renderList() {
            const filtered = getFilteredEntries();
            renderSummary(filtered);
            if (!filtered.length) {
                if (pathList) pathList.innerHTML = '<div class="empty">没有匹配的路径</div>';
                if (!entries.some(item => item.path === activePath)) activePath = '';
                renderDetails();
                return;
            }
            if (!filtered.some(item => item.path === activePath)) activePath = filtered[0].path;
            if (!pathList) return;
            pathList.innerHTML = filtered.map(item => {
                const count = Number(item.count || 0);
                const kinds = Array.isArray(item.source_kinds) ? item.source_kinds : [];
                return `
                    <div class="path-item ${item.path === activePath ? 'active' : ''}" data-path="${escapeHtml(item.path)}">
                        <div class="path-text">${escapeHtml(item.path)}</div>
                        <span class="badge">${count}</span>
                        ${kinds.length ? `<span class="kind">${escapeHtml(kinds.join('/'))}</span>` : ''}
                    </div>`;
            }).join('');
            renderDetails();
        }

        function renderDetails() {
            const entry = entries.find(item => item.path === activePath);
            if (!entry) {
                if (detailPanel) detailPanel.innerHTML = '<div class="empty">选择左侧路径查看上下文证据</div>';
                return;
            }
            const findings = Array.isArray(entry.findings) ? entry.findings : [];
            const cards = findings.length ? findings.map(item => `
                <div class="finding-card">
                    <div class="finding-meta">
                        <span>${escapeHtml(item.source || '')}</span>
                        <span class="kind">${escapeHtml(item.source_kind || 'JS')}</span>
                    </div>
                    <div class="context">${item.context ? highlightContext(item.context, entry.path) : '无额外上下文'}</div>
                </div>`).join('') : '<div class="empty">无额外上下文</div>';
            if (!detailPanel) return;
            detailPanel.innerHTML = `
                <div class="toolbar" style="margin-bottom:10px;">
                    <button class="copy-btn" id="copyCurrentPathBtn">复制当前路径</button>
                </div>
                <h3 class="detail-title">${escapeHtml(entry.path)}</h3>
                <div class="summary">命中证据 ${findings.length} 条</div>
                ${cards}`;
            const copyCurrent = document.getElementById('copyCurrentPathBtn');
            if (copyCurrent) {
                copyCurrent.addEventListener('click', () => copyText(entry.path || ''));
            }
        }

        function copyText(text) {
            const value = String(text || '');
            if (!value) return;
            navigator.clipboard.writeText(value).catch(() => {
                const textarea = document.createElement('textarea');
                textarea.value = value;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
            });
        }

        document.getElementById('copyVisibleBtn').addEventListener('click', () => copyText(getFilteredEntries().map(item => item.path).join('\\n')));
        searchInput.addEventListener('input', (event) => { searchTerm = event.target.value || ''; renderList(); });
        pathList.addEventListener('click', (event) => {
            const row = event.target.closest('.path-item');
            if (!row) return;
            activePath = row.dataset.path || '';
            renderList();
        });

        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(item => item.classList.remove('active'));
                btn.classList.add('active');
                const isBrowser = btn.dataset.tab === 'browser';
                document.getElementById('browserTab').classList.toggle('hidden', !isBrowser);
                document.getElementById('plainTab').classList.toggle('hidden', isBrowser);
            });
        });

        renderList();
    </script>
</body>
</html>
""".replace('__PAYLOAD_JSON__', payload_json)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return html_path

    def save_results(self, matches: Dict, unique_paths: List, path_mappings: List, path_findings: List[Dict[str, object]]) -> None:
        """保存扫描结果到文件"""
        if not os.path.exists(self.output_directory):
            os.makedirs(self.output_directory)

        html_path = self.generate_html_output(matches)
        paths_html_path = self.generate_paths_html(unique_paths, path_mappings, path_findings)

        self.log.info(f"HTML格式结果已保存到: {html_path}")
        self.log.info(f"路径视图已保存到: {paths_html_path}")

        # 全局 fuzz_last_segments.txt 导出已取消
        self.log.debug("已跳过 fuzz_last_segments.txt 导出（功能已取消）")

        # 单文件智能收敛导出功能已取消，跳过 endpoints.jsonl 与 inventory.md 生成
        self.log.debug("已跳过 API Inventory 导出（功能已取消）")

    def start_scan(self) -> bool:
        """开始扫描JavaScript文件中的敏感信息"""
        self.log.info("开始JavaScript敏感信息扫描...")

        try:
            project_path = DatabaseType(self.projectTag).getPathfromDB()
            if not project_path:
                self.log.error("无法获取项目路径")
                return False

            result = self.process_js_files(project_path)

            if result:
                self.log.info(f"JavaScript敏感信息扫描完成，结果保存在: {self.output_directory}")
                return True
            else:
                self.log.error("JavaScript敏感信息扫描失败")
                return False

        except Exception as e:
            self.log.error(f"JavaScript敏感信息扫描过程中出错: {e}")
            return False

    def extract_last_segments(self, paths: List[str]) -> List[str]:
        """从路径列表中提取最后一个“看起来像API”的有效段并去重"""
        tokens = set()
        for original in paths:
            try:
                path = original
                # 支持完整URL：仅取其路径部分
                if '://' in path:
                    from urllib.parse import urlparse
                    path = urlparse(path).path or '/'
                # 去掉查询串和fragment
                path = path.split('?', 1)[0].split('#', 1)[0].strip()
                if not path:
                    continue
                # 规范化/分段
                segments = [s for s in path.strip('/').split('/') if s]
                if not segments:
                    continue
                candidate = segments[-1].strip()
                if not candidate:
                    continue
                if self.is_reasonable_api_segment(candidate):
                    tokens.add(candidate)
            except Exception:
                continue
        return sorted(tokens)

    def is_reasonable_api_segment(self, segment: str) -> bool:
        """基于启发式判断一个末段是否像“正常API接口名”"""
        seg = segment.strip()
        if not seg:
            return False
        low = seg.lower()
        # 排除静态资源及常见非接口后缀
        static_exts = (
            '.js', '.mjs', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.map',
            '.eot', '.ttf', '.woff', '.woff2', '.mp3', '.mp4', '.avi', '.mov', '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.vue'
        )
        if any(low.endswith(ext) for ext in static_exts):
            return False
        # 含点通常是文件，直接排除
        if '.' in seg:
            return False
        # 过长/过短或明显随机
        if len(seg) > 48:
            return False
        # 纯数字
        if re.fullmatch(r'\d+', seg):
            return False
        # UUID或长哈希
        if re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', seg, re.IGNORECASE):
            return False
        if re.fullmatch(r'[A-Fa-f0-9]{24,}', seg):
            return False
        # 合理的API命名：字母开头，允许数字/下划线/破折号，长度限制
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{1,47}', seg):
            return True
        return False

    def _split_identifier(self, s: str) -> List[str]:
        s = re.sub(r'([a-z])([A-Z])', r'\1 \2', s or '')
        s = s.replace('-', ' ').replace('_', ' ')
        return [t for t in s.lower().split() if t]

    def _is_verb(self, tok: str) -> bool:
        return tok in self._verbs

    def _last_noun_from_tokens(self, toks: List[str]) -> str:
        for t in reversed(toks or []):
            if t not in self._stop_tokens and t not in self._verbs and t not in self._suffix_detail_like:
                return t
        return (toks or [''])[ -1 ] if toks else ''

    def _split_verb_noun(self, segment: str) -> Tuple[str, str]:
        toks = self._split_identifier(segment)
        if not toks:
            return None, None
        if self._is_verb(toks[0]) and len(toks) >= 2:
            return toks[0], self._last_noun_from_tokens(toks[1:])
        if toks[-1] in self._suffix_detail_like and len(toks) >= 2:
            suffix = toks[-1]
            verb = 'detail' if suffix in {'detail', 'info'} else 'list'
            return verb, self._last_noun_from_tokens(toks[:-1])
        # 既非动词开头也非后缀，返回最后一个“像名词”的token
        return None, self._last_noun_from_tokens(toks)

    def _normalize_noun(self, n: str) -> str:
        if not n:
            return ''
        n = self._synonyms.get(n, n)
        if n.endswith('ies') and len(n) > 3:
            n = n[:-3] + 'y'
        elif n.endswith('s') and len(n) > 3:
            n = n[:-1]
        return re.sub(r'[^a-z0-9]', '', n)

    def _classify_action(self, verb: str, segment: str) -> Tuple[str, str]:
        v = verb
        if not v:
            toks = self._split_identifier(segment)
            if toks and toks[0] in self._verbs:
                v = toks[0]
        verb2method = {
            'add': 'post','create': 'post','new': 'post','save': 'post','upload': 'post','import': 'post',
            'update': 'put','edit': 'put','change': 'put',
            'delete': 'delete','remove': 'delete','clear': 'delete','reset': 'delete',
            'list': 'get','get': 'get','detail': 'get','info': 'get','show': 'get','search': 'get','query': 'get','export': 'get','download': 'get'
        }
        method = verb2method.get(v or '', '')
        if not method and v in {'list','detail','info','get','show','search','query','export','download'}:
            method = 'get'
        return method, v or ''

    def build_endpoint_records(self, paths: List[str]) -> List[Dict[str, str]]:
        records = []
        for original in paths:
            try:
                path = original
                if '://' in path:
                    from urllib.parse import urlparse
                    path = urlparse(path).path or '/'
                path = path.split('?', 1)[0].split('#', 1)[0].strip()
                segs = [s for s in path.strip('/').split('/') if s]
                if not segs:
                    continue
                last = segs[-1].strip()
                if not self.is_reasonable_api_segment(last):
                    continue
                module = segs[0].lower()
                verb, noun = self._split_verb_noun(last)
                if noun:
                    resource = self._normalize_noun(noun)
                elif len(segs) > 1:
                    resource = self._normalize_noun(self._last_noun_from_tokens(self._split_identifier(segs[-2])))
                else:
                    resource = self._normalize_noun(self._last_noun_from_tokens(self._split_identifier(last)))
                action_method, action_verb = self._classify_action(verb, last)
                rec = {
                    'path': path,
                    'module': module,
                    'resource': resource or 'others',
                    'action': action_verb or '',
                    'method': action_method or '',
                    'token': last
                }
                records.append(rec)
            except Exception:
                continue
        return records

    def export_single_inventory(self, endpoints: List[Dict[str, str]], max_resources: int = 12, min_support: int = 2) -> Dict[str, str]:
        # 资源计数与裁剪
        res_counts = Counter([e.get('resource') for e in endpoints if e.get('resource')])
        sorted_resources = [r for r, _ in res_counts.most_common()]
        keep = set([r for r in sorted_resources if r and res_counts[r] >= min_support][:max_resources])

        by_res = defaultdict(list)
        for e in endpoints:
            r = e.get('resource') or 'others'
            by_res[r if r in keep else 'others'].append(e)

        # 写 endpoints.jsonl（全量，可编程）
        jsonl_path = os.path.join(self.output_directory, 'endpoints.jsonl')
        os.makedirs(self.output_directory, exist_ok=True)
        with open(jsonl_path, 'w', encoding='utf-8') as f:
            for e in endpoints:
                f.write(json.dumps(e, ensure_ascii=False) + '\n')

        # 写 inventory.md（收敛的人读报告）
        md_path = os.path.join(self.output_directory, 'inventory.md')
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('# API Inventory (收敛视图)\n\n')
            f.write(f"- resources_kept: {len(keep)} (min_support={min_support}, max={max_resources})\n")
            f.write(f"- total_endpoints: {len(endpoints)}\n\n")
            for r, items in sorted(by_res.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                mods = Counter([e.get('module') for e in items])
                tokens = Counter([e.get('token') for e in items])
                actions = Counter([(e.get('action') or 'unknown') for e in items])
                f.write(f"## Resource: {r} (paths={len(items)})\n")
                if mods:
                    f.write(f"- modules: {', '.join([f'{m}:{c}' for m, c in mods.most_common()])}\n")
                if actions:
                    f.write(f"- actions: {', '.join([f'{a}:{c}' for a, c in actions.most_common()])}\n")
                danger = sum(c for a, c in actions.items() if a in {'delete','clear','reset','remove'})
                if danger:
                    f.write(f"- risks: delete/clear/reset={danger}\n")
                top_tokens = ', '.join([t for t, _ in tokens.most_common(10)])
                if top_tokens:
                    f.write(f"- tokens: {top_tokens}\n")
                # examples
                for e in items[:3]:
                    f.write(f"  - {e.get('path')}\n")
                # CRUD 补全建议
                have = set([e.get('action') for e in items if e.get('action')])
                missing = [a for a in ('add','update','delete','list','detail') if a not in have]
                if missing:
                    f.write(f"- suggest: {', '.join([f'{r}{a.capitalize()}' for a in missing])}\n")
                f.write('\n')

        return {'jsonl': jsonl_path, 'md': md_path, 'kept_resources': str(len(keep))}
